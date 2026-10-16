// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Discord addition. Per-attached-PID drain goroutine: activates lazily (the
// segment appears when BeamScope.start/1 runs, which may be long after the
// NIF .so is mapped), polls the rings at the configured interval, and
// dispatches decoded records to the reporter and JSONL sinks.
package beamscope // import "go.opentelemetry.io/ebpf-profiler/interpreter/beamscope"

import (
	"errors"
	"math"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

// heldMaxCycles is how many poll cycles a pprof-bound record waits for its
// PROC_META before being converted with the fallback naming.
const heldMaxCycles = 2

// defaultHeldCap bounds the meta-settling buffer. Past it the oldest held
// record is converted immediately (with fallback naming -- the sample is never
// discarded) and counted as evicted.
const defaultHeldCap = 4096

// heldRecord waits for lazy PROC_META or SCOPE_CONFIG records. gen is its
// enqueue poll generation; the FIFO therefore expires from the front.
type heldRecord struct {
	rec    Record
	pidKey uint64
	gen    uint64
	// Snapshot a resolved MSG_FLOW shift at dispatch so later config changes
	// do not rescale a held record. An unresolved shift is retried at conversion.
	msgShift   uint32
	msgShiftOK bool
}

// drainer owns one attached BEAM process end to end.
type drainer struct {
	pid        libpf.PID
	rm         remotememory.RemoteMemory
	exportAddr libpf.Address
	poll       time.Duration

	mapped []byte
	seg    *Segment
	// dead is set when activation can never succeed (wrong magic/version) or
	// when the drain goroutine hit a residual panic (recoverPanic); the
	// goroutine then stops polling and idles/exits until Detach.
	dead bool

	rep   *reporterSink
	jsonl *jsonlSink

	// Retain the two newest active configs by ktime across all rings. Records
	// use the newest retained config that predates their own timestamp.
	latestConfig *ScopeConfig
	prevConfig   *ScopeConfig

	stats DrainStats
	// statsEmitted is false until the first drain after activation has
	// published a drain_stats line: that first line carries the writer's
	// pre-attach drop counters, which would otherwise be unobservable.
	statsEmitted bool

	// held is the meta-settling buffer (FIFO), bounded by heldCap.
	// JSONL-bound records are never held: their lines carry pid_key and both
	// clocks, so consumers join offline.
	held            []heldRecord
	exitedPids      map[uint64]struct{}
	heldCap         int
	heldEvicted     uint64
	lastHeldEvicted uint64
	// Count MSG_FLOW records lacking a usable config. Their raw JSONL records
	// are still written; this counter is included in drain_stats.
	msgFlowScaleSkipped     uint64
	lastMsgFlowScaleSkipped uint64
	// pollGen counts drainOnce passes; held records expire when the drainer
	// is heldMaxCycles generations past their enqueue.
	pollGen uint64

	// scratch is the reusable per-pass DrainStats for DrainInto, so a poll
	// does not allocate a DroppedPerRing slice.
	scratch DrainStats

	stopc    chan struct{}
	done     chan struct{}
	stopOnce sync.Once
}

func newDrainer(pid libpf.PID, rm remotememory.RemoteMemory,
	exportAddr libpf.Address, cfg *Config) *drainer {
	return &drainer{
		pid:        pid,
		rm:         rm,
		exportAddr: exportAddr,
		poll:       cfg.PollInterval,
		rep:        newReporterSink(cfg.Reporter, pid),
		jsonl:      newJSONLSink(cfg.JSONLDir, int(pid)),
		heldCap:    defaultHeldCap,
		stopc:      make(chan struct{}),
		done:       make(chan struct{}),
	}
}

// run is the drain loop. It exits on stop(), or on a residual panic (which
// parks this one PID; see recoverPanic).
func (d *drainer) run() {
	defer close(d.done)
	defer d.recoverPanic()
	ticker := time.NewTicker(d.poll)
	defer ticker.Stop()
	for {
		select {
		case <-d.stopc:
			d.shutdown()
			return
		case <-ticker.C:
			if d.dead {
				continue
			}
			if d.seg == nil && !d.tryActivate() {
				continue
			}
			d.drainOnce()
		}
	}
}

// stop terminates the drain loop and waits for the final flush.
func (d *drainer) stop() {
	d.stopOnce.Do(func() { close(d.stopc) })
	<-d.done
}

// recoverPanic isolates an unexpected decode or reporter panic to this PID
// and releases its resources without trying to drain the segment again.
func (d *drainer) recoverPanic() {
	r := recover()
	if r == nil {
		return
	}
	log.Errorf("beamscope: PID %d drain goroutine panicked (parking this PID; "+
		"profiling continues): %v", d.pid, r)
	d.dead = true
	// Release resources without re-draining the (possibly poisoned) segment,
	// and never let a cleanup panic escape.
	func() {
		defer func() { _ = recover() }()
		d.jsonl.Close()
		if d.mapped != nil {
			_ = unix.Munmap(d.mapped)
			d.mapped = nil
			d.seg = nil
		}
	}()
}

// tryActivate attempts to map the segment. Transient failures (segment not
// initialized yet, process mid-exit) are retried on the next tick; permanent
// ones (bad magic/version) park the drainer.
func (d *drainer) tryActivate() bool {
	mem, seg, err := openSegment(d.pid, d.rm, d.exportAddr)
	if err != nil {
		if errors.Is(err, errNotReady) {
			return false
		}
		if errors.Is(err, errPermanent) {
			// The export can never yield a segment this reader understands
			// (wrong magic/version). Park the drainer so it stops re-running
			// readlink/open/fstat/mmap and logging every poll for the life of
			// the process; Detach still cleans up.
			log.Warnf("beamscope: PID %d permanently cannot activate: %v; "+
				"parking drainer", d.pid, err)
			d.dead = true
			return false
		}
		// The BEAM can exit at any time (ENOENT/ESRCH/EOF): keep retrying;
		// the process manager will detach us when it notices the exit.
		// Malformed exports will keep failing the same way; log at debug to
		// avoid noise and keep retrying only if plausibly transient.
		log.Debugf("beamscope: PID %d activation failed: %v", d.pid, err)
		return false
	}
	hdr := seg.Header()
	if hdr.OSPid != uint64(d.pid) {
		// Expected under PID namespaces (the segment stores the writer's own
		// view of its PID); informational only.
		log.Debugf("beamscope: PID %d segment reports os_pid %d (pid namespace?)",
			d.pid, hdr.OSPid)
	}
	d.mapped = mem
	d.seg = seg
	d.rep.setProcessMeta(gatherProcessMeta(d.pid))
	log.Infof("beamscope: PID %d segment mapped: %d rings x %d bytes, OTP %d",
		d.pid, hdr.NRings, hdr.RingDataSize, hdr.OTPRelease)
	return true
}

// drainOnce ages the meta-settling buffer, drains every ring and flushes the
// JSONL sink. Aging runs first so a record is held for heldMaxCycles full
// polls after the one that read it, and so records arriving this pass are
// stamped with the fresh generation.
func (d *drainer) drainOnce() {
	d.ageHeld()
	d.seg.DrainInto(&d.scratch, d.dispatch)
	st := &d.scratch
	if st.CorruptRings > d.stats.CorruptRings {
		log.Warnf("beamscope: PID %d has %d corrupt rings (was %d)",
			d.pid, st.CorruptRings, d.stats.CorruptRings)
	}
	statsChanged := st.Dropped != d.stats.Dropped ||
		st.CorruptRings != d.stats.CorruptRings ||
		d.heldEvicted != d.lastHeldEvicted ||
		d.msgFlowScaleSkipped != d.lastMsgFlowScaleSkipped
	prevDropped := d.stats.Dropped
	d.stats.Records += st.Records
	d.stats.Padding += st.Padding
	d.stats.Unknown += st.Unknown
	d.stats.Dropped = st.Dropped
	// Aliases the scratch backing array; safe because it is only read (by
	// WriteDrainStats below) on this goroutine, between DrainInto passes.
	d.stats.DroppedPerRing = st.DroppedPerRing
	d.stats.CorruptRings = st.CorruptRings
	if !d.statsEmitted || statsChanged {
		// The first emission's delta is against zero, so it reads as the
		// count of records the writer dropped before this reader attached.
		if st.Dropped > prevDropped {
			log.Infof("beamscope: PID %d writer dropped %d records total (+%d)",
				d.pid, st.Dropped, st.Dropped-prevDropped)
		}
		d.jsonl.WriteDrainStats(&d.stats, len(d.held), d.heldEvicted, d.msgFlowScaleSkipped)
		d.statsEmitted = true
		d.lastHeldEvicted = d.heldEvicted
		d.lastMsgFlowScaleSkipped = d.msgFlowScaleSkipped
	}
	d.jsonl.Flush()
}

// reportBound emits one measurement. MSG_FLOW uses the shift captured at
// dispatch, or retries resolution if the covering config arrived later.
func (d *drainer) reportBound(h heldRecord) {
	switch r := h.rec.(type) {
	case *GCDelta:
		d.rep.handleGCDelta(r)
	case *GCDelta2:
		d.rep.handleGCDelta2(r)
	case *SchedDelta:
		d.rep.handleSchedDelta(r)
	case *MsgFlow:
		shift, ok := h.msgShift, h.msgShiftOK
		if !ok {
			shift, ok = d.resolveRecvShift(r.KTimeNS)
		}
		if !ok {
			// Nothing retained can scale this record. The raw record already
			// reached JSONL, so nothing is lost; only the pprof sample is.
			d.msgFlowScaleSkipped++
			return
		}
		d.rep.handleMsgFlow(r, scaleArrivals(r.ArrivalsRaw, shift))
	}
}

// resolveRecvShift uses the newest retained active config at or before ktime.
// An old payload or disabled receive tracing is authoritative: do not fall
// back to a superseded config.
func (d *drainer) resolveRecvShift(ktime uint64) (uint32, bool) {
	for _, cfg := range [2]*ScopeConfig{d.latestConfig, d.prevConfig} {
		if cfg == nil || cfg.KTimeNS > ktime {
			continue
		}
		if cfg.PayloadLen < 48 || cfg.RecvSampleShift >= 63 {
			return 0, false
		}
		return cfg.RecvSampleShift, true
	}
	return 0, false
}

// scaleArrivals scales a sampled arrival count, saturating at MaxInt64
// instead of wrapping into a negative measurement.
func scaleArrivals(raw uint64, shift uint32) int64 {
	if raw == 0 {
		return 0
	}
	// raw <= MaxInt64>>shift is exactly the condition for raw<<shift to fit.
	// Go defines an over-wide shift as yielding 0, so shift >= 63 saturates
	// here too without a special case.
	if raw > uint64(math.MaxInt64)>>shift {
		return math.MaxInt64
	}
	return int64(raw << shift)
}

// holdOrReport parks a pprof-bound record until its PROC_META is cached, up
// to heldMaxCycles polls. Past heldCap the oldest held record is converted
// immediately with the fallback ranking (never discarded) and counted.
func (d *drainer) holdOrReport(h heldRecord) {
	if d.rep.hasMeta(h.pidKey) && (h.msgShiftOK || !isMsgFlow(h.rec)) {
		d.reportBound(h)
		return
	}
	if len(d.held) >= d.heldCap && len(d.held) > 0 {
		d.reportBound(d.held[0])
		d.held[0] = heldRecord{} // release the Record for GC
		d.held = d.held[1:]
		d.heldEvicted++
	}
	h.gen = d.pollGen
	d.held = append(d.held, h)
}

// releaseHeld converts (in arrival order) every held record whose PROC_META
// just arrived.
func (d *drainer) releaseHeld(pidKey uint64) {
	kept := d.held[:0]
	for _, h := range d.held {
		if h.pidKey == pidKey && (h.msgShiftOK || !isMsgFlow(h.rec)) {
			d.reportBound(h)
		} else {
			kept = append(kept, h)
		}
	}
	// Zero the compacted-out tail so released Records are collectable.
	for i := len(kept); i < len(d.held); i++ {
		d.held[i] = heldRecord{}
	}
	d.held = kept
	d.evictExitedMeta()
}

// ageHeld advances the poll generation and converts the expired with the
// fallback ranking. Expired records are always a FIFO prefix (see
// heldRecord.gen), so this is O(expired), not O(held), per poll.
func (d *drainer) ageHeld() {
	d.pollGen++
	n := 0
	for n < len(d.held) && d.pollGen-d.held[n].gen >= heldMaxCycles {
		d.reportBound(d.held[n])
		d.held[n] = heldRecord{} // release the Record for GC
		n++
	}
	if n > 0 {
		d.held = d.held[n:]
	}
	d.evictExitedMeta()
}

// flushHeld converts everything still held (detach/shutdown path: a held
// sample must never be lost).
func (d *drainer) flushHeld() {
	for _, h := range d.held {
		d.reportBound(h)
	}
	d.held = nil
	d.evictExitedMeta()
}

// dispatch routes one decoded record to its sinks.
func (d *drainer) dispatch(rec Record) {
	switch r := rec.(type) {
	case *GCDelta:
		d.holdOrReport(heldRecord{rec: r, pidKey: r.PidKey})
	case *GCDelta2:
		d.holdOrReport(heldRecord{rec: r, pidKey: r.PidKey})
	case *SchedDelta:
		d.holdOrReport(heldRecord{rec: r, pidKey: r.PidKey})
	case *MsgFlow:
		// Capture the shift in force at the record's timestamp. If its config
		// is in a later ring, hold the record and retry after the pass.
		shift, ok := d.resolveRecvShift(r.KTimeNS)
		d.holdOrReport(heldRecord{
			rec: r, pidKey: r.PidKey, msgShift: shift, msgShiftOK: ok,
		})
		d.jsonl.Write(r)
	case *ProcMeta:
		d.rep.cacheProcMeta(r)
		d.releaseHeld(r.PidKey)
		d.jsonl.Write(r)
	case *ProcExit:
		d.evictMetaOnExit(r.PidKey)
		d.jsonl.Write(r)
	case *ScopeConfig:
		d.updateLatestConfig(r)
		d.jsonl.Write(r)
	case *PanelSample, *TopkSend, *MonitorEvent, *PanelTick, *SchedUtil,
		*VMStat, *SenderTopk, *PortStat, *EtsStat:
		// JSONL-only: these carry no pid_key stack worth synthesizing into a
		// pprof sample.
		d.jsonl.Write(rec)
	default:
		// decodeRecord only produces the types above; nothing to do.
	}
}

// updateLatestConfig retains the newest two active configs by ktime.
// Inactive configs still reach JSONL but cannot supply a sampling shift.
func (d *drainer) updateLatestConfig(sc *ScopeConfig) {
	if !sc.Active {
		return
	}
	switch {
	case d.latestConfig == nil || sc.KTimeNS > d.latestConfig.KTimeNS:
		d.prevConfig = d.latestConfig
		d.latestConfig = sc
	case sc.KTimeNS < d.latestConfig.KTimeNS &&
		(d.prevConfig == nil || sc.KTimeNS > d.prevConfig.KTimeNS):
		d.prevConfig = sc
	}
}

// evictMetaOnExit releases cached metadata unless a held sample still needs it.
func (d *drainer) evictMetaOnExit(pidKey uint64) {
	for i := range d.held {
		if d.held[i].pidKey == pidKey {
			if d.exitedPids == nil {
				d.exitedPids = make(map[uint64]struct{})
			}
			d.exitedPids[pidKey] = struct{}{}
			return
		}
	}
	d.rep.evictMeta(pidKey)
}

// shutdown performs the final drain, closes the JSONL file and unmaps.
func (d *drainer) shutdown() {
	if d.seg != nil {
		// The memfd pages stay alive under our mapping even after the BEAM
		// exits, so a final drain is always safe.
		d.drainOnce()
	}
	// No more PROC_META can arrive: convert everything still settling.
	d.flushHeld()
	d.jsonl.Close()
	if d.mapped != nil {
		_ = unix.Munmap(d.mapped)
		d.mapped = nil
		d.seg = nil
	}
}

func isMsgFlow(rec Record) bool {
	_, ok := rec.(*MsgFlow)
	return ok
}

// Retain metadata through pending message-config resolution, then release it.
func (d *drainer) evictExitedMeta() {
	for pidKey := range d.exitedPids {
		pending := false
		for _, h := range d.held {
			if h.pidKey == pidKey {
				pending = true
				break
			}
		}
		if !pending {
			d.rep.evictMeta(pidKey)
			delete(d.exitedPids, pidKey)
		}
	}
}
