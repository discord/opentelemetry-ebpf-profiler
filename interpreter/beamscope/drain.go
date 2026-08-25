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

// heldRecord is a pprof-bound record (GC_DELTA/GC_DELTA2/SCHED_DELTA/
// MSG_FLOW) parked
// because its pid_key had no cached PROC_META at drain time. Holding it a
// couple of poll cycles lets the writer's lazily-emitted metadata catch up,
// so early records do not bake fallback frames into the profile (the
// guilds-run attribution lag). gen is the drainer's poll generation at
// enqueue time; because the buffer is FIFO and the generation counter only
// grows, expiry age is nonincreasing front to back and the expired set is
// always a prefix.
type heldRecord struct {
	rec    Record
	pidKey uint64
	gen    uint64
	// msgShift/msgShiftOK carry the MSG_FLOW receive-sample shift resolved
	// when the record was DISPATCHED, not when it is finally converted: the
	// writer's SCOPE_CONFIG can change inside the settling window, and a
	// record must be scaled by the config that was in force when it arrived
	// (see resolveRecvShift). msgShiftOK false means no retained config could
	// scale it AT DISPATCH; reportBound then retries the resolve once (the
	// covering config may have been in a later ring) and only counts the skip
	// if that also fails. Both are unset for every other record type.
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

	// latestConfig is the most recently observed SCOPE_CONFIG, selected by
	// MAX ktime_ns across ALL rings (ABI.md's rule), not by dispatch/arrival
	// order: a later-ktime config drained from one ring is never displaced by
	// an earlier-ktime one processed after it from another ring. Only
	// touched from the drain goroutine, like the meta cache.
	//
	// prevConfig is the second-newest config seen, by the same ktime_ns
	// ordering. The max-ktime rule governs which config is HELD; it never
	// governs which config a given record is scaled BY. Because DrainInto
	// walks rings 0..n-1 while the writer's records are only ordered within
	// a ring, a config drained early in a pass can be NEWER than a record
	// drained later in that same pass -- scaling by the latched config would
	// then apply a shift that was not yet in force when the record was
	// written. Retaining one generation of history is enough for the
	// realistic one-change-per-window case: see resolveRecvShift, which
	// picks the newest retained config that is not newer than the record.
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
	heldCap         int
	heldEvicted     uint64
	lastHeldEvicted uint64
	// msgFlowScaleSkipped counts MSG_FLOW records for which no pprof sample
	// was synthesized because no retained SCOPE_CONFIG that predates the
	// record could support scaling (none seen yet, every retained one newer
	// than the record, one too old to carry RecvSampleShift, or receive
	// tracing disabled). The raw record still reaches the JSONL sidecar
	// either way (see dispatch). Surfaced in the
	// drain_stats JSONL line (see drainOnce/WriteDrainStats), same treatment
	// as heldEvicted below: otherwise it is invisible outside a white-box
	// test.
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

// recoverPanic is the defense-in-depth backstop for the drain goroutine.
// The drainer parses another process's shared memory (untrusted input); the
// shm bounds/alignment guards make a panic here unexpected, but a residual one
// must unwind ONLY this PID's drain, never take down host-wide profiling.
// It marks the drainer dead (no more polls) and releases this PID's resources,
// swallowing any secondary panic from the cleanup itself. Deferred after
// close(d.done) so it runs first: d.dead is set before done is signalled.
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

// reportBound converts one pprof-bound record into a reporter sample. For
// MSG_FLOW it prefers the shift resolved at dispatch time
// (heldRecord.msgShift) over the config latched by now: a record parked
// awaiting its PROC_META must not be rescaled by a config that arrived during
// the hold.
//
// Only when dispatch could resolve NOTHING is the resolve retried here. A
// SCOPE_CONFIG can land in ANY ring (hence the max-ktime-across-rings rule),
// so the config that covers this record may sit in a higher-numbered ring
// than the record and not be latched yet when the record is dispatched.
// Retrying at conversion time picks it up, because the pass that read the
// record has since completed. Correctness is unchanged: resolveRecvShift
// never accepts a config newer than the record, at either point. The skip is
// counted here, after the retry, so it is counted exactly once (reportBound
// runs once per record) and only for records nothing could ever scale.
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

// resolveRecvShift picks the receive-sample shift for a record stamped at
// ktime, from the newest RETAINED SCOPE_CONFIG that is NOT NEWER than the
// record (KTimeNS <= ktime). A newer config was not yet in force when the
// record was written, so scaling by it would produce a wrong number rather
// than a missing one.
//
// Once such a config is found it is authoritative: if it predates
// RecvSampleShift (PayloadLen < 48) or says receive tracing is disabled
// (RecvSampleShift >= 63), the answer is "cannot scale" -- falling further
// back in history would resurrect a shift the writer has since retired. If no
// retained config qualifies (none seen yet, or every retained one is newer
// than the record), the answer is also "cannot scale": the shift is never
// guessed.
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

// scaleArrivals applies a SCOPE_CONFIG receive-sample shift to a raw arrival
// count, saturating at the int64 maximum.
//
// Both inputs come from an untrusted shared-memory segment: the shift is only
// bounded to < 63 by the caller, so a large raw count shifted by 62 overflows
// a uint64 and, short of that, easily exceeds int64 -- which would arrive in
// pprof as a NEGATIVE message count and be summed into a total. Saturating is
// the same discipline clampSchedCount applies in the BEAM interpreter: a
// nonsense input must stay visibly nonsense rather than wrap into a plausible
// value. A saturated count is a bad sample; a negative one is a bad total.
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
	if d.rep.hasMeta(h.pidKey) {
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
		if h.pidKey == pidKey {
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
}

// flushHeld converts everything still held (detach/shutdown path: a held
// sample must never be lost).
func (d *drainer) flushHeld() {
	for _, h := range d.held {
		d.reportBound(h)
	}
	d.held = nil
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
		// The scaling shift is resolved HERE, against the record's own
		// ktime_ns, and latched onto the held record: by the time the record
		// is converted the latched config may have moved on (a later ring in
		// this same pass, or a later poll while it settles), and scaling by
		// that would give a wrong count rather than a missing one.
		//
		// A failure to resolve here is NOT final: the covering config may
		// simply live in a higher-numbered ring that this pass has not read
		// yet, so reportBound retries and counts the skip.
		//
		// Unlike the other pprof-bound types, MSG_FLOW also always reaches
		// JSONL: the pprof sample may be skipped when no retained config can
		// scale the record, but the raw record must never be lost.
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

// updateLatestConfig applies the max-ktime-across-rings selection rule: sc
// becomes latestConfig only if it is strictly newer (by ktime_ns) than what
// is currently held, regardless of which ring sc came from or when it was
// dispatched relative to the current holder. The displaced holder is demoted
// to prevConfig rather than dropped, and a config that is not the newest but
// is newer than the retained previous one takes that slot -- so the two
// newest configs seen (by ktime_ns) are always the two retained, whatever
// order they were dispatched in. resolveRecvShift needs that history to
// scale a record by a config that was actually in force when it was written.
func (d *drainer) updateLatestConfig(sc *ScopeConfig) {
	switch {
	case d.latestConfig == nil || sc.KTimeNS > d.latestConfig.KTimeNS:
		d.prevConfig = d.latestConfig
		d.latestConfig = sc
	case sc.KTimeNS < d.latestConfig.KTimeNS &&
		(d.prevConfig == nil || sc.KTimeNS > d.prevConfig.KTimeNS):
		d.prevConfig = sc
	}
}

// evictMetaOnExit drops the pid's cached PROC_META on process exit so the
// pprof sink's pid_key->meta cache does not grow without bound under process
// churn (a PROC_EXIT otherwise only reached the JSONL sink, never the cache).
// Skipped while a pprof-bound record for this pid is still parked in the
// meta-settling buffer: evicting then could strip its display name. A held
// record only exists when no meta is cached yet, so in practice this guard
// simply means "nothing to evict"; it is kept as an explicit invariant.
func (d *drainer) evictMetaOnExit(pidKey uint64) {
	for i := range d.held {
		if d.held[i].pidKey == pidKey {
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
