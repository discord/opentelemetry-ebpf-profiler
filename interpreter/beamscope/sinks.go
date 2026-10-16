// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Convert allocation, scheduler and message records into reporter samples;
// write the remaining runtime records to an optional per-PID JSONL file.
package beamscope // import "go.opentelemetry.io/ebpf-profiler/interpreter/beamscope"

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

// Custom label keys attached to beamscope samples. Renaming any of them is a
// breaking change for the offline consumers reading the pprof files. The
// numeric ones ride CustomLabels as decimal strings and are re-emitted as
// pprof num labels by the pprof reporter (see numLabelUnits there).
var (
	labelErlangPID     = libpf.Intern("erlang_pid")
	labelBinVheapDelta = libpf.Intern("bin_vheap_delta")
	labelMbufWords     = libpf.Intern("mbuf_words")
	labelPauseNS       = libpf.Intern("pause_ns")
	labelNSwitches     = libpf.Intern("nswitches")
	labelPreempts      = libpf.Intern("preempts")
	labelYields        = libpf.Intern("yields")

	// labelBeamscopeKind separates the beamscope sample populations: "alloc"
	// (GC_DELTA/GC_DELTA2, value = allocated words), "sched" (SCHED_DELTA,
	// value = on-scheduler nanoseconds), and "msg" (MSG_FLOW, value = scaled
	// arrival count). Present on every beamscope-origin sample.
	labelBeamscopeKind = libpf.Intern("beamscope_kind")
	kindAlloc          = libpf.Intern("alloc")
	kindSched          = libpf.Intern("sched")
	kindMsg            = libpf.Intern("msg")
)

// reporterSink converts GC_DELTA records into reporter samples.
type reporterSink struct {
	rep reporter.TraceReporter
	pid libpf.PID

	mu       sync.Mutex
	procMeta process.Meta

	// metaCache holds pid_key -> PROC_META, fed by the lazily emitted
	// metadata records (ABI: first reference per epoch). Only touched from the
	// drain goroutine.
	metaCache map[uint64]*ProcMeta

	reported    uint64
	reportErrs  uint64
	unknownPids uint64
}

func newReporterSink(rep reporter.TraceReporter, pid libpf.PID) *reporterSink {
	return &reporterSink{
		rep:       rep,
		pid:       pid,
		metaCache: map[uint64]*ProcMeta{},
	}
}

// setProcessMeta installs the /proc-derived identity used on every sample.
func (s *reporterSink) setProcessMeta(pm process.Meta) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.procMeta = pm
}

// cacheProcMeta records a PROC_META for later GC_DELTA labeling.
func (s *reporterSink) cacheProcMeta(r *ProcMeta) {
	s.metaCache[r.PidKey] = r
}

// hasMeta reports whether a PROC_META is cached for pidKey. Only touched from
// the drain goroutine, like the cache itself.
func (s *reporterSink) hasMeta(pidKey uint64) bool {
	_, ok := s.metaCache[pidKey]
	return ok
}

// evictMeta drops a cached PROC_META (PROC_EXIT eviction): without
// it the cache leaks one entry per exited pid under process churn. Only
// touched from the drain goroutine, like the cache itself.
func (s *reporterSink) evictMeta(pidKey uint64) {
	delete(s.metaCache, pidKey)
}

// unknownFrameName is the display name for a pid_key the writer told us
// nothing usable about.
func unknownFrameName(pidKey uint64) string {
	return fmt.Sprintf("<beam_pid_key:0x%x>", pidKey)
}

// formatMFA renders an MFA the way the BEAM interpreter renders one:
// "Mod.fun/arity" for Elixir modules, "mod:fun/arity" otherwise. A
// current_function-derived MFA renders the same (it is the best MFA the
// writer had).
func formatMFA(module, function string, arity uint8) string {
	if elixirModule, ok := strings.CutPrefix(module, "Elixir."); ok {
		return fmt.Sprintf("%s.%s/%d", elixirModule, function, arity)
	}
	return fmt.Sprintf("%s:%s/%d", module, function, arity)
}

// frameName renders the display name per the ABI ranking:
// registered_name > translated MFA > untranslated MFA > pid_printable
// (then the opaque key when nothing is known). A registered name is used
// as-is -- that is what humans call the process.
func (s *reporterSink) frameName(pidKey uint64) (name, erlangPid string) {
	m, ok := s.metaCache[pidKey]
	if !ok {
		s.unknownPids++
		return unknownFrameName(pidKey), ""
	}
	switch {
	case m.RegisteredName != "":
		name = m.RegisteredName
	case m.Module != "":
		name = formatMFA(m.Module, m.Function, m.Arity)
	default:
		name = m.PidPrintable
	}
	if name == "" {
		name = unknownFrameName(pidKey)
	}
	return name, m.PidPrintable
}

// reportSample synthesizes one single-frame beamscope sample. kind separates
// the sample populations ("alloc": value = allocated words; "sched": value =
// on-scheduler nanoseconds; "msg": value = scaled message arrivals);
// valueKind is the samples.ValueKind* the value is expressed in; labels are
// the kind-specific extras -- erlang_pid and beamscope_kind are added here.
func (s *reporterSink) reportSample(hdr *RecordHeader, pidKey uint64,
	value int64, kind libpf.String, valueKind uint8,
	labels map[libpf.String]libpf.String) {
	name, erlangPid := s.frameName(pidKey)

	var frames libpf.Frames
	frames.Append(&libpf.Frame{
		Type:            libpf.BEAMFrame,
		FunctionName:    libpf.Intern(name),
		AddressOrLineno: beamFrameID(uint64(s.pid), pidKey, kind.String()+"\x00"+name),
	})

	labels[labelBeamscopeKind] = kind
	if erlangPid != "" {
		labels[labelErlangPID] = libpf.Intern(erlangPid)
	}

	trace := &libpf.Trace{
		Frames:       frames,
		CustomLabels: labels,
	}

	s.mu.Lock()
	pm := s.procMeta
	s.mu.Unlock()

	meta := &samples.TraceEventMeta{
		Timestamp:      libpf.UnixTime64(hdr.UnixNS),
		KTime:          int64(hdr.KTimeNS),
		Comm:           libpf.NewCommFromString(pm.Name.String()),
		ProcessName:    pm.Name,
		ExecutablePath: pm.Executable,
		ContainerID:    pm.ContainerID,
		PID:            s.pid,
		ErlangPidKey:   pidKey,
		TID:            s.pid,
		ProfileType:    samples.BeamScopeProfile(valueKind),
		Value:          value,
	}

	if err := s.rep.ReportTraceEvent(trace, meta); err != nil {
		s.reportErrs++
		log.Debugf("beamscope: PID %d failed to report %s sample: %v",
			s.pid, kind.String(), err)
		return
	}
	s.reported++
}

func fmtU64(v uint64) libpf.String { return libpf.Intern(strconv.FormatUint(v, 10)) }

// handleGCDelta synthesizes one sample per GC_DELTA (0x01) record. Kept as-is
// for old captures: value = alloc_words, label bin_vheap_delta.
func (s *reporterSink) handleGCDelta(r *GCDelta) {
	s.reportSample(&r.RecordHeader, r.PidKey, scaleArrivals(r.AllocWords, 0), kindAlloc,
		samples.ValueKindAlloc,
		map[libpf.String]libpf.String{
			labelBinVheapDelta: fmtU64(r.BinVheapDeltaWords),
		})
}

// handleGCDelta2 emits allocation deltas and GC details. NO_START records
// carry no valid pause, mbuf or GC-kind measurement, so omit those labels.
func (s *reporterSink) handleGCDelta2(r *GCDelta2) {
	labels := map[libpf.String]libpf.String{
		labelBinVheapDelta: fmtU64(r.BinVheapDeltaWords),
	}
	if !r.NoStart {
		labels[labelMbufWords] = fmtU64(r.MbufWords)
		labels[labelPauseNS] = fmtU64(r.PauseNS)
	}
	s.reportSample(&r.RecordHeader, r.PidKey, scaleArrivals(r.AllocWords, 0), kindAlloc,
		samples.ValueKindAlloc, labels)
}

// handleSchedDelta synthesizes one sample per SCHED_DELTA (0x0A) record:
// value = on_sched_ns.
// preempts/yields are omitted when the writer cannot classify.
func (s *reporterSink) handleSchedDelta(r *SchedDelta) {
	labels := map[libpf.String]libpf.String{
		labelNSwitches: fmtU64(uint64(r.NSwitches)),
	}
	if !r.ClassificationUnsupported {
		labels[labelPreempts] = fmtU64(uint64(r.Preempts))
		labels[labelYields] = fmtU64(uint64(r.Yields))
	}
	s.reportSample(&r.RecordHeader, r.PidKey, scaleArrivals(r.OnSchedNS, 0), kindSched,
		samples.ValueKindSchedNS, labels)
}

// handleMsgFlow emits a message-arrival count already scaled by the drainer.
func (s *reporterSink) handleMsgFlow(r *MsgFlow, value int64) {
	s.reportSample(&r.RecordHeader, r.PidKey, value, kindMsg,
		samples.ValueKindMsgs, map[libpf.String]libpf.String{})
}

// beamFrameID gives synthetic frames a stable address for Trace.Hash().
func beamFrameID(osPid, pidKey uint64, name string) libpf.AddressOrLineno {
	h := fnv.New64a()
	var b [16]byte
	binary.LittleEndian.PutUint64(b[0:], osPid)
	binary.LittleEndian.PutUint64(b[8:], pidKey)
	_, _ = h.Write(b[:])
	_, _ = h.Write([]byte(name))
	return libpf.AddressOrLineno(h.Sum64())
}

// jsonlSink appends records as JSON lines to <dir>/beamscope-<pid>.jsonl.
// The file is created lazily on the first record, buffered, and flushed on
// every drain interval and on detach.
type jsonlSink struct {
	path string
	pid  int

	mu        sync.Mutex
	f         *os.File
	w         *bufio.Writer
	closed    bool
	writeErrs uint64
	written   uint64

	// scratch+enc render records without encoding/json's default HTML
	// escaping: this output is plain greppable text, and erlang pids are
	// full of '<' and '>' that must not come out as <. Guarded by mu.
	scratch bytes.Buffer
	enc     *json.Encoder
}

// newJSONLSink returns a sink writing under dir, or an inert sink if dir is
// empty (the JSONL sidecar is optional).
func newJSONLSink(dir string, pid int) *jsonlSink {
	s := &jsonlSink{pid: pid}
	if dir != "" {
		s.path = filepath.Join(dir, fmt.Sprintf("beamscope-%d.jsonl", pid))
	}
	s.enc = json.NewEncoder(&s.scratch)
	s.enc.SetEscapeHTML(false)
	return s
}

// marshalPlain renders v as one JSON document plus a trailing newline, with
// HTML escaping off. Callers hold s.mu. The returned slice aliases s.scratch
// and is valid until the next call.
func (s *jsonlSink) marshalPlain(v any) ([]byte, error) {
	s.scratch.Reset()
	if err := s.enc.Encode(v); err != nil {
		return nil, err
	}
	return s.scratch.Bytes(), nil
}

// Write appends one record as a JSON line: the envelope carries the record
// type and the OS pid, then the record's own snake_case ABI fields (always
// including ktime_ns and unix_ns).
func (s *jsonlSink) Write(rec Record) {
	if s.path == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.ensureOpen() {
		return
	}

	// body carries the encoder's own trailing newline.
	body, err := s.marshalPlain(rec)
	if err != nil || len(body) < 3 || body[0] != '{' {
		s.writeErrs++
		return
	}
	// Splice the envelope into the record's own object: every record type
	// serializes at least ktime_ns and unix_ns, so body is never "{}".
	if _, err = fmt.Fprintf(s.w, "{\"type\":%q,\"pid\":%d,%s",
		rec.TypeName(), s.pid, body[1:]); err != nil {
		s.writeErrs++
		return
	}
	s.written++
}

// ensureOpen lazily opens the output file. Callers hold s.mu.
func (s *jsonlSink) ensureOpen() bool {
	if s.closed {
		return false
	}
	if s.w != nil {
		return true
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		s.writeErrs++
		log.Errorf("beamscope: cannot open %s: %v", s.path, err)
		s.closed = true
		return false
	}
	s.f = f
	s.w = bufio.NewWriter(f)
	return true
}

// drainStatsLine is the reader-synthesized observability line: it is NOT an
// ABI record ("source":"reader" marks that). It makes the writer-side dropped
// counters and the reader's own skip/corruption counts visible in the JSONL
// artifact a run leaves behind. The first line after attach carries the
// counters as the writer left them, i.e. the pre-attach drops.
type drainStatsLine struct {
	Type          string            `json:"type"`
	Pid           int               `json:"pid"`
	KTimeNS       int64             `json:"ktime_ns"`
	UnixNS        int64             `json:"unix_ns"`
	Source        string            `json:"source"`
	DroppedTotal  uint64            `json:"dropped_total"`
	DroppedByRing map[string]uint64 `json:"dropped_by_ring,omitempty"`
	RecordsTotal  uint64            `json:"records_total"`
	PaddingTotal  uint64            `json:"padding_total"`
	UnknownTotal  uint64            `json:"unknown_total"`
	CorruptRings  uint64            `json:"corrupt_rings"`
	NRings        int               `json:"nrings"`
	// Meta-settling buffer state: records currently parked awaiting their
	// PROC_META, and the running count converted early because the buffer
	// hit its cap (evicted samples are still reported, with fallback naming).
	HeldRecords int    `json:"held_records"`
	HeldEvicted uint64 `json:"held_evicted_total"`
	// MsgFlowScaleSkipped counts records with no usable receive-sampling config.
	MsgFlowScaleSkipped uint64 `json:"msg_flow_scale_skipped_total"`
}

// WriteDrainStats appends one drain_stats line. Both clocks are the reader's
// own (the writer stamps nothing here), captured back to back like the ABI
// asks of record clocks.
func (s *jsonlSink) WriteDrainStats(st *DrainStats, heldRecords int,
	heldEvicted uint64, msgFlowScaleSkipped uint64) {
	if s.path == "" {
		return
	}
	// Rings that never dropped stay out of the map (and the map itself out of
	// the line) so the common all-zero case costs nothing to read.
	var droppedByRing map[string]uint64
	for i, n := range st.DroppedPerRing {
		if n == 0 {
			continue
		}
		if droppedByRing == nil {
			droppedByRing = make(map[string]uint64)
		}
		droppedByRing[strconv.Itoa(i)] = n
	}

	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	line := drainStatsLine{
		Type:                "drain_stats",
		Pid:                 s.pid,
		KTimeNS:             ts.Nano(),
		UnixNS:              time.Now().UnixNano(),
		Source:              "reader",
		DroppedTotal:        st.Dropped,
		DroppedByRing:       droppedByRing,
		RecordsTotal:        st.Records,
		PaddingTotal:        st.Padding,
		UnknownTotal:        st.Unknown,
		CorruptRings:        st.CorruptRings,
		NRings:              len(st.DroppedPerRing),
		HeldRecords:         heldRecords,
		HeldEvicted:         heldEvicted,
		MsgFlowScaleSkipped: msgFlowScaleSkipped,
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.ensureOpen() {
		return
	}
	// body carries the encoder's own trailing newline.
	body, err := s.marshalPlain(&line)
	if err != nil {
		s.writeErrs++
		return
	}
	if _, err := s.w.Write(body); err != nil {
		s.writeErrs++
		return
	}
	s.written++
}

// Flush drains the buffered writer to disk.
func (s *jsonlSink) Flush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.w == nil {
		return
	}
	if err := s.w.Flush(); err != nil {
		s.writeErrs++
	}
}

// Close flushes and closes the file. Further writes are dropped.
func (s *jsonlSink) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.w != nil {
		if err := s.w.Flush(); err != nil {
			s.writeErrs++
		}
		_ = s.f.Close()
		s.w = nil
		s.f = nil
	}
}
