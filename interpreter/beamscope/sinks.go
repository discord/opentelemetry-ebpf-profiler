// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Discord addition. The two beamscope egress sinks:
//
//   - reporterSink turns GC_DELTA/GC_DELTA2/SCHED_DELTA/MSG_FLOW records into
//     single-frame BEAM traces on the existing Reporter.ReportTraceEvent seam
//     with origin TraceOriginBeamScope. The frame is the process's
//     initial_call (from cached PROC_META), the sample value rides
//     meta.Value/meta.ValueKind (alloc_words, on-scheduler ns, or scaled
//     message arrivals -- see samples.ValueKind*), and erlang_pid plus
//     kind-specific extras ride as custom labels. meta.OffTime is NOT used
//     here any more: it is exclusively the off-CPU sample's value.
//   - jsonlSink appends every non-GC record as one JSON object per line to a
//     per-PID file, snake_case fields mirroring the ABI names, ktime_ns and
//     unix_ns always present.
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
	"go.opentelemetry.io/ebpf-profiler/support"
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
	procMeta process.ProcessMeta

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
func (s *reporterSink) setProcessMeta(pm process.ProcessMeta) {
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

// evictMeta drops a cached PROC_META (PROC_EXIT eviction; see FIX-6): without
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
		Type:         libpf.BEAMFrame,
		FunctionName: libpf.Intern(name),
	})

	labels[labelBeamscopeKind] = kind
	if erlangPid != "" {
		labels[labelErlangPID] = libpf.Intern(erlangPid)
	}

	trace := &libpf.Trace{
		Frames:       frames,
		Hash:         beamTraceHash(uint64(s.pid), pidKey, kind.String()+"\x00"+name),
		CustomLabels: labels,
	}

	s.mu.Lock()
	pm := s.procMeta
	s.mu.Unlock()

	meta := &samples.TraceEventMeta{
		Timestamp:      libpf.UnixTime64(hdr.UnixNS),
		KTime:          int64(hdr.KTimeNS),
		Comm:           pm.Name,
		ProcessName:    pm.Name,
		ExecutablePath: pm.Executable,
		ContainerID:    pm.ContainerID,
		PID:            s.pid,
		TID:            s.pid,
		Origin:         support.TraceOriginBeamScope,
		Value:          value,
		ValueKind:      valueKind,
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
	s.reportSample(&r.RecordHeader, r.PidKey, int64(r.AllocWords), kindAlloc,
		samples.ValueKindAlloc,
		map[libpf.String]libpf.String{
			labelBinVheapDelta: fmtU64(r.BinVheapDeltaWords),
		})
}

// handleGCDelta2 synthesizes one sample per GC_DELTA2 (0x08) record: the 0x01
// shape plus mbuf_words and pause_ns.
func (s *reporterSink) handleGCDelta2(r *GCDelta2) {
	s.reportSample(&r.RecordHeader, r.PidKey, int64(r.AllocWords), kindAlloc,
		samples.ValueKindAlloc,
		map[libpf.String]libpf.String{
			labelBinVheapDelta: fmtU64(r.BinVheapDeltaWords),
			labelMbufWords:     fmtU64(r.MbufWords),
			labelPauseNS:       fmtU64(r.PauseNS),
		})
}

// handleSchedDelta synthesizes one sample per SCHED_DELTA (0x0A) record:
// value = on_sched_ns (semantically correct for the cpu/nanoseconds slot).
// preempts/yields are omitted when the writer cannot classify.
func (s *reporterSink) handleSchedDelta(r *SchedDelta) {
	labels := map[libpf.String]libpf.String{
		labelNSwitches: fmtU64(uint64(r.NSwitches)),
	}
	if !r.ClassificationUnsupported {
		labels[labelPreempts] = fmtU64(uint64(r.Preempts))
		labels[labelYields] = fmtU64(uint64(r.Yields))
	}
	s.reportSample(&r.RecordHeader, r.PidKey, int64(r.OnSchedNS), kindSched,
		samples.ValueKindSchedNS, labels)
}

// handleMsgFlow synthesizes one sample per MSG_FLOW (0x0D) record. value is
// the caller-precomputed scaled arrival estimate: the drainer resolves the
// RecvSampleShift in force when the record was written (this sink has no
// access to the ScopeConfig state, which lives on the drainer) and only
// calls here when a config can support scaling. No kind-specific extras
// beyond the standard erlang_pid/beamscope_kind pair.
func (s *reporterSink) handleMsgFlow(r *MsgFlow, value int64) {
	s.reportSample(&r.RecordHeader, r.PidKey, value, kindMsg,
		samples.ValueKindMsgs, map[libpf.String]libpf.String{})
}

// beamTraceHash builds a stable trace hash for the synthesized single-frame
// stack. It must differ whenever the rendered stack differs, or downstream
// dedup would merge distinct stacks.
func beamTraceHash(osPid, pidKey uint64, name string) libpf.TraceHash {
	h := fnv.New128a()
	var b [16]byte
	binary.LittleEndian.PutUint64(b[0:], osPid)
	binary.LittleEndian.PutUint64(b[8:], pidKey)
	_, _ = h.Write(b[:])
	_, _ = h.Write([]byte(name))
	sum := h.Sum(nil)
	return libpf.NewTraceHash(binary.BigEndian.Uint64(sum[0:8]),
		binary.BigEndian.Uint64(sum[8:16]))
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
	// MsgFlowScaleSkipped is the running count of MSG_FLOW records for which
	// no pprof sample was synthesized because no retained SCOPE_CONFIG that
	// predates the record could support scaling (see
	// drainer.resolveRecvShift). Otherwise
	// unobservable outside a white-box test, same reasoning as HeldEvicted
	// above.
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
