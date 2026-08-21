// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package beamscope

// Whole-pipeline tests: a fixture segment is drained through a real drainer
// into (a) an in-memory reporter mock and (b) the JSONL sidecar, and further
// through the fork's PprofFileReporter to validate the pprof-side contract
// (origin name, value channel, custom labels). No live BEAM, no mmap: the
// drainer runs against an in-memory segment via the test constructor below.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/pprof/profile"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
)

// testPID is the OS pid the pipeline tests attach as. It matches the fixture
// segment header and names the JSONL sidecar file.
const testPID = libpf.PID(fixOSPid)

// mockReporter captures ReportTraceEvent calls.
type mockReporter struct {
	traces []*libpf.Trace
	metas  []*samples.TraceEventMeta
}

func (m *mockReporter) ReportTraceEvent(trace *libpf.Trace,
	meta *samples.TraceEventMeta) error {
	m.traces = append(m.traces, trace)
	metaCopy := *meta
	m.metas = append(m.metas, &metaCopy)
	return nil
}

// newTestDrainer is the pipeline test hook: a drainer wired to an in-memory
// segment instead of a mapped memfd.
func newTestDrainer(t *testing.T, seg *Segment, rep reporter.TraceReporter,
	jsonlDir string, pid libpf.PID) *drainer {
	t.Helper()
	return &drainer{
		pid:     pid,
		poll:    time.Millisecond,
		rep:     newReporterSink(rep, pid),
		jsonl:   newJSONLSink(jsonlDir, int(pid)),
		heldCap: defaultHeldCap,
		stopc:   make(chan struct{}),
		done:    make(chan struct{}),
		seg:     seg,
	}
}

// drainUntilSettled polls often enough that a record whose PROC_META never
// arrives ages out of the meta-settling hold and reaches the reporter with
// the fallback naming.
func drainUntilSettled(d *drainer) {
	for i := 0; i <= heldMaxCycles; i++ {
		d.drainOnce()
	}
}

// newPprofReporter returns a file reporter writing into a fresh temp dir,
// together with that dir. Tests flush by hand, so the interval is disabled.
func newPprofReporter(t *testing.T) (*reporter.PprofFileReporter, string) {
	t.Helper()
	dir := t.TempDir()
	rep, err := reporter.NewPprofFile(reporter.PprofFileConfig{
		Dir:              dir,
		SamplesPerSecond: 20, // required by the reporter; not meaningful here
		FlushInterval:    time.Hour,
	})
	if err != nil {
		t.Fatalf("NewPprofFile: %v", err)
	}
	return rep, dir
}

// soleProfile returns the path of the one profile file emitted into dir.
func soleProfile(t *testing.T, dir string) string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "profile-*.pb.gz"))
	if err != nil || len(files) != 1 {
		t.Fatalf("expected one emitted profile, got %v (%v)", files, err)
	}
	return files[0]
}

// parseProfile parses the one profile file emitted into dir.
func parseProfile(t *testing.T, dir string) *profile.Profile {
	t.Helper()
	fh, err := os.Open(soleProfile(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	prof, err := profile.Parse(fh)
	if err != nil {
		t.Fatalf("parsing pprof: %v", err)
	}
	return prof
}

// readJSONL flushes the sidecar and parses it into one map per line.
func readJSONL(t *testing.T, s *jsonlSink) []map[string]any {
	t.Helper()
	s.Flush()
	data := bytes.TrimSpace(mustReadFile(t, s.path))
	if len(data) == 0 {
		return nil
	}
	var out []map[string]any
	for _, line := range bytes.Split(data, []byte("\n")) {
		var obj map[string]any
		if err := json.Unmarshal(line, &obj); err != nil {
			t.Fatalf("bad JSONL line %q: %v", line, err)
		}
		out = append(out, obj)
	}
	return out
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return data
}

// fillAllTypes writes one record of every type, spread over both rings, with
// PROC_META arriving before the GC_DELTAs that reference it.
func fillAllTypes(t *testing.T, f *fixture) {
	t.Helper()
	f.mustWrite(t, 0, encProcMeta(tK, tU, 0x1001, 555, 2, "Elixir.MyApp.Worker", "run", "<0.101.0>"))
	f.mustWrite(t, 0, encProcMeta(tK, tU, 0x1002, 556, 1, "gen_server", "init", "<0.102.0>"))
	f.mustWrite(t, 0, encGCDelta(tK+10, tU+10, 0x1001, 40_000, 512, 6_765, 0))
	f.mustWrite(t, 0, encGCDelta(tK+20, tU+20, 0x1002, 20_000, 0, 10_946, 1))
	f.mustWrite(t, 0, encGCDelta(tK+30, tU+30, 0x9999, 5_000, 7, 233, 0)) // no PROC_META
	f.mustWrite(t, 1, encPanelTick(tK+40, tU+40, 7, 1000, 12, 350_000))
	f.mustWrite(t, 1, encPanelSample(tK+41, tU+41, 0x1001, 42, 65_536, 9_000, 100, -2, 0b011, 7))
	f.mustWrite(t, 1, encTopkSend(tK+42, tU+42, 0x1002, 12_345, 7, 0))
	f.mustWrite(t, 1, encMonitorEvent(tK+43, tU+43, 0x1001, 1, 250))
	f.mustWrite(t, 1, encProcExit(tK+44, tU+44, 0x1002, 2))
}

func TestPipelineToMockReporterAndJSONL(t *testing.T) {
	f := newFixture(t, 2, 4096)
	fillAllTypes(t, f)
	seg := f.mustSegment(t)

	mock := &mockReporter{}
	dir := t.TempDir()
	d := newTestDrainer(t, seg, mock, dir, testPID)

	// The 0x9999 GC record has no PROC_META, so meta-settling holds it for
	// heldMaxCycles polls before converting with the fallback.
	drainUntilSettled(d)

	// --- Reporter sink: three GC_DELTAs became three samples.
	if len(mock.traces) != 3 {
		t.Fatalf("reported %d traces, want 3", len(mock.traces))
	}
	wantNames := []string{
		"MyApp.Worker.run/2",    // Elixir formatting
		"gen_server:init/1",     // Erlang formatting
		"<beam_pid_key:0x9999>", // no PROC_META fallback
	}
	wantAlloc := []int64{40_000, 20_000, 5_000}
	wantErlPid := []string{"<0.101.0>", "<0.102.0>", ""}
	wantBinVheap := []string{"512", "0", "7"}
	for i, tr := range mock.traces {
		if len(tr.Frames) != 1 {
			t.Fatalf("trace %d has %d frames, want 1", i, len(tr.Frames))
		}
		fr := tr.Frames[0].Value()
		if fr.Type != libpf.BEAMFrame {
			t.Errorf("trace %d frame type %v, want BEAMFrame", i, fr.Type)
		}
		if got := fr.FunctionName.String(); got != wantNames[i] {
			t.Errorf("trace %d frame name %q, want %q", i, got, wantNames[i])
		}
		meta := mock.metas[i]
		if meta.Origin != support.TraceOriginBeamScope {
			t.Errorf("trace %d origin %v, want TraceOriginBeamScope", i, meta.Origin)
		}
		if meta.OffTime != wantAlloc[i] {
			t.Errorf("trace %d value (OffTime) %d, want %d", i, meta.OffTime, wantAlloc[i])
		}
		if meta.KTime != int64(tK+uint64(10*(i+1))) {
			t.Errorf("trace %d KTime %d, want %d", i, meta.KTime, tK+uint64(10*(i+1)))
		}
		if uint64(meta.Timestamp) != tU+uint64(10*(i+1)) {
			t.Errorf("trace %d Timestamp %d, want %d", i, meta.Timestamp, tU+uint64(10*(i+1)))
		}
		if meta.PID != testPID || meta.TID != testPID {
			t.Errorf("trace %d pid/tid %d/%d, want %d", i, meta.PID, meta.TID, testPID)
		}
		if got := tr.CustomLabels[labelBinVheapDelta].String(); got != wantBinVheap[i] {
			t.Errorf("trace %d bin_vheap_delta %q, want %q", i, got, wantBinVheap[i])
		}
		erlPid, hasErlPid := tr.CustomLabels[labelErlangPID]
		if wantErlPid[i] == "" {
			if hasErlPid {
				t.Errorf("trace %d has unexpected erlang_pid %q", i, erlPid.String())
			}
		} else if erlPid.String() != wantErlPid[i] {
			t.Errorf("trace %d erlang_pid %q, want %q", i, erlPid.String(), wantErlPid[i])
		}
	}
	// Distinct stacks must not share a trace hash.
	if mock.traces[0].Hash == mock.traces[1].Hash {
		t.Error("distinct stacks share a trace hash")
	}

	// --- JSONL sink: everything but GC_DELTA, one object per line.
	lines := readJSONL(t, d.jsonl)
	wantTypes := map[string]int{
		"proc_meta": 2, "panel_tick": 1, "panel_sample": 1,
		"topk_send": 1, "monitor_event": 1, "proc_exit": 1,
	}
	gotTypes := map[string]int{}
	for _, obj := range lines {
		typ, _ := obj["type"].(string)
		gotTypes[typ]++
		for _, key := range []string{"ktime_ns", "unix_ns", "pid"} {
			if _, ok := obj[key]; !ok {
				t.Errorf("JSONL %s line missing %q: %v", typ, key, obj)
			}
		}
	}
	for typ, n := range wantTypes {
		if gotTypes[typ] != n {
			t.Errorf("JSONL has %d %s lines, want %d (all: %v)",
				gotTypes[typ], typ, n, gotTypes)
		}
	}
	if gotTypes["gc_delta"] != 0 {
		t.Error("GC_DELTA leaked into the JSONL sidecar")
	}
	// Spot-check field fidelity on one line of each shape.
	for _, obj := range lines {
		switch obj["type"] {
		case "panel_sample":
			if obj["msgq_delta"].(float64) != -2 || obj["sample_flags"].(float64) != 3 {
				t.Errorf("panel_sample fields wrong: %v", obj)
			}
		case "monitor_event":
			if obj["kind"].(float64) != 1 || obj["value"].(float64) != 250 {
				t.Errorf("monitor_event fields wrong: %v", obj)
			}
		case "panel_tick":
			if obj["process_count"].(float64) != 350_000 {
				t.Errorf("panel_tick fields wrong: %v", obj)
			}
		case "proc_meta":
			if obj["pid_key"].(float64) == 0x1001 &&
				obj["module"].(string) != "Elixir.MyApp.Worker" {
				t.Errorf("proc_meta fields wrong: %v", obj)
			}
		}
	}

	// The file is plain greppable text: erlang pids come out literal, never
	// as encoding/json's default HTML escapes.
	raw := mustReadFile(t, d.jsonl.path)
	if !bytes.Contains(raw, []byte(`"pid_printable":"<0.101.0>"`)) {
		t.Error("JSONL does not contain a literal pid_printable <0.101.0>")
	}
	for _, esc := range []string{`\u003c`, `\u003e`, `\u0026`} {
		if bytes.Contains(raw, []byte(esc)) {
			t.Errorf("JSONL contains HTML escape %s", esc)
		}
	}

	// Shutdown closes cleanly (no mapped memory in the test hook).
	d.shutdown()
}

// TestDrainStatsJSONLEmission pins the drop-observability contract: the first
// drain after attach emits a reader-synthesized drain_stats line carrying the
// writer's counters as it found them (the pre-attach drops), further lines
// appear only when the counters change, and per-ring totals are included.
func TestDrainStatsJSONLEmission(t *testing.T) {
	f := newFixture(t, 2, 4096)
	// Pre-attach: the writer dropped 7 records on ring 0 before any reader
	// existed.
	f.setDropped(0, 7)
	f.mustWrite(t, 1, encPanelTick(tK, tU, 1, 10, 2, 100))
	seg := f.mustSegment(t)

	d := newTestDrainer(t, seg, &mockReporter{}, t.TempDir(), testPID)

	readStats := func() []map[string]any {
		t.Helper()
		var out []map[string]any
		for _, obj := range readJSONL(t, d.jsonl) {
			if obj["type"] == "drain_stats" {
				out = append(out, obj)
			}
		}
		return out
	}

	// First drain: one drain_stats line with the pre-attach counters.
	d.drainOnce()
	stats := readStats()
	if len(stats) != 1 {
		t.Fatalf("after first drain: %d drain_stats lines, want 1", len(stats))
	}
	first := stats[0]
	if first["dropped_total"].(float64) != 7 || first["source"] != "reader" {
		t.Fatalf("first drain_stats wrong: %v", first)
	}
	byRing := first["dropped_by_ring"].(map[string]any)
	if byRing["0"].(float64) != 7 || len(byRing) != 1 {
		t.Fatalf("dropped_by_ring wrong: %v", byRing)
	}
	if first["nrings"].(float64) != 2 || first["records_total"].(float64) != 1 {
		t.Fatalf("stats fields wrong: %v", first)
	}
	for _, key := range []string{"ktime_ns", "unix_ns"} {
		if v, ok := first[key].(float64); !ok || v <= 0 {
			t.Fatalf("drain_stats missing %s: %v", key, first)
		}
	}

	// Unchanged counters: no new line.
	d.drainOnce()
	if stats = readStats(); len(stats) != 1 {
		t.Fatalf("unchanged drain emitted a line: %d lines", len(stats))
	}

	// The writer drops more (this time on the overflow ring): a new line
	// with the new totals.
	f.setDropped(1, 3)
	d.drainOnce()
	stats = readStats()
	if len(stats) != 2 {
		t.Fatalf("after drop-count change: %d drain_stats lines, want 2", len(stats))
	}
	second := stats[1]
	if second["dropped_total"].(float64) != 10 {
		t.Fatalf("second drain_stats total = %v, want 10", second["dropped_total"])
	}
	byRing = second["dropped_by_ring"].(map[string]any)
	if byRing["0"].(float64) != 7 || byRing["1"].(float64) != 3 {
		t.Fatalf("second dropped_by_ring wrong: %v", byRing)
	}
	d.shutdown()
}

func TestPipelineThroughPprofFileReporter(t *testing.T) {
	f := newFixture(t, 2, 4096)
	fillAllTypes(t, f)
	seg := f.mustSegment(t)

	rep, dir := newPprofReporter(t)
	d := newTestDrainer(t, seg, rep, "", testPID)
	drainUntilSettled(d) // the meta-less 0x9999 record needs the full hold
	if err := rep.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	prof := parseProfile(t, dir)
	if err := prof.CheckValid(); err != nil {
		t.Fatalf("invalid pprof: %v", err)
	}
	if len(prof.Sample) != 3 {
		t.Fatalf("profile has %d samples, want 3", len(prof.Sample))
	}
	// The value channel is alloc_words; the custom labels survived the pprof
	// path (erlang_pid only where a PROC_META was known).
	wantValues := map[int64]bool{40_000: true, 20_000: true, 5_000: true}
	var sawErlangPid, sawBinVheap int
	for _, s := range prof.Sample {
		if got := s.Label["origin"]; len(got) != 1 || got[0] != "beamscope" {
			t.Errorf("sample origin label %v, want [beamscope]", got)
		}
		if _, has := s.NumLabel["off_time_ns"]; has {
			t.Errorf("beamscope sample still carries off_time_ns")
		}
		if len(s.NumLabel["ktime_ns"]) != 1 {
			t.Errorf("sample missing ktime_ns label")
		}
		if len(s.Value) != 2 || s.Value[0] != 1 {
			t.Fatalf("sample values %v, want [1 alloc_words]", s.Value)
		}
		if !wantValues[s.Value[1]] {
			t.Errorf("unexpected sample value %d", s.Value[1])
		}
		if len(s.Label["erlang_pid"]) == 1 {
			sawErlangPid++
		}
		if len(s.Label["bin_vheap_delta"]) == 1 {
			sawBinVheap++
		}
	}
	if sawErlangPid != 2 { // the 0x9999 sample has no PROC_META
		t.Errorf("erlang_pid on %d samples, want 2", sawErlangPid)
	}
	if sawBinVheap != 3 {
		t.Errorf("bin_vheap_delta on %d samples, want 3", sawBinVheap)
	}
	// Note: rep.Stop() is not called: it waits for the flush goroutine that
	// only exists after Start(), which this test never runs.
}

// fillV2Types writes the v2-era records: GC_DELTA2 before and after a
// proc_lib-translated PROC_META re-emit, SCHED_DELTA with and without
// classification, and SCHED_UTIL with and without msacc.
func fillV2Types(t *testing.T, f *fixture) {
	t.Helper()
	f.mustWrite(t, 0, encProcMeta(tK, tU, 0x2001, 555, 5, "proc_lib", "init_p", "<0.201.0>"))
	f.mustWrite(t, 0, encGCDelta2(tK+10, tU+10, 0x2001, 30_000, 5, 700, 6_765, 120_000, 0))
	// The writer learned the real callback module: the re-emit REPLACES the
	// cached entry.
	f.mustWrite(t, 0, encProcMetaF(procMetaFlagTranslated, tK+15, tU+15, 0x2001, 555, 1,
		"Elixir.MyApp.Server", "init", "<0.201.0>"))
	f.mustWrite(t, 0, encGCDelta2(tK+20, tU+20, 0x2001, 31_000, 6, 800, 10_946, 130_000, 1))
	f.mustWrite(t, 0, encSchedDelta(0, tK+30, tU+30, 0x2001, 5_000_000, 12, 3, 9))
	f.mustWrite(t, 0, encSchedDelta(schedDeltaFlagUnclassified, tK+40, tU+40,
		0x2001, 2_000_000, 4, 0, 0))
	f.mustWrite(t, 1, encSchedUtil(schedUtilFlagMsaccValid, tK+50, tU+50, 3, 1, 42,
		800_000, 1_000_000, 500_000, 100_000, 50_000, 200_000, 150_000))
	f.mustWrite(t, 1, encSchedUtil(0, tK+51, tU+51, 1, 0, 42, 800_000, 1_000_000, 0, 0, 0, 0, 0))
}

func TestPipelineV2Types(t *testing.T) {
	f := newFixture(t, 2, 4096)
	fillV2Types(t, f)
	seg := f.mustSegment(t)

	mock := &mockReporter{}
	d := newTestDrainer(t, seg, mock, t.TempDir(), testPID)
	d.drainOnce()

	if len(mock.traces) != 4 {
		t.Fatalf("reported %d traces, want 4", len(mock.traces))
	}
	type want struct {
		frame string
		kind  string
		value int64
	}
	wants := []want{
		{"proc_lib:init_p/5", "alloc", 30_000},      // before translation
		{"MyApp.Server.init/1", "alloc", 31_000},    // PROC_META replaced
		{"MyApp.Server.init/1", "sched", 5_000_000}, // classified
		{"MyApp.Server.init/1", "sched", 2_000_000}, // unclassified
	}
	for i, wt := range wants {
		tr, meta := mock.traces[i], mock.metas[i]
		if got := tr.Frames[0].Value().FunctionName.String(); got != wt.frame {
			t.Errorf("trace %d frame %q, want %q", i, got, wt.frame)
		}
		if got := tr.CustomLabels[labelBeamscopeKind].String(); got != wt.kind {
			t.Errorf("trace %d beamscope_kind %q, want %q", i, got, wt.kind)
		}
		if meta.OffTime != wt.value {
			t.Errorf("trace %d value %d, want %d", i, meta.OffTime, wt.value)
		}
	}
	// GC_DELTA2 extras.
	gc2 := mock.traces[1].CustomLabels
	if gc2[labelMbufWords].String() != "800" || gc2[labelPauseNS].String() != "130000" {
		t.Errorf("gc_delta2 labels wrong: %v", gc2)
	}
	if gc2[labelBinVheapDelta].String() != "6" {
		t.Errorf("gc_delta2 bin_vheap_delta wrong: %v", gc2)
	}
	// SCHED_DELTA classification handling.
	sched := mock.traces[2].CustomLabels
	if sched[labelNSwitches].String() != "12" || sched[labelPreempts].String() != "3" ||
		sched[labelYields].String() != "9" {
		t.Errorf("classified sched labels wrong: %v", sched)
	}
	unclassified := mock.traces[3].CustomLabels
	if unclassified[labelNSwitches].String() != "4" {
		t.Errorf("unclassified sched nswitches wrong: %v", unclassified)
	}
	if _, has := unclassified[labelPreempts]; has {
		t.Error("unclassified sched sample carries preempts")
	}
	if _, has := unclassified[labelYields]; has {
		t.Error("unclassified sched sample carries yields")
	}
	// Distinct kinds on the same process must not share a trace hash.
	if mock.traces[1].Hash == mock.traces[2].Hash {
		t.Error("alloc and sched samples share a trace hash")
	}

	// SCHED_UTIL goes to JSONL (and only there); GC_DELTA2/SCHED_DELTA do not.
	var utils []map[string]any
	for _, obj := range readJSONL(t, d.jsonl) {
		switch obj["type"] {
		case "sched_util":
			utils = append(utils, obj)
		case "gc_delta2", "sched_delta":
			t.Errorf("%s leaked into the JSONL sidecar", obj["type"])
		}
	}
	if len(utils) != 2 {
		t.Fatalf("JSONL has %d sched_util lines, want 2", len(utils))
	}
	if utils[0]["msacc_valid"] != true || utils[0]["emulator_ns"].(float64) != 500_000 {
		t.Errorf("msacc-valid sched_util wrong: %v", utils[0])
	}
	if utils[1]["msacc_valid"] != false || utils[1]["active_ns"].(float64) != 800_000 {
		t.Errorf("msacc-invalid sched_util wrong: %v", utils[1])
	}
	for i, u := range utils {
		for _, key := range []string{"ktime_ns", "unix_ns", "pid"} {
			if _, ok := u[key]; !ok {
				t.Errorf("sched_util %d missing %q: %v", i, key, u)
			}
		}
	}
	d.shutdown()
}

// TestPipelineV2ThroughPprofFileReporter validates the v2 pprof contract:
// beamscope_kind separates the populations, sched samples carry on_sched_ns
// in the value slot, and the numeric extras are num labels with units.
func TestPipelineV2ThroughPprofFileReporter(t *testing.T) {
	f := newFixture(t, 2, 4096)
	fillV2Types(t, f)
	seg := f.mustSegment(t)

	rep, dir := newPprofReporter(t)
	d := newTestDrainer(t, seg, rep, "", testPID)
	d.drainOnce()
	if err := rep.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	prof := parseProfile(t, dir)

	kinds := map[string][]int64{} // kind -> values
	for _, s := range prof.Sample {
		if got := s.Label["origin"]; len(got) != 1 || got[0] != "beamscope" {
			t.Fatalf("sample origin %v, want beamscope", got)
		}
		kind := s.Label["beamscope_kind"]
		if len(kind) != 1 {
			t.Fatalf("sample missing beamscope_kind: %v", s.Label)
		}
		kinds[kind[0]] = append(kinds[kind[0]], s.Value[1])

		switch kind[0] {
		case "alloc":
			if len(s.NumLabel["mbuf_words"]) != 1 || len(s.NumLabel["pause_ns"]) != 1 {
				t.Errorf("alloc sample missing num labels: %v", s.NumLabel)
			}
			if u := s.NumUnit["pause_ns"]; len(u) != 1 || u[0] != "nanoseconds" {
				t.Errorf("pause_ns unit wrong: %v", s.NumUnit)
			}
			if len(s.Label["bin_vheap_delta"]) != 1 {
				t.Errorf("alloc sample lost string label bin_vheap_delta: %v", s.Label)
			}
		case "sched":
			if len(s.NumLabel["nswitches"]) != 1 {
				t.Errorf("sched sample missing nswitches num label: %v", s.NumLabel)
			}
		}
	}
	if len(kinds["alloc"]) != 2 || len(kinds["sched"]) != 2 {
		t.Fatalf("kind separation wrong: %v", kinds)
	}
	schedVals := map[int64]bool{}
	for _, v := range kinds["sched"] {
		schedVals[v] = true
	}
	if !schedVals[5_000_000] || !schedVals[2_000_000] {
		t.Errorf("sched value slot does not carry on_sched_ns: %v", kinds["sched"])
	}
}

// TestRecordedFixtureV2 decodes the writer peer's v2 recorded segment
// (GC_DELTA2/SCHED_UTIL/SCHED_DELTA era) once it lands; skips until then.
func TestRecordedFixtureV2(t *testing.T) {
	seg := loadRecordedSegment(t, "BEAMSCOPE_FIXTURE_V2", "shm_v2.bin")
	recs, st := collect(seg)
	if st.CorruptRings != 0 {
		t.Errorf("v2 fixture has %d corrupt rings", st.CorruptRings)
	}
	if st.Unknown != 0 {
		t.Errorf("v2 fixture has %d unknown/truncated records", st.Unknown)
	}
	byType := map[string]int{}
	var translatedTestServer bool
	var msaccValid, nonzeroEmulator int
	for _, r := range recs {
		byType[r.TypeName()]++
		switch rec := r.(type) {
		case *ProcMeta:
			if rec.Translated && rec.Module == "Elixir.BeamScope.Test.Workloads.TestServer" {
				translatedTestServer = true
			}
		case *SchedDelta:
			// Writer verdict: preempt/yield classification is not feasible on
			// OTP 24/25, so every record must say so.
			if !rec.ClassificationUnsupported {
				t.Errorf("sched_delta without classification_unsupported: %+v", rec)
			}
			if rec.Preempts != 0 || rec.Yields != 0 {
				t.Errorf("unclassified sched_delta carries counters: %+v", rec)
			}
		case *SchedUtil:
			if rec.MsaccValid {
				msaccValid++
				if rec.EmulatorNS > 0 {
					nonzeroEmulator++
				}
			}
		}
	}
	// msacc was enabled for the whole recording (every record flagged valid)
	// and genuinely produced data (busy schedulers show emulator time). NOTE:
	// "every msacc-valid record has nonzero emulator_ns" is deliberately NOT
	// asserted — this fixture disproves it: idle schedulers (all the dirty-IO
	// ones, and normal schedulers on quiet ticks) correctly report
	// emulator_ns == 0 with sleep_ns ~= total_ns. 5 of 62 are nonzero here.
	if msaccValid != byType["sched_util"] {
		t.Errorf("only %d of %d sched_util records are msacc-valid",
			msaccValid, byType["sched_util"])
	}
	if nonzeroEmulator == 0 {
		t.Error("no msacc-valid sched_util carries nonzero emulator_ns")
	}
	// Writer ground truth for this exact fixture.
	for typ, want := range map[string]int{
		"gc_delta2":   20,
		"sched_util":  62,
		"sched_delta": 5,
		"gc_delta":    0, // v2 writers emit 0x08, never 0x01
	} {
		if byType[typ] != want {
			t.Errorf("v2 fixture has %d %s records, want %d", byType[typ], typ, want)
		}
	}
	if !translatedTestServer {
		t.Error("v2 fixture has no translated PROC_META for " +
			"Elixir.BeamScope.Test.Workloads.TestServer")
	}
	t.Logf("v2 recorded fixture: %d records %v, %d pads, %d dropped",
		len(recs), byType, st.Padding, st.Dropped)
}

// TestRecordedFixture decodes a segment recorded from a real BEAM by the
// beam_scope shmdump tool, when present. The default path is the monorepo
// handoff location; override with BEAMSCOPE_FIXTURE.
func TestRecordedFixture(t *testing.T) {
	seg := loadRecordedSegment(t, "BEAMSCOPE_FIXTURE", "shm_v1.bin")
	recs, st := collect(seg)
	if st.CorruptRings != 0 {
		t.Errorf("recorded fixture has %d corrupt rings", st.CorruptRings)
	}
	if st.Unknown != 0 {
		t.Errorf("recorded fixture has %d unknown/truncated records", st.Unknown)
	}
	if st.Dropped != 0 {
		t.Errorf("recorded fixture reports %d writer drops, want 0", st.Dropped)
	}
	// Gate: the writer's shmdump re-read of this exact file decoded 196
	// records across all 7 types.
	const wantRecords = 196
	if len(recs) != wantRecords {
		t.Errorf("decoded %d records, want %d", len(recs), wantRecords)
	}
	byType := map[string]int{}
	for _, r := range recs {
		byType[r.TypeName()]++
	}
	for _, typ := range []string{"gc_delta", "proc_meta", "proc_exit",
		"panel_sample", "topk_send", "monitor_event", "panel_tick"} {
		if byType[typ] == 0 {
			t.Errorf("recorded fixture has no %s records", typ)
		}
	}
	t.Logf("recorded fixture: %d records %v, %d pads, %d unknown, %d dropped",
		len(recs), byType, st.Padding, st.Unknown, st.Dropped)
}
