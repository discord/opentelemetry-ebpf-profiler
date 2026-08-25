// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/pprof/profile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
)

func testTrace(t *testing.T, names ...string) *libpf.Trace {
	t.Helper()
	tr := &libpf.Trace{}
	// Frames arrive leaf first from the tracer.
	for i := len(names) - 1; i >= 0; i-- {
		tr.Frames.Append(&libpf.Frame{
			Type:            libpf.NativeFrame,
			FunctionName:    libpf.Intern(names[i]),
			SourceFile:      libpf.Intern(names[i] + ".erl"),
			SourceLine:      libpf.SourceLineno(10 + i),
			AddressOrLineno: libpf.AddressOrLineno(0x1000 + i),
		})
	}
	return tr
}

func meta(ktime int64, pid, tid libpf.PID, comm, process, container string) *samples.TraceEventMeta {
	return &samples.TraceEventMeta{
		Timestamp:      libpf.UnixTime64(1_700_000_000_000_000_000 + ktime),
		KTime:          ktime,
		Comm:           libpf.Intern(comm),
		ProcessName:    libpf.Intern(process),
		ExecutablePath: libpf.Intern("/usr/lib/erlang/bin/" + process),
		ContainerID:    libpf.Intern(container),
		PID:            pid,
		TID:            tid,
		CPU:            3,
		Origin:         support.TraceOriginSampling,
	}
}

func readOne(t *testing.T, dir string) *profile.Profile {
	t.Helper()
	entries, err := filepath.Glob(filepath.Join(dir, "*.pb.gz"))
	require.NoError(t, err)
	require.Len(t, entries, 1, "expected exactly one profile file")
	f, err := os.Open(entries[0])
	require.NoError(t, err)
	defer f.Close()
	p, err := profile.Parse(f)
	require.NoError(t, err)
	return p
}

// Identical stacks must stay separate samples: a window is defined by
// per-sample timestamps, so aggregation would make windows undefinable.
func TestPprofFileReporterDoesNotAggregate(t *testing.T) {
	dir := t.TempDir()
	r, err := NewLocalEgress(LocalEgressConfig{Dir: dir, SamplesPerSecond: 1000})
	require.NoError(t, err)

	tr := testTrace(t, "caller", "callee")
	for i := int64(0); i < 5; i++ {
		require.NoError(t, r.ReportTraceEvent(tr, meta(1_000+i, 100, 101, "erts_sched_1", "beam.smp", "abc123")))
	}
	require.NoError(t, r.Flush())

	p := readOne(t, dir)
	require.Len(t, p.Sample, 5, "five identical stacks must remain five samples")
	assert.Equal(t, int64(time.Second)/1000, p.Period)
	assert.Equal(t, "cpu", p.DefaultSampleType)

	seen := map[int64]bool{}
	for _, s := range p.Sample {
		require.Len(t, s.NumLabel[LabelKTimeNs], 1)
		seen[s.NumLabel[LabelKTimeNs][0]] = true
		assert.Equal(t, []int64{1, p.Period, 0, 0, 0}, s.Value)
	}
	assert.Len(t, seen, 5, "each sample must carry its own kernel timestamp")
}

// The whole label contract has to survive to the file, since nothing downstream
// can reconstruct a label that was never written.
func TestPprofFileReporterWritesTheLabelContract(t *testing.T) {
	dir := t.TempDir()
	r, err := NewLocalEgress(LocalEgressConfig{Dir: dir, SamplesPerSecond: 997})
	require.NoError(t, err)
	require.NoError(t, r.ReportTraceEvent(testTrace(t, "a", "b"),
		meta(4_242, 100, 102, "erts_dirty_cpu_1", "beam.smp", "container-xyz")))
	require.NoError(t, r.Flush())

	p := readOne(t, dir)
	require.Len(t, p.Sample, 1)
	s := p.Sample[0]

	assert.Equal(t, []int64{4_242}, s.NumLabel[LabelKTimeNs])
	assert.Equal(t, []string{"nanoseconds"}, s.NumUnit[LabelKTimeNs])
	assert.Equal(t, []int64{1_700_000_000_000_004_242}, s.NumLabel[LabelTimestampNs])
	assert.Equal(t, []int64{100}, s.NumLabel[LabelPID])
	assert.Equal(t, []int64{102}, s.NumLabel[LabelTID])
	assert.Equal(t, []int64{3}, s.NumLabel[LabelCPU])
	assert.Equal(t, []string{"erts_dirty_cpu_1"}, s.Label[LabelComm])
	assert.Equal(t, []string{"beam.smp"}, s.Label[LabelProcessName])
	assert.Equal(t, []string{"/usr/lib/erlang/bin/beam.smp"}, s.Label[LabelExecutable])
	assert.Equal(t, []string{"container-xyz"}, s.Label[LabelContainerID])
	assert.Equal(t, []string{"sampling"}, s.Label[LabelOrigin])

	// The kernel timestamp is not the wall-clock one: a consumer that confuses
	// them gets windows that are off by the boot offset.
	assert.NotEqual(t, s.NumLabel[LabelKTimeNs], s.NumLabel[LabelTimestampNs])
}

// /proc/PID/comm ends in a newline and process.GetProcessMeta interns it
// verbatim, so ProcessName arrives here as "beam.smp\n". Emitting that means
// every offline filter on the documented label value ("-process-name beam.smp")
// matches nothing, and a grouping key carries an embedded newline -- a silent
// empty result rather than an error. Trim at the seam where the contract is
// defined.
func TestPprofFileReporterTrimsProcessName(t *testing.T) {
	dir := t.TempDir()
	r, err := NewLocalEgress(LocalEgressConfig{Dir: dir, SamplesPerSecond: 997})
	require.NoError(t, err)
	m := meta(4_242, 100, 102, "erts_sched_3", "beam.smp", "container-xyz")
	m.ProcessName = libpf.Intern("beam.smp\n")
	require.NoError(t, r.ReportTraceEvent(testTrace(t, "a", "b"), m))
	require.NoError(t, r.Flush())

	p := readOne(t, dir)
	require.Len(t, p.Sample, 1)
	assert.Equal(t, []string{"beam.smp"}, p.Sample[0].Label[LabelProcessName])
}

// pprof stores stacks leaf first; the frames the tracer delivers are already in
// that order, and the file must preserve it so root-first folding is correct.
func TestPprofFileReporterPreservesStackOrder(t *testing.T) {
	dir := t.TempDir()
	r, err := NewLocalEgress(LocalEgressConfig{Dir: dir, SamplesPerSecond: 100})
	require.NoError(t, err)
	require.NoError(t, r.ReportTraceEvent(testTrace(t, "root", "middle", "leaf"),
		meta(1, 1, 1, "c", "p", "k")))
	require.NoError(t, r.Flush())

	p := readOne(t, dir)
	require.Len(t, p.Sample, 1)
	var names []string
	for _, loc := range p.Sample[0].Location {
		require.Len(t, loc.Line, 1)
		names = append(names, loc.Line[0].Function.Name)
	}
	assert.Equal(t, []string{"leaf", "middle", "root"}, names)
}

// An unsymbolized native frame still has to be distinguishable from another
// one, or unrelated stacks collapse together and coverage is overstated.
func TestPprofFileReporterNamesUnsymbolizedFrames(t *testing.T) {
	dir := t.TempDir()
	r, err := NewLocalEgress(LocalEgressConfig{Dir: dir, SamplesPerSecond: 100})
	require.NoError(t, err)

	for _, addr := range []libpf.AddressOrLineno{0x1111, 0x2222} {
		tr := &libpf.Trace{}
		tr.Frames.Append(&libpf.Frame{Type: libpf.NativeFrame, AddressOrLineno: addr})
		require.NoError(t, r.ReportTraceEvent(tr, meta(int64(addr), 1, 1, "c", "p", "k")))
	}
	require.NoError(t, r.Flush())

	p := readOne(t, dir)
	require.Len(t, p.Sample, 2)
	first := p.Sample[0].Location[0].Line[0].Function.Name
	second := p.Sample[1].Location[0].Line[0].Function.Name
	assert.NotEqual(t, first, second, "distinct addresses must not share a frame name")
	assert.Equal(t, "0x1111", first)
}

// TestPprofFileReporterSeparatesCPUAndAllocColumns pins the mixing bug dead:
// a CPU sample's period-ns value and a beamscope alloc sample's word count
// must land in their own SampleType columns, not share column 1.
func TestPprofFileReporterSeparatesCPUAndAllocColumns(t *testing.T) {
	dir := t.TempDir()
	r, err := NewLocalEgress(LocalEgressConfig{Dir: dir, SamplesPerSecond: 100})
	require.NoError(t, err)

	cpuMeta := meta(1, 1, 1, "c", "p", "k")
	require.NoError(t, r.ReportTraceEvent(testTrace(t, "a"), cpuMeta))

	allocMeta := meta(2, 1, 1, "c", "p", "k")
	allocMeta.Origin = support.TraceOriginBeamScope
	allocMeta.Value = 12_345
	allocMeta.ValueKind = samples.ValueKindAlloc
	require.NoError(t, r.ReportTraceEvent(testTrace(t, "a"), allocMeta))

	require.NoError(t, r.Flush())
	p := readOne(t, dir)
	require.Len(t, p.Sample, 2)

	require.Len(t, p.SampleType, 5)
	assert.Equal(t, "cpu", p.SampleType[1].Type)
	assert.Equal(t, "alloc", p.SampleType[2].Type)
	assert.Equal(t, "cpu", p.DefaultSampleType)

	var cpuColSum, allocValue int64
	for _, s := range p.Sample {
		require.Len(t, s.Value, 5)
		cpuColSum += s.Value[1]
		if s.Value[2] != 0 {
			allocValue = s.Value[2]
		}
	}
	assert.Equal(t, p.Period, cpuColSum,
		"alloc mass must not leak into the cpu column")
	assert.Equal(t, int64(12_345), allocValue)
}

// TestPprofFileReporterKeepsCustomLabelsForCPUOrigin: custom labels are not
// gated to beamscope any more (Task 8 needs them on every origin).
func TestPprofFileReporterKeepsCustomLabelsForCPUOrigin(t *testing.T) {
	dir := t.TempDir()
	r, err := NewLocalEgress(LocalEgressConfig{Dir: dir, SamplesPerSecond: 100})
	require.NoError(t, err)
	tr := testTrace(t, "a")
	tr.CustomLabels = map[libpf.String]libpf.String{
		libpf.Intern("x"): libpf.Intern("y"),
	}
	require.NoError(t, r.ReportTraceEvent(tr, meta(1, 1, 1, "c", "p", "k")))
	require.NoError(t, r.Flush())

	p := readOne(t, dir)
	require.Len(t, p.Sample, 1)
	assert.Equal(t, []string{"y"}, p.Sample[0].Label["x"])
}

// TestPprofFileReporterMsgSampleInColumnFour pins the msgs column and the
// "msg" beamscope_kind label value.
func TestPprofFileReporterMsgSampleInColumnFour(t *testing.T) {
	dir := t.TempDir()
	r, err := NewLocalEgress(LocalEgressConfig{Dir: dir, SamplesPerSecond: 100})
	require.NoError(t, err)
	m := meta(1, 1, 1, "c", "p", "k")
	m.Origin = support.TraceOriginBeamScope
	m.Value = 640
	m.ValueKind = samples.ValueKindMsgs
	tr := testTrace(t, "a")
	tr.CustomLabels = map[libpf.String]libpf.String{
		libpf.Intern("beamscope_kind"): libpf.Intern("msg"),
	}
	require.NoError(t, r.ReportTraceEvent(tr, m))
	require.NoError(t, r.Flush())

	p := readOne(t, dir)
	require.Len(t, p.Sample, 1)
	s := p.Sample[0]
	require.Len(t, s.Value, 5)
	assert.Equal(t, []int64{1, 0, 0, 0, 640}, s.Value)
	assert.Equal(t, []string{"msg"}, s.Label["beamscope_kind"])
}

func TestPprofFileReporterFiltersByPIDAndComm(t *testing.T) {
	dir := t.TempDir()
	r, err := NewLocalEgress(LocalEgressConfig{
		Dir:              dir,
		SamplesPerSecond: 100,
		KeepPIDs:         ParsePIDList([]int{100}),
	})
	require.NoError(t, err)
	tr := testTrace(t, "a")
	require.NoError(t, r.ReportTraceEvent(tr, meta(1, 100, 100, "keep", "p", "k")))
	require.NoError(t, r.ReportTraceEvent(tr, meta(2, 999, 999, "drop", "p", "k")))
	require.NoError(t, r.Flush())

	p := readOne(t, dir)
	require.Len(t, p.Sample, 1)
	assert.Equal(t, []int64{100}, p.Sample[0].NumLabel[LabelPID])

	dir2 := t.TempDir()
	r2, err := NewLocalEgress(LocalEgressConfig{
		Dir:              dir2,
		SamplesPerSecond: 100,
		KeepComms:        ParseCommList([]string{"erts_sched_1"}),
	})
	require.NoError(t, err)
	require.NoError(t, r2.ReportTraceEvent(tr, meta(1, 1, 1, "erts_sched_1", "p", "k")))
	require.NoError(t, r2.ReportTraceEvent(tr, meta(2, 1, 2, "erts_sched_2", "p", "k")))
	require.NoError(t, r2.Flush())
	p2 := readOne(t, dir2)
	require.Len(t, p2.Sample, 1)
	assert.Equal(t, []string{"erts_sched_1"}, p2.Sample[0].Label[LabelComm])
}

// Truncation must be visible in the artifact: a lossy window that reads as a
// quiet one is worse than an error.
func TestPprofFileReporterReportsDrops(t *testing.T) {
	dir := t.TempDir()
	r, err := NewLocalEgress(LocalEgressConfig{Dir: dir, SamplesPerSecond: 100, MaxBufferedSamples: 2})
	require.NoError(t, err)
	tr := testTrace(t, "a")
	for i := int64(0); i < 5; i++ {
		require.NoError(t, r.ReportTraceEvent(tr, meta(i+1, 1, 1, "c", "p", "k")))
	}
	assert.Equal(t, uint64(3), r.Dropped())
	require.NoError(t, r.Flush())

	p := readOne(t, dir)
	assert.Len(t, p.Sample, 2)
	require.NotEmpty(t, p.Comments)
	assert.Contains(t, p.Comments[0], "dropped 3 samples")
}

func TestPprofFileReporterRejectsUnknownOrigin(t *testing.T) {
	dir := t.TempDir()
	r, err := NewLocalEgress(LocalEgressConfig{Dir: dir, SamplesPerSecond: 100})
	require.NoError(t, err)
	m := meta(1, 1, 1, "c", "p", "k")
	m.Origin = libpf.Origin(200)
	assert.ErrorIs(t, r.ReportTraceEvent(testTrace(t, "a"), m), errUnknownOrigin)
}

func TestPprofFileReporterFlushWithNothingBufferedWritesNoFile(t *testing.T) {
	dir := t.TempDir()
	r, err := NewLocalEgress(LocalEgressConfig{Dir: dir, SamplesPerSecond: 100})
	require.NoError(t, err)
	require.NoError(t, r.Flush())
	entries, err := filepath.Glob(filepath.Join(dir, "*.pb.gz"))
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestNewPprofFileValidatesConfig(t *testing.T) {
	_, err := NewLocalEgress(LocalEgressConfig{SamplesPerSecond: 100})
	assert.Error(t, err, "a reporter with no directory cannot write anything")
	_, err = NewLocalEgress(LocalEgressConfig{Dir: t.TempDir()})
	assert.Error(t, err, "a zero sample rate would scale every value wrongly")
}

// Start/Stop must flush what is buffered, or the last window of a campaign is
// silently lost.
func TestPprofFileReporterStopFlushes(t *testing.T) {
	dir := t.TempDir()
	r, err := NewLocalEgress(LocalEgressConfig{Dir: dir, SamplesPerSecond: 100, FlushInterval: time.Hour})
	require.NoError(t, err)
	require.NoError(t, r.Start(t.Context()))
	require.NoError(t, r.ReportTraceEvent(testTrace(t, "a"), meta(1, 1, 1, "c", "p", "k")))
	r.Stop()

	p := readOne(t, dir)
	assert.Len(t, p.Sample, 1)
}

// google/pprof drops a numeric label that is both zero-valued and unit-less, so an
// unlabelled `cpu` silently loses every sample taken on CPU 0 -- ~1/16 of a 16-core
// box, arriving downstream as "no cpu label" rather than "cpu 0". A capture taken
// before the fix had distinct cpu values 1..15 with 0 absent and 95.3% coverage.
// The label survives a real round-trip only because it carries a unit.
func TestPprofFileReporterKeepsZeroValuedIdentifierLabels(t *testing.T) {
	dir := t.TempDir()
	r, err := NewLocalEgress(LocalEgressConfig{Dir: dir, SamplesPerSecond: 997})
	require.NoError(t, err)
	m := meta(4_242, 100, 102, "erts_sched_0", "beam.smp", "container-xyz")
	m.CPU = 0
	require.NoError(t, r.ReportTraceEvent(testTrace(t, "a", "b"), m))
	require.NoError(t, r.Flush())

	// readOne parses the written file, so this is a genuine encode/decode round
	// trip rather than an inspection of the in-memory profile.
	s := readOne(t, dir).Sample[0]
	require.Contains(t, s.NumLabel, LabelCPU, "cpu=0 must survive encoding")
	assert.Equal(t, []int64{0}, s.NumLabel[LabelCPU])
	assert.Equal(t, []string{unitID}, s.NumUnit[LabelCPU])
	assert.Equal(t, []string{unitID}, s.NumUnit[LabelPID])
	assert.Equal(t, []string{unitID}, s.NumUnit[LabelTID])
}

// Task 8: a CPU-origin sample whose tid mapped to a BEAM scheduler carries the
// raw Erlang pid term as a numeric label. It is the join key against every
// beam_scope JSONL record, so it must round-trip through the pprof encoder
// exactly -- including the high bits of a 64-bit Eterm -- and must carry a
// unit for the same reason `cpu` does.
func TestPprofFileReporterErlangPidKeyLabel(t *testing.T) {
	dir := t.TempDir()
	r, err := NewLocalEgress(LocalEgressConfig{Dir: dir, SamplesPerSecond: 997})
	require.NoError(t, err)

	m := meta(7_777, 100, 110, "1_scheduler", "beam.smp", "container-xyz")
	m.ErlangPidKey = 0xABCD
	require.NoError(t, r.ReportTraceEvent(testTrace(t, "a", "b"), m))

	// A sample from a thread that is not a scheduler carries no label at all:
	// an absent pid must never be reported as pid 0.
	plain := meta(7_778, 100, 111, "1_aux", "beam.smp", "container-xyz")
	require.NoError(t, r.ReportTraceEvent(testTrace(t, "a", "b"), plain))
	require.NoError(t, r.Flush())

	p := readOne(t, dir)
	require.Len(t, p.Sample, 2)
	var labelled, bare *profile.Sample
	for _, s := range p.Sample {
		if s.NumLabel[LabelKTimeNs][0] == 7_777 {
			labelled = s
		} else {
			bare = s
		}
	}
	require.NotNil(t, labelled)
	require.NotNil(t, bare)

	require.Contains(t, labelled.NumLabel, LabelErlangPidKey)
	assert.Equal(t, []int64{0xABCD}, labelled.NumLabel[LabelErlangPidKey])
	assert.Equal(t, []string{unitID}, labelled.NumUnit[LabelErlangPidKey])
	assert.NotContains(t, bare.NumLabel, LabelErlangPidKey,
		"a non-scheduler thread must carry no erlang_pid_key at all")
}

// The label is an unsigned Eterm travelling through pprof's signed num-label
// field. The observed OTP 25 term 0x278000004f3 does not exercise that, so
// this pins the carrier itself with the sign bit set: an int64 round trip must
// not corrupt or drop a single bit.
func TestPprofFileReporterErlangPidKeyHighBits(t *testing.T) {
	dir := t.TempDir()
	r, err := NewLocalEgress(LocalEgressConfig{Dir: dir, SamplesPerSecond: 997})
	require.NoError(t, err)

	const term = uint64(0xF278_0000_0000_04F3)
	m := meta(9_999, 100, 110, "1_scheduler", "beam.smp", "c")
	m.ErlangPidKey = term
	require.NoError(t, r.ReportTraceEvent(testTrace(t, "a"), m))
	require.NoError(t, r.Flush())

	s := readOne(t, dir).Sample[0]
	require.Contains(t, s.NumLabel, LabelErlangPidKey)
	assert.Equal(t, term, uint64(s.NumLabel[LabelErlangPidKey][0]))
}

// The kernel's comm for a BEAM main thread genuinely contains a trailing
// newline, so an untrimmed comm label splits one process into two when
// grouped. Threads the VM renamed via pthread_setname_np ("1_scheduler") do
// not carry it, which is why the problem shows up on exactly one thread per VM
// and is easy to miss.
func TestPprofFileReporterTrimsCommWhitespace(t *testing.T) {
	dir := t.TempDir()
	r, err := NewLocalEgress(LocalEgressConfig{Dir: dir, SamplesPerSecond: 997})
	require.NoError(t, err)

	require.NoError(t, r.ReportTraceEvent(testTrace(t, "a"),
		meta(1, 100, 100, "beam.smp\n", "beam.smp", "c")))
	require.NoError(t, r.ReportTraceEvent(testTrace(t, "a"),
		meta(2, 100, 110, "1_scheduler", "beam.smp", "c")))
	require.NoError(t, r.Flush())

	p := readOne(t, dir)
	require.Len(t, p.Sample, 2)
	seen := map[string]bool{}
	for _, s := range p.Sample {
		require.Len(t, s.Label[LabelComm], 1)
		seen[s.Label[LabelComm][0]] = true
	}
	assert.True(t, seen["beam.smp"], "comm must be trimmed, got %v", seen)
	assert.True(t, seen["1_scheduler"])
	assert.NotContains(t, seen, "beam.smp\n")
}

// KeepComms filters on the same string, so trimming has to happen before it or
// a caller passing "beam.smp" would silently match nothing for the main thread.
func TestPprofFileReporterKeepCommsMatchesTrimmedComm(t *testing.T) {
	dir := t.TempDir()
	r, err := NewLocalEgress(LocalEgressConfig{
		Dir: dir, SamplesPerSecond: 997,
		KeepComms: map[string]struct{}{"beam.smp": {}},
	})
	require.NoError(t, err)
	require.NoError(t, r.ReportTraceEvent(testTrace(t, "a"),
		meta(1, 100, 100, "beam.smp\n", "beam.smp", "c")))
	require.NoError(t, r.Flush())
	assert.Len(t, readOne(t, dir).Sample, 1)
}

// numLabelUnits names BEAMSCOPE's numeric custom labels. Once the custom-label
// loop stopped being gated to beamscope, it applied that mapping to every
// origin -- so an ordinary Go service that sets a pprof label called "preempts"
// (or yields, nswitches, pause_ns, mbuf_words) silently got a NUMERIC label
// with unit "count" instead of the string label it asked for.
func TestPprofFileReporterDoesNotRetypeCustomLabelsForNonBeamscopeOrigins(t *testing.T) {
	dir := t.TempDir()
	r, err := NewLocalEgress(LocalEgressConfig{Dir: dir, SamplesPerSecond: 100})
	require.NoError(t, err)

	cpu := testTrace(t, "a")
	cpu.CustomLabels = map[libpf.String]libpf.String{
		libpf.Intern("preempts"): libpf.Intern("17"),
	}
	require.NoError(t, r.ReportTraceEvent(cpu, meta(1, 1, 1, "c", "p", "k")))

	// The same key on a beamscope sample IS a number, and still becomes one.
	bs := testTrace(t, "a")
	bs.CustomLabels = map[libpf.String]libpf.String{
		libpf.Intern("preempts"): libpf.Intern("17"),
	}
	m := meta(2, 1, 1, "c", "p", "k")
	m.Origin = support.TraceOriginBeamScope
	require.NoError(t, r.ReportTraceEvent(bs, m))
	require.NoError(t, r.Flush())

	p := readOne(t, dir)
	require.Len(t, p.Sample, 2)
	var sampling, beamscope *profile.Sample
	for _, s := range p.Sample {
		if s.Label[LabelOrigin][0] == "beamscope" {
			beamscope = s
		} else {
			sampling = s
		}
	}
	require.NotNil(t, sampling)
	require.NotNil(t, beamscope)

	assert.Equal(t, []string{"17"}, sampling.Label["preempts"],
		"a non-beamscope custom label keeps the type its author gave it")
	assert.NotContains(t, sampling.NumLabel, "preempts")

	assert.Equal(t, []int64{17}, beamscope.NumLabel["preempts"])
	assert.Equal(t, []string{"count"}, beamscope.NumUnit["preempts"])
	assert.NotContains(t, beamscope.Label, "preempts")
}

// The custom-label loop runs after the contract labels are assigned, so an
// un-guarded loop lets the traced process overwrite this reporter's own values.
// A filter on `comm` or `origin` has to mean the kernel's comm and this
// reporter's origin, whatever a Go service puts in its pprof labels.
func TestPprofFileReporterCustomLabelsCannotOverwriteTheContract(t *testing.T) {
	dir := t.TempDir()
	r, err := NewLocalEgress(LocalEgressConfig{Dir: dir, SamplesPerSecond: 100})
	require.NoError(t, err)
	tr := testTrace(t, "a")
	tr.CustomLabels = map[libpf.String]libpf.String{
		libpf.Intern(LabelComm):        libpf.Intern("impostor"),
		libpf.Intern(LabelOrigin):      libpf.Intern("beamscope"),
		libpf.Intern(LabelContainerID): libpf.Intern("not-my-container"),
		libpf.Intern(LabelPID):         libpf.Intern("999"),
		libpf.Intern(LabelKTimeNs):     libpf.Intern("42"),
		// A key of its own still rides along.
		libpf.Intern("mine"): libpf.Intern("kept"),
	}
	require.NoError(t, r.ReportTraceEvent(tr, meta(7, 100, 101, "1_scheduler", "beam.smp", "c0ffee")))
	require.NoError(t, r.Flush())

	s := readOne(t, dir).Sample[0]
	assert.Equal(t, []string{"1_scheduler"}, s.Label[LabelComm])
	assert.Equal(t, []string{"sampling"}, s.Label[LabelOrigin])
	assert.Equal(t, []string{"c0ffee"}, s.Label[LabelContainerID])
	assert.Equal(t, []int64{100}, s.NumLabel[LabelPID])
	assert.Equal(t, []int64{7}, s.NumLabel[LabelKTimeNs])
	assert.Equal(t, []string{"kept"}, s.Label["mine"])
	// A skipped collision must not leave a stray string copy behind either.
	assert.NotContains(t, s.Label, LabelPID)
	assert.NotContains(t, s.Label, LabelKTimeNs)
}

// originTable is the single source of truth behind the validity check, the
// pprof origin label and the socket wire byte. A new origin that reaches only
// two of the three is the bug the table exists to prevent.
func TestOriginTableCoversAllThreeConsumers(t *testing.T) {
	for origin, want := range originTable {
		assert.Equal(t, want.name, originName(origin))
		assert.Equal(t, want.wire, socketOrigin(origin))
		assert.NotEqual(t, socketOriginUnknown, socketOrigin(origin),
			"a valid origin must have a wire byte of its own")
	}
	assert.Len(t, originTable, 4)
	unknown := libpf.Origin(200)
	assert.Equal(t, "origin_200", originName(unknown))
	assert.Equal(t, socketOriginUnknown, socketOrigin(unknown))
}
