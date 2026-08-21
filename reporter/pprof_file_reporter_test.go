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
	r, err := NewPprofFile(PprofFileConfig{Dir: dir, SamplesPerSecond: 1000})
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
		assert.Equal(t, []int64{1, p.Period}, s.Value)
	}
	assert.Len(t, seen, 5, "each sample must carry its own kernel timestamp")
}

// The whole label contract has to survive to the file, since nothing downstream
// can reconstruct a label that was never written.
func TestPprofFileReporterWritesTheLabelContract(t *testing.T) {
	dir := t.TempDir()
	r, err := NewPprofFile(PprofFileConfig{Dir: dir, SamplesPerSecond: 997})
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
	r, err := NewPprofFile(PprofFileConfig{Dir: dir, SamplesPerSecond: 997})
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
	r, err := NewPprofFile(PprofFileConfig{Dir: dir, SamplesPerSecond: 100})
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
	r, err := NewPprofFile(PprofFileConfig{Dir: dir, SamplesPerSecond: 100})
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

func TestPprofFileReporterFiltersByPIDAndComm(t *testing.T) {
	dir := t.TempDir()
	r, err := NewPprofFile(PprofFileConfig{
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
	r2, err := NewPprofFile(PprofFileConfig{
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
	r, err := NewPprofFile(PprofFileConfig{Dir: dir, SamplesPerSecond: 100, MaxBufferedSamples: 2})
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
	r, err := NewPprofFile(PprofFileConfig{Dir: dir, SamplesPerSecond: 100})
	require.NoError(t, err)
	m := meta(1, 1, 1, "c", "p", "k")
	m.Origin = libpf.Origin(200)
	assert.ErrorIs(t, r.ReportTraceEvent(testTrace(t, "a"), m), errUnknownOrigin)
}

func TestPprofFileReporterFlushWithNothingBufferedWritesNoFile(t *testing.T) {
	dir := t.TempDir()
	r, err := NewPprofFile(PprofFileConfig{Dir: dir, SamplesPerSecond: 100})
	require.NoError(t, err)
	require.NoError(t, r.Flush())
	entries, err := filepath.Glob(filepath.Join(dir, "*.pb.gz"))
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestNewPprofFileValidatesConfig(t *testing.T) {
	_, err := NewPprofFile(PprofFileConfig{SamplesPerSecond: 100})
	assert.Error(t, err, "a reporter with no directory cannot write anything")
	_, err = NewPprofFile(PprofFileConfig{Dir: t.TempDir()})
	assert.Error(t, err, "a zero sample rate would scale every value wrongly")
}

// Start/Stop must flush what is buffered, or the last window of a campaign is
// silently lost.
func TestPprofFileReporterStopFlushes(t *testing.T) {
	dir := t.TempDir()
	r, err := NewPprofFile(PprofFileConfig{Dir: dir, SamplesPerSecond: 100, FlushInterval: time.Hour})
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
	r, err := NewPprofFile(PprofFileConfig{Dir: dir, SamplesPerSecond: 997})
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
