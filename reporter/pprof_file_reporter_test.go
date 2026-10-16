// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/pprof/profile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

func TestStopFlushesSamplesReceivedAfterContextCancellation(t *testing.T) {
	dir := t.TempDir()
	r, err := NewLocalEgress(LocalEgressConfig{Dir: dir, SamplesPerSecond: 100})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	require.NoError(t, r.Start(ctx))
	tr := testTrace(t, "worker")
	require.NoError(t, r.ReportTraceEvent(tr, meta(1, 1, 1, "worker", "app", "")))
	cancel()
	<-r.pprof.done
	require.NoError(t, r.ReportTraceEvent(tr, meta(2, 1, 1, "worker", "app", "")))
	r.Stop()

	paths, err := filepath.Glob(filepath.Join(dir, "*.pb.gz"))
	require.NoError(t, err)
	require.Len(t, paths, 2)
	for _, path := range paths {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		p, err := profile.ParseData(data)
		require.NoError(t, err)
		require.Len(t, p.Sample, 1)
	}
	require.Error(t, r.ReportTraceEvent(tr, meta(3, 1, 1, "worker", "app", "")))
}

func TestProfileWriteFailureCountsLostSamples(t *testing.T) {
	dir := t.TempDir()
	r, err := NewLocalEgress(LocalEgressConfig{Dir: dir, SamplesPerSecond: 100})
	require.NoError(t, err)
	tr := testTrace(t, "worker")
	require.NoError(t, r.ReportTraceEvent(tr, meta(1, 1, 1, "worker", "app", "")))
	require.NoError(t, os.Remove(dir))
	require.Error(t, r.Flush())
	require.Equal(t, uint64(1), r.Dropped())

	require.NoError(t, os.Mkdir(dir, 0o755))
	require.NoError(t, r.ReportTraceEvent(tr, meta(2, 1, 1, "worker", "app", "")))
	require.NoError(t, r.Flush())
	p := readOne(t, dir)
	require.Contains(t, strings.Join(p.Comments, "\n"), "dropped 1 samples")
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
}

func TestProfileFilesPreserveDefaultCreationPermissions(t *testing.T) {
	dir := t.TempDir()
	probe, err := os.Create(filepath.Join(dir, "permissions"))
	require.NoError(t, err)
	info, err := probe.Stat()
	require.NoError(t, err)
	require.NoError(t, probe.Close())
	require.NoError(t, os.Remove(probe.Name()))
	r, err := NewLocalEgress(LocalEgressConfig{Dir: dir, SamplesPerSecond: 100})
	require.NoError(t, err)
	require.NoError(t, r.ReportTraceEvent(testTrace(t, "worker"), meta(1, 1, 1, "worker", "app", "")))
	require.NoError(t, r.Flush())
	paths, err := filepath.Glob(filepath.Join(dir, "*.pb.gz"))
	require.NoError(t, err)
	require.Len(t, paths, 1)
	profileInfo, err := os.Stat(paths[0])
	require.NoError(t, err)
	require.Equal(t, info.Mode().Perm(), profileInfo.Mode().Perm())
}

func TestEventDrivenProfilesDoNotAddPeriodicCPUTime(t *testing.T) {
	dir := t.TempDir()
	r, err := NewLocalEgress(LocalEgressConfig{Dir: dir, SamplesPerSecond: 100})
	require.NoError(t, err)
	for _, typ := range []*samples.TypeMetadata{profileTypeSampling, profileTypeProbe, profileTypeOffCPU} {
		m := meta(1, 1, 1, "worker", "app", "")
		m.ProfileType = typ
		m.Value = 1234
		require.NoError(t, r.ReportTraceEvent(testTrace(t, "worker"), m))
	}
	require.NoError(t, r.Flush())
	p := readOne(t, dir)
	require.Len(t, p.Sample, 3)
	require.Equal(t, int64(10_000_000), p.Sample[0].Value[1])
	require.Zero(t, p.Sample[1].Value[1])
	require.Zero(t, p.Sample[2].Value[1])
	require.Equal(t, []int64{1234}, p.Sample[2].NumLabel[LabelOffTimeNs])
}

func testTrace(t *testing.T, names ...string) *libpf.Trace {
	t.Helper()
	tr := &libpf.Trace{}
	// Frames arrive leaf first from the tracer.
	for i, name := range slices.Backward(names) {
		tr.Frames.Append(&libpf.Frame{
			Type:            libpf.NativeFrame,
			FunctionName:    libpf.Intern(name),
			SourceFile:      libpf.Intern(name + ".erl"),
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
		Comm:           libpf.NewCommFromString(comm),
		ProcessName:    libpf.Intern(process),
		ExecutablePath: libpf.Intern("/usr/lib/erlang/bin/" + process),
		ContainerID:    libpf.Intern(container),
		PID:            pid,
		TID:            tid,
		CPU:            3,
		ProfileType:    profileTypeSampling,
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

func TestPprofFileReporterDoesNotAggregate(t *testing.T) {
	dir := t.TempDir()
	r, err := NewLocalEgress(LocalEgressConfig{Dir: dir, SamplesPerSecond: 1000})
	require.NoError(t, err)

	tr := testTrace(t, "caller", "callee")
	for i := range int64(5) {
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

func TestPprofFileReporterSeparatesCPUAndAllocColumns(t *testing.T) {
	dir := t.TempDir()
	r, err := NewLocalEgress(LocalEgressConfig{Dir: dir, SamplesPerSecond: 100})
	require.NoError(t, err)

	cpuMeta := meta(1, 1, 1, "c", "p", "k")
	require.NoError(t, r.ReportTraceEvent(testTrace(t, "a"), cpuMeta))

	allocMeta := meta(2, 1, 1, "c", "p", "k")
	allocMeta.Value = 12_345
	allocMeta.ProfileType = samples.BeamScopeProfile(samples.ValueKindAlloc)
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

func TestPprofFileReporterMsgSampleInColumnFour(t *testing.T) {
	dir := t.TempDir()
	r, err := NewLocalEgress(LocalEgressConfig{Dir: dir, SamplesPerSecond: 100})
	require.NoError(t, err)
	m := meta(1, 1, 1, "c", "p", "k")
	m.Value = 640
	m.ProfileType = samples.BeamScopeProfile(samples.ValueKindMsgs)
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

func TestPprofFileReporterReportsDrops(t *testing.T) {
	dir := t.TempDir()
	r, err := NewLocalEgress(LocalEgressConfig{Dir: dir, SamplesPerSecond: 100, MaxBufferedSamples: 2})
	require.NoError(t, err)
	tr := testTrace(t, "a")
	for i := range int64(5) {
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
	m.ProfileType = nil
	assert.ErrorIs(t, r.ReportTraceEvent(testTrace(t, "a"), m), errUnknownProfileType)
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
	require.Error(t, err, "a reporter with no directory cannot write anything")
	_, err = NewLocalEgress(LocalEgressConfig{Dir: t.TempDir()})
	assert.Error(t, err, "a zero sample rate would scale every value wrongly")
}

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
	var labeled, bare *profile.Sample
	for _, s := range p.Sample {
		if s.NumLabel[LabelKTimeNs][0] == 7_777 {
			labeled = s
		} else {
			bare = s
		}
	}
	require.NotNil(t, labeled)
	require.NotNil(t, bare)

	require.Contains(t, labeled.NumLabel, LabelErlangPidKey)
	assert.Equal(t, []int64{0xABCD}, labeled.NumLabel[LabelErlangPidKey])
	assert.Equal(t, []string{unitID}, labeled.NumUnit[LabelErlangPidKey])
	assert.NotContains(t, bare.NumLabel, LabelErlangPidKey,
		"a non-scheduler thread must carry no erlang_pid_key at all")
}

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
	m.ProfileType = samples.BeamScopeProfile(samples.ValueKindAlloc)
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

func TestOriginTableCoversAllThreeConsumers(t *testing.T) {
	for origin, want := range originTable {
		assert.Equal(t, want.name, originName(origin))
		assert.Equal(t, want.wire, socketOrigin(origin))
		assert.NotEqual(t, socketOriginUnknown, socketOrigin(origin),
			"a valid origin must have a wire byte of its own")
	}
	assert.Len(t, originTable, 4)
	unknown := sampleOrigin(200)
	assert.Equal(t, "origin_200", originName(unknown))
	assert.Equal(t, socketOriginUnknown, socketOrigin(unknown))
}
