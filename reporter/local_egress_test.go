// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The four combinations of the two local backends. They used to be three --
// socket-only was rejected at startup, because the socket sink was a field
// inside the pprof reporter and read its already-decoded sampleEvent. The decode
// now happens in the assembler, above both sinks, so each backend stands alone.

// waitForEmitted blocks until the socket sink has delivered n samples. Reports
// with no pprof Flush between them and Stop() otherwise race the writer
// goroutine's first dial: run() picks between a ready stop channel and a ready
// ring arm, and the drain deliberately does not dial, so everything produced
// would be charged to droppedNoSock.
func waitForEmitted(t *testing.T, s *socketSink, n uint64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for s.st.emitted.Load() < n {
		if time.Now().After(deadline) {
			t.Fatalf("socket emitted %d of %d samples", s.st.emitted.Load(), n)
		}
		time.Sleep(time.Millisecond)
	}
}

// Neither backend is a configuration error, not a silent no-op: a local egress
// that records nothing while looking like a reporter is the failure mode the
// whole design is meant to make impossible. Nothing is created and nothing is
// dialed, because nothing is constructed.
func TestLocalEgressRequiresAtLeastOneBackend(t *testing.T) {
	r, err := NewLocalEgress(LocalEgressConfig{SamplesPerSecond: 997})
	require.Error(t, err)
	assert.Nil(t, r)
	assert.Contains(t, err.Error(), "at least one backend")
}

// pprof only: files are written, and the socket is never dialed -- there is no
// socket sink at all, so nothing can reference one.
func TestLocalEgressPprofOnlyNeverTouchesTheSocket(t *testing.T) {
	dir := t.TempDir()
	r, err := NewLocalEgress(LocalEgressConfig{
		Dir: dir, SamplesPerSecond: 997, FlushInterval: time.Hour,
	})
	require.NoError(t, err)
	require.Nil(t, r.socket, "no socket sink may exist when the socket backend is off")
	require.NotNil(t, r.pprof)
	require.NoError(t, r.Start(t.Context()))

	tr := testTrace(t, "root", "leaf")
	for i := int64(0); i < 10; i++ {
		require.NoError(t, r.ReportTraceEvent(tr, meta(i, 100, 101, "c", "p", "x")))
	}
	require.NoError(t, r.Flush())
	r.Stop()

	assert.Len(t, readOne(t, dir).Sample, 10)
	assert.Zero(t, r.SocketDropped())

	// And the archive says nothing about a socket, because there is no stream
	// to cross-attest to.
	require.Nil(t, r.pprof.crossAttest,
		"cross-attestation is meaningless with one backend")
}

// socket only: records reach the consumer, and NO pprof file is produced. This
// is the combination that could not be expressed before.
func TestLocalEgressSocketOnlyWritesNoPprofFile(t *testing.T) {
	l := newListener(t)
	r, err := NewLocalEgress(LocalEgressConfig{
		SamplesPerSecond: 997,
		Socket:           SocketConfig{Path: l.path, StatsInterval: time.Hour},
	})
	require.NoError(t, err)
	require.Nil(t, r.pprof, "no pprof sink may exist when -pprof-dir is absent")
	require.NotNil(t, r.socket)
	require.NoError(t, r.Start(t.Context()))

	tr := testTrace(t, "root", "mid", "leaf")
	const n = 20
	for i := int64(0); i < n; i++ {
		require.NoError(t, r.ReportTraceEvent(tr,
			meta(5_000+i, 100, 101, "1_scheduler", "beam.smp", "cafe01")))
	}
	// Flush() is a no-op with no pprof backend, and must not be an error.
	// Nothing on the Reporter interface calls it -- the pprof sink drives its
	// own flush loop -- but it is exported, and "flush an egress that has no
	// file backend" has to mean "nothing to do", not an error a caller has to
	// special-case.
	require.NoError(t, r.Flush())
	waitForEmitted(t, r.socket, n)
	r.Stop()

	st := readStream(t, bytes.NewReader(l.readAll(t)))
	require.Len(t, st.samples, n)
	for i, s := range st.samples {
		assert.Equal(t, []string{"leaf", "mid", "root"}, s.funcs, "sample %d", i)
		assert.Equal(t, int64(5_000+i), s.ktime)
	}
	assert.Zero(t, r.Dropped(), "there is no pprof buffer to overflow")
	assert.Zero(t, r.SocketDropped())
	// The lineage cache is still consulted on the reporting path, not at a
	// flush that never happens: a socket-only run must not lose the property
	// that a short-lived process's lineage is read while it still exists.
	assert.NotNil(t, r.assembler.lineage)
}

// socket only, lossy: the loss signal must survive the absence of a pprof
// archive. With no file to carry a comment, STATS on the wire and Dropped() are
// the whole story, so both have to be right.
func TestLocalEgressSocketOnlyStillReportsLoss(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "absent.sock")
	r, err := NewLocalEgress(LocalEgressConfig{
		SamplesPerSecond: 997,
		Socket: SocketConfig{
			Path: sock, RingSize: 4, StatsInterval: time.Hour,
		},
	})
	require.NoError(t, err)
	require.NoError(t, r.Start(t.Context()))
	tr := testTrace(t, "root", "leaf")
	const n = 500
	for i := int64(0); i < n; i++ {
		require.NoError(t, r.ReportTraceEvent(tr, meta(i, 1, 2, "c", "p", "x")))
	}
	r.Stop()

	assert.Positive(t, r.SocketDropped(),
		"a socket-only run with no consumer must still count its loss")
	// Every produced sample is accounted for by exactly one channel.
	sk := r.socket
	assert.Equal(t, sk.st.produced.Load(),
		sk.st.emitted.Load()+sk.st.droppedRing.Load()+
			sk.st.droppedNoSock.Load()+sk.st.droppedWrite.Load())
	assert.Equal(t, uint64(n), sk.st.produced.Load())
	// And the summary the warning renders is non-empty, so the log carries it
	// even though no archive does.
	assert.NotEmpty(t, sk.dropSummaryIfLossy())
}

// both: ONE ReportTraceEvent reaches both backends, and the two outputs agree
// sample for sample. This is the fan-out property that used to be free (one
// struct held both) and now has to be maintained deliberately.
func TestLocalEgressBothBackendsSeeEveryEvent(t *testing.T) {
	l := newListener(t)
	dir := t.TempDir()
	r, err := NewLocalEgress(LocalEgressConfig{
		Dir: dir, SamplesPerSecond: 997, FlushInterval: time.Hour,
		Socket: SocketConfig{Path: l.path, StatsInterval: time.Hour},
	})
	require.NoError(t, err)
	require.NotNil(t, r.pprof)
	require.NotNil(t, r.socket)
	require.NotNil(t, r.pprof.crossAttest,
		"with both backends the archive must be able to attest to the stream")
	require.NoError(t, r.Start(t.Context()))

	tr := testTrace(t, "root", "mid", "leaf")
	const n = 32
	for i := int64(0); i < n; i++ {
		require.NoError(t, r.ReportTraceEvent(tr,
			meta(9_000+i, 100, 101, "1_scheduler", "beam.smp", "cafe01")))
	}
	require.NoError(t, r.Flush())
	waitForEmitted(t, r.socket, n)
	r.Stop()

	st := readStream(t, bytes.NewReader(l.readAll(t)))
	require.Len(t, st.samples, n)
	p := readOne(t, dir)
	require.Len(t, p.Sample, n, "the same events must land in both artifacts")
	assert.Zero(t, r.Dropped())
	assert.Zero(t, r.SocketDropped())

	for i, s := range p.Sample {
		var funcs []string
		for _, loc := range s.Location {
			funcs = append(funcs, loc.Line[0].Function.Name)
		}
		assert.Equal(t, st.samples[i].funcs, funcs,
			"sample %d: frame order must agree between the two backends", i)
		assert.Equal(t, st.samples[i].ktime, s.NumLabel[LabelKTimeNs][0], "sample %d", i)
		assert.Equal(t, int64(st.samples[i].pid), s.NumLabel[LabelPID][0], "sample %d", i)
		assert.Equal(t, st.samples[i].comm, s.Label[LabelComm][0], "sample %d", i)
	}
	// A lossless run says nothing about the socket in the archive; the loss
	// comment appears only when there is loss (TestSocketDropsInTheFinalDrain
	// ReachThePprofComment pins that direction).
	for _, c := range p.Comments {
		assert.NotContains(t, c, "socket egress dropped")
	}
}

// The two backends' budgets are INDEPENDENT: one sink's overflow must not cost
// the other a single record. This is the property that used to be free (there
// was one buffer) and is now only true because the fan-out in
// ReportTraceEvent keeps the sinks ignorant of each other. It was asserted
// nowhere -- re-coupling the sinks passed the whole suite -- so it is pinned in
// both directions here.
func TestLocalEgressBackendBudgetsAreIndependent(t *testing.T) {
	// A pprof buffer that overflows almost immediately must not truncate the
	// live stream a consumer is reading.
	t.Run("full pprof buffer costs the socket nothing", func(t *testing.T) {
		l := newListener(t)
		dir := t.TempDir()
		r, err := NewLocalEgress(LocalEgressConfig{
			Dir: dir, SamplesPerSecond: 997, FlushInterval: time.Hour,
			MaxBufferedSamples: 2,
			Socket:             SocketConfig{Path: l.path, StatsInterval: time.Hour},
		})
		require.NoError(t, err)
		require.NoError(t, r.Start(t.Context()))
		// Stop() is idempotent, and a failure below must not leave the sink
		// holding the listener's connection open: the listener's own cleanup
		// joins its read loop, which only returns when that connection closes.
		t.Cleanup(r.Stop)

		tr := testTrace(t, "root", "mid", "leaf")
		const n = 24
		for i := int64(0); i < n; i++ {
			require.NoError(t, r.ReportTraceEvent(tr,
				meta(7_000+i, 100, 101, "1_scheduler", "beam.smp", "cafe01")))
		}
		waitForEmitted(t, r.socket, n)
		require.NoError(t, r.Flush())
		r.Stop()

		assert.Positive(t, r.Dropped(), "MaxBufferedSamples=2 must overflow at n=24")
		assert.Zero(t, r.SocketDropped(),
			"a full pprof buffer must not drop a single socket record")

		st := readStream(t, bytes.NewReader(l.readAll(t)))
		require.Len(t, st.samples, n, "every sample must still reach the wire")
		for i, s := range st.samples {
			assert.Equal(t, int64(7_000+i), s.ktime, "sample %d", i)
		}
		// And the archive is the one that is short, by exactly what it dropped.
		assert.Len(t, readOne(t, dir).Sample, int(n-r.Dropped()))
	})

	// And the other way: a socket with nobody listening and a tiny ring drops
	// on the socket side only. The archive must be complete.
	t.Run("socket loss costs the pprof archive nothing", func(t *testing.T) {
		dir := t.TempDir()
		r, err := NewLocalEgress(LocalEgressConfig{
			Dir: dir, SamplesPerSecond: 997, FlushInterval: time.Hour,
			Socket: SocketConfig{
				Path:     filepath.Join(t.TempDir(), "absent.sock"),
				RingSize: 4, StatsInterval: time.Hour,
			},
		})
		require.NoError(t, err)
		require.NoError(t, r.Start(t.Context()))

		tr := testTrace(t, "root", "leaf")
		const n = 300
		for i := int64(0); i < n; i++ {
			require.NoError(t, r.ReportTraceEvent(tr, meta(i, 1, 2, "c", "p", "x")))
		}
		r.Stop()

		assert.Positive(t, r.SocketDropped(),
			"RingSize=4 with no consumer must overflow at n=300")
		assert.Zero(t, r.Dropped(), "socket loss must not drop a pprof sample")
		assert.Len(t, readOne(t, dir).Sample, n,
			"the archive must hold every sample the stream lost")
	})
}
