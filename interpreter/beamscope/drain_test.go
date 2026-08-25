// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package beamscope

// Drainer-lifecycle tests: panic containment (FIX-3), permanent-activation
// parking (FIX-5) and PROC_EXIT meta-cache eviction (FIX-6). These exercise
// the drainer against in-memory segments and a fake remote memory, no live
// BEAM.

import (
	"encoding/binary"
	"io"
	"math"
	"testing"
	"time"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

// panicReporter panics on every reported sample, standing in for a residual
// panic anywhere on the drain path (which parses another process's memory).
type panicReporter struct{}

func (panicReporter) ReportTraceEvent(*libpf.Trace, *samples.TraceEventMeta) error {
	panic("beamscope test: induced drain-path panic")
}

// TestDrainGoroutineRecoversFromPanic is FIX-3: a panic in the per-PID drain
// goroutine must unwind only that PID's drain (park it, release it) and never
// take down host-wide profiling. Before the recover, the goroutine had no
// backstop and the panic would crash the whole profiler process.
func TestDrainGoroutineRecoversFromPanic(t *testing.T) {
	f := newFixture(t, 1, 4096)
	// PROC_META first so the GC_DELTA is reported immediately (not held),
	// reaching the panicking reporter within the drain pass.
	f.mustWrite(t, 0, encProcMeta(tK, tU, 0x1, 0, 0, "Elixir.App", "run", "<0.1.0>"))
	f.mustWrite(t, 0, encGCDelta(tK, tU, 0x1, 100, 0, 50, 0))
	seg := f.mustSegment(t)

	d := newTestDrainer(t, seg, panicReporter{}, "", testPID)
	go d.run()

	select {
	case <-d.done:
	case <-time.After(2 * time.Second):
		t.Fatal("drain goroutine did not unwind after a panic")
	}
	// done is closed only after recoverPanic ran, so this read is ordered.
	if !d.dead {
		t.Fatal("drainer not marked dead after a panic")
	}
}

// fakeReaderAt serves fixed bytes as a process's virtual memory, so
// tryActivate can be driven without a live BEAM.
type fakeReaderAt struct{ data []byte }

func (r fakeReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(r.data)) {
		return 0, io.EOF
	}
	n := copy(p, r.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func exportBytes(magic uint64, version, flags uint32) []byte {
	raw := make([]byte, exportStructSize)
	binary.LittleEndian.PutUint64(raw[0:], magic)
	binary.LittleEndian.PutUint32(raw[8:], version)
	binary.LittleEndian.PutUint32(raw[12:], flags)
	binary.LittleEndian.PutUint32(raw[16:], 0) // memfd (unused: we fail earlier)
	binary.LittleEndian.PutUint32(raw[20:], segmentHeaderSize)
	return raw
}

func newActivationDrainer(export []byte) *drainer {
	return &drainer{
		pid:        testPID,
		rm:         remotememory.RemoteMemory{ReaderAt: fakeReaderAt{export}},
		exportAddr: 0,
		rep:        newReporterSink(&mockReporter{}, testPID),
		jsonl:      newJSONLSink("", int(testPID)),
	}
}

// TestTryActivatePermanentFailureParksDrainer is FIX-5: a permanently
// malformed export (bad magic/version) must set dead so the drainer stops
// re-running readlink/open/fstat/mmap every poll for the life of the process.
// A transient not-ready export must NOT park it.
func TestTryActivatePermanentFailureParksDrainer(t *testing.T) {
	t.Run("bad magic parks", func(t *testing.T) {
		d := newActivationDrainer(exportBytes(0xdeadbeefdeadbeef, exportVersion, 0))
		if d.tryActivate() {
			t.Fatal("tryActivate reported success on a bad-magic export")
		}
		if !d.dead {
			t.Fatal("drainer not parked (dead) on a permanent (bad-magic) failure")
		}
	})

	t.Run("bad version parks", func(t *testing.T) {
		d := newActivationDrainer(exportBytes(segmentMagic, exportVersion+1, 0))
		if d.tryActivate() {
			t.Fatal("tryActivate reported success on a bad-version export")
		}
		if !d.dead {
			t.Fatal("drainer not parked on a permanent (bad-version) failure")
		}
	})

	t.Run("not-ready does not park", func(t *testing.T) {
		// Valid magic/version but flags bit0 (segment initialized) is clear:
		// the writer has not run BeamScope.start yet. Transient; keep retrying.
		d := newActivationDrainer(exportBytes(segmentMagic, exportVersion, 0))
		if d.tryActivate() {
			t.Fatal("tryActivate reported success on an uninitialized segment")
		}
		if d.dead {
			t.Fatal("drainer parked on a transient not-ready export")
		}
	})
}

// TestReporterMetaCacheEvictedOnProcExit is FIX-6: PROC_EXIT must evict the
// pprof sink's pid_key->meta cache. Without it the cache leaks one entry per
// exited pid; under process churn it grows without bound.
func TestReporterMetaCacheEvictedOnProcExit(t *testing.T) {
	f := newFixture(t, 2, 4096)
	seg := f.mustSegment(t)
	d := newTestDrainer(t, seg, &mockReporter{}, "", testPID)

	const churn = 200
	maxCache := 0
	for i := 0; i < churn; i++ {
		pk := uint64(0x1000 + i)
		// Spawn: PROC_META then a GC_DELTA (reported immediately, since meta is
		// cached in the same pass), then PROC_EXIT.
		f.mustWrite(t, 0, encProcMeta(tK, tU, pk, 0, 0, "Elixir.App.Worker", "run", "<0.1.0>"))
		f.mustWrite(t, 0, encGCDelta(tK, tU, pk, 100, 0, 50, 0))
		f.mustWrite(t, 0, encProcExit(tK, tU, pk, 0))
		drainUntilSettled(d)
		if n := len(d.rep.metaCache); n > maxCache {
			maxCache = n
		}
	}

	if got := len(d.rep.metaCache); got != 0 {
		t.Fatalf("metaCache holds %d entries after churn of %d pids; want 0 (leak)",
			got, churn)
	}
	if maxCache > 4 {
		t.Fatalf("metaCache peaked at %d entries during churn; not bounded", maxCache)
	}
}

// TestLatestScopeConfigSelectedByMaxKtimeAcrossRings pins the ABI.md rule:
// latestConfig is selected by MAX ktime_ns ACROSS ALL RINGS, not by which
// record the drainer happened to process most recently. Ring 2's config
// carries the later ktime_ns; it is drained (and so dispatched) BEFORE ring
// 0's, in the same poll -- so a naive "last dispatched wins" implementation
// would already pass here. The second half of the test is what actually
// catches that bug: a config with an EARLIER ktime_ns arrives on ring 0 in a
// LATER poll (so it is genuinely "processed more recently" in wall-clock
// dispatch order) and must NOT displace the still-later-ktime config already
// held from ring 2.
func TestLatestScopeConfigSelectedByMaxKtimeAcrossRings(t *testing.T) {
	f := newFixture(t, 3, 4096)
	// Ring 2: the later-ktime config, drained first within the pass (ring
	// order is 0, 1, 2) purely because there is nothing on ring 0 yet.
	f.mustWrite(t, 2, encScopeConfig(48, scopeConfigFlagActive, 300, tU,
		1, 111, 222, 8, 8, 8, 8, 8, 8, 8, 0, 0, 0, 0, 0, 0))
	seg := f.mustSegment(t)
	d := newTestDrainer(t, seg, &mockReporter{}, t.TempDir(), testPID)

	d.drainOnce()
	if d.latestConfig == nil {
		t.Fatal("latestConfig not set after draining ring 2's config")
	}
	if d.latestConfig.KTimeNS != 300 {
		t.Fatalf("latestConfig.KTimeNS = %d, want 300 (ring 2)", d.latestConfig.KTimeNS)
	}

	// Ring 0: an earlier-ktime config, written and drained in a later poll.
	// Live (bit0 set) like the others: this test isolates the KTIME rule, and
	// a torn-down config would be rejected for an unrelated reason (see
	// TestTornDownScopeConfigNeverScales).
	f.mustWrite(t, 0, encScopeConfig(48, scopeConfigFlagActive, 100, tU,
		2, 999, 999, 9, 9, 9, 9, 9, 9, 9, 0, 0, 0, 0, 0, 0))
	d.drainOnce()
	if d.latestConfig.KTimeNS != 300 {
		t.Fatalf("ring 0's earlier-ktime config wrongly became latest "+
			"(got ktime_ns=%d): the max-ktime-across-rings rule was violated",
			d.latestConfig.KTimeNS)
	}
	if d.latestConfig.SendSampleShift != 1 {
		t.Fatalf("latestConfig fields changed even though it should still be "+
			"ring 2's record: SendSampleShift=%d, want 1", d.latestConfig.SendSampleShift)
	}

	// A genuinely later ktime, arriving later, DOES replace it.
	f.mustWrite(t, 0, encScopeConfig(48, scopeConfigFlagActive, 400, tU,
		3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0))
	d.drainOnce()
	if d.latestConfig.KTimeNS != 400 {
		t.Fatalf("latestConfig.KTimeNS = %d, want 400 (genuinely newer config "+
			"was not adopted)", d.latestConfig.KTimeNS)
	}

	// The drainer's own JSONL record of latestConfig selection does not
	// starve the sidecar: every SCOPE_CONFIG record still reaches JSONL, not
	// just the one selected as latest.
	lines := readJSONL(t, d.jsonl)
	var scopeConfigLines int
	for _, obj := range lines {
		if obj["type"] == "scope_config" {
			scopeConfigLines++
		}
	}
	if scopeConfigLines != 3 {
		t.Fatalf("JSONL has %d scope_config lines, want 3 (one per record, "+
			"regardless of which became latestConfig)", scopeConfigLines)
	}
	d.shutdown()
}

// TestEvictMetaOnExitRespectsSettlingHold is FIX-6's guard: while a
// pprof-bound record for a pid is still parked awaiting its PROC_META, a
// PROC_EXIT for that pid must not evict (there is nothing cached to evict yet,
// and the held record still needs naming when its meta arrives).
func TestEvictMetaOnExitRespectsSettlingHold(t *testing.T) {
	d := newTestDrainer(t, nil, &mockReporter{}, "", testPID)
	const pk = uint64(0x9)

	// Cache a meta for a DIFFERENT pid to prove selective eviction.
	other, err := decodeRecord(encProcMeta(tK, tU, 0xA, 0, 0, "Elixir.Other", "run", "<0.2.0>"))
	if err != nil {
		t.Fatalf("decode other meta: %v", err)
	}
	d.rep.cacheProcMeta(other.(*ProcMeta))

	// Park a GC_DELTA for pk (no meta cached -> held).
	gc, err := decodeRecord(encGCDelta(tK, tU, pk, 1, 0, 1, 0))
	if err != nil {
		t.Fatalf("decode gc: %v", err)
	}
	d.holdOrReport(heldRecord{rec: gc.(*GCDelta), pidKey: pk})
	if len(d.held) != 1 {
		t.Fatalf("expected the GC_DELTA to be held, held=%d", len(d.held))
	}

	// PROC_EXIT for the held pid: guard must skip eviction; the other pid's
	// meta stays cached.
	d.evictMetaOnExit(pk)
	if _, ok := d.rep.metaCache[0xA]; !ok {
		t.Fatal("evictMetaOnExit wrongly dropped an unrelated pid's meta")
	}
}

// Both inputs to the receive-sample scaling come from an untrusted shared
// memory segment. Wrapping into a negative message count would be summed into
// a pprof total; saturating keeps a nonsense input visibly nonsense.
func TestScaleArrivalsSaturates(t *testing.T) {
	for _, tc := range []struct {
		name  string
		raw   uint64
		shift uint32
		want  int64
	}{
		{"zero raw", 0, 62, 0},
		{"zero shift", 12345, 0, 12345},
		{"typical", 1000, 10, 1000 << 10},
		{"exactly at the limit", 1, 62, 1 << 62},
		{"one past the limit", 2, 62, math.MaxInt64},
		{"large raw at shift 62", 1 << 40, 62, math.MaxInt64},
		{"max raw at shift 1", math.MaxUint64, 1, math.MaxInt64},
		{"sign bit would be set", uint64(math.MaxInt64)/4 + 1, 2, math.MaxInt64},
		// The caller rejects shift >= 63, but the helper must not wrap if that
		// ever changes: Go yields 0 for an over-wide shift, so this saturates.
		{"shift 63", 3, 63, math.MaxInt64},
		{"shift 64", 3, 64, math.MaxInt64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := scaleArrivals(tc.raw, tc.shift)
			if got != tc.want {
				t.Fatalf("scaleArrivals(%d, %d) = %d, want %d",
					tc.raw, tc.shift, got, tc.want)
			}
			if got < 0 {
				t.Fatalf("negative message count %d", got)
			}
		})
	}
}
