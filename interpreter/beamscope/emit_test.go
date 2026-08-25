// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package beamscope

// TestEmitRecordedFixturePprof is a gated artifact producer, not an assertion
// suite: with BEAMSCOPE_EMIT_PPROF=<target.pb.gz> set (and optionally
// BEAMSCOPE_FIXTURE overriding the recorded segment path), it drains the
// recorded fixture through the real local-egress reporter and copies the emitted
// profile to the target path. Used to hand a genuine beamscope pprof artifact
// to the DST profile-diff toolchain for ingestion validation. Without the env
// var it skips, so the normal suite is unaffected.

import (
	"os"
	"path/filepath"
	"testing"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

func TestEmitRecordedFixturePprof(t *testing.T) {
	target := os.Getenv("BEAMSCOPE_EMIT_PPROF")
	if target == "" {
		t.Skip("set BEAMSCOPE_EMIT_PPROF=<target.pb.gz> to emit the artifact")
	}
	raw, err := os.ReadFile(recordedFixturePath("BEAMSCOPE_FIXTURE", "shm_v1.bin"))
	if err != nil {
		t.Fatalf("recorded fixture: %v", err)
	}
	seg, err := NewSegment(raw)
	if err != nil {
		t.Fatalf("recorded fixture rejected: %v", err)
	}
	// Label samples with the recording BEAM's own pid.
	pid := libpf.PID(seg.Header().OSPid)

	rep, dir := newPprofReporter(t)
	d := newTestDrainer(t, seg, rep, "", pid)
	drainUntilSettled(d)
	if d.rep.reported == 0 {
		t.Fatal("no GC_DELTA samples reported from the recorded fixture")
	}
	if err := rep.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	pprofData, err := os.ReadFile(soleProfile(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, pprofData, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("emitted %d GC_DELTA samples (pid %d) to %s", d.rep.reported, pid, target)
}
