// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package beamscope

// MSG_FLOW's scaling by the SCOPE_CONFIG recv_sample_shift that was in force
// when the record was written, the "msg" beamscope kind, and the guard that
// skips synthesizing a pprof sample when no retained config can scale the
// record. JSONL still gets the raw record regardless (see
// TestPipelineScopeTypes and dispatch in drain.go); these tests only pin the
// pprof-side behavior.

import (
	"testing"

	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

// msgFlowPidKey is the destination pid_key every MSG_FLOW in this file is
// addressed to. No PROC_META is ever written for it, so a record settles out
// of the meta hold with the fallback naming instead of being released early.
const msgFlowPidKey = uint64(0x5001)

// msgFlowCfg is one SCOPE_CONFIG for the rig below: which ring it lands in,
// its ktime_ns, its payload length (which generation of the record shape) and
// the recv_sample_shift it carries. Every other knob is fixed boilerplate --
// these are the only ones MSG_FLOW scaling reads. Note that recvShift is not
// written at all when payloadLen < 48; see encScopeConfig.
type msgFlowCfg struct {
	ring       int
	ktime      uint64
	payloadLen int
	recvShift  uint32
}

func (c msgFlowCfg) enc() []byte {
	return encScopeConfig(c.payloadLen, scopeConfigFlagActive, c.ktime, tU,
		12, 50_000, 3_000_000, 4096, 2048, 8, 1000, 500, c.recvShift, 200,
		0, 0, 0, 0, 0, 0)
}

// msgFlowRig builds an nrings segment carrying cfgs (in slice order) plus one
// MSG_FLOW of arrivals on flowRing at flowKTime, wires a drainer to it and
// drains until that MSG_FLOW has aged out of the meta hold. Returns the
// drainer (still open: the caller shuts it down) and the mock reporter that
// received whatever the pprof side synthesized.
func msgFlowRig(t *testing.T, nrings int, cfgs []msgFlowCfg,
	flowRing int, flowKTime, arrivals uint64) (*drainer, *mockReporter) {
	t.Helper()
	f := newFixture(t, nrings, 4096)
	for _, c := range cfgs {
		f.mustWrite(t, c.ring, c.enc())
	}
	f.mustWrite(t, flowRing, encMsgFlow(flowKTime, tU+1, msgFlowPidKey, arrivals))

	mock := &mockReporter{}
	d := newTestDrainer(t, f.mustSegment(t), mock, t.TempDir(), testPID)
	drainUntilSettled(d)
	return d, mock
}

// TestMsgFlowScaledSample pins the MsgFlow->pprof value math: the SCOPE_CONFIG
// in force when the record was written supplies the shift, and the
// synthesized sample's value is raw << shift, kind "msg".
func TestMsgFlowScaledSample(t *testing.T) {
	for _, tc := range []struct {
		name     string
		shift    uint32
		arrivals uint64
		want     int64
	}{
		{"typical shift", 6, 9, 9 << 6},
		// Shift 0 is the smallest usable shift -- no attenuation -- and must
		// still synthesize a sample, with the raw count unchanged.
		{"shift zero is identity scale", 0, 9, 9},
		// 62 is the largest shift the guard still accepts (only >= 63 is
		// disabled); the resulting scale is huge but the sample must still be
		// synthesized, not skipped. arrivals_raw=1 keeps 1<<62 comfortably
		// positive as an int64 (bit 63, the sign bit, stays clear); this case
		// is about the guard boundary, not int64 overflow semantics.
		{"largest usable shift", 62, 1, int64(1) << 62},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, mock := msgFlowRig(t, 1,
				[]msgFlowCfg{{ktime: tK, payloadLen: 48, recvShift: tc.shift}},
				0, tK+1, tc.arrivals)
			defer d.shutdown()

			if len(mock.traces) != 1 {
				t.Fatalf("reported %d traces, want 1", len(mock.traces))
			}
			m := mock.metas[0]
			if m.ValueKind != samples.ValueKindMsgs {
				t.Fatalf("ValueKind = %d, want ValueKindMsgs (%d)",
					m.ValueKind, samples.ValueKindMsgs)
			}
			if m.Value != tc.want {
				t.Fatalf("Value = %d, want %d (%d << %d)",
					m.Value, tc.want, tc.arrivals, tc.shift)
			}
			if m.OffTime != 0 {
				t.Errorf("OffTime = %d, want 0 (retired as a beamscope value channel)",
					m.OffTime)
			}
			if got := mock.traces[0].CustomLabels[labelBeamscopeKind].String(); got != "msg" {
				t.Errorf("beamscope_kind = %q, want msg", got)
			}
			if d.msgFlowScaleSkipped != 0 {
				t.Errorf("msgFlowScaleSkipped = %d, want 0", d.msgFlowScaleSkipped)
			}
		})
	}
}

// TestMsgFlowSkippedWhenNothingCanScaleIt: when no retained SCOPE_CONFIG that
// predates the record can supply a shift, no pprof sample is synthesized and
// the skip is counted. The shift is never guessed.
func TestMsgFlowSkippedWhenNothingCanScaleIt(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfgs []msgFlowCfg
	}{
		// No SCOPE_CONFIG has ever arrived.
		{"no config at all", nil},
		// A 40-byte SCOPE_CONFIG predates recv_sample_shift entirely
		// (PayloadLen < 48), so it cannot support scaling. 40, not the oldest
		// LOGICAL shape of 36: the writer pads, so a logical 36 reaches this
		// reader as PayloadLen 40 -- and an unpadded 36 cannot be pushed
		// through a real ring at all. See encScopeConfig.
		{"config predates recv_sample_shift",
			[]msgFlowCfg{{ktime: tK, payloadLen: 40}}},
		// recv_sample_shift >= 63 means receive tracing is disabled at the
		// writer.
		{"receive tracing disabled",
			[]msgFlowCfg{{ktime: tK, payloadLen: 48, recvShift: 63}}},
		// The only retained config is NEWER than the record, so it was not in
		// force when the record was written and must not be used to scale it.
		{"only retained config is newer than the record",
			[]msgFlowCfg{{ktime: tK + 2, payloadLen: 48, recvShift: 6}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, mock := msgFlowRig(t, 1, tc.cfgs, 0, tK+1, 9)
			defer d.shutdown()

			if len(mock.traces) != 0 {
				t.Fatalf("reported %d traces, want 0", len(mock.traces))
			}
			if d.msgFlowScaleSkipped != 1 {
				t.Errorf("msgFlowScaleSkipped = %d, want 1", d.msgFlowScaleSkipped)
			}
		})
	}
}

// TestMsgFlowNotScaledByConfigNewerThanRecord is FIX-B4(a): the max-ktime
// rule governs which config is HELD, never which config a record is scaled
// BY. DrainInto walks rings 0..n-1 while the writer only orders records
// within a ring, so a config drained early in a pass can be NEWER than a
// MSG_FLOW drained later in the SAME pass. Here ring 0 carries the old
// config (shift 4) and then a newer one (shift 0); the MSG_FLOW on ring 1 was
// written between them, so it must be scaled by 4 -- the shift actually in
// force when it was written -- even though shift 0 is what is latched by the
// time the record is dispatched.
func TestMsgFlowNotScaledByConfigNewerThanRecord(t *testing.T) {
	d, mock := msgFlowRig(t, 2, []msgFlowCfg{
		{ring: 0, ktime: tK, payloadLen: 48, recvShift: 4},
		{ring: 0, ktime: tK + 10, payloadLen: 48, recvShift: 0},
	}, 1, tK+5, 9)
	defer d.shutdown()

	if d.latestConfig == nil || d.latestConfig.KTimeNS != tK+10 {
		t.Fatalf("latestConfig is not the newer config: %+v", d.latestConfig)
	}
	if len(mock.traces) != 1 {
		t.Fatalf("reported %d traces, want 1", len(mock.traces))
	}
	if got := mock.metas[0].Value; got != int64(9<<4) {
		t.Fatalf("Value = %d, want %d (9 << 4, the shift in force at ktime_ns "+
			"%d; a newer config drained earlier in the pass must not scale it)",
			got, int64(9<<4), tK+5)
	}
	if d.msgFlowScaleSkipped != 0 {
		t.Errorf("msgFlowScaleSkipped = %d, want 0", d.msgFlowScaleSkipped)
	}
}

// TestMsgFlowScaledByConfigFromALaterRing is the mirror image of the case
// above, and the reason the dispatch-time resolve is a preference rather than
// a verdict. A SCOPE_CONFIG can land in ANY ring, and DrainInto walks rings
// 0..n-1: here the config that was in force (ktime tK, shift 4) sits in ring
// 3 while the MSG_FLOW it covers (ktime tK+5) sits in ring 0, so at dispatch
// time nothing is latched yet. The record must still be scaled by that older
// config -- resolving only at dispatch would charge a whole poll window of
// receive samples to msgFlowScaleSkipped for no reason, including on the very
// first config after activation.
func TestMsgFlowScaledByConfigFromALaterRing(t *testing.T) {
	d, mock := msgFlowRig(t, 4, []msgFlowCfg{
		{ring: 3, ktime: tK, payloadLen: 48, recvShift: 4},
	}, 0, tK+5, 9)
	defer d.shutdown()

	if len(mock.traces) != 1 {
		t.Fatalf("reported %d traces, want 1 (the config is older than the "+
			"record; only its RING is later)", len(mock.traces))
	}
	if got := mock.metas[0].Value; got != int64(9<<4) {
		t.Fatalf("Value = %d, want %d (9 << 4)", got, int64(9<<4))
	}
	if d.msgFlowScaleSkipped != 0 {
		t.Errorf("msgFlowScaleSkipped = %d, want 0", d.msgFlowScaleSkipped)
	}
}

// TestMsgFlowHeldRecordKeepsArrivalShift is FIX-B4(b): a MSG_FLOW parked
// awaiting its PROC_META is converted later, and the config can change inside
// that window. The shift is resolved and latched when the record is
// DISPATCHED, so the released sample carries the shift that was in force when
// it arrived rather than being re-resolved at release time.
//
// Two config changes land inside the settling window on purpose: that is what
// makes the latching load-bearing rather than incidental. Re-resolving at
// release time would by then find only those two configs retained -- both
// newer than the record -- and skip the sample outright, silently losing it.
func TestMsgFlowHeldRecordKeepsArrivalShift(t *testing.T) {
	f := newFixture(t, 1, 4096)
	f.mustWrite(t, 0, msgFlowCfg{ktime: tK, payloadLen: 48, recvShift: 4}.enc())
	f.mustWrite(t, 0, encMsgFlow(tK+1, tU+1, msgFlowPidKey, 9))
	seg := f.mustSegment(t)

	mock := &mockReporter{}
	d := newTestDrainer(t, seg, mock, t.TempDir(), testPID)
	d.drainOnce()
	if len(d.held) != 1 {
		t.Fatalf("held %d records, want the MSG_FLOW parked awaiting PROC_META",
			len(d.held))
	}
	if len(mock.traces) != 0 {
		t.Fatalf("reported %d traces before the hold released, want 0", len(mock.traces))
	}

	// The writer changes the shift twice INSIDE the settling window, pushing
	// the record's own arrival-time config out of the retained history, and
	// only then does the PROC_META that releases the held record arrive.
	f.mustWrite(t, 0, msgFlowCfg{ktime: tK + 2, payloadLen: 48, recvShift: 5}.enc())
	f.mustWrite(t, 0, msgFlowCfg{ktime: tK + 3, payloadLen: 48, recvShift: 0}.enc())
	f.mustWrite(t, 0, encProcMeta(tK+4, tU+4, msgFlowPidKey, 0, 0,
		"Elixir.Held", "loop", "<0.9.0>"))
	d.drainOnce()
	defer d.shutdown()

	if d.latestConfig == nil || d.latestConfig.KTimeNS != tK+3 {
		t.Fatalf("the mid-window configs did not become latestConfig: %+v",
			d.latestConfig)
	}
	if len(d.held) != 0 {
		t.Fatalf("held %d records after the PROC_META arrived, want 0", len(d.held))
	}
	if len(mock.traces) != 1 {
		t.Fatalf("reported %d traces after release, want 1", len(mock.traces))
	}
	m := mock.metas[0]
	if m.ValueKind != samples.ValueKindMsgs {
		t.Fatalf("ValueKind = %d, want ValueKindMsgs", m.ValueKind)
	}
	if m.Value != int64(9<<4) {
		t.Fatalf("Value = %d, want %d (9 << 4, the shift in force when the "+
			"record arrived; neither config retained by release time "+
			"predates it)",
			m.Value, int64(9<<4))
	}
	if d.msgFlowScaleSkipped != 0 {
		t.Errorf("msgFlowScaleSkipped = %d, want 0", d.msgFlowScaleSkipped)
	}
}

// TestMsgFlowScaleSkippedSurfacedInDrainStats: the skip counter must not be
// a white-box-only signal. A whole sample class silently failing to
// synthesize (stale/missing SCOPE_CONFIG) has to be visible in the same
// drain_stats JSONL line that already surfaces heldEvicted, for the same
// reason -- otherwise it is invisible in production.
func TestMsgFlowScaleSkippedSurfacedInDrainStats(t *testing.T) {
	// No SCOPE_CONFIG at all: every MSG_FLOW is skipped.
	d, _ := msgFlowRig(t, 1, nil, 0, tK, 9)
	defer d.shutdown()

	if d.msgFlowScaleSkipped != 1 {
		t.Fatalf("msgFlowScaleSkipped = %d, want 1", d.msgFlowScaleSkipped)
	}

	var last map[string]any
	for _, obj := range readJSONL(t, d.jsonl) {
		if obj["type"] == "drain_stats" {
			last = obj
		}
	}
	if last == nil {
		t.Fatal("no drain_stats line emitted")
	}
	if got, ok := last["msg_flow_scale_skipped_total"].(float64); !ok || got != 1 {
		t.Errorf("drain_stats msg_flow_scale_skipped_total = %v, want 1",
			last["msg_flow_scale_skipped_total"])
	}
}
