// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package beamscope

// Frame-ranking and meta-settling tests. The settling machinery exists for
// one measured failure: in a real guilds run, GC records drained before their
// lazily-emitted PROC_META baked proc_lib fallback frames into the profile.
// A pprof-bound record whose pid_key has no cached metadata is now held for
// up to heldMaxCycles polls; the PROC_META arriving releases it immediately
// with proper naming.

import (
	"testing"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

// TestFrameRanking pins the ABI display ranking:
// registered_name > translated MFA > untranslated MFA > pid_printable,
// then the opaque key when nothing is cached.
func TestFrameRanking(t *testing.T) {
	s := newReporterSink(&mockReporter{}, 4242)
	meta := func(flags uint32, module, function string, arity uint8,
		pidPrint, regName string) *ProcMeta {
		rec, err := decodeRecord(encProcMetaReg(flags, tK, tU, 0x1, 0, arity,
			module, function, pidPrint, regName))
		if err != nil {
			t.Fatalf("fixture meta: %v", err)
		}
		return rec.(*ProcMeta)
	}

	tests := []struct {
		name    string
		meta    *ProcMeta // nil = nothing cached
		want    string
		wantErl string
	}{
		{
			name: "registered_name_wins",
			meta: meta(procMetaFlagTranslated|procMetaFlagRegisteredName,
				"Elixir.MyApp.Server", "init", 1, "<0.10.0>", "guild_registry"),
			want:    "guild_registry",
			wantErl: "<0.10.0>",
		},
		{
			name: "translated_mfa",
			meta: meta(procMetaFlagTranslated,
				"Elixir.MyApp.Server", "init", 1, "<0.11.0>", ""),
			want:    "MyApp.Server.init/1",
			wantErl: "<0.11.0>",
		},
		{
			name:    "untranslated_mfa",
			meta:    meta(0, "proc_lib", "init_p", 5, "<0.12.0>", ""),
			want:    "proc_lib:init_p/5",
			wantErl: "<0.12.0>",
		},
		{
			name: "current_function_mfa_renders_like_any_mfa",
			meta: meta(procMetaFlagCurrentFunction,
				"gen_event", "fetch_msg", 3, "<0.13.0>", ""),
			want:    "gen_event:fetch_msg/3",
			wantErl: "<0.13.0>",
		},
		{
			name:    "pid_printable_fallback",
			meta:    meta(0, "", "", 0, "<0.14.0>", ""),
			want:    "<0.14.0>",
			wantErl: "<0.14.0>",
		},
		{
			name: "nothing_cached",
			meta: nil,
			want: "<beam_pid_key:0x1>",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.meta != nil {
				s.cacheProcMeta(tc.meta)
			} else {
				delete(s.metaCache, 0x1)
			}
			name, erl := s.frameName(0x1)
			if name != tc.want || erl != tc.wantErl {
				t.Fatalf("frameName = (%q, %q), want (%q, %q)",
					name, erl, tc.want, tc.wantErl)
			}
		})
	}
}

// settle builds a drainer over an empty two-ring fixture; tests write into
// the fixture between drainOnce calls.
func settle(t *testing.T) (*fixture, *drainer, *mockReporter) {
	t.Helper()
	f := newFixture(t, 2, 4096)
	mock := &mockReporter{}
	d := newTestDrainer(t, f.mustSegment(t), mock, "", libpf.PID(4242))
	return f, d, mock
}

// TestMetaSettlingReleaseOnArrival is the exact guilds failure: a GC record
// drained BEFORE its PROC_META must still get the translated frame.
func TestMetaSettlingReleaseOnArrival(t *testing.T) {
	f, d, mock := settle(t)
	if !f.writeRecord(0, encGCDelta2(tK, tU, 0x3001, 40_000, 0, 0, 100, 1_000, 0)) {
		t.Fatal("write failed")
	}
	d.drainOnce()
	if len(mock.traces) != 0 {
		t.Fatalf("meta-less record reported immediately (%d traces)", len(mock.traces))
	}
	if len(d.held) != 1 {
		t.Fatalf("held = %d, want 1", len(d.held))
	}

	// The PROC_META arrives one poll later: immediate release, proper name.
	if !f.writeRecord(0, encProcMetaF(procMetaFlagTranslated, tK+5, tU+5,
		0x3001, 1, 1, "Elixir.Guilds.Server", "init", "<0.30.0>")) {
		t.Fatal("write failed")
	}
	d.drainOnce()
	if len(mock.traces) != 1 {
		t.Fatalf("released %d traces, want 1", len(mock.traces))
	}
	if got := mock.traces[0].Frames[0].Value().FunctionName.String(); got != "Guilds.Server.init/1" {
		t.Fatalf("released frame %q, want Guilds.Server.init/1", got)
	}
	if got := mock.traces[0].CustomLabels[labelErlangPID].String(); got != "<0.30.0>" {
		t.Fatalf("released erlang_pid %q", got)
	}
	if len(d.held) != 0 {
		t.Fatalf("held = %d after release, want 0", len(d.held))
	}
	// The sample keeps its own record clocks, not the release-time ones.
	if mock.metas[0].KTime != int64(tK) {
		t.Fatalf("released KTime %d, want %d", mock.metas[0].KTime, tK)
	}
}

// TestMetaSettlingExpiry: with no PROC_META forthcoming, the hold expires
// after heldMaxCycles polls and converts with the fallback ranking.
func TestMetaSettlingExpiry(t *testing.T) {
	f, d, mock := settle(t)
	if !f.writeRecord(0, encSchedDelta(schedDeltaFlagUnclassified, tK, tU,
		0x3002, 7_000_000, 3, 0, 0)) {
		t.Fatal("write failed")
	}
	d.drainOnce() // read + hold (age 0)
	d.drainOnce() // age 1
	if len(mock.traces) != 0 {
		t.Fatal("expired before heldMaxCycles")
	}
	d.drainOnce() // age 2 -> expire
	if len(mock.traces) != 1 {
		t.Fatalf("expiry reported %d traces, want 1", len(mock.traces))
	}
	if got := mock.traces[0].Frames[0].Value().FunctionName.String(); got != "<beam_pid_key:0x3002>" {
		t.Fatalf("expired frame %q, want pid_key fallback", got)
	}
	if mock.metas[0].Value != 7_000_000 {
		t.Fatalf("expired sample value %d, want 7000000", mock.metas[0].Value)
	}
	if mock.metas[0].ValueKind != samples.ValueKindSchedNS {
		t.Fatalf("expired sample ValueKind %d, want ValueKindSchedNS", mock.metas[0].ValueKind)
	}
	if mock.metas[0].OffTime != 0 {
		t.Fatalf("expired sample OffTime %d, want 0 (retired as a beamscope value channel)",
			mock.metas[0].OffTime)
	}
	if len(d.held) != 0 {
		t.Fatalf("held = %d after expiry, want 0", len(d.held))
	}
}

// TestMetaSettlingCap: past the cap the OLDEST held record is converted
// immediately (never discarded) and counted as evicted.
func TestMetaSettlingCap(t *testing.T) {
	f, d, mock := settle(t)
	d.heldCap = 2
	for i := uint64(1); i <= 3; i++ {
		if !f.writeRecord(0, encGCDelta2(tK+i, tU+i, 0x4000+i,
			1000*i, 0, 0, 10, 100, 0)) {
			t.Fatal("write failed")
		}
	}
	d.drainOnce()
	// The third hold evicted the first: converted with fallback, counted.
	if len(mock.traces) != 1 {
		t.Fatalf("evicted %d traces, want 1", len(mock.traces))
	}
	if got := mock.traces[0].Frames[0].Value().FunctionName.String(); got != "<beam_pid_key:0x4001>" {
		t.Fatalf("evicted frame %q, want oldest (0x4001) fallback", got)
	}
	if d.heldEvicted != 1 || len(d.held) != 2 {
		t.Fatalf("heldEvicted=%d held=%d, want 1 and 2", d.heldEvicted, len(d.held))
	}

	// Shutdown must flush the remainder -- a held sample is never lost.
	d.shutdown()
	if len(mock.traces) != 3 {
		t.Fatalf("after shutdown %d traces, want 3", len(mock.traces))
	}
	vals := map[int64]bool{}
	for _, m := range mock.metas {
		vals[m.Value] = true
		if m.ValueKind != samples.ValueKindAlloc {
			t.Errorf("sample ValueKind %d, want ValueKindAlloc", m.ValueKind)
		}
	}
	if !vals[1000] || !vals[2000] || !vals[3000] {
		t.Fatalf("sample values lost across settling: %v", vals)
	}
}

// TestRecordedFixtureV3 decodes the writer peer's v3 recorded segment
// (registered_name / current_function era) once it lands; skips until then.
// Assertions are provisional until the orchestrator relays the writer's
// ground-truth counts.
func TestRecordedFixtureV3(t *testing.T) {
	seg := loadRecordedSegment(t, "BEAMSCOPE_FIXTURE_V3", "shm_v3.bin")
	recs, st := collect(seg)
	if st.CorruptRings != 0 {
		t.Errorf("v3 fixture has %d corrupt rings", st.CorruptRings)
	}
	if st.Unknown != 0 {
		t.Errorf("v3 fixture has %d unknown/truncated records", st.Unknown)
	}
	byType := map[string]int{}
	metaFlags := map[uint32]int{}
	regNames := map[string]int{}
	var rawIdleCF bool
	for _, r := range recs {
		byType[r.TypeName()]++
		pm, ok := r.(*ProcMeta)
		if !ok {
			continue
		}
		flags := pm.Flags & (procMetaFlagTranslated |
			procMetaFlagRegisteredName | procMetaFlagCurrentFunction)
		metaFlags[flags]++
		if pm.Translated && pm.CurrentFunction {
			t.Errorf("PROC_META with bit0+bit2 set: %+v", pm)
		}
		if pm.Flags&procMetaFlagRegisteredName != 0 {
			if pm.RegisteredName == "" {
				t.Errorf("bit1 PROC_META with empty registered_name: %+v", pm)
			}
			regNames[pm.RegisteredName]++
		} else if pm.RegisteredName != "" {
			t.Errorf("bit1-clear PROC_META decoded a registered_name: %+v", pm)
		}
		if pm.CurrentFunction && pm.Function == "raw_idle" && pm.Arity == 1 {
			rawIdleCF = true
		}
	}
	// Writer ground truth for this exact fixture: 222 records.
	if len(recs) != 222 {
		t.Errorf("decoded %d records, want 222", len(recs))
	}
	for typ, want := range map[string]int{
		"gc_delta2":     20,
		"proc_meta":     66,
		"proc_exit":     5,
		"panel_sample":  51,
		"topk_send":     9,
		"monitor_event": 4,
		"panel_tick":    6,
		"sched_util":    56,
		"sched_delta":   5,
		"gc_delta":      0,
	} {
		if byType[typ] != want {
			t.Errorf("v3 fixture has %d %s records, want %d", byType[typ], typ, want)
		}
	}
	// PROC_META flag population, exactly.
	for flags, want := range map[uint32]int{
		0x0: 13, // untranslated initial_call
		0x1: 1,  // translated, no registered name
		0x3: 10, // translated + registered_name
		0x4: 42, // current_function fallbacks
	} {
		if metaFlags[flags] != want {
			t.Errorf("PROC_META flags 0x%x count = %d, want %d",
				flags, metaFlags[flags], want)
		}
	}
	if regNames["bsrun_registered_server"] != 4 {
		t.Errorf("registered_name bsrun_registered_server seen %d times, want 4",
			regNames["bsrun_registered_server"])
	}
	for _, name := range []string{"kernel_refc", "Elixir.BeamScope.Supervisor"} {
		if regNames[name] == 0 {
			t.Errorf("registered_name %q absent", name)
		}
	}
	if !rawIdleCF {
		t.Error("no current_function PROC_META for raw_idle/1 (the raw-spawn fallback)")
	}
	t.Logf("v3 recorded fixture: %d records %v, meta flags %v, reg names %v, "+
		"%d pads, %d dropped",
		len(recs), byType, metaFlags, regNames, st.Padding, st.Dropped)
}
