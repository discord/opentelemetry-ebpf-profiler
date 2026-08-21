// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package beamscope

// Golden decode tests: every record type is encoded byte-for-byte per ABI.md
// by the fixture builder and decoded by the production decoder; the results
// must match field by field.

import (
	"encoding/binary"
	"errors"
	"reflect"
	"testing"
)

const (
	tK = uint64(123_456_789)           // ktime_ns
	tU = uint64(1_755_000_000_000_042) // unix_ns
)

func hdr(typ uint16, total int) RecordHeader {
	return RecordHeader{Len: uint16(total), Type: typ, KTimeNS: tK, UnixNS: tU}
}

func TestDecodeGolden(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
		want Record
	}{
		{
			name: "gc_delta",
			raw:  encGCDelta(tK, tU, 0xdeadbeef, 40_000, 512, 121_393, 1),
			want: &GCDelta{
				RecordHeader:       hdr(recTypeGCDelta, 64),
				PidKey:             0xdeadbeef,
				AllocWords:         40_000,
				BinVheapDeltaWords: 512,
				HeapSizeWords:      121_393,
				GCKind:             1,
			},
		},
		{
			name: "proc_meta",
			raw: encProcMeta(tK, tU, 0xcafe, 999, 2,
				"Elixir.MyApp.Worker", "run", "<0.123.0>"),
			// payload: 8+8+1 + (1+19)+(1+3)+(1+9) = 51 -> record 24+51=75 -> 80
			want: &ProcMeta{
				RecordHeader: hdr(recTypeProcMeta, 80),
				PidKey:       0xcafe,
				SpawnKtimeNS: 999,
				Arity:        2,
				Module:       "Elixir.MyApp.Worker",
				Function:     "run",
				PidPrintable: "<0.123.0>",
				NameSource:   "initial_call",
			},
		},
		{
			name: "proc_exit",
			raw:  encProcExit(tK, tU, 0xcafe, 3),
			want: &ProcExit{
				RecordHeader: hdr(recTypeProcExit, 40),
				PidKey:       0xcafe,
				ReasonClass:  3,
			},
		},
		{
			name: "panel_sample",
			raw:  encPanelSample(tK, tU, 7, 100, 65_536, 1_000_000, 5_000, -3, 0b101, 42),
			want: &PanelSample{
				RecordHeader:    hdr(recTypePanelSample, 80),
				PidKey:          7,
				MsgqLen:         100,
				MemoryBytes:     65_536,
				Reductions:      1_000_000,
				ReductionsDelta: 5_000,
				MsgqDelta:       -3,
				SampleFlags:     0b101,
				Epoch:           42,
			},
		},
		{
			name: "topk_send",
			raw:  encTopkSend(tK, tU, 9, 12_345, 42, 0),
			want: &TopkSend{
				RecordHeader: hdr(recTypeTopkSend, 48),
				PidKey:       9,
				EstArrivals:  12_345,
				Epoch:        42,
				Rank:         0,
			},
		},
		{
			name: "monitor_event",
			raw:  encMonitorEvent(tK, tU, 11, 1, 250),
			want: &MonitorEvent{
				RecordHeader: hdr(recTypeMonitorEvent, 48),
				PidKey:       11,
				Kind:         1,
				Value:        250,
			},
		},
		{
			name: "panel_tick",
			raw:  encPanelTick(tK, tU, 42, 1000, 64, 350_000),
			want: &PanelTick{
				RecordHeader: hdr(recTypePanelTick, 48),
				Epoch:        42,
				PanelSize:    1000,
				WatchSize:    64,
				ProcessCount: 350_000,
			},
		},
		{
			name: "gc_delta2",
			// payload 6*8+1 = 49 -> record 73 -> 80
			raw: encGCDelta2(tK, tU, 0xbeef2, 40_000, 512, 1_024, 121_393, 250_000, 1),
			want: &GCDelta2{
				RecordHeader:       hdr(recTypeGCDelta2, 80),
				PidKey:             0xbeef2,
				AllocWords:         40_000,
				BinVheapDeltaWords: 512,
				MbufWords:          1_024,
				HeapSizeWords:      121_393,
				PauseNS:            250_000,
				GCKind:             1,
			},
		},
		{
			name: "sched_util_msacc_valid",
			// payload 4+1+4+7*8 = 65 -> record 89 -> 96
			raw: encSchedUtil(schedUtilFlagMsaccValid, tK, tU, 3, 1, 42,
				800_000, 1_000_000, 500_000, 100_000, 50_000, 200_000, 150_000),
			want: &SchedUtil{
				RecordHeader: RecordHeader{Len: 96, Type: recTypeSchedUtil,
					Flags: schedUtilFlagMsaccValid, KTimeNS: tK, UnixNS: tU},
				SchedulerID: 3,
				SchedType:   1,
				Epoch:       42,
				ActiveNS:    800_000,
				TotalNS:     1_000_000,
				EmulatorNS:  500_000,
				GCNS:        100_000,
				PortNS:      50_000,
				SleepNS:     200_000,
				OtherNS:     150_000,
				MsaccValid:  true,
			},
		},
		{
			name: "sched_util_msacc_invalid",
			// flags bit0 clear: wall-time fields valid, microstates zero.
			raw: encSchedUtil(0, tK, tU, 1, 0, 7,
				800_000, 1_000_000, 0, 0, 0, 0, 0),
			want: &SchedUtil{
				RecordHeader: hdr(recTypeSchedUtil, 96),
				SchedulerID:  1,
				Epoch:        7,
				ActiveNS:     800_000,
				TotalNS:      1_000_000,
				MsaccValid:   false,
			},
		},
		{
			name: "sched_delta_classified",
			// payload 8+8+4*4 = 32 -> record 56
			raw: encSchedDelta(0, tK, tU, 0xab, 5_000_000, 12, 3, 9),
			want: &SchedDelta{
				RecordHeader: hdr(recTypeSchedDelta, 56),
				PidKey:       0xab,
				OnSchedNS:    5_000_000,
				NSwitches:    12,
				Preempts:     3,
				Yields:       9,
			},
		},
		{
			name: "sched_delta_classification_unsupported",
			raw:  encSchedDelta(schedDeltaFlagUnclassified, tK, tU, 0xab, 2_000_000, 4, 0, 0),
			want: &SchedDelta{
				RecordHeader: RecordHeader{Len: 56, Type: recTypeSchedDelta,
					Flags: schedDeltaFlagUnclassified, KTimeNS: tK, UnixNS: tU},
				PidKey:                    0xab,
				OnSchedNS:                 2_000_000,
				NSwitches:                 4,
				ClassificationUnsupported: true,
			},
		},
		{
			name: "proc_meta_translated",
			raw: encProcMetaF(procMetaFlagTranslated, tK, tU, 0xcafe, 999, 1,
				"Elixir.MyApp.Server", "init", "<0.201.0>"),
			want: &ProcMeta{
				RecordHeader: RecordHeader{
					// payload 17 + 20 + 5 + 10 = 52 -> record 76 -> 80
					Len: 80, Type: recTypeProcMeta,
					Flags: procMetaFlagTranslated, KTimeNS: tK, UnixNS: tU},
				PidKey:       0xcafe,
				SpawnKtimeNS: 999,
				Arity:        1,
				Module:       "Elixir.MyApp.Server",
				Function:     "init",
				PidPrintable: "<0.201.0>",
				Translated:   true,
				NameSource:   "translated",
			},
		},
		{
			name: "proc_meta_registered_name",
			// bit0|bit1: translated MFA plus an appended registered_name.
			// payload 17 + 11 + 5 + 10 + 15 = 58 -> record 82 -> 88
			raw: encProcMetaReg(procMetaFlagTranslated|procMetaFlagRegisteredName,
				tK, tU, 0xcafe, 999, 1, "gen_server", "init", "<0.201.0>",
				"guild_registry"),
			want: &ProcMeta{
				RecordHeader: RecordHeader{Len: 88, Type: recTypeProcMeta,
					Flags:   procMetaFlagTranslated | procMetaFlagRegisteredName,
					KTimeNS: tK, UnixNS: tU},
				PidKey:         0xcafe,
				SpawnKtimeNS:   999,
				Arity:          1,
				Module:         "gen_server",
				Function:       "init",
				PidPrintable:   "<0.201.0>",
				RegisteredName: "guild_registry",
				Translated:     true,
				NameSource:     "translated",
			},
		},
		{
			name: "proc_meta_current_function",
			// bit2: the MFA names what the process was doing, not how it
			// started; here with bit1 too, exercising both appended strings.
			raw: encProcMetaReg(procMetaFlagCurrentFunction|procMetaFlagRegisteredName,
				tK, tU, 0xd00d, 0, 3, "gen_event", "fetch_msg", "<0.77.0>",
				"error_logger"),
			want: &ProcMeta{
				RecordHeader: RecordHeader{Len: 88, Type: recTypeProcMeta,
					Flags:   procMetaFlagCurrentFunction | procMetaFlagRegisteredName,
					KTimeNS: tK, UnixNS: tU},
				PidKey:          0xd00d,
				Arity:           3,
				Module:          "gen_event",
				Function:        "fetch_msg",
				PidPrintable:    "<0.77.0>",
				RegisteredName:  "error_logger",
				CurrentFunction: true,
				NameSource:      "current_function",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.raw)%8 != 0 {
				t.Fatalf("fixture record len %d not 8-byte aligned", len(tc.raw))
			}
			if got := int(binary.LittleEndian.Uint16(tc.raw)); got != len(tc.raw) {
				t.Fatalf("len field %d != record size %d", got, len(tc.raw))
			}
			got, err := decodeRecord(tc.raw)
			if err != nil {
				t.Fatalf("decodeRecord: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("decode mismatch:\n got: %#v\nwant: %#v", got, tc.want)
			}
		})
	}
}

// TestMonitorEventPackedLayout pins the ABI ruling that payload fields are
// packed in listed order with no inter-field padding: MONITOR_EVENT's value
// sits at payload offset 9 (after pid_key u64 + kind u8), not at a naturally
// aligned offset 16. Both encodings pad to the same record length, so only a
// byte-level check can catch a drift here.
func TestMonitorEventPackedLayout(t *testing.T) {
	const value = uint64(0x1122334455667788)
	raw := encMonitorEvent(tK, tU, 0xaabb, 3, value)
	if len(raw) != 48 {
		t.Fatalf("record length %d, want 48", len(raw))
	}
	payload := raw[recordHeaderSize:]
	if got := payload[8]; got != 3 {
		t.Fatalf("kind at payload offset 8 = %d, want 3", got)
	}
	if got := binary.LittleEndian.Uint64(payload[9:]); got != value {
		t.Fatalf("value at payload offset 9 = 0x%x, want 0x%x", got, value)
	}
	rec, err := decodeRecord(raw)
	if err != nil {
		t.Fatalf("decodeRecord: %v", err)
	}
	me := rec.(*MonitorEvent)
	if me.PidKey != 0xaabb || me.Kind != 3 || me.Value != value {
		t.Fatalf("packed decode mismatch: %+v", me)
	}
}

func TestDecodeUnknownType(t *testing.T) {
	raw := encRecord(0x7f, 0, tK, tU, []byte{1, 2, 3, 4})
	if _, err := decodeRecord(raw); !errors.Is(err, errUnknownRecordType) {
		t.Fatalf("want errUnknownRecordType, got %v", err)
	}
}

func TestDecodeTruncatedPayload(t *testing.T) {
	// A GC_DELTA whose len only covers half its payload.
	full := encGCDelta(tK, tU, 1, 2, 3, 4, 0)
	short := full[:32]
	binary.LittleEndian.PutUint16(short[0:], 32)
	if _, err := decodeRecord(short); !errors.Is(err, errTruncatedRecord) {
		t.Fatalf("want errTruncatedRecord, got %v", err)
	}
}

// BenchmarkDecodeRecord is the per-record decode baseline (one fixed-field
// record and one string-carrying record per iteration).
func BenchmarkDecodeRecord(b *testing.B) {
	gc := encGCDelta2(tK, tU, 0xbeef2, 40_000, 512, 1_024, 121_393, 250_000, 1)
	pm := encProcMetaReg(procMetaFlagTranslated|procMetaFlagRegisteredName,
		tK, tU, 0xcafe, 999, 1, "gen_server", "init", "<0.201.0>",
		"guild_registry")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := decodeRecord(gc); err != nil {
			b.Fatal(err)
		}
		if _, err := decodeRecord(pm); err != nil {
			b.Fatal(err)
		}
	}
}

func TestDecodeEmptyStrings(t *testing.T) {
	raw := encProcMeta(tK, tU, 5, 0, 0, "", "", "")
	rec, err := decodeRecord(raw)
	if err != nil {
		t.Fatalf("decodeRecord: %v", err)
	}
	pm := rec.(*ProcMeta)
	if pm.Module != "" || pm.Function != "" || pm.PidPrintable != "" {
		t.Fatalf("expected empty strings, got %#v", pm)
	}
	if pm.SpawnKtimeNS != 0 {
		t.Fatalf("expected zero spawn ktime, got %d", pm.SpawnKtimeNS)
	}
}
