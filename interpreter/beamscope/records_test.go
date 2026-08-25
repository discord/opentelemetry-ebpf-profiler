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
			// Payload bytes 12-15 used to be discarded as Reserved; the
			// producer now writes dropped_ticks there, valid when flags bit0
			// is set. A pre-bit0 capture keeps decoding as DroppedValid=false.
			name: "panel_tick_dropped",
			raw:  encPanelTickDropped(tK, tU, 43, 1000, 64, 350_001, 17, true),
			want: &PanelTick{
				RecordHeader: RecordHeader{Len: 48, Type: recTypePanelTick,
					Flags: panelTickFlagDroppedValid, KTimeNS: tK, UnixNS: tU},
				Epoch:        43,
				PanelSize:    1000,
				WatchSize:    64,
				DroppedTicks: 17,
				DroppedValid: true,
				ProcessCount: 350_001,
			},
		},
		{
			// dropped_ticks present in the bytes but the flag clear: the
			// value is not trustworthy, so it must not be surfaced as valid.
			name: "panel_tick_dropped_flag_clear",
			raw:  encPanelTickDropped(tK, tU, 44, 1000, 64, 350_002, 17, false),
			want: &PanelTick{
				RecordHeader: hdr(recTypePanelTick, 48),
				Epoch:        44,
				PanelSize:    1000,
				WatchSize:    64,
				DroppedTicks: 17,
				DroppedValid: false,
				ProcessCount: 350_002,
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
			name: "vm_stat",
			raw: encVMStat(vmStatFlagMemoryValid, tK, tU,
				1_234_567, 8, 999_000, 111_000, 50_000_000, 4096, 64,
				100_000_000, 60_000_000, 20_000_000, 15_000_000, 99),
			want: &VMStat{
				RecordHeader: RecordHeader{Len: 112, Type: recTypeVMStat,
					Flags: vmStatFlagMemoryValid, KTimeNS: tK, UnixNS: tU},
				ContextSwitches: 1_234_567,
				RunQueueTotal:   8,
				IOInBytes:       999_000,
				IOOutBytes:      111_000,
				Reductions:      50_000_000,
				AtomCount:       4096,
				PortCount:       64,
				MemTotal:        100_000_000,
				MemProcesses:    60_000_000,
				MemBinary:       20_000_000,
				MemEts:          15_000_000,
				Epoch:           99,
				MemoryValid:     true,
			},
		},
		{
			name: "vm_stat_memory_invalid",
			// flags bit0 clear: mem_* fields are zero (writer's convention),
			// not decoder-injected -- the encoded bytes really are zero here.
			raw: encVMStat(0, tK, tU,
				1_234_567, 8, 999_000, 111_000, 50_000_000, 4096, 64,
				0, 0, 0, 0, 99),
			want: &VMStat{
				RecordHeader:    hdr(recTypeVMStat, 112),
				ContextSwitches: 1_234_567,
				RunQueueTotal:   8,
				IOInBytes:       999_000,
				IOOutBytes:      111_000,
				Reductions:      50_000_000,
				AtomCount:       4096,
				PortCount:       64,
				Epoch:           99,
				MemoryValid:     false,
			},
		},
		{
			name: "msg_flow",
			raw:  encMsgFlow(tK, tU, 0x2222, 777),
			want: &MsgFlow{
				RecordHeader: hdr(recTypeMsgFlow, 40),
				PidKey:       0x2222,
				ArrivalsRaw:  777,
			},
		},
		{
			name: "sender_topk",
			// payload 8+8+8+4+1 = 29 -> record 53 -> 56
			raw: encSenderTopk(tK, tU, 0x1111, 0x2222, 500_000, 7, 2),
			want: &SenderTopk{
				RecordHeader: hdr(recTypeSenderTopk, 56),
				DestPidKey:   0x1111,
				SenderPidKey: 0x2222,
				EstArrivals:  500_000,
				Epoch:        7,
				Rank:         2,
			},
		},
		{
			name: "port_stat_no_dist",
			raw: encPortStat(tK, tU, 0xf00, 4096, 0xbeef, 3, 0,
				"tcp_inet", "#Port<0.7>", false, ""),
			want: &PortStat{
				RecordHeader:    hdr(recTypePortStat, 80),
				PortKey:         0xf00,
				QueueSizeBytes:  4096,
				ConnectedPidKey: 0xbeef,
				Epoch:           3,
				Rank:            0,
				DriverName:      "tcp_inet",
				PortPrintable:   "#Port<0.7>",
			},
		},
		{
			name: "port_stat_dist",
			raw: encPortStat(tK, tU, 0xf01, 8192, 0, 4, 1,
				"tcp_inet", "#Port<0.8>", true, "node2@host"),
			want: &PortStat{
				RecordHeader: RecordHeader{
					Len: 88, Type: recTypePortStat,
					Flags: portStatFlagDist, KTimeNS: tK, UnixNS: tU},
				PortKey:         0xf01,
				QueueSizeBytes:  8192,
				ConnectedPidKey: 0, // connected process gone
				Epoch:           4,
				Rank:            1,
				DriverName:      "tcp_inet",
				PortPrintable:   "#Port<0.8>",
				NodeName:        "node2@host",
				Dist:            true,
			},
		},
		{
			name: "ets_stat",
			raw:  encEtsStat(tK, tU, 0xd00d, 2048, 100, 5, 0, "my_table", false),
			want: &EtsStat{
				RecordHeader: hdr(recTypeEtsStat, 64),
				OwnerPidKey:  0xd00d,
				MemoryWords:  2048,
				SizeObjects:  100,
				Epoch:        5,
				Rank:         0,
				Name:         "my_table",
			},
		},
		{
			name: "ets_stat_sweep_truncated",
			raw:  encEtsStat(tK, tU, 0xd00e, 4096, 200, 6, 1, "big_table", true),
			want: &EtsStat{
				RecordHeader: RecordHeader{
					Len: 64, Type: recTypeEtsStat,
					Flags: etsStatFlagSweepTruncated, KTimeNS: tK, UnixNS: tU},
				OwnerPidKey:    0xd00e,
				MemoryWords:    4096,
				SizeObjects:    200,
				Epoch:          6,
				Rank:           1,
				Name:           "big_table",
				SweepTruncated: true,
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

// TestDecodeScopeConfigLengths pins the three known SCOPE_CONFIG payload
// lengths (36, 40, 48) and the absent-field convention: a field past the
// writer's length decodes as the Go zero value AND PayloadLen says so, so a
// consumer can tell "0" from "this writer never had the field". These are
// kept out of TestDecodeGolden because encScopeConfig(36, ...) deliberately
// builds a non-8-aligned total record length (60 bytes) to make length 36
// distinguishable on the wire from length 40 with tick_ms == 0 -- see
// encScopeConfig's doc comment -- and the golden table asserts 8-byte
// alignment on every fixture.
func TestDecodeScopeConfigLengths(t *testing.T) {
	tests := []struct {
		name       string
		payloadLen int
		flags      uint32
		wantRecLen int
		// want is nil for the truncated case: decodeRecord must return
		// errTruncatedRecord instead of a decoded value.
		want *ScopeConfig
	}{
		{
			name:       "length_36_oldest_writer",
			payloadLen: 36,
			flags:      0,
			wantRecLen: 60,
			want: &ScopeConfig{
				RecordHeader:     hdr(recTypeScopeConfig, 60),
				SendSampleShift:  10,
				GCThresholdWords: 40_000,
				SchedThresholdNS: 2_000_000,
				SketchCapacity:   8192,
				MirrorCapacity:   4096,
				TopkK:            16,
				MemoryEvery:      5000,
				// TickMS, RecvSampleShift, RecvEmitThreshold,
				// SenderSampleShift, SenderTopkK, WatchSetSize, PortTopN,
				// EtsTopN, EtsEvery: absent -> zero, even though nonzero
				// bytes were passed to the encoder for them.
				PayloadLen: 36,
			},
		},
		{
			name:       "length_40_adds_tick_ms",
			payloadLen: 40,
			flags:      0,
			wantRecLen: 64,
			want: &ScopeConfig{
				RecordHeader:     hdr(recTypeScopeConfig, 64),
				SendSampleShift:  10,
				GCThresholdWords: 40_000,
				SchedThresholdNS: 2_000_000,
				SketchCapacity:   8192,
				MirrorCapacity:   4096,
				TopkK:            16,
				MemoryEvery:      5000,
				TickMS:           250,
				// RecvSampleShift, RecvEmitThreshold, SenderSampleShift,
				// SenderTopkK, WatchSetSize, PortTopN, EtsTopN, EtsEvery:
				// still absent -> zero.
				PayloadLen: 40,
			},
		},
		{
			name:       "length_48_newest_writer_active",
			payloadLen: 48,
			flags:      scopeConfigFlagActive,
			wantRecLen: 72,
			want: &ScopeConfig{
				RecordHeader: RecordHeader{Len: 72, Type: recTypeScopeConfig,
					Flags: scopeConfigFlagActive, KTimeNS: tK, UnixNS: tU},
				SendSampleShift:   63, // >= 63: send sampling disabled
				GCThresholdWords:  40_000,
				SchedThresholdNS:  2_000_000,
				SketchCapacity:    8192,
				MirrorCapacity:    4096,
				TopkK:             16,
				MemoryEvery:       5000,
				TickMS:            250,
				RecvSampleShift:   4,
				RecvEmitThreshold: 100,
				Active:            true,
				// SenderSampleShift, SenderTopkK, WatchSetSize, PortTopN,
				// EtsTopN, EtsEvery: all absent -> zero, even though nonzero
				// bytes were passed to the encoder for them.
				PayloadLen: 48,
			},
		},
		{
			name:       "length_60_adds_sender_topk_and_watch_set",
			payloadLen: 60,
			flags:      scopeConfigFlagActive,
			wantRecLen: 84,
			want: &ScopeConfig{
				RecordHeader: RecordHeader{Len: 84, Type: recTypeScopeConfig,
					Flags: scopeConfigFlagActive, KTimeNS: tK, UnixNS: tU},
				SendSampleShift:   63,
				GCThresholdWords:  40_000,
				SchedThresholdNS:  2_000_000,
				SketchCapacity:    8192,
				MirrorCapacity:    4096,
				TopkK:             16,
				MemoryEvery:       5000,
				TickMS:            250,
				RecvSampleShift:   4,
				RecvEmitThreshold: 100,
				SenderSampleShift: 20,
				SenderTopkK:       8,
				WatchSetSize:      32,
				// PortTopN, EtsTopN, EtsEvery: still absent -> zero.
				Active:     true,
				PayloadLen: 60,
			},
		},
		{
			name:       "length_64_adds_port_top_n",
			payloadLen: 64,
			flags:      scopeConfigFlagActive,
			wantRecLen: 88,
			want: &ScopeConfig{
				RecordHeader: RecordHeader{Len: 88, Type: recTypeScopeConfig,
					Flags: scopeConfigFlagActive, KTimeNS: tK, UnixNS: tU},
				SendSampleShift:   63,
				GCThresholdWords:  40_000,
				SchedThresholdNS:  2_000_000,
				SketchCapacity:    8192,
				MirrorCapacity:    4096,
				TopkK:             16,
				MemoryEvery:       5000,
				TickMS:            250,
				RecvSampleShift:   4,
				RecvEmitThreshold: 100,
				SenderSampleShift: 20,
				SenderTopkK:       8,
				WatchSetSize:      32,
				PortTopN:          5,
				// EtsTopN, EtsEvery: still absent -> zero.
				Active:     true,
				PayloadLen: 64,
			},
		},
		{
			name:       "length_72_newest_writer_full",
			payloadLen: 72,
			flags:      scopeConfigFlagActive,
			wantRecLen: 96,
			want: &ScopeConfig{
				RecordHeader: RecordHeader{Len: 96, Type: recTypeScopeConfig,
					Flags: scopeConfigFlagActive, KTimeNS: tK, UnixNS: tU},
				SendSampleShift:   63,
				GCThresholdWords:  40_000,
				SchedThresholdNS:  2_000_000,
				SketchCapacity:    8192,
				MirrorCapacity:    4096,
				TopkK:             16,
				MemoryEvery:       5000,
				TickMS:            250,
				RecvSampleShift:   4,
				RecvEmitThreshold: 100,
				SenderSampleShift: 20,
				SenderTopkK:       8,
				WatchSetSize:      32,
				PortTopN:          5,
				EtsTopN:           5,
				EtsEvery:          1000,
				Active:            true,
				PayloadLen:        72,
			},
		},
		{
			// 20 bytes only covers send_sample_shift + part of
			// gc_threshold_words.
			name:       "truncated_below_minimum",
			payloadLen: 20,
			flags:      0,
			want:       nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// sendShift is the one field the encoder always writes fully
			// (it is the first field, present at every known length), so it
			// doubles as the value asserted in want.SendSampleShift; the
			// truncated case has no want, so any value works.
			sendShift := uint32(10)
			if tc.want != nil {
				sendShift = tc.want.SendSampleShift
			}
			raw := encScopeConfig(tc.payloadLen, tc.flags, tK, tU,
				sendShift, 40_000, 2_000_000, 8192, 4096, 16, 5000,
				250, 4, 100, 20, 8, 32, 5, 5, 1000)

			if tc.want == nil {
				if _, err := decodeRecord(raw); !errors.Is(err, errTruncatedRecord) {
					t.Fatalf("want errTruncatedRecord, got %v", err)
				}
				return
			}
			if len(raw) != tc.wantRecLen {
				t.Fatalf("record length %d, want %d", len(raw), tc.wantRecLen)
			}
			got, err := decodeRecord(raw)
			if err != nil {
				t.Fatalf("decodeRecord: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("decode mismatch:\n got: %#v\nwant: %#v", got, tc.want)
			}
		})
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

// TestDecodeGCDelta2NoStart pins the NO_START flag (0x08 bit0). The writer
// sets it when the matching gc_start was never observed and then ZERO-FILLS
// pause_ns and mbuf_words; gc_kind is meaningless. Without the decode a
// NO_START record is indistinguishable from a genuine 0 ns pause on a
// zero-mbuf GC, and gets averaged into GC-pause statistics as if measured.
// The encoder writes NONZERO values into those fields on purpose here: a
// reader that merely echoed the bytes would pass a zero-valued fixture.
func TestDecodeGCDelta2NoStart(t *testing.T) {
	for _, tc := range []struct {
		name        string
		flags       uint32
		wantNoStart bool
	}{
		{name: "measured", flags: 0, wantNoStart: false},
		{name: "no_start", flags: gcDelta2FlagNoStart, wantNoStart: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := encGCDelta2F(tc.flags, tK, tU, 0x77, 4096, 8, 16, 2048,
				123_456, 1)
			rec, err := decodeRecord(raw)
			if err != nil {
				t.Fatalf("decodeRecord: %v", err)
			}
			g := rec.(*GCDelta2)
			if g.NoStart != tc.wantNoStart {
				t.Fatalf("NoStart = %v, want %v", g.NoStart, tc.wantNoStart)
			}
			// The measured fields decode identically either way; it is the
			// FLAG that tells a consumer whether to trust them. Asserting the
			// raw values still decode keeps the flag from being read as
			// "these bytes are absent".
			if g.AllocWords != 4096 || g.HeapSizeWords != 2048 {
				t.Fatalf("measured fields wrong: %+v", g)
			}
			if g.PauseNS != 123_456 || g.MbufWords != 16 {
				t.Fatalf("payload fields not decoded verbatim: %+v", g)
			}
		})
	}
}

// TestDecodeSchedUtilMsaccOnly pins MSACC_ONLY (0x09 bit1). Aux (sched_type
// 3) and poll (sched_type 4) threads have no scheduler_wall_time entry, so
// the writer zero-fills active_ns/total_ns and scheduler_id is the PER-TYPE
// msacc id. Without the decode those rows reach JSONL as
// "active_ns: 0, total_ns: 0, msacc_valid: true" -- indistinguishable from a
// scheduler that was idle since the previous tick, and colliding with a real
// scheduler's id.
func TestDecodeSchedUtilMsaccOnly(t *testing.T) {
	for _, tc := range []struct {
		name      string
		flags     uint32
		schedType uint8
		active    uint64
		total     uint64
		wantOnly  bool
	}{
		{name: "normal_scheduler", flags: schedUtilFlagMsaccValid,
			schedType: 0, active: 700, total: 1000, wantOnly: false},
		{name: "aux_thread",
			flags:     schedUtilFlagMsaccValid | schedUtilFlagMsaccOnly,
			schedType: 3, wantOnly: true},
		{name: "poll_thread",
			flags:     schedUtilFlagMsaccValid | schedUtilFlagMsaccOnly,
			schedType: 4, wantOnly: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := encSchedUtil(tc.flags, tK, tU, 1, tc.schedType, 3,
				tc.active, tc.total, 10, 20, 30, 40, 50)
			rec, err := decodeRecord(raw)
			if err != nil {
				t.Fatalf("decodeRecord: %v", err)
			}
			su := rec.(*SchedUtil)
			if su.MsaccOnly != tc.wantOnly {
				t.Fatalf("MsaccOnly = %v, want %v", su.MsaccOnly, tc.wantOnly)
			}
			if !su.MsaccValid {
				t.Fatalf("MsaccValid = false, want true: %+v", su)
			}
			if su.SchedType != tc.schedType {
				t.Fatalf("SchedType = %d, want %d", su.SchedType, tc.schedType)
			}
			// The microstate fields are the ones an MsaccOnly row actually
			// carries, so they must survive regardless.
			if su.EmulatorNS != 10 || su.SleepNS != 40 {
				t.Fatalf("microstate fields wrong: %+v", su)
			}
		})
	}
}

// TestDecodeSchedUtilMsaccOnlyWithoutValid covers the flag combination this
// reader must not conflate: bit1 without bit0. Each bit answers a separate
// question (is this an aux/poll row? do the microstate fields carry data?)
// and neither may imply the other.
func TestDecodeSchedUtilMsaccOnlyWithoutValid(t *testing.T) {
	raw := encSchedUtil(schedUtilFlagMsaccOnly, tK, tU, 2, 3, 3,
		0, 0, 0, 0, 0, 0, 0)
	rec, err := decodeRecord(raw)
	if err != nil {
		t.Fatalf("decodeRecord: %v", err)
	}
	su := rec.(*SchedUtil)
	if !su.MsaccOnly || su.MsaccValid {
		t.Fatalf("MsaccOnly=%v MsaccValid=%v, want true/false: %+v",
			su.MsaccOnly, su.MsaccValid, su)
	}
}

// TestDecodeScopeConfigSubsystemFlags pins SCOPE_CONFIG bits 1/2/3
// (MONITORS_ACTIVE, PROCS_ACTIVE, RECV_ACTIVE). They used to survive only as
// the raw record_flags envelope field, forcing every consumer to re-decode
// the producer's ABI by hand.
func TestDecodeScopeConfigSubsystemFlags(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		flags                    uint32
		active, mon, procs, recv bool
	}{
		{name: "torn_down", flags: 0},
		{name: "active_only", flags: scopeConfigFlagActive, active: true},
		{name: "procs_and_recv",
			flags: scopeConfigFlagActive | scopeConfigFlagProcsActive |
				scopeConfigFlagRecvActive,
			active: true, procs: true, recv: true},
		{name: "all",
			flags: scopeConfigFlagActive | scopeConfigFlagMonitorsActive |
				scopeConfigFlagProcsActive | scopeConfigFlagRecvActive,
			active: true, mon: true, procs: true, recv: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := encScopeConfig(72, tc.flags, tK, tU, 6, 40_000, 2_000_000,
				8192, 4096, 16, 5000, 250, 4, 100, 20, 8, 32, 5, 5, 1000)
			rec, err := decodeRecord(raw)
			if err != nil {
				t.Fatalf("decodeRecord: %v", err)
			}
			sc := rec.(*ScopeConfig)
			if sc.Active != tc.active || sc.MonitorsActive != tc.mon ||
				sc.ProcsActive != tc.procs || sc.RecvActive != tc.recv {
				t.Fatalf("active=%v mon=%v procs=%v recv=%v, want %v/%v/%v/%v",
					sc.Active, sc.MonitorsActive, sc.ProcsActive, sc.RecvActive,
					tc.active, tc.mon, tc.procs, tc.recv)
			}
		})
	}
}
