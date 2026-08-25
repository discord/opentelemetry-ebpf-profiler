// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Discord addition. Record decoding for the beam_scope shared-memory ABI v1.
// The layout is specified in the monorepo at discord_common/ex/beam_scope/ABI.md;
// this file is the reader side of that contract and must not drift from it.
//
// All integers little-endian. Records are length-prefixed TLVs, 8-byte aligned,
// with a fixed 24-byte header carrying both clocks. Payload fields are packed
// sequentially with no inter-field padding; strings are a u8 length followed by
// the bytes (no NUL); the whole record is padded to 8-byte alignment at the end.
package beamscope // import "go.opentelemetry.io/ebpf-profiler/interpreter/beamscope"

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Record type identifiers (ABI.md section 3).
const (
	recTypePad          = 0x00
	recTypeGCDelta      = 0x01
	recTypeProcMeta     = 0x02
	recTypeProcExit     = 0x03
	recTypePanelSample  = 0x04
	recTypeTopkSend     = 0x05
	recTypeMonitorEvent = 0x06
	recTypePanelTick    = 0x07
	recTypeGCDelta2     = 0x08
	recTypeSchedUtil    = 0x09
	recTypeSchedDelta   = 0x0A
	recTypeScopeConfig  = 0x0B
	recTypeVMStat       = 0x0C
	recTypeMsgFlow      = 0x0D
	recTypeSenderTopk   = 0x0E
	recTypePortStat     = 0x0F
	recTypeEtsStat      = 0x10
)

// Per-type record flag bits (record header flags field).
const (
	// procMetaFlagTranslated: initial_call was translated through proc_lib,
	// i.e. module/function is the real callback module, not proc_lib:init_p.
	procMetaFlagTranslated = 1 << 0
	// procMetaFlagRegisteredName: a registered_name string is appended
	// immediately after pid_printable. Absent entirely when clear, so
	// pre-bit1 captures decode unchanged.
	procMetaFlagRegisteredName = 1 << 1
	// procMetaFlagCurrentFunction: module/function/arity is a
	// current_function snapshot (fallback when there is no translatable
	// $initial_call) -- it names what the process was doing, not how it
	// started.
	procMetaFlagCurrentFunction = 1 << 2
	// schedUtilFlagMsaccValid: the msacc microstate fields carry data (zero
	// otherwise, when msacc is not enabled in the writer's config).
	schedUtilFlagMsaccValid = 1 << 0
	// schedDeltaFlagUnclassified: preempt/yield classification unsupported by
	// this writer; those counters are zero, nswitches is still valid.
	schedDeltaFlagUnclassified = 1 << 0
	// scopeConfigFlagActive: tracing is active in the writer (the config
	// reflects a live BeamScope.start/1, not a stopped/idle segment).
	scopeConfigFlagActive = 1 << 0
	// vmStatFlagMemoryValid: the mem_* fields carry data (zero otherwise, when
	// the writer's memory sampling is disabled).
	vmStatFlagMemoryValid = 1 << 0
	// panelTickFlagDroppedValid: dropped_ticks (payload bytes 12-15, formerly
	// reserved) carries data. Captures from writers predating the counter have
	// the flag clear and zeroes in those bytes, so they decode unchanged.
	panelTickFlagDroppedValid = 1 << 0
	// portStatFlagDist: the record carries a trailing node_name string (the
	// port is a distribution port). Absent entirely when clear.
	portStatFlagDist = 1 << 0
	// etsStatFlagSweepTruncated: the writer ranked only a subset of ETS tables
	// for this sweep (e.g. it hit a scan budget), not the full table set.
	etsStatFlagSweepTruncated = 1 << 0
)

// recordHeaderSize is the fixed record header: len u16, type u16, flags u32,
// ktime_ns u64, unix_ns u64.
const recordHeaderSize = 24

var (
	// errUnknownRecordType marks a record type this reader does not know. The
	// caller must skip it by length and count it; it is never fatal (ABI rule).
	errUnknownRecordType = errors.New("unknown record type")
	// errTruncatedRecord marks a known record type whose len is too small for
	// its payload. Skipped by length and counted, like an unknown type.
	errTruncatedRecord = errors.New("truncated record payload")
)

// RecordHeader is the fixed header present on every record. The JSON tags are
// part of the JSONL sidecar contract: ktime_ns and unix_ns appear on every line.
type RecordHeader struct {
	Len     uint16 `json:"-"`
	Type    uint16 `json:"-"`
	Flags   uint32 `json:"record_flags,omitempty"`
	KTimeNS uint64 `json:"ktime_ns"`
	UnixNS  uint64 `json:"unix_ns"`
}

// Record is a decoded beam_scope record.
type Record interface {
	Header() *RecordHeader
	// TypeName is the snake_case name used as the JSONL "type" field.
	TypeName() string
}

func (h *RecordHeader) Header() *RecordHeader { return h }

// GCDelta (0x01): emitted when a process's allocated-words accumulator crosses
// the configured threshold at a GC.
type GCDelta struct {
	RecordHeader
	PidKey             uint64 `json:"pid_key"`
	AllocWords         uint64 `json:"alloc_words"`
	BinVheapDeltaWords uint64 `json:"bin_vheap_delta_words"`
	HeapSizeWords      uint64 `json:"heap_size_words"`
	GCKind             uint8  `json:"gc_kind"` // 0 minor, 1 major
}

func (*GCDelta) TypeName() string { return "gc_delta" }

// ProcMeta (0x02): lazy pid_key -> initial_call metadata. A later PROC_META
// for the same pid_key REPLACES the cached entry (writers re-emit when better
// metadata becomes available, e.g. after proc_lib translation).
type ProcMeta struct {
	RecordHeader
	PidKey       uint64 `json:"pid_key"`
	SpawnKtimeNS uint64 `json:"spawn_ktime_ns"` // 0 if unknown (pre-attach process)
	Arity        uint8  `json:"arity"`
	Module       string `json:"module"`
	Function     string `json:"function"`
	PidPrintable string `json:"pid_printable"`
	// RegisteredName (flags bit1): the process's registered name, appended
	// after pid_printable. Empty when the record carries none.
	RegisteredName string `json:"registered_name,omitempty"`
	// Translated (flags bit0): module/function is the proc_lib-translated
	// real callback module rather than proc_lib:init_p.
	Translated bool `json:"translated"`
	// CurrentFunction (flags bit2): module/function/arity is a
	// current_function snapshot, not an initial call.
	CurrentFunction bool `json:"-"`
	// NameSource says where module/function came from:
	// "current_function" (bit2), "translated" (bit0), or "initial_call".
	NameSource string `json:"name_source"`
}

func (*ProcMeta) TypeName() string { return "proc_meta" }

// ProcExit (0x03).
type ProcExit struct {
	RecordHeader
	PidKey      uint64 `json:"pid_key"`
	ReasonClass uint8  `json:"reason_class"` // 0 normal, 1 shutdown, 2 killed, 3 other
}

func (*ProcExit) TypeName() string { return "proc_exit" }

// PanelSample (0x04): one process_info poll of a panel/watch-list member.
type PanelSample struct {
	RecordHeader
	PidKey          uint64 `json:"pid_key"`
	MsgqLen         uint64 `json:"msgq_len"`
	MemoryBytes     uint64 `json:"memory_bytes"`
	Reductions      uint64 `json:"reductions"`
	ReductionsDelta uint64 `json:"reductions_delta"` // 0 on first observation
	MsgqDelta       int64  `json:"msgq_delta"`       // 0 on first observation
	SampleFlags     uint32 `json:"sample_flags"`     // bit0 panel, bit1 watch, bit2 sticky
	Epoch           uint32 `json:"epoch"`
}

func (*PanelSample) TypeName() string { return "panel_sample" }

// TopkSend (0x05): one entry of the send-side heavy-hitter sketch.
type TopkSend struct {
	RecordHeader
	PidKey      uint64 `json:"pid_key"` // destination
	EstArrivals uint64 `json:"est_arrivals"`
	Epoch       uint32 `json:"epoch"`
	Rank        uint8  `json:"rank"` // 0 = hottest
}

func (*TopkSend) TypeName() string { return "topk_send" }

// MonitorEvent (0x06): a system_monitor hit.
type MonitorEvent struct {
	RecordHeader
	PidKey uint64 `json:"pid_key"`
	Kind   uint8  `json:"kind"` // 0 large_heap, 1 long_schedule, 2 busy_port, 3 busy_dist_port
	Value  uint64 `json:"value"`
}

func (*MonitorEvent) TypeName() string { return "monitor_event" }

// PanelTick (0x07): one per Panel tick; delimits epochs.
type PanelTick struct {
	RecordHeader
	Epoch     uint32 `json:"epoch"`
	PanelSize uint32 `json:"panel_size"`
	WatchSize uint32 `json:"watch_size"`
	// DroppedTicks counts Panel ticks the writer skipped, and is meaningful
	// only when DroppedValid: a zero with the flag clear means "this writer
	// does not report it", not "none were dropped".
	DroppedTicks uint32 `json:"dropped_ticks"`
	DroppedValid bool   `json:"dropped_valid"`
	ProcessCount uint64 `json:"process_count"`
}

func (*PanelTick) TypeName() string { return "panel_tick" }

// GCDelta2 (0x08): supersedes GC_DELTA for new writers (0x01 stays decodable
// for old captures). Emitted at GC end rather than start, so it carries the
// pause and the message-buffer words.
type GCDelta2 struct {
	RecordHeader
	PidKey             uint64 `json:"pid_key"`
	AllocWords         uint64 `json:"alloc_words"`
	BinVheapDeltaWords uint64 `json:"bin_vheap_delta_words"`
	MbufWords          uint64 `json:"mbuf_words"`
	HeapSizeWords      uint64 `json:"heap_size_words"` // live heap after this GC
	PauseNS            uint64 `json:"pause_ns"`
	GCKind             uint8  `json:"gc_kind"` // 0 minor, 1 major
}

func (*GCDelta2) TypeName() string { return "gc_delta2" }

// SchedUtil (0x09): one per scheduler per Panel tick. Microstate fields are
// zero unless MsaccValid.
type SchedUtil struct {
	RecordHeader
	SchedulerID uint32 `json:"scheduler_id"`
	SchedType   uint8  `json:"sched_type"` // 0 normal, 1 dirty_cpu, 2 dirty_io
	Epoch       uint32 `json:"epoch"`
	ActiveNS    uint64 `json:"active_ns"`
	TotalNS     uint64 `json:"total_ns"`
	EmulatorNS  uint64 `json:"emulator_ns"`
	GCNS        uint64 `json:"gc_ns"`
	PortNS      uint64 `json:"port_ns"`
	SleepNS     uint64 `json:"sleep_ns"`
	OtherNS     uint64 `json:"other_ns"`
	// MsaccValid (flags bit0): the msacc microstate fields carry data.
	MsaccValid bool `json:"msacc_valid"`
}

func (*SchedUtil) TypeName() string { return "sched_util" }

// SchedDelta (0x0A): per-Erlang-process on-scheduler time, emitted when the
// writer's per-pid accumulator crosses its threshold.
type SchedDelta struct {
	RecordHeader
	PidKey    uint64 `json:"pid_key"`
	OnSchedNS uint64 `json:"on_sched_ns"`
	NSwitches uint32 `json:"nswitches"`
	Preempts  uint32 `json:"preempts"`
	Yields    uint32 `json:"yields"`
	Reserved  uint32 `json:"-"`
	// ClassificationUnsupported (flags bit0): preempts/yields are zero
	// because this writer cannot classify; nswitches is still valid.
	ClassificationUnsupported bool `json:"classification_unsupported"`
}

func (*SchedDelta) TypeName() string { return "sched_delta" }

// ScopeConfig (0x0B): the writer's live sampling/config knobs, re-emitted
// whenever they change. Six payload lengths are in the wild (36, 40, 48, 60,
// 64, 72 bytes); a longer payload from a newer writer is decoded the same as
// 72 and any bytes past offset 72 are future fields this reader does not know
// about yet (tolerated, never read). PayloadLen lets a consumer distinguish a
// field that is genuinely 0 from one absent at this writer's length -- e.g.
// TickMS == 0 with PayloadLen == 36 means "this writer never had a tick_ms
// field", not "tick_ms is known to be zero".
type ScopeConfig struct {
	RecordHeader
	// SendSampleShift: send-side sample-rate shift; >= 63 means send sampling
	// is disabled.
	SendSampleShift  uint32 `json:"send_sample_shift"`
	GCThresholdWords uint64 `json:"gc_threshold_words"`
	SchedThresholdNS uint64 `json:"sched_threshold_ns"`
	SketchCapacity   uint32 `json:"sketch_capacity"`
	MirrorCapacity   uint32 `json:"mirror_capacity"`
	TopkK            uint32 `json:"topk_k"`
	// MemoryEvery: 0 means unknown (also the zero value when absent at
	// PayloadLen == 36, which ends exactly at this field).
	MemoryEvery uint32 `json:"memory_every"`
	// TickMS: 0 means unknown/no panel; also the zero value when absent at
	// PayloadLen < 40.
	TickMS uint32 `json:"tick_ms"`
	// RecvSampleShift: >= 63 means receive tracing is disabled; also the zero
	// value when absent at PayloadLen < 48.
	RecvSampleShift   uint32 `json:"recv_sample_shift"`
	RecvEmitThreshold uint32 `json:"recv_emit_threshold"`
	// SenderSampleShift: >= 63 means SENDER_TOPK sampling is disabled; also
	// the zero value when absent at PayloadLen < 60. Distinct from
	// SendSampleShift (TOPK_SEND, 0x05) -- these are two independently
	// configured sketches.
	SenderSampleShift uint32 `json:"sender_sample_shift"`
	// SenderTopkK: 0 means SENDER_TOPK is off; also the zero value when
	// absent at PayloadLen < 60.
	SenderTopkK uint32 `json:"sender_topk_k"`
	// WatchSetSize: also the zero value when absent at PayloadLen < 60.
	WatchSetSize uint32 `json:"watch_set_size"`
	// PortTopN: 0 means PORT_STAT is off; also the zero value when absent at
	// PayloadLen < 64.
	PortTopN uint32 `json:"port_top_n"`
	// EtsTopN: 0 means ETS_STAT is off; also the zero value when absent at
	// PayloadLen < 72.
	EtsTopN uint32 `json:"ets_top_n"`
	// EtsEvery: 0 means off/unknown; also the zero value when absent at
	// PayloadLen < 72.
	EtsEvery uint32 `json:"ets_every"`
	// Active (flags bit0): tracing is active in the writer.
	Active bool `json:"active"`
	// PayloadLen is the number of payload bytes actually present in this
	// record (36, 40, 48, 60, 64, or 72 for known writers so far; may be
	// larger for a future writer whose extra fields this reader does not
	// decode).
	PayloadLen int `json:"payload_len"`
}

func (*ScopeConfig) TypeName() string { return "scope_config" }

// VMStat (0x0C): one whole-VM statistics snapshot per Panel tick.
type VMStat struct {
	RecordHeader
	ContextSwitches uint64 `json:"context_switches"` // cumulative
	RunQueueTotal   uint64 `json:"run_queue_total"`  // instantaneous
	IOInBytes       uint64 `json:"io_in_bytes"`      // cumulative
	IOOutBytes      uint64 `json:"io_out_bytes"`     // cumulative
	Reductions      uint64 `json:"reductions"`       // cumulative
	AtomCount       uint32 `json:"atom_count"`
	PortCount       uint32 `json:"port_count"`
	// MemTotal/MemProcesses/MemBinary/MemEts are zero unless MemoryValid.
	MemTotal     uint64 `json:"mem_total"`
	MemProcesses uint64 `json:"mem_processes"`
	MemBinary    uint64 `json:"mem_binary"`
	MemEts       uint64 `json:"mem_ets"`
	Epoch        uint32 `json:"epoch"`
	// MemoryValid (flags bit0): the mem_* fields carry data.
	MemoryValid bool `json:"memory_valid"`
}

func (*VMStat) TypeName() string { return "vm_stat" }

// MsgFlow (0x0D): one send-arrival-rate sample for a destination pid_key.
// ArrivalsRaw is a raw sampled count; scale by 2^RecvSampleShift from the
// drainer's latestConfig to get the estimated true arrival count.
type MsgFlow struct {
	RecordHeader
	PidKey      uint64 `json:"pid_key"`
	ArrivalsRaw uint64 `json:"arrivals_raw"`
}

func (*MsgFlow) TypeName() string { return "msg_flow" }

// SenderTopk (0x0E): one entry of the send-side heavy-hitter sketch keyed by
// (dest, sender) pair, distinguishing this from TOPK_SEND (0x05) which is
// keyed by destination alone. EstArrivals is raw; scale by
// 2^SenderSampleShift (ScopeConfig) to get the estimated true count -- this
// reader does not perform that scaling, unlike MsgFlow's pprof path.
type SenderTopk struct {
	RecordHeader
	DestPidKey   uint64 `json:"dest_pid_key"`
	SenderPidKey uint64 `json:"sender_pid_key"`
	EstArrivals  uint64 `json:"est_arrivals"`
	// Epoch carries the same TOPK_SEND-style E vs E+1 skew as TopkSend;
	// decoded verbatim, not reconciled here.
	Epoch uint32 `json:"epoch"`
	Rank  uint8  `json:"rank"` // 0 = hottest
}

func (*SenderTopk) TypeName() string { return "sender_topk" }

// PortStat (0x0F): one entry of the per-port ranking (e.g. by queue size).
type PortStat struct {
	RecordHeader
	PortKey        uint64 `json:"port_key"`
	QueueSizeBytes uint64 `json:"queue_size_bytes"`
	// ConnectedPidKey: 0 means the connected process is gone.
	ConnectedPidKey uint64 `json:"connected_pid_key"`
	Epoch           uint32 `json:"epoch"`
	Rank            uint8  `json:"rank"` // 0 = hottest
	DriverName      string `json:"driver_name"`
	PortPrintable   string `json:"port_printable"`
	// NodeName (flags bit0/Dist): present only for a distribution port.
	NodeName string `json:"node_name,omitempty"`
	// Dist (flags bit0): this is a distribution port; NodeName is present.
	Dist bool `json:"dist"`
}

func (*PortStat) TypeName() string { return "port_stat" }

// EtsStat (0x10): one entry of the per-ETS-table ranking (e.g. by memory).
type EtsStat struct {
	RecordHeader
	OwnerPidKey uint64 `json:"owner_pid_key"`
	MemoryWords uint64 `json:"memory_words"`
	SizeObjects uint64 `json:"size_objects"`
	Epoch       uint32 `json:"epoch"`
	Rank        uint8  `json:"rank"` // 0 = hottest
	Name        string `json:"name"`
	// SweepTruncated (flags bit0): the writer ranked only a subset of ETS
	// tables for this sweep, not the full table set.
	SweepTruncated bool `json:"sweep_truncated"`
}

func (*EtsStat) TypeName() string { return "ets_stat" }

// cursor is a bounds-checked sequential reader over a record payload.
type cursor struct {
	b   []byte
	off int
	err bool
}

func (c *cursor) need(n int) bool {
	if c.err || c.off+n > len(c.b) {
		c.err = true
		return false
	}
	return true
}

func (c *cursor) u8() uint8 {
	if !c.need(1) {
		return 0
	}
	v := c.b[c.off]
	c.off++
	return v
}

func (c *cursor) u32() uint32 {
	if !c.need(4) {
		return 0
	}
	v := binary.LittleEndian.Uint32(c.b[c.off:])
	c.off += 4
	return v
}

func (c *cursor) u64() uint64 {
	if !c.need(8) {
		return 0
	}
	v := binary.LittleEndian.Uint64(c.b[c.off:])
	c.off += 8
	return v
}

func (c *cursor) i64() int64 { return int64(c.u64()) }

// str reads a `u8 len` prefixed string (no NUL terminator).
func (c *cursor) str() string {
	l := int(c.u8())
	if !c.need(l) {
		return ""
	}
	v := string(c.b[c.off : c.off+l])
	c.off += l
	return v
}

// decodeRecord decodes one complete record (header included). The caller has
// already validated len and sliced rec to exactly that many bytes.
func decodeRecord(rec []byte) (Record, error) {
	if len(rec) < recordHeaderSize {
		return nil, errTruncatedRecord
	}
	hdr := RecordHeader{
		Len:     binary.LittleEndian.Uint16(rec[0:]),
		Type:    binary.LittleEndian.Uint16(rec[2:]),
		Flags:   binary.LittleEndian.Uint32(rec[4:]),
		KTimeNS: binary.LittleEndian.Uint64(rec[8:]),
		UnixNS:  binary.LittleEndian.Uint64(rec[16:]),
	}
	c := &cursor{b: rec[recordHeaderSize:]}

	var out Record
	switch hdr.Type {
	case recTypeGCDelta:
		out = &GCDelta{
			RecordHeader:       hdr,
			PidKey:             c.u64(),
			AllocWords:         c.u64(),
			BinVheapDeltaWords: c.u64(),
			HeapSizeWords:      c.u64(),
			GCKind:             c.u8(),
		}
	case recTypeProcMeta:
		pm := &ProcMeta{
			RecordHeader:    hdr,
			PidKey:          c.u64(),
			SpawnKtimeNS:    c.u64(),
			Arity:           c.u8(),
			Module:          c.str(),
			Function:        c.str(),
			PidPrintable:    c.str(),
			Translated:      hdr.Flags&procMetaFlagTranslated != 0,
			CurrentFunction: hdr.Flags&procMetaFlagCurrentFunction != 0,
		}
		if hdr.Flags&procMetaFlagRegisteredName != 0 {
			pm.RegisteredName = c.str()
		}
		switch {
		case pm.CurrentFunction:
			pm.NameSource = "current_function"
		case pm.Translated:
			pm.NameSource = "translated"
		default:
			pm.NameSource = "initial_call"
		}
		out = pm
	case recTypeProcExit:
		out = &ProcExit{
			RecordHeader: hdr,
			PidKey:       c.u64(),
			ReasonClass:  c.u8(),
		}
	case recTypePanelSample:
		out = &PanelSample{
			RecordHeader:    hdr,
			PidKey:          c.u64(),
			MsgqLen:         c.u64(),
			MemoryBytes:     c.u64(),
			Reductions:      c.u64(),
			ReductionsDelta: c.u64(),
			MsgqDelta:       c.i64(),
			SampleFlags:     c.u32(),
			Epoch:           c.u32(),
		}
	case recTypeTopkSend:
		out = &TopkSend{
			RecordHeader: hdr,
			PidKey:       c.u64(),
			EstArrivals:  c.u64(),
			Epoch:        c.u32(),
			Rank:         c.u8(),
		}
	case recTypeMonitorEvent:
		out = &MonitorEvent{
			RecordHeader: hdr,
			PidKey:       c.u64(),
			Kind:         c.u8(),
			Value:        c.u64(),
		}
	case recTypePanelTick:
		out = &PanelTick{
			RecordHeader: hdr,
			Epoch:        c.u32(),
			PanelSize:    c.u32(),
			WatchSize:    c.u32(),
			DroppedTicks: c.u32(),
			DroppedValid: hdr.Flags&panelTickFlagDroppedValid != 0,
			ProcessCount: c.u64(),
		}
	case recTypeGCDelta2:
		out = &GCDelta2{
			RecordHeader:       hdr,
			PidKey:             c.u64(),
			AllocWords:         c.u64(),
			BinVheapDeltaWords: c.u64(),
			MbufWords:          c.u64(),
			HeapSizeWords:      c.u64(),
			PauseNS:            c.u64(),
			GCKind:             c.u8(),
		}
	case recTypeSchedUtil:
		out = &SchedUtil{
			RecordHeader: hdr,
			SchedulerID:  c.u32(),
			SchedType:    c.u8(),
			Epoch:        c.u32(),
			ActiveNS:     c.u64(),
			TotalNS:      c.u64(),
			EmulatorNS:   c.u64(),
			GCNS:         c.u64(),
			PortNS:       c.u64(),
			SleepNS:      c.u64(),
			OtherNS:      c.u64(),
			MsaccValid:   hdr.Flags&schedUtilFlagMsaccValid != 0,
		}
	case recTypeSchedDelta:
		out = &SchedDelta{
			RecordHeader:              hdr,
			PidKey:                    c.u64(),
			OnSchedNS:                 c.u64(),
			NSwitches:                 c.u32(),
			Preempts:                  c.u32(),
			Yields:                    c.u32(),
			Reserved:                  c.u32(),
			ClassificationUnsupported: hdr.Flags&schedDeltaFlagUnclassified != 0,
		}
	case recTypeScopeConfig:
		// payloadLen drives the absent-field convention: fields past what this
		// writer's length covers are never read (they stay Go zero values),
		// and a payload shorter than the oldest known shape is truncated via
		// the cursor's own bounds check below, same as every other type.
		payloadLen := len(rec) - recordHeaderSize
		sc := &ScopeConfig{
			RecordHeader:     hdr,
			PayloadLen:       payloadLen,
			SendSampleShift:  c.u32(),
			GCThresholdWords: c.u64(),
			SchedThresholdNS: c.u64(),
			SketchCapacity:   c.u32(),
			MirrorCapacity:   c.u32(),
			TopkK:            c.u32(),
			MemoryEvery:      c.u32(),
			Active:           hdr.Flags&scopeConfigFlagActive != 0,
		}
		if payloadLen >= 40 {
			sc.TickMS = c.u32()
		}
		if payloadLen >= 48 {
			sc.RecvSampleShift = c.u32()
			sc.RecvEmitThreshold = c.u32()
		}
		if payloadLen >= 60 {
			sc.SenderSampleShift = c.u32()
			sc.SenderTopkK = c.u32()
			sc.WatchSetSize = c.u32()
		}
		if payloadLen >= 64 {
			sc.PortTopN = c.u32()
		}
		if payloadLen >= 72 {
			sc.EtsTopN = c.u32()
			sc.EtsEvery = c.u32()
		}
		out = sc
	case recTypeVMStat:
		out = &VMStat{
			RecordHeader:    hdr,
			ContextSwitches: c.u64(),
			RunQueueTotal:   c.u64(),
			IOInBytes:       c.u64(),
			IOOutBytes:      c.u64(),
			Reductions:      c.u64(),
			AtomCount:       c.u32(),
			PortCount:       c.u32(),
			MemTotal:        c.u64(),
			MemProcesses:    c.u64(),
			MemBinary:       c.u64(),
			MemEts:          c.u64(),
			Epoch:           c.u32(),
			MemoryValid:     hdr.Flags&vmStatFlagMemoryValid != 0,
		}
	case recTypeMsgFlow:
		out = &MsgFlow{
			RecordHeader: hdr,
			PidKey:       c.u64(),
			ArrivalsRaw:  c.u64(),
		}
	case recTypeSenderTopk:
		out = &SenderTopk{
			RecordHeader: hdr,
			DestPidKey:   c.u64(),
			SenderPidKey: c.u64(),
			EstArrivals:  c.u64(),
			Epoch:        c.u32(),
			Rank:         c.u8(),
		}
	case recTypePortStat:
		ps := &PortStat{
			RecordHeader:    hdr,
			PortKey:         c.u64(),
			QueueSizeBytes:  c.u64(),
			ConnectedPidKey: c.u64(),
			Epoch:           c.u32(),
			Rank:            c.u8(),
			DriverName:      c.str(),
			PortPrintable:   c.str(),
			Dist:            hdr.Flags&portStatFlagDist != 0,
		}
		if ps.Dist {
			ps.NodeName = c.str()
		}
		out = ps
	case recTypeEtsStat:
		out = &EtsStat{
			RecordHeader:   hdr,
			OwnerPidKey:    c.u64(),
			MemoryWords:    c.u64(),
			SizeObjects:    c.u64(),
			Epoch:          c.u32(),
			Rank:           c.u8(),
			Name:           c.str(),
			SweepTruncated: hdr.Flags&etsStatFlagSweepTruncated != 0,
		}
	default:
		return nil, fmt.Errorf("%w: 0x%02x", errUnknownRecordType, hdr.Type)
	}
	if c.err {
		return nil, fmt.Errorf("%w: type 0x%02x len %d", errTruncatedRecord, hdr.Type, hdr.Len)
	}
	return out, nil
}
