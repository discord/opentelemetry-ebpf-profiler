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
	// $initial_call) — it names what the process was doing, not how it
	// started.
	procMetaFlagCurrentFunction = 1 << 2
	// schedUtilFlagMsaccValid: the msacc microstate fields carry data (zero
	// otherwise, when msacc is not enabled in the writer's config).
	schedUtilFlagMsaccValid = 1 << 0
	// schedDeltaFlagUnclassified: preempt/yield classification unsupported by
	// this writer; those counters are zero, nswitches is still valid.
	schedDeltaFlagUnclassified = 1 << 0
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
	Epoch        uint32 `json:"epoch"`
	PanelSize    uint32 `json:"panel_size"`
	WatchSize    uint32 `json:"watch_size"`
	Reserved     uint32 `json:"-"`
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
			Reserved:     c.u32(),
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
	default:
		return nil, fmt.Errorf("%w: 0x%02x", errUnknownRecordType, hdr.Type)
	}
	if c.err {
		return nil, fmt.Errorf("%w: type 0x%02x len %d", errTruncatedRecord, hdr.Type, hdr.Len)
	}
	return out, nil
}
