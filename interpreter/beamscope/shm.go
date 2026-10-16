// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Shared-memory reader for beam_scope ABI v1. Rings contain aligned records
// that never wrap: PAD records fill the tail. SPSC rings publish write_pos;
// the final ring reserves space with CAS and publishes each record's length.
// Its reader must clear all consumed bytes before advancing read_pos, so a
// new reservation cannot expose stale payload bytes as a record header.
package beamscope // import "go.opentelemetry.io/ebpf-profiler/interpreter/beamscope"

import (
	"encoding/binary"
	"fmt"
	"sync/atomic"
	"unsafe"
)

const (
	// segmentMagic is "BEASCOPE" as big-endian ASCII, stored little-endian.
	segmentMagic = 0x42454153434F5045
	// segmentABIVersion is the only ABI version this reader implements.
	segmentABIVersion = 1
	// segmentHeaderSize is the fixed header page size.
	segmentHeaderSize = 4096
	// ringCtrlSize is the per-ring control block size.
	ringCtrlSize = 64

	// Control block field offsets.
	ctrlOffWritePos = 0
	ctrlOffReadPos  = 8
	ctrlOffDropped  = 16

	// maxRings bounds nrings so the ring_offset array fits in the header page:
	// 64 + 8*nrings <= 4096.
	maxRings = (segmentHeaderSize - 64) / 8
)

// SegmentHeader is the decoded fixed header (page 0).
type SegmentHeader struct {
	TotalSize    uint64
	NRings       uint32
	RingDataSize uint32
	InitKTimeNS  uint64
	InitUnixNS   uint64
	OSPid        uint64
	OTPRelease   uint32
	RingOffsets  []uint64
}

// ringState is the reader-side view of one ring.
type ringState struct {
	ctrlOff uint64 // byte offset of the control block in the segment
	dataOff uint64 // byte offset of the data area
	readPos uint64 // reader-owned monotonic byte counter (mirrors shm read_pos)
	corrupt bool   // set once on corruption; the ring is never drained again
}

// Segment is a mapped (or in tests, in-memory) beam_scope shm segment.
type Segment struct {
	data  []byte
	hdr   SegmentHeader
	rings []ringState
}

// DrainStats accumulates one Drain pass. Dropped and CorruptRings are
// point-in-time totals (writer counter / ring flags), not per-pass deltas.
type DrainStats struct {
	// Records is the number of records delivered to the handler.
	Records uint64
	// Padding is the number of PAD records skipped.
	Padding uint64
	// Unknown is the number of records skipped by length: unknown type or a
	// known type whose payload did not fit its len.
	Unknown uint64
	// Dropped is the writer-side dropped counter, summed over all rings.
	Dropped uint64
	// DroppedPerRing is the writer-side dropped counter of each ring, in ring
	// order. Point-in-time totals, like Dropped.
	DroppedPerRing []uint64
	// CorruptRings is how many rings are stopped due to corruption.
	CorruptRings uint64
}

// NewSegment validates a raw segment and prepares it for draining. read_pos is
// resumed from the segment so a reader restart does not replay records.
func NewSegment(data []byte) (*Segment, error) {
	if len(data) < segmentHeaderSize {
		return nil, fmt.Errorf("segment too small: %d bytes", len(data))
	}
	if got := binary.LittleEndian.Uint64(data[0:]); got != segmentMagic {
		return nil, fmt.Errorf("bad segment magic 0x%016x", got)
	}
	if v := binary.LittleEndian.Uint32(data[8:]); v != segmentABIVersion {
		return nil, fmt.Errorf("unsupported ABI version %d", v)
	}
	if hs := binary.LittleEndian.Uint32(data[12:]); hs != segmentHeaderSize {
		return nil, fmt.Errorf("unexpected header_size %d", hs)
	}
	hdr := SegmentHeader{
		TotalSize:    binary.LittleEndian.Uint64(data[16:]),
		NRings:       binary.LittleEndian.Uint32(data[24:]),
		RingDataSize: binary.LittleEndian.Uint32(data[28:]),
		InitKTimeNS:  binary.LittleEndian.Uint64(data[32:]),
		InitUnixNS:   binary.LittleEndian.Uint64(data[40:]),
		OSPid:        binary.LittleEndian.Uint64(data[48:]),
		OTPRelease:   binary.LittleEndian.Uint32(data[56:]),
	}
	if hdr.TotalSize != uint64(len(data)) {
		return nil, fmt.Errorf("total_size %d != mapped size %d", hdr.TotalSize, len(data))
	}
	if hdr.NRings == 0 || hdr.NRings > maxRings {
		return nil, fmt.Errorf("implausible nrings %d", hdr.NRings)
	}
	rds := hdr.RingDataSize
	if rds < 8 || rds&(rds-1) != 0 {
		return nil, fmt.Errorf("ring_data_size %d is not a power of two", rds)
	}

	seg := &Segment{data: data, hdr: hdr}
	seg.hdr.RingOffsets = make([]uint64, hdr.NRings)
	seg.rings = make([]ringState, hdr.NRings)
	for i := range seg.rings {
		off := binary.LittleEndian.Uint64(data[64+8*i:])
		// Use subtraction to check bounds without overflowing a corrupt offset.
		if off < segmentHeaderSize || off%8 != 0 ||
			off > hdr.TotalSize || hdr.TotalSize-off < ringCtrlSize+uint64(rds) {
			return nil, fmt.Errorf("ring %d offset %d out of bounds", i, off)
		}
		seg.hdr.RingOffsets[i] = off
		seg.rings[i] = ringState{
			ctrlOff: off,
			dataOff: off + ringCtrlSize,
		}
		// Resume read_pos so reattachment does not replay records. Misaligned
		// or backwards positions park the ring as corrupt.
		rp := atomic.LoadUint64(seg.u64(off + ctrlOffReadPos))
		wp := atomic.LoadUint64(seg.u64(off + ctrlOffWritePos))
		if rp%8 != 0 || rp > wp {
			seg.rings[i].corrupt = true
		}
		seg.rings[i].readPos = rp
	}
	return seg, nil
}

// Header returns the decoded segment header.
func (s *Segment) Header() SegmentHeader { return s.hdr }

// u64 returns a pointer suitable for atomic access at the given byte offset.
// All control-block fields are 8-byte aligned by construction (offsets are
// validated to be multiples of 8 and the mapping is page-aligned).
func (s *Segment) u64(off uint64) *uint64 {
	return (*uint64)(unsafe.Pointer(&s.data[off]))
}

// Drain consumes all published records from every ring, invoking handler for
// each decoded record, and returns the pass statistics.
func (s *Segment) Drain(handler func(Record)) DrainStats {
	var st DrainStats
	s.DrainInto(&st, handler)
	return st
}

// DrainInto is Drain with caller-owned stats storage: st is reset and filled
// in place, reusing its DroppedPerRing backing array. The per-PID drain
// goroutine calls this every poll so an idle pass allocates nothing.
func (s *Segment) DrainInto(st *DrainStats, handler func(Record)) {
	per := st.DroppedPerRing[:0]
	if cap(per) < len(s.rings) {
		per = make([]uint64, 0, len(s.rings))
	}
	*st = DrainStats{DroppedPerRing: per}
	overflowRing := len(s.rings) - 1
	for i := range s.rings {
		dropped := atomic.LoadUint64(s.u64(s.rings[i].ctrlOff + ctrlOffDropped))
		st.DroppedPerRing = append(st.DroppedPerRing, dropped)
		st.Dropped += dropped
		s.drainRing(&s.rings[i], i == overflowRing, handler, st)
	}
}

func (s *Segment) drainRing(r *ringState, isOverflow bool,
	handler func(Record), st *DrainStats) {
	if r.corrupt {
		st.CorruptRings++
		return
	}

	wp := atomic.LoadUint64(s.u64(r.ctrlOff + ctrlOffWritePos))
	rp := r.readPos
	startRp := rp
	rds := uint64(s.hdr.RingDataSize)
	mask := rds - 1
	if wp < rp || wp-rp > rds || wp%8 != 0 {
		// The writer must publish aligned positions and never overrun unread data.
		r.corrupt = true
		st.CorruptRings++
		return
	}

	for rp < wp {
		idx := rp & mask
		base := r.dataOff + idx
		if wp-rp < 2 {
			// Less than a length prefix published. On the SPSC rings write_pos
			// is release-stored after whole records, so this is a protocol
			// violation; on the overflow ring it is an in-flight reservation.
			if !isOverflow {
				r.corrupt = true
				st.CorruptRings++
			}
			break
		}
		var recLen uint64
		if isOverflow {
			// Overflow records publish their aligned header word with a release
			// store. Acquire-load it before reading the payload, especially on arm64.
			recLen = uint64(uint16(atomic.LoadUint64(s.u64(base))))
		} else {
			// SPSC rings: the acquire-load of write_pos above already orders
			// the record bytes, so a plain read of the len prefix is correct.
			recLen = uint64(binary.LittleEndian.Uint16(s.data[base:]))
		}
		if recLen == 0 && isOverflow {
			// A CAS reservation whose bytes are not yet visible. Leave rp
			// where it is and retry on the next poll.
			break
		}
		if recLen == 0 || recLen%8 != 0 {
			r.corrupt = true
			st.CorruptRings++
			break
		}
		if recLen > rds-idx {
			// Records never cross the buffer end; the writer pads instead.
			r.corrupt = true
			st.CorruptRings++
			break
		}
		if recLen > wp-rp {
			// Header visible but the record extends past the published
			// position. In-flight on the overflow ring; corruption elsewhere.
			if !isOverflow {
				r.corrupt = true
				st.CorruptRings++
			}
			break
		}

		rec := s.data[base : base+recLen]
		typ := binary.LittleEndian.Uint16(rec[2:])
		if typ == recTypePad {
			st.Padding++
		} else if recLen < recordHeaderSize {
			// A non-PAD record cannot even carry its clock header.
			st.Unknown++
		} else if decoded, err := decodeRecord(rec); err != nil {
			// Unknown or truncated: skip by len, count, never fatal.
			st.Unknown++
		} else {
			handler(decoded)
			st.Records++
		}
		rp += recLen
	}

	if rp != startRp {
		if isOverflow {
			// Clear every consumed byte before releasing read_pos. On a later lap,
			// a record can start inside a previous payload, so clearing only headers
			// would expose stale nonzero lengths in unpublished reservations.
			s.zeroConsumed(r.dataOff, startRp, rp, rds, mask)
		}
		r.readPos = rp
		atomic.StoreUint64(s.u64(r.ctrlOff+ctrlOffReadPos), rp)
	}
}

// zeroConsumed zeroes the ring-data bytes for the consumed monotonic range
// [from, to) on the overflow ring, handling a single wrap as two spans. The
// caller guarantees to-from <= ring_data_size (one drain pass never consumes
// more than one lap), so at most one wrap occurs.
func (s *Segment) zeroConsumed(dataOff, from, to, rds, mask uint64) {
	n := to - from
	start := from & mask
	if start+n <= rds {
		clear(s.data[dataOff+start : dataOff+start+n])
		return
	}
	first := rds - start
	clear(s.data[dataOff+start : dataOff+rds])
	clear(s.data[dataOff : dataOff+(n-first)])
}
