// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package beamscope

// Test fixture builder: constructs beam_scope shm segments byte-for-byte from
// ABI.md (discord_common/ex/beam_scope/ABI.md), emulating the writer side
// including the never-wrap PAD rule and the drop-when-full rule. This is the
// reference the reader tests decode against; any change here must come from
// the ABI document, not from the reader implementation.

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

const (
	fixInitKTime = uint64(1_000_000_000)
	fixInitUnix  = uint64(1_755_000_000_000_000_000)
	fixOSPid     = uint64(4242)
	fixOTP       = uint32(25)
)

// fixture is an in-memory shm segment with writer-side record emission.
type fixture struct {
	data         []byte
	nrings       int
	ringDataSize int
	ringOffs     []uint64
}

func pageAlign(n int) int { return (n + 4095) &^ 4095 }

// newFixture builds a valid empty segment: header page + nrings rings, each
// ring at a page-aligned offset (control block + power-of-two data area).
func newFixture(t testing.TB, nrings, ringDataSize int) *fixture {
	t.Helper()
	if ringDataSize&(ringDataSize-1) != 0 {
		t.Fatalf("ringDataSize %d is not a power of two", ringDataSize)
	}
	ringSpan := pageAlign(ringCtrlSize + ringDataSize)
	total := segmentHeaderSize + nrings*ringSpan

	f := &fixture{
		data:         make([]byte, total),
		nrings:       nrings,
		ringDataSize: ringDataSize,
		ringOffs:     make([]uint64, nrings),
	}
	le := binary.LittleEndian
	le.PutUint64(f.data[0:], segmentMagic)
	le.PutUint32(f.data[8:], segmentABIVersion)
	le.PutUint32(f.data[12:], segmentHeaderSize)
	le.PutUint64(f.data[16:], uint64(total))
	le.PutUint32(f.data[24:], uint32(nrings))
	le.PutUint32(f.data[28:], uint32(ringDataSize))
	le.PutUint64(f.data[32:], fixInitKTime)
	le.PutUint64(f.data[40:], fixInitUnix)
	le.PutUint64(f.data[48:], fixOSPid)
	le.PutUint32(f.data[56:], fixOTP)
	for i := 0; i < nrings; i++ {
		off := uint64(segmentHeaderSize + i*ringSpan)
		f.ringOffs[i] = off
		le.PutUint64(f.data[64+8*i:], off)
	}
	return f
}

func (f *fixture) getU64(off uint64) uint64 {
	return binary.LittleEndian.Uint64(f.data[off:])
}

func (f *fixture) putU64(off, v uint64) {
	binary.LittleEndian.PutUint64(f.data[off:], v)
}

func (f *fixture) writePos(ring int) uint64  { return f.getU64(f.ringOffs[ring]) }
func (f *fixture) readPos(ring int) uint64   { return f.getU64(f.ringOffs[ring] + 8) }
func (f *fixture) droppedAt(ring int) uint64 { return f.getU64(f.ringOffs[ring] + 16) }

func (f *fixture) setWritePos(ring int, v uint64) { f.putU64(f.ringOffs[ring], v) }
func (f *fixture) setDropped(ring int, v uint64)  { f.putU64(f.ringOffs[ring]+16, v) }

func (f *fixture) dataOff(ring int) uint64 { return f.ringOffs[ring] + ringCtrlSize }

// writeRecord emits one encoded record into a ring, emulating the writer
// protocol: PAD to the buffer boundary if the record would cross it, drop and
// count if it would overwrite unread data. Returns false on drop.
func (f *fixture) writeRecord(ring int, rec []byte) bool {
	size := uint64(f.ringDataSize)
	mask := size - 1
	wp := f.writePos(ring)
	rp := f.readPos(ring)

	idx := wp & mask
	if uint64(len(rec)) > size-idx {
		// Record would cross the end: fill with a PAD record first.
		padLen := size - idx
		if (wp-rp)+padLen > size {
			f.setDropped(ring, f.droppedAt(ring)+1)
			return false
		}
		pad := make([]byte, padLen)
		binary.LittleEndian.PutUint16(pad[0:], uint16(padLen))
		binary.LittleEndian.PutUint16(pad[2:], recTypePad)
		copy(f.data[f.dataOff(ring)+idx:], pad)
		wp += padLen
		idx = 0
	}
	if (wp-rp)+uint64(len(rec)) > size {
		f.setDropped(ring, f.droppedAt(ring)+1)
		return false
	}
	copy(f.data[f.dataOff(ring)+idx:], rec)
	f.setWritePos(ring, wp+uint64(len(rec)))
	return true
}

// mustWrite emits one record into a ring, failing the test if the writer
// protocol dropped it.
func (f *fixture) mustWrite(t testing.TB, ring int, rec []byte) {
	t.Helper()
	if !f.writeRecord(ring, rec) {
		t.Fatal("fixture write failed")
	}
}

// rawWrite copies bytes at the current write position and advances write_pos,
// bypassing the writer protocol. For corruption tests.
func (f *fixture) rawWrite(ring int, b []byte, advance uint64) {
	wp := f.writePos(ring)
	idx := wp & uint64(f.ringDataSize-1)
	copy(f.data[f.dataOff(ring)+idx:], b)
	f.setWritePos(ring, wp+advance)
}

// payloadWriter builds packed record payloads.
type payloadWriter struct{ b []byte }

func (p *payloadWriter) u8(v uint8)   { p.b = append(p.b, v) }
func (p *payloadWriter) u32(v uint32) { p.b = binary.LittleEndian.AppendUint32(p.b, v) }
func (p *payloadWriter) u64(v uint64) { p.b = binary.LittleEndian.AppendUint64(p.b, v) }
func (p *payloadWriter) i64(v int64)  { p.u64(uint64(v)) }
func (p *payloadWriter) str(s string) {
	p.u8(uint8(len(s)))
	p.b = append(p.b, s...)
}

// encRecord wraps a payload with the 24-byte record header, padding the total
// to 8-byte alignment.
func encRecord(typ uint16, flags uint32, ktime, unix uint64, payload []byte) []byte {
	n := (recordHeaderSize + len(payload) + 7) &^ 7
	rec := make([]byte, n)
	binary.LittleEndian.PutUint16(rec[0:], uint16(n))
	binary.LittleEndian.PutUint16(rec[2:], typ)
	binary.LittleEndian.PutUint32(rec[4:], flags)
	binary.LittleEndian.PutUint64(rec[8:], ktime)
	binary.LittleEndian.PutUint64(rec[16:], unix)
	copy(rec[recordHeaderSize:], payload)
	return rec
}

func encGCDelta(ktime, unix, pidKey, alloc, binVheap, heap uint64, kind uint8) []byte {
	var p payloadWriter
	p.u64(pidKey)
	p.u64(alloc)
	p.u64(binVheap)
	p.u64(heap)
	p.u8(kind)
	return encRecord(recTypeGCDelta, 0, ktime, unix, p.b)
}

func encProcMeta(ktime, unix, pidKey, spawn uint64, arity uint8,
	module, function, pidPrint string) []byte {
	return encProcMetaF(0, ktime, unix, pidKey, spawn, arity, module, function, pidPrint)
}

// encProcMetaF is encProcMeta with header flags (bit0 = proc_lib-translated,
// bit2 = current_function-derived).
func encProcMetaF(flags uint32, ktime, unix, pidKey, spawn uint64, arity uint8,
	module, function, pidPrint string) []byte {
	return encProcMetaReg(flags, ktime, unix, pidKey, spawn, arity,
		module, function, pidPrint, "")
}

// encProcMetaReg additionally appends a registered_name string when flags
// bit1 is set (per ABI, the string is absent entirely when bit1 is clear).
func encProcMetaReg(flags uint32, ktime, unix, pidKey, spawn uint64, arity uint8,
	module, function, pidPrint, regName string) []byte {
	var p payloadWriter
	p.u64(pidKey)
	p.u64(spawn)
	p.u8(arity)
	p.str(module)
	p.str(function)
	p.str(pidPrint)
	if flags&procMetaFlagRegisteredName != 0 {
		p.str(regName)
	}
	return encRecord(recTypeProcMeta, flags, ktime, unix, p.b)
}

func encProcExit(ktime, unix, pidKey uint64, reason uint8) []byte {
	var p payloadWriter
	p.u64(pidKey)
	p.u8(reason)
	return encRecord(recTypeProcExit, 0, ktime, unix, p.b)
}

func encPanelSample(ktime, unix, pidKey, msgq, mem, reds, redsDelta uint64,
	msgqDelta int64, sampleFlags, epoch uint32) []byte {
	var p payloadWriter
	p.u64(pidKey)
	p.u64(msgq)
	p.u64(mem)
	p.u64(reds)
	p.u64(redsDelta)
	p.i64(msgqDelta)
	p.u32(sampleFlags)
	p.u32(epoch)
	return encRecord(recTypePanelSample, 0, ktime, unix, p.b)
}

func encTopkSend(ktime, unix, pidKey, est uint64, epoch uint32, rank uint8) []byte {
	var p payloadWriter
	p.u64(pidKey)
	p.u64(est)
	p.u32(epoch)
	p.u8(rank)
	return encRecord(recTypeTopkSend, 0, ktime, unix, p.b)
}

func encMonitorEvent(ktime, unix, pidKey uint64, kind uint8, value uint64) []byte {
	var p payloadWriter
	p.u64(pidKey)
	p.u8(kind)
	p.u64(value)
	return encRecord(recTypeMonitorEvent, 0, ktime, unix, p.b)
}

func encPanelTick(ktime, unix uint64, epoch, panelSize, watchSize uint32,
	processCount uint64) []byte {
	var p payloadWriter
	p.u32(epoch)
	p.u32(panelSize)
	p.u32(watchSize)
	p.u32(0) // reserved
	p.u64(processCount)
	return encRecord(recTypePanelTick, 0, ktime, unix, p.b)
}

func encGCDelta2(ktime, unix, pidKey, alloc, binVheap, mbuf, heap, pause uint64,
	kind uint8) []byte {
	var p payloadWriter
	p.u64(pidKey)
	p.u64(alloc)
	p.u64(binVheap)
	p.u64(mbuf)
	p.u64(heap)
	p.u64(pause)
	p.u8(kind)
	return encRecord(recTypeGCDelta2, 0, ktime, unix, p.b)
}

// encSchedUtil takes header flags first (bit0 = msacc fields valid).
func encSchedUtil(flags uint32, ktime, unix uint64, schedID uint32, schedType uint8,
	epoch uint32, active, total, emulator, gc, port, sleep, other uint64) []byte {
	var p payloadWriter
	p.u32(schedID)
	p.u8(schedType)
	p.u32(epoch)
	p.u64(active)
	p.u64(total)
	p.u64(emulator)
	p.u64(gc)
	p.u64(port)
	p.u64(sleep)
	p.u64(other)
	return encRecord(recTypeSchedUtil, flags, ktime, unix, p.b)
}

// encSchedDelta takes header flags first (bit0 = classification unsupported).
func encSchedDelta(flags uint32, ktime, unix, pidKey, onSched uint64,
	nswitches, preempts, yields uint32) []byte {
	var p payloadWriter
	p.u64(pidKey)
	p.u64(onSched)
	p.u32(nswitches)
	p.u32(preempts)
	p.u32(yields)
	p.u32(0) // reserved
	return encRecord(recTypeSchedDelta, flags, ktime, unix, p.b)
}

// mustSegment validates the fixture bytes through the real entry point.
func (f *fixture) mustSegment(t testing.TB) *Segment {
	t.Helper()
	seg, err := NewSegment(f.data)
	if err != nil {
		t.Fatalf("NewSegment: %v", err)
	}
	return seg
}

// collect drains into a slice.
func collect(seg *Segment) (recs []Record, st DrainStats) {
	st = seg.Drain(func(r Record) { recs = append(recs, r) })
	return recs, st
}

// recordedFixtureDir is where the writer peer hands over segments recorded
// from a real BEAM by the beam_scope shmdump tool.
const recordedFixtureDir = "/home/discord/dev/worktrees/main/.worktrees/" +
	"sanchda/evil_beam_shit/discord_common/ex/beam_scope/test/fixtures"

// recordedFixturePath resolves a recorded segment path: the env var when set,
// otherwise the monorepo handoff location.
func recordedFixturePath(env, name string) string {
	if p := os.Getenv(env); p != "" {
		return p
	}
	return filepath.Join(recordedFixtureDir, name)
}

// loadRecordedSegment validates a recorded segment through the real entry
// point, skipping the test when the writer peer has not handed it over yet.
func loadRecordedSegment(t *testing.T, env, name string) *Segment {
	t.Helper()
	raw, err := os.ReadFile(recordedFixturePath(env, name))
	if err != nil {
		t.Skipf("recorded fixture not available: %v", err)
	}
	seg, err := NewSegment(raw)
	if err != nil {
		t.Fatalf("recorded fixture rejected: %v", err)
	}
	return seg
}
