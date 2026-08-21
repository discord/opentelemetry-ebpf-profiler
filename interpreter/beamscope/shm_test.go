// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package beamscope

// Ring drain tests: wraparound with PAD, drop counter visibility, unknown
// record skip, corruption stop, read_pos persistence and overflow-ring
// in-flight tolerance. All against in-memory fixtures; no live BEAM.

import (
	"encoding/binary"
	"testing"
)

func TestSegmentHeaderValidation(t *testing.T) {
	f := newFixture(t, 3, 4096)
	seg := f.mustSegment(t)
	h := seg.Header()
	if h.NRings != 3 || h.RingDataSize != 4096 {
		t.Fatalf("bad header decode: %+v", h)
	}
	if h.OSPid != fixOSPid || h.OTPRelease != fixOTP {
		t.Fatalf("bad identity fields: %+v", h)
	}
	if h.InitKTimeNS != fixInitKTime || h.InitUnixNS != fixInitUnix {
		t.Fatalf("bad clock fields: %+v", h)
	}

	// Corrupted variants must be rejected.
	bad := func(mutate func([]byte), why string) {
		g := newFixture(t, 3, 4096)
		mutate(g.data)
		if _, err := NewSegment(g.data); err == nil {
			t.Fatalf("NewSegment accepted %s", why)
		}
	}
	bad(func(b []byte) { b[0] ^= 0xff }, "bad magic")
	bad(func(b []byte) { binary.LittleEndian.PutUint32(b[8:], 2) }, "bad version")
	bad(func(b []byte) { binary.LittleEndian.PutUint32(b[28:], 4095) }, "non-pow2 ring size")
	bad(func(b []byte) { binary.LittleEndian.PutUint32(b[24:], 0) }, "zero rings")
	bad(func(b []byte) { binary.LittleEndian.PutUint64(b[16:], 1<<40) }, "wrong total_size")
	bad(func(b []byte) { binary.LittleEndian.PutUint64(b[64:], 1<<40) }, "ring offset OOB")
	// FIX-1: an 8-aligned ring offset so large that off+ctrlSize+ring_data
	// wraps uint64 must still be rejected, not wrap past the check and panic
	// in NewSegment reading read_pos at s.data[off+8].
	bad(func(b []byte) { binary.LittleEndian.PutUint64(b[64:], 0xFFFFFFFFFFFFF000) },
		"ring offset that wraps uint64 in the bounds check")
}

// TestSegmentRingOffsetOverflowIsRejected is FIX-1 in isolation: before the
// overflow-safe bounds check, a hostile 8-aligned ring_offset near uint64 max
// wrapped off+ringCtrlSize+ring_data_size around to a small value, passed
// validation, and panicked with an out-of-range index. It must now be a clean
// error (the segment is another process's memory: untrusted input).
func TestSegmentRingOffsetOverflowIsRejected(t *testing.T) {
	f := newFixture(t, 2, 4096)
	// Wrapping, 8-aligned, and >= header size, so it clears every check but
	// the (now subtraction-based) bounds test.
	binary.LittleEndian.PutUint64(f.data[64:], 0xFFFFFFFFFFFFF000)
	if _, err := NewSegment(f.data); err == nil {
		t.Fatal("NewSegment accepted a ring offset that overflows the bounds check")
	}
}

// TestSegmentHostileReadPosParksRingNoPanic is FIX-2: a resumed read_pos taken
// from the untrusted segment is now alignment/range-validated. A misaligned
// read_pos with idx = ring_data_size-1 made the 2-byte len read cross the end
// of the mapping and panic. The segment here is packed so the last ring's data
// ends exactly at total_size (no page slack), reproducing that geometry; the
// ring must be parked as corruption instead of crashing.
func TestSegmentHostileReadPosParksRingNoPanic(t *testing.T) {
	const rds = 64 // power of two; NewSegment only requires that
	total := segmentHeaderSize + ringCtrlSize + rds
	data := make([]byte, total)
	le := binary.LittleEndian
	le.PutUint64(data[0:], segmentMagic)
	le.PutUint32(data[8:], segmentABIVersion)
	le.PutUint32(data[12:], segmentHeaderSize)
	le.PutUint64(data[16:], uint64(total))
	le.PutUint32(data[24:], 1) // one ring, packed right after the header page
	le.PutUint32(data[28:], rds)
	off := uint64(segmentHeaderSize)
	le.PutUint64(data[64:], off)
	// Hostile resumed state: read_pos = rds-1 (misaligned, idx = rds-1),
	// write_pos = read_pos + 8 so the drain loop would enter and read a len.
	le.PutUint64(data[off+ctrlOffReadPos:], rds-1)
	le.PutUint64(data[off+ctrlOffWritePos:], rds-1+8)

	seg, err := NewSegment(data)
	if err != nil {
		t.Fatalf("NewSegment rejected a structurally valid segment: %v", err)
	}
	// Draining must not panic and must count the poisoned ring as corrupt.
	recs, st := collect(seg)
	if len(recs) != 0 {
		t.Fatalf("delivered %d records from a poisoned ring", len(recs))
	}
	if st.CorruptRings != 1 {
		t.Fatalf("CorruptRings = %d, want 1", st.CorruptRings)
	}
}

// TestSegmentReadPosPastWritePosParksRing is the range half of FIX-2: a
// read_pos beyond write_pos is also treated as corruption at NewSegment time.
func TestSegmentReadPosPastWritePosParksRing(t *testing.T) {
	f := newFixture(t, 1, 4096)
	// 8-aligned but past write_pos (which is 0).
	f.putU64(f.ringOffs[0]+ctrlOffReadPos, 4096)
	seg := f.mustSegment(t)
	_, st := collect(seg)
	if st.CorruptRings != 1 {
		t.Fatalf("read_pos past write_pos not parked: CorruptRings = %d", st.CorruptRings)
	}
}

// TestDrainOverflowWholeRegionZeroedAcrossLaps is FIX-4 (ABI v1.1): the reader
// must zero the ENTIRE consumed byte range on the overflow ring, not just each
// record's len word. Record boundaries do not align across laps, so a lap-N+1
// reservation can start at an offset that was lap-N record interior; if only
// the len words were zeroed, that interior byte stays non-zero and a reader
// polling between the writer's CAS reservation and its zero-len step could
// read it as a bogus len and desync. The test proves the interior byte is
// zeroed and that a reservation landing on it reads as in-flight, not a
// misparsed record.
func TestDrainOverflowWholeRegionZeroedAcrossLaps(t *testing.T) {
	f := newFixture(t, 2, 256)
	ov := 1

	// Lap 1: five 48-byte TOPK records at indices 0,48,96,144,192. Their epoch
	// field lands at record offset +40 (24-byte header + 8 pid_key + 8 est),
	// i.e. data index 40 for the first record: interior payload, never a len
	// word. Give it a distinctive non-zero value.
	const epoch = uint32(0x11223344)
	for i := 0; i < 5; i++ {
		f.mustWrite(t, ov, encTopkSend(tK, tU, uint64(i+1), 7, epoch, uint8(i)))
	}
	// Confirm the interior byte is non-zero before the drain (so the post-drain
	// zero is meaningful, not a fresh-buffer artifact).
	if f.data[f.dataOff(ov)+40] == 0 {
		t.Fatal("test setup: expected non-zero interior byte at index 40 pre-drain")
	}
	seg := f.mustSegment(t)
	if recs, st := collect(seg); len(recs) != 5 || st.CorruptRings != 0 {
		t.Fatalf("lap 1 drain: %d records, stats %+v", len(recs), st)
	}
	// Whole-region zeroing: every byte of the consumed range [0,240) is zero,
	// including the record-interior epoch byte at index 40. The old
	// len-word-only rule would have left index 40 holding 0x44.
	for off := uint64(0); off < 240; off++ {
		if f.data[f.dataOff(ov)+off] != 0 {
			t.Fatalf("consumed byte at index %d not zeroed: 0x%02x",
				off, f.data[f.dataOff(ov)+off])
		}
	}

	// Lap 2, mid-flight. Boundary PAD (16 bytes) at index 240 -> position 256.
	// A published 40-byte PROC_EXIT at index 0 -> position 296. Then a 48-byte
	// reservation at index 40 (position 296) that the writer has CAS-advanced
	// write_pos over but not yet written. Index 40 was lap-1 record interior,
	// so only whole-region zeroing makes it read len==0 (in-flight).
	pad := make([]byte, 16)
	binary.LittleEndian.PutUint16(pad[0:], 16)
	binary.LittleEndian.PutUint16(pad[2:], recTypePad)
	copy(f.data[f.dataOff(ov)+240:], pad)
	exit := encProcExit(tK, tU, 0xabc, 1) // 40 bytes
	copy(f.data[f.dataOff(ov):], exit)
	if got := binary.LittleEndian.Uint16(f.data[f.dataOff(ov)+40:]); got != 0 {
		t.Fatalf("reservation start (index 40) not zero: %d", got)
	}
	f.setWritePos(ov, 240+16+40+48) // PAD + exit + reserved-but-unpublished 48-byte record

	recs, st := collect(seg)
	if st.CorruptRings != 0 {
		t.Fatalf("in-flight reservation over old interior bytes flagged corrupt: %+v", st)
	}
	if len(recs) != 1 || st.Padding != 1 {
		t.Fatalf("reservation misparsed as a record: %d records, %d pads", len(recs), st.Padding)
	}
	if pe, ok := recs[0].(*ProcExit); !ok || pe.PidKey != 0xabc {
		t.Fatalf("wrong published record: %#v", recs[0])
	}
	if got := f.readPos(ov); got != 296 {
		t.Fatalf("read_pos advanced into the reservation: %d, want 296", got)
	}

	// The writer finishes the reserved record; the reader picks up exactly it.
	real := encMonitorEvent(tK+1, tU+1, 0xdef, 0, 999)
	copy(f.data[f.dataOff(ov)+40:], real)
	recs, st = collect(seg)
	if len(recs) != 1 || st.CorruptRings != 0 {
		t.Fatalf("publish-after-reservation drain failed: %d recs, %+v", len(recs), st)
	}
	if me, ok := recs[0].(*MonitorEvent); !ok || me.PidKey != 0xdef || me.Value != 999 {
		t.Fatalf("wrong record after reservation completed: %#v", recs[0])
	}
}

func TestDrainBasic(t *testing.T) {
	f := newFixture(t, 2, 4096)
	if !f.writeRecord(0, encGCDelta(tK, tU, 1, 100, 0, 50, 0)) {
		t.Fatal("write failed")
	}
	if !f.writeRecord(1, encPanelTick(tK+1, tU+1, 1, 10, 2, 100)) {
		t.Fatal("write failed")
	}
	seg := f.mustSegment(t)
	recs, st := collect(seg)
	if len(recs) != 2 || st.Records != 2 {
		t.Fatalf("expected 2 records, got %d (stats %+v)", len(recs), st)
	}
	if _, ok := recs[0].(*GCDelta); !ok {
		t.Fatalf("ring order: expected GCDelta first, got %T", recs[0])
	}
	if _, ok := recs[1].(*PanelTick); !ok {
		t.Fatalf("expected PanelTick second, got %T", recs[1])
	}

	// read_pos must be stored back per ring.
	if f.readPos(0) != f.writePos(0) || f.readPos(1) != f.writePos(1) {
		t.Fatalf("read_pos not stored: r0 %d/%d r1 %d/%d",
			f.readPos(0), f.writePos(0), f.readPos(1), f.writePos(1))
	}

	// A second drain sees nothing new.
	recs, st = collect(seg)
	if len(recs) != 0 || st.Records != 0 {
		t.Fatalf("redrain delivered %d records", len(recs))
	}
}

func TestDrainWraparoundWithPad(t *testing.T) {
	// Ring of 256 bytes; TOPK_SEND records are 48 bytes, so the sixth record
	// (at index 240) does not fit the remaining 16 bytes and the writer must
	// emit a 16-byte PAD and wrap.
	f := newFixture(t, 1, 256)
	rec := func(i int) []byte {
		return encTopkSend(tK+uint64(i), tU+uint64(i), uint64(i), 100, 1, uint8(i))
	}
	seg := f.mustSegment(t)
	for i := 0; i < 5; i++ {
		if !f.writeRecord(0, rec(i)) {
			t.Fatalf("write %d failed", i)
		}
	}
	recs, st := collect(seg)
	if len(recs) != 5 || st.Padding != 0 {
		t.Fatalf("pre-wrap: got %d records, %d pads", len(recs), st.Padding)
	}

	// This write crosses the boundary: 16-byte PAD + record at index 0.
	if !f.writeRecord(0, rec(5)) {
		t.Fatal("wrapping write failed")
	}
	if f.writePos(0) != 256+48 {
		t.Fatalf("write_pos after wrap = %d, want %d", f.writePos(0), 256+48)
	}
	recs, st = collect(seg)
	if len(recs) != 1 || st.Padding != 1 {
		t.Fatalf("post-wrap: got %d records, %d pads (stats %+v)",
			len(recs), st.Padding, st)
	}
	ts := recs[0].(*TopkSend)
	if ts.PidKey != 5 || ts.Rank != 5 {
		t.Fatalf("wrong record after wrap: %+v", ts)
	}
	if f.readPos(0) != f.writePos(0) {
		t.Fatalf("read_pos %d != write_pos %d", f.readPos(0), f.writePos(0))
	}
}

func TestDrainStatsPerRing(t *testing.T) {
	// Writer drop counters are surfaced per ring and as a total, including
	// counters that were already non-zero before this reader ever drained
	// (the pre-attach case).
	f := newFixture(t, 3, 4096)
	f.setDropped(0, 7)
	f.setDropped(2, 35)
	seg := f.mustSegment(t)
	_, st := collect(seg)
	if st.Dropped != 42 {
		t.Fatalf("Dropped = %d, want 42", st.Dropped)
	}
	want := []uint64{7, 0, 35}
	if len(st.DroppedPerRing) != len(want) {
		t.Fatalf("DroppedPerRing = %v, want %v", st.DroppedPerRing, want)
	}
	for i, n := range want {
		if st.DroppedPerRing[i] != n {
			t.Fatalf("DroppedPerRing[%d] = %d, want %d", i, st.DroppedPerRing[i], n)
		}
	}
}

func TestDrainDropCounterVisible(t *testing.T) {
	// Fill the ring without draining until the writer must drop.
	f := newFixture(t, 1, 256)
	wrote, dropped := 0, 0
	for i := 0; i < 10; i++ {
		if f.writeRecord(0, encTopkSend(tK, tU, uint64(i), 1, 1, 0)) {
			wrote++
		} else {
			dropped++
		}
	}
	if dropped == 0 {
		t.Fatal("fixture never dropped; test is not exercising the full ring")
	}
	seg := f.mustSegment(t)
	recs, st := collect(seg)
	if st.Dropped != uint64(dropped) {
		t.Fatalf("stats.Dropped = %d, want %d", st.Dropped, dropped)
	}
	if len(recs) != wrote {
		t.Fatalf("delivered %d, want %d", len(recs), wrote)
	}
}

func TestDrainUnknownTypeSkippedByLen(t *testing.T) {
	f := newFixture(t, 1, 4096)
	if !f.writeRecord(0, encRecord(0x66, 0, tK, tU, []byte{0xaa, 0xbb, 0xcc})) {
		t.Fatal("write failed")
	}
	if !f.writeRecord(0, encProcExit(tK, tU, 3, 0)) {
		t.Fatal("write failed")
	}
	seg := f.mustSegment(t)
	recs, st := collect(seg)
	if st.Unknown != 1 {
		t.Fatalf("unknown count = %d, want 1", st.Unknown)
	}
	if len(recs) != 1 {
		t.Fatalf("delivered %d records, want 1", len(recs))
	}
	if pe, ok := recs[0].(*ProcExit); !ok || pe.PidKey != 3 {
		t.Fatalf("record after unknown skip: %#v", recs[0])
	}
	if f.readPos(0) != f.writePos(0) {
		t.Fatal("unknown record was not consumed")
	}
}

func TestDrainCorruptionZeroLenStopsRing(t *testing.T) {
	f := newFixture(t, 2, 4096)
	if !f.writeRecord(0, encProcExit(tK, tU, 1, 0)) {
		t.Fatal("write failed")
	}
	// Garbage: write_pos advances but the length field stays zero. Ring 0 is
	// SPSC (not the overflow ring, which is ring 1), so this is corruption.
	f.rawWrite(0, make([]byte, 16), 16)
	// A healthy record on the other ring must still flow.
	if !f.writeRecord(1, encProcExit(tK, tU, 2, 1)) {
		t.Fatal("write failed")
	}

	seg := f.mustSegment(t)
	recs, st := collect(seg)
	if st.CorruptRings != 1 {
		t.Fatalf("CorruptRings = %d, want 1", st.CorruptRings)
	}
	if len(recs) != 2 {
		// The record before the corruption and the one on the healthy ring.
		t.Fatalf("delivered %d records, want 2", len(recs))
	}

	// The corrupt ring stays stopped even if valid-looking bytes follow.
	f.setWritePos(0, f.writePos(0)+64)
	recs, st = collect(seg)
	if len(recs) != 0 || st.CorruptRings != 1 {
		t.Fatalf("corrupt ring was drained again: %d recs, stats %+v", len(recs), st)
	}
}

func TestDrainCorruptionMisalignedLenStopsRing(t *testing.T) {
	f := newFixture(t, 2, 4096)
	bad := make([]byte, 16)
	binary.LittleEndian.PutUint16(bad[0:], 12) // 12 % 8 != 0
	f.rawWrite(0, bad, 16)
	seg := f.mustSegment(t)
	recs, st := collect(seg)
	if len(recs) != 0 || st.CorruptRings != 1 {
		t.Fatalf("misaligned len not treated as corruption: %+v", st)
	}
}

func TestDrainCorruptionRecordCrossesBoundary(t *testing.T) {
	// A record whose len would cross the buffer end violates the never-wrap
	// rule.
	f := newFixture(t, 2, 256)
	// Manually place a 64-byte record at index 224 (only 32 bytes remain).
	rec := encGCDelta(tK, tU, 1, 1, 1, 1, 0) // 64 bytes
	f.setWritePos(0, 224)
	f.putU64(f.ringOffs[0]+8, 224) // read_pos follows
	copy(f.data[f.dataOff(0)+224:], rec[:32])
	f.setWritePos(0, 224+64)
	seg := f.mustSegment(t)
	_, st := collect(seg)
	if st.CorruptRings != 1 {
		t.Fatalf("boundary-crossing record not treated as corruption: %+v", st)
	}
}

func TestDrainOverflowRingInFlightReservation(t *testing.T) {
	// The last ring is the CAS overflow ring: a bumped write_pos with
	// not-yet-visible bytes (len still 0) must be retried, not declared
	// corrupt.
	f := newFixture(t, 2, 4096)
	overflow := 1
	rec := encMonitorEvent(tK, tU, 5, 2, 0)
	f.setWritePos(overflow, uint64(len(rec)))

	seg := f.mustSegment(t)
	recs, st := collect(seg)
	if st.CorruptRings != 0 {
		t.Fatalf("in-flight overflow reservation flagged corrupt: %+v", st)
	}
	if len(recs) != 0 {
		t.Fatalf("unpublished record delivered")
	}

	// Bytes become visible; the retry drains it.
	copy(f.data[f.dataOff(overflow):], rec)
	recs, st = collect(seg)
	if len(recs) != 1 || st.CorruptRings != 0 {
		t.Fatalf("retry after publish failed: %d recs, %+v", len(recs), st)
	}
}

func TestDrainOverflowRingZeroesConsumedLens(t *testing.T) {
	// ABI ruling: on the overflow ring only, the reader zeroes each consumed
	// record's len word (PADs included) before the release-store of the
	// advanced read_pos, restoring the len==0 in-flight marker behind itself.
	f := newFixture(t, 2, 256)
	overflow := 1
	if !f.writeRecord(0, encTopkSend(tK, tU, 1, 1, 1, 0)) { // SPSC control
		t.Fatal("write failed")
	}
	offsets := []uint64{0, 48, 96}
	for i := range offsets {
		if !f.writeRecord(overflow, encTopkSend(tK, tU, uint64(i), 1, 1, 0)) {
			t.Fatalf("write %d failed", i)
		}
	}
	seg := f.mustSegment(t)
	if recs, _ := collect(seg); len(recs) != 4 {
		t.Fatalf("drained %d records, want 4", len(recs))
	}
	// Overflow ring: every consumed len word is zeroed.
	for _, off := range offsets {
		if got := binary.LittleEndian.Uint16(f.data[f.dataOff(overflow)+off:]); got != 0 {
			t.Errorf("overflow ring len at %d = %d, want 0", off, got)
		}
	}
	// SPSC ring: consumed bytes are left alone.
	if got := binary.LittleEndian.Uint16(f.data[f.dataOff(0):]); got != 48 {
		t.Errorf("SPSC ring len was zeroed (got %d, want 48)", got)
	}
}

func TestDrainOverflowRingStaleLenBehindReservation(t *testing.T) {
	// The scenario the zeroing rule exists for: a writer CAS-reserves a
	// region that wraps onto bytes from a previous lap, and between the CAS
	// and the writer's own zero-len step that region still holds the old
	// lap's record. Because the reader zeroed the lens as it consumed the
	// previous lap, the stale region reads len==0 (in-flight) instead of
	// being misparsed as a fresh record.
	f := newFixture(t, 2, 256)
	overflow := 1

	// Lap 1: five 48-byte records fill the ring to 240; the reader consumes
	// them (zeroing the len words at 0,48,96,144,192 behind itself).
	for i := 0; i < 5; i++ {
		if !f.writeRecord(overflow, encTopkSend(tK, tU, uint64(i), 1, 1, uint8(i))) {
			t.Fatalf("write %d failed", i)
		}
	}
	seg := f.mustSegment(t)
	if recs, _ := collect(seg); len(recs) != 5 {
		t.Fatal("lap 1 drain failed")
	}

	// Lap 2, mid-flight: the writer has published the boundary PAD (16 bytes
	// at index 240) and CAS-advanced write_pos over the wrapped record region
	// (index 0..48), but has not yet written that record: the region holds
	// only lap-1 residue.
	pad := make([]byte, 16)
	binary.LittleEndian.PutUint16(pad[0:], 16)
	binary.LittleEndian.PutUint16(pad[2:], recTypePad)
	copy(f.data[f.dataOff(overflow)+240:], pad)
	// Re-plant a stale non-zero len inside the reserved region, as if the
	// reader had NOT zeroed it: prove the drain honors the zeroed state, not
	// this test's bookkeeping. First verify the drain actually zeroed it.
	if got := binary.LittleEndian.Uint16(f.data[f.dataOff(overflow):]); got != 0 {
		t.Fatalf("lap 1 len at index 0 not zeroed (got %d)", got)
	}
	f.setWritePos(overflow, 240+16+48) // reservation through the wrapped record

	recs, st := collect(seg)
	if st.CorruptRings != 0 {
		t.Fatalf("in-flight reservation flagged corrupt: %+v", st)
	}
	if len(recs) != 0 || st.Padding != 1 {
		t.Fatalf("reservation misparsed: %d records, %d pads", len(recs), st.Padding)
	}
	// The reader consumed the PAD but stopped at the unpublished region.
	if got := f.readPos(overflow); got != 256 {
		t.Fatalf("read_pos advanced past the reservation: %d, want 256", got)
	}

	// Counterfactual: with a stale len in place (reader never zeroed it),
	// the same drain would have swallowed lap-1's record as a ghost. Plant
	// one and confirm the reader would have believed it -- on a throwaway
	// copy, to document the hazard without corrupting the real state.
	ghost := newFixture(t, 2, 256)
	copy(ghost.data, f.data)
	stale := encTopkSend(tK, tU, 0xdead, 1, 1, 9)
	copy(ghost.data[ghost.dataOff(overflow):], stale)
	gseg := ghost.mustSegment(t)
	grecs, _ := collect(gseg)
	if len(grecs) != 1 {
		t.Fatalf("hazard counterfactual did not reproduce: %d records", len(grecs))
	}

	// The writer finishes publishing the real wrapped record; the reader
	// picks up exactly that record.
	real := encMonitorEvent(tK+9, tU+9, 0x77, 2, 123)
	copy(f.data[f.dataOff(overflow):], real)
	recs, st = collect(seg)
	if len(recs) != 1 || st.CorruptRings != 0 {
		t.Fatalf("publish-after-reservation drain failed: %d recs, %+v", len(recs), st)
	}
	me := recs[0].(*MonitorEvent)
	if me.PidKey != 0x77 || me.Value != 123 {
		t.Fatalf("wrong record after reservation completed: %+v", me)
	}
	if got := f.readPos(overflow); got != 240+16+48 {
		t.Fatalf("read_pos = %d, want %d", got, 240+16+48)
	}
	// And the freshly consumed record's len is zeroed in turn.
	if got := binary.LittleEndian.Uint16(f.data[f.dataOff(overflow):]); got != 0 {
		t.Fatalf("consumed wrapped record's len not zeroed (got %d)", got)
	}
}

func TestDrainResumesFromStoredReadPos(t *testing.T) {
	f := newFixture(t, 1, 4096)
	if !f.writeRecord(0, encProcExit(tK, tU, 1, 0)) {
		t.Fatal("write failed")
	}
	seg := f.mustSegment(t)
	if recs, _ := collect(seg); len(recs) != 1 {
		t.Fatal("first drain failed")
	}

	// A new Segment over the same memory (reader restart) must not replay.
	if !f.writeRecord(0, encProcExit(tK, tU, 2, 0)) {
		t.Fatal("write failed")
	}
	seg2 := f.mustSegment(t)
	recs, _ := collect(seg2)
	if len(recs) != 1 {
		t.Fatalf("restart replayed records: got %d, want 1", len(recs))
	}
	if pe := recs[0].(*ProcExit); pe.PidKey != 2 {
		t.Fatalf("wrong record after restart: %+v", pe)
	}
}

func TestDrainCompactEightBytePad(t *testing.T) {
	// ABI ruling: PAD has a compact 8-byte clock-less form {len, type, flags},
	// len >= 8. Arrange the ring so exactly 8 bytes remain at the boundary:
	// 48 (TOPK_SEND) + 5*40 (PROC_EXIT) = 248 of 256.
	f := newFixture(t, 1, 256)
	if !f.writeRecord(0, encTopkSend(tK, tU, 1, 1, 1, 0)) {
		t.Fatal("write failed")
	}
	for i := 0; i < 5; i++ {
		if !f.writeRecord(0, encProcExit(tK, tU, uint64(i), 0)) {
			t.Fatalf("write %d failed", i)
		}
	}
	seg := f.mustSegment(t)
	if recs, _ := collect(seg); len(recs) != 6 {
		t.Fatal("prefill drain failed")
	}

	// This write forces the compact PAD and wraps.
	if !f.writeRecord(0, encProcExit(tK, tU, 99, 1)) {
		t.Fatal("wrap write failed")
	}
	// The fixture writer must have emitted the compact clock-less form at
	// index 248: len=8, type=PAD, flags=0, and nothing else.
	pad := f.data[f.dataOff(0)+248 : f.dataOff(0)+256]
	if got := binary.LittleEndian.Uint16(pad[0:]); got != 8 {
		t.Fatalf("compact PAD len = %d, want 8", got)
	}
	if got := binary.LittleEndian.Uint16(pad[2:]); got != recTypePad {
		t.Fatalf("compact PAD type = %d, want %d", got, recTypePad)
	}
	if got := binary.LittleEndian.Uint32(pad[4:]); got != 0 {
		t.Fatalf("compact PAD flags = %d, want 0", got)
	}

	recs, st := collect(seg)
	if st.Padding != 1 || st.CorruptRings != 0 {
		t.Fatalf("compact PAD mishandled: stats %+v", st)
	}
	if len(recs) != 1 {
		t.Fatalf("got %d records after compact PAD, want 1", len(recs))
	}
	if pe := recs[0].(*ProcExit); pe.PidKey != 99 || pe.ReasonClass != 1 {
		t.Fatalf("wrong record after compact PAD: %+v", pe)
	}
	if f.readPos(0) != f.writePos(0) {
		t.Fatalf("read_pos %d != write_pos %d", f.readPos(0), f.writePos(0))
	}
}

// BenchmarkDrainInto drains one full SPSC ring of mixed records per
// iteration, rewinding read_pos (reader state and the shm word) in between.
// Per-record allocations here are the decoded Record values themselves;
// the drain machinery adds none.
func BenchmarkDrainInto(b *testing.B) {
	f := newFixture(b, 2, 1<<16)
	n := uint64(0)
	for i := 0; ; i++ {
		var rec []byte
		switch i % 3 {
		case 0:
			rec = encGCDelta2(tK, tU, uint64(i), 1000, 10, 5, 100, 2000, 0)
		case 1:
			rec = encTopkSend(tK, tU, uint64(i), 42, 7, 1)
		default:
			rec = encProcMeta(tK, tU, uint64(i), 5, 1,
				"Elixir.MyApp.Worker", "run", "<0.123.0>")
		}
		if !f.writeRecord(0, rec) {
			break
		}
		n++
	}
	seg := f.mustSegment(b)
	var st DrainStats
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		seg.rings[0].readPos = 0
		f.putU64(f.ringOffs[0]+ctrlOffReadPos, 0)
		seg.DrainInto(&st, func(Record) {})
	}
	b.StopTimer()
	if st.Records != n {
		b.Fatalf("drained %d records, want %d", st.Records, n)
	}
}

// BenchmarkDrainIntoIdle is the steady-state poll with nothing published:
// this is the per-poll fixed cost and must not allocate.
func BenchmarkDrainIntoIdle(b *testing.B) {
	f := newFixture(b, 8, 4096)
	seg := f.mustSegment(b)
	var st DrainStats
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		seg.DrainInto(&st, func(Record) {})
	}
}

// BenchmarkDrainIdle is the allocating wrapper for comparison: one
// DroppedPerRing slice per pass.
func BenchmarkDrainIdle(b *testing.B) {
	f := newFixture(b, 8, 4096)
	seg := f.mustSegment(b)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = seg.Drain(func(Record) {})
	}
}

func TestDrainShortPadAtBufferEnd(t *testing.T) {
	// A 16-byte PAD: the compact clock-less form {len, type, flags} plus
	// fill. Only len/type/flags are meaningful; the fill is skipped by len.
	f := newFixture(t, 1, 256)
	for i := 0; i < 5; i++ {
		if !f.writeRecord(0, encTopkSend(tK, tU, uint64(i), 1, 1, 0)) {
			t.Fatalf("write %d failed", i)
		}
	}
	seg := f.mustSegment(t)
	if recs, _ := collect(seg); len(recs) != 5 {
		t.Fatal("prefill drain failed")
	}
	if !f.writeRecord(0, encTopkSend(tK, tU, 99, 1, 1, 0)) {
		t.Fatal("wrap write failed")
	}
	recs, st := collect(seg)
	if st.Padding != 1 || len(recs) != 1 || st.CorruptRings != 0 {
		t.Fatalf("short PAD mishandled: %d recs, stats %+v", len(recs), st)
	}
}
