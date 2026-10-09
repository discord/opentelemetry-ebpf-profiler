// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package beam

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

func otp25TestModule(name, firstRange string, base uint64, size uint32) []byte {
	nameBytes := []byte(name + "\x00")
	rangeBytes := []byte(firstRange + "\x00")
	blob := make([]byte, otp25DebugInfoSize+len(nameBytes)+otp25RangeSize+len(rangeBytes))
	binary.LittleEndian.PutUint32(blob[0:4], 1)
	binary.LittleEndian.PutUint64(blob[8:16], base)
	binary.LittleEndian.PutUint32(blob[16:20], 1)
	binary.LittleEndian.PutUint32(blob[20:24], size)
	binary.LittleEndian.PutUint16(blob[24:26], uint16(len(nameBytes)))
	copy(blob[26:], nameBytes)
	off := otp25DebugInfoSize + len(nameBytes)
	binary.LittleEndian.PutUint32(blob[off+4:off+8], size)
	binary.LittleEndian.PutUint16(blob[off+12:off+14], uint16(len(rangeBytes)))
	copy(blob[off+14:], rangeBytes)
	return blob
}

func otp25TestShared() []byte {
	blob := otp25TestModule("global", "global::apply_fun_shared", 0x200000, 0x120)
	firstRange := otp25DebugInfoSize + len("global") + 1
	binary.LittleEndian.PutUint32(blob[firstRange+4:firstRange+8], 0x40)
	name := []byte("global::call_light_bif_shared\x00")
	record := make([]byte, otp25RangeSize+len(name))
	binary.LittleEndian.PutUint32(record[0:4], 0x40)
	binary.LittleEndian.PutUint32(record[4:8], 0x60)
	binary.LittleEndian.PutUint16(record[12:14], uint16(len(name)))
	copy(record[14:], name)
	binary.LittleEndian.PutUint32(blob[16:20], 2)
	return append(blob, record...)
}

func otp25TestAppendRange(blob []byte, name string, start, end uint32) []byte {
	nameBytes := []byte(name + "\x00")
	record := make([]byte, otp25RangeSize+len(nameBytes))
	binary.LittleEndian.PutUint32(record[0:4], start)
	binary.LittleEndian.PutUint32(record[4:8], end)
	binary.LittleEndian.PutUint16(record[12:14], uint16(len(nameBytes)))
	copy(record[14:], nameBytes)
	binary.LittleEndian.PutUint32(blob[16:20], binary.LittleEndian.Uint32(blob[16:20])+1)
	return append(blob, record...)
}

type otp25CountingReader struct {
	reader          io.ReaderAt
	descriptorReads int
}

func (r *otp25CountingReader) ReadAt(dst []byte, off int64) (int, error) {
	if off == 0x100 {
		r.descriptorReads++
	}
	return r.reader.ReadAt(dst, off)
}

func otp25TestFindFragment(rm remotememory.RemoteMemory, descriptor libpf.Address,
	name string) (libpf.Address, libpf.Address, error) {
	_, fragments, err := findOTP25GlobalJITRanges(rm, descriptor, []string{name})
	if err != nil {
		return 0, 0, err
	}
	addressRange := fragments[name]
	return addressRange.start, addressRange.end, nil
}

func TestFindOTP25GlobalJITRanges(t *testing.T) {
	shared := otp25TestShared()
	shared = otp25TestAppendRange(shared, "global::call_bif_shared", 0x60, 0x90)
	shared = otp25TestAppendRange(shared, "global::bif_export_trap", 0x90, 0xa0)
	rm := otp25TestMemory(otp25TestModule("global", "global::codeHeader", 0x100000, 0x80), shared)
	reader := &otp25CountingReader{reader: rm.ReaderAt}
	rm.ReaderAt = reader
	allocation, found, err := findOTP25GlobalJITRanges(rm, 0x100, []string{
		"global::call_light_bif_shared", "global::call_bif_shared",
		"global::bif_export_trap", "global::missing", "global::call_bif_shared",
	})
	if err != nil {
		t.Fatal(err)
	}
	if allocation != (otp25JITRange{0x200000, 0x200120}) {
		t.Fatalf("allocation = %+v", allocation)
	}
	want := map[string]otp25JITRange{
		"global::call_light_bif_shared": {0x200040, 0x200060},
		"global::call_bif_shared":       {0x200060, 0x200090},
		"global::bif_export_trap":       {0x200090, 0x2000a0},
	}
	if len(found) != len(want) {
		t.Fatalf("found = %+v", found)
	}
	for name, addressRange := range want {
		if found[name] != addressRange {
			t.Errorf("%s = %+v, want %+v", name, found[name], addressRange)
		}
	}
	if reader.descriptorReads != 1 {
		t.Fatalf("descriptor reads = %d, want 1", reader.descriptorReads)
	}
}

func TestFindOTP25GlobalJITRangesMalformed(t *testing.T) {
	shared := otp25TestAppendRange(otp25TestShared(), "global::later", 0x121, 0x122)
	rm := otp25TestMemory(shared)
	allocation, found, err := findOTP25GlobalJITRanges(rm, 0x100,
		[]string{"global::call_light_bif_shared"})
	if err == nil || !strings.Contains(err.Error(), "invalid range offsets") {
		t.Fatalf("error = %v, want invalid range offsets", err)
	}
	if allocation != (otp25JITRange{}) || found != nil {
		t.Fatalf("partial result: %+v, %+v", allocation, found)
	}
}

func TestFindOTP25GlobalJITHeavyBIFFragments(t *testing.T) {
	shared := otp25TestShared()
	for _, fragment := range []struct {
		name       string
		start, end uint32
	}{
		{"global::call_bif_shared", 0x60, 0x90},
		{"global::bif_export_trap", 0x90, 0xa0},
	} {
		name := []byte(fragment.name + "\x00")
		record := make([]byte, otp25RangeSize+len(name))
		binary.LittleEndian.PutUint32(record[0:4], fragment.start)
		binary.LittleEndian.PutUint32(record[4:8], fragment.end)
		binary.LittleEndian.PutUint16(record[12:14], uint16(len(name)))
		copy(record[14:], name)
		shared = append(shared, record...)
	}
	binary.LittleEndian.PutUint32(shared[16:20], 4)
	rm := otp25TestMemory(shared)
	for _, want := range []struct {
		name       string
		start, end libpf.Address
	}{
		{"global::call_bif_shared", 0x200060, 0x200090},
		{"global::bif_export_trap", 0x200090, 0x2000a0},
	} {
		start, end, err := otp25TestFindFragment(rm, 0x100, want.name)
		if err != nil || start != want.start || end != want.end {
			t.Fatalf("%s: got [%#x,%#x), %v", want.name, start, end, err)
		}
	}
}

func otp25TestMemory(blobs ...[]byte) remotememory.RemoteMemory {
	memory := make([]byte, 0x4000)
	binary.LittleEndian.PutUint32(memory[0x100:0x104], 1)
	binary.LittleEndian.PutUint64(memory[0x110:0x118], 0x200)
	for i, blob := range blobs {
		entry := 0x200 + i*0x40
		blobAddr := 0x800 + i*0x600
		if i+1 < len(blobs) {
			binary.LittleEndian.PutUint64(memory[entry:entry+8], uint64(entry+0x40))
		}
		if i > 0 {
			binary.LittleEndian.PutUint64(memory[entry+8:entry+16], uint64(entry-0x40))
		}
		binary.LittleEndian.PutUint64(memory[entry+16:entry+24], uint64(blobAddr))
		binary.LittleEndian.PutUint64(memory[entry+24:entry+32], uint64(len(blob)))
		copy(memory[blobAddr:], blob)
	}
	return remotememory.RemoteMemory{ReaderAt: bytes.NewReader(memory)}
}

func TestFindOTP25GlobalJITRangeNameCollision(t *testing.T) {
	module := otp25TestModule("global", "global::codeHeader", 0x100000, 0x80)
	shared := otp25TestShared()
	rm := otp25TestMemory(module, shared)
	base, end, err := otp25TestFindFragment(rm, 0x100, "global::call_light_bif_shared")
	if err != nil {
		t.Fatalf("find shared fragment: %v", err)
	}
	if base != 0x200040 || end != 0x200060 {
		t.Fatalf("got [%#x,%#x), want [0x200040,0x200060)", base, end)
	}
}

func TestFindOTP25GlobalJITAllocation(t *testing.T) {
	rm := otp25TestMemory(otp25TestModule("global", "global::codeHeader", 0x100000, 0x80), otp25TestShared())
	allocation, _, err := findOTP25GlobalJITRanges(rm, 0x100, nil)
	if err != nil || allocation != (otp25JITRange{0x200000, 0x200120}) {
		t.Fatalf("got %+v, error %v", allocation, err)
	}
}

func TestFindOTP25GlobalJITRangeConcurrentHeadUpdate(t *testing.T) {
	module := otp25TestModule("other", "other::codeHeader", 0x100000, 0x80)
	rm := otp25TestMemory(module, otp25TestShared())
	memory := make([]byte, 0x4000)
	_, _ = rm.ReadAt(memory, 0)
	// OTP sets the previous head's prev link before publishing a new head.
	binary.LittleEndian.PutUint64(memory[0x208:0x210], 0x280)
	start, end, err := otp25TestFindFragment(
		remotememory.RemoteMemory{ReaderAt: bytes.NewReader(memory)}, 0x100,
		"global::call_light_bif_shared")
	if err != nil || start != 0x200040 || end != 0x200060 {
		t.Fatalf("got [%#x,%#x), error %v", start, end, err)
	}
}

func TestFindOTP25GlobalJITRangeIgnoresUnrelatedLines(t *testing.T) {
	module := otp25TestModule("guilds", "guilds::codeHeader", 0x100000, 0x80)
	rangeOffset := otp25DebugInfoSize + len("guilds") + 1
	binary.LittleEndian.PutUint32(module[rangeOffset+8:rangeOffset+12], 1)
	line := make([]byte, 12+len("guilds.erl")+1)
	binary.LittleEndian.PutUint32(line[:4], 0x1000) // Outside the module's range.
	binary.LittleEndian.PutUint16(line[8:10], uint16(len("guilds.erl")+1))
	copy(line[10:], "guilds.erl\x00")
	module = append(module, line...)
	shared := otp25TestShared()
	start, end, err := otp25TestFindFragment(otp25TestMemory(module, shared), 0x100,
		"global::call_light_bif_shared")
	if err != nil || start != 0x200040 || end != 0x200060 {
		t.Fatalf("got [%#x,%#x), error %v; want shared range", start, end, err)
	}
}

func TestFindOTP25GlobalJITRangeMalformed(t *testing.T) {
	makeShared := func() []byte {
		return otp25TestShared()
	}
	tests := []struct {
		name   string
		change func([]byte)
		want   string
	}{
		{"range beyond code", func(blob []byte) {
			off := otp25DebugInfoSize + len("global") + 1
			binary.LittleEndian.PutUint32(blob[off+4:off+8], 0x121)
		}, "invalid range offsets"},
		{"unterminated range name", func(blob []byte) {
			blob[len(blob)-3] = 'x'
		}, "invalid JIT name terminator"},
		{"address overflow", func(blob []byte) {
			binary.LittleEndian.PutUint64(blob[8:16], ^uint64(0)-0x20)
		}, "invalid module bounds"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blob := makeShared()
			tt.change(blob)
			rm := otp25TestMemory(blob)
			_, _, err := otp25TestFindFragment(rm, 0x100, "global::call_light_bif_shared")
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got error %v, want %q", err, tt.want)
			}
		})
	}
	t.Run("cycle", func(t *testing.T) {
		rm := otp25TestMemory(otp25TestModule("other", "other::codeHeader", 0x100000, 0x80))
		memory := make([]byte, 0x4000)
		_, _ = rm.ReadAt(memory, 0)
		binary.LittleEndian.PutUint64(memory[0x200:0x208], 0x200)
		_, _, err := otp25TestFindFragment(
			remotememory.RemoteMemory{ReaderAt: bytes.NewReader(memory)}, 0x100,
			"global::call_light_bif_shared")
		if err == nil || !strings.Contains(err.Error(), "cycle") {
			t.Fatalf("got error %v, want cycle", err)
		}
	})
	t.Run("unreadable blob", func(t *testing.T) {
		memory := make([]byte, 0x400)
		binary.LittleEndian.PutUint32(memory[0x100:0x104], 1)
		binary.LittleEndian.PutUint64(memory[0x110:0x118], 0x200)
		binary.LittleEndian.PutUint64(memory[0x210:0x218], 0x1000)
		binary.LittleEndian.PutUint64(memory[0x218:0x220], 32)
		_, _, err := otp25TestFindFragment(
			remotememory.RemoteMemory{ReaderAt: bytes.NewReader(memory)}, 0x100,
			"global::call_light_bif_shared")
		if err == nil || !strings.Contains(err.Error(), "read JIT blob") {
			t.Fatalf("got error %v, want read JIT blob failure", err)
		}
	})
}
