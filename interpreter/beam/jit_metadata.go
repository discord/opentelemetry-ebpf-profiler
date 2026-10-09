// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package beam // import "go.opentelemetry.io/ebpf-profiler/interpreter/beam"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

// These offsets describe the 64-bit Linux OTP25 layout in beam_jit_metadata.cpp.
// The GDB descriptor and its private symfile format are not a stable public ABI.
const (
	otp25DescriptorSize = 24
	otp25EntrySize      = 32
	otp25DebugInfoSize  = 32
	otp25RangeSize      = 16
	otp25MaxEntries     = 65536
	otp25MaxBlobSize    = 16 << 20
	otp25MaxTotalBytes  = 256 << 20
)

type otp25JITRange struct {
	start, end libpf.Address
}

// findOTP25GlobalJITRanges collects the allocation and requested fragments in one descriptor walk.
func findOTP25GlobalJITRanges(rm remotememory.RemoteMemory, descriptor libpf.Address,
	fragments []string) (otp25JITRange, map[string]otp25JITRange, error) {
	wanted := make(map[string]struct{}, len(fragments))
	for _, fragment := range fragments {
		if fragment == "" {
			return otp25JITRange{}, nil, fmt.Errorf("empty JIT fragment name")
		}
		wanted[fragment] = struct{}{}
	}
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		var allocation otp25JITRange
		found := make(map[string]otp25JITRange, len(wanted))
		err = walkOTP25JIT(rm, descriptor, func(blobAddr libpf.Address, size uint64, header []byte) (bool, error) {
			base, ranges, match, parseErr := otp25ModuleRanges(rm, blobAddr, size, header, wanted)
			if parseErr != nil {
				return false, fmt.Errorf("JIT module at %#x: %w", blobAddr, parseErr)
			}
			if !match {
				return false, nil
			}
			allocation = base
			for name, addressRange := range ranges {
				found[name] = addressRange
			}
			return true, nil
		})
		if err == nil {
			if allocation.start == 0 {
				err = fmt.Errorf("shared global JIT fragment not found")
			} else {
				return allocation, found, nil
			}
		}
	}
	return otp25JITRange{}, nil, err
}

func walkOTP25JIT(rm remotememory.RemoteMemory, descriptor libpf.Address,
	visit func(blobAddr libpf.Address, size uint64, header []byte) (bool, error)) error {
	if !rm.Valid() {
		return fmt.Errorf("invalid remote memory")
	}
	desc := make([]byte, otp25DescriptorSize)
	if err := otp25Read(rm, descriptor, desc); err != nil {
		return fmt.Errorf("read JIT descriptor: %w", err)
	}
	if binary.LittleEndian.Uint32(desc[:4]) != 1 {
		return fmt.Errorf("unsupported JIT descriptor version")
	}
	if binary.LittleEndian.Uint32(desc[4:8]) > 2 {
		return fmt.Errorf("invalid JIT descriptor action")
	}
	entry, err := otp25Pointer(rm, binary.LittleEndian.Uint64(desc[16:24]))
	if err != nil {
		return err
	}
	seen := make(map[libpf.Address]struct{})
	var total uint64
	for count := 0; entry != 0; count++ {
		if count == otp25MaxEntries {
			return fmt.Errorf("JIT entry limit exceeded")
		}
		if _, ok := seen[entry]; ok {
			return fmt.Errorf("JIT entry cycle at %#x", entry)
		}
		seen[entry] = struct{}{}
		var record [otp25EntrySize]byte
		if err := otp25Read(rm, entry, record[:]); err != nil {
			return fmt.Errorf("read JIT entry at %#x: %w", entry, err)
		}
		next, err := otp25Pointer(rm, binary.LittleEndian.Uint64(record[0:8]))
		if err != nil {
			return err
		}
		blobAddr, err := otp25Pointer(rm, binary.LittleEndian.Uint64(record[16:24]))
		if err != nil {
			return err
		}
		size := binary.LittleEndian.Uint64(record[24:32])
		if size < otp25DebugInfoSize || size > otp25MaxBlobSize {
			return fmt.Errorf("invalid JIT blob size %d", size)
		}
		if blobAddr == 0 || uint64(blobAddr) > math.MaxInt64 ||
			size > math.MaxInt64-uint64(blobAddr) || total+size > otp25MaxTotalBytes {
			return fmt.Errorf("invalid JIT blob address or total size")
		}
		total += size
		var header [otp25DebugInfoSize]byte
		if err := otp25ReadBlob(rm, blobAddr, size, 0, header[:]); err != nil {
			return fmt.Errorf("read JIT blob at %#x: %w", blobAddr, err)
		}
		switch binary.LittleEndian.Uint32(header[:4]) {
		case 0: // emulator_info
			if size != otp25DebugInfoSize {
				return fmt.Errorf("invalid emulator JIT blob size")
			}
		case 1: // module_info
			stop, err := visit(blobAddr, size, header[:])
			if err != nil {
				return err
			}
			if stop {
				return nil
			}
		default:
			return fmt.Errorf("unknown JIT blob kind")
		}
		entry = next
	}
	return nil
}

func otp25ModuleRange(rm remotememory.RemoteMemory, blobAddr libpf.Address, size uint64,
	header []byte) (base, end libpf.Address, match bool, err error) {
	nameLen := uint64(binary.LittleEndian.Uint16(header[24:26]))
	if nameLen == 0 {
		return 0, 0, false, fmt.Errorf("invalid module name length")
	}
	// module_info.name begins at 26; sizeof(debug_info) is 32.
	if nameLen > size-otp25DebugInfoSize {
		return 0, 0, false, fmt.Errorf("module name exceeds JIT blob")
	}
	nameBytes := make([]byte, nameLen)
	if err := otp25ReadBlob(rm, blobAddr, size, 26, nameBytes); err != nil {
		return 0, 0, false, err
	}
	name, err := otp25Name(nameBytes, 0, int(nameLen))
	if err != nil || name != "global" {
		return 0, 0, false, err
	}
	if binary.LittleEndian.Uint32(header[16:20]) == 0 {
		return 0, 0, false, fmt.Errorf("global JIT module has no ranges")
	}
	rangeOffset := uint64(otp25DebugInfoSize) + nameLen
	var first [otp25RangeSize]byte
	if err := otp25ReadBlob(rm, blobAddr, size, rangeOffset, first[:]); err != nil {
		return 0, 0, false, fmt.Errorf("read first JIT range: %w", err)
	}
	rangeNameLen := uint64(binary.LittleEndian.Uint16(first[12:14]))
	if rangeNameLen == 0 {
		return 0, 0, false, fmt.Errorf("invalid first JIT range name length")
	}
	if rangeNameLen > size-rangeOffset-otp25RangeSize {
		return 0, 0, false, fmt.Errorf("first JIT range exceeds blob size")
	}
	rangeNameBytes := make([]byte, rangeNameLen)
	if err := otp25ReadBlob(rm, blobAddr, size, rangeOffset+14, rangeNameBytes); err != nil {
		return 0, 0, false, fmt.Errorf("read first JIT range name: %w", err)
	}
	rangeName, err := otp25Name(rangeNameBytes, 0, int(rangeNameLen))
	if err != nil || rangeName != "global::apply_fun_shared" {
		return 0, 0, false, err
	}
	rangeCount := uint64(binary.LittleEndian.Uint32(header[16:20]))
	if rangeCount > (size-rangeOffset)/otp25RangeSize {
		return 0, 0, false, fmt.Errorf("global JIT module range count exceeds blob size")
	}
	address := binary.LittleEndian.Uint64(header[8:16])
	codeSize := binary.LittleEndian.Uint32(header[20:24])
	if address == 0 || codeSize == 0 || address > math.MaxUint64-uint64(codeSize) {
		return 0, 0, false, fmt.Errorf("invalid module bounds")
	}
	return libpf.Address(address), libpf.Address(address + uint64(codeSize)), true, nil
}

func otp25ModuleRanges(rm remotememory.RemoteMemory, blobAddr libpf.Address, size uint64,
	header []byte, wanted map[string]struct{}) (otp25JITRange, map[string]otp25JITRange, bool, error) {
	start, end, match, err := otp25ModuleRange(rm, blobAddr, size, header)
	if err != nil || !match {
		return otp25JITRange{}, nil, false, err
	}
	allocation := otp25JITRange{start, end}
	found := make(map[string]otp25JITRange, len(wanted))
	rangeOffset := uint64(otp25DebugInfoSize) + uint64(binary.LittleEndian.Uint16(header[24:26]))
	rangeCount := uint64(binary.LittleEndian.Uint32(header[16:20]))
	for i := uint64(0); i < rangeCount; i++ {
		var record [otp25RangeSize]byte
		if err := otp25ReadBlob(rm, blobAddr, size, rangeOffset, record[:]); err != nil {
			return otp25JITRange{}, nil, false, fmt.Errorf("read JIT range: %w", err)
		}
		nameLen := uint64(binary.LittleEndian.Uint16(record[12:14]))
		if nameLen == 0 || nameLen > size-rangeOffset-otp25RangeSize {
			return otp25JITRange{}, nil, false, fmt.Errorf("invalid JIT range name length")
		}
		nameBytes := make([]byte, nameLen)
		if err := otp25ReadBlob(rm, blobAddr, size, rangeOffset+14, nameBytes); err != nil {
			return otp25JITRange{}, nil, false, err
		}
		name, err := otp25Name(nameBytes, 0, int(nameLen))
		if err != nil {
			return otp25JITRange{}, nil, false, err
		}
		rangeStart := binary.LittleEndian.Uint32(record[0:4])
		rangeEnd := binary.LittleEndian.Uint32(record[4:8])
		codeSize := binary.LittleEndian.Uint32(header[20:24])
		if rangeStart > rangeEnd || rangeEnd > codeSize {
			return otp25JITRange{}, nil, false, fmt.Errorf("invalid range offsets")
		}
		if _, ok := wanted[name]; ok {
			if rangeStart == rangeEnd {
				return otp25JITRange{}, nil, false, fmt.Errorf("empty %s range", name)
			}
			found[name] = otp25JITRange{
				start + libpf.Address(rangeStart), start + libpf.Address(rangeEnd),
			}
		}
		rangeOffset += otp25RangeSize + nameLen
		lineCount := uint64(binary.LittleEndian.Uint32(record[8:12]))
		if lineCount > (size-rangeOffset)/12 {
			return otp25JITRange{}, nil, false, fmt.Errorf("JIT range line count exceeds blob size")
		}
		for j := uint64(0); j < lineCount; j++ {
			var line [12]byte
			if err := otp25ReadBlob(rm, blobAddr, size, rangeOffset, line[:]); err != nil {
				return otp25JITRange{}, nil, false, err
			}
			fileLen := uint64(binary.LittleEndian.Uint16(line[8:10]))
			if fileLen == 0 || fileLen > size-rangeOffset-12 {
				return otp25JITRange{}, nil, false, fmt.Errorf("invalid JIT line file length")
			}
			rangeOffset += 12 + fileLen
		}
	}
	return allocation, found, true, nil
}

func otp25ReadBlob(rm remotememory.RemoteMemory, addr libpf.Address, size, offset uint64,
	dst []byte) error {
	if offset > size || uint64(len(dst)) > size-offset {
		return fmt.Errorf("JIT field exceeds blob size")
	}
	return otp25Read(rm, addr+libpf.Address(offset), dst)
}

func otp25Name(blob []byte, start, length int) (string, error) {
	if length == 0 || start < 0 || start > len(blob) || length > len(blob)-start {
		return "", fmt.Errorf("invalid JIT name length")
	}
	name := blob[start : start+length]
	if name[length-1] != 0 || bytes.IndexByte(name[:length-1], 0) >= 0 {
		return "", fmt.Errorf("invalid JIT name terminator")
	}
	return string(name[:length-1]), nil
}

func otp25Pointer(rm remotememory.RemoteMemory, raw uint64) (libpf.Address, error) {
	if raw == 0 {
		return 0, nil
	}
	if raw < uint64(rm.Bias) {
		return 0, fmt.Errorf("JIT pointer underflows remote memory bias")
	}
	return libpf.Address(raw - uint64(rm.Bias)), nil
}

func otp25Read(rm remotememory.RemoteMemory, addr libpf.Address, dst []byte) error {
	if addr == 0 || uint64(addr) > math.MaxInt64 || uint64(len(dst)) > math.MaxInt64-uint64(addr) {
		return fmt.Errorf("invalid remote address %#x", addr)
	}
	n, err := rm.ReadAt(dst, int64(addr))
	if err != nil {
		return err
	}
	if n != len(dst) {
		return io.ErrUnexpectedEOF
	}
	return nil
}
