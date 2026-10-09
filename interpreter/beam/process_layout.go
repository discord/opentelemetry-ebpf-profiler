// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package beam

import (
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"io"
	"math"
)

// otp25ProcessLayout holds offsets from the matching OTP executable. The JIT
// saves the BEAM stack in Process.stop before some native calls.
type otp25ProcessLayout struct {
	stop          uint16
	framePointer  uint16
	i             uint16
	current       uint16
	schedulerData uint16
}

type otp25SchedulerLayout struct {
	currentProcess uint16
	currentNIF     uint16
}

type otp25NativeFuncLayout struct {
	trampoline uint16
	mfa        uint16
	argc       uint16
}

func readOTP25NativeFuncLayout(reader io.ReaderAt) (otp25NativeFuncLayout, error) {
	f, err := elf.NewFile(reader)
	if err != nil {
		return otp25NativeFuncLayout{}, fmt.Errorf("open OTP executable: %w", err)
	}
	defer f.Close()
	d, err := f.DWARF()
	if err != nil {
		return otp25NativeFuncLayout{}, fmt.Errorf("read OTP DWARF: %w", err)
	}
	r := d.Reader()
	for {
		entry, err := r.Next()
		if err != nil {
			return otp25NativeFuncLayout{}, fmt.Errorf("scan OTP DWARF: %w", err)
		}
		if entry == nil {
			return otp25NativeFuncLayout{}, fmt.Errorf("OTP ErtsNativeFunc layout is unavailable in DWARF")
		}
		if entry.Tag != dwarf.TagTypedef || entry.Val(dwarf.AttrName) != "ErtsNativeFunc" {
			continue
		}
		t, err := d.Type(entry.Offset)
		if err != nil {
			return otp25NativeFuncLayout{}, fmt.Errorf("read OTP ErtsNativeFunc: %w", err)
		}
		def, ok := t.(*dwarf.TypedefType)
		if !ok {
			continue
		}
		outer, ok := def.Type.(*dwarf.StructType)
		if !ok {
			continue
		}
		var layout otp25NativeFuncLayout
		for _, field := range outer.Field {
			switch field.Name {
			case "trampoline":
				inner, ok := field.Type.(*dwarf.StructType)
				if !ok {
					continue
				}
				for _, nested := range inner.Field {
					if nested.Name == "call_bif_nif" && nested.ByteOffset >= 0 &&
						field.ByteOffset+nested.ByteOffset <= math.MaxUint16 {
						layout.trampoline = uint16(field.ByteOffset + nested.ByteOffset)
					}
				}
			case "mfa":
				if field.ByteOffset > 0 && field.ByteOffset <= math.MaxUint16 {
					layout.mfa = uint16(field.ByteOffset)
				}
			case "argc":
				if field.ByteOffset > 0 && field.ByteOffset <= math.MaxUint16 {
					layout.argc = uint16(field.ByteOffset)
				}
			}
		}
		if layout.trampoline != 0 && layout.mfa > layout.trampoline &&
			layout.argc > layout.mfa && int64(layout.argc)+4 <= outer.ByteSize {
			return layout, nil
		}
	}
}

func readOTP25ProcessLayout(reader io.ReaderAt) (otp25ProcessLayout, error) {
	f, err := elf.NewFile(reader)
	if err != nil {
		return otp25ProcessLayout{}, fmt.Errorf("open OTP executable: %w", err)
	}
	defer f.Close()
	d, err := f.DWARF()
	if err != nil {
		return otp25ProcessLayout{}, fmt.Errorf("read OTP DWARF: %w", err)
	}
	r := d.Reader()
	for {
		entry, err := r.Next()
		if err != nil {
			return otp25ProcessLayout{}, fmt.Errorf("scan OTP DWARF: %w", err)
		}
		if entry == nil {
			return otp25ProcessLayout{}, fmt.Errorf("OTP Process layout is unavailable in DWARF")
		}
		if entry.Tag != dwarf.TagStructType || entry.Val(dwarf.AttrName) != "process" ||
			!entry.Children {
			continue
		}
		layout, ok, err := readProcessStruct(r, entry)
		if err != nil {
			return otp25ProcessLayout{}, err
		}
		if ok {
			return layout, nil
		}
	}
}

// Read scheduler fields from the same executable as the Process layout.
func readOTP25SchedulerLayout(reader io.ReaderAt) (otp25SchedulerLayout, error) {
	f, err := elf.NewFile(reader)
	if err != nil {
		return otp25SchedulerLayout{}, fmt.Errorf("open OTP executable: %w", err)
	}
	defer f.Close()
	d, err := f.DWARF()
	if err != nil {
		return otp25SchedulerLayout{}, fmt.Errorf("read OTP DWARF: %w", err)
	}
	r := d.Reader()
	for {
		entry, err := r.Next()
		if err != nil {
			return otp25SchedulerLayout{}, fmt.Errorf("scan OTP DWARF: %w", err)
		}
		if entry == nil {
			return otp25SchedulerLayout{}, fmt.Errorf("OTP scheduler layout is unavailable in DWARF")
		}
		if entry.Tag != dwarf.TagStructType || entry.Val(dwarf.AttrName) != "ErtsSchedulerData_" || !entry.Children {
			continue
		}
		size, ok := entry.Val(dwarf.AttrByteSize).(int64)
		if !ok || size <= 0 {
			r.SkipChildren()
			continue
		}
		var layout otp25SchedulerLayout
		for {
			child, err := r.Next()
			if err != nil {
				return otp25SchedulerLayout{}, fmt.Errorf("read OTP scheduler members: %w", err)
			}
			if child == nil || child.Tag == 0 {
				break
			}
			if child.Tag == dwarf.TagMember &&
				(child.Val(dwarf.AttrName) == "current_nif" || child.Val(dwarf.AttrName) == "current_process") {
				offset, ok := child.Val(dwarf.AttrDataMemberLoc).(int64)
				if !ok || offset <= 0 || offset > math.MaxUint16 || offset+8 > size || offset&7 != 0 {
					return otp25SchedulerLayout{}, fmt.Errorf("invalid OTP scheduler offset")
				}
				if child.Val(dwarf.AttrName) == "current_nif" {
					layout.currentNIF = uint16(offset)
				} else {
					layout.currentProcess = uint16(offset)
				}
			}
			if child.Children {
				r.SkipChildren()
			}
		}
		if layout.currentProcess != 0 && layout.currentNIF != 0 {
			return layout, nil
		}
	}
}

// Read member DIEs sequentially to retain compilation-unit context.
func readProcessStruct(r *dwarf.Reader, entry *dwarf.Entry) (otp25ProcessLayout, bool, error) {
	size, ok := entry.Val(dwarf.AttrByteSize).(int64)
	if !ok || size <= 0 {
		r.SkipChildren()
		return otp25ProcessLayout{}, false, nil
	}
	fields := make(map[string]uint16, 5)
	for {
		child, err := r.Next()
		if err != nil {
			return otp25ProcessLayout{}, false, fmt.Errorf("read OTP Process members: %w", err)
		}
		if child == nil || child.Tag == 0 {
			break
		}
		if child.Tag == dwarf.TagMember {
			name, _ := child.Val(dwarf.AttrName).(string)
			switch name {
			case "stop", "frame_pointer", "i", "current", "scheduler_data":
				offset, ok := child.Val(dwarf.AttrDataMemberLoc).(int64)
				if !ok || offset <= 0 || offset > math.MaxUint16 || offset+8 > size || offset&7 != 0 {
					return otp25ProcessLayout{}, false, fmt.Errorf("invalid OTP Process.%s offset", name)
				}
				if previous, duplicate := fields[name]; duplicate && previous != uint16(offset) {
					return otp25ProcessLayout{}, false, fmt.Errorf("conflicting OTP Process.%s offsets", name)
				}
				fields[name] = uint16(offset)
			}
		}
		if child.Children {
			r.SkipChildren()
		}
	}
	if fields["stop"] == 0 || fields["i"] == 0 || fields["current"] == 0 ||
		fields["scheduler_data"] == 0 {
		return otp25ProcessLayout{}, false, nil
	}
	result := otp25ProcessLayout{fields["stop"], fields["frame_pointer"], fields["i"], fields["current"], fields["scheduler_data"]}
	if (result.framePointer != 0 && uint32(result.stop)+8 != uint32(result.framePointer)) ||
		result.i <= result.stop || (result.framePointer != 0 && result.i <= result.framePointer) ||
		result.current <= result.i ||
		result.schedulerData <= result.current {
		return otp25ProcessLayout{}, false, fmt.Errorf("invalid OTP Process field ordering")
	}
	return result, true, nil
}
