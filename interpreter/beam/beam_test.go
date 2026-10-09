// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package beam

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"os"
	"testing"
	"unsafe"

	"github.com/elastic/go-freelru"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/hash"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/lpm"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/traceutil"
)

type procDataRecorder struct {
	interpreter.EbpfHandler
	info support.BEAMProcInfo
}

func (r *procDataRecorder) UpdateProcData(_ libpf.InterpreterType, _ libpf.PID, data unsafe.Pointer) error {
	r.info = *(*support.BEAMProcInfo)(data)
	return nil
}

func TestAttachReadsBeamNormalExitValue(t *testing.T) {
	const normalExit = uint64(0x7f9678900c10)
	const bias = libpf.Address(0x1000)
	memory := make([]byte, 0x1100)
	binary.LittleEndian.PutUint64(memory[0x1010:], normalExit)
	data := &beamData{beamNormalExit: 0x10}
	recorder := &procDataRecorder{}
	_, err := data.Attach(recorder, 123, bias,
		remotememory.RemoteMemory{ReaderAt: bytes.NewReader(memory)})
	require.NoError(t, err)
	require.Equal(t, normalExit, recorder.info.Beam_normal_exit)
	require.NotEqual(t, uint64(bias+data.beamNormalExit), recorder.info.Beam_normal_exit)
}

type mappingRecorder struct {
	interpreter.EbpfHandler
	updates []lpm.Prefix
	deletes []lpm.Prefix
}

func (r *mappingRecorder) UpdatePidInterpreterMapping(_ libpf.PID, prefix lpm.Prefix,
	_ uint8, _ host.FileID, _ uint64) error {
	r.updates = append(r.updates, prefix)
	return nil
}

func (r *mappingRecorder) DeletePidInterpreterMapping(_ libpf.PID, prefix lpm.Prefix) error {
	r.deletes = append(r.deletes, prefix)
	return nil
}

type pidOnlyProcess struct {
	process.Process
}

func (pidOnlyProcess) PID() libpf.PID { return 123 }

type unreadableMemory struct{}

func (unreadableMemory) ReadAt([]byte, int64) (int, error) {
	return 0, errors.New("remote memory is unreadable")
}

type failAtomReadOnce struct {
	reader   *bytes.Reader
	failAt   int64
	failSize int
	failed   bool
}

func (r *failAtomReadOnce) ReadAt(p []byte, offset int64) (int, error) {
	if offset == r.failAt && len(p) == r.failSize && !r.failed {
		r.failed = true
		return 0, errors.New("temporary atom read failure")
	}
	return r.reader.ReadAt(p, offset)
}

func TestLookupAtomRetriesAfterLengthReadFailure(t *testing.T) {
	memory := make([]byte, 0x600)
	putPtr := func(addr, value uint64) {
		binary.LittleEndian.PutUint64(memory[addr:], value)
	}
	putPtr(0x100+120, 0x200) // IndexTable.seg_table
	putPtr(0x200, 0x300)     // First page
	putPtr(0x300, 0x400)     // First Atom entry
	binary.LittleEndian.PutUint16(memory[0x400+24:], 3)
	putPtr(0x400+32, 0x500)
	copy(memory[0x500:], "foo")

	cache, err := freelru.New[uint32, libpf.String](8, hash.Uint32)
	require.NoError(t, err)
	data := &beamData{otpRelease: 25}
	data.vmStructs.indexTable.segTable = 120
	data.vmStructs.atom.len = 24
	data.vmStructs.atom.name = 32
	instance := &beamInstance{
		data:      data,
		atomTable: 0x100,
		atomCache: cache,
		rm: remotememory.RemoteMemory{ReaderAt: &failAtomReadOnce{
			reader: bytes.NewReader(memory), failAt: 0x418, failSize: 2,
		}},
	}

	_, err = instance.lookupAtom(0)
	require.Error(t, err)
	name, err := instance.lookupAtom(0)
	require.NoError(t, err)
	require.Equal(t, "foo", name.String())
}

func TestLookupAtomRetriesAfterPointerReadFailure(t *testing.T) {
	memory := make([]byte, 0x600)
	putPtr := func(addr, value uint64) {
		binary.LittleEndian.PutUint64(memory[addr:], value)
	}
	putPtr(0x100+120, 0x200) // IndexTable.seg_table
	putPtr(0x200, 0x300)     // First page
	putPtr(0x300, 0x400)     // First Atom entry
	putPtr(0, 0x350)         // Readable but wrong path when a failed pointer read returns zero
	putPtr(0x350, 0x450)
	for _, atom := range []struct {
		entry, name uint64
		value       string
	}{{0x400, 0x500, "foo"}, {0x450, 0x550, "bad"}} {
		binary.LittleEndian.PutUint16(memory[atom.entry+24:], uint16(len(atom.value)))
		putPtr(atom.entry+32, atom.name)
		copy(memory[atom.name:], atom.value)
	}

	cache, err := freelru.New[uint32, libpf.String](8, hash.Uint32)
	require.NoError(t, err)
	data := &beamData{otpRelease: 25}
	data.vmStructs.indexTable.segTable = 120
	data.vmStructs.atom.len = 24
	data.vmStructs.atom.name = 32
	instance := &beamInstance{
		data:      data,
		atomTable: 0x100,
		atomCache: cache,
		rm: remotememory.RemoteMemory{ReaderAt: &failAtomReadOnce{
			reader: bytes.NewReader(memory), failAt: 0x178, failSize: 8,
		}},
	}

	_, err = instance.lookupAtom(0)
	require.ErrorContains(t, err, "temporary atom read failure")
	_, cached := cache.Get(0)
	require.False(t, cached)
	name, err := instance.lookupAtom(0)
	require.NoError(t, err)
	require.Equal(t, "foo", name.String())
}

func prefixContains(prefix lpm.Prefix, address uint64) bool {
	blockSize := uint64(1) << (64 - prefix.Length)
	return prefix.Key <= address && address-prefix.Key < blockSize
}

func containsAddress(prefixes []lpm.Prefix, address uint64) bool {
	for _, prefix := range prefixes {
		if prefixContains(prefix, address) {
			return true
		}
	}
	return false
}

func TestSynchronizeMappingsUsesExecutableAnonymousVMAs(t *testing.T) {
	instance := &beamInstance{
		rm:       remotememory.RemoteMemory{ReaderAt: unreadableMemory{}},
		prefixes: make(map[lpm.Prefix]uint32),
	}
	recorder := &mappingRecorder{}
	mappings := []process.RawMapping{
		{Vaddr: 0x1000, Length: 0x2000, Flags: elf.PF_R | elf.PF_X, Path: "/memfd:vmem (deleted)"},
		{Vaddr: 0x4000, Length: 0x1000, Flags: elf.PF_R | elf.PF_X},
		{Vaddr: 0x6000, Length: 0x1000, Flags: elf.PF_R | elf.PF_X, Path: "/lib/libc.so"},
		{Vaddr: 0x8000, Length: 0x1000, Flags: elf.PF_R | elf.PF_W},
	}

	require.NoError(t, instance.SynchronizeMappings(recorder, nil, pidOnlyProcess{}, mappings))
	require.True(t, containsAddress(recorder.updates, 0x2800), "OTP25 JIT PC was not dispatched to BEAM")
	require.True(t, containsAddress(recorder.updates, 0x4800), "anonymous executable PC was not dispatched to BEAM")
	require.False(t, containsAddress(recorder.updates, 0x6800), "file-backed PC was dispatched to BEAM")
	require.False(t, containsAddress(recorder.updates, 0x8800), "non-executable PC was dispatched to BEAM")

	previousUpdates := len(recorder.updates)
	require.NoError(t, instance.SynchronizeMappings(recorder, nil, pidOnlyProcess{}, mappings[1:2]))
	require.Len(t, recorder.updates, previousUpdates)
	require.True(t, containsAddress(recorder.deletes, 0x2800), "removed JIT mapping was not deleted")
}

func TestSynchronizeMappingsRejectsInvalidVMAsBeforeUpdating(t *testing.T) {
	for _, invalid := range []process.RawMapping{
		{Vaddr: 0x4000, Length: 0, Flags: elf.PF_X},
		{Vaddr: ^uint64(0) - 0xfff, Length: 0x2000, Flags: elf.PF_X},
	} {
		instance := &beamInstance{prefixes: make(map[lpm.Prefix]uint32)}
		recorder := &mappingRecorder{}
		mappings := []process.RawMapping{
			{Vaddr: 0x1000, Length: 0x1000, Flags: elf.PF_X},
			invalid,
		}
		require.Error(t, instance.SynchronizeMappings(recorder, nil, pidOnlyProcess{}, mappings))
		require.Empty(t, recorder.updates)
		require.Empty(t, recorder.deletes)
		require.Zero(t, instance.mappingGeneration)
	}
}

func TestLoadOTP25ELF(t *testing.T) {
	path := os.Getenv("BEAM_OTP25_TEST_ELF")
	if path == "" {
		t.Skip("set BEAM_OTP25_TEST_ELF to an OTP25 beam.smp to run the ELF smoke test")
	}
	ref := pfelf.NewReferenceWithOpenFunc(path, nil, func() (*pfelf.File, error) {
		return pfelf.Open(path)
	})
	defer ref.Close()
	info := interpreter.NewLoaderInfo(0, ref, nil)
	loaded, err := loader(nil, info)
	require.NoError(t, err)
	data, ok := loaded.(*beamData)
	require.True(t, ok)
	require.Equal(t, uint8(25), data.otpRelease)
	require.NotZero(t, data.r)
	require.Equal(t, uint8(104), data.vmStructs.beamCodeHeader.sizeOf)
	require.Equal(t, uint8(80), data.vmStructs.beamCodeHeader.md5Ptr)
	require.Equal(t, uint8(96), data.vmStructs.beamCodeHeader.functions)
	require.Equal(t, uint8(32), data.vmStructs.atom.name)
}

func TestFindMFAChecksFinalCandidate(t *testing.T) {
	for _, tc := range []struct {
		name         string
		numFunctions uint32
		pc           libpf.Address
		wantIndex    uint64
		wantMFA      beamMfa
		wantError    bool
	}{
		{name: "only function", numFunctions: 1, pc: 0x350, wantIndex: 0,
			wantMFA: beamMfa{module: 11, function: 12, arity: 1}},
		{name: "last function", numFunctions: 2, pc: 0x450, wantIndex: 1,
			wantMFA: beamMfa{module: 21, function: 22, arity: 2}},
		{name: "outside last function", numFunctions: 2, pc: 0x500, wantError: true},
		{name: "empty table", numFunctions: 0, pc: 0x350, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			memory := make([]byte, 0x600)
			const codeHeader = 0x100
			const functionsOffset = 136
			binary.LittleEndian.PutUint32(memory[codeHeader:], tc.numFunctions)
			for idx, start := range []uint64{0x300, 0x400, 0x500} {
				binary.LittleEndian.PutUint64(memory[codeHeader+functionsOffset+idx*8:], start)
			}
			for idx, mfa := range []beamMfa{
				{module: 11, function: 12, arity: 1},
				{module: 21, function: 22, arity: 2},
			} {
				addr := 0x300 + idx*0x100 + 16
				binary.LittleEndian.PutUint32(memory[addr:], mfa.module)
				binary.LittleEndian.PutUint32(memory[addr+8:], mfa.function)
				binary.LittleEndian.PutUint32(memory[addr+16:], mfa.arity)
			}
			data := &beamData{}
			data.vmStructs.beamCodeHeader.numFunctions = 0
			data.vmStructs.beamCodeHeader.functions = functionsOffset
			data.vmStructs.ertsCodeInfo.mfa = 16
			data.vmStructs.ertsCodeMfa.sizeOf = 24
			data.vmStructs.ertsCodeMfa.module = 0
			data.vmStructs.ertsCodeMfa.function = 8
			data.vmStructs.ertsCodeMfa.arity = 16
			instance := &beamInstance{
				data: data,
				rm:   remotememory.RemoteMemory{ReaderAt: bytes.NewReader(memory)},
			}
			index, mfa, err := instance.findMFA(tc.pc, codeHeader)
			if tc.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.wantIndex, index)
			require.Equal(t, tc.wantMFA, mfa)
		})
	}
}

func TestFindFileLocationFallsBackToLastLine(t *testing.T) {
	memory := make([]byte, 0x500)
	putPtr := func(addr, value uint64) {
		binary.LittleEndian.PutUint64(memory[addr:], value)
	}
	const codeHeader = uint64(0x10)
	const lineTable = uint64(0x100)
	putPtr(codeHeader+72, lineTable)
	putPtr(lineTable, 0x400) // Filename table.
	binary.LittleEndian.PutUint32(memory[lineTable+8:], 2)
	putPtr(lineTable+16, 0x300) // Location table.
	putPtr(lineTable+24, 0x200) // First line address for function 0.
	putPtr(lineTable+32, 0x210) // End of its line range.
	putPtr(0x200, 0x1000)
	putPtr(0x208, 0x2000)
	putPtr(0x210, 0x3000)
	binary.LittleEndian.PutUint16(memory[0x302:], 42) // Last location has line 42.
	putPtr(0x400, 0x3b)                               // Empty Erlang string.

	data := &beamData{}
	data.vmStructs.beamCodeHeader.lineTable = 72
	data.vmStructs.beamCodeLineTab.sizeOf = 32
	data.vmStructs.beamCodeLineTab.locSize = 8
	data.vmStructs.beamCodeLineTab.locTab = 16
	data.vmStructs.beamCodeLineTab.funcTab = 24
	stringCache, err := freelru.New[libpf.Address, libpf.String](8, libpf.Address.Hash32)
	require.NoError(t, err)
	instance := &beamInstance{
		data:        data,
		rm:          remotememory.RemoteMemory{ReaderAt: bytes.NewReader(memory)},
		stringCache: stringCache,
	}
	_, line, err := instance.findFileLocation(libpf.Address(codeHeader), 0, 0x4000)
	require.NoError(t, err)
	require.Equal(t, uint64(42), line)
}

func TestModuleMappingIdentityAcrossRelocation(t *testing.T) {
	newInstance := func(base uint64, checksumByte byte, runtimeID uint64,
		framePointers bool) (*beamInstance, libpf.Address) {
		memory := make([]byte, base+0x1000)
		putPtr := func(addr, value uint64) {
			binary.LittleEndian.PutUint64(memory[addr:], value)
		}
		putPtr(base+80, base+0x600)     // md5_ptr
		putPtr(base+96+2*8, base+0x500) // functions[2], the module end
		binary.LittleEndian.PutUint32(memory[base:], 2)
		for j := range 16 {
			memory[base+0x600+uint64(j)] = checksumByte
		}
		data := &beamData{runtimeFileID: runtimeID}
		data.vmStructs.beamCodeHeader.numFunctions = 0
		data.vmStructs.beamCodeHeader.md5Ptr = 80
		data.vmStructs.beamCodeHeader.functions = 96
		return &beamInstance{
			data:                 data,
			rm:                   remotememory.RemoteMemory{ReaderAt: bytes.NewReader(memory)},
			framePointersEnabled: framePointers,
		}, libpf.Address(base)
	}
	frame := func(instance *beamInstance, base libpf.Address, offset uint64) libpf.Frame {
		mapping, address, err := instance.moduleMapping(base, base+libpf.Address(offset),
			libpf.Intern("Elixir.ProbeShape.Heat"))
		require.NoError(t, err)
		require.Equal(t, libpf.AddressOrLineno(offset), address)
		require.Equal(t, libpf.Address(0x500), mapping.Value().End)
		return libpf.Frame{
			Type: libpf.BEAMFrame, Mapping: mapping, AddressOrLineno: address,
			FunctionName: libpf.Intern("ProbeShape.Heat.burn/2"),
		}
	}
	traceHash := func(f libpf.Frame) libpf.TraceHash {
		trace := &libpf.Trace{}
		trace.Frames.Append(&f)
		return traceutil.HashTrace(trace)
	}
	first, firstBase := newInstance(0x100, 0x41, 0x1234, false)
	relocated, relocatedBase := newInstance(0x1000, 0x41, 0x1234, false)
	changedModule, changedModuleBase := newInstance(0x100, 0x42, 0x1234, false)
	changedRuntime, changedRuntimeBase := newInstance(0x100, 0x41, 0x5678, false)
	framePointers, framePointersBase := newInstance(0x100, 0x41, 0x1234, true)

	original := traceHash(frame(first, firstBase, 0x380))
	require.Equal(t, original, traceHash(frame(relocated, relocatedBase, 0x380)))
	require.NotEqual(t, original, traceHash(frame(first, firstBase, 0x388)))
	require.NotEqual(t, original, traceHash(frame(changedModule, changedModuleBase, 0x380)))
	require.NotEqual(t, original, traceHash(frame(changedRuntime, changedRuntimeBase, 0x380)))
	require.NotEqual(t, original, traceHash(frame(framePointers, framePointersBase, 0x380)))
}
