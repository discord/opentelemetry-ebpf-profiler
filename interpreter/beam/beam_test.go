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
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/lpm"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/support"
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
	info := interpreter.NewLoaderInfo(0, ref)
	loaded, err := loader(nil, info)
	require.NoError(t, err)
	data, ok := loaded.(*beamData)
	require.True(t, ok)
	require.Equal(t, uint8(25), data.otpRelease)
	require.NotZero(t, data.r)
	require.Equal(t, uint8(144), data.vmStructs.beamCodeHeader.sizeOf)
	require.Equal(t, uint8(32), data.vmStructs.atom.name)
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
