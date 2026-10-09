// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package beam // import "go.opentelemetry.io/ebpf-profiler/interpreter/beam"

// BEAM VM Unwinder support code

// The BEAM VM is an interpreter for Erlang, as well as several other languages
// that share the same bytecode, such as Elixir and Gleam.

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"unsafe"

	"github.com/elastic/go-freelru"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf/hash"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfunsafe"
	npsr "go.opentelemetry.io/ebpf-profiler/nopanicslicereader"

	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/lpm"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/support"
)

var (
	// regex for matching the process name
	beamRegex                      = regexp.MustCompile(`(^|\/)beam\.smp`)
	_         interpreter.Data     = &beamData{}
	_         interpreter.Instance = &beamInstance{}
)

type beamData struct {
	processLayout       otp25ProcessLayout
	nativeFuncLayout    otp25NativeFuncLayout
	schedulerLayout     otp25SchedulerLayout
	otpRelease          uint8
	ertsVersion         string
	runtimeFileID       uint64
	theActiveCodeIndex  libpf.Address
	r                   libpf.Address
	beamNormalExit      libpf.Address
	jitDebugDescriptor  libpf.Address
	ertsFrameLayout     uint64
	ertsAtomTable       uint64
	etpPtrMask          uint64
	etpHeaderSubtagMask uint64
	etpHeapBitsSubtag   uint64
	// Sizes and offsets BEAM internal structs we need to traverse
	vmStructs struct {
		// ranges
		// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/beam_ranges.c#L56-L61
		ranges struct {
			sizeOf uint8
		}

		// BeamCodeHeader
		// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/beam_code.h#L56-L125
		beamCodeHeader struct {
			sizeOf, numFunctions, lineTable, md5Ptr, functions uint8
		}

		// ErtsCodeInfo
		// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/code_ix.h#L104-L123
		ertsCodeInfo struct {
			sizeOf, mfa uint8
		}

		// ErtsCodeMFA
		// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/code_ix.h#L87-L95
		ertsCodeMfa struct {
			sizeOf, module, function, arity uint8
		}

		// BeamCodeLineTab
		// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/beam_code.h#L130-L138
		beamCodeLineTab struct {
			sizeOf, fnamePtr, locSize, locTab, funcTab uint8
		}

		// IndexTable
		// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/index.h#L39-L47
		indexTable struct {
			segTable uint8
		}

		// Atom
		// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/atom.h#L48-L54
		// In OTP 28, we need to look it up as a binary:
		// https://github.com/erlang/otp/blob/OTP-28.0.2/erts/emulator/beam/atom.h#L50-L59
		atom struct {
			len, name uint8
			u         struct {
				bin uint8
			}
		}

		// ErlHeapBits
		// https://github.com/erlang/otp/blob/OTP-28.0.2/erts/emulator/beam/erl_bits.h#L149-L154
		erlHeapBits struct {
			data uint8
		}
	}
}

type beamMfa struct {
	module   uint32
	function uint32
	arity    uint32
}

type beamInstance struct {
	interpreter.InstanceStubs

	pid                  libpf.PID
	data                 *beamData
	rm                   remotememory.RemoteMemory
	atomTable            libpf.Address
	atomCache            *freelru.LRU[uint32, libpf.String]
	mfaNameCache         *freelru.LRU[beamMfa, libpf.String]
	stringCache          *freelru.LRU[libpf.Address, libpf.String]
	framePointersEnabled bool

	// prefixes is indexed by the prefix added to ebpf maps (to be cleaned up) to its generation
	prefixes map[lpm.Prefix]uint32
	// mappingGeneration is the current generation (so old entries can be pruned)
	mappingGeneration uint32
}

func GetLoader(_ Config) interpreter.Loader {
	return interpreter.NewLoader(loader, []interpreter.InterpreterResource{
		{MapName: BPFMapName, ProgID: uint32(support.ProgUnwindBEAM), ProgName: "unwind_beam"},
	})
}

func loader(ebpf interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	matches := beamRegex.FindStringSubmatch(info.FileName())
	if matches == nil {
		return nil, nil
	}

	ef, err := info.GetELF()
	if err != nil {
		return nil, err
	}

	_, otpReleaseString, err := ef.SymbolData("etp_otp_release", 4)
	if err != nil {
		return nil, fmt.Errorf("failed to read OTP release: %v", err)
	}
	// Slice off the null-terminator before parsing
	otpRelease, err := strconv.ParseUint(string(otpReleaseString[:len(otpReleaseString)-1]), 10, 32)
	if err != nil || otpRelease > 255 {
		return nil, fmt.Errorf("invalid OTP Release: %v", otpReleaseString)
	}

	_, ertsVersion, err := ef.SymbolData("etp_erts_version", 64)
	if err != nil {
		return nil, fmt.Errorf("failed to read ERTS version: %v", err)
	}

	// "r" symbol is from:
	// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/beam_ranges.c#L62
	// TODO: We want to avoid reading static symbols to find the address of r here,
	// because it would be removed if the binary is stripped, but it seems that's the only
	// way to get it currently. If possible, we should get it exported in erl_etp.c
	//
	// Double hack: when the emulator is built with LTO , the linker renames
	// file-local symbols by appending a ".llvm.<hash>" suffix, so "r" appears
	// as e.g. "r.llvm.5915997031394578193". Match either form.
	var r libpf.Symbol
	var rFound bool
	ef.VisitSymbols(func(sym libpf.Symbol) bool {
		if sym.Name == "r" || strings.HasPrefix(string(sym.Name), "r.llvm.") {
			r = sym
			rFound = true
			return false
		}
		return true
	})
	if !rFound {
		return nil, fmt.Errorf("symbol 'r' not found")
	}

	// "the_active_code_index" symbol is from:
	// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/code_ix.c#L46
	codeIndex, _, err := ef.SymbolData("the_active_code_index", 4)
	if err != nil {
		return nil, fmt.Errorf("symbol 'the_active_code_index' not found: %v", err)
	}

	// "erts_atom_table" symbol is from:
	// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/atom.c#L35
	atomTable, _, err := ef.SymbolData("erts_atom_table", 128)
	if err != nil {
		return nil, fmt.Errorf("symbol 'erts_atom_table' not found: %v", err)
	}

	// "etp_ptr_mask" symbol is from:
	// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/erl_etp.c#L82-L85
	_, etpPtrMask, err := ef.SymbolData("etp_ptr_mask", 8)
	if err != nil {
		return nil, fmt.Errorf("symbol 'etp_ptr_mask' not found: %v", err)
	}

	// "beam_normal_exit" symbol is from:
	// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/jit/beam_jit_main.cpp#L54
	beamNormalExit, _, err := ef.SymbolData("beam_normal_exit", 8)
	if err != nil {
		return nil, fmt.Errorf("symbol 'beam_normal_exit' not found: %v", err)
	}

	d := &beamData{
		otpRelease:         uint8(otpRelease),
		ertsVersion:        string(ertsVersion[:len(ertsVersion)-1]),
		runtimeFileID:      uint64(info.FileID()),
		theActiveCodeIndex: libpf.Address(codeIndex.Address),
		r:                  libpf.Address(r.Address),
		beamNormalExit:     libpf.Address(beamNormalExit.Address),
		ertsAtomTable:      uint64(atomTable.Address),
		etpPtrMask:         npsr.Uint64(etpPtrMask, 0),
	}
	if d.otpRelease == 25 {
		if address, err := ef.LookupSymbolAddress("__jit_debug_descriptor"); err == nil {
			d.jitDebugDescriptor = libpf.Address(address)
		}
	}
	if d.otpRelease == 25 {
		if layout, err := readOTP25ProcessLayout(ef.Underlying()); err == nil {
			d.processLayout = layout
		} else {
			log.Debugf("BEAM Process layout unavailable: %v", err)
		}
		if layout, err := readOTP25SchedulerLayout(ef.Underlying()); err == nil {
			d.schedulerLayout = layout
		} else {
			log.Debugf("BEAM scheduler layout unavailable: %v", err)
		}
		if layout, err := readOTP25NativeFuncLayout(ef.Underlying()); err == nil {
			d.nativeFuncLayout = layout
		} else {
			log.Debugf("BEAM native function layout unavailable: %v", err)
		}
	}

	if otpRelease >= 28 {
		// "etp_header_subtag_mask" is from:
		// https://github.com/erlang/otp/blob/OTP-28.0.2/erts/emulator/beam/erl_etp.c#L132
		_, etpHeaderSubtagMask, err := ef.SymbolData("etp_header_subtag_mask", 8)
		if err != nil {
			return nil, fmt.Errorf("symbol 'etp_header_subtag_mask' not found: %v", err)
		}

		// "etp_heap_bits_subtag" is from:
		// https://github.com/erlang/otp/blob/OTP-28.0.2/erts/emulator/beam/erl_etp.c#L108
		_, etpHeapBitsSubtag, err := ef.SymbolData("etp_heap_bits_subtag", 8)
		if err != nil {
			return nil, fmt.Errorf("symbol 'etp_heap_bits_subtag' not found: %v", err)
		}

		d.etpHeaderSubtagMask = npsr.Uint64(etpHeaderSubtagMask, 0)
		d.etpHeapBitsSubtag = npsr.Uint64(etpHeapBitsSubtag, 0)
	}

	// If erts_frame_layout is not defined, it means that frame pointers are not supported,
	// so use 0 to signify that they're not enabled since that shouldn't be a real offset.
	erts_frame_layout_symbol, _, err := ef.SymbolData("erts_frame_layout", 8)
	if err == nil {
		d.ertsFrameLayout = uint64(erts_frame_layout_symbol.Address)
	} else {
		d.ertsFrameLayout = 0
	}

	vms := &d.vmStructs

	// These values are the same on OTP releases 27.2.4 and 28.0.2.
	vms.ranges.sizeOf = 32
	vms.beamCodeHeader.numFunctions = 0
	vms.beamCodeHeader.lineTable = 72
	vms.ertsCodeInfo.sizeOf = 40
	vms.ertsCodeInfo.mfa = 16
	vms.ertsCodeMfa.sizeOf = 24
	vms.ertsCodeMfa.module = 0
	vms.ertsCodeMfa.function = 8
	vms.ertsCodeMfa.arity = 16
	vms.beamCodeLineTab.sizeOf = 32
	vms.beamCodeLineTab.fnamePtr = 0
	vms.beamCodeLineTab.locSize = 8
	vms.beamCodeLineTab.locTab = 16
	vms.beamCodeLineTab.funcTab = 24
	vms.indexTable.segTable = 120
	vms.atom.len = 24
	vms.erlHeapBits.data = 16

	switch d.otpRelease {
	case 25, 26:
		// OTP 25 and 26 have no coverage fields in BeamCodeHeader.
		vms.beamCodeHeader.sizeOf = 104
		vms.beamCodeHeader.md5Ptr = 80
		vms.beamCodeHeader.functions = 96
		vms.atom.name = 32
	case 27:
		vms.beamCodeHeader.sizeOf = 144
		vms.beamCodeHeader.md5Ptr = 120
		vms.beamCodeHeader.functions = 136
		vms.atom.name = 32
	case 28:
		vms.beamCodeHeader.sizeOf = 160
		vms.beamCodeHeader.md5Ptr = 136
		vms.beamCodeHeader.functions = 152
		vms.atom.u.bin = 32
	default:
		return d, fmt.Errorf("unsupported OTP version for BEAM interpreter: %d", d.otpRelease)
	}

	return d, nil
}

func (d *beamData) String() string {
	return fmt.Sprintf("BEAM OTP %d, ERTS %s", d.otpRelease, d.ertsVersion)
}

func hashMFA(key beamMfa) uint32 {
	mfhash := uint32(hash.Uint64(uint64(key.module)<<32 | uint64(key.function)))
	return uint32(hash.Uint64(uint64(mfhash)<<32 | uint64(key.arity)))
}

func (d *beamData) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID, bias libpf.Address,
	rm remotememory.RemoteMemory) (interpreter.Instance, error) {
	log.Debugf("BEAM attaching, OTP %d, ERTS %s, bias: 0x%x", d.otpRelease, d.ertsVersion, bias)

	// beam_normal_exit is a pointer variable in the executable. The unwinder
	// compares PCs with its value, which points into the JIT code cache.
	var normalExitBytes [8]byte
	if err := rm.Read(bias+d.beamNormalExit, normalExitBytes[:]); err != nil {
		return nil, fmt.Errorf("failed to read BEAM normal exit: %w", err)
	}
	normalExit := binary.LittleEndian.Uint64(normalExitBytes[:])
	if normalExit == 0 {
		return nil, fmt.Errorf("BEAM normal exit is null")
	}

	data := support.BEAMProcInfo{
		R:                     uint64(bias + d.r),
		The_active_code_index: uint64(bias + d.theActiveCodeIndex),
		Beam_normal_exit:      normalExit,
		Ranges_sizeof:         uint8(d.vmStructs.ranges.sizeOf),
		Otp_release:           d.otpRelease,
	}

	// If this value is zero, it means that frame pointer support is not included in the runtime binary
	if d.ertsFrameLayout != 0 {
		ertsFrameLayout := rm.Uint64(bias + libpf.Address(d.ertsFrameLayout))
		// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/erl_vm.h#L68-L73
		data.Frame_pointers_enabled = ertsFrameLayout == 1
	}
	if d.otpRelease == 25 && d.jitDebugDescriptor != 0 {
		fragments := map[string][2]*uint64{
			"global::call_light_bif_shared":   {&data.Light_bif_start, &data.Light_bif_end},
			"global::i_bif_guard_shared":      {&data.Guard_bif_start, &data.Guard_bif_end},
			"global::i_bif_body_shared":       {&data.Body_bif_start, &data.Body_bif_end},
			"global::garbage_collect":         {&data.Garbage_collect_start, &data.Garbage_collect_end},
			"global::process_main":            {&data.Process_main_start, &data.Process_main_end},
			"global::update_map_assoc_shared": {&data.Map_assoc_start, &data.Map_assoc_end},
			"global::raise_exception_shared":  {&data.Raise_exception_start, &data.Raise_exception_end},
			"global::call_nif_shared":         {&data.Call_nif_start, &data.Call_nif_end},
		}
		// Process-based boundaries require offsets from the matching executable.
		if d.processLayout.stop != 0 &&
			(runtime.GOARCH == "arm64" ||
				(data.Frame_pointers_enabled && d.processLayout.framePointer != 0)) {
			data.Process_stop_offset = d.processLayout.stop
			data.Process_frame_pointer_offset = d.processLayout.framePointer
			data.Process_i_offset = d.processLayout.i
			data.Process_current_offset = d.processLayout.current
			data.Process_scheduler_data_offset = d.processLayout.schedulerData
			data.Scheduler_current_process_offset = d.schedulerLayout.currentProcess
			data.Dirty_nif_current_offset = d.schedulerLayout.currentNIF
			data.Native_func_trampoline_offset = d.nativeFuncLayout.trampoline
			data.Native_func_mfa_offset = d.nativeFuncLayout.mfa
			data.Native_func_argc_offset = d.nativeFuncLayout.argc
		}
		if data.Process_stop_offset != 0 {
			fragments["global::call_bif_shared"] = [2]*uint64{&data.Heavy_bif_start, &data.Heavy_bif_end}
			fragments["global::bif_export_trap"] = [2]*uint64{&data.Bif_export_trap_start, &data.Bif_export_trap_end}
		}
		names := make([]string, 0, len(fragments))
		for name := range fragments {
			names = append(names, name)
		}
		allocation, ranges, err := findOTP25GlobalJITRanges(rm, bias+d.jitDebugDescriptor, names)
		if err != nil {
			log.Debugf("BEAM global JIT metadata unavailable: %v", err)
		} else {
			data.Global_jit_start = uint64(allocation.start)
			data.Global_jit_end = uint64(allocation.end)
			for name, fields := range fragments {
				if r, ok := ranges[name]; ok {
					*fields[0], *fields[1] = uint64(r.start), uint64(r.end)
				} else {
					log.Debugf("BEAM JIT fragment unavailable: %s", name)
				}
			}
			if runtime.GOARCH == "amd64" &&
				(data.Heavy_bif_start == 0 || data.Bif_export_trap_start == 0) {
				data.Heavy_bif_start, data.Heavy_bif_end = 0, 0
			}
		}
	}

	if err := ebpf.UpdateProcData(libpf.BEAM, pid, unsafe.Pointer(&data)); err != nil {
		return nil, err
	}
	if runtime.GOARCH == "amd64" && data.Frame_pointers_enabled && data.Heavy_bif_start != 0 {
		probePath := fmt.Sprintf("/proc/%d/exe", pid)
		probes, ok := ebpf.(interface{ AttachBEAMBIF(uint64, string) error })
		var probeErr error
		if !ok {
			probeErr = fmt.Errorf("probe handler is unavailable")
		} else {
			probeErr = probes.AttachBEAMBIF(d.runtimeFileID, probePath)
		}
		if probeErr != nil {
			log.Debugf("BEAM BIF probes unavailable for %s: %v", probePath, probeErr)
			data.Heavy_bif_start = 0
			data.Heavy_bif_end = 0
			if err := ebpf.UpdateProcData(libpf.BEAM, pid, unsafe.Pointer(&data)); err != nil {
				return nil, err
			}
		}
	}
	if d.otpRelease == 25 && data.Process_stop_offset != 0 && data.Dirty_nif_current_offset != 0 &&
		(runtime.GOARCH != "arm64" ||
			(data.Process_i_offset != 0 && data.Process_current_offset != 0 &&
				data.Native_func_trampoline_offset != 0 && data.Native_func_mfa_offset != 0 &&
				data.Native_func_argc_offset != 0)) &&
		(runtime.GOARCH == "arm64" || data.Frame_pointers_enabled) {
		probePath := fmt.Sprintf("/proc/%d/exe", pid)
		if probes, ok := ebpf.(interface{ AttachBEAMDirtyNIF(uint64, string) error }); ok {
			if err := probes.AttachBEAMDirtyNIF(d.runtimeFileID, probePath); err != nil {
				log.Debugf("BEAM dirty NIF probes unavailable for %s: %v", probePath, err)
			}
		}
	}

	atomCache, err := freelru.New[uint32, libpf.String](
		interpreter.LruFunctionCacheSize, hash.Uint32)
	if err != nil {
		return nil, err
	}

	mfaNameCache, err := freelru.New[beamMfa, libpf.String](
		interpreter.LruFunctionCacheSize, hashMFA)
	if err != nil {
		return nil, err
	}

	stringCache, err := freelru.New[libpf.Address, libpf.String](
		interpreter.LruFunctionCacheSize, libpf.Address.Hash32)
	if err != nil {
		return nil, err
	}

	return &beamInstance{
		pid:                  pid,
		data:                 d,
		rm:                   rm,
		prefixes:             make(map[lpm.Prefix]uint32),
		atomTable:            bias + libpf.Address(d.ertsAtomTable),
		atomCache:            atomCache,
		mfaNameCache:         mfaNameCache,
		stringCache:          stringCache,
		framePointersEnabled: data.Frame_pointers_enabled,
	}, nil
}

func (d *beamData) Unload(ebpf interpreter.EbpfHandler) {
	if probes, ok := ebpf.(interface{ DetachBEAMBIF(uint64) }); ok {
		probes.DetachBEAMBIF(d.runtimeFileID)
	}
	if probes, ok := ebpf.(interface{ DetachBEAMDirtyNIF(uint64) }); ok {
		probes.DetachBEAMDirtyNIF(d.runtimeFileID)
	}
}

func (i *beamInstance) UsesAnonymousMappings() bool {
	return true
}

func (i *beamInstance) SynchronizeMappings(ebpf interpreter.EbpfHandler, _ reporter.ExecutableReporter, pr process.Process, mappings []process.RawMapping) error {
	// Validate the complete mapping set before changing any eBPF entries.
	for idx := range mappings {
		m := &mappings[idx]
		if !m.IsExecutable() || !m.IsAnonymous() {
			continue
		}
		if m.Length == 0 || m.Vaddr > ^uint64(0)-m.Length {
			return fmt.Errorf("invalid BEAM executable mapping %#x/%#x", m.Vaddr, m.Length)
		}
	}

	pid := pr.PID()
	i.mappingGeneration++
	for idx := range mappings {
		m := &mappings[idx]
		if !m.IsExecutable() || !m.IsAnonymous() {
			continue
		}

		log.Debugf("Enabling BEAM for %#x/%#x", m.Vaddr, m.Length)

		prefixes, err := lpm.CalculatePrefixList(m.Vaddr, m.Vaddr+m.Length)
		if err != nil {
			return fmt.Errorf("new BEAM mapping lpm failure %#x/%#x: %w", m.Vaddr, m.Length, err)
		}

		for _, prefix := range prefixes {
			_, exists := i.prefixes[prefix]
			if !exists {
				err := ebpf.UpdatePidInterpreterMapping(pid, prefix, support.ProgUnwindBEAM, 0, 0)
				if err != nil {
					return err
				}
			}
			i.prefixes[prefix] = i.mappingGeneration
		}
	}

	// Remove prefixes not seen
	for prefix, generation := range i.prefixes {
		if generation == i.mappingGeneration {
			continue
		}
		log.Debugf("Delete BEAM prefix %#v", prefix)
		_ = ebpf.DeletePidInterpreterMapping(pid, prefix)
		delete(i.prefixes, prefix)
	}

	return nil
}

func (i *beamInstance) Detach(interpreter.EbpfHandler, libpf.PID) error {
	return nil
}

func (i *beamInstance) Symbolize(ef libpf.EbpfFrame, frames *libpf.Frames, _ libpf.FrameMapping) error {
	if !ef.Type().IsInterpType(libpf.BEAM) {
		return interpreter.ErrMismatchInterpreterType
	}
	pc := libpf.Address(ef.Data())
	codeHeader := libpf.Address(ef.Variable(0))

	functionIndex, mfa, err := i.findMFA(pc, codeHeader)
	if err != nil {
		return err
	}
	moduleName, err := i.lookupAtom(mfa.module)
	if err != nil {
		return err
	}
	mapping, offset, err := i.moduleMapping(codeHeader, pc, moduleName)
	if err != nil {
		return err
	}

	var mfaName libpf.String
	if value, ok := i.mfaNameCache.Get(mfa); ok {
		mfaName = value
	} else {
		functionName, err := i.lookupAtom(mfa.function)
		if err != nil {
			return err
		}

		if strings.HasPrefix(moduleName.String(), "Elixir.") {
			// This is an Elixir module, so format the function using Elixir syntax (without the "Elixir." prefix)
			mfaName = libpf.Intern(fmt.Sprintf("%s.%s/%d", moduleName.String()[7:], functionName, mfa.arity))
		} else {
			// Assume it's Erlang and format it using Erlang syntax
			mfaName = libpf.Intern(fmt.Sprintf("%s:%s/%d", moduleName, functionName, mfa.arity))
		}

		i.mfaNameCache.Add(mfa, mfaName)
	}

	fileName, lineNumber, err := i.findFileLocation(codeHeader, functionIndex, pc)
	if err == nil {
		log.Debugf("BEAM Found function %s at %s:%d", mfaName, fileName, lineNumber)
		frames.Append(&libpf.Frame{
			Type:            libpf.BEAMFrame,
			Mapping:         mapping,
			AddressOrLineno: offset,
			FunctionName:    mfaName,
			SourceFile:      fileName,
			SourceLine:      libpf.SourceLineno(lineNumber),
		})
	} else {
		log.Debugf("BEAM Found function %s", mfaName)
		frames.Append(&libpf.Frame{
			Type:            libpf.BEAMFrame,
			Mapping:         mapping,
			AddressOrLineno: offset,
			FunctionName:    mfaName,
		})
	}

	return nil
}

// moduleMapping gives anonymous BEAM JIT code a stable, module-relative identity.
// OTP embeds the BEAM module checksum in each code allocation. The runtime
// executable and frame layout qualify it because both affect generated code.
func (i *beamInstance) moduleMapping(codeHeader, pc libpf.Address,
	moduleName libpf.String) (libpf.FrameMapping, libpf.AddressOrLineno, error) {
	vms := i.data.vmStructs.beamCodeHeader
	numFunctions := i.rm.Uint32(codeHeader + libpf.Address(vms.numFunctions))
	if numFunctions == 0 || numFunctions > 1<<20 {
		return libpf.FrameMapping{}, 0, fmt.Errorf("BEAM invalid function count %d at %#x", numFunctions, codeHeader)
	}
	moduleEnd := i.rm.Ptr(codeHeader + libpf.Address(vms.functions) + libpf.Address(numFunctions)*8)
	if moduleEnd <= codeHeader || pc < codeHeader || pc >= moduleEnd {
		return libpf.FrameMapping{}, 0, fmt.Errorf("BEAM PC %#x outside module %#x-%#x", pc, codeHeader, moduleEnd)
	}
	md5Ptr := i.rm.Ptr(codeHeader + libpf.Address(vms.md5Ptr))
	if md5Ptr == 0 {
		return libpf.FrameMapping{}, 0, fmt.Errorf("BEAM module checksum pointer is null at %#x", codeHeader)
	}
	var checksum [16]byte
	if err := i.rm.Read(md5Ptr, checksum[:]); err != nil {
		return libpf.FrameMapping{}, 0, fmt.Errorf("BEAM module checksum read at %#x: %w", md5Ptr, err)
	}

	const domain = "BEAM-JIT-module-v1\x00"
	var identity [len(domain) + 8 + 1 + 16]byte
	copy(identity[:], domain)
	binary.BigEndian.PutUint64(identity[len(domain):], i.data.runtimeFileID)
	if i.framePointersEnabled {
		identity[len(domain)+8] = 1
	}
	copy(identity[len(domain)+9:], checksum[:])
	digest := sha256.Sum256(identity[:])
	fileID, _ := libpf.FileIDFromBytes(digest[:16])
	file := libpf.NewFrameMappingFile(libpf.FrameMappingFileData{
		FileID:   fileID,
		FileName: libpf.Intern("BEAM:" + moduleName.String()),
	})
	mapping := libpf.NewFrameMapping(libpf.FrameMappingData{
		File:  file,
		Start: 0,
		End:   moduleEnd - codeHeader,
	})
	return mapping, libpf.AddressOrLineno(pc - codeHeader), nil
}

func (i *beamInstance) findMFA(pc libpf.Address, codeHeader libpf.Address) (functionIndex uint64, mfa beamMfa, err error) {
	vms := i.data.vmStructs

	numFunctions := i.rm.Uint32(codeHeader + libpf.Address(vms.beamCodeHeader.numFunctions))
	functions := codeHeader + libpf.Address(vms.beamCodeHeader.functions)

	// This buffer is used to load the start and end pointers for the memory
	// ranges as we binary-search for the correct MFA entry in the codeHeader
	// based on whether the PC falls before, after, or within the mid range.
	// Based on the implementation here:
	// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/etc/unix/etp-commands.in#L1343
	midBuffer := make([]byte, 16)

	ertsCodeInfo := libpf.Address(0)
	lowIdx := uint64(0)
	highIdx := uint64(numFunctions)
	for lowIdx < highIdx {
		midIdx := lowIdx + (highIdx-lowIdx)/2
		err := i.rm.Read(functions+libpf.Address(midIdx*8), midBuffer)
		if err != nil {
			return 0, beamMfa{}, fmt.Errorf("BEAM unable to read codeHeader.functions[%d] for codeHeader 0x%x", midIdx, codeHeader)
		}
		midStart := npsr.Ptr(midBuffer, 0)
		midEnd := npsr.Ptr(midBuffer, 8)
		if pc < midStart {
			highIdx = midIdx
		} else if pc >= midEnd {
			lowIdx = midIdx + 1
		} else {
			ertsCodeInfo = midStart
			functionIndex = midIdx

			data := make([]byte, vms.ertsCodeMfa.sizeOf)
			err = i.rm.Read(ertsCodeInfo+libpf.Address(vms.ertsCodeInfo.mfa), data)
			if err != nil {
				return 0, beamMfa{}, fmt.Errorf("BEAM unable to look up MFA at for ertsCodeInfo 0x%x", ertsCodeInfo)
			}
			mfa.module = npsr.Uint32(data, uint(vms.ertsCodeMfa.module))
			mfa.function = npsr.Uint32(data, uint(vms.ertsCodeMfa.function))
			mfa.arity = npsr.Uint32(data, uint(vms.ertsCodeMfa.arity))

			return functionIndex, mfa, nil
		}
	}

	return 0, beamMfa{}, fmt.Errorf("BEAM unable to find the MFA for PC 0x%x in expected code range", pc)
}

func (i *beamInstance) findFileLocation(codeHeader libpf.Address, functionIndex uint64, pc libpf.Address) (fileName libpf.String, lineNumber uint64, err error) {
	vms := i.data.vmStructs

	lineTable := i.rm.Ptr(codeHeader + libpf.Address(vms.beamCodeHeader.lineTable))
	functionTable := lineTable + libpf.Address(vms.beamCodeLineTab.funcTab)
	functionEntryStart := functionTable + libpf.Address(8*functionIndex)

	lineRange := make([]byte, 16)
	err = i.rm.Read(functionEntryStart, lineRange)
	if err != nil {
		return libpf.NullString, 0, fmt.Errorf("BEAM failed to read function table info")
	}
	lineLow := npsr.Ptr(lineRange, 0)
	lineHigh := npsr.Ptr(lineRange, 8)

	// This buffer is used to load the start and end pointers for the memory
	// ranges as we binary-search for the correct line number from the start of
	// the MFA entry in the codeHeader based on whether the PC falls before,
	// after, or within the mid range.
	// Based on the implementation here:
	// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/etc/unix/etp-commands.in#L1269
	lineMidBuffer := make([]byte, 16)
	// We need to align the lineMid values on 8-byte address boundaries
	bitmask := libpf.Address(^(uint64(0xf)))
	for lineHigh > lineLow {
		lineMid := lineLow + ((lineHigh-lineLow)/2)&bitmask
		err := i.rm.Read(lineMid, lineMidBuffer)
		if err != nil {
			return libpf.NullString, 0, fmt.Errorf("BEAM failed to read line table")
		}
		if pc < npsr.Ptr(lineMidBuffer, 0) {
			lineHigh = lineMid
		} else if pc < npsr.Ptr(lineMidBuffer, 8) {
			firstLine := i.rm.Ptr(functionTable)
			locIndex := uint32((lineMid - firstLine) / 8)
			lineTab := make([]byte, vms.beamCodeLineTab.sizeOf)
			err = i.rm.Read(lineTable, lineTab)
			if err != nil {
				return libpf.NullString, 0, fmt.Errorf("BEAM failed to read line table info")
			}
			locSize := npsr.Uint32(lineTab, uint(vms.beamCodeLineTab.locSize))
			locTab := npsr.Ptr(lineTab, uint(vms.beamCodeLineTab.locTab))
			locAddr := locTab + libpf.Address(locSize*locIndex)
			loc := uint64(0)
			if locSize == 2 {
				loc = uint64(i.rm.Uint16(locAddr))
			} else {
				loc = uint64(i.rm.Uint32(locAddr))
			}
			fnameIndex := loc >> 24
			fileNamePtr := i.rm.Ptr(lineTable) + libpf.Address(8*fnameIndex)
			fileName = i.readErlangString(i.rm.Ptr(fileNamePtr), 256)

			return fileName, loc & ((1 << 24) - 1), nil
		} else {
			lineLow = lineMid + 8
		}
	}

	// If the PC is beyond the last line-table entry, use the last valid entry as a best effort.
	var lastLinePtr libpf.Address
	if lineLow > functionEntryStart {
		lastLinePtr = lineLow - 8
	} else {
		lastLinePtr = functionEntryStart
	}

	locIndex := uint32((lastLinePtr - i.rm.Ptr(functionTable)) / 8)
	lineTab := make([]byte, vms.beamCodeLineTab.sizeOf)
	if err = i.rm.Read(lineTable, lineTab); err != nil {
		return libpf.NullString, 0, fmt.Errorf("BEAM failed to read line table info")
	}
	locSize := npsr.Uint32(lineTab, uint(vms.beamCodeLineTab.locSize))
	locTab := npsr.Ptr(lineTab, uint(vms.beamCodeLineTab.locTab))
	locAddr := locTab + libpf.Address(locSize*locIndex)

	loc := uint64(0)
	if locSize == 2 {
		loc = uint64(i.rm.Uint16(locAddr))
	} else {
		loc = uint64(i.rm.Uint32(locAddr))
	}
	fnameIndex := loc >> 24
	fileNamePtr := i.rm.Ptr(lineTable) + libpf.Address(8*fnameIndex)
	fileName = i.readErlangString(i.rm.Ptr(fileNamePtr), 256)

	return fileName, loc & ((1 << 24) - 1), nil
}

func (i *beamInstance) lookupAtom(index uint32) (libpf.String, error) {
	if value, ok := i.atomCache.Get(index); ok {
		return value, nil
	}

	vms := i.data.vmStructs
	readPtr := func(addr libpf.Address) (libpf.Address, error) {
		var buf [8]byte
		if err := i.rm.Read(addr, buf[:]); err != nil {
			return 0, fmt.Errorf("BEAM unable to read atom pointer at %#x for index %d: %w", addr, index, err)
		}
		return libpf.Address(binary.LittleEndian.Uint64(buf[:])) - i.rm.Bias, nil
	}

	segTable, err := readPtr(i.atomTable + libpf.Address(vms.indexTable.segTable))
	if err != nil {
		return libpf.NullString, err
	}
	segment, err := readPtr(segTable + libpf.Address(8*(index>>16)))
	if err != nil {
		return libpf.NullString, err
	}
	entry, err := readPtr(segment + libpf.Address(8*((index>>6)&0x3FF)))
	if err != nil {
		return libpf.NullString, err
	}

	var length [2]byte
	if err := i.rm.Read(entry+libpf.Address(vms.atom.len), length[:]); err != nil {
		return libpf.NullString, fmt.Errorf("BEAM unable to read atom length for index %d: %w", index, err)
	}
	len := binary.LittleEndian.Uint16(length[:])

	name := make([]byte, len)
	switch i.data.otpRelease {
	case 28:
		// Implementation based on https://github.com/erlang/otp/blob/OTP-28.0.2/erts/etc/unix/etp-commands.in#L657-L674
		unboxed, err := readPtr(entry + libpf.Address(vms.atom.u.bin))
		if err != nil {
			return libpf.NullString, err
		}
		unboxed &= libpf.Address(i.data.etpPtrMask)

		subtag := i.rm.Uint64(unboxed) & uint64(i.data.etpHeaderSubtagMask)
		if subtag == uint64(i.data.etpHeapBitsSubtag) {
			err := i.rm.Read(unboxed+libpf.Address(vms.erlHeapBits.data), name)
			if err != nil {
				return libpf.NullString, fmt.Errorf("BEAM Unable to lookup atom with index %d (ErlHeapBits tag): %v", index, err)
			}
		} else {
			return libpf.NullString, fmt.Errorf("BEAM Unable to lookup atom with index %d: expected boxed value subtag 0x%x, found 0x%x", index, i.data.etpHeapBitsSubtag, subtag)
		}
	default:
		namePtr, err := readPtr(entry + libpf.Address(vms.atom.name))
		if err != nil {
			return libpf.NullString, err
		}
		err = i.rm.Read(namePtr, name)
		if err != nil {
			return libpf.NullString, fmt.Errorf("BEAM Unable to lookup atom with index %d: %v", index, err)
		}
	}

	nameString := libpf.Intern(pfunsafe.ToString(name))
	i.atomCache.Add(index, nameString)
	return nameString, nil
}

func (i *beamInstance) readErlangString(eterm libpf.Address, maxLength uint64) libpf.String {
	if value, ok := i.stringCache.Get(eterm); ok {
		return value
	}

	result := strings.Builder{}
	length := uint64(0)

	// TODO: Get this exported if possible in erl_etp.c
	// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/etc/unix/etp-commands.in#L5326
	etp_nil := libpf.Address(0x3B)

	for eterm != etp_nil && length < maxLength {
		charAddr := eterm & libpf.Address(i.data.etpPtrMask)
		charValue := i.rm.Uint64(charAddr)
		char := uint8(charValue >> 4)
		result.WriteByte(char)
		length++
		nextAddr := libpf.Address((eterm & libpf.Address(i.data.etpPtrMask)) + 8)
		eterm = libpf.Address(i.rm.Uint64(nextAddr))
	}

	if length > maxLength {
		result.WriteString("...")
	}

	value := libpf.Intern(result.String())
	i.stringCache.Add(eterm, value)

	return value
}
