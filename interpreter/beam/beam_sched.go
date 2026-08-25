// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package beam // import "go.opentelemetry.io/ebpf-profiler/interpreter/beam"

// Per-sample Erlang process attribution (Discord addition).
//
// This is the user-space half of the erlang_pid_key label. It answers three
// questions for one BEAM process, once, at attach time:
//
//  1. which kernel tids are scheduler threads (from /proc/<pid>/task/*/comm),
//  2. where each of those threads' ErtsSchedulerData lives, and
//  3. where current_process sits inside it.
//
// The answers go into the beam_sched_tids eBPF map, and support/ebpf/
// beam_sched.h then does nothing but two pointer reads and a tag check on the
// sampling path. Keeping all version knowledge here is deliberate: the eBPF
// side has no way to fail safely, so it must never be given a choice.
//
// Nothing here is allowed to be fatal. The label is an enrichment; if any step
// is not certain, the feature is disabled for that process and BEAM unwinding
// carries on unchanged.

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/support"
)

const (
	// ertsCacheLineSize is the granularity of ERTS_ALC_CACHE_LINE_ALIGN_SIZE,
	// which is what makes ErtsAlignedSchedulerData's size a multiple of 64 and
	// therefore what makes the stride probe below a 64-step search rather than
	// a byte-by-byte one.
	// https://github.com/erlang/otp/blob/OTP-25.3.2.7/erts/emulator/beam/erl_alloc.h
	ertsCacheLineSize = 64

	// maxAlignedStride bounds the stride probe. sizeof(ErtsSchedulerData) is
	// dominated by ErtsAuxWorkData and ErtsAtomCacheMap and measured at 41728
	// bytes on OTP 25.3.2.7 (nix, x86_64); 256 KiB leaves a wide margin for
	// other builds. The probe cannot stop at the first match (acceptance
	// requires uniqueness), so this is 4096 candidates every time, each
	// normally costing one 8-byte read. Paid once per BEAM process, for the
	// normal array only -- the dirty array is a single verification pass at
	// the stride this measured -- and under the ProcessManager write lock.
	maxAlignedStride = 1 << 18

	// maxSchedulersPerVM sanity-bounds erts_no_schedulers before it is used as
	// a loop count against a remote address. It is also the eBPF map's size,
	// so a VM above it could not be fully represented anyway.
	maxSchedulersPerVM = 4096

	// tagImmed1Mask / tagImmed1Pid select an internal pid Eterm:
	// (term & _TAG_IMMED1_MASK) == _TAG_IMMED1_PID.
	// https://github.com/erlang/otp/blob/OTP-25.3.2.7/erts/emulator/beam/erl_term.h
	tagImmed1Mask = 0xF
	tagImmed1Pid  = 0x3

	// procFSRoot is /proc. Overridden only by tests, which pass their own root
	// to scanSchedulerThreads directly.
	procFSRoot = "/proc"

	// strideUndetermined is what probeAlignedStride reports for a
	// single-scheduler VM: there is no second element to measure a stride
	// against, and none is needed because only esdp[0] is ever addressed.
	// Multiplying it by (num-1) == 0 yields the base either way, so it is a
	// truthful "not measured" rather than a plausible-looking guess.
	strideUndetermined = 0
)

// schedKind says what sort of scheduler thread a comm names. Only normal and
// dirty-CPU schedulers are attributed: dirty-IO threads are blocked in
// syscalls by construction, so a CPU sample on one is not "running Erlang".
type schedKind uint8

const (
	schedKindNone schedKind = iota
	schedKindNormal
	schedKindDirtyCPU
)

// schedThread is one BEAM scheduler thread: its kernel tid and its 1-based
// index into the matching erts_aligned_*_scheduler_data array.
type schedThread struct {
	tid  uint32
	kind schedKind
	num  uint32
}

// schedOffsets are the ErtsSchedulerData field offsets the sampling path
// needs, per OTP major release.
type schedOffsets struct {
	// currentProcess is offsetof(ErtsSchedulerData, current_process).
	currentProcess uint32
	// schedNo is offsetof(ErtsSchedulerData, no): the normal-scheduler
	// tripwire, 1-based.
	schedNo uint32
	// dirtySchedNo is offsetof(ErtsSchedulerData, dirty_no): the dirty-CPU
	// tripwire, 1-based, with `no` zero on those schedulers.
	dirtySchedNo uint32
}

// forKind returns (numOff, zeroOff): the field that holds the 1-based array
// index for kind, and the companion field that init_scheduler_data explicitly
// zeroes for it -- schedNo/dirtySchedNo for normal, swapped for dirty-CPU. See
// checkSchedArray for the invariant this feeds.
func (o schedOffsets) forKind(kind schedKind) (numOff, zeroOff uint32) {
	if kind == schedKindDirtyCPU {
		return o.dirtySchedNo, o.schedNo
	}
	return o.schedNo, o.dirtySchedNo
}

// schedOffsetsByOTP is hand-derived from erts/emulator/beam/erl_process.h at
// the tags the rest of this interpreter already cites, and confirmed
// empirically on OTP 25 (see TestBeamSchedLiveAttach).
//
// The prefix of struct ErtsSchedulerData_ is byte-identical at OTP-25.3.2.7,
// OTP-26.2.5.9, OTP-27.3.4.6 and OTP-28.0.2:
//
//	ErtsSchedulerRegisters *registers;      //   0  (8)
//	ErtsTimerWheel *timer_wheel;            //   8  (8)
//	ErtsNextTimeoutRef next_tmo_ref;        //  16  (8)  ErtsMonotonicTime*
//	ErtsHLTimerService *timer_service;      //  24  (8)
//	ethr_tid tid;                           //  32  (8)  pthread_t
//	void *match_pseudo_process;             //  40  (8)
//	Process *free_process;                  //  48  (8)
//	ErtsThrPrgrData thr_progress_data;      //  56  (104)
//	ErtsSchedulerSleepInfo *ssi;            // 160  (8)
//	Process *current_process;               // 168  (8)
//	ErtsSchedType type;                     // 176  (4) + 4 pad
//	Uint no;                                // 184  (8)
//	Uint dirty_no;                          // 192  (8)
//
// ErtsThrPrgrData is 104 bytes on LP64 release builds (its only conditional
// member, is_delaying, is behind ERTS_ENABLE_LOCK_CHECK, a debug build
// option); it is identical at all four tags.
// erts/emulator/beam/erl_thr_progress.h
//
// This table deliberately does NOT carry sizeof(ErtsAlignedSchedulerData). It
// is not hand-derivable with the same confidence -- it depends on
// ErtsAuxWorkData, ErtsAtomCacheMap and several build-time macros -- so the
// stride is measured against the live VM instead, by probeAlignedStride.
var schedOffsetsByOTP = map[uint8]schedOffsets{
	// OTP-25.3.2.7 erts/emulator/beam/erl_process.h L682-L695
	25: {currentProcess: 168, schedNo: 184, dirtySchedNo: 192},
	// OTP-26.2.5.9 erts/emulator/beam/erl_process.h (identical prefix)
	26: {currentProcess: 168, schedNo: 184, dirtySchedNo: 192},
	// OTP-27.3.4.6 erts/emulator/beam/erl_process.h (identical prefix)
	27: {currentProcess: 168, schedNo: 184, dirtySchedNo: 192},
	// OTP-28.0.2 erts/emulator/beam/erl_process.h (identical prefix)
	28: {currentProcess: 168, schedNo: 184, dirtySchedNo: 192},
}

func lookupSchedOffsets(otpRelease uint8) (schedOffsets, bool) {
	offs, ok := schedOffsetsByOTP[otpRelease]
	return offs, ok
}

// isInternalPidTerm reports whether an Eterm is a live internal pid. A null
// or wrongly tagged word means the scheduler was between processes or the read
// caught a dispatch in flight; either way there is no label.
func isInternalPidTerm(term uint64) bool {
	return term != 0 && term&tagImmed1Mask == tagImmed1Pid
}

// schedSymbols are the emulator symbols the feature needs. All four are
// present in an unstripped beam.smp's .symtab; a stripped one simply does not
// get the feature.
type schedSymbols struct {
	// normalBase and dirtyCPUBase hold the ADDRESSES OF the pointer variables
	// erts_aligned_scheduler_data and erts_aligned_dirty_cpu_scheduler_data,
	// not the arrays: both are allocated at VM start and the globals are
	// pointers to them.
	normalBase    libpf.Address
	dirtyCPUBase  libpf.Address
	noSchedulers  libpf.Address
	noDirtyCPUSch libpf.Address
}

func (s schedSymbols) normalUsable() bool {
	return s.normalBase != 0 && s.noSchedulers != 0
}

func (s schedSymbols) dirtyUsable() bool {
	return s.dirtyCPUBase != 0 && s.noDirtyCPUSch != 0
}

// resolvedSymbols bundles every symbol beam.go's Loader needs out of
// beam.smp's .symtab: the "r" range-table symbol (see beam.go) plus the four
// scheduler symbols below. Resolving them together lets resolveSymbols make
// a single VisitSymbols pass instead of two.
type resolvedSymbols struct {
	r      libpf.Symbol
	rFound bool
	sched  schedSymbols
}

// resolveSymbols walks .symtab ONCE for "r" (or its LTO-renamed form,
// "r.llvm.<hash>") and the four scheduler symbols, early-exiting as soon as
// all five have been found. VisitSymbols reads and string-resolves the whole
// symbol table per call, and this runs under the process-manager write lock,
// so a single pass matters for attach-time latency.
func resolveSymbols(ef *pfelf.File) resolvedSymbols {
	var out resolvedSymbols
	const wanted = 5
	found := 0
	// found must count DISTINCT symbols RESOLVED, not matches: the four sched
	// cases are guarded on "slot still zero", which stays true when a matched
	// .symtab entry's address is genuinely 0 (an undefined or weak entry), so
	// counting matches would let duplicate entries for such a name drive found
	// to wanted with only four names resolved -- ending the pass early and
	// possibly before "r" is seen, which is fatal (no r, no BEAM interpreter)
	// rather than merely a lost enrichment label. The zero-valued slot IS the
	// not-yet-resolved bit, so setSched only bumps found on the zero ->
	// non-zero transition: duplicate names resolve FIRST-NON-ZERO-wins, chosen
	// deliberately over first-wins (which would latch a useless 0 and stop
	// looking) and over last-wins (which would let a later undefined entry
	// undo a good address).
	setSched := func(dst *libpf.Address, addr libpf.SymbolValue) {
		if addr == 0 {
			return
		}
		*dst = libpf.Address(addr)
		found++
	}
	_ = ef.VisitSymbols(func(sym libpf.Symbol) bool {
		switch {
		case !out.rFound && (sym.Name == "r" || strings.HasPrefix(string(sym.Name), "r.llvm.")):
			out.r = sym
			out.rFound = true
			found++
		case sym.Name == "erts_aligned_scheduler_data" && out.sched.normalBase == 0:
			setSched(&out.sched.normalBase, sym.Address)
		case sym.Name == "erts_aligned_dirty_cpu_scheduler_data" && out.sched.dirtyCPUBase == 0:
			setSched(&out.sched.dirtyCPUBase, sym.Address)
		case sym.Name == "erts_no_schedulers" && out.sched.noSchedulers == 0:
			setSched(&out.sched.noSchedulers, sym.Address)
		case sym.Name == "erts_no_dirty_cpu_schedulers" && out.sched.noDirtyCPUSch == 0:
			setSched(&out.sched.noDirtyCPUSch, sym.Address)
		}
		return found < wanted
	})
	return out
}

// parseSchedComm classifies a thread comm.
//
// The emulator names its threads "<N>_scheduler", "<N>_dirty_cpu_scheduler"
// and "<N>_dirty_io_scheduler" (erl_process.c, erts_snprintf(opts.name, ...)),
// and Linux truncates comm to TASK_COMM_LEN-1 = 15 bytes. Observed on OTP
// 25.3.2.7 / erts-13.2.2.4, x86_64, `erl +S 4:4 +SDcpu 2:2`:
//
//	1_scheduler  2_scheduler  3_scheduler  4_scheduler
//	1_dirty_cpu_sch  2_dirty_cpu_sch
//	1_dirty_io_sche  ...  10_dirty_io_sch
//	1_aux  0_poller  async_1  sys_sig_dispatc  beam.smp
//
// So the dirty names arrive truncated and must be matched as a prefix, while
// the normal ones do not (they only truncate above 99999 schedulers, which
// this rejects rather than guesses about). The prefix must be long enough to
// separate "dirty_cpu" from "dirty_io" -- mistaking one for the other would
// index the wrong half of a shared allocation.
func parseSchedComm(comm string) (schedKind, uint32) {
	const (
		normalSuffix      = "scheduler"
		dirtyCPUSuffix    = "dirty_cpu_scheduler"
		dirtyCPUMinPrefix = len("dirty_c")
	)

	sep := strings.IndexByte(comm, '_')
	if sep <= 0 {
		return schedKindNone, 0
	}
	num, err := strconv.ParseUint(comm[:sep], 10, 32)
	if err != nil || num == 0 {
		// Scheduler numbers are 1-based; 0 is a different kind of thread
		// (e.g. "0_poller").
		return schedKindNone, 0
	}

	switch rest := comm[sep+1:]; {
	case rest == normalSuffix:
		return schedKindNormal, uint32(num)
	case len(rest) >= dirtyCPUMinPrefix && strings.HasPrefix(dirtyCPUSuffix, rest):
		return schedKindDirtyCPU, uint32(num)
	}
	return schedKindNone, 0
}

// scanSchedulerThreads lists the BEAM scheduler threads of one process.
//
// Scheduler threads are created during VM startup, before any Erlang code (let
// alone a NIF) runs, and are never added or removed at runtime, so one scan at
// attach is complete. procRoot is "/proc" outside tests.
//
// Known limitation (documented, not implemented): this scan runs exactly once,
// at attach, and is never repeated. If attach lands while the VM is still in
// the middle of creating its scheduler threads, threads that appear after the
// scan never get a beam_sched_tids entry, and because this call still returns
// at least one thread, enableSchedAttribution's zero-threads warning does not
// fire either -- attribution is silently partial for that process (missing
// labels on the late threads, never wrong ones on any thread). If this ever
// matters in practice, the fix is a re-scan (e.g. triggered off
// SynchronizeMappings), not a change here.
func scanSchedulerThreads(procRoot string, pid libpf.PID) []schedThread {
	taskDir := filepath.Join(procRoot, strconv.Itoa(int(pid)), "task")
	entries, err := os.ReadDir(taskDir)
	if err != nil {
		return nil
	}
	out := make([]schedThread, 0, len(entries))
	for _, e := range entries {
		tid, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(taskDir, e.Name(), "comm"))
		if err != nil {
			// The thread exited between ReadDir and here.
			continue
		}
		kind, num := parseSchedComm(strings.TrimSpace(string(raw)))
		if kind == schedKindNone {
			continue
		}
		out = append(out, schedThread{tid: uint32(tid), kind: kind, num: num})
	}
	return out
}

// checkSchedArray verifies the init_scheduler_data invariant over elements
// [from, n) of a scheduler array laid out at the given stride.
//
// The invariant is set at VM start and never changes (erl_process.c
// init_scheduler_data, called as init_scheduler_data(esdp, ix+1, ...) for
// every ix, OTP-25.3.2.7 L5912-L5934). It gives TWO constraints per element,
// not one -- whichever of the two number fields is the index, the other is
// explicitly zeroed:
//
//	normal     esdp[i]:  .no == i+1        AND  .dirty_no == 0  (L5931-L5932)
//	dirty-CPU  esdp[i]:  .dirty_no == i+1  AND  .no == 0        (L5913, L5920)
//
// Both are checked for both arrays. Leaning on the index field alone would
// leave a 2-element array resting on a single predicate ("some 64-aligned word
// equals 2"), asked of hundreds of words inside element 0's own struct, where
// a small integer 2 is entirely plausible.
//
// A failed remote read yields 0 from rm, which fails the index comparison.
// That is the intended direction: unreadable means disabled.
func checkSchedArray(rm remotememory.RemoteMemory, base libpf.Address, from, n, stride uint32,
	offs schedOffsets, kind schedKind) error {
	num, zero := offs.forKind(kind)
	numOff, zeroOff := libpf.Address(num), libpf.Address(zero)
	for i := from; i < n; i++ {
		esdp := base + libpf.Address(i*stride)
		if got := rm.Uint64(esdp + numOff); got != uint64(i)+1 {
			return fmt.Errorf("element %d: index field is %d, want %d", i, got, i+1)
		}
		if got := rm.Uint64(esdp + zeroOff); got != 0 {
			return fmt.Errorf("element %d: companion number field is %d, want 0", i, got)
		}
	}
	return nil
}

// probeAlignedStride measures sizeof(ErtsAlignedSchedulerData) against a live
// VM, and is the tripwire that gates the whole feature.
//
// It walks 64-byte-aligned candidate strides (ERTS_ALC_CACHE_LINE_ALIGN_SIZE)
// and requires checkSchedArray to hold across the whole array. Acceptance
// requires UNIQUENESS: the entire candidate range is scanned and the result is
// accepted only if exactly one stride satisfies the invariant. Two matches is
// a clean disable, not a coin flip.
//
// Uniqueness cannot reject the true stride S *of a homogeneous array*: any
// multiple k*S reads element k*i at index i, whose index field is k*i+1, which
// differs from i+1 for every i >= 1. A second match can then only be an
// unrelated coincidence -- which is exactly the thing that must not be
// silently resolved in favour of a guess.
//
// "Homogeneous" is load-bearing and is why callers must only run this against
// erts_aligned_scheduler_data. See dirtyArrayAliasing below.
//
// n == 1 carries no discriminating information, but also needs none: only
// element 0 is ever addressed, and it is still checked against both
// constraints.
func probeAlignedStride(rm remotememory.RemoteMemory, base libpf.Address, n uint32,
	offs schedOffsets, kind schedKind) (uint32, error) {
	if base == 0 {
		return 0, fmt.Errorf("scheduler data array is NULL")
	}
	if n == 0 || n > maxSchedulersPerVM {
		return 0, fmt.Errorf("implausible scheduler count %d", n)
	}

	// Element 0 sits at the base whatever the stride is, so it discriminates
	// nothing between strides -- but it is the only check available when
	// n == 1, and a cheap early rejection of a wrong offsets table otherwise.
	if err := checkSchedArray(rm, base, 0, 1, 0, offs, kind); err != nil {
		return 0, fmt.Errorf("layout tripwire failed at the array base "+
			"(offsets: current_process=%d no=%d dirty_no=%d): %w",
			offs.currentProcess, offs.schedNo, offs.dirtySchedNo, err)
	}
	if n == 1 {
		return strideUndetermined, nil
	}

	found := uint32(0)
	for stride := uint32(ertsCacheLineSize); stride <= maxAlignedStride; stride += ertsCacheLineSize {
		if checkSchedArray(rm, base, 1, n, stride, offs, kind) != nil {
			continue
		}
		if found != 0 {
			return 0, fmt.Errorf("ambiguous scheduler array stride: both %d "+
				"and %d satisfy the layout tripwire for %d schedulers",
				found, stride, n)
		}
		found = stride
	}
	if found == 0 {
		return 0, fmt.Errorf("no aligned stride up to %d satisfies the layout "+
			"tripwire for %d schedulers", maxAlignedStride, n)
	}
	return found, nil
}

// verifyDirtyCPUArray tripwires the dirty-CPU array at a stride measured
// elsewhere, because the dirty array must NOT be probed on its own.
//
// erts_aligned_scheduler_data is exactly erts_no_schedulers elements indexed
// 1..n with no gaps -- homogeneous, so probeAlignedStride's uniqueness
// argument holds there. The dirty arrays are not: both live in ONE allocation
// of (no_dirty_cpu + no_dirty_io) elements, with
//
//	erts_aligned_dirty_io_scheduler_data = &erts_aligned_dirty_cpu_scheduler_data[no_dirty_cpu]
//
// (erl_process.c L6193-L6212 @OTP-25.3.2.7), and the IO half RESTARTS
// dirty_no at 1. Probing the dirty-CPU array therefore has a SYSTEMATIC false
// match at k = no_dirty_cpu + 1: element k is dirty_io[1], whose dirty_no is 2
// and whose no is 0 -- indistinguishable from dirty_cpu[1] by any local test.
// Observed on a real VM at `+SDcpu 2:2` (10 dirty-IO schedulers by default):
// strides 41728 and 125184 == 3*41728 both satisfied the invariant, and the
// uniqueness rule correctly refused to choose.
//
// Both arrays are the same struct, so the stride measured on the homogeneous
// array is authoritative for this one. The dirty array still gets a full
// tripwire, just at a known stride rather than a searched one.
func verifyDirtyCPUArray(rm remotememory.RemoteMemory, base libpf.Address, n, normalStride uint32,
	offs schedOffsets) error {
	if base == 0 {
		return fmt.Errorf("dirty-CPU scheduler data array is NULL")
	}
	if n > maxSchedulersPerVM {
		return fmt.Errorf("implausible dirty-CPU scheduler count %d", n)
	}
	if n > 1 && normalStride == strideUndetermined {
		// A single-scheduler VM leaves nothing to measure the stride against,
		// and guessing one for the dirty array is exactly what this whole
		// mechanism exists to avoid.
		return fmt.Errorf("no stride available: the normal array has only one scheduler")
	}
	return checkSchedArray(rm, base, 0, n, normalStride, offs, schedKindDirtyCPU)
}

// schedArray is one validated erts_aligned_*_scheduler_data array.
type schedArray struct {
	base   libpf.Address
	n      uint32
	stride uint32
	ok     bool
}

// clampSchedCount narrows a scheduler count read out of the VM without
// wrapping: an implausible value must stay implausible so probeAlignedStride
// rejects it, rather than truncating into a plausible one.
func clampSchedCount(n uint64) uint32 {
	if n > maxSchedulersPerVM {
		return maxSchedulersPerVM + 1
	}
	return uint32(n)
}

// warnSchedUnsupportedOnce logs, at most once per beamData, that per-sample
// process attribution is disabled for a reason that holds for every process
// using this ELF (a missing offsets table or missing symbols) rather than for
// one process in particular.
func (d *beamData) warnSchedUnsupportedOnce(format string, args ...any) {
	d.schedUnsupportedOnce.Do(func() {
		log.Warnf("BEAM per-sample process attribution disabled: "+format, args...)
	})
}

// enableSchedAttribution populates beam_sched_tids for one BEAM process and
// returns the tids it wrote, for Detach to remove.
//
// Order matters: every tripwire runs to completion before the first map entry
// is written, so a wrong offsets table produces an empty map rather than a
// partially-populated one.
func (d *beamData) enableSchedAttribution(ebpf interpreter.EbpfHandler, pid libpf.PID,
	bias libpf.Address, rm remotememory.RemoteMemory) []libpf.PID {
	offs, ok := lookupSchedOffsets(d.otpRelease)
	if !ok {
		d.warnSchedUnsupportedOnce("no ErtsSchedulerData layout for OTP %d", d.otpRelease)
		return nil
	}
	if !d.schedSymbols.normalUsable() {
		d.warnSchedUnsupportedOnce("beam.smp is stripped of the scheduler symbols")
		return nil
	}

	// The scan below runs once, here, at attach. See its own comment for the
	// limitation that creates.
	threads := scanSchedulerThreads(procFSRoot, pid)
	if len(threads) == 0 {
		// A beam.smp with no recognisable scheduler threads should not happen
		// -- they exist before any Erlang code runs -- so this is a silent
		// loss of the feature for a VM that looks fully supported. Warn.
		log.Warnf("BEAM PID %d: no scheduler threads found in %s, per-sample "+
			"process attribution disabled", pid, procFSRoot)
		return nil
	}

	// Resolve and validate both arrays before touching the map. A dirty-CPU
	// failure disables only the dirty half: normal schedulers are where
	// virtually all Erlang execution happens, and they are validated
	// independently.
	var arrays [3]schedArray // indexed by schedKind

	normal := &arrays[schedKindNormal]
	normal.base = rm.Ptr(bias + d.schedSymbols.normalBase)
	normal.n = clampSchedCount(rm.Uint64(bias + d.schedSymbols.noSchedulers))
	stride, err := probeAlignedStride(rm, normal.base, normal.n, offs, schedKindNormal)
	if err != nil {
		log.Warnf("BEAM PID %d: per-sample process attribution disabled: %v", pid, err)
		return nil
	}
	normal.stride, normal.ok = stride, true

	if d.schedSymbols.dirtyUsable() {
		dirty := &arrays[schedKindDirtyCPU]
		dirty.base = rm.Ptr(bias + d.schedSymbols.dirtyCPUBase)
		dirty.n = clampSchedCount(rm.Uint64(bias + d.schedSymbols.noDirtyCPUSch))
		// dirty.n == 0 is a runtime built without dirty scheduler support:
		// not a failure, and there are no dirty threads to map either.
		if dirty.n > 0 {
			// Verified at the normal array's stride, never probed on its own
			// -- see verifyDirtyCPUArray for the aliasing that makes an
			// independent probe unsound.
			if derr := verifyDirtyCPUArray(rm, dirty.base, dirty.n, normal.stride,
				offs); derr != nil {
				log.Warnf("BEAM PID %d: dirty-CPU scheduler attribution disabled "+
					"(normal schedulers unaffected): %v", pid, derr)
			} else {
				dirty.stride, dirty.ok = normal.stride, true
			}
		}
	}

	written := make([]libpf.PID, 0, len(threads))
	for _, th := range threads {
		arr := &arrays[th.kind]
		if !arr.ok || th.num > arr.n {
			continue
		}
		info := beamSchedInfoFor(arr, offs, th.num, pid)
		if err := ebpf.UpdateBeamSchedTid(libpf.PID(th.tid), info); err != nil {
			log.Warnf("BEAM PID %d: failed to map scheduler tid %d: %v", pid, th.tid, err)
			continue
		}
		written = append(written, libpf.PID(th.tid))
	}
	if log.DebugEnabled() {
		// Gated: countRunningProcesses is 2n remote reads, and Debugf's
		// arguments are evaluated whether or not the level is on.
		log.Debugf("BEAM PID %d: per-sample process attribution enabled for "+
			"%d/%d scheduler threads (stride %d, %d/%d normal schedulers "+
			"currently on a pid-tagged process)", pid, len(written),
			len(threads), normal.stride,
			countRunningProcesses(rm, normal, offs), normal.n)
	}
	return written
}

// beamSchedInfoFor builds the map value for one scheduler thread: the address
// of its ErtsSchedulerData, the offset the eBPF side reads from it, and the
// tgid the entry belongs to.
//
// The tgid is not decoration: see support/ebpf/beam_sched.h's identity
// section for why the map value must be bound to it.
//
// num is 1-based, so element num-1 is addressed; when the stride was not
// measured (single-scheduler VM) num is necessarily 1 and the product is zero.
func beamSchedInfoFor(arr *schedArray, offs schedOffsets, num uint32,
	tgid libpf.PID) support.BeamSchedInfo {
	return support.BeamSchedInfo{
		Esdp_addr:        uint64(arr.base) + uint64(num-1)*uint64(arr.stride),
		Off_current_proc: offs.currentProcess,
		Tgid:             uint32(tgid),
	}
}

// countRunningProcesses is diagnostics only: it applies the same two reads the
// eBPF side will make and counts how many land on a properly tagged pid. It
// cannot gate anything -- an idle VM legitimately has every current_process
// null -- but on a busy one a zero here in the log is the signature of a
// currentProcess offset that passed the tripwire by coincidence.
func countRunningProcesses(rm remotememory.RemoteMemory, arr *schedArray,
	offs schedOffsets) int {
	n := 0
	for i := uint32(0); i < arr.n; i++ {
		esdp := arr.base + libpf.Address(i*arr.stride)
		proc := rm.Ptr(esdp + libpf.Address(offs.currentProcess))
		if proc != 0 && isInternalPidTerm(rm.Uint64(proc)) {
			n++
		}
	}
	return n
}

// disableSchedAttribution removes this process's scheduler tids from
// beam_sched_tids, conditioned on tgid: see support/ebpf/beam_sched.h's
// identity section for why the delete cannot be unconditional.
func disableSchedAttribution(ebpf interpreter.EbpfHandler, tids []libpf.PID, tgid libpf.PID) {
	for _, tid := range tids {
		if err := ebpf.DeleteBeamSchedTid(tid, tgid); err != nil {
			log.Debugf("BEAM: failed to unmap scheduler tid %d: %v", tid, err)
		}
	}
}
