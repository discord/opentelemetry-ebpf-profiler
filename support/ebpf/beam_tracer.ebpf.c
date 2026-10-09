#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

// The number of frames to unwind per frame-unwinding eBPF program.
#define BEAM_FRAMES_PER_PROGRAM 8

// The max number of loops to unroll when searching for the correct CodeHeader.
// Should be log base 2 of a reasonable number of modules to binary-search through.
#define BEAM_CODE_HEADER_SEARCH_ITERATIONS 16

// The maximum number of reads to perform when scanning for a continuation pointer. Read the
// stack in smaller chunks so the temporary buffer does not consume the eBPF program's entire
// stack.
#define BEAM_STACK_FRAME_SCAN_ITERATIONS     32
#define BEAM_STACK_FRAME_SCAN_WORDS_PER_READ 16

struct beam_procs_t {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u32);
  __type(value, BEAMProcInfo);
  __uint(max_entries, 256);
} beam_procs SEC(".maps");

#if defined(__x86_64__)
struct beam_bif_processes_t {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, u64);
  __type(value, u64);
  __uint(max_entries, 65536);
} beam_bif_processes SEC(".maps");
#endif

// We assume this Range struct is stable so we can read it all at once directly.
// If it were to change in the future, we'd need to change the way this struct is read.
// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/beam_ranges.c#L31-L34
typedef struct BEAMRangeEntry {
  u64 start;
  u64 end;
} BEAMRangeEntry;

// We assume this ranges struct will at least have these two values as the first two fields.
// That allows us to directly read them efficiently at once, but it could break in in the future.
// https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/beam_ranges.c#L56-L61
typedef struct BEAMRangesInfo {
  u64 modules;
  u64 n;
} BEAMRangesInfo;

typedef struct BEAMRangesSearchCache {
  BEAMRangesInfo info;
  BEAMRangeEntry first, mid, last;
} BEAMRangesSearchCache;

static EBPF_INLINE ErrorCode
beam_check_range_snapshot(BEAMProcInfo *info, u32 index, BEAMRangesSearchCache *ranges)
{
  u32 current_index;
  BEAMRangesInfo current_info;
  if (
    bpf_probe_read_user(
      &current_index, sizeof(current_index), (void *)info->the_active_code_index) ||
    current_index != index) {
    return ERR_BEAM_RANGE_SNAPSHOT_CHANGED;
  }
  u64 active_ranges = info->r + (index * info->ranges_sizeof);
  if (
    bpf_probe_read_user(&current_info, sizeof(current_info), (void *)active_ranges) ||
    current_info.modules != ranges->info.modules || current_info.n != ranges->info.n) {
    return ERR_BEAM_RANGE_SNAPSHOT_CHANGED;
  }
  return ERR_OK;
}

#if defined(__x86_64__)
typedef enum BEAMFPTransition {
  BEAM_FP_ESTABLISHED,
  BEAM_FP_BEFORE_PUSH,
  BEAM_FP_AFTER_PUSH,
  BEAM_FP_UNREADABLE,
} BEAMFPTransition;

// OTP 25 emits push rbp; mov rbp,rsp at entry and leave at exits. Perf can
// sample between these instructions, while RBP still describes the caller.
// Examine only the live leaf: saved return addresses are never sampled PCs.
static EBPF_INLINE BEAMFPTransition beam_fp_transition(UnwindState *state, BEAMRangeEntry *range)
{
  if (state->return_address) {
    return BEAM_FP_ESTABLISHED;
  }

  u64 pc = state->pc;
  u32 insn;
  if (bpf_probe_read_user(&insn, sizeof(insn), (void *)pc)) {
    return BEAM_FP_UNREADABLE;
  }

  // At the push itself, or at the mov immediately after it.
  if (insn == 0xe5894855) {
    return BEAM_FP_BEFORE_PUSH;
  }
  if (pc > range->start) {
    u32 entry;
    if (bpf_probe_read_user(&entry, sizeof(entry), (void *)(pc - 1))) {
      return BEAM_FP_UNREADABLE;
    }
    if (entry == 0xe5894855) {
      return BEAM_FP_AFTER_PUSH;
    }
  }

  // Code-info's jump to the function entry runs before the push. Accept
  // short and near jumps only if their target starts with the FP prologue.
  u64 target = 0;
  if ((insn & 0xff) == 0xeb) {
    target = pc + 2 + (s8)((insn >> 8) & 0xff);
  } else if ((insn & 0xff) == 0xe9) {
    s32 rel;
    if (bpf_probe_read_user(&rel, sizeof(rel), (void *)(pc + 1))) {
      return BEAM_FP_UNREADABLE;
    }
    target = pc + 5 + rel;
  }
  if (target >= range->start && target < range->end && range->end - target >= 4) {
    u32 prologue;
    if (bpf_probe_read_user(&prologue, sizeof(prologue), (void *)target)) {
      return BEAM_FP_UNREADABLE;
    }
    if (prologue == 0xe5894855) {
      return BEAM_FP_BEFORE_PUSH;
    }
  }

  // Tail calls: leave; jmp. Normal returns: leave; dec r14; jl; ret.
  if (pc > range->start) {
    u8 previous;
    if (bpf_probe_read_user(&previous, sizeof(previous), (void *)(pc - 1))) {
      return BEAM_FP_UNREADABLE;
    }
    if (previous == 0xc9) {
      u8 op = insn & 0xff;
      if (op == 0xeb || op == 0xe9 || op == 0xff || op == 0xc3 || (insn & 0xffffff) == 0xceff49) {
        return BEAM_FP_BEFORE_PUSH;
      }
    }
  }
  if (pc >= range->start + 4 && (insn & 0xffff) == 0x8c0f) {
    u32 previous;
    if (bpf_probe_read_user(&previous, sizeof(previous), (void *)(pc - 4))) {
      return BEAM_FP_UNREADABLE;
    }
    if (previous == 0xceff49c9) {
      return BEAM_FP_BEFORE_PUSH;
    }
  }
  if (pc >= range->start + 10 && (insn & 0xff) == 0xc3) {
    u32 previous;
    u16 branch;
    if (
      bpf_probe_read_user(&previous, sizeof(previous), (void *)(pc - 10)) ||
      bpf_probe_read_user(&branch, sizeof(branch), (void *)(pc - 6))) {
      return BEAM_FP_UNREADABLE;
    }
    if (previous == 0xceff49c9 && branch == 0x8c0f) {
      return BEAM_FP_BEFORE_PUSH;
    }
  }
  return BEAM_FP_ESTABLISHED;
}

static EBPF_INLINE bool beam_unwind_fp_transition(UnwindState *state, BEAMFPTransition transition)
{
  u64 slot    = state->sp + (transition == BEAM_FP_AFTER_PUSH ? 8 : 0);
  u64 next_sp = slot + 8;
  u64 caller_pc;
  if (
    slot < state->sp || next_sp < slot || state->fp < next_sp || state->fp - next_sp > (1 << 20) ||
    bpf_probe_read_user(&caller_pc, sizeof(caller_pc), (void *)slot) || caller_pc == 0) {
    return false;
  }
  state->sp       = next_sp;
  state->fp_bound = next_sp;
  state->pc       = caller_pc;
  unwinder_mark_nonleaf_frame(state);
  return true;
}
#endif

static EBPF_INLINE ErrorCode push_beam(UnwindState *state, Trace *trace, u64 range_start)
{
  const u8 ra_flag = state->return_address ? FRAME_FLAG_RETURN_ADDRESS : 0;

  // `pc` is in the `current_range` CodeHeader
  u64 *data = push_frame(state, trace, FRAME_MARKER_BEAM, ra_flag, state->pc, 1);
  if (!data) {
    return false;
  }
  data[0] = range_start;
  return true;
}

#if defined(__x86_64__)
static EBPF_INLINE ErrorCode
beam_unwind_heavy_bif(PerCPURecord *record, BEAMProcInfo *info, BEAMRangesSearchCache *ranges)
{
  UnwindState *state = &record->state;
  DEBUG_PRINT("beam: heavy BIF boundary at 0x%llx", state->pc);
  if (
    !state->return_address || !info->process_stop_offset || !info->process_frame_pointer_offset ||
    !info->process_scheduler_data_offset || !info->scheduler_current_process_offset) {
    return ERR_BEAM_NATIVE_BOUNDARY_INVALID;
  }

  u64 id           = ((u64)record->trace.pid << 32) | record->trace.tid;
  u64 *process_ptr = bpf_map_lookup_elem(&beam_bif_processes, &id);
  if (!process_ptr || !*process_ptr) {
    return ERR_BEAM_NATIVE_BOUNDARY_INVALID;
  }
  u64 process = *process_ptr;
  u64 scheduler, active_process, scheduler_again, active_process_again;
  if (
    bpf_probe_read_user(
      &scheduler, sizeof(scheduler), (void *)(process + info->process_scheduler_data_offset)) ||
    !scheduler ||
    bpf_probe_read_user(
      &active_process,
      sizeof(active_process),
      (void *)(scheduler + info->scheduler_current_process_offset)) ||
    active_process != process) {
    return ERR_BEAM_NATIVE_BOUNDARY_INVALID;
  }
  u64 current, instruction, stack[2], slots[2];
  u64 current_again, instruction_again, stack_again[2];
  u64 mfa[3];
  if (
    bpf_probe_read_user(stack, sizeof(stack), (void *)(process + info->process_stop_offset)) ||
    bpf_probe_read_user(
      &instruction, sizeof(instruction), (void *)(process + info->process_i_offset)) ||
    bpf_probe_read_user(
      &current, sizeof(current), (void *)(process + info->process_current_offset)) ||
    !current || bpf_probe_read_user(mfa, sizeof(mfa), (void *)current)) {
    return ERR_BEAM_NATIVE_BOUNDARY_INVALID;
  }

  u64 fp = stack[1];
  if (
    stack[0] != fp || fp == 0 || (fp & 7) || (mfa[0] & 0x3f) != 0xb || (mfa[1] & 0x3f) != 0xb ||
    mfa[2] > 255 || bpf_probe_read_user(slots, sizeof(slots), (void *)fp) || slots[0] <= fp ||
    slots[0] - fp < 16 || slots[0] - fp >= (1 << 20) || (slots[0] & 7) ||
    slots[1] < ranges->first.start || slots[1] >= ranges->last.end) {
    return ERR_BEAM_NATIVE_BOUNDARY_INVALID;
  }

  if (
    bpf_probe_read_user(
      stack_again, sizeof(stack_again), (void *)(process + info->process_stop_offset)) ||
    bpf_probe_read_user(
      &instruction_again, sizeof(instruction_again), (void *)(process + info->process_i_offset)) ||
    bpf_probe_read_user(
      &current_again, sizeof(current_again), (void *)(process + info->process_current_offset)) ||
    bpf_probe_read_user(
      &scheduler_again,
      sizeof(scheduler_again),
      (void *)(process + info->process_scheduler_data_offset)) ||
    bpf_probe_read_user(
      &active_process_again,
      sizeof(active_process_again),
      (void *)(scheduler + info->scheduler_current_process_offset)) ||
    stack_again[0] != stack[0] || stack_again[1] != fp || instruction_again != instruction ||
    current_again != current || scheduler_again != scheduler || active_process_again != process) {
    return ERR_BEAM_NATIVE_BOUNDARY_INVALID;
  }

  state->fp = fp;
  if (instruction >= info->bif_export_trap_start && instruction < info->bif_export_trap_end) {
    DEBUG_PRINT("beam: heavy BIF trap caller 0x%llx", slots[1]);
    return unwinder_unwind_frame_pointer_regs(state, slots) ? ERR_OK
                                                            : ERR_BEAM_NATIVE_BOUNDARY_INVALID;
  }
  if (instruction >= ranges->first.start && instruction < ranges->last.end) {
    DEBUG_PRINT("beam: heavy BIF module frame 0x%llx", instruction);
    state->sp             = fp;
    state->fp_bound       = fp;
    state->pc             = instruction;
    state->return_address = false;
    return ERR_OK;
  }
  return ERR_BEAM_NATIVE_BOUNDARY_INVALID;
}
#endif

#if defined(__x86_64__)
static EBPF_INLINE bool beam_resume_shared_frame(
  UnwindState *state, BEAMRangesSearchCache *ranges, u64 fragment_start, u64 fragment_end)
{
  if (!state->return_address) {
    BEAMRangeEntry fragment     = {.start = fragment_start, .end = fragment_end};
    BEAMFPTransition transition = beam_fp_transition(state, &fragment);
    if (transition == BEAM_FP_UNREADABLE) {
      return false;
    }
    if (transition != BEAM_FP_ESTABLISHED) {
      if (!beam_unwind_fp_transition(state, transition)) {
        return false;
      }
      return state->pc >= ranges->first.start && state->pc < ranges->last.end;
    }
  }
  if (state->fp == 0 || (state->fp & 7)) {
    DEBUG_PRINT(
      "beam: shared frame state pc=%llx fp=%llx ra=%d",
      state->pc,
      state->fp,
      state->return_address);
    return false;
  }
  u64 slots[2];
  if (bpf_probe_read_user(slots, sizeof(slots), (void *)state->fp)) {
    DEBUG_PRINT("beam: shared frame unreadable pc=%llx fp=%llx", state->pc, state->fp);
    return false;
  }
  if (
    slots[0] <= state->fp || slots[0] - state->fp < 16 || slots[0] - state->fp >= (1 << 20) ||
    (slots[0] & 7) || slots[1] < ranges->first.start || slots[1] >= ranges->last.end) {
    DEBUG_PRINT("beam: shared frame slots pc=%llx fp=%llx", state->pc, state->fp);
    DEBUG_PRINT("beam: shared frame next=%llx caller=%llx", slots[0], slots[1]);
    return false;
  }
  return unwinder_unwind_frame_pointer_regs(state, slots);
}
#endif

#if defined(__aarch64__)
static EBPF_INLINE bool
beam_arm_fragment_callsite(u64 caller, u64 fragment, BEAMRangesSearchCache *ranges)
{
  u32 call;
  if (
    caller < ranges->first.start || caller >= ranges->last.end || caller < sizeof(call) ||
    bpf_probe_read_user(&call, sizeof(call), (void *)(caller - sizeof(call))) ||
    (call & 0xfc000000) != 0x94000000) {
    return false;
  }

  s32 displacement = (s32)(call << 6) >> 6;
  u64 target       = caller - sizeof(call) + (s64)displacement * 4;
  if (target == fragment) {
    return true;
  }
  if (target < ranges->first.start || target >= ranges->last.end) {
    return false;
  }

  // Resolve a branch veneer and the x14 fragment stub.
  u32 instructions[5];
  if (bpf_probe_read_user(instructions, sizeof(instructions), (void *)target)) {
    return false;
  }
  if ((instructions[0] & 0xfc000000) == 0x14000000) {
    displacement = (s32)(instructions[0] << 6) >> 6;
    target += (s64)displacement * 4;
    if (
      target < ranges->first.start || target >= ranges->last.end ||
      bpf_probe_read_user(instructions, sizeof(instructions), (void *)target)) {
      return false;
    }
  }

  if ((instructions[0] & 0xff80001f) != 0xd280000e) {
    return false;
  }
  u32 shift    = (instructions[0] >> 21) & 3;
  u64 resolved = (u64)((instructions[0] >> 5) & 0xffff) << (shift * 16);
  u32 seen     = 1U << shift;
  #pragma unroll
  for (int i = 1; i < 5; i++) {
    u32 instruction = instructions[i];
    if (instruction == 0xd61f01c0) {
      return resolved == fragment;
    }
    if ((instruction & 0xff80001f) != 0xf280000e) {
      return false;
    }
    shift = (instruction >> 21) & 3;
    if (seen & (1U << shift)) {
      return false;
    }
    resolved |= (u64)((instruction >> 5) & 0xffff) << (shift * 16);
    seen |= 1U << shift;
  }
  return false;
}

static EBPF_INLINE void beam_arm_include_first_continuation(
  UnwindState *state, BEAMProcInfo *info, BEAMRangesSearchCache *ranges)
{
  u64 e = state->r20;
  u64 first;
  if (
    e >= sizeof(u64) && !(e & 7) && !bpf_probe_read_user(&first, sizeof(first), (void *)e) &&
    first != state->pc &&
    (first == info->beam_normal_exit ||
     (first >= ranges->first.start && first < ranges->last.end))) {
    state->r20 = e - sizeof(u64);
  }
}

static EBPF_INLINE bool
beam_arm_resume_lr(UnwindState *state, BEAMProcInfo *info, BEAMRangesSearchCache *ranges)
{
  u64 caller = state->lr;
  if (
    state->r20 < sizeof(u64) || (state->r20 & 7) ||
    (caller != info->beam_normal_exit &&
     (caller < ranges->first.start || caller >= ranges->last.end))) {
    return false;
  }
  state->r20 -= sizeof(u64);
  state->pc = caller;
  unwinder_mark_nonleaf_frame(state);
  return true;
}

static EBPF_INLINE bool
beam_resume_arm_shared_bif(UnwindState *state, BEAMProcInfo *info, BEAMRangesSearchCache *ranges)
{
  u64 fp = state->fp;
  u64 e  = state->r20;
  u64 slots[2];
  if (
    fp == 0 || fp != state->sp || (fp & 15) || e == 0 || (e & 7) ||
    bpf_probe_read_user(slots, sizeof(slots), (void *)fp)) {
    return false;
  }
  u64 caller = normalize_pac_ptr(slots[1]);
  if (
    slots[0] <= fp || slots[0] - fp < 16 || slots[0] - fp >= (1 << 20) || (slots[0] & 15) ||
    caller < ranges->first.start || caller >= ranges->last.end) {
    return false;
  }
  state->sp       = fp + 16;
  state->fp       = slots[0];
  state->fp_bound = fp + 16;
  state->pc       = caller;
  beam_arm_include_first_continuation(state, info, ranges);
  unwinder_mark_nonleaf_frame(state);
  return true;
}

static EBPF_INLINE bool beam_resume_arm_framed_bif(
  UnwindState *state, BEAMProcInfo *info, BEAMRangesSearchCache *ranges, u64 fragment_start)
{
  u64 pc = state->pc;
  if (state->return_address) {
    return beam_resume_arm_shared_bif(state, info, ranges);
  }
  if (state->r20 < sizeof(u64) || (state->r20 & 7)) {
    return false;
  }
  if (pc == fragment_start) {
    u32 instructions[2];
    if (
      !beam_arm_fragment_callsite(state->lr, fragment_start, ranges) ||
      bpf_probe_read_user(instructions, sizeof(instructions), (void *)pc) ||
      instructions[0] != 0xa9bf7bfd || instructions[1] != 0x910003fd) {
      return false;
    }
    state->pc = state->lr;
    beam_arm_include_first_continuation(state, info, ranges);
    unwinder_mark_nonleaf_frame(state);
    return true;
  }
  if (pc == fragment_start + 4) {
    u32 instructions[2];
    u64 slots[2], slots_again[2];
    u64 sp = state->sp;
    if (
      !sp || (sp & 15) ||
      bpf_probe_read_user(instructions, sizeof(instructions), (void *)fragment_start) ||
      instructions[0] != 0xa9bf7bfd || instructions[1] != 0x910003fd ||
      bpf_probe_read_user(slots, sizeof(slots), (void *)sp) || slots[0] != state->fp ||
      slots[0] < sp + 16 || slots[0] - sp >= (1 << 20) || (slots[0] & 15)) {
      return false;
    }
    u64 caller = normalize_pac_ptr(slots[1]);
    if (
      !beam_arm_fragment_callsite(caller, fragment_start, ranges) ||
      bpf_probe_read_user(slots_again, sizeof(slots_again), (void *)sp) ||
      slots_again[0] != slots[0] || slots_again[1] != slots[1]) {
      return false;
    }
    state->sp       = sp + 16;
    state->fp       = slots[0];
    state->fp_bound = sp + 16;
    state->pc       = caller;
  } else {
    u32 instruction;
    if (
      pc < fragment_start + 8 ||
      bpf_probe_read_user(&instruction, sizeof(instruction), (void *)pc) ||
      instruction != 0xd65f03c0) {
      return beam_resume_arm_shared_bif(state, info, ranges);
    }
    u32 instructions[3];
    u64 caller = normalize_pac_ptr(state->lr);
    if (
      (state->sp & 15) ||
      bpf_probe_read_user(instructions, sizeof(instructions), (void *)(pc - 8)) ||
      instructions[0] != 0x910003bf || instructions[1] != 0xa8c17bfd ||
      instructions[2] != 0xd65f03c0 ||
      !beam_arm_fragment_callsite(caller, fragment_start, ranges)) {
      return false;
    }
    state->pc = caller;
  }
  beam_arm_include_first_continuation(state, info, ranges);
  unwinder_mark_nonleaf_frame(state);
  return true;
}

static EBPF_INLINE ErrorCode
beam_resume_arm_heavy_bif(UnwindState *state, BEAMProcInfo *info, BEAMRangesSearchCache *ranges)
{
  if (
    !state->return_address || !info->process_stop_offset || !info->process_i_offset ||
    !info->process_current_offset || !info->process_scheduler_data_offset ||
    !info->scheduler_current_process_offset || !state->r21 || (state->r21 & 7)) {
    return ERR_BEAM_NATIVE_BOUNDARY_INVALID;
  }

  u64 process = state->r21;
  bool trap   = info->bif_export_trap_start != 0 && state->pc >= info->bif_export_trap_start &&
              state->pc < info->bif_export_trap_end;
  u64 stop, instruction, current, scheduler, active_process, first_caller;
  u64 stop_again, instruction_again, current_again, scheduler_again, active_process_again;
  u64 mfa[3];
  if (
    bpf_probe_read_user(&stop, sizeof(stop), (void *)(process + info->process_stop_offset)) ||
    bpf_probe_read_user(
      &instruction, sizeof(instruction), (void *)(process + info->process_i_offset)) ||
    bpf_probe_read_user(
      &current, sizeof(current), (void *)(process + info->process_current_offset)) ||
    bpf_probe_read_user(
      &scheduler, sizeof(scheduler), (void *)(process + info->process_scheduler_data_offset)) ||
    !scheduler || stop != state->r20 || stop < 8 || (stop & 7) ||
    (!trap && (instruction < ranges->first.start || instruction >= ranges->last.end) &&
     (instruction < info->bif_export_trap_start || instruction >= info->bif_export_trap_end)) ||
    bpf_probe_read_user(&first_caller, sizeof(first_caller), (void *)stop) ||
    first_caller < ranges->first.start || first_caller >= ranges->last.end || !current ||
    bpf_probe_read_user(mfa, sizeof(mfa), (void *)current) || (mfa[0] & 0x3f) != 0xb ||
    (mfa[1] & 0x3f) != 0xb || mfa[2] > 255 ||
    bpf_probe_read_user(
      &active_process,
      sizeof(active_process),
      (void *)(scheduler + info->scheduler_current_process_offset)) ||
    active_process != process) {
    return ERR_BEAM_NATIVE_BOUNDARY_INVALID;
  }

  if (
    bpf_probe_read_user(
      &stop_again, sizeof(stop_again), (void *)(process + info->process_stop_offset)) ||
    bpf_probe_read_user(
      &instruction_again, sizeof(instruction_again), (void *)(process + info->process_i_offset)) ||
    bpf_probe_read_user(
      &current_again, sizeof(current_again), (void *)(process + info->process_current_offset)) ||
    bpf_probe_read_user(
      &scheduler_again,
      sizeof(scheduler_again),
      (void *)(process + info->process_scheduler_data_offset)) ||
    bpf_probe_read_user(
      &active_process_again,
      sizeof(active_process_again),
      (void *)(scheduler + info->scheduler_current_process_offset)) ||
    stop_again != stop || instruction_again != instruction || current_again != current ||
    scheduler_again != scheduler || active_process_again != process) {
    return ERR_BEAM_NATIVE_BOUNDARY_INVALID;
  }

  if (
    trap || (info->bif_export_trap_start != 0 && instruction >= info->bif_export_trap_start &&
             instruction < info->bif_export_trap_end)) {
    state->pc  = first_caller;
    state->r20 = stop;
    unwinder_mark_nonleaf_frame(state);
  } else {
    state->pc             = instruction;
    state->r20            = stop - 8;
    state->return_address = false;
  }
  return ERR_OK;
}

static EBPF_INLINE ErrorCode
beam_resume_arm_nif(UnwindState *state, BEAMProcInfo *info, BEAMRangesSearchCache *ranges)
{
  if (
    !state->return_address || !info->process_stop_offset || !info->process_current_offset ||
    !info->process_scheduler_data_offset || !info->scheduler_current_process_offset ||
    !state->r21 || (state->r21 & 7)) {
    return ERR_BEAM_CALL_NIF_BOUNDARY_INVALID;
  }

  u64 process = state->r21;
  u64 stop, current, scheduler, active_process;
  u64 stop_again, current_again, scheduler_again, active_process_again;
  u64 first_caller;
  u64 mfa[3];
  if (
    bpf_probe_read_user(&stop, sizeof(stop), (void *)(process + info->process_stop_offset)) ||
    bpf_probe_read_user(
      &current, sizeof(current), (void *)(process + info->process_current_offset)) ||
    bpf_probe_read_user(
      &scheduler, sizeof(scheduler), (void *)(process + info->process_scheduler_data_offset)) ||
    !scheduler || stop != state->r20 || stop < 8 || (stop & 7) || !current ||
    bpf_probe_read_user(&first_caller, sizeof(first_caller), (void *)stop) ||
    first_caller < ranges->first.start || first_caller >= ranges->last.end ||
    bpf_probe_read_user(
      &active_process,
      sizeof(active_process),
      (void *)(scheduler + info->scheduler_current_process_offset)) ||
    active_process != process || bpf_probe_read_user(mfa, sizeof(mfa), (void *)current) ||
    (mfa[0] & 0x3f) != 0xb || (mfa[1] & 0x3f) != 0xb || mfa[2] > 255) {
    return ERR_BEAM_CALL_NIF_BOUNDARY_INVALID;
  }

  u64 pc         = current;
  bool scheduled = false;
  if (current < ranges->first.start || current >= ranges->last.end) {
    u64 instruction, instruction_again, saved_mfa, saved_mfa_again;
    s32 argc, argc_again;
    if (
      !info->process_i_offset || !info->native_func_trampoline_offset ||
      !info->native_func_mfa_offset || !info->native_func_argc_offset ||
      bpf_probe_read_user(
        &instruction, sizeof(instruction), (void *)(process + info->process_i_offset)) ||
      instruction < info->native_func_trampoline_offset || instruction < sizeof(mfa) ||
      current != instruction - sizeof(mfa)) {
      return ERR_BEAM_CALL_NIF_BOUNDARY_INVALID;
    }
    u64 wrapper = instruction - info->native_func_trampoline_offset;
    if (
      !wrapper || (wrapper & 7) ||
      bpf_probe_read_user(
        &saved_mfa, sizeof(saved_mfa), (void *)(wrapper + info->native_func_mfa_offset)) ||
      bpf_probe_read_user(&argc, sizeof(argc), (void *)(wrapper + info->native_func_argc_offset)) ||
      ranges->last.end < sizeof(mfa) || saved_mfa < ranges->first.start ||
      saved_mfa > ranges->last.end - sizeof(mfa) || argc < 0 || argc > 255 ||
      bpf_probe_read_user(mfa, sizeof(mfa), (void *)saved_mfa) || (mfa[0] & 0x3f) != 0xb ||
      (mfa[1] & 0x3f) != 0xb || mfa[2] != (u64)argc ||
      bpf_probe_read_user(
        &instruction_again,
        sizeof(instruction_again),
        (void *)(process + info->process_i_offset)) ||
      bpf_probe_read_user(
        &saved_mfa_again,
        sizeof(saved_mfa_again),
        (void *)(wrapper + info->native_func_mfa_offset)) ||
      bpf_probe_read_user(
        &argc_again, sizeof(argc_again), (void *)(wrapper + info->native_func_argc_offset)) ||
      instruction_again != instruction || saved_mfa_again != saved_mfa || argc_again != argc) {
      return ERR_BEAM_CALL_NIF_BOUNDARY_INVALID;
    }
    pc        = saved_mfa + sizeof(mfa);
    // The scheduled call already established this BEAM frame.
    scheduled = true;
  }

  if (
    bpf_probe_read_user(
      &stop_again, sizeof(stop_again), (void *)(process + info->process_stop_offset)) ||
    bpf_probe_read_user(
      &current_again, sizeof(current_again), (void *)(process + info->process_current_offset)) ||
    bpf_probe_read_user(
      &scheduler_again,
      sizeof(scheduler_again),
      (void *)(process + info->process_scheduler_data_offset)) ||
    bpf_probe_read_user(
      &active_process_again,
      sizeof(active_process_again),
      (void *)(scheduler + info->scheduler_current_process_offset)) ||
    stop_again != stop || current_again != current || scheduler_again != scheduler ||
    active_process_again != process) {
    return ERR_BEAM_CALL_NIF_BOUNDARY_INVALID;
  }

  state->pc             = pc;
  // The BEAM scanner starts at r20 + 8; Process.stop points at the first caller.
  state->r20            = stop - 8;
  state->return_address = scheduled;
  return ERR_OK;
}
#endif

static EBPF_INLINE ErrorCode unwind_one_beam_frame(
  PerCPURecord *record, BEAMProcInfo *info, BEAMRangesSearchCache *ranges, u32 active_index)
{
  UnwindState *state = &record->state;
  Trace *trace       = &record->trace;
  u64 pc             = state->pc;

#if defined(__x86_64__)
  if (
    info->otp_release == 25 && info->frame_pointers_enabled && info->heavy_bif_start != 0 &&
    pc >= info->heavy_bif_start && pc < info->heavy_bif_end) {
    return beam_unwind_heavy_bif(record, info, ranges);
  }

  // Guard BIFs call this shared fragment from a module. The fragment has its
  // own frame; its saved return address identifies the module caller.
  if (
    info->otp_release == 25 && info->frame_pointers_enabled && info->guard_bif_start != 0 &&
    pc >= info->guard_bif_start && pc < info->guard_bif_end) {
    return beam_resume_shared_frame(state, ranges, info->guard_bif_start, info->guard_bif_end)
             ? ERR_OK
             : ERR_BEAM_GUARD_BIF_BOUNDARY_INVALID;
  }
  if (
    info->otp_release == 25 && info->frame_pointers_enabled && info->body_bif_start != 0 &&
    pc >= info->body_bif_start && pc < info->body_bif_end) {
    return beam_resume_shared_frame(state, ranges, info->body_bif_start, info->body_bif_end)
             ? ERR_OK
             : ERR_BEAM_BODY_BIF_BOUNDARY_INVALID;
  }

  // The GC fragment also establishes a frame before calling into the runtime.
  if (
    info->otp_release == 25 && info->frame_pointers_enabled && info->garbage_collect_start != 0 &&
    pc >= info->garbage_collect_start && pc < info->garbage_collect_end) {
    return beam_resume_shared_frame(
             state, ranges, info->garbage_collect_start, info->garbage_collect_end)
             ? ERR_OK
             : ERR_BEAM_GARBAGE_COLLECT_BOUNDARY_INVALID;
  }

  // Shared map updates establish a frame and return to their module caller.
  if (
    info->otp_release == 25 && info->frame_pointers_enabled && info->map_assoc_start != 0 &&
    pc >= info->map_assoc_start && pc < info->map_assoc_end) {
    return beam_resume_shared_frame(state, ranges, info->map_assoc_start, info->map_assoc_end)
             ? ERR_OK
             : ERR_BEAM_MAP_UPDATE_BOUNDARY_INVALID;
  }

  // The module NIF stub establishes the frame before jumping here. The
  // shared fragment returns to that stub after the native NIF call.
  if (
    info->otp_release == 25 && info->frame_pointers_enabled && info->call_nif_start != 0 &&
    pc >= info->call_nif_start && pc < info->call_nif_end) {
    return beam_resume_shared_frame(state, ranges, info->call_nif_start, info->call_nif_end)
             ? ERR_OK
             : ERR_BEAM_CALL_NIF_BOUNDARY_INVALID;
  }

  // OTP 25's shared light-BIF fragment is outside the module range table. A
  // return address into that code can follow a native BIF frame while RBP
  // still points to the Erlang frame chain. Heavy BIFs establish a module
  // frame before entering shared code and must not use this shortcut.
  if (
    info->otp_release == 25 && info->frame_pointers_enabled && info->light_bif_start != 0 &&
    info->light_bif_start < info->light_bif_end && pc >= info->light_bif_start &&
    pc < info->light_bif_end) {
    return beam_resume_shared_frame(state, ranges, info->light_bif_start, info->light_bif_end)
             ? ERR_OK
             : ERR_BEAM_LIGHT_BIF_BOUNDARY_INVALID;
  }
#endif

  // Exception handling is entered by a jump and may replace the stack.
  if (
    info->otp_release == 25 && info->raise_exception_start != 0 &&
    pc >= info->raise_exception_start && pc < info->raise_exception_end) {
    return ERR_BEAM_SHARED_EXCEPTION_UNWIND;
  }

#if defined(__aarch64__)
  if (
    info->otp_release == 25 && info->heavy_bif_start != 0 && pc >= info->heavy_bif_start &&
    pc < info->heavy_bif_end) {
    return beam_resume_arm_heavy_bif(state, info, ranges);
  }

  if (
    info->otp_release == 25 && info->bif_export_trap_start != 0 &&
    pc >= info->bif_export_trap_start && pc < info->bif_export_trap_end) {
    return beam_resume_arm_heavy_bif(state, info, ranges);
  }

  if (
    info->otp_release == 25 && info->light_bif_start != 0 && pc >= info->light_bif_start &&
    pc < info->light_bif_end) {
    if (
      !state->return_address && state->r20 >= sizeof(u64) && !(state->r20 & 7) &&
      beam_arm_fragment_callsite(state->lr, info->light_bif_start, ranges)) {
      state->pc = state->lr;
      beam_arm_include_first_continuation(state, info, ranges);
      unwinder_mark_nonleaf_frame(state);
      return ERR_OK;
    }
    return beam_resume_arm_shared_bif(state, info, ranges) ? ERR_OK
                                                           : ERR_BEAM_LIGHT_BIF_BOUNDARY_INVALID;
  }

  if (
    info->otp_release == 25 && info->guard_bif_start != 0 && pc >= info->guard_bif_start &&
    pc < info->guard_bif_end) {
    return beam_resume_arm_framed_bif(state, info, ranges, info->guard_bif_start)
             ? ERR_OK
             : ERR_BEAM_GUARD_BIF_BOUNDARY_INVALID;
  }

  if (
    info->otp_release == 25 && info->body_bif_start != 0 && pc >= info->body_bif_start &&
    pc < info->body_bif_end) {
    return beam_resume_arm_framed_bif(state, info, ranges, info->body_bif_start)
             ? ERR_OK
             : ERR_BEAM_BODY_BIF_BOUNDARY_INVALID;
  }
  if (
    info->otp_release == 25 && info->garbage_collect_start != 0 &&
    pc >= info->garbage_collect_start && pc < info->garbage_collect_end) {
    return ERR_BEAM_GARBAGE_COLLECT_BOUNDARY_INVALID;
  }
  if (
    info->otp_release == 25 && info->map_assoc_start != 0 && pc >= info->map_assoc_start &&
    pc < info->map_assoc_end) {
    return ERR_BEAM_MAP_UPDATE_BOUNDARY_INVALID;
  }
  if (
    info->otp_release == 25 && info->call_nif_start != 0 && pc >= info->call_nif_start &&
    pc < info->call_nif_end) {
    return beam_resume_arm_nif(state, info, ranges);
  }
#endif

  if (
    info->otp_release == 25 && info->global_jit_start != 0 && pc >= info->global_jit_start &&
    pc < info->global_jit_end) {
    return ERR_BEAM_GLOBAL_JIT_UNHANDLED;
  }

  if (pc < ranges->first.start || pc >= ranges->last.end) {
    ErrorCode snapshot_error = beam_check_range_snapshot(info, active_index, ranges);
    if (snapshot_error) {
      return snapshot_error;
    }
    return ERR_BEAM_PC_INVALID;
  }

  u64 low     = 0;
  u64 high    = ranges->info.n;
  u64 current = low + (high - low) / 2;

  BEAMRangeEntry current_range = ranges->mid;

  for (u64 i = 0; i < BEAM_CODE_HEADER_SEARCH_ITERATIONS; i++) {
    if (pc < current_range.start) {
      high = current;
    } else if (pc >= current_range.end) {
      low = current + 1;
    } else {
      break;
    }

    if (low >= high) {
      ErrorCode snapshot_error = beam_check_range_snapshot(info, active_index, ranges);
      if (snapshot_error) {
        return snapshot_error;
      }
      DEBUG_PRINT("beam: module range gap PC 0x%llx", pc);
      return ERR_BEAM_MODULE_RANGE_GAP;
    }

    current = low + (high - low) / 2;

    u64 entry_ptr = ranges->info.modules + current * sizeof(BEAMRangeEntry);
    if (bpf_probe_read_user(&current_range, sizeof(BEAMRangeEntry), (void *)(entry_ptr))) {
      DEBUG_PRINT("beam: Failed to read current range");
      return ERR_BEAM_MODULES_READ_FAILURE;
    }
  }

  if (pc < current_range.start || pc >= current_range.end) {
    ErrorCode snapshot_error = beam_check_range_snapshot(info, active_index, ranges);
    if (snapshot_error) {
      return snapshot_error;
    }
    // Ran out of loop iterations without locating the correct range
    return ERR_BEAM_RANGE_SEARCH_EXHAUSTED;
  }

  ErrorCode snapshot_error = beam_check_range_snapshot(info, active_index, ranges);
  if (snapshot_error) {
    return snapshot_error;
  }
  BEAMRangeEntry selected_again;
  u64 selected_ptr = ranges->info.modules + current * sizeof(BEAMRangeEntry);
  if (
    bpf_probe_read_user(&selected_again, sizeof(selected_again), (void *)selected_ptr) ||
    selected_again.start != current_range.start || selected_again.end != current_range.end) {
    return ERR_BEAM_RANGE_SNAPSHOT_CHANGED;
  }

  if (!push_beam(state, trace, current_range.start)) {
    return ERR_STACK_LENGTH_EXCEEDED;
  }

  if (info->frame_pointers_enabled) {
#if defined(__x86_64__)
    if (info->otp_release == 25) {
      BEAMFPTransition transition = beam_fp_transition(state, &current_range);
      if (transition == BEAM_FP_UNREADABLE) {
        return ERR_BEAM_FP_TRANSITION_INVALID;
      }
      if (transition != BEAM_FP_ESTABLISHED) {
        if (!beam_unwind_fp_transition(state, transition)) {
          return ERR_BEAM_FP_TRANSITION_INVALID;
        }
        return ERR_OK;
      }
    }
#endif
    if (!unwinder_unwind_frame_pointer(state)) {
      DEBUG_PRINT("beam: invalid frame pointer");
      return ERR_BEAM_FRAME_POINTER_INVALID;
    }
    return ERR_OK;
  }

#if defined(__aarch64__)
  // Native stack is not supported on ARM due to 16-byte stack alignment hassle
  // r20 is used to store the stack pointer for JIT code to allow 8-bit alignment.
  #define stack_reg r20
#else
  #define stack_reg sp
#endif
  // The scan starts after stack_reg so subsequent frames do not rediscover
  // the same continuation. Include the first slot for a sampled leaf.
#if defined(__x86_64__)
  if (!state->return_address) {
    state->stack_reg -= sizeof(u64);
  }
#elif defined(__aarch64__)
  if (info->otp_release == 25 && !state->return_address) {
    u32 instruction;
    if (bpf_probe_read_user(&instruction, sizeof(instruction), (void *)state->pc)) {
      return ERR_BEAM_INSTRUCTION_READ_FAILURE;
    }
    // str x30, [x20, #-8]! saves the caller at a module entry.
    if (instruction == 0xf81f8e9e) {
      return beam_arm_resume_lr(state, info, ranges) ? ERR_OK : ERR_BEAM_ARM_FRAME_ENTRY_UNSAVED;
    }
    // ldr x30, [x20], #8 restores LR before a return or tail branch.
    // Until the branch executes, LR still identifies this frame's caller.
    if (state->pc >= current_range.start + 12) {
      u32 previous[3];
      if (!bpf_probe_read_user(previous, sizeof(previous), (void *)(state->pc - 12))) {
        bool branch =
          (instruction & 0xfc000000) == 0x14000000 || (instruction & 0xfffffc1f) == 0xd61f0000;
        bool conditional   = (instruction & 0xff00001f) == 0x54000004;
        bool before_branch = previous[2] == 0xf840869e && (instruction == 0xf10006d6 || branch);
        bool before_return = previous[1] == 0xf840869e && previous[2] == 0xf10006d6 && conditional;
        bool at_return     = previous[0] == 0xf840869e && previous[1] == 0xf10006d6 &&
                         (previous[2] & 0xff00001f) == 0x54000004 && instruction == 0xd65f03c0;
        if (before_branch || before_return || at_return) {
          return beam_arm_resume_lr(state, info, ranges) ? ERR_OK : ERR_BEAM_ARM_FRAME_EXIT_INVALID;
        }
      }
    }
    beam_arm_include_first_continuation(state, info, ranges);
  }
#endif
  u64 data[BEAM_STACK_FRAME_SCAN_WORDS_PER_READ];
  for (u64 chunk = 0; chunk < BEAM_STACK_FRAME_SCAN_ITERATIONS; chunk++) {
    if (info->otp_release != 25 && chunk >= 8) {
      break;
    }
    if (bpf_probe_read_user(data, sizeof(data), (void *)(state->stack_reg + 8))) {
      DEBUG_PRINT("beam: failed to read stack chunk at 0x%llx", state->stack_reg + 8);
      return ERR_BEAM_STACK_READ_FAILURE;
    }

    for (u64 i = 0; i < BEAM_STACK_FRAME_SCAN_WORDS_PER_READ; i++) {
      state->stack_reg += 8;
      pc = data[i];

      // On the stack, if the value is tagged as a header value, then that means it's actually a
      // continuation pointer.
      // https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/erl_etp.c#L132
      // https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/erl_etp.c#L133
      if ((pc & 0x03) == 0) {
        goto found_pc;
      }
    }
  }
#undef stack_reg
  return ERR_BEAM_STACK_SCAN_EXHAUSTED;

found_pc:
  state->pc = pc;
  unwinder_mark_nonleaf_frame(state);
  return ERR_OK;
}

// unwind_beam is the entry point for tracing when invoked from the native tracer
// or interpreter dispatcher. It does not reset the trace object and will append the
// BEAM stack frames to the trace object for the current CPU.
static EBPF_INLINE int unwind_beam(struct pt_regs *ctx)
{
  int unwinder    = PROG_UNWIND_STOP;
  ErrorCode error = ERR_OK;

  PerCPURecord *record = get_per_cpu_record();
  if (!record) {
    DEBUG_PRINT("beam: no PerCPURecord found");
    return -1;
  }

  Trace *trace       = &record->trace;
  UnwindState *state = &record->state;
  u32 pid            = trace->pid;

  BEAMProcInfo *info = bpf_map_lookup_elem(&beam_procs, &pid);

  if (!info) {
    DEBUG_PRINT("beam: no BEAMProcInfo for this pid");
    error = ERR_BEAM_NO_PROC_INFO;
    goto exit;
  }

  DEBUG_PRINT("==== unwind_beam %d, pc: 0x%llx ====", trace->num_frames, state->pc);

  unwinder_analyze_frame_pointer(&record->state);

  // "the_active_code_index" symbol is from:
  // https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/code_ix.c#L46
  u32 the_active_code_index;
  if (bpf_probe_read_user(
        &the_active_code_index, sizeof(u32), (void *)info->the_active_code_index)) {
    DEBUG_PRINT("beam: Failed to read the_active_code_index");
    error = ERR_BEAM_ACTIVE_CODE_INDEX_READ_FAILURE;
    goto exit;
  }

  // Index into the active static `r` variable using the currently-active code index
  // https://github.com/erlang/otp/blob/OTP-27.2.4/erts/emulator/beam/beam_ranges.c#L62
  u64 active_ranges = info->r + (the_active_code_index * info->ranges_sizeof);

  DEBUG_PRINT(
    "beam: r: %llx, the_active_code_index: %d, active_ranges: %llx",
    info->r,
    the_active_code_index,
    active_ranges);

  BEAMRangesSearchCache ranges;

  if (bpf_probe_read_user(&ranges.info, sizeof(BEAMRangesInfo), (void *)(active_ranges))) {
    DEBUG_PRINT("beam: Failed to read active ranges");
    error = ERR_BEAM_MODULES_READ_FAILURE;
    goto exit;
  }

  DEBUG_PRINT("beam: modules: %llx, n: %llu", ranges.info.modules, ranges.info.n);

  if (ranges.info.n == 0) {
    error = ERR_BEAM_PC_INVALID;
    goto exit;
  }

  u64 entry_ptr = ranges.info.modules;
  if (bpf_probe_read_user(&ranges.first, sizeof(BEAMRangeEntry), (void *)(entry_ptr))) {
    DEBUG_PRINT("beam: Failed to read first range");
    error = ERR_BEAM_MODULES_READ_FAILURE;
    goto exit;
  }

  entry_ptr = ranges.info.modules + (ranges.info.n / 2) * sizeof(BEAMRangeEntry);
  if (bpf_probe_read_user(&ranges.mid, sizeof(BEAMRangeEntry), (void *)(entry_ptr))) {
    DEBUG_PRINT("beam: Failed to read middle range");
    error = ERR_BEAM_MODULES_READ_FAILURE;
    goto exit;
  }

  entry_ptr = ranges.info.modules + (ranges.info.n - 1) * sizeof(BEAMRangeEntry);
  if (bpf_probe_read_user(&ranges.last, sizeof(BEAMRangeEntry), (void *)(entry_ptr))) {
    DEBUG_PRINT("beam: Failed to read last range");
    error = ERR_BEAM_MODULES_READ_FAILURE;
    goto exit;
  }

  DEBUG_PRINT("beam: valid addresses 0x%llx - 0x%llx", ranges.first.start, ranges.last.end);

  for (u64 i = 0; i < BEAM_FRAMES_PER_PROGRAM; i++) {
    error = beam_check_range_snapshot(info, the_active_code_index, &ranges);
    if (error) {
      break;
    }
    if (record->state.pc == info->beam_normal_exit) {
      unwinder = PROG_UNWIND_STOP;
      break;
    }

    // process_main is the scheduler's JIT entry, not an Erlang caller.
    if (
      info->otp_release == 25 && info->process_main_start != 0 &&
      record->state.pc >= info->process_main_start && record->state.pc < info->process_main_end) {
      bool scheduler_root = record->state.return_address && trace->num_frames != 0;
#if defined(__x86_64__)
      scheduler_root = scheduler_root && record->state.fp == 0;
#endif
      if (scheduler_root) {
        unwinder = PROG_UNWIND_STOP;
      } else {
        error = ERR_BEAM_PROCESS_MAIN_BOUNDARY_INVALID;
      }
      break;
    }

    error = unwind_one_beam_frame(record, info, &ranges, the_active_code_index);
    if (error) {
      break;
    }

    error = get_next_unwinder_after_native_frame(record, &unwinder);
    if (error || unwinder != PROG_UNWIND_BEAM) {
      break;
    }
  }

exit:
  state->unwind_error = error;
  tail_call(ctx, unwinder);
  DEBUG_PRINT("beam: tail call for next frame unwinder (%d) failed", unwinder);
  return -1;
}

MULTI_USE_FUNC(unwind_beam)
