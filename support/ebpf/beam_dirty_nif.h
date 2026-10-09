#ifndef OPTI_BEAM_DIRTY_NIF_H
#define OPTI_BEAM_DIRTY_NIF_H

extern struct beam_procs_t beam_procs;
extern struct beam_dirty_nif_threads_t beam_dirty_nif_threads;

static EBPF_INLINE ErrorCode beam_try_dirty_nif_boundary(PerCPURecord *record, int *unwinder)
{
#if defined(__x86_64__)
  BEAMProcInfo *info = bpf_map_lookup_elem(&beam_procs, &record->trace.pid);
  if (
    !info || info->otp_release != 25 || !info->frame_pointers_enabled ||
    !info->process_stop_offset || !info->dirty_nif_current_offset) {
    return ERR_OK;
  }
  u64 id                       = ((u64)record->trace.pid << 32) | record->trace.tid;
  BEAMDirtyNIFContext *context = bpf_map_lookup_elem(&beam_dirty_nif_threads, &id);
  if (!context) {
    return ERR_OK;
  }
  if (
    !info->process_i_offset || !info->process_current_offset || !context->scheduler ||
    !context->process || !context->entry_i) {
    return ERR_BEAM_DIRTY_NIF_BOUNDARY_INVALID;
  }

  u64 active_nif, active_nif_again;
  u64 active_slot = context->scheduler + info->dirty_nif_current_offset;
  if (bpf_probe_read_user(&active_nif, sizeof(active_nif), (void *)active_slot)) {
    return ERR_BEAM_DIRTY_NIF_BOUNDARY_INVALID;
  }
  if (!active_nif) {
    return ERR_OK;
  }

  u64 process = context->process;
  u64 stack[2], stack_again[2], instruction, instruction_again;
  u64 current, current_again, slots[2], mfa[3];
  if (
    bpf_probe_read_user(stack, sizeof(stack), (void *)(process + info->process_stop_offset)) ||
    bpf_probe_read_user(
      &instruction, sizeof(instruction), (void *)(process + info->process_i_offset)) ||
    bpf_probe_read_user(
      &current, sizeof(current), (void *)(process + info->process_current_offset)) ||
    !current || bpf_probe_read_user(mfa, sizeof(mfa), (void *)current)) {
    return ERR_BEAM_DIRTY_NIF_BOUNDARY_INVALID;
  }

  u64 fp = stack[1];
  if (
    stack[0] != fp || instruction != context->entry_i || fp == 0 || (fp & 7) ||
    (mfa[0] & 0x3f) != 0xb || (mfa[1] & 0x3f) != 0xb || mfa[2] > 255 ||
    bpf_probe_read_user(slots, sizeof(slots), (void *)fp) || slots[0] <= fp || slots[0] - fp < 16 ||
    slots[0] - fp >= (1 << 20) || (slots[0] & 7) || slots[1] < 0x1000) {
    return ERR_BEAM_DIRTY_NIF_BOUNDARY_INVALID;
  }

  if (
    bpf_probe_read_user(
      stack_again, sizeof(stack_again), (void *)(process + info->process_stop_offset)) ||
    bpf_probe_read_user(
      &instruction_again, sizeof(instruction_again), (void *)(process + info->process_i_offset)) ||
    bpf_probe_read_user(
      &current_again, sizeof(current_again), (void *)(process + info->process_current_offset)) ||
    stack_again[0] != stack[0] || stack_again[1] != fp || instruction_again != instruction ||
    current_again != current ||
    bpf_probe_read_user(&active_nif_again, sizeof(active_nif_again), (void *)active_slot) ||
    active_nif_again != active_nif) {
    return ERR_BEAM_DIRTY_NIF_BOUNDARY_INVALID;
  }

  UnwindState *state = &record->state;
  if (
    info->native_func_trampoline_offset && info->native_func_mfa_offset &&
    info->native_func_argc_offset && instruction >= info->native_func_trampoline_offset) {
    u64 wrapper = instruction - info->native_func_trampoline_offset;
    u64 saved_mfa, saved_mfa_again, saved_words[3];
    s32 saved_argc, saved_argc_again;
    if (
      bpf_probe_read_user(
        &saved_mfa, sizeof(saved_mfa), (void *)(wrapper + info->native_func_mfa_offset)) ||
      bpf_probe_read_user(
        &saved_argc, sizeof(saved_argc), (void *)(wrapper + info->native_func_argc_offset)) ||
      !saved_mfa || saved_argc < 0 || saved_argc > 255 ||
      bpf_probe_read_user(saved_words, sizeof(saved_words), (void *)saved_mfa) ||
      (saved_words[0] & 0x3f) != 0xb || (saved_words[1] & 0x3f) != 0xb || saved_words[2] > 255 ||
      bpf_probe_read_user(
        &saved_mfa_again,
        sizeof(saved_mfa_again),
        (void *)(wrapper + info->native_func_mfa_offset)) ||
      bpf_probe_read_user(
        &saved_argc_again,
        sizeof(saved_argc_again),
        (void *)(wrapper + info->native_func_argc_offset)) ||
      saved_mfa_again != saved_mfa || saved_argc_again != saved_argc) {
      return ERR_BEAM_DIRTY_NIF_BOUNDARY_INVALID;
    }
    // The saved BEAM frame is established. Represent its entry as a return
    // address so the BEAM unwinder follows the saved frame pointer.
    state->pc             = saved_mfa + sizeof(saved_words) + 1;
    state->sp             = fp;
    state->fp             = fp;
    state->fp_bound       = fp;
    state->return_address = true;
  } else {
    state->fp = fp;
    unwinder_unwind_frame_pointer_regs(state, slots);
  }
  ErrorCode error = get_next_unwinder_after_native_frame(record, unwinder);
  if (error) {
    return error;
  }
  if (*unwinder != PROG_UNWIND_BEAM) {
    *unwinder = PROG_UNWIND_STOP;
    return ERR_BEAM_DIRTY_NIF_BOUNDARY_INVALID;
  }
#elif defined(__aarch64__)
  BEAMProcInfo *info = bpf_map_lookup_elem(&beam_procs, &record->trace.pid);
  if (
    !info || info->otp_release != 25 || !info->process_stop_offset || !info->process_i_offset ||
    !info->process_current_offset || !info->dirty_nif_current_offset ||
    !info->native_func_trampoline_offset || !info->native_func_mfa_offset ||
    !info->native_func_argc_offset) {
    return ERR_OK;
  }
  u64 id                       = ((u64)record->trace.pid << 32) | record->trace.tid;
  BEAMDirtyNIFContext *context = bpf_map_lookup_elem(&beam_dirty_nif_threads, &id);
  if (!context) {
    return ERR_OK;
  }

  u64 active_nif, active_nif_again;
  u64 active_slot = context->scheduler + info->dirty_nif_current_offset;
  if (
    !context->scheduler || !context->process || !context->entry_i ||
    bpf_probe_read_user(&active_nif, sizeof(active_nif), (void *)active_slot)) {
    return ERR_BEAM_DIRTY_NIF_BOUNDARY_INVALID;
  }
  if (!active_nif) {
    return ERR_OK;
  }

  u64 process = context->process;
  u64 stop, stop_again, instruction, instruction_again;
  u64 current, current_again, caller, saved_mfa, saved_mfa_again, mfa[3];
  s32 argc, argc_again;
  if (
    bpf_probe_read_user(&stop, sizeof(stop), (void *)(process + info->process_stop_offset)) ||
    bpf_probe_read_user(
      &instruction, sizeof(instruction), (void *)(process + info->process_i_offset)) ||
    bpf_probe_read_user(
      &current, sizeof(current), (void *)(process + info->process_current_offset)) ||
    instruction != context->entry_i || !current || stop < 8 || (stop & 7) ||
    instruction < info->native_func_trampoline_offset ||
    bpf_probe_read_user(&caller, sizeof(caller), (void *)stop) ||
    bpf_probe_read_user(mfa, sizeof(mfa), (void *)current) || (mfa[0] & 0x3f) != 0xb ||
    (mfa[1] & 0x3f) != 0xb || mfa[2] > 255) {
    return ERR_BEAM_DIRTY_NIF_BOUNDARY_INVALID;
  }

  u64 wrapper = instruction - info->native_func_trampoline_offset;
  if (
    bpf_probe_read_user(
      &saved_mfa, sizeof(saved_mfa), (void *)(wrapper + info->native_func_mfa_offset)) ||
    bpf_probe_read_user(&argc, sizeof(argc), (void *)(wrapper + info->native_func_argc_offset)) ||
    !saved_mfa || argc < 0 || argc > 255 ||
    bpf_probe_read_user(mfa, sizeof(mfa), (void *)saved_mfa) || (mfa[0] & 0x3f) != 0xb ||
    (mfa[1] & 0x3f) != 0xb || mfa[2] > 255) {
    return ERR_BEAM_DIRTY_NIF_BOUNDARY_INVALID;
  }
  u64 pc = saved_mfa + sizeof(mfa);
  if (pc < saved_mfa || pc == 0 || caller == 0) {
    return ERR_BEAM_DIRTY_NIF_BOUNDARY_INVALID;
  }

  if (
    bpf_probe_read_user(
      &stop_again, sizeof(stop_again), (void *)(process + info->process_stop_offset)) ||
    bpf_probe_read_user(
      &instruction_again, sizeof(instruction_again), (void *)(process + info->process_i_offset)) ||
    bpf_probe_read_user(
      &current_again, sizeof(current_again), (void *)(process + info->process_current_offset)) ||
    bpf_probe_read_user(
      &saved_mfa_again,
      sizeof(saved_mfa_again),
      (void *)(wrapper + info->native_func_mfa_offset)) ||
    bpf_probe_read_user(
      &argc_again, sizeof(argc_again), (void *)(wrapper + info->native_func_argc_offset)) ||
    bpf_probe_read_user(&active_nif_again, sizeof(active_nif_again), (void *)active_slot) ||
    stop_again != stop || instruction_again != instruction || current_again != current ||
    saved_mfa_again != saved_mfa || argc_again != argc || active_nif_again != active_nif) {
    return ERR_BEAM_DIRTY_NIF_BOUNDARY_INVALID;
  }

  record->state.pc             = pc;
  record->state.r20            = stop - 8;
  // Treat the instruction after the saved MFA as a BEAM return address.
  record->state.return_address = true;
  ErrorCode error              = get_next_unwinder_after_native_frame(record, unwinder);
  if (error) {
    return error;
  }
  if (*unwinder != PROG_UNWIND_BEAM) {
    *unwinder = PROG_UNWIND_STOP;
    return ERR_BEAM_DIRTY_NIF_BOUNDARY_INVALID;
  }
#else
  (void)record;
  (void)unwinder;
#endif
  return ERR_OK;
}

#endif
