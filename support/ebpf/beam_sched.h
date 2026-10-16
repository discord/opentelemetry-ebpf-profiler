// Attribute a CPU sample to the Erlang process running on a known scheduler.
// Scheduler addresses and offsets are validated in user space. Bind entries
// to tgid because kernel TIDs can be reused before a stale entry is detached.
// The perf interrupt pauses the scheduler that owns current_process; null or
// invalid PID terms leave the sample unattributed.

#ifndef OPTI_BEAM_SCHED_H
#define OPTI_BEAM_SCHED_H

#include "bpfdefs.h"
#include "extmaps.h"
#include "types.h"

// Erlang term tag for an internal pid: (term & _TAG_IMMED1_MASK) ==
// _TAG_IMMED1_PID, i.e. (term & 0xF) == 0x3.
// https://github.com/erlang/otp/blob/OTP-25.3.2.7/erts/emulator/beam/erl_term.h
#define BEAM_TAG_IMMED1_MASK 0xF
#define BEAM_TAG_IMMED1_PID  0x3

static EBPF_INLINE void beam_stamp_current_process(Trace *trace, u32 pid, u32 tid)
{
  BeamSchedInfo *si = bpf_map_lookup_elem(&beam_sched_tids, &tid);
  if (!si) {
    return;
  }
  if (si->tgid != pid) {
    // This TID now belongs to another process.
    return;
  }

  u64 proc = 0;
  if (bpf_probe_read_user(&proc, sizeof(proc), (void *)(si->esdp_addr + si->off_current_proc))) {
    return;
  }
  if (!proc) {
    // The scheduler is between processes; there is nothing to attribute.
    return;
  }

  // Process.common.id is at offset 0: struct process starts with
  // ErtsPTabElementCommon ("*Need* to be first in struct"), whose first member
  // is `Eterm id`.
  // https://github.com/erlang/otp/blob/OTP-25.3.2.7/erts/emulator/beam/erl_process.h#L1007-L1008
  // https://github.com/erlang/otp/blob/OTP-25.3.2.7/erts/emulator/beam/erl_ptab.h
  u64 id = 0;
  if (bpf_probe_read_user(&id, sizeof(id), (void *)proc)) {
    return;
  }
  if ((id & BEAM_TAG_IMMED1_MASK) != BEAM_TAG_IMMED1_PID) {
    // Not an internal pid: a torn/mid-dispatch read, or a shadow process on a
    // dirty scheduler. Anything but a pid means no label.
    return;
  }

  trace->erlang_pid_key = id;
}

#endif // OPTI_BEAM_SCHED_H
