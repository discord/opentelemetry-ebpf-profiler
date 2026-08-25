// Per-sample Erlang process attribution.
//
// Discord addition. At perf-sample time, for a tid known to be a BEAM
// scheduler thread, read esdp->current_process and stamp the raw pid Eterm on
// the trace.
//
// Coherence: the perf interrupt runs on the CPU executing that scheduler
// thread, and the only writer of current_process is the interrupted thread
// itself, so the read is quiescent -- there is no other thread that could be
// mutating the field while we are stopped in the interrupt. A stale value is
// bounded by dispatch latency (the window between the scheduler picking a
// process and assigning the field), and the tag check below plus the null
// check turn any mid-dispatch race into "no label", never a wrong label.
//
// Identity: the map is keyed by global kernel tid, and kernel tids are
// reused. If a Detach is ever missed -- a dropped process-exit notification,
// which is an unbounded window -- an unrelated thread could inherit a mapped
// tid, and the two reads below would then happen at a dead VM's addresses in
// the NEW process's address space, where they may well be mapped and may well
// pass the tag check. So the entry carries the tgid it was written for and
// this helper refuses to stamp anything when the sampled process is not that
// one. Without that binding "never a wrong label" would not be true.
//
// Everything version-specific -- which tid is a scheduler, where its
// ErtsSchedulerData lives, and where current_process sits inside it -- is
// resolved and tripwire-validated in user space before beam_sched_tids gains
// an entry (interpreter/beam/beam_sched.go). If any of that fails the map
// stays empty for that process and this helper is a single failed map lookup.

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
    // A stale entry whose tid has been reused by another process; see the
    // identity section above.
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
