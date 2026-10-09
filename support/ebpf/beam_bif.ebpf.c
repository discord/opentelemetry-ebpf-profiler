#include "bpfdefs.h"
#include "kernel.h"
#include "types.h"

extern struct beam_procs_t beam_procs;
extern struct beam_bif_processes_t beam_bif_processes;

// Capture Process* at BIF entry; read movable BEAM stack fields at sample time.
#if defined(__x86_64__)
SEC("uprobe/beam_jit_call_bif")
int beam_bif_enter(struct pt_regs *ctx)
{
  u64 id             = bpf_get_current_pid_tgid();
  u32 pid            = id >> 32;
  BEAMProcInfo *info = bpf_map_lookup_elem(&beam_procs, &pid);
  if (!info || !info->heavy_bif_start) {
    return 0;
  }

  // An update failure must not leave a previous process under this thread ID.
  bpf_map_delete_elem(&beam_bif_processes, &id);
  u64 process = ctx->di;
  if (!process) {
    return 0;
  }
  bpf_map_update_elem(&beam_bif_processes, &id, &process, BPF_ANY);
  return 0;
}

#endif
