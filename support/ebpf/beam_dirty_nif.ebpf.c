#include "bpfdefs.h"
#include "kernel.h"
#include "types.h"

extern struct beam_procs_t beam_procs;

struct beam_dirty_nif_threads_t {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, u64);
  __type(value, BEAMDirtyNIFContext);
  __uint(max_entries, 65536);
} beam_dirty_nif_threads SEC(".maps");

SEC("uprobe/erts_call_dirty_nif")
int beam_dirty_nif_enter(struct pt_regs *ctx)
{
  u64 id             = bpf_get_current_pid_tgid();
  u32 pid            = id >> 32;
  BEAMProcInfo *info = bpf_map_lookup_elem(&beam_procs, &pid);
  if (!info || !info->process_stop_offset || !info->dirty_nif_current_offset) {
    return 0;
  }

  // An update failure must not leave an older invocation under this thread.
  bpf_map_delete_elem(&beam_dirty_nif_threads, &id);
  BEAMDirtyNIFContext value;
#if defined(__x86_64__)
  if (!info->frame_pointers_enabled) {
    return 0;
  }
  value = (BEAMDirtyNIFContext){.scheduler = ctx->di, .process = ctx->si, .entry_i = ctx->dx};
#elif defined(__aarch64__)
  value = (BEAMDirtyNIFContext){
    .scheduler = ctx->regs[0], .process = ctx->regs[1], .entry_i = ctx->regs[2]};
#endif
  if (value.scheduler && value.process && value.entry_i) {
    bpf_map_update_elem(&beam_dirty_nif_threads, &id, &value, BPF_ANY);
  }
  return 0;
}
