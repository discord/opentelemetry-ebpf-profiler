# The Discord fork of opentelemetry-ebpf-profiler

This repo is `github.com/discord/opentelemetry-ebpf-profiler`: upstream
`open-telemetry/opentelemetry-ebpf-profiler` plus a small Discord delta. This
document is the map a contributor needs before changing two things upstream
will not carry for us: **egress** (we need our own output path; none of this
is destined for the mainline OTel package) and **sampling semantics** (we
expect to modify how and when samples are taken). It also documents the BEAM
interpreter work, which is the reason the fork exists.

Line references are against fork HEAD `e86db84`.

## 1. What the fork changes

Two commits on top of a recent upstream `main`:

| Commit | What it does |
|---|---|
| `d97b69a` "Merge forked OTP 25 support into main" | BEAM/Erlang unwinder support for OTP 25-27 (upstream lineage targeted 27/28 only): `interpreter/beam/beam.go`, a new `libpf` frame type, and small `host`/`tracer` compat shims. ~200 lines across 4 files. |
| `e86db84` "Add hack to find the 'r' symbol table when LTO is enabled" | LTO builds rename the file-local `r` symbol (BEAM's module ranges table) to `r.llvm.<hash>`; the loader now matches both spellings (`interpreter/beam/beam.go:165-180`). |

Everything else is upstream. That is deliberate: the smaller the delta, the
cheaper the rebase. New Discord-specific code (a custom reporter, sampling
changes) should be added as *new files* where possible, not edits to upstream
ones.

### Known consumers

`dd-otel-host-profiler` (Datadog's host agent) can consume this fork via a
`go.mod` replace directive:

```
replace go.opentelemetry.io/ebpf-profiler => github.com/discord/opentelemetry-ebpf-profiler v0.0.0-<pseudo-version>
```

A Discord checkout of that wrapper exists and pins this repo's HEAD. It is
one possible egress host (see section 3, option B) but not the planned one:
its reporter uploads to the Datadog intake. If this fork's public API shifts
during a rebase, that wrapper's pseudo-version must be bumped and its
`reporter/` adapted.

Related lineage: `GregMefford/opentelemetry-ebpf-profiler` branch
`beam_support` is the sibling BEAM effort (OTP 27/28, frame-pointer-less
unwinding, OTP 28 fixes on an older upstream base). Useful as a cherry-pick
source, but its reporter interfaces are an older upstream generation --
`SymbolReporter`/`HostMetadataReporter` there vs. our slimmer
`TraceReporter`+`ExecutableReporter` -- so ports need adjustment.

## 2. The data path in sixty seconds

```
kernel:  perf event (freq mode, CPU clock) per CPU
           -> eBPF native_tracer_entry -> collect_trace() -> unwinder tail calls
           -> trace_events perf ring buffer
user:    tracer (reads ring, enriches with /proc, hashes)
           -> tracehandler (LRU trace cache, symbolization via interpreters)
           -> Reporter.ReportTraceEvent(trace, meta)     <- THE EGRESS SEAM
                one call per sample, timestamps intact
           -> (built-in reporters) buffer into TraceEventsTree,
              flush on a ticker as OTLP profiles
```

The standalone agent (`main.go:109-127`) constructs `reporter.NewOTLP` and
hands it to `internal/controller`, which threads it into `tracer.Config`
(`internal/controller/controller.go:95` `TraceReporter:`, `:111`
`ExecutableReporter:`). There is also `cmd/otelcol-ebpf-profiler`, which runs
the profiler as an OTel collector receiver via `CollectorReporter`
(`reporter/collector_reporter.go`), and a `ReporterFactory` hook in the
controller config (`internal/controller/config.go:25-28`) if construction
needs to be deferred.

## 3. Egress: adding our own output path

### The seam

`reporter/iface.go` defines the whole contract:

```go
type Reporter interface {          // iface.go:15
    TraceReporter                  //   ReportTraceEvent(*libpf.Trace, *samples.TraceEventMeta) error
    Start(context.Context) error
    Stop()
}
type ExecutableReporter interface { // iface.go:56, optional
    ReportExecutable(*ExecutableMetadata)
}
```

Guarantees at this boundary, verified in code:

- **Delivery is strictly per-sample.** The tracehandler calls
  `ReportTraceEvent` once per perf event. Aggregation is the *reporter's*
  choice, not the engine's: the built-in `baseReporter` dedups on
  `TraceAndMetaKey` (hash+comm+exec+pid+tid+cpu, `base_reporter.go:65-75`)
  and **appends each sample's wall-clock nanosecond timestamp** to
  `TraceEvents.Timestamps` (`base_reporter.go:91-99`). Nothing is lost before
  the seam; sample count is `len(Timestamps)`.
- **`meta` carries the attribution we need**: PID, TID, CPU, comm,
  `/proc`-derived executable path and process name, container ID (cgroup v2),
  per-sample timestamp, origin, off-CPU nanoseconds, and env vars from an
  allowlist (`reporter/samples/samples.go`).
- **`trace` carries interned frames** (`libpf.Frames`) with function name,
  source file/line, frame type (native/kernel/BEAM/...), mapping and build
  IDs -- already symbolized by the time the reporter sees them -- plus a
  stable `TraceHash` and `CustomLabels`.
- **Three origins are accepted** by the built-in buffering:
  `TraceOriginSampling`, `TraceOriginOffCPU`, `TraceOriginProbe`
  (`base_reporter.go:50-57`, constants `support/types.go:95-98`).
- **Per-sample extension hook**: `Config.ExtraSampleAttrProd`
  (`reporter/config.go`) lets a host attach arbitrary metadata to each sample
  as it enters the tree, and that metadata participates in the dedup key
  (`base_reporter.go:59-62,74`). This is the intended place to stamp an
  external correlation ID (e.g. a test-iteration ordinal) onto samples
  without touching engine code.

### Flush machinery you get for free

`baseReporter` + `runLoop` (`reporter/runloop.go:19-40`) give you: the
buffered tree, a ticker with configurable interval and jitter, and a purge
callback. `OTLPReporter.reportOTLPProfile` (`reporter/otlp_reporter.go:114-141`)
shows the canonical flush: swap the tree under the write lock, stamp the
window `[collectionStartTime, now]`, generate, send. A window cut is ~10
lines and can equally be driven by an external signal instead of the ticker
-- nothing in the engine assumes periodic flushing.

`reporter/internal/pdata/generate.go` converts the tree to OTLP pprofile
pdata (per-container `ResourceProfiles`, timestamps on the wire via
`TimestampsUnixNano`, `Period = 1e9/samplesPerSecond` at `generate.go:154`).
For a pprof-file egress you would write the equivalent walk emitting
`google/pprof/profile` instead; the Datadog wrapper's
`reporter/pprof/profile_builder.go` is a complete worked example of exactly
that walk (~350 lines) and is safe to crib from.

### Integration options

**A. In-tree custom reporter (recommended).** Add
`reporter/discord_reporter.go` embedding `*baseReporter`, implement
`Start`/`Stop` with a flush that writes pprof (or whatever container we
choose) to a directory or a local socket, and add a CLI flag in
`cli_flags.go` to select it. Pros: smallest code, reuses buffering/runloop,
`internal/` packages stay reachable, ships inside the one binary we deploy.
Cons: lives on the rebase path (one new file, one flag hunk -- cheap).

**B. Out-of-tree host binary.** The Datadog wrapper pattern: a separate Go
module depends on the fork, implements `Reporter` itself, and drives
`tracer.NewTracer` + `AttachTracer` + `tracehandler` directly (the public
API is sufficient; the wrapper proves it). Pros: zero rebase surface in this
repo; the egress can live next to its consumer. Cons: you re-own the ~200
lines of controller wiring, and `internal/controller` (and its
`ReporterFactory` convenience) is not importable outside this module.

**C. Collector pipeline.** `CollectorReporter` feeds an in-process
`xconsumer.Profiles`; any OTel collector exporter (file, OTLP) can terminate
it. Pros: no code if an existing exporter fits. Cons: drags in collector
config machinery and OTLP-profiles intermediaries for what is ultimately a
local file write; least control over window boundaries.

Given the goal -- profiles as local artifacts consumed by our own tooling,
with externally-driven window cuts -- option A is the right default, with
`ExtraSampleAttrProd` carrying window/iteration identity.

### 3.5 What was actually built: `PprofFileReporter`

`reporter/pprof_file_reporter.go` implements option A. Consumed by
`misc/users/sanchda/hackweek_2026/profile_diff/` in the monorepo, which slices
these files into per-run windows and diffs them.

Enable it with `-pprof-dir`; the agent then never dials a collection agent.
Other flags: `-pprof-flush-interval` (default 10s), `-pprof-max-buffered-samples`,
`-pprof-keep-pids`, `-pprof-keep-comms`. Wiring is in a new root-level
`pprof_egress.go`, so `main.go` and `cli_flags.go` each gained one call.

Two design points worth knowing before changing it:

- **It does not embed `baseReporter`.** That path aggregates into a
  `TraceEventsTree` keyed by container/origin/`TraceAndMetaKey`. It does keep a
  timestamp list per key, so nothing is lost, but the consumer needs one pprof
  sample per raw sample -- windows are cut by filtering on per-sample timestamps
  -- and reconstructing per-sample rows from the tree is more code than
  accumulating them directly. If you make this reporter aggregate, offline
  window slicing stops working.
- **Buffer overflow is reported, not hidden.** Samples past
  `MaxBufferedSamples` are dropped, counted, and the count is written into the
  next profile's `Comments`. A lossy window that reads as a quiet one is worse
  than an error.

Labels written per sample: `ktime_ns`, `timestamp_ns`, `pid`, `tid`, `comm`,
`process_name`, `executable`, `cpu`, `container_id`, `origin`, and `off_time_ns`
when non-zero. Renaming any of them is a breaking change for the consumer.

One encoding caveat, load-bearing for anyone aggregating by `cpu`:
`google/pprof`'s encoder drops a num label whose value is 0 and which carries
no unit, so **samples taken on cpu 0 had no `cpu` label in the file** - this
applied to every origin that flowed through this reporter. Verified against the
library in isolation: `cpu=0` with no unit is absent after a round trip,
`cpu=0` with a unit survives, `cpu=7` with no unit survives. Measured in a real
16-core capture: distinct `cpu` values ran 1..15 with 0 absent entirely, at
95.3% label coverage.

**Resolved 2026-08-20 by giving `cpu`, `pid`, `tid` and `ppid` the unit `id`.**
An earlier revision of this section decided to leave it unfixed and document it,
on the grounds that emitting the unit is "a silent format change mid-dataset".
That objection is correct about the cost but is answered rather than overridden
by the fix, because **the unit is itself the version marker**:

    NumUnit["cpu"] present  -> post-fix capture; a missing `cpu` means genuinely
                               missing, and cpu 0 is present as cpu 0
    NumUnit["cpu"] absent   -> pre-fix capture; a missing `cpu` means
                               "cpu 0 or unlabeled", per the old rule

So the change is detectable per file rather than silent, which was the actual
hazard. Two further reasons it is worth taking now: the old contract asks a
consumer to conflate "cpu 0" with "no cpu label", which is not recoverable
information; and no known consumer groups by `cpu` today, so the blast radius is
at its smallest it will ever be. `pid`, `tid` and `ppid` shared the hazard and
were spared only because none is ever 0 for a sampled thread; giving them units
means that exemption stops being load-bearing.

Pinned by `TestPprofFileReporterKeepsZeroValuedIdentifierLabels`, which asserts
through a real encode/decode round trip rather than on the in-memory profile.

Found by a peer session building an unrelated BEAM instrument, which hit the
encoding while validating its own output and recognised it would land here too.

### 3.6 `KTime` now reaches the seam (a one-field change with a reason)

`TraceEventMeta` gained `KTime int64`, assigned from `bpfTrace.KTime` in
`processmanager.HandleTrace` (`manager.go`) alongside the existing `Timestamp`.

Before this, the raw kernel stamp was destroyed at that line: `Timestamp` is
`libpf.UnixTime64(times.KTime(bpfTrace.KTime).UnixNano())`, i.e. KTime plus a
boot-time offset that `times.getBootTimeUnixNano` re-estimates periodically. For
a consumer that needs exact stamps this is strictly worse than what the kernel
gave us:

- the offset carries estimation error, and across a resync two samples can
  disagree about **ordering**;
- CLOCK_MONOTONIC is the domain of everything else worth correlating against
  (perf, sched tracepoints, and a `CLOCK_MONOTONIC` reading inside the profiled
  application -- which is what Rust's `Instant` and the BEAM's monotonic time
  are);
- it is immune to NTP steps and `settimeofday`.

Both stamps are emitted, so nothing that wants wall clock loses it.

## 4. Sampling semantics: what it does today, where to change it

### Mechanics (all in `tracer/tracer.go` unless noted)

- **Frequency-mode CPU-clock sampling.** `AttachTracer` (`:1234-1272`)
  creates one perf event per **online** CPU:
  `attr.SetSampleFreq(samplesPerSecond)` (`:1241`, frequency mode -- the
  kernel adapts the period to hit N samples/sec), software event
  `PERF_COUNT_SW_CPU_CLOCK` (`:1242`, works in VMs, no PMU needed),
  `perf.Open(attr, perf.AllThreads, cpuID, nil)` (`:1254`, system-wide
  pid=-1), then `SetBPF` attaches `native_tracer_entry` (`:1259`).
  Default rate: **20 Hz** (`cli_flags.go:21`, `--samples-per-second`).
  No CPU-hotplug handling: CPUs onlined later are never attached.
- **Events are created disabled** and enabled by `EnableProfiling`
  (`:1275-1287`) -- or duty-cycled by probabilistic profiling.
- **Probabilistic profiling** (`:1293-1346`) is whole-interval duty cycling,
  not per-sample decimation: every `--probabilistic-interval` (1-5 min) it
  draws a random number and either `Enable()`s or `Disable()`s *all* perf
  events for the next interval. Off by default.
- **Off-CPU profiling** (`StartOffCPUProfiling`, `:1349-1395`): tracepoint
  `sched:sched_switch` records the switch-out timestamp (gated by
  `--off-cpu-threshold`, a probability scaled to u32 and compared against
  `bpf_get_prandom_u32()` in `support/ebpf/off_cpu.ebpf.c`); a kprobe on
  `finish_task_switch*` unwinds the switched-in thread and reports
  `TraceOriginOffCPU` with the off-time. Off by default (threshold 0).
- **Generic probes.** `--probe-link probe_type:target[:symbol]` with
  kprobe/kretprobe/uprobe/uretprobe (`tracer/probe.go`,
  `AttachProbes` `:1397`), plus `--load-probe` to load a generic program for
  external attachment. Probe hits run the full unwinder stack and surface as
  `TraceOriginProbe` samples.
- **Scheduler monitor** (`tracer/tracepoints.go:33-42`) is process-exit
  cleanup, not sampling: tracepoint `sched:sched_process_free`, with v1/v2
  program variants for the pre/post-6.16 kernel tracepoint layout selected
  by `schedProcessFreeHookName`.

### The modification map

These are the levers, in increasing order of work:

1. **On/off at runtime: already supported.** Perf events can be
   `Enable()`d/`Disable()`d live per event; `probabilisticProfile`
   (`:1293-1331`) is the in-tree prior art for toggling the whole set. A
   "sample only while a window is open" mode is a direct reuse of that loop
   driven by an external signal instead of a random draw.
2. **Rate change at runtime: small patch.** The frequency is set once at
   attach (`:1241`) and never touched again -- but the vendored go-perf
   exposes `Event.UpdatePeriod` (wrapping `PERF_EVENT_IOC_PERIOD`, which
   updates `sample_freq` for freq-mode events). Iterating
   `t.perfEntrypoints` and calling it is the same shape as
   `probabilisticProfile`. Caveat: three consumers snapshot
   `SamplesPerSecond` at startup and would misreport after a live change --
   perf ring sizing (`tracer/events.go:147`), OTLP `Period`
   (`reporter/internal/pdata/generate.go:154`), and the controller's cache
   sizing. Fallback: full `Close()` + re-`AttachTracer()` is also fine at
   our scale; attach is milliseconds.
3. **Scoping (per-PID / per-cgroup): greenfield.** Nothing filters today.
   The eBPF entry filters only idle (`pid == 0 && filter_idle_frames`,
   `support/ebpf/native_stack_trace.ebpf.c:616`, controlled by
   `--send-idle-frames`); the `pid_information_exists` check in
   `collect_trace` is process-discovery bookkeeping, not policy. Two natural
   insertion points if we ever want scoping: an allowlist map consulted at
   the top of `native_tracer_entry`, or the cgroup-fd mode of
   `perf_event_open` (the 4th argument of `perf.Open` at `:1254` -- one
   event per cgroup instead of `AllThreads`). For a host we own end to end,
   post-hoc filtering by the container ID already present on every sample is
   usually sufficient and costs nothing in kernel.
4. **New trigger sources: the seam exists.** The probe mechanism plus
   `TraceOriginProbe` is the shape for "a tracepoint that induces a check in
   the profiler": attach a probe (including a uprobe/USDT on our own
   binaries) and every hit produces a fully-unwound, origin-tagged sample.
   `loadKProbeUnwinders`-style program retyping is how off-CPU reuses the
   perf-event unwinder suite from kprobe context; a new hook class follows
   the same pattern. Known scale caveat, documented in-tree
   (`tracer/events.go` comments): the kernel-to-user pipeline is serial and
   not designed for off-CPU-class volumes -- fine for targeted probes and
   markers, not for tracing every sched switch on a busy host.

## 5. The BEAM interpreter (`interpreter/beam/beam.go`, 686 lines)

The reason this fork exists: Erlang/Elixir stack unwinding for the BEAM VM.
eBPF side in `support/ebpf/beam_tracer.ebpf.c`.

- **Detection**: executable name matches `beam.smp` (`:35`, `:134`), gated by
  `beam` in `--tracers`. Version read from the `etp_otp_release` /
  `etp_erts_version` debug symbols (`:144-157`).
- **Supported OTP**: **25, 26, 27** (shared struct offsets) and **28**
  (larger `BeamCodeHeader`, atom names become boxed `ErlHeapBits` binaries)
  -- `:269-280`. Anything else fails load with `unsupported OTP version`.
  Offsets are hardcoded per version range with links to the exact OTP source
  lines (`:52-105`, `:250-267`); an OTP upgrade means auditing that table.
- **Required symbols**, all from the **static** symbol table -- a stripped
  `beam.smp` cannot be unwound (TODO at `:161-163`): `r` (module ranges;
  matched as `r` or LTO-renamed `r.llvm.<hash>`, `:165-180`),
  `the_active_code_index`, `erts_atom_table`, `etp_ptr_mask`,
  `beam_normal_exit`, plus `etp_header_subtag_mask`/`etp_heap_bits_subtag`
  on OTP 28 (`:220-237`). `erts_frame_layout` is optional: absent means the
  runtime has no frame-pointer support and the offset is left 0 (`:239-246`,
  consumed in `Attach` `:304-309`).
- **Frame output**: full MFA with Elixir-aware formatting -- `Mod.fun/arity`
  for `Elixir.`-prefixed modules, `mod:fun/arity` otherwise (`:448-454`) --
  plus source file and line via a binary search of the module's line table
  (`findFileLocation`, `:527-614`, including a best-effort fallback past the
  last entry). Emitted as `libpf.BEAMFrame`.
- **Hot code loading works**: `SynchronizeMappings` (`:368-417`) re-walks the
  active code index's module ranges each sync, installs LPM prefixes for the
  eBPF unwinder, and GCs prefixes from unloaded generations.
- **Caches**: LRU atom cache, MFA-name cache, and Erlang-string cache
  (`:315-331`), all `LruFunctionCacheSize`.

## 6. Sharp edges

Engine:

- `StartOffCPUProfiling` **swallows a `sched_switch` attach failure**
  (`tracer/tracer.go:1388-1391` returns nil on error), leaving the kprobe
  half installed with no entry hook: off-CPU silently produces nothing.
- Only online-at-startup CPUs are sampled; no hotplug re-attach.
- Perf ring buffer, OTLP `Period`, and cache sizes snapshot
  `SamplesPerSecond` at startup (see section 4, lever 2).

BEAM:

- `findMFA`: `highIdx := uint64(numFunctions) - 1` underflows if a code
  header reports zero functions (`:494`).
- `readErlangString` caches under the *mutated* loop variable rather than
  the original address (`:683`), so the string cache can never hit; and the
  `length > maxLength` truncation branch (`:678`) is unreachable given the
  loop condition (`< maxLength`).
- Symbolization depends on the static symtab: any move to stripped BEAM
  images breaks the interpreter until the etp symbols are exported
  properly (the TODO at `:161-163`).

## 7. Working on the fork

- Build/test as upstream: `make` targets, Go >= the version in `go.mod`,
  plus the eBPF toolchain for `support/ebpf` changes. The BEAM unwinder has
  no Go tests in-tree; validation is running against a live `beam.smp` with
  `--tracers beam -v` and checking the `BEAM loaded, OTP version` /
  `BEAM attaching` log lines and symbolized frames.
- Rebase strategy: the delta is intentionally 2 commits + (soon) this doc +
  any new Discord-only files. Rebase onto upstream `main`, re-run the BEAM
  validation, then bump the pseudo-version in any consumer using the
  `replace` directive.
- Upstreaming: the BEAM interpreter is a candidate for upstream contribution
  (upstream has an open interest in new language unwinders); the egress and
  sampling changes we make for the fault-fuzzing platform are not -- keep
  them in clearly separated files so the two categories never tangle.

## Gotcha: zero-valued numeric labels are dropped unless they carry a unit

`google/pprof`'s encoder omits a numeric label that is **both zero-valued and
unit-less**. This is a property of the output format, not of any consumer, so it bites
everyone reading these files.

Verified in isolation against the library:

```
cpu=0, no unit      -> label absent after round-trip
cpu=0, unit "cpu"   -> present, value 0
cpu=7, no unit      -> present
```

In the local-pprof egress this silently swallowed **every sample taken on CPU 0** --
roughly 1/16 of a 16-core host, arriving downstream as *unlabelled* rather than as
`cpu=0`. Measured in a real capture before the fix: distinct `cpu` values ran 1..15 with
0 absent entirely, at 95.3% label coverage.

`pid`, `tid` and `ppid` shared the hazard and were spared only because none is ever 0 for
a sampled thread. All four now carry `unit "id"`, so the exemption is not load-bearing.
Pinned by `TestPprofFileReporterKeepsZeroValuedIdentifierLabels`.

**Captures taken before this fix are missing their CPU-0 samples' `cpu` label** and must
not be grouped or filtered on `cpu`; every other label is unaffected.

Found by a peer session building an unrelated BEAM instrument, which hit the encoding
while validating its own output and recognised it would land here too. Two independent
tools reading one format is the configuration that surfaces format-level bugs neither
finds alone.
