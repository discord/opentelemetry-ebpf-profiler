# The Discord fork of opentelemetry-ebpf-profiler

This repo is `github.com/discord/opentelemetry-ebpf-profiler`: upstream
`open-telemetry/opentelemetry-ebpf-profiler` plus a small Discord delta. This
document is the map a contributor needs before changing two things upstream
will not carry for us: **egress** (we need our own output path; none of this
is destined for the mainline OTel package) and **sampling semantics** (we
expect to modify how and when samples are taken). It also documents the BEAM
interpreter work, which is the reason the fork exists.

Line references below are approximate and move with the fork's HEAD: this doc
is maintained across an active hackweek series of tasks (beamscope interpreter,
pprof/socket egress, ...), not pinned to one commit. For "what changed and
when", `git log --oneline e86db84..HEAD` is more reliable than any SHA named
here.

## 1. What the fork changes

Two commits carry the upstream-facing BEAM/OTP unwinder lineage on top of a
recent upstream `main`:

| Commit | What it does |
|---|---|
| `d97b69a` "Merge forked OTP 25 support into main" | BEAM/Erlang unwinder support for OTP 25-27 (upstream lineage targeted 27/28 only): `interpreter/beam/beam.go`, a new `libpf` frame type, and small `host`/`tracer` compat shims. ~200 lines across 4 files. |
| `e86db84` "Add hack to find the 'r' symbol table when LTO is enabled" | LTO builds rename the file-local `r` symbol (BEAM's module ranges table) to `r.llvm.<hash>`; the loader now matches both spellings (`interpreter/beam/beam.go:165-180`). |

Everything on top of those two is Discord-specific and grows with each
hackweek task: the beamscope interpreter plugin (`interpreter/beamscope/`),
the pprof-file and socket egress paths (`reporter/pprof_file_reporter.go`,
`reporter/socket_sink.go`), and this doc's own sections 3.5 onward. That
growing set is mostly additive -- new files and new reporter methods, not
edits to upstream ones -- so the rebase surface against upstream `main` stays
close to the two commits above.

One change breaks that rule and is worth knowing about before a rebase. The
per-sample attribution (section 3.9, `erlang_pid_key`) needed a new field on
the eBPF `Trace` struct
and therefore touches upstream files along its whole path:
`support/ebpf/types.h`, `support/ebpf/tracemgmt.h`, `support/ebpf/extmaps.h`,
`support/types_def.go` (and the regenerated `support/types.go`),
`libpf/trace.go`, `tracer/tracer.go`, `processmanager/manager.go`,
`processmanager/ebpf/ebpf.go`, `tools/coredump/ebpf{maps,helpers}.go`, and
`interpreter/types.go` -- the last of which **adds two methods to the
`interpreter.EbpfHandler` interface**, so any out-of-tree implementation of it
must grow them too. Each edit is a handful of lines next to an existing one
(the `offtime` field, the `OffTime` copy, the `beam_procs` map), so the
conflicts are mechanical, but they are not zero.

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

### 3.5 What was actually built: the local egress

`reporter/local_egress.go` (`LocalEgressReporter`) plus its pprof backend in
`reporter/pprof_file_reporter.go` implement option A. Consumed by
`misc/users/sanchda/hackweek_2026/profile_diff/` in the monorepo, which slices
these files into per-run windows and diffs them.

The local egress assembles each sample ONCE -- frames flattened, lineage
resolved on the reporting path, keep filters and comm trim applied -- and fans
that one `sampleEvent` out to whichever backends are enabled: pprof files
(`-pprof-dir`), the socket stream (`-socket-egress`, section 3.7), or both.
Either backend runs without the other; with neither, the agent ships OTLP as
upstream does.

Enable pprof files with `-pprof-dir`; with either local backend the agent never
dials a collection agent.
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
Emitting the unit does change the format mid-dataset, but detectably, because
**the unit is itself the version marker**:

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

### 3.7 Socket egress: the same samples, streamed live

`reporter/socket_sink.go`. Enable with `-socket-egress <path>`. It is
INDEPENDENT of `-pprof-dir`: socket-only, pprof-only and both all work, and with
both **pprof files keep being written, unchanged**. Consumed by
`profile_store/crates/pstore-ingest` in the monorepo.

**Why it exists.** The pprof reporter flushes on a timer (5s in the harness)
but fuzzer iterations run 1-3s, so an iteration can sit entirely inside one
flush and per-iteration windows cannot be cut. The flush interval is a
file-size knob, not a resolution knob, and no offline slicing recovers a window
that was never a window. The socket path removes the file-flush latency floor:
measured sample-to-queryable is p50 9.95ms / p99 30.3ms.

**Why it has no decode of its own.** The local egress's assembler has already
resolved everything that matters into one `sampleEvent` -- frames flattened out
of the interned tables, lineage read while the process still exists,
comm/container/pid/tid/ktime -- and this sink emits from that exact value. That
is what makes the two paths structurally identical rather than merely intended
to agree: there is no second decode to drift. **Do not give the socket its own
decode.** (It used to be a field inside the pprof reporter, reading that
reporter's buffer-path event; that is why it could not run without
`-pprof-dir`.)

**Latency.** Every sample is flushed to the socket as it is written, so the
producer-side floor is one write syscall, not a flush period.
`-socket-egress-flush-interval` survives only as a safety net (nothing may sit
in the write buffer indefinitely) and normally finds an empty buffer. The write
deadline that unwedges a consumer which accepts but never reads has its own
knob, `-socket-egress-write-timeout` (default 1s, clamped to 250ms..5s); it used
to be 20x the flush interval, a derivation that stopped meaning anything once
records no longer wait for a flush.

**It never blocks the agent.** `offer()` is a non-blocking channel send;
everything past the channel is one writer goroutine. A slow or absent consumer
costs samples, not latency -- the alternative is the profiler stalling the box
it is measuring. Measured: with the consumer reading nothing for 1.5s and a
256-slot ring, 40,000 produced / 2,161 emitted / 37,839 dropped, and the
sampling path never stalled.

**It is never silently lossy.** Every drop is counted, the count rides on the
wire next to the gap it describes, the absolute totals are restated
periodically, and -- when the pprof backend is also enabled -- they are written
into the pprof file's `Comments` so the archive and the stream cross-attest. In
a socket-only run there is no archive to attest to, so the STATS records and the
loss warning carry the signal instead; no combination loses it.

#### Wire format (version 1)

All integers **little-endian**. Consumer listens, agent dials and reconnects.
The normative copy of these constants is `reporter/socket_sink.go`; the
consumer's mirror is `pstore-ingest/src/wire.rs`. Keep all three in step.

A connection is a header followed by records:

    <stream header, header_len bytes>
    <record>*

**Stream header, 32 bytes in v1:**

| off | size | field |
|---|---|---|
| 0  | 8 | magic `PSTRSOK1` (ASCII, no terminator) |
| 8  | 2 | `u16` version = 1 |
| 10 | 2 | `u16` header_len = 32. A reader consumes exactly this many bytes, so a later version can grow the header without breaking framing. |
| 12 | 4 | `u32` stream flags; bit 0 = frames are LEAF-FIRST (always set in v1) |
| 16 | 4 | `u32` samples_per_second |
| 20 | 4 | `u32` max_frames, the per-sample frame cap |
| 24 | 8 | `i64` CLOCK_MONOTONIC ns at connection open |

**Record:**

    u32 payload_len   // bytes that follow, INCLUDING the rec_type byte
    u8  rec_type
    u8  payload[payload_len - 1]

The length prefix is what makes an unknown `rec_type` skippable, so the format
can grow without a flag day.

**`rec_type = 1` STRDEF** -- one entry of the per-connection string table:

| off | size | field |
|---|---|---|
| 0 | 4 | `u32` id, dense from 1. **Id 0 always means the empty string.** |
| 4 | 4 | `u32` byte_len |
| 8 | n | UTF-8 bytes, no terminator |

A STRDEF always precedes the first record referencing it, because interning
happens on the writer goroutine -- downstream of the only lossy point in the
design -- so a reference can never dangle. The table resets on reconnect.
Measured on a real 479,660-sample capture: 101,788 STRDEFs cover 5.8M frame
references.

**`rec_type = 2` SAMPLE** -- one raw sample, never aggregated. Fixed part 80 bytes:

| off | size | field |
|---|---|---|
| 0  | 8 | `i64` ktime_ns (`bpf_ktime_get_ns`, CLOCK_MONOTONIC) |
| 8  | 8 | `i64` unix_ns (derived CLOCK_REALTIME; carried, never compared against ktime) |
| 16 | 8 | `i64` off_time_ns. **Meaningful only for `origin = 2` (off_cpu).** It reads 0 for `origin = 4` (beamscope), whose own measurement lives in `value`/`value_kind` below -- the two-column reporter once smuggled it through this field, the five-column one does not (see 3.8). |
| 24 | 4 | `i32` pid |
| 28 | 4 | `i32` tid |
| 32 | 4 | `i32` cpu |
| 36 | 4 | `u32` **dropped_since_prev** |
| 40 | 4 | `u32` comm -> string id |
| 44 | 4 | `u32` process_name -> string id |
| 48 | 4 | `u32` executable -> string id |
| 52 | 4 | `u32` container_id -> string id. **0 = no cgroup, meaning a HOST process** (dockerd, falco, kernel threads, the agent itself) -- never "missing data". |
| 56 | 1 | `u8` origin: 1 sampling, 2 off_cpu, 3 probe, 4 beamscope. Numbered independently of libpf's so an upstream renumbering cannot silently relabel a capture. |
| 57 | 1 | `u8` flags; bit 0 = frame list TRUNCATED |
| 58 | 2 | `u16` n_frames |
| 60 | 2 | `u16` n_labels |
| 62 | 1 | `u8` value_kind: 0 none, 1 alloc words, 2 sched nanoseconds, 3 msgs count. Numbered independently of `samples.ValueKind*` for the same reason `origin` is. |
| 63 | 1 | `u8` reserved, must be 0 |
| 64 | 8 | `i64` value -- the sample's own measurement, in the unit `value_kind` names. **Written as 0 whenever `value_kind` is 0**, so a consumer can never find a number here it might mistake for a measurement. |
| 72 | 8 | `u64` erlang_pid_key -- raw Erlang pid Eterm (section 3.9), 0 when unattributable. Never "pid 0". |

then `n_frames` x 12 bytes, **leaf-first** (as the tracer delivers them and as
the pprof writer orders `Location`): `u32 func_str`, `u32 file_str`, `i32 line`.

then `n_labels` x 24 bytes, **sorted by key**, so two identical captures
serialize byte-identically:

| off | size | field |
|---|---|---|
| 0 | 4 | `u32` key -> string id |
| 4 | 4 | `u32` value -> string id (string labels; 0 for numeric) |
| 8 | 4 | `u32` unit -> string id (numeric labels; 0 for string) |
| 12 | 1 | `u8` kind: 0 string, 1 numeric |
| 13 | 3 | reserved, must be 0 |
| 16 | 8 | `i64` num (numeric labels; 0 for string) |

A label whose key is one the reporter assigns itself (`comm`, `origin`, `pid`,
... -- the contract keys of 3.6) is **skipped**, exactly as the pprof path skips
it: a traced process must not be able to overwrite the reporter's own values by
emitting a custom label of that name. Numeric promotion applies to
beamscope-origin samples only, using the same unit table the pprof writer uses,
so the two backends produce the same labels for the same event.

**The socket is beamscope-complete.** As of v2 it carries all four of the things
v1 could not: `value`, `value_kind`, `erlang_pid_key`, and custom labels. So
`-beamscope` is satisfied by **either** local backend, and a socket-only capture
is a whole capture rather than one silently stripped of everything
beamscope-specific. `TestSocketBeamscopeSampleMatchesPprof` compares the two
backends field for field on the same event; that equivalence is the contract.

What still does not satisfy `-beamscope` is having no local egress at all: the
OTLP path aggregates on the trace hash and freezes per-sample labels at first
insert, which is wrong data rather than missing data.
A consumer building a root-first folded key reverses.

**`rec_type = 3` STATS** -- the producer's counters, 80 bytes: `i64 ktime_ns`,
`i64 unix_ns`, then `u64` x 8: produced, emitted, dropped_ring, dropped_nosock,
truncated_frames, bytes_written, strings_defined, connect_errors.

Emitted right after the header (so a consumer attaching mid-run learns exactly
what it missed), periodically, and immediately before a clean close.
`produced >= emitted + dropped_ring + dropped_nosock` **always**; equality holds
only at a quiescent point, because `produced` is incremented on the sampling
path while STATS is written by the serializing goroutine. The difference is
in-flight samples, and at the FINAL stats it must be zero -- anything else is
samples lost at close without being counted as dropped.

#### Truncation is described twice, on purpose

- **Samples lost** -- `SAMPLE.dropped_since_prev` puts the count next to the gap
  it describes; STATS carries the exact absolute total. Per-record attribution
  is exact to within one writer iteration, the total is exact.
- **Frames lost** -- the `FRAMES_TRUNCATED` sample flag. The pprof path never
  truncates, so such a sample is NOT comparable with its pprof twin, and a
  consumer asserting equivalence must refuse a stream carrying any.

#### Byte budget, measured

231.9 B/sample on the wire over a real 65,021-sample capture (214.2 in SAMPLE
records, 17.7 amortised STRDEF), against 32.5 B/sample for the gzipped pprof of
the same samples. The wire is 7.1x the archive because it is uncompressed and
per-sample; at the profiler's measured 2,465 samples/s that is 572 KB/s over a
unix socket, which is not a constraint.

#### Equivalence is the acceptance test

`profile_store/crates/pstore-ingest/tests/equivalence.rs` replays real captures
through `ReportTraceEvent` with both egresses attached, folds the pprof with
`profile_diff`'s own Go `internal/fold.Fold`, ingests the stream, and requires
the two flame graphs to be EXACTLY equal -- same key set, bit-identical weights,
in total and per container. Verified over 40 real captures / 479,660 samples /
124,937 distinct stacks / 93 containers, under four fold projections. If the
two paths ever disagree, that is the finding; do not relax the test.

### 3.8 Honest multi-column values: retiring the `OffTime` smuggle

Before this task, the pprof backend wrote a two-column `SampleType`
(`{samples,count}`, `{cpu,nanoseconds}`) for **every** origin, but a
beamscope-origin sample's own value (allocated words for a GC sample,
on-scheduler nanoseconds for a SCHED_DELTA sample) was smuggled directly into
that same cpu-nanoseconds slot: `s.Value = {1, ev.offTime}`, reusing
`TraceEventMeta.OffTime` as a generic value channel. `SampleType` still said
`cpu`/`nanoseconds`, so any consumer that summed column 1 across a mixed
capture silently added alloc-word counts and cpu nanoseconds together.

The fix is a wider, honest sample:

```
SampleType = [{samples,count}, {cpu,nanoseconds}, {alloc,words},
              {sched,nanoseconds}, {msgs,count}]
DefaultSampleType = "cpu"
```

`TraceEventMeta` gained a real value channel, separate from `OffTime`:
`Value int64` and `ValueKind uint8` (`samples.ValueKindNone/Alloc/SchedNS/Msgs`).
`OffTime` is once again exclusively the off-CPU sample's off-scheduler
nanoseconds -- beamscope never sets it.

This was a real loss on the socket path until wire v2: v1 carried `off_time_ns`
but not `value`/`value_kind`, so where a two-column-era socket consumer read a
beamscope sample's value out of `off_time_ns`, it got 0 and no other field held
it. **v2 carries `value` and `value_kind` as their own fields** (section 3.7),
so both backends now express the same measurement -- the file in its own column,
the wire in its own field.

The fill rule, exactly one measurement column non-zero per sample:

| Origin | Value | Notes |
|---|---|---|
| CPU (sampling/probe) | `{1, periodNs, 0, 0, 0}` | unchanged from before this task |
| off-CPU | `{1, 0, 0, 0, 0}` | off-scheduler time is not cpu time, so column 1 stays 0; the value still rides the `off_time_ns` label, as before |
| beamscope, `ValueKindAlloc` | `{1, 0, value, 0, 0}` | GC_DELTA/GC_DELTA2, `beamscope_kind=alloc` |
| beamscope, `ValueKindSchedNS` | `{1, 0, 0, value, 0}` | SCHED_DELTA, `beamscope_kind=sched` |
| beamscope, `ValueKindMsgs` | `{1, 0, 0, 0, value}` | MSG_FLOW, `beamscope_kind=msg` (new this task) |

MSG_FLOW's `value` is its raw arrival count scaled by the currently-latched
SCOPE_CONFIG's `recv_sample_shift` at drain time (`ArrivalsRaw << shift`,
`interpreter/beamscope/drain.go`'s `reportMsgFlow`); if no usable config is
held yet (none seen, one that predates the field at `PayloadLen < 48`, or
`recv_sample_shift >= 63` meaning receive tracing is off), no pprof sample is
synthesized for that record -- the raw MSG_FLOW still reaches the JSONL
sidecar either way, so nothing is silently dropped from the artifact, only
from the pprof projection of it.

**Version marker.** A consumer must not assume column 1 is pure cpu-ns
without checking which shape it is reading: the presence of the `alloc`
`SampleType` entry (`p.SampleType[2].Type == "alloc"`) identifies a five-column
capture, exactly the same trick as the `id` unit on the `cpu` label in section
3.5 -- a per-file, detectable version bump rather than a silent format change.
A two-column file has only two `SampleType` entries and mixed alloc/sched mass
in column 1.

**Custom labels are no longer beamscope-only.** The local egress now
carries `trace.CustomLabels` for every origin (previously gated to
`TraceOriginBeamScope`), in preparation for a later task attaching labels to
CPU-origin samples. The numeric-label unit table (`numLabelUnits`, named
`beamscopeNumLabelUnits` when this task landed) was unchanged at the time; no
CPU-origin numeric labels existed yet. Section 3.9 adds the first one.

**Known follow-up:** `profile_diff`'s `fold` currently reads
whatever sits in `Sample.Value[1]` and treats it as cpu-nanoseconds
unconditionally. Against a five-column capture that is still correct for
CPU/off-CPU samples (columns 0/1) but silently reads zero for every beamscope
sample (whose mass moved to columns 2-4) instead of erroring -- the opposite
failure mode from the pre-fix mixing bug, but still wrong for anyone folding a
mixed capture. `fold` needs to select the cpu column by `SampleType` name
before consuming new captures (tracked as a later task). Any capture taken
between this task landing and that fix should be scored only against a `fold`
that has picked up the name-based column selection, not blindly re-run through
the old positional one.

### 3.9 Per-sample Erlang process attribution: the `erlang_pid_key` label

A CPU sample taken inside a BEAM VM tells you which C stack the emulator was
executing. It does not tell you **which Erlang process** that work belonged to,
and in a VM running hundreds of thousands of processes that is the only
attribution anybody actually wants. Section 3.9 adds it: every CPU-origin sample
whose thread is a BEAM scheduler carries a numeric pprof label

```
erlang_pid_key  <raw Eterm>   unit: id
```

which is the same 64-bit pid term beam_scope stamps on every JSONL record and
PROC_META name, so a capture and a beam_scope sidecar join on it directly.
(The fold-side naming join is a later task.)

#### Why the read is coherent

At sample time the eBPF program reads `esdp->current_process` for the
scheduler thread it interrupted, and dereferences it to
`Process.common.id`.

The perf interrupt runs on the CPU that is executing that scheduler thread,
and the **only** writer of `current_process` is that same thread
(`erl_process.c`: `esdp->current_process = p;` in `schedule()`, and the
`= NULL` stores in the exit paths, all executed by the scheduler itself). We
are stopped inside it. So the read is quiescent: there is no concurrent writer
to tear against, and no lock to take.

What remains is staleness, bounded by dispatch latency -- the window between a
scheduler picking a process and assigning the field. Three checks turn that
window, and the identity problem below it, into a *missing* label instead of a
*wrong* one:

- **null check.** `current_process == NULL` means the scheduler is between
  processes. No label.
- **pid tag check.** `(id & 0xF) != 0x3` means the word is not an internal pid
  (`_TAG_IMMED1_PID`, `erl_term.h`). A torn or half-initialised
  `Process` cannot pass it. No label.
- **tgid check.** `beam_sched_tids` is keyed by **global kernel tid**, and
  kernel tids are reused. Coherence and tagging say nothing about *whose*
  address space we are reading: if a `Detach` is ever missed -- a dropped
  process-exit notification, which is an unbounded window -- an unrelated
  thread can inherit a mapped tid, and then both reads happen at a dead VM's
  addresses inside the new process. Those addresses may well be mapped, and a
  word passes the tag check roughly 1 in 16 times, so this is exactly the
  plausible-but-wrong label everything else here is built to avoid. So each
  entry carries the tgid it was written for (in what used to be `BeamSchedInfo`
  padding, so no ABI size change) and `beam_stamp_current_process` bails when
  the sampled pid is not that one. Without this binding the "never a wrong
  label" claim would be false.

Zero is never emitted: `erlangPidKey == 0` omits the label entirely, so
"unattributable" and "pid 0" are not made to look alike downstream.

CPU-origin only. Off-CPU and probe traces are not "what this scheduler is
running now", so stamping `current_process` on one would be a wrong label
rather than a missing one; `collect_trace` gates on `origin == TRACE_SAMPLING`.

#### The tripwire, and why the stride is measured rather than tabulated

All version knowledge lives in user space (`interpreter/beam/beam_sched.go`);
the eBPF side (`support/ebpf/beam_sched.h`) does two pointer reads and a tag
check and has no way to fail safely, so it is never given a choice. At attach
the interpreter:

1. resolves `erts_aligned_scheduler_data`,
   `erts_aligned_dirty_cpu_scheduler_data`, `erts_no_schedulers` and
   `erts_no_dirty_cpu_schedulers` from `beam.smp`'s `.symtab` (best effort: a
   stripped emulator simply loses the label);
2. scans `/proc/<pid>/task/*/comm` for scheduler threads;
3. **validates the layout before writing a single map entry**;
4. writes one `beam_sched_tids` entry per validated scheduler tid, keyed by
   kernel tid.

The invariant the tripwire uses is fixed at VM start and never changes
(`erl_process.c`, `init_scheduler_data(esdp, ix+1, ...)` for every `ix`,
L5912-L5934 at OTP-25.3.2.7). It gives **two** constraints per scheduler, not
one -- whichever of the two number fields is the index, the other is
explicitly zeroed:

| array | invariant |
|---|---|
| `erts_aligned_scheduler_data[i]` | `.no == i+1` **and** `.dirty_no == 0` (L5931-L5932) |
| `erts_aligned_dirty_cpu_scheduler_data[i]` | `.dirty_no == i+1` **and** `.no == 0` (L5913, L5920) |

Requiring it across the whole array also *derives* the array stride, which is
the part that cannot be honestly tabulated.
`sizeof(ErtsAlignedSchedulerData)` is dominated by `ErtsAuxWorkData` and
`ErtsAtomCacheMap` and depends on build-time macros; it measured **41728
bytes** on OTP 25.3.2.7 / erts-13.2.2.4 (nix, x86_64), a number no amount of
header reading would have produced with confidence. So `probeAlignedStride`
walks candidate strides in 64-byte steps (`ERTS_ALC_CACHE_LINE_ALIGN_SIZE`)
looking for one that satisfies the invariant everywhere.

**Acceptance requires uniqueness, and this matters most exactly where the
probe is weakest.** At `n == 2` the search sees only `esdp[1]`, so the whole
question reduces to "is there a 64-aligned word that looks like scheduler 2?"
-- asked of several hundred words *inside scheduler 0's own struct*, where a
small integer like 2 is entirely plausible. Both defences exist for that case:

- the second, zeroed number field, which a stray `2` in unrelated data has no
  reason to be accompanied by; and
- a full scan of the candidate range, accepting only if **exactly one** stride
  matches. Two matches disables the feature rather than picking one.

Uniqueness cannot reject the true stride `S` **of a homogeneous array**: any
multiple `k*S` reads `esdp[k*i]` at index `i`, whose index field is `k*i+1`,
differing from `i+1` for every `i >= 1`. So no multiple of `S` can also match,
and a second match can only be an unrelated coincidence -- which is precisely
the thing that must not be silently resolved in favour of a guess. (Earlier
revisions of this section claimed the *first* match was provably the true
stride. That was only true across multiples of `S`, which is not the whole
candidate set.)

The residual cost of that strictness is that a 2-scheduler VM can occasionally
disable itself on a coincidence. That is the intended direction; a missing
label is recoverable, a wrong pid is not. `TestProbeAlignedStride` pins all
three outcomes (true stride accepted, half-decoy rejected by the zero field,
full decoy disabling) against a synthetic address space.

#### Only the normal array may be probed (the dirty-IO aliasing)

"Homogeneous" above is load-bearing, and the dirty arrays are not.
`erts_aligned_scheduler_data` is exactly `erts_no_schedulers` elements indexed
`1..n` with no gaps. The dirty arrays share **one** allocation of
`no_dirty_cpu + no_dirty_io` elements --

```c
erts_aligned_dirty_io_scheduler_data =
    &erts_aligned_dirty_cpu_scheduler_data[no_dirty_cpu_schedulers];
```

(`erl_process.c` L6193-L6212 @OTP-25.3.2.7) -- and the IO half **restarts
`dirty_no` at 1**. Probing the dirty-CPU array therefore has a *systematic*
false match at `k = no_dirty_cpu + 1`: element `k` is `dirty_io[1]`, whose
`dirty_no` is 2 and whose `no` is 0, indistinguishable from `dirty_cpu[1]` by
any local test. This is not hypothetical -- adding the uniqueness rule
immediately produced, on a real VM at `+SDcpu 2:2` (10 dirty-IO schedulers by
default):

```
ambiguous scheduler array stride: both 41728 and 125184 satisfy the layout
tripwire for 2 schedulers
```

`125184 == 3 * 41728`, exactly `(no_dirty_cpu + 1) * S`. So the dirty-CPU array
is never probed: the stride is measured on the homogeneous normal array and the
dirty array is **verified** at it (`verifyDirtyCPUArray`), which is a full
tripwire over every dirty-CPU element, just at a known stride rather than a
searched one. If the normal array has only one scheduler there is no measured
stride, and dirty-CPU attribution with more than one dirty scheduler is
disabled rather than guessed. `TestVerifyDirtyCPUArray` reproduces the aliasing
synthetically so this does not depend on having a VM to hand.

A single scheduler (`+S 1`) carries no discriminating information, and needs
none -- only `esdp[0]` is ever addressed, and it is still checked against both
constraints. The probe reports `strideUndetermined` (0) in that case rather
than a plausible-looking number it did not measure; `(num-1) * 0` addresses
the base either way.

#### Offsets table

Hand-derived from `erts/emulator/beam/erl_process.h` and confirmed empirically
against a live OTP 25 VM (`TestBeamSchedLiveAttach`). The prefix of
`struct ErtsSchedulerData_` is byte-identical at **OTP-25.3.2.7**,
**OTP-26.2.5.9**, **OTP-27.3.4.6** and **OTP-28.0.2**, so one row covers all
four:

| field | offset | derivation |
|---|---|---|
| `current_process` | 168 | 7 pointers/`ethr_tid` (56) + `ErtsThrPrgrData` (104) + `ssi` (8) |
| `no` | 184 | `current_process` (8) + `ErtsSchedType type` (4) + 4 pad |
| `dirty_no` | 192 | `no` (8) |

`ethr_tid` is `pthread_t` (8 on LP64,
`erts/include/internal/ethread.h:132`). `ErtsThrPrgrData` is 104 bytes; its
only conditional member (`is_delaying`) sits behind `ERTS_ENABLE_LOCK_CHECK`,
a debug build option, and the struct is unchanged across all four tags
(`erts/emulator/beam/erl_thr_progress.h`). `Process.common.id` is at offset 0:
`struct process` opens with `ErtsPTabElementCommon common; /* *Need* to be
first in struct */` (`erl_process.h:1007`) whose first member is `Eterm id`
(`erl_ptab.h`).

OTP 25 (erts 13.x) is the first-class, required target. 26/27/28 are listed
because the same derivation holds byte-for-byte at those tags; anything else
is absent from the table and cleanly disables.

#### Disable semantics

Every failure is a disable, logged, never a guess and never a partial state:

| condition | effect |
|---|---|
| OTP release not in `schedOffsetsByOTP` | feature off for that VM, warned once per `beamData` |
| `beam.smp` stripped of the scheduler symbols | feature off for that VM, warned once per `beamData` |
| tripwire fails on the normal array (wrong offsets, unreadable memory, implausible `erts_no_schedulers`) | feature off for that VM, warned; **no map entries written** -- the validation completes before the first write |
| tripwire fails on the dirty-CPU array only | dirty-CPU attribution off, normal schedulers unaffected |
| more than one dirty-CPU scheduler but the normal array has only one (no measured stride) | dirty-CPU attribution off, normal schedulers unaffected |
| no scheduler threads found in `/proc` | feature off for that VM, **warned** (schedulers exist before any Erlang code runs, so this should be impossible and would otherwise be a silent loss) |
| individual map update fails | that tid skipped; the rest proceed |
| a stale entry survives (missed `Detach`) and its tid is reused | no label on the unrelated thread: the entry's tgid does not match the sampled pid (see the tgid check above). Not a disable -- a per-sample miss |

Dirty-IO schedulers are deliberately never attributed: they are blocked in
syscalls by construction, so a CPU sample on one is not Erlang execution.
Dirty-CPU schedulers *are*, and they share the normal schedulers' struct and
therefore their stride -- which is why the stride measured on the normal array
is the one used to address them (see the dirty-IO aliasing above).

On `Detach` the instance's tids are removed from `beam_sched_tids`. Kernel
tids are reused; a leaked entry would eventually attribute an unrelated
thread's samples through a dead VM's addresses.

**`beam_sched_tids` is loaded unconditionally**, unlike `beam_procs`.
`collect_trace` reads it and is inlined into `native_tracer_entry`, which is
always loaded, so a map gated on `-tracers beam` would leave that program with
an unresolvable map reference and the whole agent would fail to start without
the BEAM tracer. It is `BPF_F_NO_PREALLOC` and empty on any host not running a
BEAM, and it is only ever written from user space, so the non-preallocated
allocation path is never entered from a sampling context.

#### Thread comms are not what you would guess

The scheduler thread names are `"<N>_scheduler"`,
`"<N>_dirty_cpu_scheduler"`, `"<N>_dirty_io_scheduler"` (`erl_process.c`,
`erts_snprintf(opts.name, ...)`), and the kernel truncates `comm` to 15 bytes,
so the dirty ones arrive already cut. Observed on OTP 25.3.2.7 /
erts-13.2.2.4, x86_64, `erl -noshell +S 4:4 +SDcpu 2:2`:

```
1_scheduler  2_scheduler  3_scheduler  4_scheduler
1_dirty_cpu_sch  2_dirty_cpu_sch
1_dirty_io_sche  2_dirty_io_sche ... 10_dirty_io_sch
1_aux  0_poller  async_1  sys_msg_dispatc  sys_sig_dispatc  beam.smp
```

`parseSchedComm` therefore prefix-matches the dirty names and requires at
least `dirty_c` before it will call one a dirty-CPU scheduler -- confusing
`dirty_cpu` with `dirty_io` would index the wrong half of a shared allocation.
There is no `erts_`-prefixed form on Linux.

#### Where it shows up, and what did not change

`Trace.erlang_pid_key` (eBPF) -> `libpf.EbpfTrace.ErlangPidKey` ->
`samples.TraceEventMeta.ErlangPidKey` -> pprof num label, following the
`KTime` precedent exactly (section 3.6). It is **not** a string
`CustomLabel`: the eBPF custom-label array is a scarce fixed-size resource and
a decimal string would be lossy to re-parse.

Two things this task did not touch:

- **The socket wire format (section 3.7) does not carry it.** Version 1's
  fixed header has no room -- a `u64` term does not fit the one spare `u32` --
  so a socket consumer that needs the attribution reads the pprof files. Same
  gap as section 3.8's `value`/`valueKind`; both are listed under "What v1 does NOT
  carry" in 3.7.
- **The OTLP reporter does not emit it.** Only the local egress's pprof backend
  does.

#### Validating it end to end (needs root)

`TestBeamSchedLiveAttach` (`interpreter/beam/beam_sched_test.go`) covers the
whole user-space half against a real VM without root -- it starts `erl` as a
child, so it may read the child's memory under `yama/ptrace_scope=1` -- and
performs exactly the two reads the eBPF side performs. It skips when there is
no local `erl`.

The eBPF half needs a privileged agent run:

```sh
# 1. build the agent. The committed tracer objects already contain
#    erlang_pid_key, so `make -C support/ebpf` is only needed if you changed
#    the eBPF C (and see the section 7 banner about the clang pin first).
go build .

# 2. a VM with a busy process pinned to scheduler 1
erl -noshell +S 4:4 +SDcpu 2:2 \
    -eval 'spawn_opt(fun Loop() -> Loop() end, [{scheduler,1}]), timer:sleep(600000)' &

# 3. profile it
sudo ./ebpf-profiler -tracers beam -pprof-dir /tmp/prof \
     -pprof-flush-interval 5s -samples-per-second 997
```

Then, over the resulting profile: at least 90% of the samples whose `tid`
label is the `1_scheduler` thread must carry an `erlang_pid_key`, all equal to
the spinner's term; and samples on non-scheduler tids (`1_aux`, `0_poller`,
`beam.smp`) must carry none. The remaining <10% is real: it is the scheduler
in its own dispatch or bookkeeping code with `current_process` null.

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

## 5. The BEAM interpreter (`interpreter/beam/beam.go`, 707 lines)

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
- **Per-sample Erlang process attribution** lives in a sibling file,
  `interpreter/beam/beam_sched.go`, and is independent of unwinding: it can be
  disabled for a VM (stripped symbols, unknown OTP, failed tripwire) with no
  effect on stacks. See section 3.9.

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
  properly (the TODO at `:161-163`). The same applies, separately, to
  `erlang_pid_key` (section 3.9), which loses its four scheduler symbols
  there and disables itself.
- The `erlang_pid_key` stride probe costs up to 4096 8-byte
  `process_vm_readv` calls **per array** per BEAM process at attach -- the
  full candidate range, because acceptance requires uniqueness (section 3.9)
  and so cannot stop at the first match. Paid once per process, but a host
  churning through short-lived VMs pays it repeatedly, **and it runs inside
  `ProcessManager.mu`'s write lock** (`processinfo.go` calls
  `handleNewInterpreter`, and thus `Data.Attach`, between `pm.mu.Lock()` and
  `pm.mu.Unlock()`), so those remote reads serialize process discovery for
  their duration.
- **The committed `support/ebpf/tracer.ebpf.{amd64,arm64}` already carry the
  field.** They were rebuilt and committed, and verified by `readelf`/BTF/
  disassembly to contain `beam_sched_tids`, `BeamSchedInfo`, and the store of
  `erlang_pid_key` at offset 720 (`*(u64 *)(r9 + 0x2d0) = r1`). No rebuild is
  needed to receive traces. See the banner at the top of section 7 for which
  clang built them and what that does and does not establish.

## 7. Working on the fork

> **The committed eBPF objects were relinked with clang-16, not the
> Makefile's default clang-17.** `support/ebpf/tracer.ebpf.{amd64,arm64}`
> include the `Trace.erlang_pid_key` field (section 3.9); they were built with
>
> ```
> make -C support/ebpf BPF_CLANG=clang-16 BPF_LINK=llvm-link-16 \
>      STRIP=llvm-strip-16 LLC=llc-16 [TARGET_ARCH=arm64]
> ```
>
> because no clang-17 was available. clang-16 is what this project built with
> before upstream PR #270 bumped the pin, and that bump names no feature
> requirement; measured here, the clang-16 object is +0.07% instructions
> against the clang-17 one (33,066 vs 33,042) with the new field included, so
> codegen is equivalent and nowhere near a verifier limit. Two things this
> does NOT establish: byte-reproducibility against a clang-17 build (relink
> with 17 if you want the canonical artifact), and BPF verifier acceptance,
> which needs one privileged run.
>
> If the objects ever fall behind the Go-side `support.Trace` again, the
> failure is loud rather than silent: `loadBpfTrace` rejects the first sample
> and `tracer/events.go` tears the receive loop down with
>
> ```
> Stop receiving traces: <got> < <want>: trace record too small
> ```

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

`erlang_pid_key` (section 3.9) carries `unit "id"` for the same reason, but
also sidesteps the hazard from the other end: a zero Eterm means
"unattributable", so the label is omitted rather than emitted as 0. An absent
`erlang_pid_key` therefore always means "no attribution", never "pid 0".

**Captures taken before this fix are missing their CPU-0 samples' `cpu` label** and must
not be grouped or filtered on `cpu`; every other label is unaffected.

Found by a peer session building an unrelated BEAM instrument, which hit the encoding
while validating its own output and recognised it would land here too. Two independent
tools reading one format is the configuration that surfaces format-level bugs neither
finds alone.
