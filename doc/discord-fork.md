# Discord profiler additions

This branch adds a standalone agent, local pprof and Unix socket output,
beam_scope runtime instrumentation, and Erlang process attribution to the
Discord fork of opentelemetry-ebpf-profiler. The base branch supplies OTP25
unwinding and LTO symbol lookup support.

## Build and run

Use the Go version in `go.mod` and LLVM 17 for eBPF builds. The standalone
agent remains available here even though upstream main removed it.

```sh
go build -o ebpf-profiler .
sudo ./ebpf-profiler -tracers beam -samples-per-second 997 \
  -pprof-dir /tmp/profiles -pprof-flush-interval 5s
```

`-socket-egress /path/to/consumer.sock` streams samples to a listening consumer.
Either local backend can run alone, or both can run together. With neither,
the standalone agent uses the OTLP reporter. `-pprof-keep-pids` and
`-pprof-keep-comms` apply to both local outputs.

`-beamscope` enables discovery of the beam_scope NIF's shared memory and
requires at least one local output. `-beamscope-jsonl-dir` optionally saves
runtime records alongside the profiles; `-beamscope-poll-interval` defaults
to 250ms. `-metrics-file` writes the profiler's own metrics as JSONL.
See `-help` for buffer limits, intervals and socket deadlines.

## Reporter integration

`reporter.NewLocalEgress` implements `reporter.Reporter`. Each call to
`ReportTraceEvent` becomes one immutable event shared by the enabled sinks:
frames are flattened, labels copied, filters applied, and process lineage
resolved before buffering. Files and socket streams preserve individual
event timestamps rather than aggregating equal stacks.

Main uses `TraceEventMeta.ProfileType` and `Value` to describe measurements;
kernel origin IDs are allocated dynamically and are not wire origin codes.
The local reporter classifies periodic CPU, off-CPU, probe and beamscope
metadata. `samples.BeamScopeProfile` supplies allocation, scheduler and
message profile metadata. OTLP aggregation rejects those beamscope types
because their labels vary per event.

`KTime` is CLOCK_MONOTONIC nanoseconds; `Timestamp` is the wall-clock
conversion. Use KTime when correlating with kernel or application monotonic
clocks. Clock resynchronization can change the wall-clock offset.

The five pprof value columns are:

| Measurement | samples/count | cpu/ns | alloc/words | sched/ns | msgs/count |
|---|---:|---:|---:|---:|---:|
| Periodic CPU sample | 1 | sampling period | 0 | 0 | 0 |
| Probe event | 1 | 0 | 0 | 0 | 0 |
| Off-CPU interval | 1 | 0 | 0 | 0 | 0 |
| Allocation delta | 1 | 0 | value | 0 | 0 |
| Scheduler delta | 1 | 0 | 0 | value | 0 |
| Message arrivals | 1 | 0 | 0 | 0 | value |

Off-CPU duration is carried in the `off_time_ns` label. Contract labels include
`ktime_ns`, `timestamp_ns`, `pid`, `tid`, `ppid`, `ancestry`, `comm`,
`process_name`, `executable`, `cpu`, `container_id`, `origin`, and
`erlang_pid_key` when available. Custom labels cannot replace these keys.
Numeric ID labels have an `id` unit so zero values survive pprof encoding.
Beamscope's known numeric labels retain their units; other custom labels stay
strings.

Each pprof file is published with an atomic rename. Buffer overflow and failed
profile writes count toward `Dropped()` and subsequent profile comments.
Socket loss is counted separately and included in profile comments when both
outputs are enabled. A full buffer in one backend does not suppress the other.

## Socket wire format, version 2

The consumer listens; the agent dials and reconnects. All integers are
little-endian. Constants in `reporter/socket_sink.go` define the wire contract.

The 40-byte stream header is:

| Offset | Bytes | Field |
|---|---:|---|
| 0 | 8 | ASCII magic `PSTRSOK1` |
| 8 | 2 | u16 version = 2 |
| 10 | 2 | u16 header_len = 40 |
| 12 | 4 | u32 flags; bit 0 means leaf-first frames |
| 16 | 4 | u32 samples_per_second |
| 20 | 4 | u32 max_frames |
| 24 | 8 | i64 CLOCK_MONOTONIC ns at connection open |
| 32 | 2 | u16 sample_fixed_len = 80 |
| 34 | 2 | u16 label_stride = 24 |
| 36 | 4 | reserved, zero |

Each following record starts with a u32 length counting all subsequent bytes,
then a u8 record type. Unknown types can be skipped by length. Payload offsets
below exclude that type byte.

STRDEF (type 1): u32 id, u32 byte_len, then byte_len string bytes. ID 0 means
an empty string. Definitions precede references and the table resets for each
connection.

SAMPLE (type 2) has this fixed prefix:

| off | size | field |
|---|---|---|
| 0  | 8 | `i64` ktime_ns (`bpf_ktime_get_ns`, CLOCK_MONOTONIC) |
| 8  | 8 | `i64` unix_ns (derived CLOCK_REALTIME; carried, never compared against ktime) |
| 16 | 8 | `i64` off_time_ns. Off-CPU duration; zero for other origins. |
| 24 | 4 | `i32` pid |
| 28 | 4 | `i32` tid |
| 32 | 4 | `i32` cpu |
| 36 | 4 | `u32` dropped_since_prev |
| 40 | 4 | `u32` comm -> string id |
| 44 | 4 | `u32` process_name -> string id |
| 48 | 4 | `u32` executable -> string id |
| 52 | 4 | `u32` container_id -> string id. 0 means no container ID was resolved. |
| 56 | 1 | `u8` origin: 1 sampling, 2 off_cpu, 3 probe, 4 beamscope. |
| 57 | 1 | `u8` flags; bit 0 = frame list TRUNCATED |
| 58 | 2 | `u16` n_frames |
| 60 | 2 | `u16` n_labels |
| 62 | 1 | `u8` value_kind: 0 none, 1 alloc words, 2 sched nanoseconds, 3 msgs count. |
| 63 | 1 | `u8` reserved, must be 0 |
| 64 | 8 | `i64` value -- the sample's own measurement, in the unit `value_kind` names. Zero when value_kind is 0. |
| 72 | 8 | `u64` erlang_pid_key; raw Erlang PID Eterm, 0 when unattributable. |


The prefix is followed by n_frames entries of 12 bytes: u32 function string
ID, u32 filename string ID, i32 line. Frames are leaf-first. The socket may
cap the frame list; bit 0 of sample flags marks this and STATS counts it.
Pprof files keep all frames.

Then come n_labels entries, sorted by key:

| Offset | Bytes | Field |
|---|---:|---|
| 0 | 4 | u32 key string ID |
| 4 | 4 | u32 value string ID, zero for numeric labels |
| 8 | 4 | u32 unit string ID, zero for string labels |
| 12 | 1 | u8 kind: 0 string, 1 numeric |
| 13 | 3 | reserved, zero |
| 16 | 8 | i64 numeric value, zero for string labels |

Labels use the same reserved-key and numeric conversion rules as pprof.
Samples whose label count or total record size exceeds the encoder's bounds
are rejected and counted as write losses.

STATS (type 3) has an 80-byte payload: i64 ktime_ns, i64 unix_ns, followed by
eight u64 counters: produced, emitted, dropped_ring, dropped_nosock,
truncated_frames, bytes_written, strings_defined, connect_errors.
It is sent after connection setup, periodically, and before a clean close.
Samples count as emitted after their buffered bytes are successfully written.
At quiescence, write-path losses are the residual
`produced - emitted - dropped_ring - dropped_nosock`; while running, that
residual can also include queued samples. SAMPLE.dropped_since_prev includes
losses since the preceding delivered sample, saturating at u32 maximum.

## BEAM runtime data

`interpreter/beamscope` discovers `discord_beamscope_shm_v1`, maps the exported
memfd, and drains its rings. The source ABI is
`discord_common/ex/beam_scope/ABI.md` in the monorepo. Allocation, scheduler
and message deltas become single-frame BEAM samples; runtime panels,
configuration, monitors and process records are written to the optional JSONL
sidecar.

The reader holds records briefly for lazy process metadata and receive-sample
configuration. Message arrivals use the newest retained active config that
predates their timestamp, never a newer shift. Records lacking a usable config
remain in JSONL and increment `msg_flow_scale_skipped_total`. `drain_stats`
also reports writer drops, unknown records and corrupt rings. Invalid rings
are parked; an unpublished overflow-ring reservation is retried.

The final ring uses CAS reservations and publishes each record's header word.
Its consumer must acquire-load that word and zero every consumed byte before
releasing read_pos. Clearing only record headers allows stale interior bytes
from a previous lap to look like published records.

`interpreter/beam/beam_sched.go` resolves normal and dirty-CPU scheduler TIDs,
validates scheduler numbering, and measures the normal array's aligned stride.
The dirty-CPU array uses that stride: searching it independently can mistake
the adjacent dirty-IO array for another matching layout. Layout offsets are
known for OTP25–28; failures disable attribution for the affected process or
scheduler class. Scheduler enumeration runs once at attach, so late-created
threads may lack attribution.

On periodic CPU samples, eBPF reads the scheduler's current_process and its
PID-tagged Eterm into erlang_pid_key. Zero means no attribution. Entries are
bound to the BEAM's tgid to reject reused TIDs from another process. Custom
eBPF handlers may omit this optional scheduler-map interface.

Shutdown detaches interpreters and drains their final records before stopping
the reporter. The pprof reporter also flushes events received after its ticker
has stopped on context cancellation.

## Validation

```sh
make test
```

This generates Go/C ABI mirrors, builds eBPF, and prepares test binaries before
running the suite. Build eBPF for both amd64 and arm64 after changing the trace
header. The support tests compare the generated Go header with the embedded
objects' BTF layout.

Recorded shared-memory fixtures in `interpreter/beamscope/testdata` exercise
decoding and the full reporter pipeline. `TestBeamSchedLiveAttach` additionally
checks a local Erlang VM when `erl` is installed. Host profiling requires Linux
BPF/perf privileges; Go tests alone do not validate every live kernel path.
