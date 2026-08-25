// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

// LocalEgressReporter is a Discord addition: the local egress path, which keeps
// every sample on this host instead of shipping OTLP to a collection agent. It
// has two INDEPENDENT backends, either or both of which can be enabled:
//
//   - the pprof-file sink (pprof_file_reporter.go), an archive to be sliced and
//     diffed after the fact;
//   - the socket sink (socket_sink.go), a live stream for a consumer that needs
//     sub-flush-interval resolution.
//
// The structure that matters is that the per-sample DECODE happens once, here,
// and both sinks receive the same assembled *sampleEvent:
//
//   - frames flattened out of the tracer's interned tables, so nothing keeps
//     those caches alive and both sinks see identical stacks;
//   - lineage resolved on the REPORTING path, not at flush time, because by
//     flush time a short-lived process is gone and its lineage with it;
//   - the keep filters and the comm trim applied before either sink sees the
//     sample, so "what was recorded" cannot differ between them.
//
// One decode means the two artifacts are structurally identical rather than
// merely intended to agree: there is no second decode to drift. Neither sink
// knows the other's type -- the socket sink used to be a field inside the pprof
// reporter, which is why the socket could not run without pprof files.

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
)

// LocalEgressConfig configures the local egress. At least one backend must be
// enabled: Dir non-empty (pprof files) or Socket.Path non-empty (live stream).
type LocalEgressConfig struct {
	// Dir enables the pprof-file sink and is where profiles are written.
	// Created if absent. Empty disables the sink entirely: no directory, no
	// files, no flush loop.
	Dir string
	// FlushInterval is how often a profile file is emitted. Each file covers
	// one interval; windows finer than that are cut offline from the timestamps,
	// so this is a file-size knob, not a resolution knob. Ignored when Dir is
	// empty.
	FlushInterval time.Duration
	// SamplesPerSecond is the sampling frequency. It becomes the pprof profile
	// period and is announced in the socket stream's header, so it must match
	// the tracer's actual rate for either backend: every pprof value is scaled
	// by it, and a consumer converts counts to CPU time with it.
	SamplesPerSecond int
	// MaxBufferedSamples bounds the pprof sink's memory between flushes.
	// Samples beyond it are dropped and counted, and the count is reported in
	// the next profile's comments: a profiler that silently truncates would
	// make a window look quiet rather than lossy. Ignored when Dir is empty.
	MaxBufferedSamples int
	// ProcFS overrides /proc, for tests.
	ProcFS string
	// KeepPIDs and KeepComms, when non-empty, restrict what is recorded at all,
	// for BOTH backends. This is a volume knob for a host-wide profiler; prefer
	// filtering offline on the labels, which keeps one capture re-sliceable.
	KeepPIDs  map[libpf.PID]struct{}
	KeepComms map[string]struct{}
	// Socket, when its Path is non-empty, streams every assembled sample over a
	// unix socket. It is independent of Dir: socket-only, pprof-only and both
	// are all valid. See socket_sink.go for the wire format and the drop
	// accounting.
	Socket SocketConfig
}

// LocalEgressReporter implements Reporter by fanning each assembled sample out
// to the enabled local backends.
type LocalEgressReporter struct {
	assembler sampleAssembler

	// pprof is nil unless cfg.Dir was set, socket nil unless
	// cfg.Socket.Path was. Neither field is required for the other to work.
	pprof  *pprofFileSink
	socket *socketSink
}

// NewLocalEgress constructs the local egress reporter for cfg.
func NewLocalEgress(cfg LocalEgressConfig) (*LocalEgressReporter, error) {
	if cfg.Dir == "" && cfg.Socket.Path == "" {
		// Not a no-op reporter: a local egress with no backend records nothing
		// while looking like it is recording, which is the failure mode this
		// whole file exists to make impossible.
		return nil, fmt.Errorf("local egress: at least one backend is required " +
			"(Dir for pprof files, Socket.Path for the live stream)")
	}
	if cfg.SamplesPerSecond <= 0 {
		return nil, fmt.Errorf("local egress: SamplesPerSecond must be positive, got %d",
			cfg.SamplesPerSecond)
	}
	lineage := newLineageCache(cfg.ProcFS)
	r := &LocalEgressReporter{
		assembler: sampleAssembler{
			keepPIDs:  cfg.KeepPIDs,
			keepComms: cfg.KeepComms,
			lineage:   lineage,
		},
	}
	if cfg.Dir != "" {
		sink, err := newPprofFileSink(cfg, lineage)
		if err != nil {
			return nil, err
		}
		r.pprof = sink
	}
	if cfg.Socket.Path != "" {
		sockCfg := cfg.Socket
		if sockCfg.SamplesPerSecond == 0 {
			sockCfg.SamplesPerSecond = cfg.SamplesPerSecond
		}
		sink, err := newSocketSink(sockCfg)
		if err != nil {
			return nil, err
		}
		r.socket = sink
	}
	if r.pprof != nil && r.socket != nil {
		// Cross-attestation is only meaningful when both backends are running:
		// the archive states the stream's loss so the two artifacts cannot
		// disagree about the same run. With one backend there is nothing to
		// attest to -- a socket-only run's loss lives in its STATS records and
		// in the loss warning, and a pprof-only run has no stream to lose
		// anything.
		r.pprof.crossAttest = r.socket.dropSummaryIfLossy
	}
	return r, nil
}

// ReportTraceEvent assembles one sample and hands it to every enabled backend.
func (r *LocalEgressReporter) ReportTraceEvent(trace *libpf.Trace,
	meta *samples.TraceEventMeta) error {
	ev, err := r.assembler.assemble(trace, meta)
	if err != nil || ev == nil {
		return err
	}
	// Both sinks see the identical sampleEvent, and their budgets are
	// independent: a full pprof buffer must not silently truncate the socket
	// stream, which is the path a live consumer is reading. Neither may mutate
	// it, and neither does.
	if r.socket != nil {
		r.socket.offer(ev)
	}
	if r.pprof != nil {
		r.pprof.consume(ev)
	}
	return nil
}

// Start begins whatever background work the enabled backends need.
func (r *LocalEgressReporter) Start(ctx context.Context) error {
	if r.socket != nil {
		r.socket.start()
	}
	if r.pprof != nil {
		r.pprof.start(ctx)
	}
	return nil
}

// Stop shuts the enabled backends down.
//
// The socket sink is shut down FIRST, before the pprof sink's final flush. Its
// drain is where the socket path's loss is finally accounted -- a consumer that
// has gone away is discovered there, and that is where the write buffer is
// discarded and the ring charged to droppedNoSock -- so draining afterwards put
// every one of those drops after the last pprof file was written. The archive
// then stated "no loss" for a run whose log warned about loss, which is exactly
// the cross-attestation the comment claims to provide. Both backends already
// received every event at ReportTraceEvent time, so the reordering costs the
// socket nothing.
func (r *LocalEgressReporter) Stop() {
	if r.socket != nil {
		r.socket.shutdown()
	}
	if r.pprof != nil {
		r.pprof.stopAndFlush()
	}
}

// Flush writes whatever the pprof sink has buffered as one file. A no-op when
// the pprof backend is disabled: the socket sink has no notion of a flush the
// caller can ask for, because it writes every sample as it arrives.
func (r *LocalEgressReporter) Flush() error {
	if r.pprof == nil {
		return nil
	}
	return r.pprof.Flush()
}

// Dropped reports how many samples the pprof sink discarded for exceeding its
// buffer, zero when that backend is disabled.
func (r *LocalEgressReporter) Dropped() uint64 {
	if r.pprof == nil {
		return 0
	}
	return r.pprof.dropped.Load()
}

// SocketDropped reports how many samples the socket egress discarded, zero when
// that backend is disabled. A silently lossy profiler is worse than a dead one,
// so socket loss is surfaced in every combination: here, in every STATS record
// on the wire, in the loss warning, and -- when the pprof backend is also
// enabled -- in the pprof file's comments, so the archive and the stream
// cross-attest.
func (r *LocalEgressReporter) SocketDropped() uint64 {
	if r.socket == nil {
		return 0
	}
	return r.socket.Dropped()
}

// sampleAssembler turns a tracer event into the one *sampleEvent both backends
// consume. It is deliberately the only place this decode happens.
type sampleAssembler struct {
	keepPIDs  map[libpf.PID]struct{}
	keepComms map[string]struct{}
	lineage   *lineageCache
}

// assemble decodes one tracer event. It returns (nil, nil) when the sample is
// filtered out by the keep sets, and an error only for an origin no backend
// knows how to render.
func (a *sampleAssembler) assemble(trace *libpf.Trace,
	meta *samples.TraceEventMeta) (*sampleEvent, error) {
	if _, ok := originTable[meta.Origin]; !ok {
		return nil, fmt.Errorf("skip reporting trace for %d origin: %w",
			meta.Origin, errUnknownOrigin)
	}
	if len(a.keepPIDs) > 0 {
		if _, ok := a.keepPIDs[meta.PID]; !ok {
			return nil, nil
		}
	}
	// The kernel's comm for a BEAM main thread genuinely contains the trailing
	// newline ("beam.smp\n"); threads the VM renamed via pthread_setname_np
	// ("1_scheduler") do not, so the problem shows up on exactly one thread per
	// VM. Untrimmed, that makes one process look like two when grouped on the
	// label, AND makes a `-keep-comms beam.smp` filter silently match nothing
	// for the main thread -- so trim once, before the filter.
	comm := strings.TrimSpace(meta.Comm.String())
	if len(a.keepComms) > 0 {
		if _, ok := a.keepComms[comm]; !ok {
			return nil, nil
		}
	}

	// Resolved on the reporting path, not at flush: by flush time a short-lived
	// process is often gone, and its lineage with it. Doing it here means the
	// socket sink gets that property too, without resolving anything itself.
	lin := a.lineage.get(int(meta.PID))

	ev := &sampleEvent{
		frames:       flatten(trace.Frames),
		ppid:         lin.ppid,
		ancestry:     lin.ancestryLabel(),
		ktime:        meta.KTime,
		unixNano:     int64(meta.Timestamp),
		pid:          meta.PID,
		tid:          meta.TID,
		cpu:          meta.CPU,
		offTime:      meta.OffTime,
		origin:       meta.Origin,
		value:        meta.Value,
		valueKind:    meta.ValueKind,
		erlangPidKey: meta.ErlangPidKey,
		comm:         comm, // trimmed above, before KeepComms
		processName:  strings.TrimSpace(meta.ProcessName.String()),
		executable:   meta.ExecutablePath.String(),
		containerID:  meta.ContainerID.String(),
	}
	// Discord: custom labels ride every origin (un-gate; needs
	// them off beamscope too). Today only beamscope populates any
	// (erlang_pid, bin_vheap_delta, beamscope_kind, ...).
	if len(trace.CustomLabels) > 0 {
		ev.labels = make(map[string]string, len(trace.CustomLabels))
		for k, v := range trace.CustomLabels {
			ev.labels[k.String()] = v.String()
		}
	}
	return ev, nil
}

// sampleEvent is one raw sample, with its frames flattened out of the interned
// representation so nothing keeps the tracer's caches alive. Assembled once and
// shared, read-only, by every backend.
type sampleEvent struct {
	frames      []frame
	ktime       int64
	unixNano    int64
	pid, tid    libpf.PID
	cpu         int
	offTime     int64
	origin      libpf.Origin
	ppid        int
	ancestry    string
	comm        string
	processName string
	executable  string
	containerID string
	// value/valueKind are the Discord general per-sample value
	// channel; only beamscope-origin samples populate them (samples.ValueKind*
	// says which SampleType column value belongs in). offTime above stays
	// exclusively the off-CPU sample's off-scheduler nanoseconds.
	value     int64
	valueKind uint8
	// erlangPidKey is the Discord per-sample Erlang process
	// attribution: the raw pid Eterm, or 0 when the sample is not
	// attributable. Zero means "no label", never "pid 0".
	erlangPidKey uint64
	// labels carries trace custom labels for every origin (un-gate;
	// beamscope populates erlang_pid, bin_vheap_delta, beamscope_kind, ...).
	labels map[string]string
}

type frame struct {
	function string
	file     string
	line     int64
}

// flatten resolves interned frames, leaf first as the tracer delivers them.
func flatten(frames libpf.Frames) []frame {
	out := make([]frame, 0, len(frames))
	for _, handle := range frames {
		f := handle.Value()
		name := f.FunctionName.String()
		file := f.SourceFile.String()
		line := int64(f.SourceLine)
		if name == "" {
			// An unsymbolized native frame: name it by mapping and address so
			// two different unknown frames do not collapse into one stack.
			if f.Mapping.Valid() {
				name = fmt.Sprintf("%s+0x%x",
					filepath.Base(f.Mapping.Value().File.Value().FileName.String()),
					uint64(f.AddressOrLineno))
			} else {
				name = fmt.Sprintf("0x%x", uint64(f.AddressOrLineno))
			}
		}
		out = append(out, frame{function: name, file: file, line: line})
	}
	return out
}

// originTable is the single enumeration of the origins the local egress
// accepts. It answers all three questions that used to be three hand-maintained
// switches: is the origin valid at all (assemble), what does the pprof `origin`
// label say (originName), and what byte goes on the socket wire (socketOrigin,
// socket_sink.go). Adding an origin here cannot leave one of the three behind.
//
// The value-column fill rule is deliberately NOT here: it is frozen, and its
// default arm exists precisely so that a newly added origin is noticed.
var originTable = map[libpf.Origin]struct {
	name string
	wire uint8
}{
	support.TraceOriginSampling: {"sampling", socketOriginSampling},
	support.TraceOriginOffCPU:   {"off_cpu", socketOriginOffCPU},
	support.TraceOriginProbe:    {"probe", socketOriginProbe},
	// Discord: BEAM shm instrumentation.
	support.TraceOriginBeamScope: {"beamscope", socketOriginBeamScope},
}

func originName(o libpf.Origin) string {
	if info, ok := originTable[o]; ok {
		return info.name
	}
	return fmt.Sprintf("origin_%d", o)
}

// ParsePIDList turns a comma-separated PID list into a set.
func ParsePIDList(pids []int) map[libpf.PID]struct{} {
	if len(pids) == 0 {
		return nil
	}
	out := make(map[libpf.PID]struct{}, len(pids))
	for _, pid := range pids {
		out[libpf.PID(pid)] = struct{}{}
	}
	return out
}

// ParseCommList turns a list of process names into a set.
func ParseCommList(comms []string) map[string]struct{} {
	if len(comms) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(comms))
	for _, c := range comms {
		if c == "" {
			continue
		}
		out[c] = struct{}{}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
