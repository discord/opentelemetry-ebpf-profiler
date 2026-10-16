// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

// Local egress assembles each sample once and sends the same immutable event
// to the enabled pprof and socket backends. Lineage is resolved on receipt
// while short-lived processes may still exist.

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
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
	mu        sync.RWMutex
	stopped   bool
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
		if sockCfg.SamplesPerSecond != 0 && sockCfg.SamplesPerSecond != cfg.SamplesPerSecond {
			return nil, fmt.Errorf("socket sample rate %d differs from reporter rate %d", sockCfg.SamplesPerSecond, cfg.SamplesPerSecond)
		}
		sockCfg.SamplesPerSecond = cfg.SamplesPerSecond
		sink, err := newSocketSink(sockCfg)
		if err != nil {
			return nil, err
		}
		r.socket = sink
	}
	if r.pprof != nil && r.socket != nil {
		// Include socket loss counters in profiles when both outputs are enabled.
		r.pprof.crossAttest = r.socket.dropSummaryIfLossy
	}
	return r, nil
}

// ReportTraceEvent assembles one sample and hands it to every enabled backend.
func (r *LocalEgressReporter) ReportTraceEvent(trace *libpf.Trace,
	meta *samples.TraceEventMeta) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.stopped {
		return errors.New("local egress is stopped")
	}
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
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.stopped {
		return errors.New("local egress is stopped")
	}
	if r.socket != nil {
		r.socket.start()
	}
	if r.pprof != nil {
		r.pprof.start(ctx)
	}
	return nil
}

// Stop drains the socket before the final profile flush so that the profile
// includes the socket's final loss counters.
func (r *LocalEgressReporter) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return
	}
	r.stopped = true
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

// Dropped returns samples lost to a full buffer or a failed profile write,
// or zero when the pprof backend is disabled.
func (r *LocalEgressReporter) Dropped() uint64 {
	if r.pprof == nil {
		return 0
	}
	return r.pprof.dropped.Load()
}

// SocketDropped returns socket losses, or zero when that backend is disabled.
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
	origin := profileOrigin(meta.ProfileType)
	if origin == originUnknown {
		return nil, fmt.Errorf("unsupported profile type %v: %w", meta.ProfileType, errUnknownProfileType)
	}
	if len(a.keepPIDs) > 0 {
		if _, ok := a.keepPIDs[meta.PID]; !ok {
			return nil, nil
		}
	}
	// Normalize the trailing newline in the BEAM main thread's comm before
	// filtering or writing labels.
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
		frames:   flatten(trace.Frames),
		ppid:     lin.ppid,
		ancestry: lin.ancestryLabel(),
		ktime:    meta.KTime,
		unixNano: int64(meta.Timestamp),
		pid:      meta.PID,
		tid:      meta.TID,
		cpu:      int(meta.CPU),

		origin:       origin,
		value:        meta.Value,
		valueKind:    samples.BeamScopeValueKind(meta.ProfileType),
		erlangPidKey: meta.ErlangPidKey,
		comm:         comm, // trimmed above, before KeepComms
		processName:  strings.TrimSpace(meta.ProcessName.String()),
		executable:   meta.ExecutablePath.String(),
		containerID:  meta.ContainerID.String(),
	}
	if origin == originOffCPU {
		ev.offTime = meta.Value
	}
	// Copy labels because the tracer may reuse them after this call.
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
	origin      sampleOrigin
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
	// labels contains a snapshot of the trace custom labels.
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

// originTable maps local profile classifications to labels and wire codes.
var originTable = map[sampleOrigin]struct {
	name string
	wire uint8
}{
	originSampling: {"sampling", socketOriginSampling},
	originOffCPU:   {"off_cpu", socketOriginOffCPU},
	originProbe:    {"probe", socketOriginProbe},
	// Discord: BEAM shm instrumentation.
	originBeamScope: {"beamscope", socketOriginBeamScope},
}

func originName(o sampleOrigin) string {
	if info, ok := originTable[o]; ok {
		return info.name
	}
	return fmt.Sprintf("origin_%d", o)
}

// ParsePIDList turns a PID slice into a set.
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

// sampleOrigin is the local file/socket classification, independent of kernel origin IDs.
type sampleOrigin uint8

const (
	originUnknown sampleOrigin = iota
	originSampling
	originOffCPU
	originProbe
	originBeamScope
)

func profileOrigin(p *samples.TypeMetadata) sampleOrigin {
	if p == nil {
		return originUnknown
	}
	if samples.BeamScopeValueKind(p) != samples.ValueKindNone {
		return originBeamScope
	}
	switch {
	case p.PeriodType == "cpu" && p.PeriodUnit == "nanoseconds" && p.SampleType == "samples" && p.SampleUnit == "count":
		return originSampling
	case p.SampleType == "off_cpu" && p.SampleUnit == "nanoseconds" && p.ReportValues:
		return originOffCPU
	case p.SampleType == "events" && p.SampleUnit == "count":
		return originProbe
	default:
		return originUnknown
	}
}
