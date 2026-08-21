// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

// PprofFileReporter is a Discord addition: an egress path that writes pprof
// files to a local directory instead of shipping OTLP anywhere. It exists for
// offline analysis, where the profile is an artifact to be sliced and diffed
// after the fact rather than a stream to a backend.
//
// Two properties are load-bearing for that use and are the reason this is not
// the OTLP reporter with a different transport:
//
//   - One pprof sample per raw eBPF sample, never aggregated. Callers slice
//     windows out of a continuously running profiler by filtering on the
//     per-sample kernel timestamp, so collapsing identical stacks would destroy
//     the only thing that makes a window definable.
//   - The full per-sample label set: kernel and wall-clock timestamps, pid and
//     tid, thread comm and process name, executable, cpu, container id, origin.
//     Anything dropped here cannot be recovered later, and narrowing a host-wide
//     profile to one application is a label filter.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/pprof/profile"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
)

// Label keys written per sample. These are a contract with the offline
// analysis; renaming one is a breaking change for anything reading the files.
const (
	LabelKTimeNs     = "ktime_ns"
	LabelTimestampNs = "timestamp_ns"
	LabelPID         = "pid"
	LabelTID         = "tid"
	LabelPPID        = "ppid"
	LabelAncestry    = "ancestry"
	LabelComm        = "comm"
	LabelProcessName = "process_name"
	LabelExecutable  = "executable"
	LabelCPU         = "cpu"
	LabelContainerID = "container_id"
	LabelOrigin      = "origin"
	LabelOffTimeNs   = "off_time_ns"

	unitNanoseconds = "nanoseconds"
	// unitID marks a numeric label that identifies rather than measures (cpu, pid,
	// tid, ppid). Any non-empty unit prevents google/pprof from dropping a
	// zero-valued numeric label; "id" also reads correctly in `pprof -raw`.
	unitID = "id"
)

// PprofFileConfig configures a PprofFileReporter.
type PprofFileConfig struct {
	// Dir is where profiles are written. Created if absent.
	Dir string
	// FlushInterval is how often a profile file is emitted. Each file covers
	// one interval; windows finer than that are cut offline from the timestamps,
	// so this is a file-size knob, not a resolution knob.
	FlushInterval time.Duration
	// SamplesPerSecond is the sampling frequency, used to derive the profile
	// period. It must match the tracer's actual rate or every value in the file
	// is scaled wrongly.
	SamplesPerSecond int
	// MaxBufferedSamples bounds memory between flushes. Samples beyond it are
	// dropped and counted, and the count is reported in the next profile's
	// comments: a profiler that silently truncates would make a window look
	// quiet rather than lossy.
	MaxBufferedSamples int
	// ProcFS overrides /proc, for tests.
	ProcFS string
	// KeepPIDs and KeepComms, when non-empty, restrict what is buffered at all.
	// This is a volume knob for a host-wide profiler; prefer filtering offline
	// on the labels, which keeps one capture re-sliceable.
	KeepPIDs  map[libpf.PID]struct{}
	KeepComms map[string]struct{}
}

const (
	defaultFlushInterval      = 10 * time.Second
	defaultMaxBufferedSamples = 4 << 20
)

// PprofFileReporter implements Reporter by writing pprof files locally.
type PprofFileReporter struct {
	cfg PprofFileConfig

	mu          sync.Mutex
	events      []sampleEvent
	windowStart time.Time

	dropped atomic.Uint64
	written atomic.Uint64

	lineage *lineageCache

	stop chan struct{}
	done chan struct{}
}

// sampleEvent is one raw sample, with its frames flattened out of the interned
// representation so nothing keeps the tracer's caches alive.
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
	// labels carries trace custom labels; only populated for beamscope-origin
	// samples (erlang_pid, bin_vheap_delta) so existing output is unchanged.
	labels map[string]string
}

type frame struct {
	function string
	file     string
	line     int64
}

// NewPprofFile constructs a reporter writing pprof files under cfg.Dir.
func NewPprofFile(cfg PprofFileConfig) (*PprofFileReporter, error) {
	if cfg.Dir == "" {
		return nil, fmt.Errorf("pprof reporter: Dir is required")
	}
	if cfg.SamplesPerSecond <= 0 {
		return nil, fmt.Errorf("pprof reporter: SamplesPerSecond must be positive, got %d",
			cfg.SamplesPerSecond)
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = defaultFlushInterval
	}
	if cfg.MaxBufferedSamples <= 0 {
		cfg.MaxBufferedSamples = defaultMaxBufferedSamples
	}
	if err := os.MkdirAll(cfg.Dir, 0o755); err != nil {
		return nil, fmt.Errorf("pprof reporter: %w", err)
	}
	return &PprofFileReporter{
		cfg:     cfg,
		lineage: newLineageCache(cfg.ProcFS),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}, nil
}

// ReportTraceEvent buffers one sample.
func (r *PprofFileReporter) ReportTraceEvent(trace *libpf.Trace,
	meta *samples.TraceEventMeta) error {
	switch meta.Origin {
	case support.TraceOriginSampling, support.TraceOriginOffCPU, support.TraceOriginProbe:
	case support.TraceOriginBeamScope: // Discord: BEAM shm instrumentation (beamscope)
	default:
		return fmt.Errorf("skip reporting trace for %d origin: %w", meta.Origin, errUnknownOrigin)
	}
	if len(r.cfg.KeepPIDs) > 0 {
		if _, ok := r.cfg.KeepPIDs[meta.PID]; !ok {
			return nil
		}
	}
	if len(r.cfg.KeepComms) > 0 {
		if _, ok := r.cfg.KeepComms[meta.Comm.String()]; !ok {
			return nil
		}
	}

	// Resolved on the buffering path, not at flush: by flush time a short-lived
	// process is often gone, and its lineage with it.
	lin := r.lineage.get(int(meta.PID))

	ev := sampleEvent{
		frames:      flatten(trace.Frames),
		ppid:        lin.ppid,
		ancestry:    lin.ancestryLabel(),
		ktime:       meta.KTime,
		unixNano:    int64(meta.Timestamp),
		pid:         meta.PID,
		tid:         meta.TID,
		cpu:         meta.CPU,
		offTime:     meta.OffTime,
		origin:      meta.Origin,
		comm:        meta.Comm.String(),
		processName: strings.TrimSpace(meta.ProcessName.String()),
		executable:  meta.ExecutablePath.String(),
		containerID: meta.ContainerID.String(),
	}
	// Discord: beamscope samples carry their labels (erlang_pid,
	// bin_vheap_delta) as trace custom labels; preserve them.
	if meta.Origin == support.TraceOriginBeamScope && len(trace.CustomLabels) > 0 {
		ev.labels = make(map[string]string, len(trace.CustomLabels))
		for k, v := range trace.CustomLabels {
			ev.labels[k.String()] = v.String()
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.events) >= r.cfg.MaxBufferedSamples {
		r.dropped.Add(1)
		return nil
	}
	if r.windowStart.IsZero() {
		r.windowStart = time.Now()
	}
	r.events = append(r.events, ev)
	return nil
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
				name = fmt.Sprintf("%s+0x%x", filepath.Base(f.Mapping.Value().File.Value().FileName.String()),
					uint64(f.AddressOrLineno))
			} else {
				name = fmt.Sprintf("0x%x", uint64(f.AddressOrLineno))
			}
		}
		out = append(out, frame{function: name, file: file, line: line})
	}
	return out
}

// Start begins the flush loop.
func (r *PprofFileReporter) Start(ctx context.Context) error {
	go func() {
		defer close(r.done)
		ticker := time.NewTicker(r.cfg.FlushInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := r.Flush(); err != nil {
					log.Errorf("pprof reporter: flush failed: %v", err)
				}
			case <-ctx.Done():
				if err := r.Flush(); err != nil {
					log.Errorf("pprof reporter: final flush failed: %v", err)
				}
				return
			case <-r.stop:
				if err := r.Flush(); err != nil {
					log.Errorf("pprof reporter: final flush failed: %v", err)
				}
				return
			}
		}
	}()
	return nil
}

// Stop flushes and shuts the flush loop down.
func (r *PprofFileReporter) Stop() {
	select {
	case <-r.stop:
	default:
		close(r.stop)
	}
	<-r.done
}

// Dropped reports how many samples were discarded for exceeding the buffer.
func (r *PprofFileReporter) Dropped() uint64 { return r.dropped.Load() }

// Flush writes the buffered samples as one pprof file and returns its path.
// A flush with nothing buffered writes no file and is not an error.
func (r *PprofFileReporter) Flush() error {
	r.mu.Lock()
	events := r.events
	start := r.windowStart
	r.events = nil
	r.windowStart = time.Time{}
	r.mu.Unlock()

	if len(events) == 0 {
		return nil
	}
	end := time.Now()
	if start.IsZero() {
		start = end
	}
	p := r.build(events, start, end)
	seq := r.written.Add(1)
	path := filepath.Join(r.cfg.Dir,
		fmt.Sprintf("profile-%06d-%d.pb.gz", seq, start.UnixNano()))
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := p.Write(f); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// build renders buffered samples as a pprof profile: one sample per event,
// values in samples and nanoseconds, every label from the contract attached.
func (r *PprofFileReporter) build(events []sampleEvent, start, end time.Time) *profile.Profile {
	periodNs := int64(time.Second) / int64(r.cfg.SamplesPerSecond)
	p := &profile.Profile{
		SampleType: []*profile.ValueType{
			{Type: "samples", Unit: "count"},
			{Type: "cpu", Unit: unitNanoseconds},
		},
		DefaultSampleType: "cpu",
		PeriodType:        &profile.ValueType{Type: "cpu", Unit: unitNanoseconds},
		Period:            periodNs,
		TimeNanos:         start.UnixNano(),
		DurationNanos:     end.Sub(start).Nanoseconds(),
	}
	if dropped := r.dropped.Load(); dropped > 0 {
		p.Comments = append(p.Comments,
			fmt.Sprintf("dropped %d samples exceeding MaxBufferedSamples=%d",
				dropped, r.cfg.MaxBufferedSamples))
	}
	if unresolved := r.lineage.Unresolved(); unresolved > 0 {
		// An ancestry filter can only be trusted as far as this number is small:
		// a process that died before /proc could be read has no lineage.
		p.Comments = append(p.Comments,
			fmt.Sprintf("lineage unresolved for %d pids (process exited before /proc could be read)",
				unresolved))
	}

	funcs := map[frame]*profile.Function{}
	locs := map[frame]*profile.Location{}
	location := func(fr frame) *profile.Location {
		if loc, ok := locs[fr]; ok {
			return loc
		}
		fn, ok := funcs[fr]
		if !ok {
			fn = &profile.Function{
				ID:         uint64(len(p.Function) + 1),
				Name:       fr.function,
				SystemName: fr.function,
				Filename:   fr.file,
			}
			p.Function = append(p.Function, fn)
			funcs[fr] = fn
		}
		loc := &profile.Location{
			ID:   uint64(len(p.Location) + 1),
			Line: []profile.Line{{Function: fn, Line: fr.line}},
		}
		p.Location = append(p.Location, loc)
		locs[fr] = loc
		return loc
	}

	for i := range events {
		ev := &events[i]
		locations := make([]*profile.Location, 0, len(ev.frames))
		for _, fr := range ev.frames {
			locations = append(locations, location(fr))
		}
		s := &profile.Sample{
			Location: locations,
			Value:    []int64{1, periodNs},
			Label:    map[string][]string{},
			NumLabel: map[string][]int64{},
			NumUnit:  map[string][]string{},
		}
		s.NumLabel[LabelKTimeNs] = []int64{ev.ktime}
		s.NumUnit[LabelKTimeNs] = []string{unitNanoseconds}
		s.NumLabel[LabelTimestampNs] = []int64{ev.unixNano}
		s.NumUnit[LabelTimestampNs] = []string{unitNanoseconds}
		// Identifier-valued numeric labels carry a unit, and it is not decoration:
		// google/pprof's encoder DROPS a numeric label that is both zero-valued and
		// unit-less, so an unlabelled `cpu` would silently swallow every sample taken
		// on CPU 0 -- ~1/16 of a 16-core box, arriving downstream as "no cpu label"
		// rather than as "cpu 0". Measured before the fix: a capture's distinct cpu
		// values ran 1..15 with 0 absent entirely, at 95.3% label coverage. pid and
		// tid share the hazard and are only spared because neither is ever 0 for a
		// sampled thread; giving them units too means that is not load-bearing.
		s.NumLabel[LabelPID] = []int64{int64(ev.pid)}
		s.NumUnit[LabelPID] = []string{unitID}
		s.NumLabel[LabelTID] = []int64{int64(ev.tid)}
		s.NumUnit[LabelTID] = []string{unitID}
		s.NumLabel[LabelCPU] = []int64{int64(ev.cpu)}
		s.NumUnit[LabelCPU] = []string{unitID}
		if ev.ppid > 0 {
			s.NumLabel[LabelPPID] = []int64{int64(ev.ppid)}
			s.NumUnit[LabelPPID] = []string{unitID}
		}
		setString(s, LabelAncestry, ev.ancestry)
		if ev.offTime != 0 {
			s.NumLabel[LabelOffTimeNs] = []int64{ev.offTime}
			s.NumUnit[LabelOffTimeNs] = []string{unitNanoseconds}
		}
		setString(s, LabelComm, ev.comm)
		setString(s, LabelProcessName, ev.processName)
		setString(s, LabelExecutable, ev.executable)
		setString(s, LabelContainerID, ev.containerID)
		setString(s, LabelOrigin, originName(ev.origin))
		// Discord: beamscope samples. The value channel (OffTime) carries the
		// sample's own value (allocated words for beamscope_kind=alloc,
		// on-scheduler nanoseconds for kind=sched): put it in the value slot
		// and drop the misleading off_time_ns label. Numeric labels arrive as
		// decimal strings in the custom labels; re-emit them as num labels,
		// with units so zero values survive pprof encoding.
		if ev.origin == support.TraceOriginBeamScope {
			s.Value = []int64{1, ev.offTime}
			delete(s.NumLabel, LabelOffTimeNs)
			delete(s.NumUnit, LabelOffTimeNs)
			for k, v := range ev.labels {
				if unit, numeric := beamscopeNumLabelUnits[k]; numeric {
					if n, err := strconv.ParseInt(v, 10, 64); err == nil {
						s.NumLabel[k] = []int64{n}
						s.NumUnit[k] = []string{unit}
						continue
					}
				}
				setString(s, k, v)
			}
		}
		p.Sample = append(p.Sample, s)
	}
	return p
}

// beamscopeNumLabelUnits names the beamscope custom labels that are numeric
// and the unit each is emitted with (bin_vheap_delta stays a string label for
// compatibility with existing captures).
var beamscopeNumLabelUnits = map[string]string{
	"mbuf_words": "words",
	"pause_ns":   unitNanoseconds,
	"nswitches":  "count",
	"preempts":   "count",
	"yields":     "count",
}

func setString(s *profile.Sample, key, value string) {
	if value == "" {
		return
	}
	s.Label[key] = []string{value}
}

func originName(o libpf.Origin) string {
	switch o {
	case support.TraceOriginSampling:
		return "sampling"
	case support.TraceOriginOffCPU:
		return "off_cpu"
	case support.TraceOriginProbe:
		return "probe"
	case support.TraceOriginBeamScope: // Discord: BEAM shm instrumentation
		return "beamscope"
	default:
		return fmt.Sprintf("origin_%d", o)
	}
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
