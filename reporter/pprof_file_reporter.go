// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

// pprofFileSink is the local egress's pprof-file backend: it writes pprof files
// to a local directory instead of shipping OTLP anywhere. It exists for offline
// analysis, where the profile is an artifact to be sliced and diffed after the
// fact rather than a stream to a backend. Selected by LocalEgressConfig.Dir; the
// socket backend is independent of it (see local_egress.go).
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
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/pprof/profile"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
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
	// LabelErlangPidKey carries the raw Erlang pid Eterm of the process a BEAM
	// scheduler was running when a CPU sample landed. It is the join key
	// against every beam_scope JSONL record and PROC_META naming, so its
	// spelling is a hard contract with the offline tooling.
	LabelErlangPidKey = "erlang_pid_key"

	unitNanoseconds = "nanoseconds"
	// unitID marks a numeric label that identifies rather than measures (cpu, pid,
	// tid, ppid). Any non-empty unit prevents google/pprof from dropping a
	// zero-valued numeric label; "id" also reads correctly in `pprof -raw`.
	unitID = "id"
)

// Exported because the command-line help interpolates them: the flags are
// registered with a zero default ("not specified", so the reporter picks), and
// Go's flag package prints no "(default ...)" for a zero value, so without this
// the numbers would exist in exactly one place and be documented in none.
const (
	// DefaultPprofFlushInterval is the default LocalEgressConfig.FlushInterval.
	DefaultPprofFlushInterval = 10 * time.Second
	// DefaultPprofMaxBufferedSamples is the default
	// LocalEgressConfig.MaxBufferedSamples.
	DefaultPprofMaxBufferedSamples = 4 << 20
)

// pprofFileSink buffers assembled samples and writes them out as pprof files.
type pprofFileSink struct {
	dir              string
	flushInterval    time.Duration
	samplesPerSecond int
	maxBuffered      int

	mu sync.Mutex
	// events holds the assembler's *sampleEvent, the SAME pointer the socket
	// sink may also be holding: the assembler builds one per sample and
	// local_egress.go fans that one value out. NOTHING MAY MUTATE A BUFFERED
	// EVENT -- not this sink, not the socket sink, not the assembler after
	// handing it over. It is read-only shared state, and build() below is the
	// only reader here. Adding a "fix it up at flush time" write would silently
	// change what a co-resident socket stream already emitted, or race it.
	events      []*sampleEvent
	windowStart time.Time

	dropped atomic.Uint64
	written atomic.Uint64

	// lineage is the cache the assembler resolves against. This sink only reads
	// its unresolved count, for the profile's comments: an ancestry filter can
	// only be trusted as far as that number is small.
	//
	// That comment is the ONLY place the count is surfaced, so a socket-only
	// run ships the `ancestry` label with no confidence signal at all (the v1
	// wire has no field for it, and adding one is a v2 header). Noted rather
	// than fixed: a consumer that needs it runs with -pprof-dir too.
	lineage *lineageCache

	// crossAttest, when non-nil, renders a co-resident backend's loss summary
	// into this profile's comments, or "" when that backend lost nothing. It is
	// set only when the socket backend is also enabled -- an archive can only
	// attest to a stream that exists -- and it is a func rather than a
	// *socketSink so this sink does not depend on the other's type.
	crossAttest func() string

	// started is set by start(). stopAndFlush must not wait on a flush loop
	// that was never launched -- that wait never returns, and "Stop() hangs" is
	// a bad way to learn a reporter was never started.
	started atomic.Bool

	stop chan struct{}
	done chan struct{}
}

func newPprofFileSink(cfg LocalEgressConfig, lineage *lineageCache) (*pprofFileSink, error) {
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = DefaultPprofFlushInterval
	}
	if cfg.MaxBufferedSamples <= 0 {
		cfg.MaxBufferedSamples = DefaultPprofMaxBufferedSamples
	}
	if err := os.MkdirAll(cfg.Dir, 0o755); err != nil {
		return nil, fmt.Errorf("pprof egress: %w", err)
	}
	return &pprofFileSink{
		dir:              cfg.Dir,
		flushInterval:    cfg.FlushInterval,
		samplesPerSecond: cfg.SamplesPerSecond,
		maxBuffered:      cfg.MaxBufferedSamples,
		lineage:          lineage,
		stop:             make(chan struct{}),
		done:             make(chan struct{}),
	}, nil
}

// consume buffers one assembled sample, or counts it as dropped when the buffer
// is full. It never blocks on I/O: the file is written by the flush loop.
func (s *pprofFileSink) consume(ev *sampleEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.events) >= s.maxBuffered {
		s.dropped.Add(1)
		return
	}
	if s.windowStart.IsZero() {
		s.windowStart = time.Now()
	}
	s.events = append(s.events, ev)
}

// start begins the flush loop.
func (s *pprofFileSink) start(ctx context.Context) {
	s.started.Store(true)
	go func() {
		defer close(s.done)
		ticker := time.NewTicker(s.flushInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := s.Flush(); err != nil {
					log.Errorf("pprof egress: flush failed: %v", err)
				}
			case <-ctx.Done():
				if err := s.Flush(); err != nil {
					log.Errorf("pprof egress: final flush failed: %v", err)
				}
				return
			case <-s.stop:
				if err := s.Flush(); err != nil {
					log.Errorf("pprof egress: final flush failed: %v", err)
				}
				return
			}
		}
	}()
}

// stopAndFlush shuts the flush loop down, which flushes what is buffered.
func (s *pprofFileSink) stopAndFlush() {
	if !s.started.Load() {
		// No loop to stop, but there may be buffered samples, and discarding
		// them silently is worse than writing one more file.
		if err := s.Flush(); err != nil {
			log.Errorf("pprof egress: final flush failed: %v", err)
		}
		return
	}
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
	<-s.done
}

// Flush writes the buffered samples as one pprof file.
// A flush with nothing buffered writes no file and is not an error.
func (s *pprofFileSink) Flush() error {
	s.mu.Lock()
	events := s.events
	start := s.windowStart
	s.events = nil
	s.windowStart = time.Time{}
	s.mu.Unlock()

	if len(events) == 0 {
		return nil
	}
	end := time.Now()
	if start.IsZero() {
		start = end
	}
	p := s.build(events, start, end)
	seq := s.written.Add(1)
	path := filepath.Join(s.dir,
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
func (s *pprofFileSink) build(events []*sampleEvent, start, end time.Time) *profile.Profile {
	periodNs := int64(time.Second) / int64(s.samplesPerSecond)
	p := &profile.Profile{
		// Discord: five honest columns, one per measurement kind,
		// instead of smuggling beamscope's alloc/sched/msgs values into the
		// cpu-nanoseconds column. The presence of the "alloc" SampleType is
		// the version marker a consumer checks before trusting column 1 as
		// pure cpu-ns (see doc/discord-fork.md section 3.8).
		SampleType: []*profile.ValueType{
			{Type: "samples", Unit: "count"},
			{Type: "cpu", Unit: unitNanoseconds},
			{Type: "alloc", Unit: "words"},
			{Type: "sched", Unit: unitNanoseconds},
			{Type: "msgs", Unit: "count"},
		},
		DefaultSampleType: "cpu",
		PeriodType:        &profile.ValueType{Type: "cpu", Unit: unitNanoseconds},
		Period:            periodNs,
		TimeNanos:         start.UnixNano(),
		DurationNanos:     end.Sub(start).Nanoseconds(),
	}
	if dropped := s.dropped.Load(); dropped > 0 {
		p.Comments = append(p.Comments,
			fmt.Sprintf("dropped %d samples exceeding MaxBufferedSamples=%d",
				dropped, s.maxBuffered))
	}
	if s.crossAttest != nil {
		// Same rendering the socket's log line uses, so the archive and the log
		// cannot state different numbers for one run.
		if summary := s.crossAttest(); summary != "" {
			p.Comments = append(p.Comments, summary)
		}
	}
	if unresolved := s.lineage.Unresolved(); unresolved > 0 {
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

	for _, ev := range events {
		locations := make([]*profile.Location, 0, len(ev.frames))
		for _, fr := range ev.frames {
			locations = append(locations, location(fr))
		}
		sm := &profile.Sample{
			Location: locations,
			// samples column is always 1; the four measurement columns
			// (cpu/alloc/sched/msgs) start at 0 and exactly one is filled in
			// below, per ev.origin (see the fill-rule switch).
			Value:    []int64{1, 0, 0, 0, 0},
			Label:    map[string][]string{},
			NumLabel: map[string][]int64{},
			NumUnit:  map[string][]string{},
		}
		setNumLabel(sm, LabelKTimeNs, ev.ktime, unitNanoseconds)
		setNumLabel(sm, LabelTimestampNs, ev.unixNano, unitNanoseconds)
		// Identifier-valued numeric labels carry a unit, and it is not decoration:
		// google/pprof's encoder DROPS a numeric label that is both zero-valued and
		// unit-less, so an unlabelled `cpu` would silently swallow every sample taken
		// on CPU 0 -- ~1/16 of a 16-core box, arriving downstream as "no cpu label"
		// rather than as "cpu 0". Measured before the fix: a capture's distinct cpu
		// values ran 1..15 with 0 absent entirely, at 95.3% label coverage. pid and
		// tid share the hazard and are only spared because neither is ever 0 for a
		// sampled thread; giving them units too means that is not load-bearing.
		setNumLabel(sm, LabelPID, int64(ev.pid), unitID)
		setNumLabel(sm, LabelTID, int64(ev.tid), unitID)
		setNumLabel(sm, LabelCPU, int64(ev.cpu), unitID)
		if ev.ppid > 0 {
			setNumLabel(sm, LabelPPID, int64(ev.ppid), unitID)
		}
		setString(sm, LabelAncestry, ev.ancestry)
		if ev.offTime != 0 {
			setNumLabel(sm, LabelOffTimeNs, ev.offTime, unitNanoseconds)
		}
		// Discord: 0 means the sample is not attributable to an
		// Erlang process, and the label is omitted entirely rather than
		// emitted as 0 -- a pid term is never 0, so "absent" and "pid 0" must
		// not be made to look alike downstream. The value is an Eterm, not a
		// count; int64 here is a bit-pattern carrier (pprof has no unsigned
		// num label) and the reader must cast back to uint64.
		if ev.erlangPidKey != 0 {
			setNumLabel(sm, LabelErlangPidKey, int64(ev.erlangPidKey), unitID)
		}
		setString(sm, LabelComm, ev.comm)
		setString(sm, LabelProcessName, ev.processName)
		setString(sm, LabelExecutable, ev.executable)
		setString(sm, LabelContainerID, ev.containerID)
		setString(sm, LabelOrigin, originName(ev.origin))
		// Discord: fill exactly one measurement column per origin.
		// CPU-origin (sampling/probe) fills cpu-ns from the tracer's period.
		// Off-CPU leaves cpu-ns at 0 -- off-scheduler time is not cpu time --
		// and keeps carrying its value only in the off_time_ns label set
		// above. Beamscope fills the column named by its ValueKind; the
		// off_time_ns label-delete special case that used to live here is
		// gone because beamscope no longer touches OffTime at all.
		switch ev.origin {
		case support.TraceOriginBeamScope:
			switch ev.valueKind {
			case samples.ValueKindAlloc:
				sm.Value[2] = ev.value
			case samples.ValueKindSchedNS:
				sm.Value[3] = ev.value
			case samples.ValueKindMsgs:
				sm.Value[4] = ev.value
			}
		case support.TraceOriginOffCPU:
			// cpu-ns column intentionally stays 0.
		default: // TraceOriginSampling, TraceOriginProbe
			// A NEW origin added upstream or here lands in this arm and silently
			// becomes cpu-ns mass at the tracer's period, which is right only
			// for something that really is a CPU sample. Any new origin must
			// pick its value column deliberately -- add a case rather than
			// inheriting this one.
			sm.Value[1] = periodNs
		}
		// Discord: custom labels ride every origin now, which makes
		// the traced process a co-author of this sample's label set. Two
		// things follow, and neither was true while the loop was gated to
		// beamscope:
		//
		//   - It runs AFTER the contract labels are assigned, so a custom key
		//     spelled like one of them would overwrite the reporter's own
		//     value. A Go service is free to set a pprof label called "comm"
		//     or "origin"; the label contract is not.
		//   - numLabelUnits names BEAMSCOPE's numeric labels. Applying it to
		//     every origin means a Go service whose label happens to be
		//     called "preempts" or "pause_ns" gets it silently converted to a
		//     numeric label with a unit it never asked for.
		//
		// So: never overwrite a contract key, and only re-type numerics for
		// the origin the mapping actually describes.
		for k, v := range ev.labels {
			if _, reserved := contractLabelKeys[k]; reserved {
				continue
			}
			if ev.origin == support.TraceOriginBeamScope {
				if unit, numeric := numLabelUnits[k]; numeric {
					if n, err := strconv.ParseInt(v, 10, 64); err == nil {
						setNumLabel(sm, k, n, unit)
						continue
					}
				}
			}
			setString(sm, k, v)
		}
		p.Sample = append(p.Sample, sm)
	}
	return p
}

// numLabelUnits names the labels that are emitted as pprof numeric labels and
// the unit each carries. Every entry a lookup can reach is a beamscope custom
// label arriving as a decimal string (bin_vheap_delta stays a string label for
// compatibility with existing captures).
//
// LabelErlangPidKey is the exception and is unreachable from that loop by
// design: it is a contract key, so contractLabelKeys skips it before the
// lookup, and its value comes from the meta field instead. It is listed anyway
// so the unit it is written with lives next to the others rather than only at
// its one call site.
var numLabelUnits = map[string]string{
	"mbuf_words":      "words",
	"pause_ns":        unitNanoseconds,
	"nswitches":       "count",
	"preempts":        "count",
	"yields":          "count",
	LabelErlangPidKey: unitID,
}

// contractLabelKeys is every label name this sink assigns itself. A custom
// label carrying one of these names is skipped rather than allowed to replace
// the reporter's value: an offline filter on `comm` or `origin` has to mean the
// kernel's comm and this reporter's origin, whatever the traced process puts in
// its own pprof labels.
var contractLabelKeys = map[string]struct{}{
	LabelKTimeNs:      {},
	LabelTimestampNs:  {},
	LabelPID:          {},
	LabelTID:          {},
	LabelPPID:         {},
	LabelAncestry:     {},
	LabelComm:         {},
	LabelProcessName:  {},
	LabelExecutable:   {},
	LabelCPU:          {},
	LabelContainerID:  {},
	LabelOrigin:       {},
	LabelOffTimeNs:    {},
	LabelErlangPidKey: {},
}

func setString(s *profile.Sample, key, value string) {
	if value == "" {
		return
	}
	s.Label[key] = []string{value}
}

// setNumLabel writes a pprof numeric label. The unit is not decoration: see
// unitID -- google/pprof drops a numeric label that is both zero-valued and
// unit-less, so every num label written here carries one.
func setNumLabel(s *profile.Sample, key string, value int64, unit string) {
	s.NumLabel[key] = []int64{value}
	s.NumUnit[key] = []string{unit}
}
