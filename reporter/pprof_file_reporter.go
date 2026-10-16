// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

// pprofFileSink writes one sample per event, with timestamps for offline
// window slicing and labels for process attribution.

import (
	"context"
	"crypto/rand"
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

// Default output settings, also used in CLI help.
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
	// Events are shared with the socket writer and must remain immutable.
	events      []*sampleEvent
	windowStart time.Time

	dropped atomic.Uint64
	written atomic.Uint64

	// The assembler's lineage cache supplies unresolved-lookup counts for
	// profile comments.
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

	stopOnce sync.Once
	stop     chan struct{}
	done     chan struct{}
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
	if !s.started.CompareAndSwap(false, true) {
		return
	}
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
	s.stopOnce.Do(func() { close(s.stop) })
	<-s.done
	if err := s.Flush(); err != nil {
		log.Errorf("pprof egress: final flush failed: %v", err)
	}
}

// Flush writes the buffered samples as one pprof file.
// A flush with nothing buffered writes no file and is not an error.
func (s *pprofFileSink) Flush() (err error) {
	s.mu.Lock()
	events := s.events
	start := s.windowStart
	s.events = nil
	s.windowStart = time.Time{}
	s.mu.Unlock()

	if len(events) == 0 {
		return nil
	}
	defer func() {
		if err != nil {
			s.dropped.Add(uint64(len(events)))
		}
	}()
	end := time.Now()
	if start.IsZero() {
		start = end
	}
	p := s.build(events, start, end)
	seq := s.written.Add(1)
	path := filepath.Join(s.dir,
		fmt.Sprintf("profile-%06d-%d.pb.gz", seq, start.UnixNano()))
	// Preserve normal file creation permissions and the caller's umask.
	tempPath := filepath.Join(s.dir, ".profile-"+rand.Text()+".tmp")
	f, err := os.OpenFile(tempPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o666)
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = p.Write(f); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

// build renders buffered samples as a pprof profile: one sample per event,
// values in samples and nanoseconds, every label from the contract attached.
func (s *pprofFileSink) build(events []*sampleEvent, start, end time.Time) *profile.Profile {
	periodNs := int64(time.Second) / int64(s.samplesPerSecond)
	p := &profile.Profile{
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
			fmt.Sprintf("dropped %d samples (buffer limit %d or profile write failures)",
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

	type functionKey struct{ name, file string }
	funcs := map[functionKey]*profile.Function{}
	locs := map[frame]*profile.Location{}
	location := func(fr frame) *profile.Location {
		if loc, ok := locs[fr]; ok {
			return loc
		}
		key := functionKey{fr.function, fr.file}
		fn, ok := funcs[key]
		if !ok {
			fn = &profile.Function{
				ID:         uint64(len(p.Function) + 1),
				Name:       fr.function,
				SystemName: fr.function,
				Filename:   fr.file,
			}
			p.Function = append(p.Function, fn)
			funcs[key] = fn
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
		// pprof drops numeric labels when both value and unit are zero. Supply
		// an ID unit so CPU 0 and other zero-valued identifiers survive encoding.
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
		// Zero means no Erlang attribution. pprof numeric labels are signed;
		// cast back to uint64 to recover the opaque Eterm bit pattern.
		if ev.erlangPidKey != 0 {
			setNumLabel(sm, LabelErlangPidKey, int64(ev.erlangPidKey), unitID)
		}
		setString(sm, LabelComm, ev.comm)
		setString(sm, LabelProcessName, ev.processName)
		setString(sm, LabelExecutable, ev.executable)
		setString(sm, LabelContainerID, ev.containerID)
		setString(sm, LabelOrigin, originName(ev.origin))
		// Only periodic CPU samples carry period-derived CPU time. Event-driven
		// probes contribute to the sample count; beamscope fills its measured column.
		switch ev.origin {
		case originBeamScope:
			switch ev.valueKind {
			case samples.ValueKindAlloc:
				sm.Value[2] = ev.value
			case samples.ValueKindSchedNS:
				sm.Value[3] = ev.value
			case samples.ValueKindMsgs:
				sm.Value[4] = ev.value
			}
		case originOffCPU:
			// cpu-ns column intentionally stays 0.
		case originSampling:

			sm.Value[1] = periodNs
		}
		// Custom labels cannot overwrite contract labels. Numeric promotion
		// applies only to beamscope's known measurement labels.
		for k, v := range ev.labels {
			if _, reserved := contractLabelKeys[k]; reserved {
				continue
			}
			if ev.origin == originBeamScope {
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

// numLabelUnits defines beamscope's numeric label units. Other custom
// labels retain their string representation.
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
