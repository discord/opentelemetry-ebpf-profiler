// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

import (
	"errors"
	"fmt"
	"time"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
	"go.opentelemetry.io/ebpf-profiler/reporter/internal/pdata"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
)

// baseReporter encapsulates shared behavior between all the available reporters.
type baseReporter struct {
	cfg *Config

	// name is the ScopeProfile's name.
	name string

	// version is the ScopeProfile's version.
	version string

	// runLoop handles the run loop
	runLoop *runLoop

	// pdata holds the generator for the data being exported.
	pdata *pdata.Pdata

	// traceEvents stores reported trace events (trace metadata with frames and counts)
	traceEvents xsync.RWMutex[samples.TraceEventsTree]

	// collectionStartTime tracks when the current collection window started.
	// Initialized when Start() is called. The duration of the first profile may be
	// slightly overestimated as it includes tracer setup time before samples arrive.
	collectionStartTime time.Time
}

var errUnknownOrigin = errors.New("unknown trace origin")

func (b *baseReporter) Stop() {
	b.runLoop.Stop()
}

func (b *baseReporter) ReportTraceEvent(trace *libpf.Trace, meta *samples.TraceEventMeta) error {
	switch meta.Origin {
	case support.TraceOriginSampling:
	case support.TraceOriginOffCPU:
	case support.TraceOriginProbe:
	case support.TraceOriginBeamScope:
		// Discord (FIX-7): the OTLP/collector aggregation below keys on the
		// trace hash, which (correctly) excludes beamscope's per-sample num
		// labels (bin_vheap_delta, mbuf_words, pause_ns, nswitches, ...).
		// CustomLabels are stored only when a key is first inserted, so every
		// later sample for that key would silently inherit the first event's
		// frozen label values. Rather than emit wrong per-sample data, reject
		// the origin here: beamscope must be paired with the pprof file
		// reporter (-pprof-dir), which snapshots labels per event. main.go
		// enforces this at startup; this is the belt-and-suspenders backstop.
		return fmt.Errorf("beamscope requires the pprof-file reporter "+
			"(-pprof-dir); the OTLP path freezes per-sample labels: %w",
			errUnknownOrigin)
	default:
		return fmt.Errorf("skip reporting trace for %d origin: %w", meta.Origin,
			errUnknownOrigin)
	}

	var extraMeta any
	if b.cfg.ExtraSampleAttrProd != nil {
		extraMeta = b.cfg.ExtraSampleAttrProd.CollectExtraSampleMeta(trace, meta)
	}

	containerID := meta.ContainerID
	key := samples.TraceAndMetaKey{
		Hash:           trace.Hash,
		Comm:           meta.Comm,
		ProcessName:    meta.ProcessName,
		ExecutablePath: meta.ExecutablePath,
		ApmServiceName: meta.APMServiceName,
		Pid:            int64(meta.PID),
		Tid:            int64(meta.TID),
		CPU:            int64(meta.CPU),
		ExtraMeta:      extraMeta,
	}

	eventsTree := b.traceEvents.WLock()
	defer b.traceEvents.WUnlock(&eventsTree)

	if _, exists := (*eventsTree)[samples.ContainerID(containerID)]; !exists {
		(*eventsTree)[samples.ContainerID(containerID)] =
			make(map[libpf.Origin]samples.KeyToEventMapping)
	}

	if _, exists := (*eventsTree)[samples.ContainerID(containerID)][meta.Origin]; !exists {
		(*eventsTree)[samples.ContainerID(containerID)][meta.Origin] =
			make(samples.KeyToEventMapping)
	}

	if events, exists := (*eventsTree)[samples.ContainerID(containerID)][meta.Origin][key]; exists {
		events.Timestamps = append(events.Timestamps, uint64(meta.Timestamp))
		events.OffTimes = append(events.OffTimes, meta.OffTime)
		(*eventsTree)[samples.ContainerID(containerID)][meta.Origin][key] = events
		return nil
	}
	(*eventsTree)[samples.ContainerID(containerID)][meta.Origin][key] = &samples.TraceEvents{
		Frames:     trace.Frames,
		Timestamps: []uint64{uint64(meta.Timestamp)},
		OffTimes:   []int64{meta.OffTime},
		EnvVars:    meta.EnvVars,
		Labels:     trace.CustomLabels,
	}
	return nil
}
