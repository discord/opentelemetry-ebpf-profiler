// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package samples // import "go.opentelemetry.io/ebpf-profiler/reporter/samples"

import (
	"go.opentelemetry.io/ebpf-profiler/libpf"
)

type TraceEventMeta struct {
	Timestamp libpf.UnixTime64
	// KTime is the raw kernel timestamp the sample was taken at:
	// bpf_ktime_get_ns(), CLOCK_MONOTONIC nanoseconds since boot.
	//
	// Timestamp above is derived from this by adding a boot-time offset that is
	// re-estimated periodically, so it carries that estimate's error and can
	// even reorder two samples across a resync. Consumers that need an exact
	// stamp, or that correlate against any other kernel-side instrumentation
	// (perf, sched tracepoints) or against a CLOCK_MONOTONIC reading in the
	// profiled application, want this one.
	KTime          int64
	Comm           libpf.String
	ProcessName    libpf.String
	ExecutablePath libpf.String
	APMServiceName string
	ContainerID    libpf.String
	PID, TID       libpf.PID
	CPU            int
	Origin         libpf.Origin
	// OffTime is exclusively the off-CPU sample's off-scheduler nanoseconds.
	// It is never a generic value channel for other origins (see Value below).
	OffTime int64
	// Value and ValueKind are Discord additions: a general per-sample
	// value channel, distinct from OffTime, used by beamscope-origin samples.
	// ValueKind says what unit Value is in (see the ValueKind* consts); it is
	// ValueKindNone for every origin that does not use this channel.
	Value     int64
	ValueKind uint8
	// ErlangPidKey is a Discord addition: the raw Eterm of the Erlang
	// process a BEAM scheduler thread was running when the CPU sample landed,
	// or 0 when the sample is not attributable. It is the join key against
	// beam_scope's JSONL records, so it is carried as an opaque 64-bit value
	// and never reinterpreted.
	ErlangPidKey uint64
	EnvVars      map[libpf.String]libpf.String
}

// ValueKind* name the units TraceEventMeta.Value can carry. ValueKindNone
// means the sample does not use this channel (its value, if any, lives
// elsewhere, e.g. OffTime for off-CPU samples).
const (
	ValueKindNone    uint8 = 0
	ValueKindAlloc   uint8 = 1
	ValueKindSchedNS uint8 = 2
	ValueKindMsgs    uint8 = 3
)

// TraceEvents holds known information about a trace.
type TraceEvents struct {
	Frames     libpf.Frames
	Timestamps []uint64 // in nanoseconds
	OffTimes   []int64  // in nanoseconds
	EnvVars    map[libpf.String]libpf.String
	Labels     map[libpf.String]libpf.String
}

// TraceAndMetaKey is the deduplication key for samples. This **must always**
// contain all trace fields that aren't already part of the trace hash to ensure
// that we don't accidentally merge traces with different fields.
type TraceAndMetaKey struct {
	// Hash is not sent forward, but it is used as the primary key
	// to not aggregate difference traces.
	Hash libpf.TraceHash
	// comm and apmServiceName are provided by the eBPF programs
	Comm           libpf.String
	ApmServiceName string
	Pid            int64
	Tid            int64
	CPU            int64
	// Process name is retrieved from /proc/PID/comm
	ProcessName libpf.String
	// Executable path is retrieved from /proc/PID/exe
	ExecutablePath libpf.String

	// ExtraMeta stores extra meta info that may have been produced by a
	// `SampleAttrProducer` instance. May be nil.
	ExtraMeta any
}

// TraceEventsTree stores samples and their related metadata in a tree-like
// structure optimized for the OTel Profiling protocol representation.
type TraceEventsTree map[ContainerID]map[libpf.Origin]KeyToEventMapping

// ContainerID represents an extracted key from /proc/<PID>/cgroup.
type ContainerID = libpf.String

// KeyToEventMapping supports temporary mapping traces to additional information.
type KeyToEventMapping map[TraceAndMetaKey]*TraceEvents
