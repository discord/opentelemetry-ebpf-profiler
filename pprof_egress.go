// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

// Discord addition: wiring for the local egress path
// (reporter.LocalEgressReporter). Kept in its own file so the delta on
// upstream's main.go and cli_flags.go is two calls, which is what keeps rebases
// cheap.
//
// The local egress has two INDEPENDENT backends, selected by their own flags:
// -pprof-dir writes pprof files, -socket-egress streams the same samples over a
// unix socket. Either, both, or neither: with neither, the agent ships OTLP to a
// collection agent exactly as upstream does.

import (
	"flag"
	"fmt"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/ebpf-profiler/reporter"
)

type pprofEgressArgs struct {
	dir           string
	flushInterval time.Duration
	maxBuffered   int
	keepPIDs      string
	keepComms     string

	// Socket egress: the same assembled samples, streamed live. Independent of
	// -pprof-dir; when both are set, pprof files are written exactly as before.
	socketPath          string
	socketRing          int
	socketMaxFrames     int
	socketFlushInterval time.Duration
	socketStatsInterval time.Duration
	socketWriteTimeout  time.Duration
}

var pprofEgress pprofEgressArgs

// Help strings. The tunables' defaults live in the reporter package and are
// interpolated here rather than restated, so there is one source of truth AND
// the numbers are discoverable from -help. See registerPprofEgressFlags for why
// the flags themselves default to zero.
const pprofDirHelp = "Write pprof files to this directory instead of sending OTLP to a " +
	"collection agent. One file per flush interval, one pprof sample per raw sample, " +
	"with per-sample kernel timestamp, pid, tid, comm, process name and container id."

var (
	pprofFlushIntervalHelp = fmt.Sprintf("How often the local pprof egress writes a file "+
		"(default %s). This is a file-size knob, not a resolution knob: finer windows are "+
		"cut offline from the per-sample kernel timestamps.",
		reporter.DefaultPprofFlushInterval)
	pprofMaxBufferedHelp = fmt.Sprintf("Maximum samples buffered between flushes of the "+
		"local pprof egress (default %d). Samples beyond this are dropped, counted, and "+
		"reported in the next profile's comments.",
		reporter.DefaultPprofMaxBufferedSamples)
	pprofKeepPIDsHelp = "Comma-separated PIDs to record, for the local egress. Applied " +
		"above the fan-out, so it restricts BOTH backends (pprof files and the socket " +
		"stream). Empty records every process. Prefer filtering offline on the sample " +
		"labels, which keeps one capture re-sliceable."
	pprofKeepCommsHelp = "Comma-separated thread names (comm) to record, for the local " +
		"egress. Applied above the fan-out, so it restricts BOTH backends. Empty " +
		"records every thread."

	socketPathHelp = "Stream every sample over this unix socket (the CONSUMER listens, " +
		"the agent dials and reconnects). Independent of -pprof-dir: use either, both, " +
		"or neither. With both, the same sample reaches both and pprof files are written " +
		"unchanged. This is the sub-iteration-resolution path: the pprof flush interval " +
		"is a file-size knob and cannot resolve a 1-3s iteration."
	socketRingHelp = fmt.Sprintf("Samples queued between the sampling path and the socket "+
		"writer (default %d). The agent NEVER blocks on a slow consumer: beyond this, "+
		"samples are dropped and counted, and the count rides on the wire next to the gap "+
		"it describes.", reporter.DefaultSocketRingSize)
	socketMaxFramesHelp = fmt.Sprintf("Maximum frames emitted per sample over the socket "+
		"(default %d). A capped sample is flagged on the wire and counted; the pprof file "+
		"never truncates, so a capped sample is NOT equivalent between the two paths.",
		reporter.DefaultSocketMaxFrames)
	socketFlushIntervalHelp = fmt.Sprintf("Safety net bounding how long a serialized "+
		"record may sit in the socket write buffer (default %s). NOT the latency floor: "+
		"every sample is flushed as it is written, so this ticker normally finds an empty "+
		"buffer.", reporter.DefaultSocketFlushInterval)
	socketWriteTimeoutHelp = fmt.Sprintf("How long one socket record write may take "+
		"before the consumer is declared gone and the connection is torn down "+
		"(default %s, clamped to [250ms, 5s]). A consumer that cannot keep up costs "+
		"samples, never agent latency. Shutdown waits this long plus 1s of slack, so "+
		"raising it also raises the shutdown backstop: the write deadline always "+
		"fires first, which is what makes a wedged consumer's loss exact rather "+
		"than approximate.", reporter.DefaultSocketWriteTimeout)
	socketStatsIntervalHelp = fmt.Sprintf("How often a STATS record (the absolute "+
		"counters) is emitted on the socket (default %s). Also emitted right after the "+
		"header and before a clean close.", reporter.DefaultSocketStatsInterval)
)

// registerPprofEgressFlags adds the local-pprof egress flags.
//
// The tunables are registered with a ZERO default on purpose. Every one of them
// already has a `if cfg.X <= 0 { cfg.X = defaultX }` fallback in the reporter
// package, and duplicating the numbers here means two places to change and a
// silent disagreement when only one of them is changed. Zero here means "not
// specified"; the reporter picks the default, whose value the help string above
// interpolates from the same constant.
func registerPprofEgressFlags(fs *flag.FlagSet) {
	fs.StringVar(&pprofEgress.dir, "pprof-dir", "", pprofDirHelp)
	fs.DurationVar(&pprofEgress.flushInterval, "pprof-flush-interval", 0,
		pprofFlushIntervalHelp)
	fs.IntVar(&pprofEgress.maxBuffered, "pprof-max-buffered-samples", 0, pprofMaxBufferedHelp)
	fs.StringVar(&pprofEgress.keepPIDs, "pprof-keep-pids", "", pprofKeepPIDsHelp)
	fs.StringVar(&pprofEgress.keepComms, "pprof-keep-comms", "", pprofKeepCommsHelp)
	fs.StringVar(&pprofEgress.socketPath, "socket-egress", "", socketPathHelp)
	fs.IntVar(&pprofEgress.socketRing, "socket-egress-ring", 0, socketRingHelp)
	fs.IntVar(&pprofEgress.socketMaxFrames, "socket-egress-max-frames", 0,
		socketMaxFramesHelp)
	fs.DurationVar(&pprofEgress.socketFlushInterval, "socket-egress-flush-interval",
		0, socketFlushIntervalHelp)
	fs.DurationVar(&pprofEgress.socketStatsInterval, "socket-egress-stats-interval",
		0, socketStatsIntervalHelp)
	fs.DurationVar(&pprofEgress.socketWriteTimeout, "socket-egress-write-timeout",
		0, socketWriteTimeoutHelp)
}

// pprofFlushInterval is the interval that will actually be used: the flag when
// set, the reporter's default otherwise. A zero flag value means "not
// specified", so printing it verbatim says "every 0s".
func pprofFlushInterval() time.Duration {
	if pprofEgress.flushInterval > 0 {
		return pprofEgress.flushInterval
	}
	return reporter.DefaultPprofFlushInterval
}

// socketEgressEnabled reports whether the socket backend was requested.
func socketEgressEnabled() bool { return pprofEgress.socketPath != "" }

// pprofEgressEnabled reports whether the pprof-file backend was requested.
func pprofEgressEnabled() bool { return pprofEgress.dir != "" }

// localEgressEnabled reports whether ANY local backend was requested. It is the
// condition for taking the local path instead of OTLP.
func localEgressEnabled() bool { return pprofEgressEnabled() || socketEgressEnabled() }

// beamscopeEgressSupported reports whether the selected egress can actually
// carry beamscope's per-sample data. Both local backends can: the socket wire
// carries value/value_kind, erlang_pid_key and typed custom labels as of
// version 2, resolved by the same rules the pprof path uses, so a socket-only
// capture is beamscope-complete rather than silently stripped. What is still
// not sufficient is no local egress at all -- the OTLP path freezes per-sample
// beamscope labels.
func beamscopeEgressSupported() bool { return localEgressEnabled() }

// newLocalEgressReporter builds the local egress reporter. samplesPerSecond must
// be the tracer's actual rate: it becomes the pprof profile period and the rate
// announced in the socket header, so every value derived from it is scaled by it.
func newLocalEgressReporter(samplesPerSecond int) (reporter.Reporter, error) {
	pids, err := parsePIDs(pprofEgress.keepPIDs)
	if err != nil {
		return nil, err
	}
	return reporter.NewLocalEgress(reporter.LocalEgressConfig{
		Dir:                pprofEgress.dir,
		FlushInterval:      pprofEgress.flushInterval,
		SamplesPerSecond:   samplesPerSecond,
		MaxBufferedSamples: pprofEgress.maxBuffered,
		KeepPIDs:           reporter.ParsePIDList(pids),
		KeepComms:          reporter.ParseCommList(splitList(pprofEgress.keepComms)),
		Socket: reporter.SocketConfig{
			Path:             pprofEgress.socketPath,
			RingSize:         pprofEgress.socketRing,
			MaxFrames:        pprofEgress.socketMaxFrames,
			FlushInterval:    pprofEgress.socketFlushInterval,
			StatsInterval:    pprofEgress.socketStatsInterval,
			WriteTimeout:     pprofEgress.socketWriteTimeout,
			SamplesPerSecond: samplesPerSecond,
		},
	})
}

func parsePIDs(csv string) ([]int, error) {
	var out []int
	for _, part := range splitList(csv) {
		pid, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("-pprof-keep-pids: %q is not a pid: %w", part, err)
		}
		out = append(out, pid)
	}
	return out, nil
}

func splitList(csv string) []string {
	if csv == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(csv, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
