// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

// CLI configuration for the local pprof and socket reporters.

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
	pprofFlushIntervalHelp  = fmt.Sprintf("Write a pprof file at this interval (default %s). Samples retain their individual timestamps.", reporter.DefaultPprofFlushInterval)
	pprofMaxBufferedHelp    = fmt.Sprintf("Maximum buffered pprof samples (default %d). Excess samples are dropped and counted.", reporter.DefaultPprofMaxBufferedSamples)
	pprofKeepPIDsHelp       = "Comma-separated PIDs to record in both local outputs. Empty records all processes."
	pprofKeepCommsHelp      = "Comma-separated thread names to record in both local outputs. Empty records all threads."
	socketPathHelp          = "Stream samples to this Unix socket. The consumer listens and the agent reconnects. Can be used with -pprof-dir."
	socketRingHelp          = fmt.Sprintf("Maximum queued socket samples (default %d). Excess samples are dropped and counted.", reporter.DefaultSocketRingSize)
	socketMaxFramesHelp     = fmt.Sprintf("Maximum frames per socket sample (default %d). Truncated stacks are flagged.", reporter.DefaultSocketMaxFrames)
	socketFlushIntervalHelp = fmt.Sprintf("Maximum buffered socket-record latency (default %s). Samples are also flushed individually.", reporter.DefaultSocketFlushInterval)
	socketWriteTimeoutHelp  = fmt.Sprintf("Socket write timeout (default %s, clamped to [250ms, 5s]).", reporter.DefaultSocketWriteTimeout)
	socketStatsIntervalHelp = fmt.Sprintf("Interval between socket counter snapshots (default %s).", reporter.DefaultSocketStatsInterval)
)

// registerPprofEgressFlags registers local output flags. Zero-valued tunables
// use the defaults exported by the reporter package.
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

// beamscopeEgressSupported requires an output that preserves per-event labels.
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
	for part := range strings.SplitSeq(csv, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
