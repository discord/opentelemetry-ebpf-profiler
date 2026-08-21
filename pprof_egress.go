// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

// Discord addition: wiring for the local-pprof egress path
// (reporter.PprofFileReporter). Kept in its own file so the delta on upstream's
// main.go and cli_flags.go is two calls, which is what keeps rebases cheap.
//
// With -pprof-dir set, the agent writes pprof files locally and never dials a
// collection agent. Without it, nothing here changes behaviour.

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
}

var pprofEgress pprofEgressArgs

const (
	pprofDirHelp = "Write pprof files to this directory instead of sending OTLP to a " +
		"collection agent. One file per flush interval, one pprof sample per raw sample, " +
		"with per-sample kernel timestamp, pid, tid, comm, process name and container id."
	pprofFlushIntervalHelp = "How often the local pprof egress writes a file. This is a " +
		"file-size knob, not a resolution knob: finer windows are cut offline from the " +
		"per-sample kernel timestamps."
	pprofMaxBufferedHelp = "Maximum samples buffered between flushes of the local pprof " +
		"egress. Samples beyond this are dropped, counted, and reported in the next " +
		"profile's comments."
	pprofKeepPIDsHelp = "Comma-separated PIDs to record, for the local pprof egress. " +
		"Empty records every process. Prefer filtering offline on the sample labels, " +
		"which keeps one capture re-sliceable."
	pprofKeepCommsHelp = "Comma-separated thread names (comm) to record, for the local " +
		"pprof egress. Empty records every thread."
)

// registerPprofEgressFlags adds the local-pprof egress flags.
func registerPprofEgressFlags(fs *flag.FlagSet) {
	fs.StringVar(&pprofEgress.dir, "pprof-dir", "", pprofDirHelp)
	fs.DurationVar(&pprofEgress.flushInterval, "pprof-flush-interval", 10*time.Second,
		pprofFlushIntervalHelp)
	fs.IntVar(&pprofEgress.maxBuffered, "pprof-max-buffered-samples", 4<<20, pprofMaxBufferedHelp)
	fs.StringVar(&pprofEgress.keepPIDs, "pprof-keep-pids", "", pprofKeepPIDsHelp)
	fs.StringVar(&pprofEgress.keepComms, "pprof-keep-comms", "", pprofKeepCommsHelp)
}

// pprofEgressEnabled reports whether the local pprof path was requested.
func pprofEgressEnabled() bool { return pprofEgress.dir != "" }

// newPprofEgressReporter builds the local-pprof reporter. samplesPerSecond must
// be the tracer's actual rate: it becomes the profile period, and every value in
// the file is scaled by it.
func newPprofEgressReporter(samplesPerSecond int) (reporter.Reporter, error) {
	pids, err := parsePIDs(pprofEgress.keepPIDs)
	if err != nil {
		return nil, err
	}
	return reporter.NewPprofFile(reporter.PprofFileConfig{
		Dir:                pprofEgress.dir,
		FlushInterval:      pprofEgress.flushInterval,
		SamplesPerSecond:   samplesPerSecond,
		MaxBufferedSamples: pprofEgress.maxBuffered,
		KeepPIDs:           reporter.ParsePIDList(pids),
		KeepComms:          reporter.ParseCommList(splitList(pprofEgress.keepComms)),
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
