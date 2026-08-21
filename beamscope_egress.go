// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

// Discord addition: wiring for the beamscope BEAM runtime-instrumentation
// plugin (interpreter/beamscope). Kept in its own file so the delta on
// upstream's main.go and cli_flags.go is one call each, which is what keeps
// rebases cheap.
//
// With -beamscope set, the agent discovers beam_scope shared-memory segments
// exported by the BEAM-resident NIF, reports GC allocation deltas through the
// active reporter (they land in the same pprof files as CPU samples, origin
// "beamscope"), and optionally writes the panel/monitor/process record stream
// as JSONL files under -beamscope-jsonl-dir. Without it, nothing here changes
// behaviour.

import (
	"flag"
	"time"

	"go.opentelemetry.io/ebpf-profiler/interpreter/beamscope"
	"go.opentelemetry.io/ebpf-profiler/reporter"
)

type beamscopeEgressArgs struct {
	enabled      bool
	pollInterval time.Duration
	jsonlDir     string
}

var beamscopeEgress beamscopeEgressArgs

const (
	beamscopeHelp = "Enable the beamscope BEAM runtime-instrumentation reader: discover " +
		"beam_scope shared-memory segments in BEAM processes and report GC allocation " +
		"deltas through the active reporter (origin \"beamscope\")."
	beamscopePollIntervalHelp = "How often each attached BEAM's beamscope rings are " +
		"drained. This bounds record latency and, together with the ring size, how much " +
		"burst the rings can absorb before the writer drops."
	beamscopeJSONLDirHelp = "Write beamscope panel/top-k/monitor/process records as JSONL " +
		"files (one beamscope-<pid>.jsonl per attached process) to this directory. " +
		"Empty disables the JSONL sidecar; GC deltas still go to the reporter."
)

// registerBeamscopeEgressFlags adds the beamscope flags.
func registerBeamscopeEgressFlags(fs *flag.FlagSet) {
	fs.BoolVar(&beamscopeEgress.enabled, "beamscope", false, beamscopeHelp)
	fs.DurationVar(&beamscopeEgress.pollInterval, "beamscope-poll-interval",
		250*time.Millisecond, beamscopePollIntervalHelp)
	fs.StringVar(&beamscopeEgress.jsonlDir, "beamscope-jsonl-dir", "",
		beamscopeJSONLDirHelp)
}

// configureBeamscopeEgress enables the beamscope plugin against the selected
// reporter. A no-op unless -beamscope was given.
func configureBeamscopeEgress(rep reporter.TraceReporter) error {
	if !beamscopeEgress.enabled {
		return nil
	}
	return beamscope.Configure(beamscope.Config{
		Reporter:     rep,
		PollInterval: beamscopeEgress.pollInterval,
		JSONLDir:     beamscopeEgress.jsonlDir,
	})
}
