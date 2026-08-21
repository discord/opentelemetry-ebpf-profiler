// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

// Discord addition: write the agent's own metrics to a local file.
//
// The agent counts what it drops -- failed pid_events writes, reported-PID
// errors, unknown-PC traces, ring-buffer losses -- and those counters are the
// only way to tell "the profiler missed this process" from "the process was
// idle". Upstream ships them to the collector alongside profiles; the local
// pprof egress has no collector, so without this they go nowhere and a lossy
// capture is indistinguishable from a quiet one.

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"go.opentelemetry.io/otel/exporters/stdout/stdoutmetric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/metrics"
)

type metricsEgressArgs struct {
	path     string
	interval time.Duration
}

var metricsEgress metricsEgressArgs

const (
	metricsFileHelp = "Write the agent's own metrics as JSON lines to this file. " +
		"Without it, and without a collection agent, the counters that record dropped " +
		"samples and failed PID notifications are discarded."
	metricsIntervalHelp = "How often to write agent metrics to -metrics-file."
)

func registerMetricsEgressFlags(fs *flag.FlagSet) {
	fs.StringVar(&metricsEgress.path, "metrics-file", "", metricsFileHelp)
	fs.DurationVar(&metricsEgress.interval, "metrics-interval", 5*time.Second, metricsIntervalHelp)
}

// startMetricsEgress points the metrics package at a file-backed meter. It
// returns a shutdown function, and reports whether it started: with no
// -metrics-file the caller keeps upstream's noop meter.
func startMetricsEgress(ctx context.Context) (shutdown func(), started bool) {
	if metricsEgress.path == "" {
		return func() {}, false
	}
	f, err := os.Create(metricsEgress.path)
	if err != nil {
		log.Errorf("metrics egress: %v", err)
		return func() {}, false
	}
	exporter, err := stdoutmetric.New(
		stdoutmetric.WithWriter(f),
		// One JSON object per line: greppable, and appendable without a parser.
		stdoutmetric.WithoutTimestamps(),
	)
	if err != nil {
		log.Errorf("metrics egress: %v", err)
		f.Close()
		return func() {}, false
	}
	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter,
			sdkmetric.WithInterval(metricsEgress.interval))),
	)
	metrics.Start(provider.Meter("ebpf-profiler"))
	log.Infof("Writing agent metrics to %s every %s", metricsEgress.path, metricsEgress.interval)

	return func() {
		// Flush before closing: the last interval is usually the interesting
		// one, since that is where a run ends.
		flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := provider.ForceFlush(flushCtx); err != nil {
			log.Errorf("metrics egress: flush: %v", err)
		}
		if err := provider.Shutdown(flushCtx); err != nil {
			log.Errorf("metrics egress: shutdown: %v", err)
		}
		if err := f.Close(); err != nil {
			log.Errorf("metrics egress: %v", err)
		}
		fmt.Fprintln(os.Stderr, "agent metrics written to "+metricsEgress.path)
	}, true
}
