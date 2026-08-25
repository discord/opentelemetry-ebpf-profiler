// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	//nolint:gosec
	_ "net/http/pprof"
	"os"
	"os/signal"

	"golang.org/x/sys/unix"

	"go.opentelemetry.io/ebpf-profiler/internal/controller"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/times"
	tracertypes "go.opentelemetry.io/ebpf-profiler/tracer/types"
	"go.opentelemetry.io/ebpf-profiler/vc"
	"go.opentelemetry.io/otel/metric/noop"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
)

// Short copyright / license text for eBPF code
var copyright = `Copyright The OpenTelemetry Authors.

For the eBPF code loaded by Universal Profiling Agent into the kernel,
the following license applies (GPLv2 only). You can obtain a copy of the GPLv2 code at:
https://go.opentelemetry.io/ebpf-profiler/tree/main/support/ebpf

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 only,
as published by the Free Software Foundation;

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details:

https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html
`

type exitCode int

const (
	exitSuccess exitCode = 0
	exitFailure exitCode = 1

	// Go 'flag' package calls os.Exit(2) on flag parse errors, if ExitOnError is set
	exitParseError exitCode = 2
)

func main() {
	os.Exit(int(mainWithExitCode()))
}

func mainWithExitCode() exitCode {
	cfg, err := parseArgs()
	if err != nil {
		log.Errorf("Failure to parse arguments: %v", err)
		return exitParseError
	}

	if cfg.Copyright {
		fmt.Print(copyright)
		return exitSuccess
	}

	if cfg.Version {
		fmt.Printf("%s\n", vc.Version())
		return exitSuccess
	}

	if cfg.VerboseMode {
		log.SetLevel(slog.LevelDebug)
		// Dump the arguments in debug mode.
		cfg.Dump()
	}

	if err = cfg.Validate(); err != nil {
		log.Error(err)
		return exitFailure
	}

	// Context to drive main goroutine and the Tracer monitors.
	ctx, mainCancel := signal.NotifyContext(context.Background(),
		unix.SIGINT, unix.SIGTERM, unix.SIGABRT)
	defer mainCancel()

	if cfg.PprofAddr != "" {
		go func() {
			//nolint:gosec
			if err = http.ListenAndServe(cfg.PprofAddr, nil); err != nil {
				log.Errorf("Serving pprof on %s failed: %s", cfg.PprofAddr, err)
			}
		}()
	}

	intervals := times.New(cfg.ReporterInterval,
		cfg.MonitorInterval, cfg.ProbabilisticInterval)

	// Discord: with -metrics-file the agent's own counters go to a local file;
	// otherwise upstream's noop meter, which discards them.
	metricsShutdown, metricsStarted := startMetricsEgress(ctx)
	defer metricsShutdown()
	if !metricsStarted {
		metrics.Start(noop.Meter{})
	}

	// Discord (FIX-7): beamscope's per-sample num labels are encoded correctly
	// only by the local egress's pprof-file backend, which snapshots
	// CustomLabels per event. The OTLP/collector path aggregates on the trace
	// hash (which excludes those labels) and would freeze them at the first
	// event per key. Fail loud at startup rather than silently emit wrong
	// per-sample data; the base reporter also rejects the origin as a backstop.
	//
	// Either local backend satisfies this: socket wire v2 carries value,
	// value_kind, erlang_pid_key and typed custom labels, so socket-only is a
	// complete beamscope capture. What is still not sufficient is OTLP or no
	// egress at all.
	if beamscopeEgress.enabled && !beamscopeEgressSupported() {
		return failure("-beamscope requires a local egress (-pprof-dir or " +
			"-socket-egress); the OTLP path freezes per-sample beamscope labels")
	}

	// Discord: per-sample Erlang attribution (erlang_pid_key, section 3.9 of
	// doc/discord-fork.md) is switched on by "-tracers beam" ALONE -- it does
	// not need -beamscope -- and reaches BOTH local backends: the pprof file
	// writes it as a numeric label, socket wire v2 as a fixed field. The OTLP
	// reporter never emits it, so "-tracers beam" with no local egress still
	// pays the whole attach-time stride probe and then drops every label it
	// bought. Warn rather than fail: the BEAM tracer is genuinely useful
	// without the attribution, but the loss must not be silent.
	if !localEgressEnabled() {
		if it, perr := tracertypes.Parse(cfg.Tracers); perr == nil &&
			it.Has(tracertypes.BEAMTracer) {
			log.Warn("the beam tracer is enabled without a local egress " +
				"(-pprof-dir or -socket-egress): for any BEAM process profiled " +
				"here, per-sample Erlang attribution (erlang_pid_key) is " +
				"computed and then DROPPED -- the OTLP reporter cannot carry it")
		}
	}

	// Discord: with -pprof-dir and/or -socket-egress, egress is local; see
	// pprof_egress.go.
	if localEgressEnabled() {
		rep, err := newLocalEgressReporter(int(cfg.SamplesPerSecond))
		if err != nil {
			log.Error(err)
			return exitFailure
		}
		cfg.Reporter = rep
		if pprofEgressEnabled() {
			log.Infof("Writing pprof profiles to %s every %s",
				pprofEgress.dir, pprofFlushInterval())
		}
		if socketEgressEnabled() {
			log.Infof("Streaming samples to unix socket %s", pprofEgress.socketPath)
		}
	} else {
		rep, err := reporter.NewOTLP(&reporter.Config{
			Name:                   os.Args[0],
			Version:                vc.Version(),
			CollAgentAddr:          cfg.CollAgentAddr,
			DisableTLS:             cfg.DisableTLS,
			MaxRPCMsgSize:          32 << 20, // 32 MiB
			MaxGRPCRetries:         5,
			GRPCOperationTimeout:   intervals.GRPCOperationTimeout(),
			GRPCStartupBackoffTime: intervals.GRPCStartupBackoffTime(),
			GRPCConnectionTimeout:  intervals.GRPCConnectionTimeout(),
			ReportInterval:         intervals.ReportInterval(),
			ReportJitter:           cfg.ReporterJitter,
			SamplesPerSecond:       cfg.SamplesPerSecond,
		})
		if err != nil {
			log.Error(err)
			return exitFailure
		}
		cfg.Reporter = rep
	}

	// Discord: with -beamscope, drain BEAM shm instrumentation into the
	// selected reporter (+ optional JSONL sidecar); see beamscope_egress.go.
	if err = configureBeamscopeEgress(cfg.Reporter); err != nil {
		log.Error(err)
		return exitFailure
	}

	log.Infof("Starting OTEL profiling agent %s (revision %s, build timestamp %s)",
		vc.Version(), vc.Revision(), vc.BuildTimestamp())

	ctlr := controller.New(cfg)
	err = ctlr.Start(ctx)
	if err != nil {
		return failure("Failed to start agent controller: %v", err)
	}
	defer ctlr.Shutdown()

	// Block waiting for a signal to indicate the program should terminate
	<-ctx.Done()

	log.Info("Exiting ...")
	return exitSuccess
}

func failure(msg string, args ...any) exitCode {
	log.Errorf(msg, args...)
	return exitFailure
}
