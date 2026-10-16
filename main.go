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
	"runtime/debug"

	"golang.org/x/sys/unix"

	"go.opentelemetry.io/otel/metric/noop"

	"go.opentelemetry.io/ebpf-profiler/internal/controller"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/times"

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
		fmt.Printf("%s\n", agentVersion())
		return exitSuccess
	}

	if cfg.VerboseMode {
		log.SetLevel(slog.LevelDebug)
		// Dump the arguments in debug mode.
		log.Debugf("Configuration: %+v", cfg)
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
			if err := http.ListenAndServe(cfg.PprofAddr, nil); err != nil {
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

	if beamscopeEgress.enabled && !beamscopeEgressSupported() {
		return failure("-beamscope requires a local egress (-pprof-dir or " +
			"-socket-egress); the OTLP path freezes per-sample beamscope labels")
	}

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
			Version:                agentVersion(),
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

	log.Infof("Starting OTEL profiling agent %s", agentVersion())

	ctlr := controller.New(&cfg.Config)
	defer ctlr.Shutdown()
	err = ctlr.Start(ctx)
	if err != nil {
		return failure("Failed to start agent controller: %v", err)
	}
	cleanupProbes, err := enableCLIProbes(ctx, ctlr, cfg)
	if err != nil {
		return failure("Failed to enable probes: %v", err)
	}
	defer cleanupProbes()

	// Block waiting for a signal to indicate the program should terminate
	<-ctx.Done()

	log.Info("Exiting ...")
	return exitSuccess
}

func failure(msg string, args ...any) exitCode {
	log.Errorf(msg, args...)
	return exitFailure
}

func agentVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		return info.Main.Version
	}
	return "unknown"
}
