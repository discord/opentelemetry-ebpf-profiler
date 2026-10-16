// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"slices"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension"
	"go.uber.org/zap"

	cebpf "github.com/cilium/ebpf"

	"go.opentelemetry.io/ebpf-profiler/internal/controller"
	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/probes/kprobe"
	"go.opentelemetry.io/ebpf-profiler/probes/offcpu"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

func enableCLIProbes(ctx context.Context, ctlr *controller.Controller, cfg *cliConfig) (func(), error) {
	var probes []tracer.Probe
	cleanup := func() {
		for _, p := range slices.Backward(probes) {
			if err := p.Unload(); err != nil {
				log.Errorf("Unloading probe: %v", err)
			}
		}
	}
	enableProbe := func(p tracer.Probe) error {
		probes = append(probes, p)
		return ctlr.EnableProbe(ctx, p)
	}
	fail := func(err error) (func(), error) { cleanup(); return nil, err }
	if cfg.LoadProbe {
		if err := enableProbe(&unattachedProbe{}); err != nil {
			return fail(err)
		}
	}
	enable := func(factory extension.Factory, c component.Config) error {
		if validator, ok := c.(interface{ Validate() error }); ok {
			if err := validator.Validate(); err != nil {
				return err
			}
		}
		e, err := factory.Create(ctx, extension.Settings{
			ID:                component.NewID(factory.Type()),
			TelemetrySettings: component.TelemetrySettings{Logger: zap.NewNop()},
		}, c)
		if err != nil {
			return err
		}
		return enableProbe(e.(interface{ Probe() tracer.Probe }).Probe())
	}
	if cfg.OffCPUThreshold > 0 {
		if err := enable(offcpu.NewFactory(), &offcpu.Config{Threshold: cfg.OffCPUThreshold}); err != nil {
			return fail(err)
		}
	}
	for _, value := range cfg.ProbeLinks {
		spec, err := tracer.ParseProbe(value)
		if err != nil {
			return fail(err)
		}
		if err := enable(kprobe.NewFactory(), &kprobe.Config{
			Mode: spec.Mode.String(), Target: spec.Target, Symbol: spec.Symbol,
		}); err != nil {
			return fail(err)
		}
	}
	return cleanup, nil
}

// unattachedProbe keeps the generic unwinder loaded for external attachment by program ID.
type unattachedProbe struct{ prog *cebpf.Program }

func (p *unattachedProbe) Load(_ context.Context, reg tracer.ProbeRegistrar, ctx *tracer.ProbeContext) error {
	const name = "kprobe__generic"
	id, err := reg.Register(&samples.TypeMetadata{SampleType: "events", SampleUnit: "count"})
	if err != nil {
		return err
	}
	coll, err := ctx.CollectionSpecWith(nil, []string{name}, []string{"origin_id_probe"})
	if err != nil {
		return err
	}
	if err = coll.Variables["origin_id_probe"].Set(id); err != nil {
		return err
	}
	if err = ctx.RewriteMaps(coll, nil); err != nil {
		return err
	}
	progs := make(map[string]*cebpf.Program)
	if err = ctx.LoadProbeUnwinders(coll, progs, []tracer.ProgLoaderHelper{{Name: name, NoTailCallTarget: true, Enable: true}}, 0); err != nil {
		return err
	}
	p.prog = progs[name]
	if p.prog == nil {
		return fmt.Errorf("generic probe program was not loaded")
	}
	return nil
}

func (p *unattachedProbe) Unload() error {
	if p.prog == nil {
		return nil
	}
	return p.prog.Close()
}
