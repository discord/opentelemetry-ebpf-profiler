// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package samples // import "go.opentelemetry.io/ebpf-profiler/reporter/samples"

const (
	ValueKindNone uint8 = iota
	ValueKindAlloc
	ValueKindSchedNS
	ValueKindMsgs
)

var beamscopeProfiles = [...]TypeMetadata{
	ValueKindAlloc:   {SampleType: "alloc", SampleUnit: "words", ReportValues: true},
	ValueKindSchedNS: {SampleType: "on_sched", SampleUnit: "nanoseconds", ReportValues: true},
	ValueKindMsgs:    {SampleType: "msgs", SampleUnit: "count", ReportValues: true},
}

// BeamScopeProfile describes a beamscope measurement. Unknown kinds return nil.
func BeamScopeProfile(kind uint8) *TypeMetadata {
	if kind == ValueKindNone || int(kind) >= len(beamscopeProfiles) {
		return nil
	}
	return &beamscopeProfiles[kind]
}

// BeamScopeValueKind maps profile metadata to the local egress measurement kind.
func BeamScopeValueKind(p *TypeMetadata) uint8 {
	if p != nil {
		for kind := ValueKindAlloc; int(kind) < len(beamscopeProfiles); kind++ {
			if *p == beamscopeProfiles[kind] {
				return kind
			}
		}
	}
	return ValueKindNone
}
