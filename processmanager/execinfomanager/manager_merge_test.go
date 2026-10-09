// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package execinfomanager

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/nativeunwind/stackdeltatypes"
	"go.opentelemetry.io/ebpf-profiler/support"
)

func TestCalculateMergeOpcodeRequiresSameRegisterRules(t *testing.T) {
	first := stackdeltatypes.StackDelta{
		Offset: 0x100,
		Info: stackdeltatypes.UnwindInfo{
			BaseReg: support.UnwindRegSp,
			Param:   8,
		},
	}
	second := first
	second.Offset++
	second.Info.Param += 8

	require.Equal(t, uint8(1), calculateMergeOpcode(first, second))

	second.Info.Flags = support.UnwindFlagDerefCfa
	require.Zero(t, calculateMergeOpcode(first, second))

	second.Info.Flags = first.Info.Flags
	second.Info.X20Param = -24
	require.Zero(t, calculateMergeOpcode(first, second))

	second.Info.X20Param = first.Info.X20Param
	second.Info.X21Param = -16
	require.Zero(t, calculateMergeOpcode(first, second))

	second.Info.X21Param = first.Info.X21Param
	second.Info.X21Rule = support.UnwindX21CFA
	require.Zero(t, calculateMergeOpcode(first, second))
}
