// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStandaloneDefaultsValidateAfterRebase(t *testing.T) {
	saved := os.Args
	t.Cleanup(func() { os.Args = saved })
	os.Args = []string{"ebpf-profiler", "-tracers", "beam", "-no-kernel-version-check"}
	cfg, err := parseArgs()
	require.NoError(t, err)
	require.NoError(t, cfg.Validate())
	require.False(t, cfg.Interpreters.BEAM.IsDisabled())
	require.True(t, cfg.Interpreters.Python.IsDisabled())
	require.True(t, cfg.Interpreters.Go.IsDisabled())
}
