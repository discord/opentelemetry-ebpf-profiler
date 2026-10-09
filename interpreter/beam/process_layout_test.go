// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package beam

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func openLayoutFixture(t *testing.T, name string) *os.File {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, f.Close()) })
	return f
}

func TestReadOTP25ProcessLayout(t *testing.T) {
	layout, err := readOTP25ProcessLayout(openLayoutFixture(t, "process_layout.o"))
	require.NoError(t, err)
	require.Equal(t, otp25ProcessLayout{stop: 8, framePointer: 16, i: 24, current: 32, schedulerData: 40}, layout)
}

func TestReadOTP25ProcessLayoutWithoutFramePointer(t *testing.T) {
	layout, err := readOTP25ProcessLayout(openLayoutFixture(t, "process_layout_no_fp.o"))
	require.NoError(t, err)
	require.Equal(t, otp25ProcessLayout{stop: 8, i: 16, current: 24, schedulerData: 32}, layout)
}

func TestReadOTP25ProcessLayoutFailsClosed(t *testing.T) {
	_, err := readOTP25ProcessLayout(openLayoutFixture(t, "process_layout_no_dwarf.o"))
	require.Error(t, err)
}

func TestReadOTP25SchedulerLayout(t *testing.T) {
	layout, err := readOTP25SchedulerLayout(openLayoutFixture(t, "process_layout.o"))
	require.NoError(t, err)
	require.Equal(t, otp25SchedulerLayout{currentProcess: 32, currentNIF: 40}, layout)
}

func TestReadOTP25SchedulerLayoutFailsClosed(t *testing.T) {
	_, err := readOTP25SchedulerLayout(openLayoutFixture(t, "process_layout_no_dwarf.o"))
	require.Error(t, err)
}

func TestReadOTP25NativeFuncLayout(t *testing.T) {
	layout, err := readOTP25NativeFuncLayout(openLayoutFixture(t, "process_layout.o"))
	require.NoError(t, err)
	require.Equal(t, otp25NativeFuncLayout{trampoline: 16, mfa: 24, argc: 32}, layout)
}

func TestReadOTP25NativeFuncLayoutFailsClosed(t *testing.T) {
	_, err := readOTP25NativeFuncLayout(openLayoutFixture(t, "process_layout_no_dwarf.o"))
	require.Error(t, err)
}
