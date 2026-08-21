// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeProcFS writes /proc/<pid>/stat files with the given pid -> ppid mapping.
func fakeProcFS(t *testing.T, tree map[int]int, comms map[int]string) string {
	t.Helper()
	root := t.TempDir()
	for pid, ppid := range tree {
		dir := filepath.Join(root, fmt.Sprint(pid))
		require.NoError(t, os.MkdirAll(dir, 0o755))
		comm := comms[pid]
		if comm == "" {
			comm = "proc"
		}
		// Real format: pid (comm) state ppid ... -- comm can contain spaces and
		// parentheses, which is why parsing anchors on the last ')'.
		line := fmt.Sprintf("%d (%s) S %d 1 1 0 -1 4194304 0 0 0 0 0 0\n", pid, comm, ppid)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "stat"), []byte(line), 0o644))
	}
	return root
}

func TestLineageResolvesChainRootFirst(t *testing.T) {
	// 1 -> 100 (container init) -> 200 (beam.smp) -> 300 (erl_child_setup)
	root := fakeProcFS(t, map[int]int{1: 0, 100: 1, 200: 100, 300: 200}, nil)
	c := newLineageCache(root)

	l := c.get(300)
	assert.True(t, l.resolved)
	assert.Equal(t, 200, l.ppid)
	assert.Equal(t, "1/100/200", l.ancestryLabel(), "root first, excluding the process itself")

	l = c.get(100)
	assert.Equal(t, 1, l.ppid)
	assert.Equal(t, "1", l.ancestryLabel())

	assert.Zero(t, c.Unresolved())
}

// A comm containing spaces and parentheses is the classic /proc/stat parsing
// trap: splitting the line on whitespace puts the wrong field in ppid.
func TestLineageParsesAwkwardComm(t *testing.T) {
	root := fakeProcFS(t, map[int]int{1: 0, 42: 1},
		map[int]string{42: "weird (name) with spaces"})
	c := newLineageCache(root)
	l := c.get(42)
	require.True(t, l.resolved)
	assert.Equal(t, 1, l.ppid)
}

// A process that died before we looked has no lineage, and that has to be
// counted rather than silently rendered as "child of nothing".
func TestLineageCountsUnresolved(t *testing.T) {
	c := newLineageCache(t.TempDir())
	l := c.get(9999)
	assert.False(t, l.resolved)
	assert.Empty(t, l.ancestryLabel())
	assert.Equal(t, uint64(1), c.Unresolved())

	// Cached: a second lookup must not re-read or double-count.
	c.get(9999)
	assert.Equal(t, uint64(1), c.Unresolved())
}

// A cycle from pid reuse must terminate, and so must a very deep tree.
func TestLineageBoundsTheWalk(t *testing.T) {
	tree := map[int]int{}
	for pid := 2; pid <= 200; pid++ {
		tree[pid] = pid - 1
	}
	tree[1] = 0
	c := newLineageCache(fakeProcFS(t, tree, nil))
	l := c.get(200)
	require.True(t, l.resolved)
	assert.LessOrEqual(t, len(l.ancestors), maxAncestryDepth)

	// Self-parenting would loop forever without the guard.
	cyc := newLineageCache(fakeProcFS(t, map[int]int{7: 7}, nil))
	got := cyc.get(7)
	assert.True(t, got.resolved)
	assert.Equal(t, 7, got.ppid)
}

// The labels have to reach the file, or a descendant filter has nothing to match.
func TestPprofFileReporterWritesLineageLabels(t *testing.T) {
	root := fakeProcFS(t, map[int]int{1: 0, 100: 1, 200: 100}, nil)
	dir := t.TempDir()
	r, err := NewPprofFile(PprofFileConfig{Dir: dir, SamplesPerSecond: 100, ProcFS: root})
	require.NoError(t, err)
	require.NoError(t, r.ReportTraceEvent(testTrace(t, "a", "b"),
		meta(1, 200, 201, "worker", "beam.smp", "cid")))
	require.NoError(t, r.Flush())

	p := readOne(t, dir)
	require.Len(t, p.Sample, 1)
	assert.Equal(t, []int64{100}, p.Sample[0].NumLabel[LabelPPID])
	assert.Equal(t, []string{"1/100"}, p.Sample[0].Label[LabelAncestry])
}

// Unresolvable lineage is reported in the profile, so a reader can weigh an
// ancestry-based number instead of trusting it blindly.
func TestPprofFileReporterReportsUnresolvedLineage(t *testing.T) {
	dir := t.TempDir()
	r, err := NewPprofFile(PprofFileConfig{Dir: dir, SamplesPerSecond: 100, ProcFS: t.TempDir()})
	require.NoError(t, err)
	require.NoError(t, r.ReportTraceEvent(testTrace(t, "a"), meta(1, 4242, 4242, "c", "p", "k")))
	require.NoError(t, r.Flush())

	p := readOne(t, dir)
	require.NotEmpty(t, p.Comments)
	assert.Contains(t, p.Comments[0], "lineage unresolved for 1 pids")
	assert.Empty(t, p.Sample[0].Label[LabelAncestry])
}
