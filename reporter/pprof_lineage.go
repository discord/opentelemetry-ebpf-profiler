// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

// Resolve parent and ancestor PIDs from /proc when a process first appears.
// An exited process may have no lineage; unresolved lookups are counted.

import (
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// maxAncestryDepth bounds the walk up the process tree. Deep enough for
// container init -> supervisor -> service -> worker -> child, shallow enough
// that a cycle from pid reuse cannot spin.
const maxAncestryDepth = 16

// lineageCacheCap bounds memory on a host that churns processes. On overflow the
// cache is dropped wholesale rather than evicting cleverly: entries are cheap to
// rebuild, and a clear is one log line instead of a policy.
const lineageCacheCap = 16384

type lineage struct {
	ppid      int
	ancestors []int // root first, excluding the process itself
	resolved  bool
}

type lineageCache struct {
	mu     sync.RWMutex
	byPID  map[int]lineage
	procFS string

	unresolved atomic.Uint64
	clears     atomic.Uint64
}

func newLineageCache(procFS string) *lineageCache {
	if procFS == "" {
		procFS = "/proc"
	}
	return &lineageCache{byPID: make(map[int]lineage), procFS: procFS}
}

// get returns the lineage for a pid, reading /proc on first sight.
func (c *lineageCache) get(pid int) lineage {
	c.mu.RLock()
	l, ok := c.byPID[pid]
	c.mu.RUnlock()
	if ok {
		return l
	}

	l = c.resolve(pid)
	if !l.resolved {
		c.unresolved.Add(1)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.byPID) >= lineageCacheCap {
		c.byPID = make(map[int]lineage)
		c.clears.Add(1)
	}
	c.byPID[pid] = l
	return l
}

// resolve walks up the process tree. A failed read at any level truncates the
// chain rather than discarding it: knowing the parent but not the grandparent is
// still worth having.
func (c *lineageCache) resolve(pid int) lineage {
	ppid, err := c.readPPID(pid)
	if err != nil {
		return lineage{}
	}
	l := lineage{ppid: ppid, resolved: true}

	// Walk upward, then reverse: the label reads better root first, and a prefix
	// then corresponds to a subtree.
	chain := []int{ppid}
	for cur := ppid; cur > 1 && len(chain) < maxAncestryDepth; {
		next, err := c.readPPID(cur)
		if err != nil || next == cur {
			break
		}
		chain = append(chain, next)
		cur = next
	}
	for _, pid := range slices.Backward(chain) {
		if pid == 0 {
			continue
		}
		l.ancestors = append(l.ancestors, pid)
	}
	return l
}

// readPPID reads field 4 of /proc/<pid>/stat. The comm field can contain spaces
// and parentheses, so the fields after it are located from the last ')' rather
// than by splitting the whole line.
func (c *lineageCache) readPPID(pid int) (int, error) {
	data, err := os.ReadFile(fmt.Sprintf("%s/%d/stat", c.procFS, pid))
	if err != nil {
		return 0, err
	}
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 || end+2 >= len(data) {
		return 0, fmt.Errorf("malformed stat for pid %d", pid)
	}
	fields := strings.Fields(string(data[end+2:]))
	if len(fields) < 2 {
		return 0, fmt.Errorf("stat for pid %d has %d fields after comm", pid, len(fields))
	}
	ppid, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0, fmt.Errorf("stat for pid %d: ppid %q: %w", pid, fields[1], err)
	}
	return ppid, nil
}

// ancestryLabel renders the chain root first, e.g. "1/4242/4250".
func (l lineage) ancestryLabel() string {
	if len(l.ancestors) == 0 {
		return ""
	}
	parts := make([]string, 0, len(l.ancestors))
	for _, pid := range l.ancestors {
		parts = append(parts, strconv.Itoa(pid))
	}
	return strings.Join(parts, "/")
}

// Unresolved reports how many pids had no lineage, which is the honest bound on
// how much any ancestry-based conclusion can be trusted.
func (c *lineageCache) Unresolved() uint64 { return c.unresolved.Load() }
