// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestSocketEgressPaced drives the REAL reporter at a paced rate into a socket
// somebody else is listening on, stamping each sample with the real
// CLOCK_MONOTONIC. It exists so the Rust consumer can be measured against the
// actual producer across a real unix socket, rather than against a Rust
// re-encoding of the wire format.
//
// Environment:
//
//	PSTORE_PACED_SOCK   the unix socket to dial (required; the test skips without it)
//	PSTORE_PACED_N      samples to emit (default 5000)
//	PSTORE_PACED_HZ     samples per second (default 2500 -- the measured
//	                    profiler rate is 2465/s, so this is slightly above real)
//	PSTORE_PACED_RING   socket ring size (default 65536; shrink it to force drops)
//	PSTORE_PACED_DEPTH  stack depth (default 12)
//
// It prints one summary line to stdout that the caller parses:
//
//	PACED produced=<n> dropped=<n> first_ktime=<ns> last_ktime=<ns> wall_ns=<n>
func TestSocketEgressPaced(t *testing.T) {
	sock := os.Getenv("PSTORE_PACED_SOCK")
	if sock == "" {
		t.Skip("set PSTORE_PACED_SOCK to drive a paced stream at an external listener")
	}
	n := envInt(t, "PSTORE_PACED_N", 5000)
	hz := envInt(t, "PSTORE_PACED_HZ", 2500)
	ring := envInt(t, "PSTORE_PACED_RING", 1<<16)
	depth := envInt(t, "PSTORE_PACED_DEPTH", 12)

	dir := t.TempDir()
	r, err := NewLocalEgress(LocalEgressConfig{
		Dir:              dir,
		SamplesPerSecond: 997,
		FlushInterval:    time.Hour,
		ProcFS:           t.TempDir(),
		Socket: SocketConfig{
			Path:     sock,
			RingSize: ring,
			// 10ms is the producer-side term in end-to-end latency: a
			// serialized record may sit in the write buffer this long.
			FlushInterval: 10 * time.Millisecond,
			StatsInterval: time.Second,
		},
	})
	require.NoError(t, err)
	require.NoError(t, r.Start(t.Context()))

	names := make([]string, depth)
	for i := range names {
		names[i] = fmt.Sprintf("frame_%02d", i)
	}
	tr := testTrace(t, names...)

	period := time.Duration(int64(time.Second) / int64(hz))
	start := time.Now()
	var firstK, lastK int64
	for i := 0; i < n; i++ {
		k := ktimeNs()
		if i == 0 {
			firstK = k
		}
		lastK = k
		m := meta(k, 4242, 4243, "1_scheduler", "beam.smp", "cafe0123deadbeef")
		m.KTime = k
		require.NoError(t, r.ReportTraceEvent(tr, m))
		// Busy-free pacing: sleeping per sample at 2500Hz is 400us, which the
		// scheduler honours well enough for this purpose.
		next := start.Add(time.Duration(i+1) * period)
		if d := time.Until(next); d > 0 {
			time.Sleep(d)
		}
	}
	wall := time.Since(start)
	require.NoError(t, r.Flush())
	r.Stop()

	fmt.Printf("PACED produced=%d dropped=%d first_ktime=%d last_ktime=%d wall_ns=%d\n",
		n, r.SocketDropped(), firstK, lastK, wall.Nanoseconds())
}

func envInt(t *testing.T, key string, def int) int {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	require.NoError(t, err, "%s must be an integer", key)
	return n
}
