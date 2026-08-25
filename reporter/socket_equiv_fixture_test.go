// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/pprof/profile"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
)

// TestGenerateEquivalenceFixture replays REAL captures back through
// ReportTraceEvent with both egresses attached, and writes the two artifacts
// side by side:
//
//	$PSTORE_EQUIV_OUT/pprof/*.pb.gz   the pprof path's output
//	$PSTORE_EQUIV_OUT/stream.bin      the socket path's output, byte for byte
//	$PSTORE_EQUIV_OUT/manifest.json   what was replayed, and the counters
//
// Both come from the SAME ReportTraceEvent calls, so a difference between the
// flame graphs a consumer derives from them is a real semantic divergence in
// this fork's socket path and nothing else. That is the acceptance test the
// Rust side runs; this is only the fixture for it.
//
// Skipped unless PSTORE_EQUIV_OUT is set, so it costs a normal `go test`
// nothing and never needs the corpus to exist.
func TestGenerateEquivalenceFixture(t *testing.T) {
	out := os.Getenv("PSTORE_EQUIV_OUT")
	if out == "" {
		t.Skip("set PSTORE_EQUIV_OUT (and optionally PSTORE_EQUIV_IN) to generate the fixture")
	}
	in := os.Getenv("PSTORE_EQUIV_IN")
	if in == "" {
		in = "/home/discord/fsf_slots/campaigns/*/profiles/agent/*.pb.gz"
	}
	srcs, err := filepath.Glob(in)
	require.NoError(t, err)
	require.NotEmpty(t, srcs, "no captures matched %s", in)
	sort.Strings(srcs)
	if n := os.Getenv("PSTORE_EQUIV_FILES"); n != "" {
		var k int
		_, err := fmt.Sscanf(n, "%d", &k)
		require.NoError(t, err)
		if k > 0 && k < len(srcs) {
			srcs = srcs[:k]
		}
	}

	require.NoError(t, os.MkdirAll(filepath.Join(out, "pprof"), 0o755))
	streamPath := filepath.Join(out, "stream.bin")

	// PSTORE_EQUIV_NO_SOCKET produces the pprof artifact ALONE, from the same
	// replay. Folding that against the with-socket pprof is how acceptance (d)
	// is proved rather than asserted: if the socket egress perturbed the pprof
	// path at all, the two files disagree.
	noSocket := os.Getenv("PSTORE_EQUIV_NO_SOCKET") != ""

	// A listener that dumps straight to the file: this stands in for
	// pstore-ingest, and capturing the bytes means the Rust decoder is tested
	// against the real producer rather than a Rust re-encoding of the spec.
	sockDir, err := os.MkdirTemp("", "pseq")
	require.NoError(t, err)
	defer os.RemoveAll(sockDir)
	sockPath := filepath.Join(sockDir, "s")
	ln, err := net.Listen("unix", sockPath)
	require.NoError(t, err)
	f, err := os.Create(streamPath)
	require.NoError(t, err)
	var wg sync.WaitGroup
	if !noSocket {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// The same accept/drain loop the socket tests use, with the
			// fixture file as the sink instead of an in-memory buffer.
			serveOne(ln, f, nil)
		}()
	}

	// An empty procfs makes lineage deterministically unresolved: the replay
	// must not pick up ppid/ancestry from whatever happens to be running now.
	emptyProc := t.TempDir()

	r, err := NewLocalEgress(LocalEgressConfig{
		Dir:                filepath.Join(out, "pprof"),
		SamplesPerSecond:   997,
		FlushInterval:      time.Hour, // one file, flushed explicitly at the end
		MaxBufferedSamples: 1 << 24,
		ProcFS:             emptyProc,
		Socket:             socketCfg(noSocket, sockPath),
	})
	require.NoError(t, err)
	require.NoError(t, r.Start(t.Context()))

	var replayed int
	for _, src := range srcs {
		fh, err := os.Open(src)
		require.NoError(t, err)
		p, err := profile.Parse(fh)
		fh.Close()
		require.NoError(t, err)
		for _, s := range p.Sample {
			tr, ok := traceFromPprofSample(t, s)
			if !ok {
				continue
			}
			require.NoError(t, r.ReportTraceEvent(tr, metaFromPprofSample(s)))
			replayed++
		}
	}
	require.NoError(t, r.Flush())
	r.Stop()
	_ = ln.Close()
	wg.Wait()
	require.NoError(t, f.Close())

	// The fixture is only usable if NOTHING was lost on either side: an
	// equivalence test run over a lossy capture would compare two different
	// sample sets and could pass or fail for the wrong reason.
	require.Zero(t, r.Dropped(), "pprof path dropped samples; fixture is not comparable")
	if noSocket {
		// SocketDropped() is 0 for a reporter that has no socket sink, so
		// asserting it here would pin nothing. Assert the actual property of
		// this mode instead: the pprof-only artifact was produced with the
		// socket backend genuinely absent.
		require.Nil(t, r.socket, "PSTORE_EQUIV_NO_SOCKET must build no socket sink")
	} else {
		require.Zero(t, r.SocketDropped(),
			"socket path dropped samples; fixture is not comparable")
	}

	manifest := fmt.Sprintf(`{
  "sources": %d,
  "replayed_samples": %d,
  "pprof_dropped": %d,
  "socket_dropped": %d,
  "socket_version": %d,
  "input_glob": %q
}
`, len(srcs), replayed, r.Dropped(), r.SocketDropped(), SocketVersion, in)
	require.NoError(t, os.WriteFile(filepath.Join(out, "manifest.json"), []byte(manifest), 0o644))
	t.Logf("replayed %d samples from %d captures into %s", replayed, len(srcs), out)
}

// socketCfg returns the socket egress config, or the zero value (disabled)
// when the caller asked for a pprof-only fixture.
func socketCfg(disabled bool, path string) SocketConfig {
	if disabled {
		return SocketConfig{}
	}
	return SocketConfig{
		Path:          path,
		RingSize:      1 << 20,
		FlushInterval: 10 * time.Millisecond,
		StatsInterval: time.Hour,
	}
}

// traceFromPprofSample rebuilds the libpf.Trace that produced a pprof sample.
//
// This fork's pprof writer emits exactly one Location per frame with exactly
// one Line, so the mapping is 1:1 and lossless. That is asserted rather than
// assumed: if it ever stops holding, the fixture would silently reshape stacks
// and the equivalence test would be measuring the reshaping.
func traceFromPprofSample(t *testing.T, s *profile.Sample) (*libpf.Trace, bool) {
	t.Helper()
	tr := &libpf.Trace{}
	for _, loc := range s.Location {
		require.Len(t, loc.Line, 1,
			"fixture assumes one Line per Location, as this fork's writer emits")
		ln := loc.Line[0]
		require.NotNil(t, ln.Function)
		tr.Frames.Append(&libpf.Frame{
			Type:            libpf.NativeFrame,
			FunctionName:    libpf.Intern(ln.Function.Name),
			SourceFile:      libpf.Intern(ln.Function.Filename),
			SourceLine:      libpf.SourceLineno(ln.Line),
			AddressOrLineno: libpf.AddressOrLineno(loc.Address),
		})
	}
	return tr, len(s.Location) > 0
}

func metaFromPprofSample(s *profile.Sample) *samples.TraceEventMeta {
	num := func(k string) int64 {
		if v, ok := s.NumLabel[k]; ok && len(v) > 0 {
			return v[0]
		}
		return 0
	}
	str := func(k string) string {
		if v, ok := s.Label[k]; ok && len(v) > 0 {
			return v[0]
		}
		return ""
	}
	origin := libpf.Origin(support.TraceOriginSampling)
	switch strings.TrimSpace(str(LabelOrigin)) {
	case "off_cpu":
		origin = libpf.Origin(support.TraceOriginOffCPU)
	case "probe":
		origin = libpf.Origin(support.TraceOriginProbe)
	}
	return &samples.TraceEventMeta{
		Timestamp:      libpf.UnixTime64(num(LabelTimestampNs)),
		KTime:          num(LabelKTimeNs),
		Comm:           libpf.Intern(str(LabelComm)),
		ProcessName:    libpf.Intern(str(LabelProcessName)),
		ExecutablePath: libpf.Intern(str(LabelExecutable)),
		ContainerID:    libpf.Intern(str(LabelContainerID)),
		PID:            libpf.PID(num(LabelPID)),
		TID:            libpf.PID(num(LabelTID)),
		CPU:            int(num(LabelCPU)),
		Origin:         origin,
	}
}
