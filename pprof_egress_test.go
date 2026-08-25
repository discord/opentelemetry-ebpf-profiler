// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.opentelemetry.io/ebpf-profiler/reporter"
)

// The local egress has two independent backends and therefore four
// combinations. This pins which reporter each one selects, including the one
// that used to be refused at startup (-socket-egress without -pprof-dir).
func TestLocalEgressBackendSelection(t *testing.T) {
	saved := pprofEgress
	t.Cleanup(func() { pprofEgress = saved })

	for _, tc := range []struct {
		name                  string
		dir, sock             string
		wantPprof, wantSocket bool
		wantLocal             bool
	}{
		{name: "neither", wantLocal: false},
		{name: "pprof only", dir: "/tmp/x", wantPprof: true, wantLocal: true},
		{name: "socket only", sock: "/tmp/s", wantSocket: true, wantLocal: true},
		{name: "both", dir: "/tmp/x", sock: "/tmp/s",
			wantPprof: true, wantSocket: true, wantLocal: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pprofEgress = pprofEgressArgs{dir: tc.dir, socketPath: tc.sock}
			if got := pprofEgressEnabled(); got != tc.wantPprof {
				t.Errorf("pprofEgressEnabled() = %v, want %v", got, tc.wantPprof)
			}
			if got := socketEgressEnabled(); got != tc.wantSocket {
				t.Errorf("socketEgressEnabled() = %v, want %v", got, tc.wantSocket)
			}
			// localEgressEnabled is what main() branches on: with neither
			// backend the agent takes the OTLP path, dials no socket and
			// writes no files.
			if got := localEgressEnabled(); got != tc.wantLocal {
				t.Errorf("localEgressEnabled() = %v, want %v", got, tc.wantLocal)
			}
		})
	}
}

// Socket-only must actually construct. Before the backends were split this
// returned a reporter that could not exist without -pprof-dir, and main
// rejected the combination outright.
func TestNewLocalEgressReporterAcceptsSocketOnly(t *testing.T) {
	saved := pprofEgress
	t.Cleanup(func() { pprofEgress = saved })

	dir := t.TempDir()
	pprofEgress = pprofEgressArgs{socketPath: filepath.Join(dir, "s.sock")}
	rep, err := newLocalEgressReporter(997)
	if err != nil {
		t.Fatalf("socket-only reporter: %v", err)
	}
	if rep == nil {
		t.Fatal("socket-only reporter is nil")
	}
	// Nothing is written anywhere: the pprof backend does not exist, and the
	// socket is not dialed until Start.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("socket-only reporter created %d files", len(entries))
	}

	// And neither backend is a construction error, not a silent no-op reporter.
	pprofEgress = pprofEgressArgs{}
	if _, err := newLocalEgressReporter(997); err == nil {
		t.Error("a local egress with no backend must not construct")
	}
}

// -help has to document every knob with its real default. The socket tunables
// are registered with a zero default on purpose (the reporter picks), so the
// number only reaches the user through the help string.
func TestSocketFlagsDocumentTheirDefaults(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	registerPprofEgressFlags(fs)
	for _, tc := range []struct{ name, want string }{
		{"socket-egress", ""},
		{"socket-egress-ring", "65536"},
		{"socket-egress-max-frames", "4096"},
		{"socket-egress-flush-interval", reporter.DefaultSocketFlushInterval.String()},
		{"socket-egress-stats-interval", reporter.DefaultSocketStatsInterval.String()},
		{"socket-egress-write-timeout", reporter.DefaultSocketWriteTimeout.String()},
		{"pprof-flush-interval", reporter.DefaultPprofFlushInterval.String()},
	} {
		f := fs.Lookup(tc.name)
		if f == nil {
			t.Errorf("-%s is not registered", tc.name)
			continue
		}
		if tc.want != "" && !strings.Contains(f.Usage, tc.want) {
			t.Errorf("-%s help does not state its default %q: %s",
				tc.name, tc.want, f.Usage)
		}
	}
	// The socket no longer requires the pprof backend, and the help must not
	// say otherwise.
	if u := fs.Lookup("socket-egress").Usage; strings.Contains(u, "Requires -pprof-dir") {
		t.Errorf("-socket-egress help still claims it requires -pprof-dir: %s", u)
	}
}

// -beamscope demands a local egress. EITHER backend satisfies it: socket wire
// v2 carries a beamscope sample's value/value_kind, its erlang_pid_key and its
// custom labels, which is what makes a socket-only capture complete rather than
// silently stripped (see TestSocketBeamscopeSampleMatchesPprof, which compares
// the two backends field for field). What is still refused is no local egress
// at all, because the OTLP path freezes per-sample labels.
func TestBeamscopeAcceptsEitherLocalBackend(t *testing.T) {
	saved := pprofEgress
	t.Cleanup(func() { pprofEgress = saved })

	for _, tc := range []struct {
		name      string
		dir, sock string
		want      bool
	}{
		{name: "neither: OTLP freezes per-sample labels", want: false},
		{name: "socket only: wire v2 carries all of it", sock: "/tmp/s", want: true},
		{name: "pprof only", dir: "/tmp/x", want: true},
		{name: "both", dir: "/tmp/x", sock: "/tmp/s", want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pprofEgress = pprofEgressArgs{dir: tc.dir, socketPath: tc.sock}
			if got := beamscopeEgressSupported(); got != tc.want {
				t.Errorf("beamscopeEgressSupported() = %v, want %v", got, tc.want)
			}
		})
	}
}
