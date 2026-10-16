// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package beamscope discovers and drains the beam_scope NIF's shared-memory
// records into the profiler reporter and an optional JSONL sidecar.
// The ABI lives in discord_common/ex/beam_scope/ABI.md in the monorepo.
// Configure must be called before interpreter discovery.
package beamscope // import "go.opentelemetry.io/ebpf-profiler/interpreter/beamscope"

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/reporter"
)

const (
	// exportSymbol is the discovery symbol exported by the beam_scope NIF.
	exportSymbol = "discord_beamscope_shm_v1"
	// exportStructSize is the size of the packed export struct.
	exportStructSize = 24
	// exportVersion is the only export version this reader implements.
	exportVersion = 1
	// exportFlagValid is bit0 of the export flags: segment initialized.
	exportFlagValid = 1

	// defaultPollInterval is used when Configure gets a zero interval.
	defaultPollInterval = 250 * time.Millisecond
)

// Config enables the plugin and provides its sinks.
type Config struct {
	// Reporter receives GC_DELTA records as single-frame BEAM traces with
	// Required; each measurement uses its corresponding beamscope profile type.
	Reporter reporter.TraceReporter
	// PollInterval is how often each attached BEAM's rings are drained.
	PollInterval time.Duration
	// JSONLDir, when non-empty, receives one beamscope-<pid>.jsonl file per
	// attached process with the non-GC record stream.
	JSONLDir string
}

var config atomic.Pointer[Config]

// attached tracks which PIDs already have a live drainer, so a second mapping
// of the NIF .so in the same process does not double-drain the SPSC rings.
var attached = struct {
	sync.Mutex
	pids map[libpf.PID]struct{}
}{pids: map[libpf.PID]struct{}{}}

// Configure enables the plugin. It must be called before the process manager
// starts probing executables (i.e. during startup wiring).
func Configure(c Config) error {
	if c.Reporter == nil {
		return errors.New("beamscope: Reporter is required")
	}
	if c.PollInterval <= 0 {
		c.PollInterval = defaultPollInterval
	}
	if c.JSONLDir != "" {
		if err := os.MkdirAll(c.JSONLDir, 0o755); err != nil {
			return fmt.Errorf("beamscope: %w", err)
		}
	}
	config.Store(&c)
	return nil
}

// Enabled reports whether Configure has been called.
func Enabled() bool { return config.Load() != nil }

// Loader implements interpreter.Loader: it recognizes any executable or DSO
// exporting the beam_scope discovery symbol.
func Loader(_ interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	if !Enabled() {
		return nil, nil
	}
	ef, err := info.GetELF()
	if err != nil {
		return nil, err
	}
	sym, err := ef.LookupSymbol(exportSymbol)
	if err != nil {
		if errors.Is(err, libpf.ErrSymbolNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if sym.Size != 0 && sym.Size != exportStructSize {
		return nil, fmt.Errorf("beamscope export symbol has wrong size %d", sym.Size)
	}
	log.Debugf("beamscope: export symbol found in %s", info.FileName())
	return &data{exportVA: libpf.Address(sym.Address)}, nil
}

// data is the per-ELF interpreter.Data: just the export symbol's file VA.
type data struct {
	exportVA libpf.Address
}

var _ interpreter.Data = &data{}

func (d *data) String() string { return "beam_scope instrumentation" }

// Attach starts a per-PID drainer. The export struct may not be populated yet
// (BeamScope.start/1 can run long after the .so is mapped), so activation is
// retried from the drain goroutine; Attach itself does not fail for that.
func (d *data) Attach(_ interpreter.EbpfHandler, pid libpf.PID,
	bias libpf.Address, rm remotememory.RemoteMemory,
) (interpreter.Instance, error) {
	cfg := config.Load()
	if cfg == nil {
		return nil, errors.New("beamscope: not configured")
	}

	attached.Lock()
	if _, dup := attached.pids[pid]; dup {
		attached.Unlock()
		// A second mapping of the NIF in this process; the first drainer owns
		// the rings. Return an inert instance.
		return &Instance{pid: pid}, nil
	}
	attached.pids[pid] = struct{}{}
	attached.Unlock()

	dr := newDrainer(pid, rm, bias+d.exportVA, cfg)
	go dr.run()
	log.Debugf("beamscope: attached to PID %d (export at 0x%x)", pid, bias+d.exportVA)
	return &Instance{pid: pid, drainer: dr}, nil
}

func (d *data) Unload(_ interpreter.EbpfHandler) {}

// Instance is the per-PID instance; it only carries the drainer lifecycle.
type Instance struct {
	interpreter.InstanceStubs
	pid     libpf.PID
	drainer *drainer
}

var _ interpreter.Instance = &Instance{}

// Detach stops the drain goroutine (final drain + JSONL flush + munmap).
func (i *Instance) Detach(_ interpreter.EbpfHandler, pid libpf.PID) error {
	if i.drainer == nil {
		return nil
	}
	i.drainer.stop()
	attached.Lock()
	delete(attached.pids, pid)
	attached.Unlock()
	log.Debugf("beamscope: detached from PID %d", pid)
	return nil
}

// exportStruct is the decoded discovery struct (ABI.md section 1).
type exportStruct struct {
	Magic   uint64
	Version uint32
	Flags   uint32
	MemFD   int32
	ShmSize uint32
}

func parseExport(b []byte) exportStruct {
	return exportStruct{
		Magic:   binary.LittleEndian.Uint64(b[0:]),
		Version: binary.LittleEndian.Uint32(b[8:]),
		Flags:   binary.LittleEndian.Uint32(b[12:]),
		MemFD:   int32(binary.LittleEndian.Uint32(b[16:])),
		ShmSize: binary.LittleEndian.Uint32(b[20:]),
	}
}

// errNotReady means the export struct exists but the segment is not (yet)
// initialized; the caller should retry on the next poll.
var errNotReady = errors.New("segment not initialized yet")

// errPermanent wraps an activation failure that can never succeed for this
// export: the writer's discovery ABI does not match ours (bad magic/version).
// tryActivate parks the drainer on it instead of retrying every poll for the
// life of the process.
var errPermanent = errors.New("permanent activation failure")

// openSegment validates the discovery struct and maps the exported memfd.
// The mapping is writable because draining updates each ring's read_pos.
// Process-exit errors are retried until the process manager detaches the reader.
func openSegment(pid libpf.PID, rm remotememory.RemoteMemory,
	exportAddr libpf.Address) ([]byte, *Segment, error) {
	var raw [exportStructSize]byte
	if err := rm.Read(exportAddr, raw[:]); err != nil {
		return nil, nil, fmt.Errorf("reading export struct: %w", err)
	}
	exp := parseExport(raw[:])
	if exp.Magic != segmentMagic {
		return nil, nil, fmt.Errorf("%w: bad export magic 0x%016x", errPermanent, exp.Magic)
	}
	if exp.Version != exportVersion {
		return nil, nil, fmt.Errorf("%w: unsupported export version %d", errPermanent, exp.Version)
	}
	if exp.Flags&exportFlagValid == 0 {
		return nil, nil, errNotReady
	}
	if exp.MemFD < 0 || exp.ShmSize < segmentHeaderSize {
		return nil, nil, fmt.Errorf("implausible export: memfd %d size %d",
			exp.MemFD, exp.ShmSize)
	}

	// Open the memfd via /proc. Verify it really is a memfd before mapping:
	// the fd number came from target memory and could have been reused.
	fdPath := fmt.Sprintf("/proc/%d/fd/%d", pid, exp.MemFD)
	link, err := os.Readlink(fdPath)
	if err != nil {
		return nil, nil, fmt.Errorf("resolving %s: %w", fdPath, err)
	}
	if !strings.HasPrefix(link, "/memfd:") {
		return nil, nil, fmt.Errorf("fd %d is not a memfd (%q)", exp.MemFD, link)
	}
	f, err := os.OpenFile(fdPath, os.O_RDWR, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("opening %s: %w", fdPath, err)
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("fstat %s: %w", fdPath, err)
	}
	if st.Size() != int64(exp.ShmSize) {
		return nil, nil, fmt.Errorf("memfd size %d != shm_size %d",
			st.Size(), exp.ShmSize)
	}

	mem, err := unix.Mmap(int(f.Fd()), 0, int(exp.ShmSize),
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, nil, fmt.Errorf("mmap %s: %w", fdPath, err)
	}
	seg, err := NewSegment(mem)
	if err != nil {
		_ = unix.Munmap(mem)
		return nil, nil, fmt.Errorf("validating segment: %w", err)
	}
	return mem, seg, nil
}

// gatherProcessMeta snapshots /proc-derived identity for sample labeling.
func gatherProcessMeta(pid libpf.PID) process.Meta {
	pr := process.New(pid, pid)
	defer pr.Close()
	return pr.GetProcessMeta(nil)
}
