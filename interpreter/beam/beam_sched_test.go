// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package beam // import "go.opentelemetry.io/ebpf-profiler/interpreter/beam"

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/lpm"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/util"
)

// The comm strings below were observed on OTP 25.3.2.7 / erts-13.2.2.4 on
// Linux x86_64; see parseSchedComm's doc comment. They come from
// erl_process.c's erts_snprintf(opts.name, ..., "%lu_scheduler", ix + 1) and
// friends, truncated by the kernel to TASK_COMM_LEN-1 = 15 bytes.
func TestParseSchedComm(t *testing.T) {
	for _, tc := range []struct {
		comm     string
		wantKind schedKind
		wantNum  uint32
	}{
		{"1_scheduler", schedKindNormal, 1},
		{"12_scheduler", schedKindNormal, 12},
		{"99999_schedule", schedKindNone, 0}, // truncated: ambiguous, reject
		{"1_dirty_cpu_sch", schedKindDirtyCPU, 1},
		{"2_dirty_cpu_sch", schedKindDirtyCPU, 2},
		{"10_dirty_cpu_s", schedKindDirtyCPU, 10},
		{"1_dirty_cpu_scheduler", schedKindDirtyCPU, 1}, // untruncated form
		{"1_dirty_io_sche", schedKindNone, 0},
		{"10_dirty_io_sch", schedKindNone, 0},
		{"1_aux", schedKindNone, 0},
		{"0_poller", schedKindNone, 0},
		{"async_1", schedKindNone, 0},
		{"sys_sig_dispatc", schedKindNone, 0},
		{"beam.smp", schedKindNone, 0},
		{"_scheduler", schedKindNone, 0},
		{"scheduler", schedKindNone, 0},
		{"x_scheduler", schedKindNone, 0},
		{"0_scheduler", schedKindNone, 0}, // scheduler numbers are 1-based
		{"1_schedulerX", schedKindNone, 0},
		{"1_dirty", schedKindNone, 0}, // too short to tell cpu from io
		{"1_dirty_", schedKindNone, 0},
		{"", schedKindNone, 0},
	} {
		t.Run(tc.comm, func(t *testing.T) {
			kind, num := parseSchedComm(tc.comm)
			assert.Equal(t, tc.wantKind, kind)
			if tc.wantKind != schedKindNone {
				assert.Equal(t, tc.wantNum, num)
			}
		})
	}
}

// scanSchedulerThreads must pick exactly the scheduler threads out of a real
// task directory listing and ignore everything else.
func TestScanSchedulerThreads(t *testing.T) {
	root := t.TempDir()
	taskDir := filepath.Join(root, "4242", "task")
	// The listing below is verbatim from `erl -noshell +S 4:4 +SDcpu 2:2` on
	// OTP 25.3.2.7.
	comms := map[string]string{
		"100": "beam.smp",
		"101": "sys_sig_dispatc",
		"102": "async_1",
		"110": "1_scheduler",
		"111": "2_scheduler",
		"112": "3_scheduler",
		"113": "4_scheduler",
		"120": "1_dirty_cpu_sch",
		"121": "2_dirty_cpu_sch",
		"130": "1_dirty_io_sche",
		"140": "1_aux",
		"141": "0_poller",
	}
	for tid, comm := range comms {
		require.NoError(t, os.MkdirAll(filepath.Join(taskDir, tid), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(taskDir, tid, "comm"),
			[]byte(comm+"\n"), 0o644))
	}

	got := scanSchedulerThreads(root, 4242)
	sort.Slice(got, func(i, j int) bool { return got[i].tid < got[j].tid })
	assert.Equal(t, []schedThread{
		{tid: 110, kind: schedKindNormal, num: 1},
		{tid: 111, kind: schedKindNormal, num: 2},
		{tid: 112, kind: schedKindNormal, num: 3},
		{tid: 113, kind: schedKindNormal, num: 4},
		{tid: 120, kind: schedKindDirtyCPU, num: 1},
		{tid: 121, kind: schedKindDirtyCPU, num: 2},
	}, got)
}

// The offsets are identical across OTP 25-28 because the ErtsSchedulerData
// prefix and ErtsThrPrgrData are byte-identical at those tags; see
// schedOffsetsByOTP for the citations. TestBeamSchedLiveAttach confirms them
// empirically on 25.
func TestSchedOffsetsLookup(t *testing.T) {
	for _, otp := range []uint8{25, 26, 27, 28} {
		offs, ok := lookupSchedOffsets(otp)
		require.True(t, ok, "OTP %d must be supported", otp)
		assert.Equal(t, uint32(168), offs.currentProcess)
		assert.Equal(t, uint32(184), offs.schedNo)
		assert.Equal(t, uint32(192), offs.dirtySchedNo)
	}
	for _, otp := range []uint8{0, 24, 29, 255} {
		_, ok := lookupSchedOffsets(otp)
		assert.False(t, ok, "OTP %d must not be supported", otp)
	}
}

// A pid term must be tagged and non-null, or there is no label.
func TestIsInternalPidTerm(t *testing.T) {
	assert.True(t, isInternalPidTerm(0x278000004f3))
	assert.True(t, isInternalPidTerm(0x3))
	assert.False(t, isInternalPidTerm(0))
	assert.False(t, isInternalPidTerm(0x278000004f0)) // header tag (0x0)
	assert.False(t, isInternalPidTerm(0x278000004f7)) // port tag (0x7)
	assert.False(t, isInternalPidTerm(0x278000004fb)) // immed2 (atom/nil) tag
	assert.False(t, isInternalPidTerm(0x278000004ff)) // small-int tag (0xf)
}

// TestBeamSchedLiveAttach exercises the whole user-space half of the feature
// against a real VM: symbol resolution, the aligned-stride probe, the
// esdp[i].no == i+1 tripwire, and reading current_process->common.id for a
// process pinned to scheduler 1. It needs a local `erl` and the ability to
// read the child's memory -- which the test gets by being the child's parent,
// so no root is required. It skips otherwise.
//
// The eBPF half performs exactly the two reads this test performs (esdp +
// off_current_proc, then *proc), so a green run here is the strongest signal
// available without root and a rebuilt tracer object. The end-to-end
// procedure is in doc/discord-fork.md.
func TestBeamSchedLiveAttach(t *testing.T) {
	if testing.Short() {
		t.Skip("live VM test skipped in -short mode")
	}
	erl, err := exec.LookPath("erl")
	if err != nil {
		t.Skip("no local erl in PATH")
	}

	cmd := exec.Command(erl, "-noshell", "+S", "4:4", "+SDcpu", "2:2",
		"-eval", `spawn_opt(fun Loop() -> Loop() end, [{scheduler, 1}]), timer:sleep(60000)`)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	pid := libpf.PID(cmd.Process.Pid)

	var threads []schedThread
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		threads = scanSchedulerThreads("/proc", pid)
		if len(threads) >= 6 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	require.GreaterOrEqual(t, len(threads), 6,
		"expected 4 normal + 2 dirty-cpu scheduler threads, got %v", threads)

	beamPath, bias := liveBeamMapping(t, pid)
	ef, err := elf.Open(beamPath)
	require.NoError(t, err)
	defer ef.Close()
	syms := liveSymbols(t, ef)
	rm := remotememory.NewProcessVirtualMemory(pid)

	offs, ok := lookupSchedOffsets(25)
	require.True(t, ok)

	base := rm.Ptr(libpf.Address(bias + syms["erts_aligned_scheduler_data"]))
	n := rm.Uint64(libpf.Address(bias + syms["erts_no_schedulers"]))
	require.NotZero(t, base)
	require.EqualValues(t, 4, n)

	stride, err := probeAlignedStride(rm, base, uint32(n), offs, schedKindNormal)
	require.NoError(t, err, "the tripwire must find a unique aligned stride")
	t.Logf("aligned stride: %d bytes", stride)
	assert.Zero(t, stride%ertsCacheLineSize,
		"ErtsAlignedSchedulerData is cache-line aligned")

	// current_process on scheduler 1 must be the pinned spinner. The field is
	// legitimately NULL whenever the scheduler is between processes, and a
	// single read is a single instant -- exactly the transient the eBPF side's
	// null check exists for -- so sample it repeatedly and require that the
	// spinner shows up and that the term is STABLE, which is what pinning
	// means. A wrong currentProcess offset produces neither.
	var id uint64
	stable := 0
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		proc := rm.Ptr(base + libpf.Address(offs.currentProcess))
		if proc == 0 {
			time.Sleep(5 * time.Millisecond)
			continue
		}
		got := rm.Uint64(proc)
		if !isInternalPidTerm(got) {
			t.Fatalf("current_process->common.id = %#x is not an internal pid", got)
		}
		if id == 0 {
			id = got
		}
		require.Equal(t, id, got, "the pinned spinner's pid term must not change")
		if stable++; stable == 5 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	require.Equal(t, 5, stable,
		"scheduler 1 never showed the pinned spinner in current_process")
	t.Logf("scheduler 1 current_process->common.id = %#x", id)

	// The dirty-CPU array shares the struct, and therefore the stride, but it
	// must be VERIFIED at that stride rather than probed on its own.
	dbase := rm.Ptr(libpf.Address(bias + syms["erts_aligned_dirty_cpu_scheduler_data"]))
	dn := rm.Uint64(libpf.Address(bias + syms["erts_no_dirty_cpu_schedulers"]))
	require.NotZero(t, dbase)
	require.EqualValues(t, 2, dn)
	require.NoError(t, verifyDirtyCPUArray(rm, dbase, uint32(dn), stride, offs))

	// And this is why it must not be probed: the dirty-IO schedulers live in
	// the same allocation immediately after the dirty-CPU ones and restart
	// dirty_no at 1 (erl_process.c L6193-L6212), so dirty_io[1] impersonates
	// dirty_cpu[1] at stride (dn+1)*S. With +SDcpu 2:2 and the default 10
	// dirty-IO schedulers that is a real, reproducible double match, and the
	// uniqueness rule must refuse it rather than pick one.
	_, err = probeAlignedStride(rm, dbase, uint32(dn), offs, schedKindDirtyCPU)
	require.Error(t, err, "an independent dirty-array probe is unsound; it must not silently succeed")
	assert.Contains(t, err.Error(), "ambiguous")

	// A deliberately wrong offset table must fail the tripwire rather than
	// produce addresses: this is the "wrong table -> clean disable" contract.
	bad := offs
	bad.schedNo += 8
	_, err = probeAlignedStride(rm, base, uint32(n), bad, schedKindNormal)
	assert.Error(t, err, "a wrong schedNo offset must fail the tripwire")
}

func liveBeamMapping(t *testing.T, pid libpf.PID) (path string, bias uint64) {
	t.Helper()
	maps, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	require.NoError(t, err)
	for _, line := range strings.Split(string(maps), "\n") {
		if !strings.Contains(line, "beam.smp") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 6 || f[2] != "00000000" {
			continue
		}
		start, err := strconv.ParseUint(strings.Split(f[0], "-")[0], 16, 64)
		require.NoError(t, err)
		ef, err := elf.Open(f[5])
		require.NoError(t, err)
		defer ef.Close()
		if ef.Type == elf.ET_EXEC {
			return f[5], 0
		}
		for _, p := range ef.Progs {
			if p.Type == elf.PT_LOAD && p.Off == 0 {
				return f[5], start - p.Vaddr
			}
		}
		return f[5], start
	}
	t.Skip("no beam.smp mapping found; not a native VM build")
	return "", 0
}

func liveSymbols(t *testing.T, ef *elf.File) map[string]uint64 {
	t.Helper()
	want := map[string]uint64{
		"erts_aligned_scheduler_data":           0,
		"erts_aligned_dirty_cpu_scheduler_data": 0,
		"erts_no_schedulers":                    0,
		"erts_no_dirty_cpu_schedulers":          0,
	}
	syms, err := ef.Symbols()
	if err != nil {
		t.Skipf("beam.smp has no symtab: %v", err)
	}
	for _, s := range syms {
		if _, ok := want[s.Name]; ok {
			want[s.Name] = s.Value
		}
	}
	for name, addr := range want {
		if addr == 0 {
			t.Skipf("beam.smp is stripped of %q; nothing to validate", name)
		}
	}
	return want
}

// fakeSchedMem is a flat, synthetic address space for probeAlignedStride. A
// read that falls outside it fails, which is what a real unmapped read does
// and which remotememory turns into a zero -- so out-of-range candidates are
// rejected rather than accidentally matching.
type fakeSchedMem struct {
	base libpf.Address
	buf  []byte
}

func (m *fakeSchedMem) ReadAt(p []byte, off int64) (int, error) {
	start := off - int64(m.base)
	if start < 0 || start+int64(len(p)) > int64(len(m.buf)) {
		return 0, io.EOF
	}
	copy(p, m.buf[start:start+int64(len(p))])
	return len(p), nil
}

func (m *fakeSchedMem) put(off uint32, v uint64) {
	binary.LittleEndian.PutUint64(m.buf[off:], v)
}

func (m *fakeSchedMem) rm() remotememory.RemoteMemory {
	return remotememory.RemoteMemory{ReaderAt: m}
}

// newFakeSchedMem allocates the flat synthetic address space shared by
// newFakeSchedArray and newFakeDirtyArray, sized to cover the whole candidate
// range for an n-element array laid out at stride, so that every stride
// probeAlignedStride tries is answered by real (zeroed) memory rather than by
// a read failure.
func newFakeSchedMem(t *testing.T, n, stride uint32) *fakeSchedMem {
	t.Helper()
	size := maxAlignedStride + n*stride + 4096
	return &fakeSchedMem{base: 0x7f0000000000, buf: make([]byte, size)}
}

// newFakeSchedArray lays out n schedulers of the given kind at the given
// stride, exactly as init_scheduler_data would: the index field holds i+1 and
// the other number field is explicitly zeroed.
func newFakeSchedArray(t *testing.T, offs schedOffsets, kind schedKind,
	n, stride uint32) *fakeSchedMem {
	t.Helper()
	m := newFakeSchedMem(t, n, stride)
	numOff, zeroOff := offs.forKind(kind)
	for i := uint32(0); i < n; i++ {
		m.put(i*stride+numOff, uint64(i)+1)
		m.put(i*stride+zeroOff, 0)
	}
	return m
}

// The n == 2 case is where the probe is weakest: the acceptance rule sees only
// esdp[1], so a single stray word can impersonate a scheduler. These cases pin
// the two defences that make it safe -- the second (zeroed) number field, and
// the requirement that the match be unique across the whole candidate range.
func TestProbeAlignedStride(t *testing.T) {
	offs, ok := lookupSchedOffsets(25)
	require.True(t, ok)
	const stride = uint32(4096) // small, so the fixture stays cheap
	// A 64-aligned offset well below the true stride: this is inside
	// scheduler 0's own struct on a real VM.
	const decoy = uint32(1024)

	t.Run("correct stride accepted", func(t *testing.T) {
		m := newFakeSchedArray(t, offs, schedKindNormal, 4, stride)
		got, err := probeAlignedStride(m.rm(), m.base, 4, offs, schedKindNormal)
		require.NoError(t, err)
		assert.Equal(t, stride, got)
	})

	t.Run("dirty-cpu kind selects dirty_no", func(t *testing.T) {
		// A dirty-CPU array with no dirty-IO suffix, purely to pin the field
		// selection. Production never probes a dirty array; see
		// TestVerifyDirtyCPUArray for why.
		m := newFakeSchedArray(t, offs, schedKindDirtyCPU, 2, stride)
		got, err := probeAlignedStride(m.rm(), m.base, 2, offs, schedKindDirtyCPU)
		require.NoError(t, err)
		assert.Equal(t, stride, got)

		// The same bytes probed as a normal array must be rejected: `no` is 0
		// where the index is expected. Mixing the two arrays up would index
		// the wrong half of a shared allocation.
		_, err = probeAlignedStride(m.rm(), m.base, 2, offs, schedKindNormal)
		assert.Error(t, err)
	})

	// A word that satisfies ONLY the index predicate. Under a single-predicate,
	// first-match rule this decoy wins, because it sits below the true stride.
	t.Run("half-decoy rejected by the zeroed second field", func(t *testing.T) {
		m := newFakeSchedArray(t, offs, schedKindNormal, 2, stride)
		m.put(decoy+offs.schedNo, 2)
		m.put(decoy+offs.dirtySchedNo, 0xdeadbeef) // not zeroed: not a scheduler

		// The decoy really would have matched the old rule.
		require.EqualValues(t, 2, m.rm().Uint64(m.base+libpf.Address(decoy+offs.schedNo)))
		require.Less(t, decoy, stride)

		got, err := probeAlignedStride(m.rm(), m.base, 2, offs, schedKindNormal)
		require.NoError(t, err)
		assert.Equal(t, stride, got, "the true stride must win over the decoy")
	})

	// A word that satisfies BOTH predicates is indistinguishable from a real
	// scheduler at n == 2. There is no principled way to choose, so the only
	// honest outcome is a clean disable.
	t.Run("full decoy is ambiguous and disables", func(t *testing.T) {
		m := newFakeSchedArray(t, offs, schedKindNormal, 2, stride)
		m.put(decoy+offs.schedNo, 2)
		m.put(decoy+offs.dirtySchedNo, 0)

		_, err := probeAlignedStride(m.rm(), m.base, 2, offs, schedKindNormal)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ambiguous")
		assert.Contains(t, err.Error(), strconv.Itoa(int(decoy)))
		assert.Contains(t, err.Error(), strconv.Itoa(int(stride)))
	})

	// The same full decoy at n == 4 is harmless: it has to hold up at
	// esdp[2] and esdp[3] too, and it does not.
	t.Run("more schedulers defeat the decoy outright", func(t *testing.T) {
		m := newFakeSchedArray(t, offs, schedKindNormal, 4, stride)
		m.put(decoy+offs.schedNo, 2)
		m.put(decoy+offs.dirtySchedNo, 0)

		got, err := probeAlignedStride(m.rm(), m.base, 4, offs, schedKindNormal)
		require.NoError(t, err)
		assert.Equal(t, stride, got)
	})

	t.Run("single scheduler reports no stride", func(t *testing.T) {
		m := newFakeSchedArray(t, offs, schedKindNormal, 1, stride)
		got, err := probeAlignedStride(m.rm(), m.base, 1, offs, schedKindNormal)
		require.NoError(t, err)
		assert.EqualValues(t, strideUndetermined, got)
		// Whatever the reported stride, scheduler 1 addresses the base.
		assert.Zero(t, uint64(1-1)*uint64(got))
	})

	t.Run("wrong offsets table fails at esdp[0]", func(t *testing.T) {
		m := newFakeSchedArray(t, offs, schedKindNormal, 4, stride)
		bad := offs
		bad.schedNo += 8
		bad.dirtySchedNo += 8
		_, err := probeAlignedStride(m.rm(), m.base, 4, bad, schedKindNormal)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "tripwire")
	})

	t.Run("no matching stride disables", func(t *testing.T) {
		m := newFakeSchedArray(t, offs, schedKindNormal, 2, stride)
		// Erase esdp[1] entirely: esdp[0] still validates, nothing else does.
		m.put(stride+offs.schedNo, 0)
		_, err := probeAlignedStride(m.rm(), m.base, 2, offs, schedKindNormal)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no aligned stride")
	})

	t.Run("implausible inputs rejected", func(t *testing.T) {
		m := newFakeSchedArray(t, offs, schedKindNormal, 4, stride)
		_, err := probeAlignedStride(m.rm(), 0, 4, offs, schedKindNormal)
		assert.Error(t, err, "NULL array")
		_, err = probeAlignedStride(m.rm(), m.base, 0, offs, schedKindNormal)
		assert.Error(t, err, "zero schedulers")
		_, err = probeAlignedStride(m.rm(), m.base, maxSchedulersPerVM+1, offs,
			schedKindNormal)
		assert.Error(t, err, "clamped-implausible scheduler count")
	})
}

// newFakeDirtyArray lays out the dirty allocation as the VM does: dirty-CPU
// elements 1..nCPU immediately followed by dirty-IO elements whose dirty_no
// RESTARTS at 1 (erl_process.c L6193-L6212 @OTP-25.3.2.7).
func newFakeDirtyArray(t *testing.T, offs schedOffsets, nCPU, nIO, stride uint32) *fakeSchedMem {
	t.Helper()
	total := nCPU + nIO
	m := newFakeSchedMem(t, total, stride)
	for i := uint32(0); i < total; i++ {
		num := i + 1
		if i >= nCPU {
			num = i - nCPU + 1 // the IO half restarts at 1
		}
		m.put(i*stride+offs.dirtySchedNo, uint64(num))
		m.put(i*stride+offs.schedNo, 0)
	}
	return m
}

// The dirty array is not homogeneous, so probeAlignedStride's uniqueness
// argument does not apply to it. This reproduces, without a VM, the double
// match observed live at `+SDcpu 2:2`, and pins the fix: measure the stride on
// the homogeneous normal array and only VERIFY the dirty one at it.
func TestVerifyDirtyCPUArray(t *testing.T) {
	offs, ok := lookupSchedOffsets(25)
	require.True(t, ok)
	const stride = uint32(4096)

	t.Run("independent probe aliases on the dirty-IO suffix", func(t *testing.T) {
		m := newFakeDirtyArray(t, offs, 2, 10, stride)
		_, err := probeAlignedStride(m.rm(), m.base, 2, offs, schedKindDirtyCPU)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ambiguous")
		// dirty_io[1] is element nCPU+1 == 3, so 3*stride impersonates
		// dirty_cpu[1].
		assert.Contains(t, err.Error(), strconv.Itoa(int(3*stride)))
	})

	t.Run("verification at the normal stride accepts", func(t *testing.T) {
		m := newFakeDirtyArray(t, offs, 2, 10, stride)
		assert.NoError(t, verifyDirtyCPUArray(m.rm(), m.base, 2, stride, offs))
	})

	t.Run("verification at a wrong stride rejects", func(t *testing.T) {
		m := newFakeDirtyArray(t, offs, 2, 10, stride)
		// 2*stride lands on dirty_cpu[2] == dirty_io[0], whose dirty_no is 1,
		// not 2. (3*stride is the one value that does alias -- which is the
		// whole reason the stride has to come from the normal array and not
		// from anything self-consistent found here.)
		assert.Error(t, verifyDirtyCPUArray(m.rm(), m.base, 2, 2*stride, offs))
	})

	t.Run("no stride available with a single normal scheduler", func(t *testing.T) {
		m := newFakeDirtyArray(t, offs, 2, 10, stride)
		err := verifyDirtyCPUArray(m.rm(), m.base, 2, strideUndetermined, offs)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no stride available")

		// One dirty-CPU scheduler needs no stride: only element 0 is read.
		assert.NoError(t, verifyDirtyCPUArray(m.rm(), m.base, 1, strideUndetermined, offs))
	})

	t.Run("null base and implausible counts rejected", func(t *testing.T) {
		m := newFakeDirtyArray(t, offs, 2, 10, stride)
		assert.Error(t, verifyDirtyCPUArray(m.rm(), 0, 2, stride, offs))
		assert.Error(t, verifyDirtyCPUArray(m.rm(), m.base, maxSchedulersPerVM+1, stride, offs))
	})
}

// The map value must bind the entry to the BEAM tgid: see
// support/ebpf/beam_sched.h's identity section for why. This pins the
// producer end; the eBPF side's comparison is compile-verified with the rest
// of the C.
func TestBeamSchedInfoFor(t *testing.T) {
	offs, ok := lookupSchedOffsets(25)
	require.True(t, ok)
	arr := &schedArray{base: 0x7f0000001000, n: 4, stride: 41728, ok: true}

	for _, num := range []uint32{1, 2, 4} {
		info := beamSchedInfoFor(arr, offs, num, 4242)
		assert.EqualValues(t, 4242, info.Tgid, "the entry must carry the BEAM tgid")
		assert.Equal(t, offs.currentProcess, info.Off_current_proc)
		assert.Equal(t, uint64(arr.base)+uint64(num-1)*uint64(arr.stride),
			info.Esdp_addr, "scheduler %d addresses element %d", num, num-1)
	}

	// A single-scheduler VM has no measured stride; scheduler 1 is the base.
	solo := &schedArray{base: 0x7f0000001000, n: 1, stride: strideUndetermined, ok: true}
	info := beamSchedInfoFor(solo, offs, 1, 7)
	assert.EqualValues(t, uint64(solo.base), info.Esdp_addr)
	assert.EqualValues(t, 7, info.Tgid)

	// The tgid is never zero for a real process, so a zero-valued entry can
	// never be mistaken for a valid one by the eBPF comparison.
	assert.NotZero(t, beamSchedInfoFor(arr, offs, 1, 1).Tgid)
}

// fakeSchedTidMap is a minimal interpreter.EbpfHandler that models
// beam_sched_tids well enough to pin the identity contract: Update always
// overwrites (as a bpf hash map update does), and Delete only removes an
// entry that still belongs to the tgid it is asked to remove for -- mirroring
// processmanager/ebpf.ebpfMapsImpl.DeleteBeamSchedTid's lookup-then-delete.
// Every other EbpfHandler method is unused here and just satisfies the
// interface.
type fakeSchedTidMap struct {
	entries map[libpf.PID]support.BeamSchedInfo
}

var _ interpreter.EbpfHandler = &fakeSchedTidMap{}

func (*fakeSchedTidMap) UpdateInterpreterOffsets(uint16, host.FileID, []util.Range) error {
	return nil
}

func (*fakeSchedTidMap) UpdateProcData(libpf.InterpreterType, libpf.PID, unsafe.Pointer) error {
	return nil
}

func (*fakeSchedTidMap) DeleteProcData(libpf.InterpreterType, libpf.PID) error { return nil }

func (*fakeSchedTidMap) UpdatePidInterpreterMapping(libpf.PID, lpm.Prefix, uint8,
	host.FileID, uint64) error {
	return nil
}

func (*fakeSchedTidMap) DeletePidInterpreterMapping(libpf.PID, lpm.Prefix) error { return nil }

func (f *fakeSchedTidMap) UpdateBeamSchedTid(tid libpf.PID, info support.BeamSchedInfo) error {
	f.entries[tid] = info
	return nil
}

func (f *fakeSchedTidMap) DeleteBeamSchedTid(tid, tgid libpf.PID) error {
	if existing, ok := f.entries[tid]; ok && existing.Tgid == uint32(tgid) {
		delete(f.entries, tid)
	}
	return nil
}

// TestDetachDoesNotDeleteRecycledTid pins the B5 fix: a dead VM's Detach must
// not remove a live VM's beam_sched_tids entry at a kernel tid the OS recycled
// between the two.
//
// Scenario: BEAM pid 100 has scheduler tid 12345 and exits. Before its Detach
// runs, pid 200 starts, one of its scheduler threads gets the recycled tid
// 12345, and its attach overwrites the map entry with {esdp of 200, tgid
// 200}. Pid 100's Detach must then leave that entry alone -- deleting it
// would silently disable pid 200's attribution on that thread for its whole
// lifetime.
func TestDetachDoesNotDeleteRecycledTid(t *testing.T) {
	const recycledTid = libpf.PID(12345)
	const deadTgid = libpf.PID(100)
	const liveTgid = libpf.PID(200)

	handler := &fakeSchedTidMap{entries: map[libpf.PID]support.BeamSchedInfo{}}

	// pid 100 attaches and claims tid 12345.
	require.NoError(t, handler.UpdateBeamSchedTid(recycledTid,
		support.BeamSchedInfo{Esdp_addr: 0x1000, Tgid: uint32(deadTgid)}))

	// The tid is recycled: pid 200 attaches and overwrites the same map key.
	require.NoError(t, handler.UpdateBeamSchedTid(recycledTid,
		support.BeamSchedInfo{Esdp_addr: 0x2000, Tgid: uint32(liveTgid)}))

	// pid 100's Detach runs after the overwrite. It must not remove pid 200's
	// live entry.
	dead := &beamInstance{pid: deadTgid, schedTids: []libpf.PID{recycledTid}}
	require.NoError(t, dead.Detach(handler, deadTgid))

	got, ok := handler.entries[recycledTid]
	require.True(t, ok, "Detach for the dead VM must not delete the live VM's entry")
	assert.Equal(t, uint32(liveTgid), got.Tgid)
	assert.Equal(t, uint64(0x2000), got.Esdp_addr)

	// The live VM's own Detach still removes its entry normally.
	live := &beamInstance{pid: liveTgid, schedTids: []libpf.PID{recycledTid}}
	require.NoError(t, live.Detach(handler, liveTgid))
	_, ok = handler.entries[recycledTid]
	assert.False(t, ok, "the owning VM's Detach must still remove its own entry")
}
