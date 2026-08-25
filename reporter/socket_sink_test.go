// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
)

// decodedSample is what a consumer reconstructs from the wire, used here to
// assert the framing round-trips.
type decodedSample struct {
	ktime, unix       int64
	pid, tid, cpu     int32
	droppedSincePrev  uint32
	comm, processName string
	containerID       string
	origin            uint8
	flags             uint8
	// value/valueKind are the sample's own measurement; valueKind says which
	// column it belongs in. erlangPidKey is 0 when unattributable.
	value        int64
	valueKind    uint8
	erlangPidKey uint64
	// labels in wire order (sorted by key). Numeric labels carry num+unit;
	// string labels carry str.
	labels []decodedLabel
	// frames, leaf-first as the wire carries them.
	funcs []string
	files []string
	lines []int32
}

type decodedLabel struct {
	key, str, unit string
	kind           uint8
	num            int64
}

type decodedStream struct {
	version        uint16
	flags          uint32
	rate           uint32
	maxFrames      uint32
	samples        []decodedSample
	lastStats      map[string]uint64
	statsCount     int
	sampleFixedLen uint16
	labelStride    uint16
}

// readStream is a reference decoder for the wire format. Its whole job is to
// be an independent second reading of the spec in socket_sink.go, so a framing
// mistake shows up here rather than in the Rust consumer.
func readStream(t *testing.T, r io.Reader) *decodedStream {
	t.Helper()
	var hdr [64]byte
	_, err := io.ReadFull(r, hdr[:8])
	require.NoError(t, err)
	require.Equal(t, SocketMagic, string(hdr[:8]))
	_, err = io.ReadFull(r, hdr[8:12])
	require.NoError(t, err)
	out := &decodedStream{
		version: binary.LittleEndian.Uint16(hdr[8:10]),
	}
	hlen := binary.LittleEndian.Uint16(hdr[10:12])
	require.Equal(t, SocketHeaderLen, hlen)
	_, err = io.ReadFull(r, hdr[12:hlen])
	require.NoError(t, err)
	out.flags = binary.LittleEndian.Uint32(hdr[12:16])
	out.rate = binary.LittleEndian.Uint32(hdr[16:20])
	out.maxFrames = binary.LittleEndian.Uint32(hdr[20:24])
	// The strides are what make the layout self-describing; a reader walks by
	// them rather than by the constants it was compiled against.
	out.sampleFixedLen = binary.LittleEndian.Uint16(hdr[32:34])
	out.labelStride = binary.LittleEndian.Uint16(hdr[34:36])
	require.Equal(t, uint16(socketSampleFixedLen), out.sampleFixedLen)
	require.Equal(t, uint16(socketLabelLen), out.labelStride)

	strs := map[uint32]string{0: ""}
	var lenBuf [4]byte
	for {
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			require.ErrorIs(t, err, io.EOF)
			return out
		}
		n := binary.LittleEndian.Uint32(lenBuf[:])
		buf := make([]byte, n)
		_, err := io.ReadFull(r, buf)
		require.NoError(t, err)
		switch buf[0] {
		case RecStrdef:
			p := buf[1:]
			id := binary.LittleEndian.Uint32(p[0:4])
			l := binary.LittleEndian.Uint32(p[4:8])
			strs[id] = string(p[8 : 8+l])
		case RecSample:
			p := buf[1:]
			nf := int(binary.LittleEndian.Uint16(p[58:60]))
			s := decodedSample{
				ktime:            int64(binary.LittleEndian.Uint64(p[0:8])),
				unix:             int64(binary.LittleEndian.Uint64(p[8:16])),
				pid:              int32(binary.LittleEndian.Uint32(p[24:28])),
				tid:              int32(binary.LittleEndian.Uint32(p[28:32])),
				cpu:              int32(binary.LittleEndian.Uint32(p[32:36])),
				droppedSincePrev: binary.LittleEndian.Uint32(p[36:40]),
				comm:             strs[binary.LittleEndian.Uint32(p[40:44])],
				processName:      strs[binary.LittleEndian.Uint32(p[44:48])],
				containerID:      strs[binary.LittleEndian.Uint32(p[52:56])],
				origin:           p[56],
				flags:            p[57],
				valueKind:        p[62],
				value:            int64(binary.LittleEndian.Uint64(p[64:72])),
				erlangPidKey:     binary.LittleEndian.Uint64(p[72:80]),
			}
			nl := int(binary.LittleEndian.Uint16(p[60:62]))
			require.Equal(t, uint8(0), p[63], "reserved byte must be zero")
			if s.valueKind == SocketValueKindNone {
				require.Zero(t, s.value,
					"value must be zero when no kind claims it")
			}
			fr := p[int(out.sampleFixedLen):]
			for i := 0; i < nf; i++ {
				o := i * socketFrameLen
				s.funcs = append(s.funcs, strs[binary.LittleEndian.Uint32(fr[o:o+4])])
				s.files = append(s.files, strs[binary.LittleEndian.Uint32(fr[o+4:o+8])])
				s.lines = append(s.lines, int32(binary.LittleEndian.Uint32(fr[o+8:o+12])))
			}
			lb := fr[nf*socketFrameLen:]
			for i := 0; i < nl; i++ {
				o := i * int(out.labelStride)
				dl := decodedLabel{
					key:  strs[binary.LittleEndian.Uint32(lb[o:o+4])],
					str:  strs[binary.LittleEndian.Uint32(lb[o+4:o+8])],
					unit: strs[binary.LittleEndian.Uint32(lb[o+8:o+12])],
					kind: lb[o+12],
					num:  int64(binary.LittleEndian.Uint64(lb[o+16 : o+24])),
				}
				s.labels = append(s.labels, dl)
			}
			out.samples = append(out.samples, s)
		case RecStats:
			p := buf[1:]
			out.statsCount++
			out.lastStats = map[string]uint64{
				"produced":      binary.LittleEndian.Uint64(p[16:24]),
				"emitted":       binary.LittleEndian.Uint64(p[24:32]),
				"droppedRing":   binary.LittleEndian.Uint64(p[32:40]),
				"droppedNoSock": binary.LittleEndian.Uint64(p[40:48]),
				"truncFrames":   binary.LittleEndian.Uint64(p[48:56]),
			}
		default:
			t.Fatalf("unknown record type %d", buf[0])
		}
	}
}

// listener accepts exactly one connection and hands back everything read.
type listener struct {
	path string
	ln   net.Listener
	wg   sync.WaitGroup
	mu   sync.Mutex
	data []byte
	// gate, when non-nil, is waited on before each read, to simulate a slow
	// consumer. Set at construction (newListenerGated), never afterwards.
	gate chan struct{}
	// closed when the read loop has seen EOF, i.e. the producer closed.
	eof chan struct{}
}

// serveOne accepts exactly one connection on ln and copies everything the
// producer sends into w, waiting on gate (when non-nil) before each read so a
// test can stall the consumer. It returns when the producer closes or ln does.
// Shared by the listener below and by the equivalence fixture, which needs the
// same loop with a file as the sink.
func serveOne(ln net.Listener, w io.Writer, gate <-chan struct{}) {
	c, err := ln.Accept()
	if err != nil {
		return
	}
	defer c.Close()
	buf := make([]byte, 1<<20)
	for {
		if gate != nil {
			<-gate
		}
		n, err := c.Read(buf)
		if n > 0 {
			_, _ = w.Write(buf[:n])
		}
		if err != nil {
			return
		}
	}
}

// Write accumulates what the producer sent. It is the io.Writer serveOne
// copies into.
func (l *listener) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.data = append(l.data, p...)
	return len(p), nil
}

func newListener(t *testing.T) *listener {
	t.Helper()
	return newListenerGated(t, nil)
}

// newListenerGated is newListener with a gate the caller already holds, so the
// read loop never observes the field being assigned after it started.
func newListenerGated(t *testing.T, gate chan struct{}) *listener {
	t.Helper()
	// The abstract-namespace-free path has to be short: sun_path is 108 bytes.
	dir, err := os.MkdirTemp("", "pssock")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	p := filepath.Join(dir, "s")
	ln, err := net.Listen("unix", p)
	require.NoError(t, err)
	l := &listener{path: p, ln: ln, gate: gate, eof: make(chan struct{})}
	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		defer close(l.eof)
		serveOne(ln, l, l.gate)
	}()
	t.Cleanup(func() { _ = ln.Close(); l.wg.Wait() })
	return l
}

// readAll waits for the producer to close the connection, then returns
// everything received. Reading the buffer straight after Stop() races the
// listener goroutine's last read, which is a flaky-test generator, not a
// property of the sink.
func (l *listener) readAll(t *testing.T) []byte {
	t.Helper()
	select {
	case <-l.eof:
	case <-time.After(5 * time.Second):
		t.Fatal("producer never closed the connection")
	}
	return l.bytes()
}

func (l *listener) bytes() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]byte, len(l.data))
	copy(out, l.data)
	return out
}

// The socket path must carry the same frames, in the same order, as the pprof
// path, for the same ReportTraceEvent calls.
func TestSocketSinkCarriesTheSameSamples(t *testing.T) {
	l := newListener(t)
	dir := t.TempDir()
	r, err := NewLocalEgress(LocalEgressConfig{
		Dir: dir, SamplesPerSecond: 997,
		Socket: SocketConfig{Path: l.path, FlushInterval: 5 * time.Millisecond},
	})
	require.NoError(t, err)
	require.NoError(t, r.Start(t.Context()))

	tr := testTrace(t, "root", "mid", "leaf")
	for i := int64(0); i < 20; i++ {
		require.NoError(t, r.ReportTraceEvent(tr,
			meta(5_000+i, 100, 101, "1_scheduler", "beam.smp", "cafe01")))
	}
	require.NoError(t, r.Flush())
	r.Stop()

	st := readStream(t, bytes.NewReader(l.readAll(t)))
	assert.Equal(t, SocketVersion, st.version)
	assert.Equal(t, StreamFlagFramesLeafFirst, st.flags&StreamFlagFramesLeafFirst)
	assert.Equal(t, uint32(997), st.rate)
	require.Len(t, st.samples, 20)
	assert.Zero(t, r.SocketDropped())

	for i, s := range st.samples {
		// testTrace appends leaf-last-to-first, so Frames is leaf-first:
		// leaf, mid, root.
		assert.Equal(t, []string{"leaf", "mid", "root"}, s.funcs, "sample %d", i)
		assert.Equal(t, []string{"leaf.erl", "mid.erl", "root.erl"}, s.files)
		assert.Equal(t, int64(5_000+i), s.ktime)
		assert.Equal(t, "1_scheduler", s.comm)
		assert.Equal(t, "beam.smp", s.processName)
		assert.Equal(t, "cafe01", s.containerID)
		assert.Equal(t, socketOriginSampling, s.origin)
		assert.Zero(t, s.flags)
		assert.Zero(t, s.droppedSincePrev)
	}

	// The pprof file is unchanged by the socket's presence.
	p := readOne(t, dir)
	require.Len(t, p.Sample, 20)
	for i, s := range p.Sample {
		require.Len(t, s.Location, 3)
		var got []string
		for _, loc := range s.Location {
			got = append(got, loc.Line[0].Function.Name)
		}
		assert.Equal(t, st.samples[i].funcs, got,
			"pprof Location order must equal the wire's frame order")
	}
	// The invariant a consumer is told to assert.
	require.NotNil(t, st.lastStats)
	assert.Equal(t, st.lastStats["produced"],
		st.lastStats["emitted"]+st.lastStats["droppedRing"]+st.lastStats["droppedNoSock"])
}

// A slow consumer must cost samples, not latency, and the loss must be visible
// both in the counter and next to the gap on the wire.
func TestSocketSinkDropsRatherThanBlocks(t *testing.T) {
	gate := make(chan struct{})
	l := newListenerGated(t, gate)
	dir := t.TempDir()
	const ring = 8
	r, err := NewLocalEgress(LocalEgressConfig{
		Dir: dir, SamplesPerSecond: 997,
		Socket: SocketConfig{
			Path: l.path, RingSize: ring,
			FlushInterval: time.Hour, StatsInterval: time.Hour,
		},
	})
	require.NoError(t, err)
	require.NoError(t, r.Start(t.Context()))

	tr := testTrace(t, "root", "leaf")
	const n = 20000
	start := time.Now()
	for i := int64(0); i < n; i++ {
		require.NoError(t, r.ReportTraceEvent(tr,
			meta(i, 100, 101, "1_scheduler", "beam.smp", "cafe01")))
	}
	elapsed := time.Since(start)

	// The point of the design: 20k reports against a consumer that has read
	// nothing must not have blocked. Generous bound -- we are asserting "did
	// not stall", not a throughput target.
	assert.Less(t, elapsed, 5*time.Second,
		"the sampling path blocked on a stalled consumer")
	assert.Positive(t, r.SocketDropped(), "a stalled consumer must produce drops")
	// The pprof path is untouched by the socket's backpressure.
	assert.Zero(t, r.Dropped())

	close(gate)
	require.NoError(t, r.Flush())
	r.Stop()

	st := readStream(t, bytes.NewReader(l.readAll(t)))
	require.NotEmpty(t, st.samples)
	var attributed uint64
	for _, s := range st.samples {
		attributed += uint64(s.droppedSincePrev)
	}
	require.NotNil(t, st.lastStats)
	total := st.lastStats["droppedRing"] + st.lastStats["droppedNoSock"]
	assert.Positive(t, total)
	assert.Equal(t, st.lastStats["produced"],
		st.lastStats["emitted"]+total, "produced == emitted + dropped")
	assert.Equal(t, uint64(n), st.lastStats["produced"])
	// Every drop the final STATS knows about is attributed to some gap on the
	// wire, except any that happened after the last emitted sample.
	assert.LessOrEqual(t, attributed, total)
	assert.Positive(t, attributed, "drops must be described next to the gap")

	// And the pprof archive says so too, so the two artifacts cross-attest.
	p := readOne(t, dir)
	var found bool
	for _, c := range p.Comments {
		if len(c) > 14 && c[:14] == "socket egress " {
			found = true
		}
	}
	assert.True(t, found, "pprof comments must record the socket drop count: %v", p.Comments)
}

// No consumer at all is a drop, not a stall and not a crash.
func TestSocketSinkSurvivesNoConsumer(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(t.TempDir(), "absent.sock")
	r, err := NewLocalEgress(LocalEgressConfig{
		Dir: dir, SamplesPerSecond: 997,
		Socket: SocketConfig{Path: sock, RingSize: 4, FlushInterval: time.Millisecond},
	})
	require.NoError(t, err)
	require.NoError(t, r.Start(t.Context()))
	tr := testTrace(t, "root", "leaf")
	for i := int64(0); i < 500; i++ {
		require.NoError(t, r.ReportTraceEvent(tr, meta(i, 1, 2, "c", "p", "x")))
	}
	require.NoError(t, r.Flush())
	r.Stop()
	assert.Positive(t, r.SocketDropped())
	// The pprof file is complete regardless.
	p := readOne(t, dir)
	assert.Len(t, p.Sample, 500)
}

// A stack deeper than the cap is flagged, not silently shortened.
func TestSocketSinkFlagsFrameTruncation(t *testing.T) {
	l := newListener(t)
	dir := t.TempDir()
	r, err := NewLocalEgress(LocalEgressConfig{
		Dir: dir, SamplesPerSecond: 997,
		Socket: SocketConfig{Path: l.path, MaxFrames: 3, FlushInterval: 5 * time.Millisecond},
	})
	require.NoError(t, err)
	require.NoError(t, r.Start(t.Context()))
	tr := testTrace(t, "a", "b", "c", "d", "e")
	require.NoError(t, r.ReportTraceEvent(tr, meta(1, 1, 2, "c", "p", "x")))
	require.NoError(t, r.Flush())
	r.Stop()

	st := readStream(t, bytes.NewReader(l.readAll(t)))
	require.Len(t, st.samples, 1)
	assert.Equal(t, SampleFlagFramesTruncated, st.samples[0].flags&SampleFlagFramesTruncated)
	assert.Len(t, st.samples[0].funcs, 3)
	// Leaf-most frames survive.
	assert.Equal(t, []string{"e", "d", "c"}, st.samples[0].funcs)
	assert.Equal(t, uint64(1), st.lastStats["truncFrames"])
}

// A frame with no symbol renders identically on both paths -- flatten() does
// it once, upstream of the fork in the data flow.
func TestSocketSinkUnsymbolizedFrameMatchesPprof(t *testing.T) {
	l := newListener(t)
	dir := t.TempDir()
	r, err := NewLocalEgress(LocalEgressConfig{
		Dir: dir, SamplesPerSecond: 997,
		Socket: SocketConfig{Path: l.path, FlushInterval: 5 * time.Millisecond},
	})
	require.NoError(t, err)
	require.NoError(t, r.Start(t.Context()))

	tr := &libpf.Trace{}
	tr.Frames.Append(&libpf.Frame{
		Type: libpf.NativeFrame, AddressOrLineno: libpf.AddressOrLineno(0xdeadbeef),
	})
	require.NoError(t, r.ReportTraceEvent(tr, meta(1, 1, 2, "c", "p", "x")))
	require.NoError(t, r.Flush())
	r.Stop()

	st := readStream(t, bytes.NewReader(l.readAll(t)))
	require.Len(t, st.samples, 1)
	p := readOne(t, dir)
	require.Len(t, p.Sample, 1)
	assert.Equal(t, []string{p.Sample[0].Location[0].Line[0].Function.Name},
		st.samples[0].funcs)
	assert.Equal(t, "0xdeadbeef", st.samples[0].funcs[0])
}

// --- writer-path stand-ins -------------------------------------------------
//
// The accounting bugs below (emitted counted before the bytes left, buffered
// records discarded silently, a shutdown that never returns) are all about what
// happens when a write does NOT complete. Driving that through a real socket is
// a race; these conns make each case exact.

type fakeAddr struct{}

func (fakeAddr) Network() string { return "unix" }
func (fakeAddr) String() string  { return "fake" }

// nopConnBase supplies the net.Conn methods the writer path never uses.
type nopConnBase struct{}

func (nopConnBase) Read([]byte) (int, error)        { return 0, io.EOF }
func (nopConnBase) Close() error                    { return nil }
func (nopConnBase) LocalAddr() net.Addr             { return fakeAddr{} }
func (nopConnBase) RemoteAddr() net.Addr            { return fakeAddr{} }
func (nopConnBase) SetDeadline(time.Time) error     { return nil }
func (nopConnBase) SetReadDeadline(time.Time) error { return nil }

// SetWriteDeadline is a no-op: these conns model a writer that a deadline
// cannot rescue, which is exactly why shutdown needs its own bound.
func (nopConnBase) SetWriteDeadline(time.Time) error { return nil }

// bufferConn accepts every write, standing in for a healthy consumer.
type bufferConn struct {
	nopConnBase
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *bufferConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

// failingConn fails every write, standing in for a consumer that vanished.
type failingConn struct {
	nopConnBase
}

func (c *failingConn) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

// wedgedConn blocks every write until it is closed and ignores deadlines.
type wedgedConn struct {
	nopConnBase
	closed chan struct{}
	once   sync.Once
}

func (c *wedgedConn) Write([]byte) (int, error) {
	<-c.closed
	return 0, io.ErrClosedPipe
}

func (c *wedgedConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

// attach wires a conn onto the sink the way dial() would, minus the socket.
func attach(s *socketSink, c net.Conn) {
	s.conn = c
	s.bw = bufio.NewWriterSize(&countingConn{Conn: c, n: &s.st.bytesWritten},
		socketWriteBufBytes)
}

func oneSample() *sampleEvent {
	return &sampleEvent{
		frames: []frame{{function: "leaf", file: "leaf.erl", line: 1}},
		ktime:  1, unixNano: 2, pid: 3, tid: 4,
	}
}

// A record handed to the 1 MiB write buffer has NOT reached the consumer.
// Counting it as emitted there is what let a consumer restart discard up to a
// megabyte of samples while STATS reported them delivered -- and, because
// Dropped() did not know about that channel either, let the equivalence
// fixture's require.Zero certify a lossy stream as loss-free.
func TestSocketSinkEmittedCountsOnlyWhatReachedTheWire(t *testing.T) {
	healthy, err := newSocketSink(SocketConfig{Path: "unused"})
	require.NoError(t, err)
	attach(healthy, &bufferConn{})
	require.NoError(t, healthy.writeSample(oneSample()))
	assert.Zero(t, healthy.st.emitted.Load(),
		"a sample sitting in the write buffer is not emitted")
	require.NoError(t, healthy.flush())
	assert.Equal(t, uint64(1), healthy.st.emitted.Load(), "flushed is emitted")
	assert.Zero(t, healthy.Dropped())

	// Same two records, but the connection dies before the flush lands: the
	// buffered sample is lost, and it has to be counted somewhere Dropped()
	// can see.
	lossy, err := newSocketSink(SocketConfig{Path: "unused"})
	require.NoError(t, err)
	attach(lossy, &failingConn{})
	require.NoError(t, lossy.writeSample(oneSample()))
	require.Error(t, lossy.flush())
	lossy.connFailed(io.ErrClosedPipe)
	assert.Zero(t, lossy.st.emitted.Load(), "nothing reached the consumer")
	assert.Equal(t, uint64(1), lossy.st.droppedWrite.Load())
	assert.Equal(t, uint64(1), lossy.Dropped(),
		"loss on the write path must reach Dropped(), or the guards are blind")
}

// A write failure mid-stream is loss, and a profiler that reports it as
// "emitted" is worse than one that crashes.
func TestSocketSinkWriteFailureMakesDroppedNonzero(t *testing.T) {
	s, err := newSocketSink(SocketConfig{
		Path: "unused", FlushInterval: 2 * time.Millisecond, StatsInterval: time.Hour,
	})
	require.NoError(t, err)
	attach(s, &failingConn{})
	s.start()
	for i := 0; i < 4; i++ {
		s.offer(oneSample())
	}
	deadline := time.Now().Add(5 * time.Second)
	for s.Dropped() == 0 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	s.shutdown()
	assert.Positive(t, s.Dropped(), "a failed write must be counted as a drop")
	assert.Zero(t, s.st.emitted.Load(), "nothing was ever delivered")
	// The residual a consumer computes from the wire's four counters is
	// exactly the write-path loss, since v1 STATS has no slot for it.
	assert.Equal(t, s.st.droppedWrite.Load(),
		s.st.produced.Load()-s.st.emitted.Load()-
			s.st.droppedRing.Load()-s.st.droppedNoSock.Load())
}

// A consumer that connects and then stops reading WITHOUT closing wedges the
// writer inside a blocking write, where it never observes the stop channel.
// Unbounded, shutdown() waits on that forever: SIGINT does nothing and the
// agent has to be SIGKILLed.
func TestSocketSinkShutdownIsBoundedWhenTheWriterIsWedged(t *testing.T) {
	s, err := newSocketSink(SocketConfig{
		Path: "unused", FlushInterval: 5 * time.Millisecond, StatsInterval: time.Hour,
	})
	require.NoError(t, err)
	c := &wedgedConn{closed: make(chan struct{})}
	// Release the abandoned writer goroutine when the test ends.
	t.Cleanup(func() { _ = c.Close() })
	attach(s, c)
	s.start()
	s.offer(oneSample())
	// Give the flush ticker time to push the buffer at the wedged conn.
	time.Sleep(100 * time.Millisecond)

	start := time.Now()
	s.shutdown()
	elapsed := time.Since(start)
	assert.Less(t, elapsed, s.shutdownTimeout()+3*time.Second,
		"shutdown must not wait on a wedged writer indefinitely")
	select {
	case <-s.done:
		t.Fatal("test did not actually wedge the writer; it exited on its own")
	default:
	}
}

// The shutdown backstop must always outlast ONE write deadline, for every
// WriteTimeout a user can set. Before this was derived, socketShutdownTimeout
// was a flat 2s while -socket-egress-write-timeout advertised a 5s max: a 3s
// setting inverted them, so a wedged consumer's shutdown hit the backstop
// first, skipped the final STATS record, and accounted its loss through the
// explicitly-approximate residual instead of exactly. Mutation-check: make
// shutdownTimeout a constant again and the 3s/5s/hour cases fail.
func TestSocketShutdownBudgetAlwaysExceedsWriteDeadline(t *testing.T) {
	for _, wt := range []time.Duration{
		0, // unset: the reporter's default
		time.Microsecond, socketWriteDeadlineMin, 500 * time.Millisecond,
		time.Second, 3 * time.Second, socketWriteDeadlineMax, time.Hour,
	} {
		s, err := newSocketSink(SocketConfig{Path: "unused", WriteTimeout: wt})
		require.NoError(t, err)
		assert.Greater(t, s.shutdownTimeout(), s.writeDeadline(),
			"WriteTimeout=%s: the shutdown backstop must fire after the write "+
				"deadline, not before it", wt)
	}
}

// End to end over a real unix socket: a consumer that accepts and never reads
// must cost samples and a torn-down connection, not the agent's ability to
// exit. This is the write deadline doing its job; the bound above is the
// backstop for when it cannot.
func TestSocketSinkStalledConsumerDoesNotBlockStop(t *testing.T) {
	gate := make(chan struct{}) // held shut: the consumer never reads
	l := newListenerGated(t, gate)
	// Released only once the test is over, so the listener's own cleanup can
	// join its read loop. Registered after newListenerGated so it runs first.
	t.Cleanup(func() { close(gate) })
	dir := t.TempDir()
	r, err := NewLocalEgress(LocalEgressConfig{
		Dir: dir, SamplesPerSecond: 997,
		// One pprof file, written by the explicit Flush below: readOne requires
		// exactly one, so the 10s default would fail this on a slow box for a
		// reason that has nothing to do with the stalled consumer.
		FlushInterval: time.Hour,
		Socket: SocketConfig{
			Path: l.path, RingSize: 1 << 16,
			FlushInterval: 5 * time.Millisecond, StatsInterval: time.Hour,
		},
	})
	require.NoError(t, err)
	require.NoError(t, r.Start(t.Context()))

	tr := testTrace(t, "root", "mid", "leaf")
	// Enough bytes to overrun the socket buffers plus the 1 MiB write buffer
	// several times over, so a flush really does block rather than being
	// absorbed. At ~105 bytes a sample this is ~5 MiB against ~1.25 MiB of
	// buffering, a margin a kernel autotuning its socket buffer cannot close.
	const n = 50000
	for i := int64(0); i < n; i++ {
		require.NoError(t, r.ReportTraceEvent(tr, meta(i, 100, 101, "c", "p", "x")))
	}
	require.NoError(t, r.Flush())

	start := time.Now()
	r.Stop()
	assert.Less(t, time.Since(start), 20*time.Second, "Stop() hung on a stalled consumer")
	assert.Positive(t, r.SocketDropped(), "a consumer that never reads must cost samples")
	// The pprof artifact is complete regardless, and says the stream was not.
	assert.Len(t, readOne(t, dir).Sample, n)
}

// connectErrors was incremented by connFailed AND again by the run loop, so one
// dead connection read as two -- which matters because the counter is on the
// wire and a consumer uses it to decide whether a gap was its own fault.
func TestSocketSinkCountsOneConnectErrorPerFailure(t *testing.T) {
	s, err := newSocketSink(SocketConfig{Path: filepath.Join(t.TempDir(), "absent.sock")})
	require.NoError(t, err)
	require.Error(t, s.dial())
	assert.Equal(t, uint64(1), s.st.connectErrors.Load(), "one failed dial is one error")
	require.Error(t, s.dial())
	assert.Equal(t, uint64(2), s.st.connectErrors.Load())

	// A failure past net.Dial is counted by connFailed, and only there.
	attach(s, &failingConn{})
	s.connFailed(errors.New("header write failed"))
	assert.Equal(t, uint64(3), s.st.connectErrors.Load())
}

// The loss warning must describe NEW loss. Warning on the cumulative total
// makes a single dropped sample warn every stats interval for the life of the
// process, which is how a real warning gets ignored.
// It asserts on lossWarning(), logIfLossy's decision, rather than capturing the
// package-global logger: internal/log exposes no way to read the logger back,
// so a test that swapped it could only "restore" a freshly built stderr logger
// and would silently discard whatever level or handler the binary had
// configured for every test that ran after it.
func TestSocketSinkWarnsOnlyWhenLossGrows(t *testing.T) {
	s, err := newSocketSink(SocketConfig{Path: "unused"})
	require.NoError(t, err)
	_, warn := s.lossWarning()
	assert.False(t, warn, "a lossless run says nothing")

	s.st.droppedRing.Add(1)
	msg, warn := s.lossWarning()
	require.True(t, warn)
	assert.Contains(t, msg, "socket egress dropped 1 samples")
	_, warn = s.lossWarning()
	assert.False(t, warn, "an unchanged total must not warn again")
	_, warn = s.lossWarning()
	assert.False(t, warn)

	s.st.droppedNoSock.Add(2)
	msg, warn = s.lossWarning()
	require.True(t, warn, "new loss must warn")
	assert.Contains(t, msg, "socket egress dropped 3 samples")
}

// bytesWritten is what a consumer reconciles against its own received count, so
// it has to be bytes the socket accepted -- not bytes handed to a 1 MiB buffer,
// which overstates the stream by up to the buffer size and permanently so once
// a connection dies with it full.
func TestSocketSinkBytesWrittenCountsOnlyDeliveredBytes(t *testing.T) {
	s, err := newSocketSink(SocketConfig{Path: "unused"})
	require.NoError(t, err)
	c := &bufferConn{}
	attach(s, c)
	require.NoError(t, s.writeHeader())
	require.NoError(t, s.writeSample(oneSample()))
	assert.Zero(t, s.st.bytesWritten.Load(), "nothing has left the buffer yet")
	require.NoError(t, s.flush())
	c.mu.Lock()
	delivered := c.buf.Len()
	c.mu.Unlock()
	assert.Equal(t, uint64(delivered), s.st.bytesWritten.Load())
}

// F2: the bounded shutdown abandons the writer, and everything the writer held
// -- the ring, and up to a megabyte of buffered records -- is charged to
// produced and to nothing else. Left unaccounted, Dropped() reports 0 for a run
// that lost all of it, which is the one answer the equivalence fixture's
// require.Zero cannot survive being wrong about.
func TestSocketSinkAbandonedWriterChargesItsResidual(t *testing.T) {
	s, err := newSocketSink(SocketConfig{
		Path: "unused", FlushInterval: 5 * time.Millisecond, StatsInterval: time.Hour,
	})
	require.NoError(t, err)
	c := &wedgedConn{closed: make(chan struct{})}
	t.Cleanup(func() { _ = c.Close() })
	attach(s, c)
	s.start()

	const n = 3
	for i := 0; i < n; i++ {
		s.offer(oneSample())
	}
	// Let the flush ticker wedge the writer inside a write it cannot finish.
	time.Sleep(100 * time.Millisecond)
	require.Zero(t, s.st.emitted.Load(), "the wedged conn accepted nothing")

	s.shutdown()
	select {
	case <-s.done:
		t.Fatal("test did not actually wedge the writer; it exited on its own")
	default:
	}
	assert.Equal(t, uint64(n), s.Dropped(),
		"samples the abandoned writer held must be counted as lost, not as nothing")
	assert.Equal(t, uint64(n), s.st.produced.Load())
	assert.Zero(t, s.residualUnaccounted(), "nothing may be left unexplained")
}

// F4: bufio flushes on its own when the 1 MiB buffer fills, and pendingSamples
// is only cleared by flush(). Records that DID reach the consumer were then
// charged to droppedWrite and never counted as emitted -- and at ~20 MB/s the
// buffer fills every ~50ms, so that was the steady state.
func TestSocketSinkEmittedIsExactAcrossABufferFill(t *testing.T) {
	s, err := newSocketSink(SocketConfig{Path: "unused"})
	require.NoError(t, err)
	c := &bufferConn{}
	attach(s, c)

	// ~105 bytes a sample, so this overruns the 1 MiB write buffer twice over.
	const n = 20000
	for i := 0; i < n; i++ {
		require.NoError(t, s.writeSample(oneSample()))
	}
	emitted := s.st.emitted.Load()
	assert.Positive(t, emitted,
		"a buffer-filling write reaches the consumer and must be promoted, not estimated")
	c.mu.Lock()
	delivered := c.buf.Len()
	c.mu.Unlock()
	assert.Positive(t, delivered)
	assert.Equal(t, uint64(delivered), s.st.bytesWritten.Load())

	// The connection now dies with the tail still buffered. Every sample is
	// either emitted or dropped: never both, and never neither.
	s.connFailed(io.ErrClosedPipe)
	assert.Equal(t, uint64(n), emitted+s.Dropped())
	assert.Equal(t, emitted, s.st.emitted.Load(), "a delivered sample stays delivered")
}

// F3: the pprof archive was built before the socket drain, so a consumer dying
// in the last flush window produced a file that said "no loss" for a run whose
// log warned about loss -- while build()'s own comment claims the two artifacts
// cross-attest. failingConn makes the case exact: nothing fails until the drain
// flushes, and the drain is what Stop() must reach first.
func TestSocketDropsInTheFinalDrainReachThePprofComment(t *testing.T) {
	dir := t.TempDir()
	r, err := NewLocalEgress(LocalEgressConfig{
		Dir: dir, SamplesPerSecond: 997,
		// One file, written by Stop()'s final flush.
		FlushInterval: time.Hour,
		Socket: SocketConfig{
			Path: "unused", FlushInterval: time.Hour, StatsInterval: time.Hour,
		},
	})
	require.NoError(t, err)
	// Stand in for a connection that is up when the samples are written and
	// discovered dead only when the drain flushes. Attached before start(), so
	// run() never dials.
	attach(r.socket, &failingConn{})
	require.NoError(t, r.Start(t.Context()))

	tr := testTrace(t, "root", "leaf")
	const n = 50
	for i := int64(0); i < n; i++ {
		require.NoError(t, r.ReportTraceEvent(tr, meta(i, 100, 101, "c", "p", "x")))
	}
	r.Stop()

	require.Equal(t, uint64(n), r.SocketDropped(),
		"every sample was lost when the drain found the connection dead")
	assert.Zero(t, r.Dropped(), "the pprof path lost nothing")

	p := readOne(t, dir)
	require.Len(t, p.Sample, n)
	// dropSummary() is the single rendering the warning also uses, so a comment
	// equal to it is a comment that cannot state different numbers than the log.
	assert.Contains(t, p.Comments, r.socket.dropSummary(),
		"the archive must state the drain's loss: %v", p.Comments)
}

// A sample must be on the wire as soon as it is written, without waiting for
// any ticker. Batching in the 1 MiB buffer made delivery latency a function of
// FlushInterval (50ms by default, and unbounded if a caller set it high), which
// is exactly the file-flush latency floor this egress exists to remove.
//
// Both tickers are set to an hour, so nothing but a per-sample flush can
// promote a sample to emitted before shutdown: against the batching code this
// test times out at zero emitted.
func TestSocketSinkFlushesEachSampleWithoutWaitingForATicker(t *testing.T) {
	s, err := newSocketSink(SocketConfig{
		Path: "unused", FlushInterval: time.Hour, StatsInterval: time.Hour,
	})
	require.NoError(t, err)
	c := &bufferConn{}
	attach(s, c)
	s.start()
	t.Cleanup(s.shutdown)

	awaitEmitted := func(want uint64) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for s.st.emitted.Load() < want {
			if time.Now().After(deadline) {
				t.Fatalf("emitted %d of %d samples with both tickers at an hour: "+
					"the sample is waiting for a flush that will not come",
					s.st.emitted.Load(), want)
			}
			time.Sleep(time.Millisecond)
		}
		require.Equal(t, want, s.st.emitted.Load())
	}

	s.offer(oneSample())
	awaitEmitted(1)
	// Emitted means the bytes were accepted by the conn, not handed to bufio.
	c.mu.Lock()
	afterFirst := c.buf.Len()
	c.mu.Unlock()
	assert.Positive(t, afterFirst, "the record must have reached the conn")
	assert.Equal(t, uint64(afterFirst), s.st.bytesWritten.Load())

	// And the second sample does not wait either: this is per-sample, not
	// "the first write happens to flush".
	s.offer(oneSample())
	awaitEmitted(2)
	c.mu.Lock()
	afterSecond := c.buf.Len()
	c.mu.Unlock()
	assert.Greater(t, afterSecond, afterFirst)
	assert.Zero(t, s.Dropped())
}

// Shutdown can reach the drain with samples queued and nothing dialed yet:
// run() dials on the first sample it processes, and its select picks between a
// ready stop and a ready ring at random. Before the drain dialed, that path
// charged every queued sample to droppedNoSock and closed without connecting,
// so a run whose first samples coincided with shutdown delivered nothing.
func TestSocketSinkDrainDialsForQueuedSamples(t *testing.T) {
	l := newListener(t)
	s, err := newSocketSink(SocketConfig{Path: l.path, FlushInterval: time.Hour})
	require.NoError(t, err)
	require.Nil(t, s.conn, "the sink must reach the drain unconnected")
	s.offer(oneSample())
	s.offer(oneSample())

	s.drainAndClose()

	st := readStream(t, bytes.NewReader(l.readAll(t)))
	require.Len(t, st.samples, 2)
	assert.Equal(t, []string{"leaf"}, st.samples[0].funcs)
	assert.Zero(t, s.Dropped(), "queued samples must not be charged as dropped")
}

// The same path with no consumer must stay bounded and honest: one dial
// attempt, no backoff loop, and the samples counted as dropped.
func TestSocketSinkDrainDialFailureStaysBounded(t *testing.T) {
	s, err := newSocketSink(SocketConfig{
		Path: filepath.Join(t.TempDir(), "absent.sock"), FlushInterval: time.Hour,
	})
	require.NoError(t, err)
	s.offer(oneSample())
	s.offer(oneSample())

	start := time.Now()
	s.drainAndClose()
	assert.Less(t, time.Since(start), 5*time.Second, "drain must not retry-loop")
	assert.Equal(t, uint64(2), s.Dropped())
	assert.Nil(t, s.conn)
}

// labelsByKey indexes a decoded sample's labels for assertion.
func labelsByKey(s decodedSample) map[string]decodedLabel {
	out := make(map[string]decodedLabel, len(s.labels))
	for _, l := range s.labels {
		out[l.key] = l
	}
	return out
}

// beamscopeEvent is a beamscope-origin sample carrying every field class the
// wire has to reproduce: a measurement with a kind, an Erlang pid, a numeric
// custom label with a unit, and a string custom label.
func beamscopeEvent(t *testing.T) (*libpf.Trace, *samples.TraceEventMeta) {
	t.Helper()
	tr := testTrace(t, "root", "leaf")
	tr.CustomLabels = map[libpf.String]libpf.String{
		libpf.Intern("pause_ns"):       libpf.Intern("4096"),
		libpf.Intern("mbuf_words"):     libpf.Intern("77"),
		libpf.Intern("beamscope_kind"): libpf.Intern("alloc"),
	}
	m := meta(7, 11, 12, "beam.smp", "p", "x")
	m.Origin = support.TraceOriginBeamScope
	m.Value = 54_321
	m.ValueKind = samples.ValueKindAlloc
	m.ErlangPidKey = 0x1234_5678_9abc_def0
	return tr, m
}

// The socket must carry a beamscope sample WHOLE with no pprof sink in
// existence. This is the property that lets -beamscope run socket-only: value,
// value_kind, erlang_pid_key and custom labels all survive the wire.
func TestSocketSinkCarriesBeamscopeSampleWithoutPprof(t *testing.T) {
	l := newListener(t)
	r, err := NewLocalEgress(LocalEgressConfig{
		SamplesPerSecond: 997,
		Socket:           SocketConfig{Path: l.path, FlushInterval: 5 * time.Millisecond},
	})
	require.NoError(t, err)
	require.Nil(t, r.pprof, "this test is meaningless if a pprof sink exists")
	require.NoError(t, r.Start(t.Context()))
	tr, m := beamscopeEvent(t)
	require.NoError(t, r.ReportTraceEvent(tr, m))
	require.NoError(t, r.Flush())
	r.Stop()

	st := readStream(t, bytes.NewReader(l.readAll(t)))
	require.Equal(t, SocketVersion, st.version)
	require.Len(t, st.samples, 1)
	got := st.samples[0]

	assert.Equal(t, int64(54_321), got.value)
	assert.Equal(t, SocketValueKindAlloc, got.valueKind)
	assert.Equal(t, uint64(0x1234_5678_9abc_def0), got.erlangPidKey)

	byKey := labelsByKey(got)
	require.Contains(t, byKey, "pause_ns")
	assert.Equal(t, SocketLabelNumeric, byKey["pause_ns"].kind)
	assert.Equal(t, int64(4096), byKey["pause_ns"].num)
	assert.Equal(t, "nanoseconds", byKey["pause_ns"].unit)

	require.Contains(t, byKey, "mbuf_words")
	assert.Equal(t, int64(77), byKey["mbuf_words"].num)
	assert.Equal(t, "words", byKey["mbuf_words"].unit)

	require.Contains(t, byKey, "beamscope_kind")
	assert.Equal(t, SocketLabelString, byKey["beamscope_kind"].kind)
	assert.Equal(t, "alloc", byKey["beamscope_kind"].str)
}

// The two backends must agree field for field, or "socket-only" silently means
// "a different capture". Same event, both backends, compared.
func TestSocketBeamscopeSampleMatchesPprof(t *testing.T) {
	l := newListener(t)
	dir := t.TempDir()
	r, err := NewLocalEgress(LocalEgressConfig{
		Dir: dir, SamplesPerSecond: 997,
		Socket: SocketConfig{Path: l.path, FlushInterval: 5 * time.Millisecond},
	})
	require.NoError(t, err)
	require.NoError(t, r.Start(t.Context()))
	tr, m := beamscopeEvent(t)
	require.NoError(t, r.ReportTraceEvent(tr, m))
	require.NoError(t, r.Flush())
	r.Stop()

	st := readStream(t, bytes.NewReader(l.readAll(t)))
	require.Len(t, st.samples, 1)
	byKey := labelsByKey(st.samples[0])

	p := readOne(t, dir)
	require.Len(t, p.Sample, 1)
	ps := p.Sample[0]

	// The measurement lands in the alloc column of the file and in
	// value/value_kind on the wire; both must say 54321 allocated words.
	require.Len(t, ps.Value, 5)
	assert.Equal(t, ps.Value[2], st.samples[0].value)
	assert.Equal(t, "alloc", p.SampleType[2].Type)

	// Erlang attribution: a numeric label in the file, a fixed field on the
	// wire, same number.
	require.Contains(t, ps.NumLabel, LabelErlangPidKey)
	assert.Equal(t, uint64(ps.NumLabel[LabelErlangPidKey][0]),
		st.samples[0].erlangPidKey)

	// Numeric custom labels: same value AND same unit on both paths.
	for _, k := range []string{"pause_ns", "mbuf_words"} {
		require.Contains(t, ps.NumLabel, k, "pprof lost %s", k)
		require.Contains(t, byKey, k, "socket lost %s", k)
		assert.Equal(t, ps.NumLabel[k][0], byKey[k].num, "%s value", k)
		assert.Equal(t, ps.NumUnit[k][0], byKey[k].unit, "%s unit", k)
	}
	// String custom labels likewise.
	require.Contains(t, ps.Label, "beamscope_kind")
	assert.Equal(t, ps.Label["beamscope_kind"][0], byKey["beamscope_kind"].str)
}

// A traced process must not be able to overwrite the reporter's own fields by
// emitting a custom label of a contract name -- the same rule the pprof path
// enforces, enforced identically here.
func TestSocketSinkSkipsReservedLabelNames(t *testing.T) {
	l := newListener(t)
	r, err := NewLocalEgress(LocalEgressConfig{
		SamplesPerSecond: 997,
		Socket:           SocketConfig{Path: l.path, FlushInterval: 5 * time.Millisecond},
	})
	require.NoError(t, err)
	require.NoError(t, r.Start(t.Context()))
	tr := testTrace(t, "leaf")
	tr.CustomLabels = map[libpf.String]libpf.String{
		libpf.Intern("comm"):   libpf.Intern("not-the-real-comm"),
		libpf.Intern("origin"): libpf.Intern("lies"),
		libpf.Intern("keep"):   libpf.Intern("kept"),
	}
	require.NoError(t, r.ReportTraceEvent(tr, meta(1, 1, 2, "realcomm", "p", "x")))
	require.NoError(t, r.Flush())
	r.Stop()

	st := readStream(t, bytes.NewReader(l.readAll(t)))
	require.Len(t, st.samples, 1)
	byKey := labelsByKey(st.samples[0])
	assert.NotContains(t, byKey, "comm")
	assert.NotContains(t, byKey, "origin")
	assert.Contains(t, byKey, "keep")
	assert.Equal(t, "realcomm", st.samples[0].comm)
}

// Labels are serialized in sorted key order so two identical captures produce
// identical bytes. Map range order would make this flaky rather than wrong,
// which is worse.
func TestSocketSinkLabelOrderIsDeterministic(t *testing.T) {
	run := func() []string {
		l := newListener(t)
		r, err := NewLocalEgress(LocalEgressConfig{
			SamplesPerSecond: 997,
			Socket:           SocketConfig{Path: l.path, FlushInterval: 5 * time.Millisecond},
		})
		require.NoError(t, err)
		require.NoError(t, r.Start(t.Context()))
		tr := testTrace(t, "leaf")
		tr.CustomLabels = map[libpf.String]libpf.String{
			libpf.Intern("zeta"):  libpf.Intern("1"),
			libpf.Intern("alpha"): libpf.Intern("2"),
			libpf.Intern("mid"):   libpf.Intern("3"),
			libpf.Intern("beta"):  libpf.Intern("4"),
		}
		require.NoError(t, r.ReportTraceEvent(tr, meta(1, 1, 2, "c", "p", "x")))
		require.NoError(t, r.Flush())
		r.Stop()
		st := readStream(t, bytes.NewReader(l.readAll(t)))
		require.Len(t, st.samples, 1)
		var keys []string
		for _, lb := range st.samples[0].labels {
			keys = append(keys, lb.key)
		}
		return keys
	}
	want := []string{"alpha", "beta", "mid", "zeta"}
	assert.Equal(t, want, run())
	assert.Equal(t, want, run(), "label order must not vary between runs")
}
