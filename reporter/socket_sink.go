// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

// Socket output for assembled local samples. A bounded queue isolates the
// reporting path from socket I/O; losses are counted in STATS and profile
// comments when both backends are active. See doc/discord-fork.md for wire v2.

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

// Wire format constants. These are a contract with pstore-ingest; changing one
// without bumping SocketVersion is a silent corruption, not a bug fix.
const (
	// SocketMagic opens every connection. 8 bytes, ASCII, no terminator.
	SocketMagic = "PSTRSOK1"
	// SocketVersion is the stream version in the header. Version 2 added the
	// four fields v1 could not carry -- value, value_kind, erlang_pid_key and
	// custom labels -- which is what lets the socket own a beamscope capture
	// outright instead of requiring the pprof file alongside it.
	SocketVersion uint16 = 2
	// SocketHeaderLen is the byte length of the stream header. A reader
	// consumes exactly this many bytes (read from the header itself), so a
	// later version can grow the header without breaking the framing.
	SocketHeaderLen uint16 = 40
)

// Value kinds. A sample carries at most one measurement of its own, and
// value_kind says which column it belongs in -- the wire equivalent of the
// pprof file's one-column-per-origin rule. These numbers are the wire's own,
// deliberately not samples.ValueKind*, so renumbering upstream cannot silently
// relabel a capture.
const (
	// SocketValueKindNone means the sample carries no measurement of its own
	// and `value` is meaningless. Every non-beamscope sample is this.
	SocketValueKindNone uint8 = 0
	// SocketValueKindAlloc is allocated words (GC_DELTA/GC_DELTA2).
	SocketValueKindAlloc uint8 = 1
	// SocketValueKindSchedNS is on-scheduler nanoseconds (SCHED_DELTA).
	SocketValueKindSchedNS uint8 = 2
	// SocketValueKindMsgs is scaled message arrivals (MSG_FLOW).
	SocketValueKindMsgs uint8 = 3
)

// Label kinds, in each label entry's kind byte.
const (
	// SocketLabelString is a string label: value_strid holds it, num and
	// unit_strid are zero.
	SocketLabelString uint8 = 0
	// SocketLabelNumeric is a numeric label: num holds the value and
	// unit_strid names its unit, value_strid is zero. The pprof path writes
	// exactly these as pprof numeric labels, so the two agree field for field.
	SocketLabelNumeric uint8 = 1
)

// Stream flags, in the header's flags word.
const (
	// StreamFlagFramesLeafFirst is set when each SAMPLE's frame array is
	// ordered leaf-first, as the tracer delivers it and as the pprof writer
	// orders Location. A consumer building a root-first folded key reverses.
	// It is always set; it exists so that a producer that ever flips the order
	// is DETECTED rather than silently mis-folded.
	StreamFlagFramesLeafFirst uint32 = 1 << 0
)

// Record types.
const (
	// RecStrdef defines one entry of the per-connection string table.
	RecStrdef uint8 = 1
	// RecSample is one raw sample.
	RecSample uint8 = 2
	// RecStats is a counter snapshot.
	RecStats uint8 = 3
)

// Sample flags.
const (
	// SampleFlagFramesTruncated marks a sample whose frame list hit the cap.
	// The frames present are the leaf-most ones. Such a sample is NOT
	// comparable with the same sample in the pprof file, which never
	// truncates, so a consumer that cares about equivalence must refuse to
	// treat a stream carrying these as equivalent.
	SampleFlagFramesTruncated uint8 = 1 << 0
)

// Fixed-size parts of the payloads, in bytes, excluding the 1-byte rec_type.
const (
	socketSampleFixedLen = 80
	socketFrameLen       = 12
	socketLabelLen       = 24
	socketStatsLen       = 80
	socketStrdefFixedLen = 8
)

// Origin codes on the wire. Deliberately their own numbering rather than
// libpf's, so an upstream renumbering cannot silently relabel a capture.
const (
	socketOriginUnknown   uint8 = 0
	socketOriginSampling  uint8 = 1
	socketOriginOffCPU    uint8 = 2
	socketOriginProbe     uint8 = 3
	socketOriginBeamScope uint8 = 4
)

// Defaults for the tunables. The four Default* ones are exported because the
// command-line help interpolates them: a flag registered with a zero default
// ("not specified", so the reporter picks) would otherwise document no number
// at all, since Go's flag package omits "(default ...)" for a zero value.
const (
	// DefaultSocketRingSize is the default SocketConfig.RingSize.
	DefaultSocketRingSize = 1 << 16
	// DefaultSocketMaxFrames is the default SocketConfig.MaxFrames.
	DefaultSocketMaxFrames = 4096
	// DefaultSocketStatsInterval is the default SocketConfig.StatsInterval.
	DefaultSocketStatsInterval = 5 * time.Second
	// DefaultSocketFlushInterval is the default SocketConfig.FlushInterval.
	// It is a safety net, not the latency floor: see SocketConfig.FlushInterval.
	DefaultSocketFlushInterval = 50 * time.Millisecond
	// DefaultSocketWriteTimeout is the default SocketConfig.WriteTimeout.
	DefaultSocketWriteTimeout = time.Second

	socketDialBackoffMin = 100 * time.Millisecond
	socketDialBackoffMax = 5 * time.Second
	socketWriteBufBytes  = 1 << 20

	// Bound writes so a stalled consumer cannot keep the writer alive forever.
	socketWriteDeadlineMin = 250 * time.Millisecond
	socketWriteDeadlineMax = 5 * time.Second

	// socketShutdownSlack gives a timed-out write time to finish its cleanup.
	socketShutdownSlack = time.Second
)

// SocketConfig configures the socket egress. Zero value = disabled.
type SocketConfig struct {
	// Path is the unix socket to dial. The CONSUMER listens and the agent
	// dials: that way restarting the consumer is a reconnect rather than a
	// profiler restart, and the socket file is owned by the process that can
	// safely unlink it.
	Path string
	// RingSize bounds samples queued between the sampling path and the writer
	// goroutine. Beyond it, offer() drops and counts.
	RingSize int
	// MaxFrames caps the frames emitted per sample. A capped sample is flagged
	// and counted; the cap exists only so a pathological stack cannot produce
	// an unbounded record.
	MaxFrames int
	// StatsInterval is how often a STATS record is emitted. Also emitted
	// immediately after the header and immediately before a clean close.
	StatsInterval time.Duration
	// FlushInterval bounds buffered-record latency. Samples are also flushed
	// individually; this ticker usually finds an empty buffer.
	FlushInterval time.Duration
	// WriteTimeout bounds ONE record write (or flush) before the connection is
	// declared dead. It is the socket path's answer to "how long may a healthy
	// consumer take to accept one record", clamped to
	// [socketWriteDeadlineMin, socketWriteDeadlineMax]. shutdown() waits this
	// long plus socketShutdownSlack, so raising it cannot invert the two.
	WriteTimeout time.Duration
	// SamplesPerSecond is announced in the header so a consumer can convert
	// counts to CPU time without a side channel.
	SamplesPerSecond int
}

// socketStats mirrors the wire counters. At quiescence:
// produced = emitted + droppedRing + droppedNoSock + droppedWrite.
// STATS has no droppedWrite field; consumers infer it as the residual.
// Concurrent snapshots may also include queued or in-flight samples.
type socketStats struct {
	produced      atomic.Uint64
	emitted       atomic.Uint64
	droppedRing   atomic.Uint64
	droppedNoSock atomic.Uint64
	// droppedWrite counts samples that were serialized but never reached the
	// consumer: the one whose write failed, plus everything still sitting in
	// the write buffer when the connection was torn down.
	droppedWrite   atomic.Uint64
	truncFrames    atomic.Uint64
	bytesWritten   atomic.Uint64
	stringsDefined atomic.Uint64
	connectErrors  atomic.Uint64
}

// socketSink streams sampleEvents to a unix socket.
type socketSink struct {
	cfg SocketConfig

	ring chan *sampleEvent
	st   socketStats

	// lastSeenDrops is the cumulative drop total the writer has already
	// attributed to a SAMPLE record. Read and written only by the writer
	// goroutine.
	lastSeenDrops    uint64
	lastEmittedDrops uint64
	// lastLoggedDrops is the drop total the last warning stated. Warning on
	// the cumulative total instead of on its growth makes one lost sample
	// produce a warning every stats interval for the life of the process,
	// which trains the reader to ignore the one line that matters.
	lastLoggedDrops uint64
	// pendingSamples counts serialized samples awaiting a successful flush.
	// Only the writer goroutine accesses it.
	pendingSamples uint64

	// String table, per connection. Reset on reconnect.
	strIDs map[string]uint32
	nextID uint32

	conn net.Conn
	bw   *bufio.Writer
	// scratch is reused for record serialization so steady state allocates
	// nothing per sample.
	scratch []byte
	// frefs is reused for the same reason. It cannot be folded into the
	// SAMPLE assembly loop: str() emits STRDEF records through scratch, which
	// is the very buffer the SAMPLE payload is being built in, so every
	// string a sample references must be resolved BEFORE the payload is
	// started. Writer goroutine only.
	frefs []fref
	lrefs []lref
	lkeys []string

	startOnce sync.Once
	stopOnce  sync.Once
	stop      chan struct{}
	done      chan struct{}
}

func newSocketSink(cfg SocketConfig) (*socketSink, error) {
	if cfg.Path == "" {
		return nil, fmt.Errorf("socket egress: Path is required")
	}
	if cfg.RingSize <= 0 {
		cfg.RingSize = DefaultSocketRingSize
	}
	if cfg.MaxFrames <= 0 {
		cfg.MaxFrames = DefaultSocketMaxFrames
	}
	if cfg.MaxFrames > 0xffff {
		// n_frames is a u16 on the wire.
		cfg.MaxFrames = 0xffff
	}
	if cfg.StatsInterval <= 0 {
		cfg.StatsInterval = DefaultSocketStatsInterval
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = DefaultSocketFlushInterval
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = DefaultSocketWriteTimeout
	}
	if cfg.SamplesPerSecond < 0 {
		cfg.SamplesPerSecond = 0
	}
	return &socketSink{
		cfg:     cfg,
		ring:    make(chan *sampleEvent, cfg.RingSize),
		strIDs:  make(map[string]uint32, 1024),
		nextID:  1,
		scratch: make([]byte, 0, 4096),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}, nil
}

// offer queues an immutable event without waiting for socket I/O.
func (s *socketSink) offer(ev *sampleEvent) {
	s.st.produced.Add(1)
	select {
	case s.ring <- ev:
	default:
		s.st.droppedRing.Add(1)
	}
}

// Dropped is the total number of samples the socket path discarded, for any
// reason: ring full, no consumer, or serialized-then-lost to a write failure.
// A guard that certifies a stream as loss-free reads this, so a channel missing
// from it is a guard that certifies a lossy stream.
func (s *socketSink) Dropped() uint64 {
	return s.st.droppedRing.Load() + s.st.droppedNoSock.Load() + s.st.droppedWrite.Load()
}

// dropSummary is the one rendering of the loss counters, shared by the log line
// and the pprof file's comment so the two artifacts cannot state different
// numbers for the same run.
func (s *socketSink) dropSummary() string {
	return fmt.Sprintf("socket egress dropped %d samples (%d ring-full, %d no consumer, "+
		"%d write failed), %d emitted of %d produced",
		s.Dropped(), s.st.droppedRing.Load(), s.st.droppedNoSock.Load(),
		s.st.droppedWrite.Load(), s.st.emitted.Load(), s.st.produced.Load())
}

// dropSummaryIfLossy supplies a loss comment when the socket discarded samples.
func (s *socketSink) dropSummaryIfLossy() string {
	if s == nil || s.Dropped() == 0 {
		return ""
	}
	return s.dropSummary()
}

func (s *socketSink) start() {
	s.startOnce.Do(func() { go s.run() })
}

func (s *socketSink) shutdown() {
	s.start()
	budget := s.shutdownTimeout()
	s.stopOnce.Do(func() { close(s.stop) })
	select {
	case <-s.done:
	case <-time.After(budget):
		// Account for the unreported residual if the writer exceeds its shutdown
		// budget. This snapshot is approximate while the writer is still running.
		residual := s.residualUnaccounted()
		s.st.droppedWrite.Add(residual)
		log.Warnf("socket egress: writer did not finish within %s; abandoning it "+
			"(final STATS record not written); charged %d unaccounted samples to "+
			"write loss: %s", budget, residual, s.dropSummary())
	}
}

// shutdownTimeout allows a write deadline and its cleanup before the backstop.
func (s *socketSink) shutdownTimeout() time.Duration {
	return s.writeDeadline() + socketShutdownSlack
}

// residualUnaccounted estimates pending samples from non-atomic snapshots.
func (s *socketSink) residualUnaccounted() uint64 {
	accounted := s.st.emitted.Load() + s.st.droppedRing.Load() +
		s.st.droppedNoSock.Load() + s.st.droppedWrite.Load()
	produced := s.st.produced.Load()
	if produced <= accounted {
		return 0
	}
	return produced - accounted
}

// writeDeadline is how long one record write may take before the connection is
// declared dead. See socketWriteDeadline* for why there is one at all, and why
// it is no longer keyed to the flush interval.
func (s *socketSink) writeDeadline() time.Duration {
	d := s.cfg.WriteTimeout
	if d <= 0 {
		d = DefaultSocketWriteTimeout
	}
	if d < socketWriteDeadlineMin {
		d = socketWriteDeadlineMin
	}
	if d > socketWriteDeadlineMax {
		d = socketWriteDeadlineMax
	}
	return d
}

// armWriteDeadline must be called before every write or flush that can reach
// the socket. bufio hides which Write that is -- a buffer-filling append
// flushes -- so the deadline is armed for all of them.
func (s *socketSink) armWriteDeadline() {
	if s.conn != nil {
		_ = s.conn.SetWriteDeadline(time.Now().Add(s.writeDeadline()))
	}
}

// flush counts buffered samples as emitted only after a successful write.
func (s *socketSink) flush() error {
	if s.bw == nil {
		return nil
	}
	// Skip the deadline syscall when there is nothing to flush.
	if s.bw.Buffered() == 0 && s.pendingSamples == 0 {
		return nil
	}
	s.armWriteDeadline()
	if err := s.bw.Flush(); err != nil {
		return err
	}
	if s.pendingSamples > 0 {
		s.st.emitted.Add(s.pendingSamples)
		s.lastEmittedDrops = s.lastSeenDrops
		s.pendingSamples = 0
	}
	return nil
}

// writeBuffered flushes explicitly before a record would fill the buffer,
// so bufio cannot flush samples without updating pendingSamples.
func (s *socketSink) writeBuffered(rec []byte) error {
	if s.bw.Available() < len(rec) {
		if err := s.flush(); err != nil {
			return err
		}
	}
	_, err := s.bw.Write(rec)
	return err
}

// The frame-only maximum fits the buffer; writeSample also checks labels.
var _ [socketWriteBufBytes - (5 + socketSampleFixedLen + 0xffff*socketFrameLen)]struct{}

// ktimeNs reads CLOCK_MONOTONIC, the clock the samples are stamped in. The
// header carries it so a consumer can prove it is in the same clock domain as
// the stream rather than assuming it.
func ktimeNs() int64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	return ts.Nano()
}

func (s *socketSink) run() {
	defer close(s.done)

	// A safety-net ticker, not the delivery mechanism: samples are flushed as
	// they are written, so this normally finds an empty buffer and returns
	// without a syscall. See SocketConfig.FlushInterval.
	flush := time.NewTicker(s.cfg.FlushInterval)
	defer flush.Stop()
	stats := time.NewTicker(s.cfg.StatsInterval)
	defer stats.Stop()

	backoff := socketDialBackoffMin
	var nextDial time.Time

	for {
		select {
		case <-s.stop:
			s.drainAndClose()
			return

		case ev := <-s.ring:
			if s.conn == nil {
				if time.Now().Before(nextDial) {
					s.st.droppedNoSock.Add(1)
					continue
				}
				if err := s.dial(); err != nil {
					// dial() and connFailed() already counted the error; a
					// second increment here made one failed connection look
					// like two whenever the failure was past net.Dial.
					s.st.droppedNoSock.Add(1)
					nextDial = time.Now().Add(backoff)
					if backoff < socketDialBackoffMax {
						backoff *= 2
					}
					continue
				}
				backoff = socketDialBackoffMin
			}
			if err := s.writeSample(ev); err != nil {
				s.sampleWriteFailed(err)
				continue
			}
			// Flush per sample: the point of this egress is that a sample is
			// queryable at sub-flush-interval resolution, and a record sitting
			// in a buffer waiting for a ticker is exactly the latency floor the
			// pprof path already has. The ring above, not the buffer, is what
			// keeps the sampling path from ever blocking on a slow consumer.
			if err := s.flush(); err != nil {
				s.connFailed(err)
			}
		case <-flush.C:
			if err := s.flush(); err != nil {
				s.connFailed(err)
			}
		case <-stats.C:
			if s.conn != nil {
				// Flush first: STATS must state the totals AFTER the samples
				// it is stating them for have actually left, or emitted lags
				// the stream it describes by a whole flush window.
				if err := s.flush(); err != nil {
					s.connFailed(err)
				} else if err := s.writeStats(); err != nil {
					s.connFailed(err)
				} else if err := s.flush(); err != nil {
					s.connFailed(err)
				}
			}
			s.logIfLossy()
		}
	}
}

// drainAndClose empties the ring into the socket, writes a final STATS, and
// closes. A consumer therefore sees the authoritative totals for the run
// immediately before EOF.
func (s *socketSink) drainAndClose() {
	// Try one connection during shutdown if the first queued sample has not
	// reached the lazy dial yet.
	dialed := false
	for {
		select {
		case ev := <-s.ring:
			if s.conn == nil && !dialed {
				dialed = true
				_ = s.dial()
			}
			if s.conn == nil {
				s.st.droppedNoSock.Add(1)
				continue
			}
			if err := s.writeSample(ev); err != nil {
				s.sampleWriteFailed(err)
			}
		default:
			if s.conn != nil {
				// Flush samples before writing their final counters.
				if err := s.flush(); err != nil {
					s.connFailed(err)
				} else if err := s.writeStats(); err != nil {
					s.connFailed(err)
				} else if err := s.flush(); err != nil {
					s.connFailed(err)
				}
			}
			if s.conn != nil {
				_ = s.conn.Close()
				s.conn, s.bw = nil, nil
				// Anything still buffered at this point never left.
				s.discardPending()
			}
			s.logIfLossy()
			return
		}
	}
}

// logIfLossy warns when the loss total has GROWN since the last check, not
// whenever it is nonzero: the latter makes a single dropped sample warn on
// every stats tick forever.
func (s *socketSink) logIfLossy() {
	if msg, warn := s.lossWarning(); warn {
		log.Warnf("%s", msg)
	}
}

// lossWarning is logIfLossy's decision, separated from the logging so a test can
// pin "warn only on growth" without reaching for the process-global logger.
// Writer goroutine only, like lastLoggedDrops.
func (s *socketSink) lossWarning() (string, bool) {
	d := s.Dropped()
	if d == 0 || d == s.lastLoggedDrops {
		return "", false
	}
	s.lastLoggedDrops = d
	return s.dropSummary(), true
}

func (s *socketSink) dial() error {
	c, err := net.DialTimeout("unix", s.cfg.Path, s.writeDeadline())
	if err != nil {
		s.st.connectErrors.Add(1)
		return err
	}
	s.conn = c
	// bytesWritten counts bytes the socket ACCEPTED, not bytes handed to
	// bufio: the two differ by up to the write-buffer size, and permanently so
	// once a connection dies with a full buffer, which makes the counter
	// useless for the one thing it is for -- a consumer reconciling it against
	// its own received count.
	s.bw = bufio.NewWriterSize(&countingConn{Conn: c, n: &s.st.bytesWritten},
		socketWriteBufBytes)
	// A fresh connection is a fresh string table: ids are per-connection so a
	// consumer that attaches late never sees a dangling reference.
	s.strIDs = make(map[string]uint32, 1024)
	s.nextID = 1
	if err := s.writeHeader(); err != nil {
		s.connFailed(err)
		return err
	}
	// State the cumulative totals up front, so a consumer attaching mid-run
	// knows exactly how much it missed rather than inferring it.
	if err := s.writeStats(); err != nil {
		s.connFailed(err)
		return err
	}
	if err := s.flush(); err != nil {
		s.connFailed(err)
		return err
	}
	log.Infof("socket egress: connected to %s", s.cfg.Path)
	return nil
}

// countingConn counts bytes the peer's socket accepted.
//
// It embeds net.Conn, which promotes *net.UnixConn's ReadFrom: an io.Copy into
// a countingConn would take that path and never touch the counter. Nothing does
// today; anything that wants to must count there too, or shadow ReadFrom.
type countingConn struct {
	net.Conn
	n *atomic.Uint64
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.n.Add(uint64(n))
	return n, err
}

// sampleWriteFailed accounts for a sample that was serialized but did not make
// it, then tears the connection down. Counting the loss is the point: a sample
// charged to produced and to nothing else is invisible to every guard.
func (s *socketSink) sampleWriteFailed(err error) {
	s.st.droppedWrite.Add(1)
	s.connFailed(err)
}

// discardPending charges everything still in the write buffer to droppedWrite.
// On run()'s path that is at most the one sample whose flush just failed; the
// drain path can be holding the whole ring's worth.
func (s *socketSink) discardPending() {
	if s.pendingSamples > 0 {
		s.st.droppedWrite.Add(s.pendingSamples)
		s.pendingSamples = 0
	}
}

func (s *socketSink) connFailed(err error) {
	if s.conn != nil {
		log.Warnf("socket egress: connection to %s failed: %v", s.cfg.Path, err)
		_ = s.conn.Close()
	}
	s.conn, s.bw = nil, nil
	s.lastSeenDrops = s.lastEmittedDrops
	// The buffer dies with the connection, so every already-serialized sample
	// still in it is gone here. That is the loss the old accounting reported as
	// "emitted".
	s.discardPending()
	s.st.connectErrors.Add(1)
}

func (s *socketSink) writeHeader() error {
	var h [SocketHeaderLen]byte
	copy(h[0:8], SocketMagic)
	binary.LittleEndian.PutUint16(h[8:10], SocketVersion)
	binary.LittleEndian.PutUint16(h[10:12], SocketHeaderLen)
	binary.LittleEndian.PutUint32(h[12:16], StreamFlagFramesLeafFirst)
	binary.LittleEndian.PutUint32(h[16:20], uint32(s.cfg.SamplesPerSecond))
	binary.LittleEndian.PutUint32(h[20:24], uint32(s.cfg.MaxFrames))
	binary.LittleEndian.PutUint64(h[24:32], uint64(ktimeNs()))
	// The two strides make the record layout self-describing: a reader that
	// knows only v2 can still walk a v3 SAMPLE by skipping sample_fixed_len
	// rather than the 80 it was compiled against, and the same for labels.
	// This is what v1 lacked and why v1 could not be grown in place.
	binary.LittleEndian.PutUint16(h[32:34], socketSampleFixedLen)
	binary.LittleEndian.PutUint16(h[34:36], socketLabelLen)
	binary.LittleEndian.PutUint32(h[36:40], 0)
	s.armWriteDeadline()
	return s.writeBuffered(h[:])
}

// str resolves a string to its table id, emitting a STRDEF first if it is new.
//
// Interning happens HERE, on the writer goroutine, deliberately: a STRDEF must
// never be lost, and the only lossy point in this design is the ring, which is
// upstream. So a reference can never dangle.
func (s *socketSink) str(v string) (uint32, error) {
	if v == "" {
		return 0, nil
	}
	if id, ok := s.strIDs[v]; ok {
		return id, nil
	}
	id := s.nextID
	s.nextID++
	s.strIDs[v] = id

	payload := socketStrdefFixedLen + len(v)
	s.scratch = s.scratch[:0]
	s.scratch = binary.LittleEndian.AppendUint32(s.scratch, uint32(payload+1))
	s.scratch = append(s.scratch, RecStrdef)
	s.scratch = binary.LittleEndian.AppendUint32(s.scratch, id)
	s.scratch = binary.LittleEndian.AppendUint32(s.scratch, uint32(len(v)))
	s.scratch = append(s.scratch, v...)
	s.armWriteDeadline()
	if err := s.writeBuffered(s.scratch); err != nil {
		return 0, err
	}
	s.st.stringsDefined.Add(1)
	return id, nil
}

func (s *socketSink) writeSample(ev *sampleEvent) error {
	// Resolve strings first: this may emit STRDEF records, which must precede
	// the SAMPLE that references them.
	comm, err := s.str(ev.comm)
	if err != nil {
		return err
	}
	pname, err := s.str(ev.processName)
	if err != nil {
		return err
	}
	exe, err := s.str(ev.executable)
	if err != nil {
		return err
	}
	cid, err := s.str(ev.containerID)
	if err != nil {
		return err
	}

	nFrames := len(ev.frames)
	var flags uint8
	if nFrames > s.cfg.MaxFrames {
		nFrames = s.cfg.MaxFrames
		flags |= SampleFlagFramesTruncated
		s.st.truncFrames.Add(1)
	}

	s.frefs = s.frefs[:0]
	for i := range nFrames {
		fn, err := s.str(ev.frames[i].function)
		if err != nil {
			return err
		}
		fl, err := s.str(ev.frames[i].file)
		if err != nil {
			return err
		}
		s.frefs = append(s.frefs, fref{fn, fl})
	}

	// Resolve labels in sorted key order for deterministic records. Match
	// the pprof backend's reserved-key and numeric-label rules.
	if err := s.resolveLabels(ev); err != nil {
		return err
	}

	// The drop delta is read at serialization time, so it attributes losses to
	// the gap they most plausibly belong to. The TOTAL is exact (STATS); the
	// per-record attribution is exact to within one writer iteration.
	cum := s.Dropped()
	delta := cum - s.lastSeenDrops
	s.lastSeenDrops = cum
	if delta > 0xffffffff {
		delta = 0xffffffff
	}

	payload := socketSampleFixedLen + nFrames*socketFrameLen +
		len(s.lrefs)*socketLabelLen
	s.scratch = s.scratch[:0]
	s.scratch = binary.LittleEndian.AppendUint32(s.scratch, uint32(payload+1))
	s.scratch = append(s.scratch, RecSample)

	var fixed [socketSampleFixedLen]byte
	binary.LittleEndian.PutUint64(fixed[0:8], uint64(ev.ktime))
	binary.LittleEndian.PutUint64(fixed[8:16], uint64(ev.unixNano))
	binary.LittleEndian.PutUint64(fixed[16:24], uint64(ev.offTime))
	binary.LittleEndian.PutUint32(fixed[24:28], uint32(ev.pid))
	binary.LittleEndian.PutUint32(fixed[28:32], uint32(ev.tid))
	binary.LittleEndian.PutUint32(fixed[32:36], uint32(ev.cpu))
	binary.LittleEndian.PutUint32(fixed[36:40], uint32(delta))
	binary.LittleEndian.PutUint32(fixed[40:44], comm)
	binary.LittleEndian.PutUint32(fixed[44:48], pname)
	binary.LittleEndian.PutUint32(fixed[48:52], exe)
	binary.LittleEndian.PutUint32(fixed[52:56], cid)
	fixed[56] = socketOrigin(ev.origin)
	fixed[57] = flags
	binary.LittleEndian.PutUint16(fixed[58:60], uint16(nFrames))
	binary.LittleEndian.PutUint16(fixed[60:62], uint16(len(s.lrefs)))
	fixed[62] = socketValueKind(ev.valueKind)
	fixed[63] = 0
	// value is meaningless unless value_kind says which column it belongs in,
	// so a kind of None writes a zero value rather than whatever the field
	// happened to hold: a consumer must never find a number here it could
	// mistake for a measurement.
	if fixed[62] != SocketValueKindNone {
		binary.LittleEndian.PutUint64(fixed[64:72], uint64(ev.value))
	}
	binary.LittleEndian.PutUint64(fixed[72:80], ev.erlangPidKey)
	s.scratch = append(s.scratch, fixed[:]...)

	for i := range nFrames {
		s.scratch = binary.LittleEndian.AppendUint32(s.scratch, s.frefs[i].fn)
		s.scratch = binary.LittleEndian.AppendUint32(s.scratch, s.frefs[i].file)
		s.scratch = binary.LittleEndian.AppendUint32(s.scratch, uint32(ev.frames[i].line))
	}

	for _, l := range s.lrefs {
		var b [socketLabelLen]byte
		binary.LittleEndian.PutUint32(b[0:4], l.key)
		binary.LittleEndian.PutUint32(b[4:8], l.val)
		binary.LittleEndian.PutUint32(b[8:12], l.unit)
		b[12] = l.kind
		binary.LittleEndian.PutUint64(b[16:24], uint64(l.num))
		s.scratch = append(s.scratch, b[:]...)
	}

	s.armWriteDeadline()
	if err := s.writeBuffered(s.scratch); err != nil {
		return err
	}
	// Not emitted yet: it is in the write buffer. flush() promotes it.
	s.pendingSamples++
	return nil
}

// resolveLabels fills s.lrefs from ev.labels, interning every string it needs.
// It mirrors the pprof path's rules exactly -- same reserved-key skip, same
// beamscope-only numeric promotion, same units -- because the whole point of
// carrying labels on the wire is that a consumer reconstructing a profile from
// the stream gets the same labels the file would have had.
func (s *socketSink) resolveLabels(ev *sampleEvent) error {
	s.lrefs = s.lrefs[:0]
	if len(ev.labels) == 0 {
		return nil
	}
	s.lkeys = s.lkeys[:0]
	for k, v := range ev.labels {
		if _, reserved := contractLabelKeys[k]; reserved || v == "" {
			continue
		}
		s.lkeys = append(s.lkeys, k)
	}
	nFrames := min(len(ev.frames), s.cfg.MaxFrames)
	maxLabels := min(0xffff, (socketWriteBufBytes-5-socketSampleFixedLen-nFrames*socketFrameLen)/socketLabelLen)
	if len(s.lkeys) > maxLabels {
		return fmt.Errorf("socket sample has %d labels; maximum for %d frames is %d", len(s.lkeys), nFrames, maxLabels)
	}
	sort.Strings(s.lkeys)

	beam := socketOrigin(ev.origin) == socketOriginBeamScope
	for _, k := range s.lkeys {
		kid, err := s.str(k)
		if err != nil {
			return err
		}
		v := ev.labels[k]
		if beam {
			if unit, numeric := numLabelUnits[k]; numeric {
				if n, perr := strconv.ParseInt(v, 10, 64); perr == nil {
					uid, uerr := s.str(unit)
					if uerr != nil {
						return uerr
					}
					s.lrefs = append(s.lrefs,
						lref{key: kid, unit: uid, kind: SocketLabelNumeric, num: n})
					continue
				}
			}
		}
		vid, err := s.str(v)
		if err != nil {
			return err
		}
		s.lrefs = append(s.lrefs, lref{key: kid, val: vid, kind: SocketLabelString})
	}
	return nil
}

// fref is one frame's two string-table ids, resolved before the SAMPLE payload
// is assembled. Package-level so the sink can keep one slice for the life of
// the process instead of allocating per sample.
type fref struct{ fn, file uint32 }

func (s *socketSink) writeStats() error {
	s.scratch = s.scratch[:0]
	s.scratch = binary.LittleEndian.AppendUint32(s.scratch, uint32(socketStatsLen+1))
	s.scratch = append(s.scratch, RecStats)
	var b [socketStatsLen]byte
	binary.LittleEndian.PutUint64(b[0:8], uint64(ktimeNs()))
	binary.LittleEndian.PutUint64(b[8:16], uint64(time.Now().UnixNano()))
	binary.LittleEndian.PutUint64(b[16:24], s.st.produced.Load())
	binary.LittleEndian.PutUint64(b[24:32], s.st.emitted.Load())
	binary.LittleEndian.PutUint64(b[32:40], s.st.droppedRing.Load())
	binary.LittleEndian.PutUint64(b[40:48], s.st.droppedNoSock.Load())
	binary.LittleEndian.PutUint64(b[48:56], s.st.truncFrames.Load())
	binary.LittleEndian.PutUint64(b[56:64], s.st.bytesWritten.Load())
	binary.LittleEndian.PutUint64(b[64:72], s.st.stringsDefined.Load())
	binary.LittleEndian.PutUint64(b[72:80], s.st.connectErrors.Load())
	s.scratch = append(s.scratch, b[:]...)
	s.armWriteDeadline()
	return s.writeBuffered(s.scratch)
}

// socketValueKind maps measurement kinds to their fixed wire codes.
func socketValueKind(k uint8) uint8 {
	switch k {
	case samples.ValueKindAlloc:
		return SocketValueKindAlloc
	case samples.ValueKindSchedNS:
		return SocketValueKindSchedNS
	case samples.ValueKindMsgs:
		return SocketValueKindMsgs
	default:
		return SocketValueKindNone
	}
}

// lref is one label resolved to string-table ids, assembled before the SAMPLE
// payload the way fref is.
type lref struct {
	key, val, unit uint32
	kind           uint8
	num            int64
}

func socketOrigin(o sampleOrigin) uint8 {
	if info, ok := originTable[o]; ok {
		return info.wire
	}
	return socketOriginUnknown
}
