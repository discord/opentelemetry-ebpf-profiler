// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

// Discord addition: one of the local egress's two independent backends
// (local_egress.go). It streams the SAME assembled samples the pprof backend
// would buffer over a unix socket, so a consumer can bucket them at
// sub-iteration resolution. It runs with the pprof backend, without it, or
// alongside it: nothing here reaches into the other sink.
//
// Why it is not its own Reporter with its own decode: the local egress's
// assembler has already resolved everything that matters (frames flattened out
// of the interned tables, lineage read while the process still exists,
// comm/container/pid/tid/ktime) into ONE sampleEvent, and this sink emits from
// that exact value. That is what makes the socket path and the pprof path
// structurally identical rather than merely intended to agree: there is no
// second decode to drift.
//
// Three properties are load-bearing and are the reason this is not simply
// "write the struct to a socket":
//
//   - NEVER BLOCK THE AGENT. A slow or absent consumer must cost samples, not
//     latency, because the alternative is the profiler stalling the box it is
//     measuring. offer() is a non-blocking channel send; everything past the
//     channel runs on one writer goroutine.
//   - A SILENTLY LOSSY PROFILER IS WORSE THAN A DEAD ONE. Every drop is
//     counted, the count rides on the wire next to the gap it describes
//     (SAMPLE.dropped_since_prev), and the absolute totals are re-stated
//     periodically (STATS). When the pprof backend is ALSO enabled the totals
//     are additionally written into that archive's comments, so the two
//     artifacts cross-attest; in a socket-only run the wire and the loss
//     warning are the whole story, because there is no archive to attest to.
//   - SELF-DESCRIBING. The stream announces its version, its framing width,
//     its frame ordering and its frame cap up front, every record is
//     length-prefixed so an unknown type is skippable, and both kinds of
//     truncation (samples dropped, frame list capped) have an explicit field.
//
// The full wire format is specified in doc/discord-fork.md, section "Socket
// egress wire format". The constants below are the normative definition; keep
// the two in step.

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf"
)

// Wire format constants. These are a contract with pstore-ingest; changing one
// without bumping SocketVersion is a silent corruption, not a bug fix.
const (
	// SocketMagic opens every connection. 8 bytes, ASCII, no terminator.
	SocketMagic = "PSTRSOK1"
	// SocketVersion is the stream version in the header.
	SocketVersion uint16 = 1
	// SocketHeaderLen is the byte length of the stream header. A reader
	// consumes exactly this many bytes (read from the header itself), so a
	// later version can grow the header without breaking the framing.
	SocketHeaderLen uint16 = 32
)

// Stream flags, in the header's flags word.
const (
	// StreamFlagFramesLeafFirst is set when each SAMPLE's frame array is
	// ordered leaf-first, as the tracer delivers it and as the pprof writer
	// orders Location. A consumer building a root-first folded key reverses.
	// It is always set in version 1; it exists so that a producer that ever
	// flips the order is DETECTED rather than silently mis-folded.
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
	socketSampleFixedLen = 64
	socketFrameLen       = 12
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

	// A consumer that connects and then stops reading WITHOUT closing fills
	// the socket buffers, and an unbounded write then blocks the writer
	// goroutine forever: it never reaches its stop channel, so shutdown never
	// completes and the agent has to be SIGKILLed. Every write is therefore
	// deadlined, by SocketConfig.WriteTimeout, clamped here so neither a
	// microsecond setting nor an hour-long one produces a nonsense deadline.
	// Exceeding it is not special: it takes the same connFailed path as any
	// other write error, because a consumer that cannot keep up is exactly a
	// consumer that is gone.
	//
	// The deadline used to be derived from FlushInterval (20x, same clamp).
	// That derivation died with per-sample flushing: a record no longer waits
	// for a flush period, so "several flush periods" stopped describing
	// anything. The bound is a property of the CONSUMER (how long a healthy one
	// may take to accept one record), so it gets its own knob.
	socketWriteDeadlineMin = 250 * time.Millisecond
	socketWriteDeadlineMax = 5 * time.Second

	// socketShutdownSlack is how much longer than ONE write deadline shutdown()
	// waits before abandoning the writer. The shutdown budget is DERIVED from
	// the write deadline (see socketSink.shutdownTimeout) rather than being an
	// independent constant, because the two are not independent: the deadline
	// is what unwedges a stuck writer, and the backstop is only a backstop if
	// it fires after the deadline has had its chance. A fixed 2s backstop under
	// a configurable deadline whose max is 5s meant a -socket-egress-write-
	// timeout of 3s inverted them: every wedged-consumer shutdown hit the
	// backstop first, so the final STATS record was never written and the loss
	// was reported through the explicitly-approximate residual path instead of
	// exactly. Deriving makes "deadline first, backstop second" structural
	// instead of a coincidence of two numbers.
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
	// FlushInterval is a SAFETY NET, not the latency floor. Every sample is
	// flushed as it is written (see run), so in normal operation the ticker it
	// drives finds an empty buffer and does nothing. It is kept because
	// "nothing may sit in the write buffer indefinitely" is a property worth
	// holding unconditionally: a future record type that forgets its flush
	// would otherwise strand bytes until the next sample, and a stream with a
	// low sample rate can make that a long time. The flag it backs also stays
	// valid for anyone who already passes it.
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

// socketStats is the counter set, mirrored onto the wire by RecStats.
//
// produced == emitted + droppedRing + droppedNoSock + droppedWrite holds at any
// quiescent point, and a consumer is expected to assert it. droppedWrite has no
// slot in the v1 STATS payload and adding one would be a wire change, so a
// consumer recovers it as the residual:
//
//	droppedWrite = produced - emitted - droppedRing - droppedNoSock
//
// which is exactly the gap the pre-fix code left unexplained. It is included in
// Dropped(), so the in-process guards (SocketDropped(), the fixture's
// require.Zero, and -- only when the pprof backend is also enabled -- the pprof
// file's comment) see it even though the wire cannot name it.
//
// The counters are read one at a time, not under a fence: the STATS record
// written just before a clean close is a snapshot, not a barrier against a
// concurrent offer(), so a sample offered during shutdown can be in produced
// and in nothing else. A consumer treats the identity above as exact only for a
// quiesced producer, and the residual as an upper bound otherwise.
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
	lastSeenDrops uint64
	// lastLoggedDrops is the drop total the last warning stated. Warning on
	// the cumulative total instead of on its growth makes one lost sample
	// produce a warning every stats interval for the life of the process,
	// which trains the reader to ignore the one line that matters.
	lastLoggedDrops uint64
	// pendingSamples is the number of SAMPLE records written into bw but not
	// yet flushed. They are not emitted yet -- a record in the write buffer has
	// not reached the consumer -- and they are lost if the connection dies
	// first. Writer goroutine only.
	//
	// run() flushes after every sample, so on that path this is only ever 0 or
	// 1. It stays a COUNT rather than a flag because writeSample does not
	// require a flush after it: drainAndClose writes the whole ring and then
	// flushes once, and a caller can too. The exactness of `emitted` must not
	// depend on who calls flush() how often.
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

	stopOnce sync.Once
	stop     chan struct{}
	done     chan struct{}
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

// offer hands one sample to the sink. It never blocks and never errors: a full
// ring means a slow consumer, and the only correct response is to drop the
// sample and say so.
//
// ev must not be mutated after this call. When the pprof backend is also
// enabled it is the SAME value that backend buffers -- both paths seeing
// byte-identical input is the whole point -- and neither side writes to it.
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

// dropSummaryIfLossy renders the loss summary, or "" when this run lost
// nothing. It is what the pprof backend's cross-attestation hook calls, so the
// archive carries the stream's loss when there is some to carry and stays quiet
// otherwise -- without either sink knowing the other's type.
// A nil receiver is "no socket backend, so no loss to report": the pprof sink
// holds this as a bare func value and calls it from build(), where a nil check
// on the func cannot see that its receiver is nil. Guarding here means the
// construction-time "only wire crossAttest when both backends exist" rule is a
// policy rather than the only thing standing between build() and a panic.
func (s *socketSink) dropSummaryIfLossy() string {
	if s == nil || s.Dropped() == 0 {
		return ""
	}
	return s.dropSummary()
}

func (s *socketSink) start() {
	go s.run()
}

func (s *socketSink) shutdown() {
	budget := s.shutdownTimeout()
	s.stopOnce.Do(func() { close(s.stop) })
	select {
	case <-s.done:
	case <-time.After(budget):
		// The writer is wedged somewhere the write deadline did not reach.
		// Abandoning it costs a goroutine and the final STATS record; waiting
		// costs the whole process, which is the profiler refusing to die on
		// SIGINT. Say so rather than exiting quietly.
		//
		// Abandoning it also abandons everything it held: up to RingSize
		// samples still in s.ring and up to socketWriteBufBytes worth in the
		// write buffer, all charged to produced and to nothing else. Left
		// there, Dropped() reports 0 for a run that lost tens of thousands of
		// samples -- and Dropped() is what the equivalence fixture's
		// require.Zero trusts when it certifies a capture as comparable. So
		// charge the whole unaccounted residual to write loss.
		residual := s.residualUnaccounted()
		s.st.droppedWrite.Add(residual)
		log.Warnf("socket egress: writer did not finish within %s; abandoning it "+
			"(final STATS record not written); charged %d unaccounted samples to "+
			"write loss: %s", budget, residual, s.dropSummary())
	}
}

// shutdownTimeout is how long shutdown() waits for the writer goroutine. It is
// one write deadline plus socketShutdownSlack, so it is strictly greater than
// writeDeadline() for every configured WriteTimeout: a wedged write is given
// its full deadline (which tears the connection down, writes the final STATS
// and accounts the loss exactly) before this backstop abandons the writer and
// falls back to the approximate residual. Pinned by
// TestSocketShutdownBudgetAlwaysExceedsWriteDeadline.
func (s *socketSink) shutdownTimeout() time.Duration {
	return s.writeDeadline() + socketShutdownSlack
}

// residualUnaccounted is the number of samples produced that no other counter
// explains. It is APPROXIMATE by construction: the abandoned writer goroutine
// may still be mutating these counters while they are read one at a time, so
// the residual can be off by however many samples that goroutine moves between
// the loads. Approximate is fine; zero is not, because zero is indistinguishable
// from a lossless run.
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

// flush pushes the write buffer at the socket and promotes what it carried from
// "written" to "emitted". Counting a sample as emitted when it was handed to
// the buffer instead is what let a consumer restart silently discard up to a
// megabyte of samples that STATS had already claimed were delivered.
//
// pendingSamples is exact rather than an estimate: every record goes out
// through writeBuffered, which flushes explicitly when the record would not
// fit, so bufio never auto-flushes behind this counter's back. Were it allowed
// to, records that DID reach the consumer would be charged to droppedWrite and
// never counted as emitted. run() now flushes per sample, so the buffer rarely
// fills there -- but writeSample is still callable without a flush after it
// (drainAndClose does exactly that with the whole ring), so the exactness
// cannot rest on the flush cadence.
func (s *socketSink) flush() error {
	if s.bw == nil {
		return nil
	}
	// Nothing buffered and nothing pending: no write, and no deadline syscall
	// either. That is the normal state of the safety-net ticker now that every
	// sample is flushed as it is written. Both conditions are checked because a
	// record too large for an EMPTY buffer would bypass bufio (Buffered() == 0
	// while pendingSamples counts it); the static assertion below rules that
	// out for SAMPLE records, and this keeps the promotion correct regardless.
	if s.bw.Buffered() == 0 && s.pendingSamples == 0 {
		return nil
	}
	s.armWriteDeadline()
	if err := s.bw.Flush(); err != nil {
		return err
	}
	if s.pendingSamples > 0 {
		s.st.emitted.Add(s.pendingSamples)
		s.pendingSamples = 0
	}
	return nil
}

// writeBuffered appends one serialized record to the write buffer, flushing
// first when it would not fit.
//
// The explicit flush is what keeps pendingSamples exact. bufio.Writer flushes
// on its own when an append does not fit, and that flush is invisible here:
// the bytes reach the consumer while pendingSamples still claims they are
// buffered, so a connection that then dies charges delivered samples to
// droppedWrite and never counts them as emitted. Flushing here instead means
// every promotion goes through flush().
func (s *socketSink) writeBuffered(rec []byte) error {
	if s.bw.Available() < len(rec) {
		if err := s.flush(); err != nil {
			return err
		}
	}
	_, err := s.bw.Write(rec)
	return err
}

// One SAMPLE record can never be larger than the write buffer, which is what
// makes the flush above sufficient: bufio bypasses its buffer entirely for a
// record that does not fit in an EMPTY buffer, and such a record would reach
// the wire immediately, leaving pendingSamples over-counting by one. A negative
// array length here is a compile error, so shrinking the buffer or widening
// n_frames past a u16 cannot silently reintroduce that case.
//
// Per-sample flushing did not retire this. The buffer still exists to batch one
// sample's STRDEF records and its SAMPLE record into ONE write syscall, and the
// bypass it rules out is exactly what would make flush()'s empty-buffer
// fast-path skip a promotion.
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
		// TODO(perf): this arm is a Go channel hand-off plus one write syscall
		// per sample. A shared-memory ring buffer between the sampling path and
		// the consumer would remove both -- no per-sample syscall, no Go
		// channel send -- and could raise sustainable throughput
		// substantially. Deliberately left alone for now: the channel is what
		// makes "the agent never blocks on a slow consumer" true and cheap to
		// reason about, and the wire format is frozen. Not designed, not
		// sketched, not started.
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
	for {
		select {
		case ev := <-s.ring:
			if s.conn == nil {
				s.st.droppedNoSock.Add(1)
				continue
			}
			if err := s.writeSample(ev); err != nil {
				s.sampleWriteFailed(err)
			}
		default:
			if s.conn != nil {
				// Same ordering as the stats tick, and it matters more here:
				// this is the record a consumer treats as authoritative for
				// the run, so the drained samples must be counted as emitted
				// before it is built.
				// Same error handling as the stats tick, too: a final STATS
				// that failed to write is a connection that died during
				// shutdown, and swallowing it hid both the warning and the
				// connectErrors increment a consumer uses to tell "the
				// producer stopped" from "my link broke".
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
	c, err := net.Dial("unix", s.cfg.Path)
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
	// The buffer dies with the connection, so every already-serialized sample
	// still in it is gone here. That is the loss the old accounting reported as
	// "emitted".
	s.discardPending()
	s.st.connectErrors.Add(1)
}

func (s *socketSink) writeHeader() error {
	var h [32]byte
	copy(h[0:8], SocketMagic)
	binary.LittleEndian.PutUint16(h[8:10], SocketVersion)
	binary.LittleEndian.PutUint16(h[10:12], SocketHeaderLen)
	binary.LittleEndian.PutUint32(h[12:16], StreamFlagFramesLeafFirst)
	binary.LittleEndian.PutUint32(h[16:20], uint32(s.cfg.SamplesPerSecond))
	binary.LittleEndian.PutUint32(h[20:24], uint32(s.cfg.MaxFrames))
	binary.LittleEndian.PutUint64(h[24:32], uint64(ktimeNs()))
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
	for i := 0; i < nFrames; i++ {
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

	// The drop delta is read at serialization time, so it attributes losses to
	// the gap they most plausibly belong to. The TOTAL is exact (STATS); the
	// per-record attribution is exact to within one writer iteration.
	cum := s.st.droppedRing.Load() + s.st.droppedNoSock.Load()
	delta := cum - s.lastSeenDrops
	s.lastSeenDrops = cum
	if delta > 0xffffffff {
		delta = 0xffffffff
	}

	payload := socketSampleFixedLen + nFrames*socketFrameLen
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
	binary.LittleEndian.PutUint32(fixed[60:64], 0)
	s.scratch = append(s.scratch, fixed[:]...)

	for i := 0; i < nFrames; i++ {
		s.scratch = binary.LittleEndian.AppendUint32(s.scratch, s.frefs[i].fn)
		s.scratch = binary.LittleEndian.AppendUint32(s.scratch, s.frefs[i].file)
		s.scratch = binary.LittleEndian.AppendUint32(s.scratch, uint32(ev.frames[i].line))
	}

	s.armWriteDeadline()
	if err := s.writeBuffered(s.scratch); err != nil {
		return err
	}
	// Not emitted yet: it is in the write buffer. flush() promotes it.
	s.pendingSamples++
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

// socketOrigin maps an origin to its wire byte. The mapping lives in
// originTable (local_egress.go) together with the origin's validity and
// its pprof label name, so a new origin cannot be added to two of the three and
// forgotten in the third.
func socketOrigin(o libpf.Origin) uint8 {
	if info, ok := originTable[o]; ok {
		return info.wire
	}
	return socketOriginUnknown
}
