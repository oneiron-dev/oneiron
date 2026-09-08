//! Guarded socket chokepoint with revocation consults on queue and flush.

use std::sync::Arc;
use std::task::Poll;

use axum::extract::ws::Message as WsMessage;
use futures_util::{SinkExt, Stream, StreamExt};
use tokio::time::Duration;

use super::connection::session_credential_revoked;
use crate::auth::RevokedTokenJtis;

/// Out-buffer size an outbound frame must exceed before the WebSocket codec
/// writes it straight to the socket, in bytes.
///
/// This is the setting that makes `start_send` a pure queue rather than a
/// write. tungstenite's `FrameCodec::buffer_frame` appends the frame to its
/// out-buffer and then, if the buffer is over this threshold, calls
/// `write_out_buffer` — a synchronous write to the socket, INSIDE
/// `start_send`, before any flush poll runs. At the 128-KiB library default a
/// single window export clears it easily, so a revocation landing after the
/// pre-handover consult would find the bytes already gone: the guard would be
/// checking a frame that had left the process.
///
/// Set beyond any frame this server will ever hand over, so the threshold is
/// out of reach and [`GuardedTransport::send_binary`]'s explicit flush is the
/// only path to the wire. It does not raise memory use: a send queues exactly
/// one frame and flushes it before returning, so the out-buffer never
/// accumulates, and the hard ceiling below is unchanged from the library
/// default.
///
/// The value alone is NOT the invariant, and nothing in the socket config
/// enforces it. `max_frame_size` bounds INBOUND reads only — tungstenite
/// applies it in `read_message_frame` and nowhere else — so outbound root,
/// window and direct frames are uncapped by it, and lowering this constant
/// would silently re-open the write-through window while every assertion
/// phrased against `max_frame_size` stayed green. What actually holds the line
/// is [`GuardedTransport::fits_below_write_through`]: a per-frame refusal that
/// runs in release builds and measures the frame the way the codec does.
pub(super) const WS_WRITE_BUFFER_SIZE: usize = usize::MAX - 1;

/// Hard ceiling on the out-buffer — the library default, restated because
/// tungstenite asserts it is strictly above [`WS_WRITE_BUFFER_SIZE`] and would
/// otherwise panic at socket construction.
pub(super) const WS_MAX_WRITE_BUFFER_SIZE: usize = usize::MAX;

/// The threshold relationships, pinned where a release build cannot drop them.
///
/// A `debug_assert` stated this before and was elided in exactly the builds
/// that matter — and stated it against `max_frame_size`, which governs the
/// inbound direction. These are compile-time and cannot be elided.
const _: () = assert!(
    WS_MAX_WRITE_BUFFER_SIZE > WS_WRITE_BUFFER_SIZE,
    "tungstenite panics at socket construction unless the hard ceiling is strictly above \
     the write-through threshold"
);

const _: () = assert!(
    WS_WRITE_BUFFER_SIZE == usize::MAX - 1,
    "the threshold must stay UNREACHABLE, not merely large. Outbound frame size is not \
     bounded by config — `max_frame_size` governs inbound reads, and a root snapshot or \
     window export is as big as the vault makes it — so any finite ceiling here is a size \
     at which live sessions start being refused. The per-frame refusal is a fail-closed \
     backstop for a socket built with a lower threshold, NOT a service limit to tune: \
     lowering this constant trades a security hole for an outage, and neither is on offer"
);

/// Longest a queued outbound frame may wait without a revocation re-consult.
///
/// The flush re-consults whenever the sink parks, but a peer that simply
/// stops reading produces no further wakeups at all — without a tick, one
/// park would be the last check before an unbounded wait. This bounds the
/// window between `token revoke` and the refusal of an already-queued frame;
/// it does NOT bound cost per byte, since a flush that makes progress
/// completes without ever reaching the tick.
pub(super) const FLUSH_RECONSULT_INTERVAL: Duration = Duration::from_millis(250);

/// Bytes an outbound binary frame occupies in the codec's out-buffer.
///
/// Mirrors tungstenite's `FrameHeader::len` plus payload: two status bytes,
/// the extended length field that the payload size selects, and no mask, since
/// a server never masks what it sends. Saturating rather than wrapping — an
/// overflowing length can only push the result further above the threshold,
/// which refuses.
pub(super) const fn encoded_frame_len(payload_len: usize) -> usize {
    let header_len = if payload_len < 126 {
        2
    } else if payload_len <= u16::MAX as usize {
        4
    } else {
        10
    };
    payload_len.saturating_add(header_len)
}

/// One step of draining the sink, distinguishing "made progress" from "the
/// peer stopped reading" — the latter is where a revocation lands.
enum FlushStep {
    /// Everything queued reached the transport.
    Flushed,
    /// The flush parked on a full peer socket and has since been woken, so
    /// the caller gets control back before the sink retries.
    Parked,
    /// The sink is gone.
    Broken,
}

/// Drains the sink, yielding control back at every backpressure edge.
///
/// A plain `poll_flush(...).await` resolves only when the bytes are gone,
/// which is exactly the outcome that must stay revocable: the future would
/// own the whole wait and no consult could run inside it. This resolves to
/// [`FlushStep::Parked`] the moment the sink wakes from a park instead, so
/// the caller re-consults before the sink is polled again. Re-polling a
/// parked `poll_flush` resumes it — sink flushes are idempotent, and no
/// queued frame is lost by handing control back between attempts.
async fn flush_step<S>(sink: &mut S) -> FlushStep
where
    S: SinkExt<WsMessage> + Unpin,
{
    let mut parked = false;
    std::future::poll_fn(|cx| {
        if std::mem::replace(&mut parked, false) {
            return Poll::Ready(FlushStep::Parked);
        }
        match sink.poll_flush_unpin(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(FlushStep::Flushed),
            Poll::Ready(Err(_)) => Poll::Ready(FlushStep::Broken),
            Poll::Pending => {
                parked = true;
                Poll::Pending
            }
        }
    })
    .await
}

/// The one place this server reads from or writes to a client socket.
///
/// Every outbound frame on a connection goes through [`Self::send_binary`] —
/// the Phase-1 root snapshot, the late-join ephemeral snapshot, direct
/// answers to inbound requests, and unsolicited broadcast fan-out — and each
/// one re-consults the revocation registry across BOTH waits a frame sits in
/// on its way out: the capacity wait before the handover, and the flush wait
/// after it.
///
/// A chokepoint rather than a gate per send arm, because per-arm reasoning
/// has been wrong twice. "The hello runs before dispatch" left the snapshot
/// sends uncovered; "direct sends only answer already-gated inbound
/// messages" ignored that a response sits queued in the direct channel and
/// drains AFTER the revocation that should have stopped it. One site cannot
/// drift from itself, and a future send arm inherits the consult by
/// construction instead of having to remember to classify itself.
///
/// # Why this owns the READ half too
///
/// A chokepoint on the write half alone is not a chokepoint on the socket.
/// Splitting the WebSocket hands the two halves to two tasks that share one
/// transport, and the read half writes: on receiving a Ping (or a Close),
/// tungstenite QUEUES the automatic response and its `read` flushes the
/// out-buffer before returning — `write_out_buffer` drains everything sitting
/// there, application frames included. So a peer that pings and keeps reading
/// pulls a guarded frame out through the read half, having never touched the
/// write half at all. No consult can catch this: the flush happens *inside*
/// the read poll, after any flag the poller could have checked.
///
/// The fix is structural rather than another gate. One task owns the UNSPLIT
/// socket, so `&mut self` is the whole transport: [`Self::send_binary`] holds
/// that unique borrow for the entire time an application frame is pending, and
/// the compiler will not let a read be polled inside that window. There is no
/// ordering to get wrong and no flag to check — the read future does not exist
/// while bytes are pending. Refusal then drops the whole socket, not one half
/// of it, so nothing on either side can still drain it.
///
/// The registry — not the whole server — is held here because the registry is
/// the only thing this type consults, which also lets the fail-closed
/// unreadable path be driven directly in tests.
pub(super) struct GuardedTransport<S> {
    /// `None` once the transport has been aborted.
    ///
    /// A revocation seen while a frame is already queued cannot be answered
    /// with a graceful close: `poll_close` flushes the queue on its way out,
    /// which IS the delivery being refused. Dropping the socket is the only
    /// refusal that withholds bytes it is already holding, so the abort path
    /// takes the socket here and never touches it again — and because this is
    /// the unsplit socket, that one `take` ends the read side as well.
    pub(super) socket: Option<S>,
    revoked: Arc<dyn RevokedTokenJtis + Send + Sync>,
    session_jti: Option<String>,
    /// Set only while an app-tier frame is draining; sync keeps its owner guard.
    pub(super) app_jti: Option<String>,
    conn_id: u32,
    /// The socket's own `write_buffer_size`, mirrored so the refusal below can
    /// be stated against it.
    ///
    /// Carried rather than read from [`WS_WRITE_BUFFER_SIZE`] at the use site
    /// so a test can lower BOTH this and the codec's configured threshold to
    /// one value and drive the real write-through — a refusal that can only be
    /// exercised at `usize::MAX` is a refusal no test can prove.
    write_through_threshold: usize,
}

impl<S, E> GuardedTransport<S>
where
    S: SinkExt<WsMessage> + Stream<Item = Result<WsMessage, E>> + Unpin,
{
    pub(super) fn new(
        socket: S,
        revoked: Arc<dyn RevokedTokenJtis + Send + Sync>,
        session_jti: Option<String>,
        conn_id: u32,
    ) -> Self {
        Self::with_write_through_threshold(
            socket,
            revoked,
            session_jti,
            conn_id,
            WS_WRITE_BUFFER_SIZE,
        )
    }

    /// The constructor that names the threshold, for a socket built with a
    /// `write_buffer_size` other than [`WS_WRITE_BUFFER_SIZE`].
    ///
    /// The two must be the SAME number: this is the guard's model of the
    /// codec's write-through point, and a guard modelling a different socket
    /// than the one it holds guarantees nothing.
    pub(super) fn with_write_through_threshold(
        socket: S,
        revoked: Arc<dyn RevokedTokenJtis + Send + Sync>,
        session_jti: Option<String>,
        conn_id: u32,
        write_through_threshold: usize,
    ) -> Self {
        Self {
            socket: Some(socket),
            revoked,
            session_jti,
            app_jti: None,
            conn_id,
            write_through_threshold,
        }
    }

    fn credential_revoked(&self) -> bool {
        session_credential_revoked(self.revoked.as_ref(), self.session_jti.as_deref())
            || session_credential_revoked(self.revoked.as_ref(), self.app_jti.as_deref())
    }

    /// Reads the next inbound frame.
    ///
    /// Taking `&mut self` is the enforcement, not a convention: an application
    /// frame is pending only inside [`Self::send_binary`], which holds the same
    /// unique borrow, so this cannot run then. That is what keeps tungstenite's
    /// automatic pong/close flush from draining guarded bytes — see the type
    /// docs. `None` once the transport has been aborted.
    pub(super) async fn read_next(&mut self) -> Option<Result<WsMessage, E>> {
        self.socket.as_mut()?.next().await
    }

    /// Whether this payload can be queued without risking a write-through.
    ///
    /// tungstenite's `buffer_frame` appends the encoded frame to its out-buffer
    /// and writes the whole thing through when `out_buffer.len() >
    /// write_buffer_size`. The test is therefore
    /// `existing_out_buffer + encoded_frame > write_buffer_size`, over the
    /// ENCODED size — header included — not the payload length.
    ///
    /// `existing_out_buffer` is not observable from outside the codec, and it
    /// is NOT bounded by anything the RFC says: each blocked read appends one
    /// more 127-byte pong to that buffer, so it grows with the number of Pings
    /// a peer sends, not with the control-frame size limit. A fixed reserve was
    /// therefore a guess, and a peer choosing how many Pings to send chose
    /// whether the guess held. [`Self::send_binary`] instead drains the buffer
    /// to EMPTY before calling this, so `existing_out_buffer` is 0 and the
    /// comparison below is exact rather than approximate.
    ///
    /// This is the invariant [`WS_WRITE_BUFFER_SIZE`] used to assert about
    /// itself. Lowering that constant now refuses frames rather than writing
    /// them pre-consult, which is what "fail-closed" means here: the threshold
    /// is a bound on what may be QUEUED, and it holds in release builds.
    const fn fits_below_write_through(&self, payload_len: usize) -> bool {
        // Saturating: an encoded length that overflows is far above the
        // threshold, and saturating at `usize::MAX` refuses just the same.
        encoded_frame_len(payload_len) <= self.write_through_threshold
    }

    /// Sends one binary frame, refusing if the credential is no longer live.
    ///
    /// Returns whether the connection may continue. `false` means either the
    /// credential was revoked (or its registry unreadable) — in which case
    /// the transport has already been ended and the frame was NOT delivered —
    /// or the peer's sink is gone. Both outcomes end the connection, so
    /// callers do not distinguish them.
    ///
    /// The send is spelled out rather than `SinkExt::send` because a frame
    /// crosses TWO unbounded waits on its way out, and a revocation can land
    /// in either:
    ///
    /// 1. the capacity wait (`poll_ready`), before the frame is handed to the
    ///    sink at all; and
    /// 2. the flush wait (`poll_flush`), after the sink has taken the frame
    ///    into its queue but before the bytes reach the socket. This is where
    ///    the peer's backpressure surfaces, so it is where the long park
    ///    actually happens.
    ///
    /// So the consult runs after the capacity wait, again BEFORE the first
    /// flush poll, and again before every subsequent one — at each park, or
    /// when a [`FLUSH_RECONSULT_INTERVAL`] tick elapses, since a peer that
    /// simply stops reading never wakes the sink at all. The pre-first-poll
    /// consult is not redundant with the capacity-wait one: `start_send` sits
    /// between them, and a flush that is immediately ready would otherwise put
    /// the frame on the wire with no flush-time check at all. Cadence is
    /// bounded by those events, never by bytes written.
    ///
    /// # Why `start_send` must be kept from writing
    ///
    /// Those consults only bound anything because `start_send` QUEUES. It does
    /// not do so on its own: tungstenite writes from inside `start_send` in two
    /// cases, and both are shut off rather than reasoned around, because a
    /// write there lands between the pre-handover consult and the first flush
    /// poll — no gate covers it.
    ///
    /// - Buffer exceeded: `buffer_frame` writes the out-buffer through once it
    ///   passes `write_buffer_size`, whose 128-KiB default a window export
    ///   clears easily. [`WS_WRITE_BUFFER_SIZE`] raises the threshold, and
    ///   [`Self::fits_below_write_through`] REFUSES any frame that would still
    ///   reach it — the threshold is never crossed because a frame that could
    ///   cross it is never handed over.
    /// - Queued automatic pong: a pong owed for a peer Ping makes `_write`
    ///   report "should flush", and `start_send` flushes the application frame
    ///   out with it. It also leaves bytes in the out-buffer that count toward
    ///   the threshold above. The pre-drain below empties control frames to
    ///   COMPLETION while nothing application-level is pending, which removes
    ///   the trigger and makes the residue zero — so the threshold test is over
    ///   the encoded frame alone, with no unobservable term to guess at.
    ///
    /// The residual gap after this is precisely one sliver: bytes the OS has
    /// already accepted into its TCP send buffer. Those are gone from this
    /// process — no userspace gate can recall them, and the kernel delivers
    /// them whenever the peer reads. That sliver cannot leak sync data: a
    /// frame reaches the OS only via the explicit flush below, which the
    /// consult precedes, so what the kernel can hold from a REFUSED frame is
    /// at most a partial frame from a write that parked mid-way. A partial
    /// WebSocket frame is not sync data — the peer's codec buffers the
    /// fragment, never delivers it as a message, and the dropped transport
    /// means the remainder never arrives. Everything still held in this
    /// process, the sink's own queue included, is revocable.
    #[must_use]
    pub(super) async fn send_binary(&mut self, data: Vec<u8>) -> bool {
        // Before anything is handed to the codec: a frame that could reach the
        // write-through threshold is refused outright, because queuing it would
        // put its bytes on the wire from inside `start_send` — between the
        // consult below and the guarded flush, where no gate can reach them.
        // Aborting rather than skipping the send: a connection that cannot
        // deliver its next frame under the guard has nothing left to offer, and
        // silently dropping one export would be a correctness bug wearing a
        // security fix's clothes.
        if !self.fits_below_write_through(data.len()) {
            tracing::error!(
                conn_id = self.conn_id,
                frame_bytes = data.len(),
                "outbound frame would reach the write-through threshold — aborting transport \
                 rather than queuing bytes the revocation guard could not withhold"
            );
            self.abort();
            return false;
        }
        let Some(socket) = self.socket.as_mut() else {
            return false;
        };
        if std::future::poll_fn(|cx| socket.poll_ready_unpin(cx))
            .await
            .is_err()
        {
            tracing::debug!(conn_id = self.conn_id, "outbound sink closed");
            return false;
        }
        if self.credential_revoked() {
            tracing::warn!(
                conn_id = self.conn_id,
                "credential revoked — closing live session instead of sending"
            );
            // Nothing is queued at this point, so the graceful close flushes
            // no application bytes; the peer gets a close frame and no data.
            self.close().await;
            return false;
        }
        // Drain owed CONTROL frames to COMPLETION before handing over
        // application bytes, so the codec's out-buffer is empty when
        // `start_send` runs.
        //
        // A pong the codec owes for a peer Ping makes the next `start_send`
        // flush eagerly — tungstenite's `_write` emits the automatic frame and
        // reports "should flush", and `Sink::start_send` obeys — carrying the
        // application frame out with it, inside `start_send`, before any
        // consult. An owed pong also SITS in the out-buffer, and the codec's
        // write-through test adds that residue to the frame being queued.
        //
        // Draining to empty answers both, and it is why no reserve term is
        // needed: `existing_out_buffer` is 0 by construction rather than
        // bounded by a guess. A single non-parking poll could not make that
        // claim — while writes are blocked, each read appends another 127-byte
        // pong, so the residue grows with the number of Pings the PEER chooses
        // to send and passes any fixed reserve.
        //
        // Nothing application-level is queued yet, so this can only emit
        // control frames: no vault state crosses here. It carries the same
        // guard as [`Self::guarded_flush`] anyway — re-consulting at every park
        // and on the tick — because it is now an unbounded wait, and a peer
        // that stops reading must not be able to park a send past a revocation.
        // A silent peer parks here exactly as it would park the flush below:
        // the wait moved earlier, it did not become a refusal.
        if !self.guarded_drain("draining owed control frames").await {
            return false;
        }
        // A FRESH consult: the drain above is an unbounded wait, so the consult
        // that preceded it may be arbitrarily stale by now.
        if self.credential_revoked() {
            tracing::warn!(
                conn_id = self.conn_id,
                "credential revoked while control frames drained — closing live session \
                 instead of sending"
            );
            // The drain left the out-buffer empty, so the graceful close
            // flushes no application bytes.
            self.close().await;
            return false;
        }
        let Some(socket) = self.socket.as_mut() else {
            return false;
        };
        // No `await` stands between the drain completing and this `start_send`,
        // so nothing can have refilled the out-buffer: only a read queues a
        // pong, and a read needs the same `&mut self` this frame is holding.
        // The out-buffer is therefore PROVABLY empty here, which is what makes
        // the threshold comparison above exact.
        if socket
            .start_send_unpin(WsMessage::Binary(data.into()))
            .is_err()
        {
            tracing::debug!(conn_id = self.conn_id, "outbound sink closed");
            return false;
        }
        // From the `start_send` above to the return below, an application frame
        // is pending and this unique borrow is held: no read can be polled in
        // that window, so tungstenite's automatic pong/close flush cannot drain
        // it. That is the whole of the read-half defence.
        self.guarded_flush().await
    }

    /// Drains the codec's out-buffer BEFORE an application frame is queued.
    ///
    /// Same posture as [`Self::guarded_flush`] and the same loop, but it runs
    /// while only control frames are pending. That distinction is in the log
    /// line and nowhere else: both are unbounded waits on the same sink, and
    /// both must abort rather than park past a revocation.
    async fn guarded_drain(&mut self, what: &'static str) -> bool {
        self.guarded_flush_loop(what).await
    }

    /// Drains the queued frame, re-consulting the registry at every park.
    ///
    /// The loop exists because the alternative — awaiting `poll_flush` to
    /// completion — hands the whole backpressure wait to a future with no
    /// gate inside it. Revocation is recorded in the vault-resident registry
    /// and can be performed by another process entirely (the operator CLI),
    /// so it cannot arrive as an in-process wakeup: observing it means
    /// re-reading the registry, which means getting control back.
    async fn guarded_flush(&mut self) -> bool {
        self.guarded_flush_loop("a frame awaited flush").await
    }

    /// The guarded wait both drains share.
    ///
    /// One loop rather than two: the pre-handover drain and the post-handover
    /// flush park on the same sink under the same rules, and two copies of a
    /// security wait drift.
    async fn guarded_flush_loop(&mut self, what: &'static str) -> bool {
        loop {
            // BEFORE the poll, not only after it. `start_send` is a synchronous
            // queue-and-return, so a revocation landing between the pre-handover
            // consult and this point has had no gate at all — and if the first
            // `poll_flush` is immediately ready (a peer that IS reading, the
            // common case), the frame is on the wire before any flush-time
            // consult ever runs. Checking only at a park makes the guard depend
            // on the peer being slow, which is exactly backwards: the fast peer
            // is the one that gets the frame.
            if self.credential_revoked() {
                tracing::warn!(
                    conn_id = self.conn_id,
                    stage = what,
                    "credential revoked mid-wait — aborting transport"
                );
                self.abort();
                return false;
            }
            let Some(socket) = self.socket.as_mut() else {
                return false;
            };
            let step = tokio::select! {
                biased;
                step = flush_step(socket) => step,
                // A peer that stops reading never wakes the sink, so the park
                // alone cannot be the only re-consult trigger.
                () = tokio::time::sleep(FLUSH_RECONSULT_INTERVAL) => FlushStep::Parked,
            };
            match step {
                FlushStep::Flushed => return true,
                FlushStep::Broken => {
                    tracing::debug!(conn_id = self.conn_id, "outbound sink closed");
                    return false;
                }
                // Back to the loop head, which re-consults before re-polling.
                FlushStep::Parked => {}
            }
        }
    }

    /// Ends the transport WITHOUT flushing what it still holds.
    ///
    /// A graceful `close` is wrong here: `poll_close` drains the queue on its
    /// way out, which would deliver the very frame the revocation refuses.
    /// Dropping the socket is the only refusal that withholds bytes already
    /// handed to it, at the cost of an unclean WebSocket teardown — the right
    /// trade when the alternative is serving a dead credential.
    ///
    /// Because this is the UNSPLIT socket, the drop takes the read half down
    /// with it. A split transport could only drop the sink, leaving a stream
    /// half alive over the same connection with the pending bytes still in the
    /// shared out-buffer for its next automatic flush to deliver.
    fn abort(&mut self) {
        drop(self.socket.take());
    }

    pub(super) async fn close(&mut self) {
        if let Some(socket) = self.socket.as_mut() {
            let _ = socket.close().await;
        }
    }

    /// Sends one non-binary control frame, bypassing the revocation consult.
    ///
    /// The single documented exception to the chokepoint: the hello-rejection
    /// close frame carries no vault state and IS the refusal, so gating it on
    /// the credential's liveness could only turn one refusal into another.
    pub(super) async fn send_unguarded_close_frame(&mut self, close: WsMessage) {
        if let Some(socket) = self.socket.as_mut() {
            let _ = socket.send(close).await;
        }
    }
}
