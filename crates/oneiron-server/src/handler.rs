//! WebSocket upgrade handler and connection lifecycle.
//!
//! Each WebSocket connection follows the protocol from ARCH-023 §3.2:
//! 1. Phase 1: Root doc sync (send snapshot to new client)
//! 2. Phase 2: Default windows (current + previous) via VV exchange + updates
//! 3. Phase 3: Historical windows via BulkTransfer (oldest first) + BulkTransferDone
//! 4. Ongoing: bidirectional incremental sync via WindowSync + ephemeral state

use std::collections::HashSet;
use std::sync::Arc;
use std::task::Poll;
use std::time::{Instant as StdInstant, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::extract::State;
use axum::extract::ws::{CloseFrame, Message as WsMessage, Utf8Bytes, WebSocket, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use futures_util::{SinkExt, Stream, StreamExt};
use loro::{ExportMode, VersionVector};
use oneiron::sync::{
    AllowBlock, EphemeralStore, EphemeralWireState, FederationConnectionQuota,
    FederationQuotaConfig, SelectorVvRequest, WindowKey, authorize_sync_selector,
    decode_ephemeral_states, decode_selector_vv_request, filtered_window_doc,
};
use tokio::time::{Duration, Instant};

use crate::auth::{RevokedTokenJtis, is_revoked_or_unreadable, require_owner_auth};
use crate::broadcast::BroadcastSubscriber;
use crate::protocol::{self, ProtocolError, SyncMessage, close_codes, window_sub_tags};
use crate::server::SyncServer;

/// How long the server waits for the client's protocol-version hello.
const HELLO_TIMEOUT_SECS: u64 = 10;
/// Numeric grant-scope ABI for this single-vault selector server path.
/// Distinct from the lease ABI's internal vault id: federation grants reject
/// zero as a shared-vault scope, and FED-001 fixtures pin the nonzero scope.
const SERVER_SELECTOR_VAULT_ID: u64 = 7;
/// Clock skew tolerated for Loro `EphemeralStore` LWW timestamps from clients.
const MAX_EPHEMERAL_FUTURE_SKEW_MS: i64 = 60_000;
/// Hard cap on records decoded from one ephemeral frame, independent of bytes.
const MAX_EPHEMERAL_RECORDS_PER_FRAME: usize = 1024;
/// Flat ephemeral keys are control-plane identifiers, not arbitrary blobs.
const MAX_EPHEMERAL_KEY_BYTES: usize = 256;
/// Longest a queued outbound frame may wait without a revocation re-consult.
///
/// The flush re-consults whenever the sink parks, but a peer that simply
/// stops reading produces no further wakeups at all — without a tick, one
/// park would be the last check before an unbounded wait. This bounds the
/// window between `token revoke` and the refusal of an already-queued frame;
/// it does NOT bound cost per byte, since a flush that makes progress
/// completes without ever reaching the tick.
const FLUSH_RECONSULT_INTERVAL: Duration = Duration::from_millis(250);

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
const WS_WRITE_BUFFER_SIZE: usize = usize::MAX - 1;
/// Hard ceiling on the out-buffer — the library default, restated because
/// tungstenite asserts it is strictly above [`WS_WRITE_BUFFER_SIZE`] and would
/// otherwise panic at socket construction.
const WS_MAX_WRITE_BUFFER_SIZE: usize = usize::MAX;

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

/// Bytes an outbound binary frame occupies in the codec's out-buffer.
///
/// Mirrors tungstenite's `FrameHeader::len` plus payload: two status bytes,
/// the extended length field that the payload size selects, and no mask, since
/// a server never masks what it sends. Saturating rather than wrapping — an
/// overflowing length can only push the result further above the threshold,
/// which refuses.
const fn encoded_frame_len(payload_len: usize) -> usize {
    let header_len = if payload_len < 126 {
        2
    } else if payload_len <= u16::MAX as usize {
        4
    } else {
        10
    };
    payload_len.saturating_add(header_len)
}

/// Per-connection mutable state. This is intentionally local to one socket:
/// Phase-1 auth has only a shared secret, so user-scoped limits are not sound.
struct ConnState {
    windows_touched: HashSet<WindowKey>,
    federation_quota: FederationConnectionQuota,
    rate_limiter: MessageRateLimiter,
    window_sync_mode: WindowSyncMode,
    protocol_version: u8,
}

impl ConnState {
    fn new(
        max_messages_per_sec: u32,
        protocol_version: u8,
        federation_quota: FederationQuotaConfig,
    ) -> Self {
        Self {
            windows_touched: HashSet::new(),
            federation_quota: FederationConnectionQuota::new(federation_quota),
            rate_limiter: MessageRateLimiter::new(max_messages_per_sec),
            window_sync_mode: WindowSyncMode::Unbound,
            protocol_version,
        }
    }

    fn record_inbound_message(&mut self) -> bool {
        self.rate_limiter.allow(Instant::now())
    }

    fn touch_window(
        &mut self,
        key: WindowKey,
        max_windows_per_connection: usize,
    ) -> Result<WindowKey, ProtocolError> {
        if self.windows_touched.contains(&key) {
            return Ok(key);
        }

        if self.windows_touched.len() >= max_windows_per_connection {
            return Err(ProtocolError::InvalidPayload(
                "window creation limit exceeded",
            ));
        }

        self.windows_touched.insert(key.clone());
        Ok(key)
    }

    fn allow_federation_window(&mut self, key: &WindowKey) -> AllowBlock {
        self.federation_quota.allow_window(key, StdInstant::now())
    }

    fn federation_quota_snapshot(&self) -> oneiron::sync::FederationQuotaSnapshot {
        self.federation_quota.snapshot(StdInstant::now())
    }

    fn bind_window_sync_mode(&mut self, mode: WindowSyncMode) -> Result<(), ProtocolError> {
        if mode == WindowSyncMode::Unbound {
            return Ok(());
        }
        match mode {
            WindowSyncMode::Selector if self.protocol_version != protocol::PROTOCOL_VERSION => {
                return Err(ProtocolError::InvalidPayload(
                    "selector sync requires the current selector protocol",
                ));
            }
            WindowSyncMode::FullWindow
                if self.protocol_version != protocol::LEGACY_FULL_WINDOW_PROTOCOL_VERSION =>
            {
                return Err(ProtocolError::InvalidPayload(
                    "full-window sync requires the current full-window protocol",
                ));
            }
            _ => {}
        }

        match (self.window_sync_mode, mode) {
            (WindowSyncMode::Unbound, requested) => {
                self.window_sync_mode = requested;
                Ok(())
            }
            (WindowSyncMode::FullWindow, WindowSyncMode::FullWindow)
            | (WindowSyncMode::Selector, WindowSyncMode::Selector) => Ok(()),
            (WindowSyncMode::Selector, WindowSyncMode::FullWindow) => {
                Err(ProtocolError::InvalidPayload(
                    "selector-scoped connection cannot use full-window sync",
                ))
            }
            (WindowSyncMode::FullWindow, WindowSyncMode::Selector) => Err(
                ProtocolError::InvalidPayload("full-window connection cannot use selector sync"),
            ),
            (_, WindowSyncMode::Unbound) => Ok(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowSyncMode {
    Unbound,
    FullWindow,
    Selector,
}

struct MessageRateLimiter {
    max_messages_per_sec: u32,
    window_start: Instant,
    messages_seen: u32,
}

impl MessageRateLimiter {
    fn new(max_messages_per_sec: u32) -> Self {
        Self {
            max_messages_per_sec,
            window_start: Instant::now(),
            messages_seen: 0,
        }
    }

    fn allow(&mut self, now: Instant) -> bool {
        if self.max_messages_per_sec == 0 {
            return false;
        }

        if now.duration_since(self.window_start) >= Duration::from_secs(1) {
            self.window_start = now;
            self.messages_seen = 0;
        }

        if self.messages_seen >= self.max_messages_per_sec {
            return false;
        }

        self.messages_seen += 1;
        true
    }
}

/// Builds the WebSocket routes for the sync server.
pub(crate) fn ws_routes(server: Arc<SyncServer>) -> Router {
    Router::new()
        .route("/ws", get(ws_upgrade_handler))
        .with_state(server)
}

/// Handles WebSocket upgrade requests.
///
/// Auth: the upgrade request must present an owner-grade credential in the
/// `Authorization: Bearer` header — the configured trust-root secret or an
/// empty-claims v2 token. Scoped delegation tokens do not reach this surface.
/// An unauthenticated upgrade is rejected with 401 BEFORE the socket upgrade
/// (fail-closed) — without this gate any network peer could pull the full
/// root snapshot and window exports. When no secret is configured, upgrades
/// are rejected unless the explicit insecure dev escape hatch is enabled,
/// matching `auth::require_owner_auth` on the HTTP side.
///
/// The credential's revocable identity is carried into the connection rather
/// than discarded with the rest of the `CoreAuth`: the handshake proves the
/// token was live at upgrade time, and the socket outlives that instant.
async fn ws_upgrade_handler(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
) -> Result<impl IntoResponse, StatusCode> {
    let auth = require_owner_auth(&headers, &server.config, server.vault().as_ref())
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let session_jti = auth.jti().map(str::to_owned);

    let conn_id = server.alloc_conn_id();
    tracing::info!(conn_id, "new WebSocket connection");

    // `write_buffer_size` is a security setting here, not a tuning knob: it is
    // what keeps `start_send` from writing to the socket on its own. See
    // [`WS_WRITE_BUFFER_SIZE`]. Note that `max_frame_size` below does NOT pin
    // that — it bounds inbound reads only — so the outbound side is held by
    // [`GuardedTransport::fits_below_write_through`], which refuses per frame
    // in release builds.
    Ok(ws
        .max_frame_size(server.config.max_frame_size)
        .write_buffer_size(WS_WRITE_BUFFER_SIZE)
        .max_write_buffer_size(WS_MAX_WRITE_BUFFER_SIZE)
        .on_upgrade(move |socket| handle_connection(socket, server, conn_id, session_jti)))
}

/// Whether this socket's credential has since been revoked.
///
/// The upgrade handshake proves the credential was live THEN; the socket
/// lives arbitrarily long after it. Revocation is an explicit operator act
/// against one named token, so it must reach sessions that were ALREADY open
/// — otherwise `token revoke` only closes the front door while the peer
/// already inside keeps full vault service. Fail-closed on an unreadable
/// registry, matching the handshake: "we could not check" is not "still live".
///
/// `None` means the credential carries no revocable identity — the bare trust
/// root or the dev fallthrough — so there is nothing to consult and the
/// lookup is skipped entirely. Those are retired by rotating `auth_secret`,
/// which invalidates them without any registry read.
fn session_credential_revoked(revoked: &dyn RevokedTokenJtis, session_jti: Option<&str>) -> bool {
    session_jti.is_some_and(|jti| is_revoked_or_unreadable(jti, revoked))
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
struct GuardedTransport<S> {
    /// `None` once the transport has been aborted.
    ///
    /// A revocation seen while a frame is already queued cannot be answered
    /// with a graceful close: `poll_close` flushes the queue on its way out,
    /// which IS the delivery being refused. Dropping the socket is the only
    /// refusal that withholds bytes it is already holding, so the abort path
    /// takes the socket here and never touches it again — and because this is
    /// the unsplit socket, that one `take` ends the read side as well.
    socket: Option<S>,
    revoked: Arc<dyn RevokedTokenJtis + Send + Sync>,
    session_jti: Option<String>,
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
    fn new(
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
    fn with_write_through_threshold(
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
            conn_id,
            write_through_threshold,
        }
    }

    fn credential_revoked(&self) -> bool {
        session_credential_revoked(self.revoked.as_ref(), self.session_jti.as_deref())
    }

    /// Reads the next inbound frame.
    ///
    /// Taking `&mut self` is the enforcement, not a convention: an application
    /// frame is pending only inside [`Self::send_binary`], which holds the same
    /// unique borrow, so this cannot run then. That is what keeps tungstenite's
    /// automatic pong/close flush from draining guarded bytes — see the type
    /// docs. `None` once the transport has been aborted.
    async fn read_next(&mut self) -> Option<Result<WsMessage, E>> {
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
    async fn send_binary(&mut self, data: Vec<u8>) -> bool {
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

    async fn close(&mut self) {
        if let Some(socket) = self.socket.as_mut() {
            let _ = socket.close().await;
        }
    }

    /// Sends one non-binary control frame, bypassing the revocation consult.
    ///
    /// The single documented exception to the chokepoint: the hello-rejection
    /// close frame carries no vault state and IS the refusal, so gating it on
    /// the credential's liveness could only turn one refusal into another.
    async fn send_unguarded_close_frame(&mut self, close: WsMessage) {
        if let Some(socket) = self.socket.as_mut() {
            let _ = socket.send(close).await;
        }
    }
}

/// What woke the connection loop.
///
/// The select produces this and nothing borrowed, so every future it raced —
/// including the read — is dropped before the handler touches the transport
/// again. That is what lets one task own both halves.
enum ConnEvent {
    Inbound(Option<Result<WsMessage, axum::Error>>),
    Broadcast(Result<Option<Vec<u8>>, crate::broadcast::BroadcastError>),
    Direct(Option<Vec<u8>>),
}

/// Main connection lifecycle.
///
/// The socket is deliberately NOT split. A split hands the two halves to two
/// tasks over one transport, and tungstenite's read path flushes the shared
/// out-buffer whenever it queues an automatic pong or close — which drains
/// application frames the write half is still holding under a revocation
/// consult. Keeping the socket whole means the borrow checker enforces what no
/// runtime check could: while a guarded frame is pending, no read exists to
/// flush it. See [`GuardedTransport`].
#[expect(clippy::cognitive_complexity)]
async fn handle_connection(
    socket: WebSocket,
    server: Arc<SyncServer>,
    conn_id: u32,
    session_jti: Option<String>,
) {
    // Every frame this connection ever writes goes through here, and each one
    // re-consults the revocation registry first. The hello close below is the
    // single deliberate exception: it carries no vault state and is the
    // refusal itself.
    let mut transport = GuardedTransport::new(
        socket,
        Arc::clone(server.vault()) as Arc<dyn RevokedTokenJtis + Send + Sync>,
        session_jti.clone(),
        conn_id,
    );

    // Phase 0: protocol-version hello (ONE-1127). The client's FIRST frame
    // must be a supported protocol hello. Malformed frames or unsupported
    // versions close with 4006 BEFORE any sync payload flows, so wire breaks
    // are detectable instead of surfacing as garbled decode errors mid-sync.
    //
    // A token can idle here — upgraded but silent — for the whole hello
    // timeout, so a revocation can land between the handshake and the first
    // frame. The sends below therefore cannot rely on the handshake's proof
    // of liveness, and do not: they consult at the chokepoint.
    let protocol_version = match await_protocol_hello(&mut transport).await {
        HelloOutcome::Valid(version) => version,
        HelloOutcome::Reject(reason) => {
            tracing::warn!(conn_id, reason, "protocol hello rejected — closing");
            let close = WsMessage::Close(Some(CloseFrame {
                code: close_codes::VERSION_MISMATCH,
                reason: Utf8Bytes::from_static(reason),
            }));
            transport.send_unguarded_close_frame(close).await;
            return;
        }
        HelloOutcome::Disconnected => {
            tracing::info!(conn_id, "client disconnected before protocol hello");
            return;
        }
    };

    // Subscribe to broadcast channel for outbound messages
    let mut subscriber = BroadcastSubscriber::new(conn_id, &server.broadcast_tx);

    // Phase 1: Send root doc snapshot to client.
    // Root doc is server-authoritative — client only reads it.
    match server.export_root_snapshot() {
        Ok(snapshot) => {
            let msg = protocol::encode_root_update(&snapshot);
            if !transport.send_binary(msg).await {
                tracing::warn!(conn_id, "failed to send root snapshot");
                return;
            }
        }
        Err(e) => {
            tracing::error!(conn_id, error = %e, "failed to export root snapshot");
            return;
        }
    }

    // Late-join/reconnect snapshot for the Loro-native ephemeral lane.
    if let Some(msg) = encode_late_join_ephemeral_snapshot(&server, conn_id)
        && !transport.send_binary(msg).await
    {
        tracing::warn!(conn_id, "failed to send ephemeral snapshot");
        return;
    }

    // Channel for direct responses (e.g. VV_REQUEST replies sent only to requester)
    let (direct_tx, mut direct_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let federation_quota = FederationQuotaConfig::new(
        server.config.max_federation_windows_per_connection,
        server.config.federation_flood_pause_secs,
    );
    let mut conn_state = ConnState::new(
        server.config.max_messages_per_sec,
        protocol_version,
        federation_quota,
    );

    // One loop, one owner. The outbound arms used to run in a spawned task over
    // the split sink; they are folded in here because two tasks cannot share
    // this transport safely — see [`GuardedTransport`]. Reads and writes now
    // interleave only at this select, never during a guarded send.
    //
    // BOTH outbound arms still write through the guarded chokepoint, so neither
    // unsolicited fan-out nor a direct answer can outlive the credential:
    // fan-out is service the peer never asked for, and a direct response can
    // sit queued in this channel — or blocked mid-`send` — across the very
    // revocation that should have stopped it.
    loop {
        let event = tokio::select! {
            msg = transport.read_next() => ConnEvent::Inbound(msg),
            broadcast_result = subscriber.recv() => ConnEvent::Broadcast(broadcast_result),
            direct_msg = direct_rx.recv() => ConnEvent::Direct(direct_msg),
        };

        let next_message = match event {
            ConnEvent::Inbound(msg) => msg,
            ConnEvent::Broadcast(broadcast_result) => {
                match broadcast_result {
                    Ok(Some(data)) => {
                        if should_forward_broadcast(protocol_version, &data)
                            && !transport.send_binary(data).await
                        {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(crate::broadcast::BroadcastError::Lagged(n)) => {
                        tracing::warn!(conn_id, missed = n, "subscriber lagged — resync needed");
                    }
                    Err(crate::broadcast::BroadcastError::TooManyLags) => {
                        tracing::warn!(conn_id, "too many lags — disconnecting");
                        transport.close().await;
                        break;
                    }
                }
                continue;
            }
            ConnEvent::Direct(direct_msg) => {
                let Some(data) = direct_msg else {
                    break;
                };
                if !transport.send_binary(data).await {
                    break;
                }
                continue;
            }
        };

        let Some(msg_result) = next_message else {
            break;
        };
        let data = match msg_result {
            Ok(WsMessage::Binary(data)) => data.to_vec(),
            Ok(WsMessage::Close(_)) => {
                tracing::info!(conn_id, "client closed connection");
                break;
            }
            Ok(WsMessage::Ping(_)) | Ok(WsMessage::Pong(_)) => {
                if !conn_state.record_inbound_message() {
                    tracing::warn!(
                        conn_id,
                        max = server.config.max_messages_per_sec,
                        "message rate limit exceeded by control frame — closing"
                    );
                    break;
                }
                continue;
            }
            Ok(WsMessage::Text(_)) => {
                if !conn_state.record_inbound_message() {
                    tracing::warn!(
                        conn_id,
                        max = server.config.max_messages_per_sec,
                        "message rate limit exceeded — closing"
                    );
                    break;
                }
                tracing::warn!(conn_id, "received unexpected text message");
                continue;
            }
            Err(e) => {
                tracing::warn!(conn_id, error = %e, "WebSocket error");
                break;
            }
        };

        if !conn_state.record_inbound_message() {
            tracing::warn!(
                conn_id,
                max = server.config.max_messages_per_sec,
                "message rate limit exceeded — closing"
            );
            break;
        }

        // Size check
        if data.len() > server.config.max_frame_size {
            tracing::warn!(conn_id, size = data.len(), "frame too large");
            break;
        }

        // Parse and dispatch the message
        match protocol::parse_message(&data) {
            Ok(msg) => {
                // Live revocation consult, ahead of every privileged sync
                // message. The handshake established liveness at upgrade
                // time only; a `jti` revoked since must get no further
                // service on this socket. This is the READ-side gate the
                // outbound chokepoint cannot supply: refusing a request
                // before it runs also stops its side effects, which for a
                // write reach the hub store and every live peer rather than
                // this socket's sink.
                if privileged_sync_message(&msg)
                    && session_credential_revoked(server.vault().as_ref(), session_jti.as_deref())
                {
                    tracing::warn!(
                        conn_id,
                        "credential revoked — refusing sync message and closing"
                    );
                    break;
                }
                let handle_result =
                    handle_sync_message(&server, conn_id, msg, &direct_tx, &mut conn_state).await;
                if let Err(e) = handle_result {
                    match &e {
                        ProtocolError::InvalidPayload(msg) => {
                            tracing::warn!(conn_id, error = %msg, "invalid payload — closing");
                            break;
                        }
                        ProtocolError::UnknownTag(tag) => {
                            tracing::warn!(conn_id, tag, "unknown tag — closing");
                            break;
                        }
                        ProtocolError::VvDecode(msg) => {
                            // Fail-closed: a malformed VV is a protocol
                            // violation, never answered with a full export.
                            tracing::warn!(conn_id, error = %msg, "version vector decode failure — closing");
                            break;
                        }
                        ProtocolError::FrameTooLarge { size, max } => {
                            tracing::warn!(conn_id, size, max, "frame too large — closing");
                            break;
                        }
                        ProtocolError::LoroImport(msg) => {
                            tracing::warn!(conn_id, error = %msg, "loro import error — closing");
                            break;
                        }
                        ProtocolError::Persistence(msg) => {
                            // Fail-closed: the server could not durably
                            // persist sync state — do not keep relaying on a
                            // connection whose updates would vanish on
                            // restart.
                            tracing::error!(conn_id, error = %msg, "sync persistence failure — closing");
                            break;
                        }
                    }
                }
            }
            Err(ProtocolError::UnknownTag(tag)) => {
                tracing::warn!(conn_id, tag, "unknown tag — closing");
                break;
            }
            Err(e) => {
                tracing::warn!(conn_id, error = %e, "protocol parse error");
                break;
            }
        }
    }

    tracing::info!(conn_id, "connection closed");
}

/// Outcome of the protocol-version hello phase.
enum HelloOutcome {
    /// First frame was a valid hello with a supported version.
    Valid(u8),
    /// Hello missing/malformed/mismatched/timed out — close with
    /// `close_codes::VERSION_MISMATCH` and this reason.
    Reject(&'static str),
    /// Client went away before sending a hello — nothing to close.
    Disconnected,
}

/// Waits for the client's protocol-version hello as the FIRST frame.
///
/// Skips ping/pong keepalives; any other frame must be the hello.
async fn await_protocol_hello<S, E>(transport: &mut GuardedTransport<S>) -> HelloOutcome
where
    S: SinkExt<WsMessage> + Stream<Item = Result<WsMessage, E>> + Unpin,
{
    let deadline = tokio::time::Duration::from_secs(HELLO_TIMEOUT_SECS);
    let outcome = tokio::time::timeout(deadline, async {
        loop {
            match transport.read_next().await {
                Some(Ok(WsMessage::Binary(data))) => {
                    return match validate_protocol_hello(&data) {
                        Ok(version) => HelloOutcome::Valid(version),
                        Err(_) => HelloOutcome::Reject("protocol version mismatch"),
                    };
                }
                Some(Ok(WsMessage::Ping(_) | WsMessage::Pong(_))) => continue,
                Some(Ok(WsMessage::Text(_))) => {
                    return HelloOutcome::Reject("expected binary protocol hello");
                }
                Some(Ok(WsMessage::Close(_))) | Some(Err(_)) | None => {
                    return HelloOutcome::Disconnected;
                }
            }
        }
    })
    .await;

    outcome.unwrap_or(HelloOutcome::Reject("protocol hello timeout"))
}

/// Validates a hello frame against the server's supported wire protocols.
///
/// Returns the negotiated version on success. Unsupported versions return the
/// close code to send (always `close_codes::VERSION_MISMATCH`) so callers
/// cannot accidentally downgrade the failure to a softer close.
fn validate_protocol_hello(frame: &[u8]) -> Result<u8, u16> {
    match protocol::decode_protocol_hello(frame) {
        Ok(version)
            if version == protocol::PROTOCOL_VERSION
                || version == protocol::LEGACY_FULL_WINDOW_PROTOCOL_VERSION =>
        {
            Ok(version)
        }
        _ => Err(close_codes::VERSION_MISMATCH),
    }
}

/// Whether this message class moves server state, and therefore requires a
/// live credential.
///
/// Everything that reads the vault out (root VV deltas, window VV exchange,
/// selector fetches), writes into it (window updates), registers device
/// identity (lease), or publishes to live peers (ephemeral presence/cursor
/// state) is privileged. Exactly one class is not:
///
/// - `RootUpdate` — the root doc is server-authoritative; the handler
///   discards client updates without touching any state, so a revoked peer
///   sending one already achieves nothing. Exempting it keeps an idle
///   keepalive-shaped connection off the registry.
///
/// `Ephemeral` is deliberately NOT exempt, though it carries no vault
/// content. The read-side argument for exempting it — the outbound guard
/// stops the revoked peer from receiving the fan-out — says nothing about
/// the write side: the handler applies the payload to the hub store and
/// broadcasts it, so a revoked bearer would keep PUBLISHING presence and
/// cursor state to every live peer after losing all read access. Revocation
/// means no further service in either direction.
///
/// The exemption is the reason this is an explicit allow-list rather than a
/// blanket check: a new privileged message variant must be classified here,
/// and the compiler forces that decision by exhaustive match.
fn privileged_sync_message(msg: &SyncMessage) -> bool {
    match msg {
        SyncMessage::RootUpdate(_) => false,
        SyncMessage::Ephemeral(_)
        | SyncMessage::RootVersionVector(_)
        | SyncMessage::LeaseRequest { .. }
        | SyncMessage::WindowSync { .. } => true,
    }
}

fn should_forward_broadcast(protocol_version: u8, data: &[u8]) -> bool {
    protocol_version == protocol::LEGACY_FULL_WINDOW_PROTOCOL_VERSION
        || data.first().copied() != Some(protocol::TAG_WINDOW_SYNC)
}

fn encode_late_join_ephemeral_snapshot(server: &SyncServer, conn_id: u32) -> Option<Vec<u8>> {
    server.ephemeral_store.remove_outdated();
    let snapshot = server.ephemeral_store.encode_all();
    match decode_ephemeral_states(&snapshot) {
        Ok(states) if states.is_empty() => return None,
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(
                conn_id,
                error = protocol::transport_err_msg(e),
                "failed to decode ephemeral snapshot"
            );
            return None;
        }
    }
    if snapshot.len() > server.config.max_ephemeral_snapshot_bytes {
        tracing::warn!(
            conn_id,
            size = snapshot.len(),
            max = server.config.max_ephemeral_snapshot_bytes,
            "ephemeral snapshot exceeds cap; skipping late-join snapshot"
        );
        return None;
    }

    match protocol::encode_ephemeral(&snapshot).into_result() {
        Ok(msg) => Some(msg),
        Err(e) => {
            tracing::warn!(
                conn_id,
                error = protocol::transport_err_msg(e),
                "failed to encode ephemeral snapshot"
            );
            None
        }
    }
}

fn validate_ephemeral_payload(
    server: &SyncServer,
    payload: &[u8],
) -> Result<Vec<EphemeralWireState>, ProtocolError> {
    if payload.len() > server.config.max_ephemeral_payload_bytes {
        return Err(ProtocolError::FrameTooLarge {
            size: payload.len(),
            max: server.config.max_ephemeral_payload_bytes,
        });
    }

    let states = decode_ephemeral_states(payload)
        .map_err(|e| ProtocolError::InvalidPayload(protocol::transport_err_msg(e)))?;
    if states.len() > MAX_EPHEMERAL_RECORDS_PER_FRAME {
        return Err(ProtocolError::InvalidPayload(
            "too many ephemeral records in one frame",
        ));
    }

    let max_timestamp = ephemeral_now_ms().saturating_add(MAX_EPHEMERAL_FUTURE_SKEW_MS);
    for state in &states {
        if state.key.is_empty() {
            return Err(ProtocolError::InvalidPayload("empty ephemeral key"));
        }
        if state.key.len() > MAX_EPHEMERAL_KEY_BYTES {
            return Err(ProtocolError::InvalidPayload("ephemeral key too long"));
        }
        if state.timestamp > max_timestamp {
            return Err(ProtocolError::InvalidPayload(
                "ephemeral timestamp too far in future",
            ));
        }
    }

    Ok(states)
}

fn ensure_ephemeral_hub_budget(
    server: &SyncServer,
    payload: &[u8],
    states: &[EphemeralWireState],
) -> Result<(), ProtocolError> {
    let current_snapshot = server.ephemeral_store.encode_all();
    if current_snapshot.len() > server.config.max_ephemeral_snapshot_bytes {
        return Err(ProtocolError::FrameTooLarge {
            size: current_snapshot.len(),
            max: server.config.max_ephemeral_snapshot_bytes,
        });
    }

    let candidate = EphemeralStore::new(server.config.ephemeral_timeout_ms);
    if !current_snapshot.is_empty() {
        candidate
            .apply(&current_snapshot)
            .map_err(|_| ProtocolError::InvalidPayload("invalid ephemeral hub snapshot"))?;
    }
    candidate
        .apply(payload)
        .map_err(|_| ProtocolError::InvalidPayload("invalid ephemeral payload"))?;
    candidate.remove_outdated();

    let candidate_snapshot = candidate.encode_all();
    if candidate_snapshot.len() > server.config.max_ephemeral_snapshot_bytes {
        return Err(ProtocolError::FrameTooLarge {
            size: candidate_snapshot.len(),
            max: server.config.max_ephemeral_snapshot_bytes,
        });
    }

    let mut seen = HashSet::new();
    for state in states {
        if !seen.insert(state.key.as_str()) {
            continue;
        }

        let canonical = candidate.encode(&state.key);
        if canonical.len() > server.config.max_ephemeral_payload_bytes {
            return Err(ProtocolError::FrameTooLarge {
                size: canonical.len(),
                max: server.config.max_ephemeral_payload_bytes,
            });
        }
    }

    Ok(())
}

fn canonical_ephemeral_frames(
    server: &SyncServer,
    states: &[EphemeralWireState],
) -> Result<Vec<Vec<u8>>, ProtocolError> {
    let mut seen = HashSet::new();
    let mut frames = Vec::new();
    for state in states {
        if !seen.insert(state.key.clone()) {
            continue;
        }

        let canonical = server.ephemeral_store.encode(&state.key);
        let canonical_states = decode_ephemeral_states(&canonical)
            .map_err(|e| ProtocolError::InvalidPayload(protocol::transport_err_msg(e)))?;
        if canonical_states.is_empty() {
            continue;
        }
        if canonical.len() > server.config.max_ephemeral_payload_bytes {
            return Err(ProtocolError::FrameTooLarge {
                size: canonical.len(),
                max: server.config.max_ephemeral_payload_bytes,
            });
        }
        let encoded = protocol::encode_ephemeral(&canonical)
            .into_result()
            .map_err(|e| ProtocolError::InvalidPayload(protocol::transport_err_msg(e)))?;
        frames.push(encoded);
    }

    Ok(frames)
}

fn ephemeral_now_ms() -> i64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    millis.min(i64::MAX as u128) as i64
}

/// Dispatches a parsed SyncMessage to the appropriate handler.
async fn handle_sync_message(
    server: &SyncServer,
    conn_id: u32,
    msg: SyncMessage,
    direct_tx: &tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    conn_state: &mut ConnState,
) -> Result<(), ProtocolError> {
    match msg {
        SyncMessage::RootUpdate(_update_bytes) => {
            // Root doc is server-authoritative — reject client updates silently
            tracing::debug!(
                conn_id,
                "rejected client root update (server-authoritative)"
            );
            Ok(())
        }
        SyncMessage::Ephemeral(payload) => {
            server.ephemeral_store.remove_outdated();
            let states = validate_ephemeral_payload(server, &payload)?;
            ensure_ephemeral_hub_budget(server, &payload, &states)?;
            server
                .ephemeral_store
                .apply(&payload)
                .map_err(|_| ProtocolError::InvalidPayload("invalid ephemeral payload"))?;
            server.ephemeral_store.remove_outdated();
            for encoded in canonical_ephemeral_frames(server, &states)? {
                let _ = crate::broadcast::broadcast(&server.broadcast_tx, conn_id, encoded);
            }
            Ok(())
        }
        SyncMessage::LeaseRequest {
            client_id,
            pubkey,
            pop_sig,
        } => {
            // ONE-1140 (OD-3): registrar under the server lease lock. A
            // storage/persist failure is fail-closed (Persistence closes
            // the connection); a REJECTED binding is a normal ack — sync
            // proceeds, peers' replay doors quarantine the device's NEW
            // receipts.
            let decision = server
                .register_lease(client_id, &pubkey, &pop_sig)
                .await
                .map_err(|e| ProtocolError::Persistence(format!("lease registrar: {e}")))?;
            let status = if decision.granted {
                protocol::LEASE_STATUS_GRANTED
            } else {
                protocol::LEASE_STATUS_REJECTED
            };
            let expires_at = if decision.granted {
                decision.expires_at
            } else {
                0
            };
            tracing::info!(
                conn_id,
                client_id = format!("{client_id:016x}"),
                granted = decision.granted,
                "lease request processed"
            );
            // Direct ack to the requester (echo suppression would drop a
            // broadcast for the sender).
            let _ = direct_tx.send(protocol::encode_lease_granted(
                status, client_id, expires_at,
            ));
            // Registry change rides the root-update broadcast to ALL
            // connections — conn_id 0 (the bridge/local sentinel) skips
            // echo suppression because the REQUESTER also needs its own
            // record mirrored into ls: for door-side verification.
            if let Some(update) = decision.root_update {
                let msg = protocol::encode_root_update(&update);
                let _ = crate::broadcast::broadcast(&server.broadcast_tx, 0, msg);
            }
            Ok(())
        }
        SyncMessage::RootVersionVector(vv_bytes) => {
            // Client is requesting root doc updates since their VV (Loro
            // binary encoding). Malformed VV → typed error, fail-closed —
            // NEVER answered with a full export as if the VV were empty.
            let client_vv = VersionVector::decode(&vv_bytes)
                .map_err(|e| ProtocolError::VvDecode(e.to_string()))?;
            tracing::debug!(conn_id, "client sent root VV — sending root delta");
            match server.export_root_updates(&client_vv) {
                Ok(delta) => {
                    let msg = protocol::encode_root_update(&delta);
                    let _ = direct_tx.send(msg);
                }
                Err(e) => {
                    tracing::error!(conn_id, error = %e, "failed to export root delta for VV response");
                }
            }
            Ok(())
        }
        SyncMessage::WindowSync {
            window_key,
            sub_tag,
            payload,
        } => {
            handle_window_sync(
                server,
                conn_id,
                &window_key,
                sub_tag,
                &payload,
                direct_tx,
                conn_state,
            )
            .await
        }
    }
}

/// Handles a WindowSync message: routes to the correct window LoroDoc.
async fn handle_window_sync(
    server: &SyncServer,
    conn_id: u32,
    window_key: &str,
    sub_tag: u8,
    payload: &[u8],
    direct_tx: &tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    conn_state: &mut ConnState,
) -> Result<(), ProtocolError> {
    // Window-key chokepoint. `decode_window_sync` already validated the key
    // at the parse boundary; re-validate here so this write path stays
    // fail-closed even if a future caller bypasses the wire decoder.
    let key = WindowKey::try_new(window_key)
        .ok_or(ProtocolError::InvalidPayload("invalid window key"))?;

    // Enforce max_update_payload BEFORE the window doc is fetched/created:
    // an oversized update must not mutate any server state.
    if matches!(
        sub_tag,
        window_sub_tags::UPDATE | window_sub_tags::SELECTOR_VV_REQUEST
    ) && payload.len() > server.config.max_update_payload
    {
        return Err(ProtocolError::FrameTooLarge {
            size: payload.len(),
            max: server.config.max_update_payload,
        });
    }

    match sub_tag {
        window_sub_tags::SELECTOR_VV_REQUEST => {
            conn_state.bind_window_sync_mode(WindowSyncMode::Selector)?;
            match conn_state.allow_federation_window(&key) {
                AllowBlock::Allow => {}
                AllowBlock::Pause(reason) => {
                    let state = conn_state.federation_quota_snapshot();
                    tracing::warn!(
                        conn_id,
                        window_key,
                        ?reason,
                        ?state,
                        "federation selector connection paused"
                    );
                    return Ok(());
                }
                AllowBlock::Block(reason) => {
                    tracing::warn!(
                        conn_id,
                        window_key,
                        ?reason,
                        "federation selector connection blocked"
                    );
                    return Err(ProtocolError::InvalidPayload(
                        "federation selector quota blocked",
                    ));
                }
            }
        }
        window_sub_tags::VV_REQUEST | window_sub_tags::VV_RESPONSE | window_sub_tags::UPDATE => {
            conn_state.bind_window_sync_mode(WindowSyncMode::FullWindow)?;
        }
        _ => {}
    }

    let selector_request = if sub_tag == window_sub_tags::SELECTOR_VV_REQUEST {
        Some(decode_and_authorize_selector_request(server, payload)?)
    } else {
        None
    };

    // Count distinct, valid window keys per connection before any load/create.
    // The default cap is generous so legitimate historical-window tombstone
    // sync can touch all real windows; it only stops fabricated-key floods.
    let key = conn_state.touch_window(key, server.config.max_windows_per_connection)?;

    // Loads persisted window state (d:w: + pending u:w:) on first touch.
    // Corrupt persisted state closes the connection rather than serving a
    // fresh empty window (fail-closed — see SyncServer::get_or_create_window).
    let doc = server
        .get_or_create_window(&key)
        .await
        .map_err(|e| ProtocolError::Persistence(format!("window load failed: {e}")))?;

    match sub_tag {
        window_sub_tags::VV_REQUEST => {
            // Client sent its binary VV (SyncStep1) — export ONLY the delta it
            // is missing (ExportMode::updates via the single delta-export entry
            // point). Malformed VV → typed error, fail-closed: never fall back
            // to a full export.
            let delta = oneiron::sync::window::export_window_updates_since(
                server.vault.as_ref(),
                &key,
                &doc,
                payload,
            )
            .map_err(map_delta_export_err)?;
            let response =
                protocol::encode_window_sync(window_key, window_sub_tags::UPDATE, &delta)
                    .into_result()
                    .map_err(|e| ProtocolError::InvalidPayload(protocol::transport_err_msg(e)))?;
            // Send directly to the requesting client's WebSocket sink, NOT via
            // broadcast. Broadcasting with the requester's conn_id would cause
            // echo suppression to drop the response for the requester.
            let _ = direct_tx.send(response);
            // Reverse SyncStep1: send our VV so the client pushes its local
            // diff back — this is what makes the exchange bidirectional.
            let vv_response = protocol::encode_window_sync(
                window_key,
                window_sub_tags::VV_RESPONSE,
                &doc.oplog_vv().encode(),
            )
            .into_result()
            .map_err(|e| ProtocolError::InvalidPayload(protocol::transport_err_msg(e)))?;
            let _ = direct_tx.send(vv_response);
        }
        window_sub_tags::SELECTOR_VV_REQUEST => {
            // Grant-backed closed-subgraph fetch. The full-window VV path
            // above stays byte-for-byte compatible; selected sync exports
            // from a synthetic doc so unauthorized entries are never present
            // in the outbound Loro update bytes.
            let request = selector_request.ok_or(ProtocolError::InvalidPayload(
                "missing sync selector request",
            ))?;
            let filtered = filtered_window_doc(
                server.vault.as_ref(),
                &doc,
                &key,
                selector_grant_scope(),
                &request.selector,
            )
            .map_err(map_selector_filter_err)?;
            let delta = filtered
                .export(ExportMode::all_updates())
                .map_err(|e| ProtocolError::LoroImport(e.to_string()))?;
            let response =
                protocol::encode_window_sync(window_key, window_sub_tags::UPDATE, &delta)
                    .into_result()
                    .map_err(|e| ProtocolError::InvalidPayload(protocol::transport_err_msg(e)))?;
            let _ = direct_tx.send(response);
        }
        window_sub_tags::UPDATE => {
            // Client sending Loro update bytes — import with origin for echo suppression
            let origin = format!("conn:{conn_id}");
            doc.import_with(payload, &origin)
                .map_err(|e| ProtocolError::LoroImport(format!("{e}")))?;
            // Durability BEFORE fan-out (ARCH-0023b Observer A duty: "MUST
            // persist synchronously"). `subscribe_local_update` does not fire
            // for imports, so the imported update bytes are appended to
            // sync_state (u:w:*) explicitly. A persistence failure closes the
            // connection without broadcasting: the server must never relay an
            // update — tombstones included — that it cannot replay after a
            // restart.
            let persist_result = server.persist_imported_update(&key, payload);
            if let Err(e) = persist_result {
                // The cached doc already imported this update (import runs
                // before the durable append), so it now holds state a restart
                // would lose. Left cached, a later VV_REQUEST would serve the
                // unpersisted update, the origin client would VV-confirm and
                // clear its local queue, and the next server restart would
                // drop the update — tombstones included — fleet-wide. Evict
                // the window so the next access reloads from durable
                // d:w:/u:w: state. Known residual: connections already
                // holding a reference-clone of the evicted doc can still
                // export it until their next fetch (generation/poison flag =
                // follow-up).
                server.evict_window(&key).await;
                return Err(ProtocolError::Persistence(format!(
                    "update persist failed: {e}"
                )));
            }

            let broadcast_msg =
                protocol::encode_window_sync(window_key, window_sub_tags::UPDATE, payload)
                    .into_result()
                    .map_err(|e| ProtocolError::InvalidPayload(protocol::transport_err_msg(e)))?;
            let _ = crate::broadcast::broadcast(&server.broadcast_tx, conn_id, broadcast_msg);
        }
        window_sub_tags::VV_RESPONSE => {
            // Client's VV answering our VV_REQUEST — export and send only our
            // local diff. Same fail-closed VV decoding as VV_REQUEST.
            let delta = oneiron::sync::window::export_window_updates_since(
                server.vault.as_ref(),
                &key,
                &doc,
                payload,
            )
            .map_err(map_delta_export_err)?;
            let response =
                protocol::encode_window_sync(window_key, window_sub_tags::UPDATE, &delta)
                    .into_result()
                    .map_err(|e| ProtocolError::InvalidPayload(protocol::transport_err_msg(e)))?;
            let _ = direct_tx.send(response);
        }
        _ => {
            tracing::warn!(window_key, sub_tag, "unknown WindowSync sub-tag");
        }
    }

    Ok(())
}

fn decode_and_authorize_selector_request(
    server: &SyncServer,
    payload: &[u8],
) -> Result<SelectorVvRequest, ProtocolError> {
    let request = decode_selector_vv_request(payload)
        .map_err(|_| ProtocolError::InvalidPayload("invalid sync selector request"))?;
    let remote_vv = VersionVector::decode(&request.remote_vv)
        .map_err(|e| ProtocolError::VvDecode(e.to_string()))?;
    if !remote_vv.is_empty() {
        return Err(ProtocolError::InvalidPayload(
            "selector sync requires empty version vector resync",
        ));
    }
    authorize_sync_selector(
        server.vault.as_ref(),
        selector_grant_scope(),
        &request.selector,
    )
    .map_err(map_selector_filter_err)?;
    Ok(request)
}

/// Maps a delta-export error onto the protocol taxonomy.
///
/// Malformed inbound VV bytes (`CrdtDecodeError`) get the dedicated
/// fail-closed `VvDecode` variant (the connection loop closes on it);
/// anything else is an export-side failure.
fn map_delta_export_err(e: oneiron::Error) -> ProtocolError {
    if matches!(e, oneiron::Error::CrdtDecodeError { .. }) {
        ProtocolError::VvDecode(e.to_string())
    } else {
        ProtocolError::LoroImport(e.to_string())
    }
}

fn map_selector_filter_err(e: oneiron::Error) -> ProtocolError {
    if matches!(
        e,
        oneiron::Error::SyncProtocolError { .. } | oneiron::Error::InvalidFederationGrantBody(_)
    ) {
        ProtocolError::InvalidPayload("sync selector rejected")
    } else {
        ProtocolError::Persistence(format!("selector filter failed: {e}"))
    }
}

fn selector_grant_scope() -> oneiron::FederationGrantScope {
    oneiron::FederationGrantScope::vault(SERVER_SELECTOR_VAULT_ID)
}

#[cfg(test)]
mod tests;
