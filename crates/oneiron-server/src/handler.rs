//! WebSocket upgrade handler and connection lifecycle.
//!
//! Each WebSocket connection follows the protocol from ARCH-023 §3.2:
//! 1. Phase 1: Root doc sync (send snapshot to new client)
//! 2. Phase 2: Default windows (current + previous) via VV exchange + updates
//! 3. Phase 3: Historical windows via BulkTransfer (oldest first) + BulkTransferDone
//! 4. Ongoing: bidirectional incremental sync via WindowSync + ephemeral state

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Instant as StdInstant, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::extract::State;
use axum::extract::ws::{CloseFrame, Message as WsMessage, Utf8Bytes, WebSocket, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use futures_util::stream::SplitStream;
use futures_util::{SinkExt, StreamExt};
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

    Ok(ws
        .max_frame_size(server.config.max_frame_size)
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

/// The one place this server writes a frame to a client socket.
///
/// Every outbound frame on a connection goes through [`Self::send_binary`] —
/// the Phase-1 root snapshot, the late-join ephemeral snapshot, direct
/// answers to inbound requests, and unsolicited broadcast fan-out — and each
/// one re-consults the revocation registry immediately before the write.
///
/// A chokepoint rather than a gate per send arm, because per-arm reasoning
/// has been wrong twice. "The hello runs before dispatch" left the snapshot
/// sends uncovered; "direct sends only answer already-gated inbound
/// messages" ignored that a response sits queued in the direct channel and
/// drains AFTER the revocation that should have stopped it. One site cannot
/// drift from itself, and a future send arm inherits the consult by
/// construction instead of having to remember to classify itself.
///
/// The registry — not the whole server — is held here because the registry is
/// the only thing this type consults, which also lets the fail-closed
/// unreadable path be driven directly in tests.
struct GuardedSink<S> {
    sink: S,
    revoked: Arc<dyn RevokedTokenJtis + Send + Sync>,
    session_jti: Option<String>,
    conn_id: u32,
}

impl<S> GuardedSink<S>
where
    S: SinkExt<WsMessage> + Unpin,
{
    fn new(
        sink: S,
        revoked: Arc<dyn RevokedTokenJtis + Send + Sync>,
        session_jti: Option<String>,
        conn_id: u32,
    ) -> Self {
        Self {
            sink,
            revoked,
            session_jti,
            conn_id,
        }
    }

    /// Sends one binary frame, refusing if the credential is no longer live.
    ///
    /// Returns whether the connection may continue. `false` means either the
    /// credential was revoked (or its registry unreadable) — in which case
    /// the socket has already been closed and nothing was written — or the
    /// peer's sink is gone. Both outcomes end the connection, so callers do
    /// not distinguish them.
    ///
    /// The send is spelled out rather than `SinkExt::send` because the ORDER
    /// is the point: wait for the sink to have capacity, THEN consult, THEN
    /// hand over the bytes. A frame can sit parked in that wait for as long
    /// as the peer's socket stays full — an unbounded interval, and precisely
    /// where an operator's `token revoke` lands. Consulting before the wait
    /// would authorize a write performed an arbitrary time later. What
    /// remains after the handover is the flush, where the bytes are already
    /// committed to the transport and no gate exists anywhere.
    #[must_use]
    async fn send_binary(&mut self, data: Vec<u8>) -> bool {
        if std::future::poll_fn(|cx| self.sink.poll_ready_unpin(cx))
            .await
            .is_err()
        {
            tracing::debug!(conn_id = self.conn_id, "outbound sink closed");
            return false;
        }
        if session_credential_revoked(self.revoked.as_ref(), self.session_jti.as_deref()) {
            tracing::warn!(
                conn_id = self.conn_id,
                "credential revoked — closing live session instead of sending"
            );
            self.close().await;
            return false;
        }
        if self
            .sink
            .start_send_unpin(WsMessage::Binary(data.into()))
            .is_err()
            || std::future::poll_fn(|cx| self.sink.poll_flush_unpin(cx))
                .await
                .is_err()
        {
            tracing::debug!(conn_id = self.conn_id, "outbound sink closed");
            return false;
        }
        true
    }

    async fn close(&mut self) {
        let _ = self.sink.close().await;
    }
}

/// Main connection lifecycle.
#[expect(clippy::cognitive_complexity)]
async fn handle_connection(
    socket: WebSocket,
    server: Arc<SyncServer>,
    conn_id: u32,
    session_jti: Option<String>,
) {
    let (ws_sink, mut ws_stream) = socket.split();
    // Every frame this connection ever writes goes through here, and each one
    // re-consults the revocation registry first. The hello close below is the
    // single deliberate exception: it carries no vault state and is the
    // refusal itself.
    let mut ws_sink = GuardedSink::new(
        ws_sink,
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
    let protocol_version = match await_protocol_hello(&mut ws_stream).await {
        HelloOutcome::Valid(version) => version,
        HelloOutcome::Reject(reason) => {
            tracing::warn!(conn_id, reason, "protocol hello rejected — closing");
            let close = WsMessage::Close(Some(CloseFrame {
                code: close_codes::VERSION_MISMATCH,
                reason: Utf8Bytes::from_static(reason),
            }));
            let _ = ws_sink.sink.send(close).await;
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
            if !ws_sink.send_binary(msg).await {
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
        && !ws_sink.send_binary(msg).await
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

    // Spawn outbound task: forwards broadcast + direct messages to WebSocket
    // sink. BOTH arms write through the guarded chokepoint, so neither
    // unsolicited fan-out nor a direct answer can outlive the credential:
    // fan-out is service the peer never asked for, and a direct response can
    // sit queued in this channel — or blocked mid-`send` — across the very
    // revocation that should have stopped it.
    let outbound_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                broadcast_result = subscriber.recv() => {
                    match broadcast_result {
                        Ok(Some(data)) => {
                            if !should_forward_broadcast(protocol_version, &data) {
                                continue;
                            }
                            if !ws_sink.send_binary(data).await {
                                break;
                            }
                        }
                        Ok(None) => break,
                        Err(crate::broadcast::BroadcastError::Lagged(n)) => {
                            tracing::warn!(conn_id, missed = n, "subscriber lagged — resync needed");
                        }
                        Err(crate::broadcast::BroadcastError::TooManyLags) => {
                            tracing::warn!(conn_id, "too many lags — disconnecting");
                            ws_sink.close().await;
                            break;
                        }
                    }
                }
                direct_msg = direct_rx.recv() => {
                    match direct_msg {
                        Some(data) => {
                            if !ws_sink.send_binary(data).await {
                                break;
                            }
                        }
                        None => break,
                    }
                }
            }
        }
    });

    // Inbound loop: process messages from client
    loop {
        let next_message = ws_stream.next().await;
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

    outbound_handle.abort();
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
async fn await_protocol_hello(ws_stream: &mut SplitStream<WebSocket>) -> HelloOutcome {
    let deadline = tokio::time::Duration::from_secs(HELLO_TIMEOUT_SECS);
    let outcome = tokio::time::timeout(deadline, async {
        loop {
            match ws_stream.next().await {
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

    // A fence can be established after this live doc acquired a body or an
    // incident edge. Every full-window export must retire those carriers
    // before computing a delta or advertising the doc's version vector.
    if matches!(
        sub_tag,
        window_sub_tags::VV_REQUEST
            | window_sub_tags::VV_RESPONSE
            | window_sub_tags::SELECTOR_VV_REQUEST
    ) {
        oneiron::sync::window::scrub_off_record_fenced_carriers(server.vault.as_ref(), &key, &doc)
            .map_err(|e| ProtocolError::Persistence(format!("off-record carrier scrub: {e}")))?;
    }

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
            let scrubbed_fenced_carrier = oneiron::sync::window::scrub_off_record_fenced_carriers(
                server.vault.as_ref(),
                &key,
                &doc,
            )
            .map_err(|e| ProtocolError::Persistence(format!("off-record carrier scrub: {e}")))?;

            // Durability BEFORE fan-out (ARCH-0023b Observer A duty: "MUST
            // persist synchronously"). `subscribe_local_update` does not fire
            // for imports, so the imported update bytes are appended to
            // sync_state (u:w:*) explicitly. A persistence failure closes the
            // connection without broadcasting: the server must never relay an
            // update — tombstones included — that it cannot replay after a
            // restart.
            let persist_result = if scrubbed_fenced_carrier {
                server.persist_sanitized_window(&key).map(|()| 0)
            } else {
                server.persist_imported_update(&key, payload)
            };
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

            // Never relay an inbound frame verbatim when it contained a
            // locally fenced carrier. In that case only the scrub commit is
            // broadcast, retiring an older peer carrier without forwarding
            // the rejected body bytes. Other accepted updates keep the
            // existing zero-copy relay path.
            let scrub_update;
            let outbound_payload = if scrubbed_fenced_carrier {
                let empty_vv = VersionVector::default().encode();
                scrub_update = oneiron::sync::window::export_window_updates_since(
                    server.vault.as_ref(),
                    &key,
                    &doc,
                    &empty_vv,
                )
                .map_err(map_delta_export_err)?;
                scrub_update.as_slice()
            } else {
                payload
            };
            let broadcast_msg =
                protocol::encode_window_sync(window_key, window_sub_tags::UPDATE, outbound_payload)
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
