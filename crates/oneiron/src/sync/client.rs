//! Client-side sync over WebSocket.
//!
//! Implements the device side of the ARCH-0023b connection flow:
//! 1. Phase 1: Root doc sync (server sends snapshot, client imports)
//! 2. Phase 2: Default windows (current + previous) via VV exchange + updates
//! 3. Phase 3: Historical windows arrive via BulkTransfer + BulkTransferDone
//! 4. Ongoing: bidirectional incremental sync via WindowSync
//!
//! Reconnection with exponential backoff (1s → 60s cap).
//! 50ms debounce for rapid edits before sending.
//!
//! # Manager-owned windows (ONE-1126)
//!
//! Window docs are NOT private bare `LoroDoc`s: every window the client
//! touches is a manager-owned [`LoadedWindow`] obtained through
//! [`WindowManager::open_window`], which consults persisted `sync_state`
//! first (`d:w:{key}` snapshot + pending `u:w:{key}:*` replay — ARCH-0023b
//! startup step 2), runs the pinned recovery order, and attaches
//! Observer A + B last. Remote updates imported here therefore reach LMDB
//! through Observer B, and local commits flow outbound through Observer A's
//! [`crate::sync::bridge::OutboundSink`].
//!
//! # Client-persisted sync_state rows (ARCH-0023b key table)
//!
//! - `d:root` / `sv:root` / `svf:root` — root doc snapshot + state vector,
//!   persisted on every accepted root import; reloaded on restart with
//!   pending `u:root:*` replay (startup step 1).
//! - `m:client_id` — this device's CRDT client id (u64 LE, 8 bytes), minted
//!   once and stable per install.
//! - `m:last_sync` — last successful sync timestamp (u64 LE, 8 bytes).
//! - `bulk:w:{key}` — BulkTransfer in-progress marker (device only);
//!   cleared when `BulkTransferDone` persistence succeeds.
//! - `sv:w:{key}` / `svf:w:{key}` — read by the fast-reconnect path in
//!   [`SyncClient::generate_initial_sync`]: a fresh flag lets the client
//!   answer the VV exchange from the persisted state vector without
//!   loading the window doc.

use std::sync::Arc;

use loro::{LoroDoc, VersionVector};
use tokio::sync::mpsc;

use crate::Vault;
use crate::error::{Error, Result};
use crate::sync::bridge::persist_window_update;
use crate::sync::loro_support::{
    doc_from_snapshot, doc_version_vector, export_snapshot, export_updates_since,
};
use crate::sync::manager::WindowManager;
use crate::sync::schema::read_window_list;
use crate::sync::transport::{
    self, MAX_DECODED_PAYLOAD_BYTES, TAG_AWARENESS, TAG_BULK_TRANSFER, TAG_BULK_TRANSFER_DONE,
    TAG_SYNC_UPDATE, TAG_VERSION_VECTOR, TAG_WINDOW_SYNC, TransportError, window_sub_tags,
};
use crate::sync::types::{WindowKey, parse_window_key_str};
use crate::sync::window::LoadedWindow;

/// Root doc snapshot row (ARCH-0023b key table: server-write-only
/// `meta.windows`; client persists what it imported).
const KEY_ROOT_DOC: &str = "d:root";
/// Root doc state vector row (StateVector V1 encoded).
const KEY_ROOT_SV: &str = "sv:root";
/// Root state-vector freshness flag (1 = fresh, 0 = stale).
const KEY_ROOT_SVF: &str = "svf:root";
/// Pending root update rows applied on top of `d:root` at startup (step 1).
const ROOT_UPDATE_PREFIX: &str = "u:root:";
/// This device's CRDT client id (u64 LE, 8 bytes) — minted once, stable per
/// install.
const KEY_CLIENT_ID: &str = "m:client_id";
/// Last successful sync timestamp (u64 LE, 8 bytes).
const KEY_LAST_SYNC: &str = "m:last_sync";

/// `svf:*` byte meaning "the persisted `sv:*` reflects the full doc state".
const SVF_FRESH: u8 = 1;

/// Client-side sync configuration.
#[derive(Debug, Clone)]
pub struct SyncClientConfig {
    /// WebSocket server URL (e.g., "wss://user-{id}.fly.dev/ws").
    pub server_url: String,
    /// Auth token (WorkOS JWT for production, shared secret for Phase 1).
    pub auth_token: String,
    /// Number of default windows to sync (current + previous). Default: 2.
    pub default_window_count: u8,
    /// Debounce interval for rapid edits before sending. Default: 50ms.
    pub sync_debounce_ms: u32,
    /// Maximum reconnection backoff delay. Default: 60s.
    pub reconnect_backoff_max_ms: u32,
    /// Initial reconnection delay. Default: 1s.
    pub reconnect_initial_ms: u32,
}

impl Default for SyncClientConfig {
    fn default() -> Self {
        Self {
            server_url: String::new(),
            auth_token: String::new(),
            default_window_count: 2,
            sync_debounce_ms: 50,
            reconnect_backoff_max_ms: 60_000,
            reconnect_initial_ms: 1_000,
        }
    }
}

/// Sync status reported by the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncStatus {
    Disconnected,
    Connecting,
    Connected,
    Synced,
}

/// Events emitted by the sync client for the host application.
#[derive(Debug)]
pub enum SyncEvent {
    StatusChanged(SyncStatus),
    WindowUpdated { window_key: String },
    BulkTransferComplete { window_key: String },
    Error(String),
}

/// Client-side sync engine.
pub struct SyncClient {
    vault: Arc<Vault>,
    manager: Arc<WindowManager>,
    root_doc: LoroDoc,
    client_id: u64,
    config: SyncClientConfig,
    status: SyncStatus,
    pub(crate) event_tx: mpsc::UnboundedSender<SyncEvent>,
}

impl SyncClient {
    /// Creates a new sync client over manager-owned windows.
    ///
    /// Loads persisted client state first (ARCH-0023b startup step 1):
    /// `m:client_id` (minted once if absent), then the root doc from
    /// `d:root` + pending `u:root:*` replay. A malformed `m:client_id` row
    /// fails closed — silently re-minting would change this device's CRDT
    /// identity.
    pub fn new(
        manager: Arc<WindowManager>,
        config: SyncClientConfig,
    ) -> Result<(Self, mpsc::UnboundedReceiver<SyncEvent>)> {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let vault = Arc::clone(manager.vault());

        let client_id = load_or_mint_client_id(&vault)?;
        let root_doc = load_root_doc(&vault)?;
        // The client never authors root ops in production (meta.windows is
        // server-write-only), so pinning the stable client id as the root
        // doc's Loro peer id is safe. Window docs keep Loro-random peer ids
        // for now: reusing a stable peer id after sync_state loss would
        // restart its op counter and mint duplicate (peer, counter) op ids
        // — CRDT corruption. Revisit with VV/convergence (M4-11/12).
        root_doc
            .set_peer_id(client_id)
            .map_err(|e| Error::SyncProtocolError(format!("set root doc peer id: {e}")))?;

        let client = Self {
            vault,
            manager,
            root_doc,
            client_id,
            config,
            status: SyncStatus::Disconnected,
            event_tx,
        };

        Ok((client, event_rx))
    }

    pub fn status(&self) -> &SyncStatus {
        &self.status
    }

    /// This device's stable CRDT client id (`m:client_id`).
    pub fn client_id(&self) -> u64 {
        self.client_id
    }

    /// The window manager owning every doc this client touches.
    pub fn manager(&self) -> &Arc<WindowManager> {
        &self.manager
    }

    /// Ensures the window for `key` is open, returning the manager-owned
    /// live instance.
    ///
    /// Opening consults persisted sync_state first (`d:w:{key}` + pending
    /// `u:w:{key}:*` replay), then runs the full pinned open path (pm
    /// replay → reverse remat → forward remat → observers) — see
    /// [`WindowManager::open_window`].
    pub fn ensure_window(
        &self,
        key: &str,
    ) -> std::result::Result<Arc<LoadedWindow>, TransportError> {
        if parse_window_key_str(key).is_none() {
            return Err(TransportError::InvalidWindowKey);
        }
        self.manager
            .open_window(&WindowKey::new(key))
            .map_err(|e| TransportError::Storage(format!("open window {key}: {e}")))
    }

    /// Returns the live window for `key` if loaded — registry lookup only,
    /// never opens.
    pub fn window(&self, key: &str) -> Option<Arc<LoadedWindow>> {
        parse_window_key_str(key)?;
        self.manager.window(&WindowKey::new(key))
    }

    pub fn root_doc(&self) -> &LoroDoc {
        &self.root_doc
    }

    /// Returns the list of window keys from the root doc (set by server).
    pub fn server_windows(&self) -> Vec<String> {
        // `meta.windows` is byte-encoded by the schema helpers
        // (`create_root_doc` / `add_window_to_root`). Decode through the shared
        // `read_window_list` path so the encoding stays consistent — reading it
        // as a `LoroValue::String` silently yields an empty list (ONE-637).
        read_window_list(&self.root_doc)
            .into_iter()
            .map(|k| k.as_str().to_string())
            .collect()
    }

    /// Records the last successful sync timestamp (`m:last_sync`, u64 LE
    /// Unix seconds). Called by the connection when status reaches Synced.
    pub fn mark_synced(&self) -> Result<()> {
        // Saturate to 0 on pre-epoch wall clock — matches the other
        // SystemTime uses in this module.
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.vault.with_write_txn(|wtxn| {
            self.vault
                .store
                .sync_state
                .put(wtxn, KEY_LAST_SYNC, &now_secs.to_le_bytes())?;
            Ok(())
        })
    }

    /// Handles an incoming wire message from the server.
    pub fn handle_server_message(
        &mut self,
        data: &[u8],
    ) -> std::result::Result<Vec<Vec<u8>>, TransportError> {
        if data.is_empty() {
            return Err(TransportError::InvalidPayload("empty message"));
        }

        let tag = data[0];
        let payload = &data[1..];
        let mut responses = Vec::new();

        match tag {
            TAG_SYNC_UPDATE => {
                // Root doc update/snapshot from server — cap before import so a
                // hostile/buggy server cannot force an unbounded allocation.
                // Reuses the bulk-transfer 8 MB cap (ONE-1127).
                if payload.len() > MAX_DECODED_PAYLOAD_BYTES {
                    return Err(TransportError::FrameTooLarge {
                        size: payload.len(),
                        max: MAX_DECODED_PAYLOAD_BYTES,
                    });
                }
                // Import, then persist so the imported state survives
                // restart (d:root).
                self.root_doc
                    .import(payload)
                    .map_err(|_| TransportError::InvalidPayload("root doc import failed"))?;
                self.persist_root_state()
                    .map_err(|e| TransportError::Storage(format!("persist root doc: {e}")))?;
            }
            TAG_AWARENESS => {
                // Server presence broadcast — the client does not track peer
                // presence yet. Ignore instead of surfacing UnknownTag errors
                // for every awareness fan-out (ONE-1127).
            }
            TAG_VERSION_VECTOR => {
                // Server's root VV. Root is server-authoritative, so there is
                // nothing to send back — but the payload must still be valid
                // Loro binary VV bytes. Malformed VV → typed error, fail-closed.
                VersionVector::decode(payload).map_err(|_| TransportError::VersionVectorDecode)?;
            }
            TAG_WINDOW_SYNC => {
                let (window_key, sub_tag, inner) = transport::decode_window_sync(payload)?;
                responses.extend(self.handle_window_sync(window_key, sub_tag, inner)?);
            }
            TAG_BULK_TRANSFER => {
                let (window_key, compressed) = transport::decode_bulk_transfer(payload)?;
                self.handle_bulk_transfer(window_key, compressed)?;
            }
            TAG_BULK_TRANSFER_DONE => {
                let (window_key, doc_state) = transport::decode_bulk_transfer_done(payload)?;
                self.handle_bulk_transfer_done(window_key, doc_state)?;
            }
            _ => return Err(TransportError::UnknownTag(tag)),
        }

        Ok(responses)
    }

    fn handle_window_sync(
        &mut self,
        window_key: &str,
        sub_tag: u8,
        payload: &[u8],
    ) -> std::result::Result<Vec<Vec<u8>>, TransportError> {
        let window = self.ensure_window(window_key)?;
        let doc = &window.doc;

        match sub_tag {
            window_sub_tags::VV_REQUEST => {
                // Peer sent its binary VV (SyncStep1) — reply with the delta it
                // is missing (SyncStep2), then our own VV so it can push its
                // local diff back (the reverse SyncStep1). Malformed VV →
                // typed error, fail-closed: NEVER fall back to a full export.
                let delta = export_updates_since(doc, payload).map_err(map_delta_export_err)?;
                Ok(vec![
                    transport::encode_window_sync(window_key, window_sub_tags::UPDATE, &delta),
                    transport::encode_window_sync(
                        window_key,
                        window_sub_tags::VV_RESPONSE,
                        &doc_version_vector(doc),
                    ),
                ])
            }
            window_sub_tags::UPDATE => {
                // Server sending Loro update bytes — import into the
                // manager-owned live doc. Observer B materializes the
                // change to LMDB synchronously (entities/edges/tombstones).
                //
                // Import-then-persist is deliberate: persisting BEFORE the
                // import would durably append an unvalidated frame as a
                // `u:w:` row, and window load is fail-closed on pending
                // updates — one malformed frame would brick every future
                // open of this window.
                window
                    .doc
                    .import(payload)
                    .map_err(|_| TransportError::InvalidPayload("window import failed"))?;
                // Remote imports never fire Observer A (local-only), so
                // persist the accepted update bytes ourselves: without a
                // u:w: row, remote state — including tombstones, whose LMDB
                // purge already ran — would vanish from the doc on restart.
                if let Err(e) = persist_window_update(&self.vault, window_key, payload) {
                    // Never leave RAM ahead of durable state on a FAILED
                    // persist (client analog of the ONE-1129 server
                    // evict-on-persist-failure): the import advanced this
                    // doc's version vector, so keeping the doc registered
                    // would tell the server — on the next VV exchange —
                    // that we already hold bytes that never became
                    // durable; they would never be re-sent and would
                    // vanish from the doc on restart (tombstones
                    // included). Discard the live window WITHOUT
                    // persisting (a persist would durably commit the
                    // unconfirmed import); the next open reloads from
                    // durable state and the ONE-1127/1128 VV exchange
                    // re-delivers the update.
                    self.manager.discard_window(&WindowKey::new(window_key));
                    return Err(TransportError::Storage(format!(
                        "persist remote update: {e}"
                    )));
                }
                let _ = self.event_tx.send(SyncEvent::WindowUpdated {
                    window_key: window_key.to_string(),
                });
                Ok(Vec::new())
            }
            window_sub_tags::VV_RESPONSE => {
                // Peer's VV answering our VV_REQUEST — export and send only our
                // local diff. Same fail-closed VV decoding as VV_REQUEST.
                let delta = export_updates_since(doc, payload).map_err(map_delta_export_err)?;
                Ok(vec![transport::encode_window_sync(
                    window_key,
                    window_sub_tags::UPDATE,
                    &delta,
                )])
            }
            _ => Ok(Vec::new()),
        }
    }

    fn handle_bulk_transfer(
        &mut self,
        window_key: &str,
        compressed: &[u8],
    ) -> std::result::Result<(), TransportError> {
        // Streaming decompression with size limit to prevent decompression bombs.
        let mut decoder = zstd::Decoder::new(compressed)
            .map_err(|_| TransportError::InvalidPayload("zstd decoder init failed"))?;
        let mut buf = Vec::with_capacity(std::cmp::min(
            compressed.len().saturating_mul(2),
            MAX_DECODED_PAYLOAD_BYTES,
        ));
        let mut chunk = [0u8; 8192];
        loop {
            let n = std::io::Read::read(&mut decoder, &mut chunk)
                .map_err(|_| TransportError::InvalidPayload("zstd decompress failed"))?;
            if n == 0 {
                break;
            }
            if buf.len() + n > MAX_DECODED_PAYLOAD_BYTES {
                return Err(TransportError::FrameTooLarge {
                    size: buf.len() + n,
                    max: MAX_DECODED_PAYLOAD_BYTES,
                });
            }
            buf.extend_from_slice(&chunk[..n]);
        }

        // Persist the in-progress marker (ARCH-0023b key table:
        // `bulk:w:{key}`, device only) so a crash between BulkTransfer and
        // BulkTransferDone is observable on restart.
        let marker_key = format!("bulk:w:{window_key}");
        self.vault
            .with_write_txn(|wtxn| {
                self.vault.store.sync_state.put(wtxn, &marker_key, &[1u8])?;
                Ok(())
            })
            .map_err(|e| TransportError::Storage(format!("persist bulk marker: {e}")))?;

        // The decompressed MessagePack payload (LMDB row application) is
        // deliberately NOT applied here: the Phase-3 server-side sender does
        // not exist yet, and building a speculative applier against an
        // unexercised wire peer is riskier than deferring. Re-ticketed for
        // the M5/M6 Phase-3 work (see ONE-1126 PR body).
        let _ = buf;
        Ok(())
    }

    fn handle_bulk_transfer_done(
        &mut self,
        window_key: &str,
        doc_state: &[u8],
    ) -> std::result::Result<(), TransportError> {
        let marker_key = format!("bulk:w:{window_key}");

        if !doc_state.is_empty() {
            if let Some(window) = self.window(window_key) {
                // Window is live: import through the observed doc so
                // Observer B materializes, then persist the merged state.
                window
                    .doc
                    .import(doc_state)
                    .map_err(|_| TransportError::InvalidPayload("bulk doc state import failed"))?;
                window
                    .persist_state(&self.vault)
                    .map_err(|e| TransportError::Storage(format!("persist bulk window: {e}")))?;
            } else {
                // Window stays ON-DISK: validate the remote snapshot's
                // structure before persisting (fail-closed — a trusted door
                // still validates structure), then write the sync_state
                // rows the next open will load.
                let doc = doc_from_snapshot(doc_state)
                    .map_err(|_| TransportError::InvalidPayload("bulk doc state invalid"))?;
                let vv = doc_version_vector(&doc);
                let doc_key = format!("d:w:{window_key}");
                let sv_key = format!("sv:w:{window_key}");
                let svf_key = format!("svf:w:{window_key}");
                let pending_prefix = format!("u:w:{window_key}:");
                self.vault
                    .with_write_txn(|wtxn| {
                        // sv reflects d:w: alone; only mark it fresh when no
                        // pending local updates sit on top of the snapshot.
                        let has_pending = {
                            let mut iter = self
                                .vault
                                .store
                                .sync_state
                                .prefix_iter(wtxn, &pending_prefix)?;
                            iter.next().transpose()?.is_some()
                        };
                        self.vault.store.sync_state.put(wtxn, &doc_key, doc_state)?;
                        self.vault.store.sync_state.put(wtxn, &sv_key, &vv)?;
                        let svf = if has_pending { 0u8 } else { SVF_FRESH };
                        self.vault.store.sync_state.put(wtxn, &svf_key, &[svf])?;
                        Ok(())
                    })
                    .map_err(|e| TransportError::Storage(format!("persist bulk doc state: {e}")))?;
            }
        }

        // Clear the in-progress marker only after persistence succeeded
        // (fail-closed: a failed persist leaves the marker set for retry).
        self.vault
            .with_write_txn(|wtxn| {
                self.vault.store.sync_state.delete(wtxn, &marker_key)?;
                Ok(())
            })
            .map_err(|e| TransportError::Storage(format!("clear bulk marker: {e}")))?;

        let _ = self.event_tx.send(SyncEvent::BulkTransferComplete {
            window_key: window_key.to_string(),
        });
        Ok(())
    }

    /// Generates initial sync messages for the connection flow.
    ///
    /// Returns messages to send to the server, in wire order:
    /// 1. Protocol-version hello (MUST be the first frame — server checks it)
    /// 2. Root doc VV (so server knows what we have)
    /// 3. Default window VV requests (current + previous month), plus any
    ///    additional already-loaded windows
    ///
    /// All version vectors are Loro binary `VersionVector::encode()` bytes —
    /// the JSON VV encoding is dead (wire break pinned in ONE-1127).
    ///
    /// Fast reconnect (the `sv:`/`svf:` reader): for a window that is not
    /// loaded and whose `svf:w:{key}` flag is fresh, the VV is decoded from
    /// the persisted `sv:w:{key}` StateVector without loading the doc.
    /// Stale or absent state vectors fall back to a full manager open.
    pub fn generate_initial_sync(&self) -> Vec<Vec<u8>> {
        let mut messages = Vec::new();

        // Phase 0: protocol-version hello — first frame on every connection so
        // the server can detect wire breaks before any sync payload flows.
        messages.push(transport::encode_protocol_hello());

        // Phase 1: Send our root VV (empty for new client — server will send snapshot)
        let mut vv_msg = vec![TAG_VERSION_VECTOR];
        vv_msg.extend_from_slice(&doc_version_vector(&self.root_doc));
        messages.push(vv_msg);

        // Phase 2: Default windows for the wall clock now (current +
        // previous), then any other windows already loaded in the manager.
        // Saturate to 0 on pre-epoch wall clock (NTP regression, suspended
        // VM, embedded device with reset RTC). Matches sync/queue.rs
        // push_embed_job.
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut keys: Vec<WindowKey> = Vec::new();
        let mut next = Some(WindowKey::from_timestamp(now_secs));
        for _ in 0..self.config.default_window_count {
            let Some(key) = next else { break };
            next = key.previous_month();
            keys.push(key);
        }
        for key in self.manager.loaded_keys() {
            if !keys.contains(&key) {
                keys.push(key);
            }
        }

        for key in keys {
            match self.window_vv_for_initial_sync(&key) {
                Ok(vv) => {
                    messages.push(transport::encode_window_sync(
                        key.as_str(),
                        window_sub_tags::VV_REQUEST,
                        &vv,
                    ));
                }
                Err(e) => {
                    let _ = self.event_tx.send(SyncEvent::Error(format!(
                        "Initial sync VV for window {key} failed: {e}"
                    )));
                }
            }
        }

        messages
    }

    /// Resolves the wire VV (Loro binary `VersionVector::encode()` bytes)
    /// for one window during initial sync: live doc when loaded; persisted
    /// `sv:w:` when `svf:w:` is fresh (no doc load — the fast-reconnect
    /// path); full manager open otherwise.
    fn window_vv_for_initial_sync(&self, key: &WindowKey) -> Result<Vec<u8>> {
        if let Some(window) = self.manager.window(key) {
            return Ok(doc_version_vector(&window.doc));
        }

        {
            let rtxn = self.vault.store.env.read_txn()?;
            let svf_key = format!("svf:w:{key}");
            let fresh = matches!(
                self.vault.store.sync_state.get(&rtxn, &svf_key)?,
                Some([SVF_FRESH])
            );
            if fresh {
                let sv_key = format!("sv:w:{key}");
                if let Some(sv_raw) = self.vault.store.sync_state.get(&rtxn, &sv_key)? {
                    // Persisted StateVector V1 — decode validates structure
                    // before anything reaches the wire (fail-closed: a
                    // corrupt row falls through to a full doc load instead
                    // of shipping garbage).
                    match VersionVector::decode(sv_raw) {
                        Ok(vv) => return Ok(vv.encode()),
                        Err(e) => {
                            tracing::warn!(
                                window = %key,
                                error = %e,
                                "initial-sync: corrupt persisted state vector — falling back to doc load"
                            );
                        }
                    }
                }
            }
        }

        let window = self.manager.open_window(key)?;
        Ok(doc_version_vector(&window.doc))
    }

    /// Persists the root doc to sync_state: `d:root` snapshot + `sv:root`
    /// state vector + `svf:root` freshness, in one txn.
    fn persist_root_state(&self) -> Result<()> {
        let snapshot = export_snapshot(&self.root_doc)?;
        let vv = doc_version_vector(&self.root_doc);
        self.vault.with_write_txn(|wtxn| {
            self.vault
                .store
                .sync_state
                .put(wtxn, KEY_ROOT_DOC, &snapshot)?;
            self.vault.store.sync_state.put(wtxn, KEY_ROOT_SV, &vv)?;
            self.vault
                .store
                .sync_state
                .put(wtxn, KEY_ROOT_SVF, &[SVF_FRESH])?;
            Ok(())
        })
    }
}

/// Loads the persisted root doc: `d:root` snapshot + pending `u:root:*`
/// replay (ARCH-0023b startup step 1). Fresh doc when nothing is persisted.
fn load_root_doc(vault: &Vault) -> Result<LoroDoc> {
    let rtxn = vault.store.env.read_txn()?;
    let doc = match vault.store.sync_state.get(&rtxn, KEY_ROOT_DOC)? {
        Some(snapshot) => doc_from_snapshot(snapshot)?,
        None => LoroDoc::new(),
    };
    let iter = vault
        .store
        .sync_state
        .prefix_iter(&rtxn, ROOT_UPDATE_PREFIX)?;
    for entry in iter {
        let (_k, v) = entry?;
        doc.import(v).map_err(|source| Error::CrdtDecodeError {
            context: "import pending root update",
            source,
        })?;
    }
    Ok(doc)
}

/// Loads `m:client_id`, minting it once (u64 LE, nonzero) when absent.
///
/// A present-but-malformed row fails closed: silently re-minting would
/// change this device's CRDT identity mid-install.
fn load_or_mint_client_id(vault: &Vault) -> Result<u64> {
    let minted = mint_client_id();
    let mut chosen = minted;
    vault.with_write_txn(
        |wtxn| match vault.store.sync_state.get(wtxn, KEY_CLIENT_ID)? {
            Some(raw) if raw.len() == 8 => {
                chosen = u64::from_le_bytes(raw.try_into().expect("length checked"));
                Ok(())
            }
            Some(_) => Err(Error::CorruptedIndex("sync client_id row")),
            None => {
                vault
                    .store
                    .sync_state
                    .put(wtxn, KEY_CLIENT_ID, &minted.to_le_bytes())?;
                Ok(())
            }
        },
    )?;
    Ok(chosen)
}

/// Mints a random nonzero u64 from the random tail of a UUID (bytes 8..16
/// of a v7 UUID are the random section — the head is a timestamp).
fn mint_client_id() -> u64 {
    loop {
        let uuid = uuid::Uuid::now_v7();
        let tail: [u8; 8] = uuid.as_bytes()[8..16]
            .try_into()
            .expect("uuid tail is 8 bytes");
        let candidate = u64::from_le_bytes(tail);
        if candidate != 0 {
            return candidate;
        }
    }
}

/// Maps a delta-export error onto the transport taxonomy.
///
/// Malformed inbound VV bytes (`CrdtDecodeError`) get the dedicated
/// fail-closed variant; anything else is an export-side failure.
fn map_delta_export_err(e: crate::error::Error) -> TransportError {
    match e {
        crate::error::Error::CrdtDecodeError { .. } => TransportError::VersionVectorDecode,
        _ => TransportError::InvalidPayload("delta export failed"),
    }
}

/// Computes the next backoff delay with exponential growth capped at max.
pub fn next_backoff(current_ms: u32, max_ms: u32) -> u32 {
    std::cmp::min(current_ms.saturating_mul(2), max_ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use loro::ExportMode;

    use crate::sync::bridge::Materializer;

    fn test_manager() -> Arc<WindowManager> {
        let dir = tempfile::tempdir().unwrap();
        let config = crate::types::VaultConfig::device();
        let vault = Arc::new(Vault::open(dir.path(), config).unwrap());
        Arc::new(WindowManager::new(
            vault,
            Arc::new(Materializer::new()),
            "test-user",
        ))
    }

    fn test_client(
        manager: &Arc<WindowManager>,
    ) -> (SyncClient, mpsc::UnboundedReceiver<SyncEvent>) {
        SyncClient::new(Arc::clone(manager), SyncClientConfig::default()).unwrap()
    }

    /// Builds a simulated server-side window doc with the schema containers.
    fn server_window_doc() -> LoroDoc {
        let doc = LoroDoc::new();
        let _ = doc.get_map("entities");
        let _ = doc.get_map("edges");
        let _ = doc.get_map("tombstones");
        doc.commit();
        doc
    }

    #[test]
    fn sync_client_rejects_invalid_window_creation() {
        let manager = test_manager();
        let (client, _rx) = test_client(&manager);
        assert!(matches!(
            client.ensure_window("2026-13"),
            Err(TransportError::InvalidWindowKey)
        ));
        assert!(matches!(
            client.ensure_window("1969-12"),
            Err(TransportError::InvalidWindowKey)
        ));
    }

    #[test]
    fn sync_client_generate_initial_sync() {
        let manager = test_manager();
        let (client, _rx) = test_client(&manager);
        let messages = client.generate_initial_sync();
        // hello + root VV + 2 window VV requests (current + prev)
        assert_eq!(messages.len(), 4);

        // Frame 0: protocol hello — exact wire bytes [tag=3, version=1]
        // (contract literal, ONE-1127). It MUST be the first frame.
        assert_eq!(messages[0], vec![3u8, 1u8]);

        // Frame 1: root VV — Loro binary encoding, decodable, NOT JSON.
        assert_eq!(messages[1][0], TAG_VERSION_VECTOR);
        VersionVector::decode(&messages[1][1..]).expect("root VV must be Loro binary encoding");
        assert!(
            serde_json::from_slice::<serde_json::Value>(&messages[1][1..]).is_err(),
            "the serde_json VV wire encoding is dead (ONE-1127)"
        );

        // Frames 2..: window VV_REQUESTs carrying binary VV payloads.
        for msg in &messages[2..] {
            assert_eq!(msg[0], TAG_WINDOW_SYNC);
            let (key, sub_tag, payload) = transport::decode_window_sync(&msg[1..]).unwrap();
            assert!(parse_window_key_str(key).is_some());
            assert_eq!(sub_tag, window_sub_tags::VV_REQUEST);
            VersionVector::decode(payload).expect("window VV must be Loro binary encoding");
            assert!(
                serde_json::from_slice::<serde_json::Value>(payload).is_err(),
                "the serde_json VV wire encoding is dead (ONE-1127)"
            );
        }
    }

    /// AC6 (ONE-1127): two docs diverge → exchange binary VVs → each imports
    /// ONLY the delta → deep values converge, and each delta payload is
    /// asserted smaller than the corresponding `all_updates` export.
    #[test]
    fn binary_vv_delta_round_trip_converges_with_smaller_payloads() {
        let manager = test_manager();
        let (mut client, _rx) = test_client(&manager);
        let key = "2026-03";
        client.ensure_window(key).unwrap();

        // Shared chunky base so all_updates is meaningfully larger than a delta.
        let server_doc = server_window_doc();
        server_doc
            .get_map("entities")
            .insert("base", vec![7u8; 2048].as_slice())
            .unwrap();
        server_doc.commit();
        let base = server_doc.export(ExportMode::all_updates()).unwrap();
        let base_msg = transport::encode_window_sync(key, window_sub_tags::UPDATE, &base);
        assert!(client.handle_server_message(&base_msg).unwrap().is_empty());

        // Diverge: client writes one key, server writes another.
        let client_window = client.window(key).unwrap();
        client_window
            .doc
            .get_map("entities")
            .insert("client-only", b"c".as_slice())
            .unwrap();
        client_window.doc.commit();
        server_doc
            .get_map("entities")
            .insert("server-only", b"s".as_slice())
            .unwrap();
        server_doc.commit();

        // Server → client SyncStep1: VV_REQUEST carrying the server's binary VV.
        let request = transport::encode_window_sync(
            key,
            window_sub_tags::VV_REQUEST,
            &server_doc.oplog_vv().encode(),
        );
        let responses = client.handle_server_message(&request).unwrap();
        assert_eq!(
            responses.len(),
            2,
            "VV_REQUEST → [UPDATE delta, VV_RESPONSE]"
        );

        // responses[0]: the client→server delta — a true delta, not all_updates.
        let (k0, sub0, client_delta) = transport::decode_window_sync(&responses[0][1..]).unwrap();
        assert_eq!(k0, key);
        assert_eq!(sub0, window_sub_tags::UPDATE);
        let client_all = client
            .window(key)
            .unwrap()
            .doc
            .export(ExportMode::all_updates())
            .unwrap();
        assert!(
            client_delta.len() < client_all.len(),
            "delta ({}) must be smaller than all_updates ({}) for the diverged case",
            client_delta.len(),
            client_all.len()
        );
        server_doc.import(client_delta).unwrap();

        // responses[1]: client VV for the reverse leg.
        let (k1, sub1, client_vv) = transport::decode_window_sync(&responses[1][1..]).unwrap();
        assert_eq!(k1, key);
        assert_eq!(sub1, window_sub_tags::VV_RESPONSE);
        VersionVector::decode(client_vv).expect("VV_RESPONSE payload must be binary VV");

        // Server computes ITS delta via the same single delta-export entry point.
        let server_delta = export_updates_since(&server_doc, client_vv).unwrap();
        let server_all = server_doc.export(ExportMode::all_updates()).unwrap();
        assert!(
            server_delta.len() < server_all.len(),
            "server delta ({}) must be smaller than all_updates ({})",
            server_delta.len(),
            server_all.len()
        );
        let update_msg = transport::encode_window_sync(key, window_sub_tags::UPDATE, &server_delta);
        assert!(
            client
                .handle_server_message(&update_msg)
                .unwrap()
                .is_empty()
        );

        // Deep-value convergence on both sides.
        assert_eq!(
            client.window(key).unwrap().doc.get_deep_value(),
            server_doc.get_deep_value()
        );
    }

    #[test]
    fn vv_response_triggers_local_diff_update() {
        // Client sent VV_REQUEST earlier; the server's VV_RESPONSE must be
        // consumed (not a no-op) — the client computes and sends its diff.
        let manager = test_manager();
        let (mut client, _rx) = test_client(&manager);
        let key = "2026-04";
        client.ensure_window(key).unwrap();
        let client_window = client.window(key).unwrap();
        client_window
            .doc
            .get_map("entities")
            .insert("local", b"x".as_slice())
            .unwrap();
        client_window.doc.commit();

        let server_doc = server_window_doc();
        let msg = transport::encode_window_sync(
            key,
            window_sub_tags::VV_RESPONSE,
            &server_doc.oplog_vv().encode(),
        );
        let responses = client.handle_server_message(&msg).unwrap();
        assert_eq!(responses.len(), 1, "VV_RESPONSE → [UPDATE local diff]");

        let (k, sub, delta) = transport::decode_window_sync(&responses[0][1..]).unwrap();
        assert_eq!(k, key);
        assert_eq!(sub, window_sub_tags::UPDATE);
        server_doc.import(delta).unwrap();
        assert_eq!(
            client.window(key).unwrap().doc.get_deep_value(),
            server_doc.get_deep_value()
        );
    }

    #[test]
    fn malformed_vv_payloads_fail_closed() {
        // The dead JSON encoding and arbitrary garbage must both be REJECTED
        // with the typed error — never silently treated as an empty VV (an
        // empty-VV fallback would ship the full history to a malformed peer).
        let manager = test_manager();
        let (mut client, _rx) = test_client(&manager);

        let json_vv: &[u8] = b"{}";
        let garbage: &[u8] = &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

        for payload in [json_vv, garbage] {
            let req =
                transport::encode_window_sync("2026-03", window_sub_tags::VV_REQUEST, payload);
            assert!(
                matches!(
                    client.handle_server_message(&req),
                    Err(TransportError::VersionVectorDecode)
                ),
                "VV_REQUEST with malformed VV must fail closed"
            );

            let resp =
                transport::encode_window_sync("2026-03", window_sub_tags::VV_RESPONSE, payload);
            assert!(
                matches!(
                    client.handle_server_message(&resp),
                    Err(TransportError::VersionVectorDecode)
                ),
                "VV_RESPONSE with malformed VV must fail closed"
            );

            let mut root = vec![TAG_VERSION_VECTOR];
            root.extend_from_slice(payload);
            assert!(
                matches!(
                    client.handle_server_message(&root),
                    Err(TransportError::VersionVectorDecode)
                ),
                "root VV with malformed payload must fail closed"
            );
        }
    }

    #[test]
    fn awareness_broadcast_is_ignored() {
        let manager = test_manager();
        let (mut client, mut rx) = test_client(&manager);
        let mut msg = vec![TAG_AWARENESS];
        msg.extend_from_slice(br#"{"online":true,"typing":false,"device_name":"mac"}"#);

        let responses = client.handle_server_message(&msg).unwrap();
        assert!(
            responses.is_empty(),
            "awareness must be ignored, not echoed"
        );
        assert!(
            rx.try_recv().is_err(),
            "awareness must not emit error events"
        );
    }

    #[test]
    fn oversized_root_update_fails_closed() {
        let manager = test_manager();
        let (mut client, _rx) = test_client(&manager);
        let mut msg = vec![TAG_SYNC_UPDATE];
        msg.extend_from_slice(&vec![0u8; MAX_DECODED_PAYLOAD_BYTES + 1]);

        assert!(matches!(
            client.handle_server_message(&msg),
            Err(TransportError::FrameTooLarge { size, max })
                if size == MAX_DECODED_PAYLOAD_BYTES + 1 && max == MAX_DECODED_PAYLOAD_BYTES
        ));
    }

    #[test]
    fn sync_client_mints_client_id_once_and_keeps_it_stable() {
        let manager = test_manager();
        let (client, _rx) = test_client(&manager);

        let raw = manager
            .vault()
            .sync_state_get(KEY_CLIENT_ID)
            .unwrap()
            .expect("m:client_id must be minted on first client construction");
        assert_eq!(raw.len(), 8, "m:client_id must be u64 LE (8 bytes)");
        let persisted = u64::from_le_bytes(raw.try_into().unwrap());
        assert_ne!(persisted, 0);
        assert_eq!(client.client_id(), persisted);
        assert_eq!(
            client.root_doc().peer_id(),
            persisted,
            "stable client id must pin the root doc's CRDT peer id"
        );

        // Second client over the same vault: same identity, no re-mint.
        let (client2, _rx2) = test_client(&manager);
        assert_eq!(client2.client_id(), persisted);
        assert_eq!(
            manager
                .vault()
                .sync_state_get(KEY_CLIENT_ID)
                .unwrap()
                .unwrap(),
            persisted.to_le_bytes()
        );
    }

    #[test]
    fn sync_client_fails_closed_on_malformed_client_id_row() {
        let manager = test_manager();
        manager
            .vault()
            .sync_state_put(KEY_CLIENT_ID, &[1, 2, 3])
            .unwrap();

        let result = SyncClient::new(Arc::clone(&manager), SyncClientConfig::default());
        assert!(
            matches!(result, Err(Error::CorruptedIndex("sync client_id row"))),
            "malformed m:client_id must not be silently re-minted"
        );
        // The corrupt row is left for diagnosis, not overwritten.
        assert_eq!(
            manager
                .vault()
                .sync_state_get(KEY_CLIENT_ID)
                .unwrap()
                .unwrap(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn sync_client_mark_synced_writes_last_sync_row() {
        let manager = test_manager();
        let (client, _rx) = test_client(&manager);

        assert!(
            manager
                .vault()
                .sync_state_get(KEY_LAST_SYNC)
                .unwrap()
                .is_none()
        );
        client.mark_synced().unwrap();

        let raw = manager
            .vault()
            .sync_state_get(KEY_LAST_SYNC)
            .unwrap()
            .expect("m:last_sync must be written");
        assert_eq!(raw.len(), 8, "m:last_sync must be u64 LE (8 bytes)");
        let ts = u64::from_le_bytes(raw.try_into().unwrap());
        assert!(ts > 1_700_000_000, "timestamp should be wall-clock seconds");
    }

    #[test]
    fn sync_client_filters_invalid_server_windows() {
        let manager = test_manager();
        let (client, _rx) = test_client(&manager);
        let meta = client.root_doc.get_map("meta");
        // Schema helpers byte-encode `meta.windows`; mirror that here so the
        // test exercises the real on-disk encoding (ONE-637).
        meta.insert("windows", "2026-03,1969-12,2026-13,2026-04".as_bytes())
            .unwrap();
        client.root_doc.commit();

        let windows = client.server_windows();
        assert_eq!(windows, vec!["2026-03".to_string(), "2026-04".to_string()]);
    }

    #[test]
    fn server_windows_reads_schema_written_byte_encoded_root_doc() {
        // Regression for ONE-637: schema::create_root_doc writes meta.windows
        // as bytes (LoroValue::Binary). server_windows() must decode it via the
        // same byte path the schema helpers use.
        use crate::sync::loro_support::export_snapshot;
        use crate::sync::schema::create_root_doc;

        let manager = test_manager();
        let (mut client, _rx) = test_client(&manager);

        let server_root = create_root_doc(
            "user-1",
            "vault-1",
            &[WindowKey::new("2026-01"), WindowKey::new("2026-02")],
        );
        let snapshot = export_snapshot(&server_root).unwrap();

        let mut msg = vec![TAG_SYNC_UPDATE];
        msg.extend_from_slice(&snapshot);
        client.handle_server_message(&msg).unwrap();

        assert_eq!(
            client.server_windows(),
            vec!["2026-01".to_string(), "2026-02".to_string()],
        );
    }

    #[test]
    fn backoff_calculation() {
        assert_eq!(next_backoff(1_000, 60_000), 2_000);
        assert_eq!(next_backoff(2_000, 60_000), 4_000);
        assert_eq!(next_backoff(32_000, 60_000), 60_000);
        assert_eq!(next_backoff(60_000, 60_000), 60_000);
    }
}
