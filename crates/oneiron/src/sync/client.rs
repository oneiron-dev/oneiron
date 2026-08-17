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
//!   once and stable per install (mint lives in `crate::identity`, OD-2).
//! - `m:device_sk` / `m:device_pk` — this device's Ed25519 attestation
//!   keypair (32 B each; ONE-1140, OD-2), minted alongside the client id.
//! - `ls:{vault_id_hex}:{client_id_hex}` — device-lease registry mirror rows
//!   (66 B pinned record, ONE-1140 OD-3/OD-4): full-mirrored from the root
//!   doc's `leases` map in the SAME txn as every root persist.
//! - `m:last_sync` — last successful sync timestamp (u64 LE, 8 bytes).
//! - `bulk:w:{key}` — BulkTransfer in-progress marker (device only);
//!   cleared when `BulkTransferDone` persistence succeeds.
//! - `sv:w:{key}` / `svf:w:{key}` — read by the fast-reconnect path in
//!   [`SyncClient::generate_initial_sync`]: a fresh flag lets the client
//!   answer the VV exchange from the persisted state vector without
//!   loading the window doc.

use std::cmp::Ordering::{Equal, Less};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

use loro::{LoroDoc, VersionVector};
use tokio::sync::mpsc;

use crate::Vault;
use crate::batch::export::{
    StagedVaultImport, VaultImportConfirmation, VaultImportStageReceipt, VaultImportStageStatus,
};
use crate::error::{Error, Result, SyncConfigField, SyncEngineContext, SyncProtocolValidation};
use crate::sync::bridge::persist_window_update;
use crate::sync::loro_support::{
    doc_from_snapshot, doc_version_vector, export_snapshot, export_updates_since,
};
use crate::sync::manager::WindowManager;
use crate::sync::quarantine;
use crate::sync::schema::{create_window_doc, read_window_list};
use crate::sync::selector::{
    FederationAdmissionRole, SyncSelector, admit_federated_window_update,
    encode_selector_vv_request,
};
use crate::sync::transport::{
    self, LEASE_STATUS_GRANTED, MAX_DECODED_PAYLOAD_BYTES, TAG_BULK_TRANSFER,
    TAG_BULK_TRANSFER_DONE, TAG_EPHEMERAL, TAG_LEASE_GRANTED, TAG_SYNC_UPDATE, TAG_VERSION_VECTOR,
    TAG_WINDOW_SYNC, TransportError, window_sub_tags,
};
use crate::sync::types::{WindowKey, parse_window_key_str};
use crate::sync::window::{LoadedWindow, apply_pending_window_updates, load_window_from_state};
use crate::sync::{
    EphemeralEventTrigger, EphemeralStore, EphemeralStoreEvent, LoroValue, Subscription,
};

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
/// install. The mint lives in `crate::identity` (ONE-1140, OD-2); this
/// test-side literal pins the row key independently of that module.
#[cfg(test)]
const KEY_CLIENT_ID: &str = "m:client_id";
/// Last successful sync timestamp (u64 LE, 8 bytes).
const KEY_LAST_SYNC: &str = "m:last_sync";

/// `svf:*` byte meaning "the persisted `sv:*` reflects the full doc state".
const SVF_FRESH: u8 = 1;

// Serialize staged-import admission and terminal receipt transition within a process.
// The durable reread remains the cross-process guard when a true CAS is unavailable.
#[cfg(feature = "sync")]
static STAGED_IMPORT_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[cfg(test)]
static STOP_AFTER_STAGED_IMPORT: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
pub fn stop_after_staged_import_once() { STOP_AFTER_STAGED_IMPORT.store(true, AtomicOrdering::SeqCst); }
#[cfg(test)]
pub fn clear_stop_after_staged_import() { STOP_AFTER_STAGED_IMPORT.store(false, AtomicOrdering::SeqCst); }

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
    /// Ephemeral state inactivity timeout in milliseconds. Default: 30s.
    pub ephemeral_timeout_ms: i64,
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
            ephemeral_timeout_ms: 30_000,
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
    WindowUpdated {
        window_key: String,
    },
    BulkTransferComplete {
        window_key: String,
    },
    /// The server rejected this device's lease request (ONE-1140: binding
    /// conflict or revoked binding). Sync PROCEEDS — fail-closed lives at
    /// the replay doors (peers quarantine this device's NEW receipts), not
    /// the pipe.
    LeaseDenied {
        client_id: u64,
    },
    EphemeralChanged {
        origin: EphemeralChangeOrigin,
        added: Vec<String>,
        updated: Vec<String>,
        removed: Vec<String>,
    },
    Error(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EphemeralChangeOrigin {
    Local,
    Remote,
    Timeout,
}

/// Client-side sync engine.
pub struct SyncClient {
    vault: Arc<Vault>,
    manager: Arc<WindowManager>,
    root_doc: LoroDoc,
    client_id: u64,
    /// This device's Ed25519 attestation key (ONE-1140, OD-2): signs the
    /// lease-request proof of possession on every connect. Receipt signing
    /// happens vault-side at mint, not here.
    device_signing_key: ed25519_dalek::SigningKey,
    config: SyncClientConfig,
    /// Last server VV observed per window from `VV_REQUEST` / `VV_RESPONSE`
    /// frames. This is the convergence witness (ONE-1128): the offline queue
    /// may only be cleared once the server's OWN vv proves it holds every op
    /// the local doc holds.
    server_vvs: HashMap<String, VersionVector>,
    ephemeral_store: EphemeralStore,
    _ephemeral_subscription: Subscription,
    status: SyncStatus,
    pub(crate) event_tx: mpsc::UnboundedSender<SyncEvent>,
}

impl SyncClient {
    /// Creates a new sync client over manager-owned windows.
    ///
    /// Loads persisted client state first (ARCH-0023b startup step 1): the
    /// device identity — `m:client_id` (minted once if absent) plus the
    /// `m:device_sk`/`m:device_pk` attestation keypair (ONE-1140, OD-2) —
    /// then the root doc from `d:root` + pending `u:root:*` replay.
    /// Malformed identity rows fail closed — silently re-minting would
    /// change this device's CRDT identity mid-install.
    pub fn new(
        manager: Arc<WindowManager>,
        config: SyncClientConfig,
    ) -> Result<(Self, mpsc::UnboundedReceiver<SyncEvent>)> {
        if config.ephemeral_timeout_ms <= 0 {
            return Err(Error::sync_protocol(
                SyncProtocolValidation::InvalidConfig {
                    field: SyncConfigField::EphemeralTimeoutMs,
                },
            ));
        }

        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let vault = Arc::clone(manager.vault());

        let identity = crate::identity::ensure_device_identity(&vault)?;
        let client_id = identity.client_id;
        let root_doc = load_root_doc(&vault)?;
        // The client never authors root ops in production (meta.windows is
        // server-write-only), so pinning the stable client id as the root
        // doc's Loro peer id is safe. Window docs keep Loro-random peer ids
        // for now: reusing a stable peer id after sync_state loss would
        // restart its op counter and mint duplicate (peer, counter) op ids
        // — CRDT corruption. Revisit with VV/convergence (M4-11/12).
        root_doc
            .set_peer_id(client_id)
            .map_err(|e| Error::sync_engine(SyncEngineContext::LoroSetPeerId, e))?;

        let ephemeral_store = EphemeralStore::new(config.ephemeral_timeout_ms);
        let ephemeral_event_tx = event_tx.clone();
        let ephemeral_subscription =
            ephemeral_store.subscribe(Box::new(move |event: &EphemeralStoreEvent| {
                let _ = ephemeral_event_tx.send(SyncEvent::EphemeralChanged {
                    origin: match event.by {
                        EphemeralEventTrigger::Local => EphemeralChangeOrigin::Local,
                        EphemeralEventTrigger::Import => EphemeralChangeOrigin::Remote,
                        EphemeralEventTrigger::Timeout => EphemeralChangeOrigin::Timeout,
                    },
                    added: event.added.as_ref().clone(),
                    updated: event.updated.as_ref().clone(),
                    removed: event.removed.as_ref().clone(),
                });
                true
            }));

        let client = Self {
            vault,
            manager,
            root_doc,
            client_id,
            device_signing_key: identity.signing_key,
            config,
            server_vvs: HashMap::new(),
            ephemeral_store,
            _ephemeral_subscription: ephemeral_subscription,
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

    /// Reads the current non-expired ephemeral value for `key`.
    pub fn ephemeral(&self, key: &str) -> Option<LoroValue> {
        self.ephemeral_store.get(key)
    }

    /// Returns all currently stored non-deleted ephemeral keys.
    pub fn ephemeral_keys(&self) -> Vec<String> {
        self.ephemeral_store.keys()
    }

    /// Sets a local ephemeral key and returns the wire frame to send.
    pub fn set_ephemeral(
        &self,
        key: &str,
        value: impl Into<LoroValue>,
    ) -> std::result::Result<Vec<u8>, TransportError> {
        self.ephemeral_store.set(key, value);
        transport::encode_ephemeral(&self.ephemeral_store.encode(key)).into_result()
    }

    /// Deletes a local ephemeral key and returns the wire frame to send.
    pub fn delete_ephemeral(&self, key: &str) -> std::result::Result<Vec<u8>, TransportError> {
        self.ephemeral_store.delete(key);
        transport::encode_ephemeral(&self.ephemeral_store.encode(key)).into_result()
    }

    /// Runs the Rust-side `EphemeralStore` timeout housekeeping tick.
    pub fn remove_outdated_ephemeral(&self) {
        self.ephemeral_store.remove_outdated();
    }

    /// Returns the list of window keys from the root doc (set by server).
    pub fn server_windows(&self) -> Vec<String> {
        // `meta.windows` is encoded by the schema helpers (`create_root_doc` /
        // `add_window_to_root`). Decode through the shared `read_window_list`
        // path so the client stays in lockstep with schema-owned changes.
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
            .map_or(0, |d| d.as_secs());
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
                let frontiers_before = self.root_doc.state_frontiers();
                self.root_doc
                    .import(payload)
                    .map_err(|_| TransportError::InvalidPayload("root doc import failed"))?;
                if let Err(err) = self.persist_root_state() {
                    if let Err(revert_err) = self.root_doc.revert_to(&frontiers_before) {
                        return Err(TransportError::Storage(format!(
                            "persist root doc: {err}; root revert after import persist failure: {revert_err}"
                        )));
                    }
                    let restored = load_root_doc(&self.vault).map_err(|reload_err| {
                        TransportError::Storage(format!(
                            "persist root doc: {err}; reload root doc after persist failure: {reload_err}"
                        ))
                    })?;
                    restored.set_peer_id(self.client_id).map_err(|peer_err| {
                        TransportError::Storage(format!(
                            "persist root doc: {err}; restore root peer id after persist failure: {peer_err}"
                        ))
                    })?;
                    self.root_doc = restored;
                    return Err(TransportError::Storage(format!("persist root doc: {err}")));
                }
            }
            TAG_EPHEMERAL => {
                if payload.len() > MAX_DECODED_PAYLOAD_BYTES {
                    return Err(TransportError::FrameTooLarge {
                        size: payload.len(),
                        max: MAX_DECODED_PAYLOAD_BYTES,
                    });
                }
                self.ephemeral_store
                    .apply(payload)
                    .map_err(|_| TransportError::InvalidPayload("ephemeral import failed"))?;
            }
            TAG_LEASE_GRANTED => {
                // ONE-1140 (OD-5): the server's ack for this connect's lease
                // request. Exhaustive frame validation; a frame echoing a
                // DIFFERENT client id is a protocol violation (the server
                // direct-replies to the requester), fail closed.
                let (status, client_id, expires_at) = transport::decode_lease_granted(payload)?;
                if client_id != self.client_id {
                    return Err(TransportError::InvalidPayload(
                        "LeaseGranted echoes a foreign client id",
                    ));
                }
                if status == LEASE_STATUS_GRANTED {
                    tracing::debug!(
                        client_id = format!("{client_id:016x}"),
                        expires_at,
                        "sync: lease granted/renewed"
                    );
                } else {
                    // Rejection is surfaced as a typed event and sync
                    // PROCEEDS: fail-closed lives at the replay doors
                    // (peers quarantine this device's NEW receipts), not
                    // the pipe.
                    tracing::warn!(
                        client_id = format!("{client_id:016x}"),
                        "sync: lease request REJECTED (binding conflict or revoked)"
                    );
                    let _ = self.event_tx.send(SyncEvent::LeaseDenied { client_id });
                }
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
        match sub_tag {
            window_sub_tags::VV_REQUEST => {
                // Peer sent its binary VV (SyncStep1) — reply with the delta it
                // is missing (SyncStep2), then our own VV so it can push its
                // local diff back (the reverse SyncStep1). Malformed VV →
                // typed error, fail-closed: NEVER fall back to a full export.
                let server_vv = VersionVector::decode(payload)
                    .map_err(|_| TransportError::VersionVectorDecode)?;
                let window = self.ensure_window(window_key)?;
                let doc = &window.doc;
                let delta = crate::sync::window::export_window_updates_since(
                    &self.vault,
                    &window.key,
                    doc,
                    payload,
                )
                .map_err(map_delta_export_err)?;
                let responses = vec![
                    transport::encode_window_sync(window_key, window_sub_tags::UPDATE, &delta)
                        .into_result()?,
                    transport::encode_window_sync(
                        window_key,
                        window_sub_tags::VV_RESPONSE,
                        &doc_version_vector(doc),
                    )
                    .into_result()?,
                ];
                // Record the server VV only after a fully valid exchange — it
                // becomes the convergence witness for this window (ONE-1128).
                self.server_vvs.insert(window_key.to_string(), server_vv);
                Ok(responses)
            }
            window_sub_tags::UPDATE => {
                if payload.len() > MAX_DECODED_PAYLOAD_BYTES {
                    return Err(TransportError::FrameTooLarge {
                        size: payload.len(),
                        max: MAX_DECODED_PAYLOAD_BYTES,
                    });
                }
                let window = self.ensure_window(window_key)?;
                self.import_accepted_window_update(window_key, &window, payload)?;
                Ok(Vec::new())
            }
            window_sub_tags::VV_RESPONSE => {
                // Peer's VV answering our VV_REQUEST — export and send only our
                // local diff. Same fail-closed VV decoding as VV_REQUEST.
                let server_vv = VersionVector::decode(payload)
                    .map_err(|_| TransportError::VersionVectorDecode)?;
                let window = self.ensure_window(window_key)?;
                let doc = &window.doc;
                let delta = crate::sync::window::export_window_updates_since(
                    &self.vault,
                    &window.key,
                    doc,
                    payload,
                )
                .map_err(map_delta_export_err)?;
                let responses = vec![
                    transport::encode_window_sync(window_key, window_sub_tags::UPDATE, &delta)
                        .into_result()?,
                ];
                self.server_vvs.insert(window_key.to_string(), server_vv);
                Ok(responses)
            }
            _ => Ok(Vec::new()),
        }
    }

    /// Builds a selector request frame for a selector-capable caller.
    ///
    /// This is deliberately pure: a generic `UPDATE` response has no selector
    /// discriminator, so `handle_window_sync` cannot safely classify the next
    /// same-window update as federated. A selector-capable caller that has
    /// explicit member/guest context must route the selected response bytes
    /// through [`SyncClient::import_federated_selector_window_update`].
    pub fn federated_selector_vv_request(
        &self,
        window_key: &str,
        selector: &SyncSelector,
        remote_vv: &[u8],
    ) -> std::result::Result<Vec<u8>, TransportError> {
        let key = WindowKey::try_new(window_key).ok_or(TransportError::InvalidWindowKey)?;
        let payload = encode_selector_vv_request(selector, remote_vv)
            .map_err(|_| TransportError::InvalidPayload("sync selector request encode failed"))?;
        let frame = transport::encode_window_sync(
            key.as_str(),
            window_sub_tags::SELECTOR_VV_REQUEST,
            &payload,
        )
        .into_result()?;
        Ok(frame)
    }

    /// Imports a selector response whose caller already bound the request to
    /// an explicit member/guest admission role.
    ///
    /// The role is explicit; it is not inferred from grant role names, and it
    /// is intentionally not stored as global "next update" state because
    /// same-window full-window updates share the same wire `UPDATE` tag.
    pub fn import_federated_selector_window_update(
        &mut self,
        window_key: &str,
        update: &[u8],
        role: FederationAdmissionRole,
    ) -> std::result::Result<(), TransportError> {
        self.import_federated_window_update(window_key, update, role)
    }

    /// Imports a member/guest federation update after applying the local
    /// federation admission gate.
    ///
    /// Full-window sync continues to call the ordinary `UPDATE` arm directly.
    /// Selector/federation callers that can identify member/guest bytes should
    /// enter through this seam so claim entities are re-stamped and admitted
    /// exactly once before the shared observed-doc import/materialization path.
    pub fn import_federated_window_update(
        &mut self,
        window_key: &str,
        update: &[u8],
        role: FederationAdmissionRole,
    ) -> std::result::Result<(), TransportError> {
        if update.len() > MAX_DECODED_PAYLOAD_BYTES {
            return Err(TransportError::FrameTooLarge {
                size: update.len(),
                max: MAX_DECODED_PAYLOAD_BYTES,
            });
        }
        let key = WindowKey::try_new(window_key).ok_or(TransportError::InvalidWindowKey)?;
        let admitted = admit_federated_window_update(&self.vault, &key, update, role)
            .map_err(map_federated_admission_err)?;
        let window = self.ensure_window(window_key)?;
        self.import_accepted_window_update(window_key, &window, &admitted)
    }

    pub fn confirm_staged_vault_import(
        &mut self,
        staged: StagedVaultImport,
        confirmation: VaultImportConfirmation,
    ) -> std::result::Result<VaultImportStageReceipt, TransportError> {
        let _admission_guard = STAGED_IMPORT_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .map_err(|_| TransportError::Storage("staged import lock poisoned".into()))?;
        if confirmation.receipt_id != staged.receipt.receipt_id
            || confirmation.confirmed_at_secs == 0
        {
            return Err(TransportError::InvalidPayload("confirmation mismatch"));
        }
        let durable = crate::batch::export::vault_import_stage_receipt(&self.vault, &confirmation.receipt_id)
            .map_err(|_| TransportError::Storage("receipt unreadable".into()))?
            .ok_or(TransportError::InvalidPayload("missing durable pending receipt"))?;
        {
            if durable.status == VaultImportStageStatus::Confirmed {
                if durable.confirmed_by == Some(confirmation.actor)
                    && durable.confirmed_at_secs == Some(confirmation.confirmed_at_secs)
                {
                    return Ok(durable);
                }
                return Err(TransportError::InvalidPayload("conflicting confirmation"));
            }
            if durable.status == VaultImportStageStatus::Failed { return Err(TransportError::InvalidPayload("failed staged import")); }
            if durable.status != VaultImportStageStatus::Pending { return Err(TransportError::InvalidPayload("receipt not pending")); }
            if durable.receipt_id != staged.receipt.receipt_id || durable.manifest_digest != staged.receipt.manifest_digest || durable.remote_update_digest != staged.receipt.remote_update_digest || durable.admitted_update_digest != staged.receipt.admitted_update_digest || durable.window_key != staged.receipt.window_key || durable.source != staged.receipt.source || durable.role != staged.receipt.role { return Err(TransportError::InvalidPayload("receipt identity mismatch")); }
        }
        // A durable Pending may only be advanced by the matching Pending stage.
        // In particular, never turn an in-crate fabricated Confirmed stage into
        // phantom success while the durable ledger is still Pending.
        if staged.receipt.status != VaultImportStageStatus::Pending {
            return Err(TransportError::InvalidPayload("staged receipt status mismatch"));
        }
        if staged.admitted_update.len() > MAX_DECODED_PAYLOAD_BYTES { return Err(TransportError::FrameTooLarge { size: staged.admitted_update.len(), max: MAX_DECODED_PAYLOAD_BYTES }); }
        let expected = durable.admitted_update_digest.ok_or(TransportError::InvalidPayload("missing durable admitted update digest"))?;
        let actual = *blake3::hash(&staged.admitted_update).as_bytes();
        if actual != expected { return Err(TransportError::InvalidPayload("admitted update digest mismatch")); }
        let window = self.ensure_window(&durable.window_key)?;
        self.import_accepted_window_update(
            &durable.window_key,
            &window,
            &staged.admitted_update,
        )?;
        #[cfg(test)]
        if STOP_AFTER_STAGED_IMPORT.swap(false, AtomicOrdering::SeqCst) {
            return Err(TransportError::Storage("test stop after staged import".into()));
        }
        let expected_receipt = durable;
        let mut receipt = expected_receipt.clone();
        receipt.status = VaultImportStageStatus::Confirmed;
        receipt.confirmed_by = Some(confirmation.actor);
        receipt.confirmed_at_secs = Some(confirmation.confirmed_at_secs);
        if crate::batch::export::vault_import_confirm_if_pending(&self.vault, &expected_receipt, &receipt)
            .map_err(|e| TransportError::Storage(e.to_string()))?
        {
            return Ok(receipt);
        }
        // A different writer won the durable CAS. Return the idempotent result
        // only when it chose the same actor/time; otherwise fail closed.
        let current = crate::batch::export::vault_import_stage_receipt(&self.vault, &confirmation.receipt_id)
            .map_err(|_| TransportError::Storage("receipt reread failed".into()))?
            .ok_or(TransportError::InvalidPayload("receipt disappeared"))?;
        if current.status == VaultImportStageStatus::Confirmed
            && current.confirmed_by == Some(confirmation.actor)
            && current.confirmed_at_secs == Some(confirmation.confirmed_at_secs)
        {
            Ok(current)
        } else {
            Err(TransportError::InvalidPayload("receipt terminal transition raced"))
        }
    }

    fn import_accepted_window_update(
        &mut self,
        window_key: &str,
        window: &LoadedWindow,
        payload: &[u8],
    ) -> std::result::Result<(), TransportError> {
        // Server sending Loro update bytes — import into the manager-owned
        // live doc. Observer B materializes the change to LMDB synchronously
        // (entities/edges/tombstones).
        //
        // Import-then-persist is deliberate: persisting BEFORE the import
        // would durably append an unvalidated frame as a `u:w:` row, and
        // window load is fail-closed on pending updates — one malformed frame
        // would brick every future open of this window.
        let vv_before = window.doc.oplog_vv();
        window
            .doc
            .import(payload)
            .map_err(|_| TransportError::InvalidPayload("window import failed"))?;
        let key = WindowKey::new(window_key);
        // A no-op import can still reveal a same-process durability gap:
        // compare the live doc with exactly what restart would load from
        // `d:w:` + surviving `u:w:` rows, then heal only the missing live-doc
        // delta.
        if window.doc.oplog_vv() == vv_before {
            let durable_doc = match load_window_from_state(&self.vault, "local", &key) {
                Ok(doc) => doc,
                Err(Error::WindowNotFound { .. }) => {
                    let doc = create_window_doc("local", &key);
                    if let Err(e) = apply_pending_window_updates(&self.vault, &doc, &key) {
                        self.manager.discard_window(&key);
                        return Err(TransportError::Storage(format!(
                            "load durable window updates: {e}"
                        )));
                    }
                    doc
                }
                Err(e) => {
                    self.manager.discard_window(&key);
                    return Err(TransportError::Storage(format!(
                        "load durable window state: {e}"
                    )));
                }
            };
            let live_vv = window.doc.oplog_vv();
            let durable_vv = durable_doc.oplog_vv();
            if matches!(live_vv.partial_cmp(&durable_vv), Some(Less | Equal)) {
                return Ok(());
            }
            let fr_key = format!("fr:w:{window_key}");
            match self.vault.sync_state_get(&fr_key) {
                Ok(Some(_)) => {
                    self.manager.discard_window(&key);
                    return Err(TransportError::Storage(
                        "post-scrub echo deferred to full resync".to_string(),
                    ));
                }
                Ok(None) => {}
                Err(e) => {
                    self.manager.discard_window(&key);
                    return Err(TransportError::Storage(format!(
                        "read full-resync marker: {e}"
                    )));
                }
            }
            let missing = match export_updates_since(&window.doc, &doc_version_vector(&durable_doc))
            {
                Ok(missing) => missing,
                Err(e) => {
                    self.manager.discard_window(&key);
                    return Err(map_delta_export_err(e));
                }
            };
            if let Err(e) = persist_window_update(&self.vault, window_key, &missing) {
                self.manager.discard_window(&key);
                return Err(TransportError::Storage(format!(
                    "persist live durable delta: {e}"
                )));
            }
            return Ok(());
        }
        // Remote imports never fire Observer A (local-only), so persist the
        // accepted update bytes ourselves: without a u:w: row, remote state —
        // including tombstones, whose LMDB purge already ran — would vanish
        // from the doc on restart.
        if let Err(e) = persist_window_update(&self.vault, window_key, payload) {
            // Never leave RAM ahead of durable state on a FAILED persist
            // (client analog of the ONE-1129 server evict-on-persist-failure):
            // the import advanced this doc's version vector, so keeping the
            // doc registered would tell the server — on the next VV exchange —
            // that we already hold bytes that never became durable; they would
            // never be re-sent and would vanish from the doc on restart
            // (tombstones included). Discard the live window WITHOUT
            // persisting (a persist would durably commit the unconfirmed
            // import); the next open reloads from durable state and the
            // ONE-1127/1128 VV exchange re-delivers the update.
            self.manager.discard_window(&WindowKey::new(window_key));
            return Err(TransportError::Storage(format!(
                "persist remote update: {e}"
            )));
        }
        let _ = self.event_tx.send(SyncEvent::WindowUpdated {
            window_key: window_key.to_string(),
        });
        Ok(())
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
                if let Err(e) = window.persist_state(&self.vault) {
                    // Never leave RAM ahead of durable state on a FAILED
                    // persist (same discipline as the WindowSync UPDATE
                    // arm above): the bulk import advanced this doc's
                    // version vector, so keeping the doc registered would
                    // tell the server — on the next VV exchange — that we
                    // already hold bytes that never became durable; they
                    // would never be re-sent and would vanish from the doc
                    // on restart. Discard the live window WITHOUT
                    // persisting (a persist would durably commit the
                    // unconfirmed import); the next open reloads from
                    // durable state and the ONE-1127/1128 VV exchange
                    // re-delivers the missing ops. The `bulk:w:`
                    // in-progress marker stays set for retry (fail-closed:
                    // the clear below only runs after a successful
                    // persist).
                    self.manager.discard_window(&WindowKey::new(window_key));
                    return Err(TransportError::Storage(format!("persist bulk window: {e}")));
                }
            } else {
                // Window is ON-DISK (cold): route the snapshot through the
                // SAME gated machinery as every other remote import
                // (ONE-1156(a), WAVE-C OD-12). The previous arm parsed the
                // snapshot structure-only (`doc_from_snapshot`) and then
                // wrote raw `d:w:`/`sv:w:`/`svf:w:` rows — remote bytes
                // becoming the next open's doc state WITHOUT Observer B
                // ever seeing them: no tombstone never-downgrade, no `dt:`
                // gate, no receipt immutability, no quarantine. Fail-closed
                // replacement:
                //
                //   1. full pinned open (pt → pm → reverse → forward remat,
                //      observers attached LAST) — `ensure_window`;
                //   2. OBSERVED import — Observer B fires synchronously, so
                //      EVERY entity/edge/tombstone door runs on the remote
                //      ops;
                //   3. inline `ra:` drain scoped to this window — doc-side
                //      tombstone re-assertion at a safe commit point
                //      (handler context, OUTSIDE observer callbacks),
                //      BEFORE the persist so the persisted `d:w:` is
                //      already re-asserted (ONE-1156(c));
                //   4. `persist_state` — anti-clobber merge + the pinned
                //      `d:`/`sv:`/`svf:` triple (which subsumes the old
                //      arm's bespoke svf freshness logic);
                //   5. unload — bulk targets cold historical windows; the
                //      memory budget is restored after the persist.
                //
                // Every failure path leaves `bulk:w:{key}` set for retry
                // (the clear below only runs after success) and DISCARDS
                // the just-opened window so RAM never runs ahead of
                // durable state (same discipline as the live arm and the
                // WindowSync UPDATE arm).
                let window = self.ensure_window(window_key)?;
                if window.doc.import(doc_state).is_err() {
                    self.manager.discard_window(&WindowKey::new(window_key));
                    return Err(TransportError::InvalidPayload(
                        "bulk doc state import failed",
                    ));
                }
                // "local" mirrors the vault's own transient window-doc user
                // id (`Vault::write_crdt_tombstone`); `create_window_doc`
                // ignores it. A `false` return (malformed `ra:` rows kept,
                // fail closed) is NOT a bulk failure: the well-formed
                // markers drained, and the kept rows stay doctor-visible
                // via `pending_reassert_windows` — failing the transfer
                // could never clear them.
                if let Err(e) = quarantine::drain_reassert_markers_for_window(
                    &self.vault,
                    "local",
                    &self.manager,
                    &WindowKey::new(window_key),
                ) {
                    self.manager.discard_window(&WindowKey::new(window_key));
                    return Err(TransportError::Storage(format!(
                        "bulk ra: re-assertion drain: {e}"
                    )));
                }
                if let Err(e) = window.persist_state(&self.vault) {
                    self.manager.discard_window(&WindowKey::new(window_key));
                    return Err(TransportError::Storage(format!("persist bulk window: {e}")));
                }
                // Drop our handle BEFORE the unload: the manager refuses /
                // warns on outstanding external holders (ONE-1150).
                drop(window);
                self.manager
                    .unload_window(&WindowKey::new(window_key))
                    .map_err(|e| TransportError::Storage(format!("unload bulk window: {e}")))?;
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

    /// Whether `window_key`'s local doc is VV-identical to the most recent
    /// server VV observed for that window (ONE-1128).
    ///
    /// `None` means there is no local doc or no server VV witness yet —
    /// callers MUST treat `None` as NOT converged (fail-closed). A window
    /// without a server witness can never vouch for queued updates.
    pub fn window_converged(&self, window_key: &str) -> Option<bool> {
        let window = self.window(window_key)?;
        let server_vv = self.server_vvs.get(window_key)?;
        Some(window.doc.oplog_vv() == *server_vv)
    }

    /// Imports a queued offline update into the LOCAL window doc before it is
    /// replayed to the server (ONE-1128).
    ///
    /// Convergence is confirmed by VV equality with the server, and equality
    /// only vouches for ops the local doc contains. Skipping this import
    /// would let a server that never received the queued ops compare
    /// VV-equal against a fresh local doc — and the queue would be cleared
    /// with the ops lost in flight (for a delete-bearing update, a vanished
    /// GDPR tombstone).
    pub fn import_queued_update(
        &mut self,
        window_key: &str,
        update: &[u8],
    ) -> std::result::Result<(), TransportError> {
        let window = self.ensure_window(window_key)?;
        window
            .doc
            .import(update)
            .map_err(|_| TransportError::InvalidPayload("queued update import failed"))?;
        Ok(())
    }

    /// Drops all in-memory CRDT state for a forced re-bootstrap (ARCH-0023b
    /// Fig. 2: "drop Docs + queue").
    ///
    /// Manager-owned window docs are discarded WITHOUT persisting (the next
    /// open reloads from durable state), recorded server VVs are cleared,
    /// and the root doc is replaced with a fresh one so Phase 1 re-runs from
    /// an empty VV. Clearing the PERSISTENT queue is the connection
    /// manager's half (`SyncQueue::clear_all`, which preserves the `h:`/`m:`
    /// metadata, the `x:` quarantine family, and delete-bearing `q:` rows +
    /// their `d:` markers).
    pub fn reset_for_re_bootstrap(&mut self) {
        for key in self.manager.loaded_keys() {
            self.manager.discard_window(&key);
        }
        self.server_vvs.clear();
        let root_doc = LoroDoc::new();
        let _meta = root_doc.get_map("meta");
        // Same peer-id pinning as `new`: the client never authors root ops,
        // and a fresh doc has no ops, so this cannot fail.
        let _ = root_doc.set_peer_id(self.client_id);
        self.root_doc = root_doc;
    }

    /// Re-bootstrap sync frames: drop all in-memory docs, then produce the
    /// Phase 1-2 frames (root VV + default-window VV requests) WITHOUT the
    /// protocol hello — the hello is a once-per-connection preamble
    /// (ONE-1127) and the re-bootstrap reuses the live connection.
    pub fn generate_re_bootstrap_sync(&mut self) -> Vec<Vec<u8>> {
        self.generate_re_bootstrap_sync_for_windows(std::iter::empty::<String>())
            .expect("re-bootstrap sync frame encode failed")
    }

    /// Re-bootstrap sync frames with explicit windows that must be requested
    /// even if they are outside the default current/previous window set.
    pub(crate) fn generate_re_bootstrap_sync_for_windows<I>(
        &mut self,
        extra_windows: I,
    ) -> std::result::Result<Vec<Vec<u8>>, TransportError>
    where
        I: IntoIterator<Item = String>,
    {
        self.reset_for_re_bootstrap();
        self.generate_phase_frames_with_extra_windows(extra_windows)
    }

    /// Generates initial sync messages for the connection flow.
    ///
    /// Returns messages to send to the server, in wire order (the ONE-1140
    /// OD-5 connect-sequence literal `[hello][lease_request][…existing]`):
    /// 1. Protocol-version hello (MUST be the first frame — server checks it)
    /// 2. Lease request (proof-of-possession over this device's identity;
    ///    sent on EVERY connect — registration and renewal are one frame)
    /// 3. Root doc VV (so server knows what we have)
    /// 4. Default window VV requests (current + previous month), plus any
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
        self.try_generate_initial_sync()
            .expect("initial sync frame encode failed")
    }

    /// Fallible initial-sync frame builder for the connection flow.
    ///
    /// Production connection code uses this path so an encoder failure aborts
    /// the connect attempt instead of silently skipping a window request.
    pub(crate) fn try_generate_initial_sync(
        &self,
    ) -> std::result::Result<Vec<Vec<u8>>, TransportError> {
        // Phase 0: full-window hello — this client path still uses the
        // pre-FED-002 full-window VV_REQUEST flow.
        // Frame #2: lease request (ONE-1140, OD-5).
        let mut messages = vec![
            transport::encode_legacy_full_window_protocol_hello(),
            self.lease_request_frame(),
        ];
        messages.extend(self.generate_phase_frames()?);
        Ok(messages)
    }

    /// Builds this device's TAG_LEASE_REQUEST frame (ONE-1140, OD-5/OD-6):
    /// Ed25519 proof of possession over
    /// `"oneiron/lease-pop/v1" || client_id:8 BE || pubkey:32`.
    fn lease_request_frame(&self) -> Vec<u8> {
        use ed25519_dalek::Signer;
        let pubkey = self.device_signing_key.verifying_key().to_bytes();
        let transcript = crate::sync::lease::lease_pop_transcript(self.client_id, &pubkey);
        let pop_sig = self.device_signing_key.sign(&transcript).to_bytes();
        transport::encode_lease_request(self.client_id, &pubkey, &pop_sig)
    }

    /// Phase 1-2 sync frames: root VV + default-window VV requests.
    ///
    /// Shared by the initial connection flow (which prepends the protocol
    /// hello) and the forced re-bootstrap (which does not).
    fn generate_phase_frames(&self) -> std::result::Result<Vec<Vec<u8>>, TransportError> {
        self.generate_phase_frames_with_extra_windows(std::iter::empty::<String>())
    }

    fn generate_phase_frames_with_extra_windows<I>(
        &self,
        extra_windows: I,
    ) -> std::result::Result<Vec<Vec<u8>>, TransportError>
    where
        I: IntoIterator<Item = String>,
    {
        let mut messages = Vec::new();

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
            .map_or(0, |d| d.as_secs());

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
        for key in extra_windows {
            let Some(window_key) = WindowKey::try_new(key.as_str()) else {
                let _ = self.event_tx.send(SyncEvent::Error(format!(
                    "Re-bootstrap skipped invalid forced window key: {key}"
                )));
                continue;
            };
            if !keys.contains(&window_key) {
                keys.push(window_key);
            }
        }

        for key in keys {
            match self.window_vv_for_initial_sync(&key) {
                Ok(vv) => {
                    let frame = transport::encode_window_sync(
                        key.as_str(),
                        window_sub_tags::VV_REQUEST,
                        &vv,
                    )
                    .into_result()
                    .inspect_err(|e| {
                        let _ = self.event_tx.send(SyncEvent::Error(format!(
                            "Initial sync frame encode for window {key} failed: {e}"
                        )));
                    })?;
                    messages.push(frame);
                }
                Err(e) => {
                    let _ = self.event_tx.send(SyncEvent::Error(format!(
                        "Initial sync VV for window {key} failed: {e}"
                    )));
                }
            }
        }

        Ok(messages)
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
                Some(raw) if *raw == [SVF_FRESH]
            );
            if fresh {
                let sv_key = format!("sv:w:{key}");
                if let Some(sv_raw) = self.vault.store.sync_state.get(&rtxn, &sv_key)? {
                    // Persisted StateVector V1 — decode validates structure
                    // before anything reaches the wire (fail-closed: a
                    // corrupt row falls through to a full doc load instead
                    // of shipping garbage).
                    match VersionVector::decode(&sv_raw) {
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
    /// state vector + `svf:root` freshness, in one txn — plus the ONE-1140
    /// (OD-3) lease-registry mirror: every `leases` map entry is upserted
    /// into its `ls:` row in the SAME txn, so the replay doors' lease reads
    /// can never observe a root state without its registry rows. Malformed
    /// entries quarantine (x: row) and keep any previous good `ls:` row.
    fn persist_root_state(&self) -> Result<()> {
        let frontiers_before = self.root_doc.state_frontiers();
        let snapshot = export_snapshot(&self.root_doc)?;
        let vv = doc_version_vector(&self.root_doc);
        if let Err(err) = self.vault.with_write_txn(|wtxn| {
            self.vault
                .store
                .sync_state
                .put(wtxn, KEY_ROOT_DOC, &snapshot)?;
            self.vault.store.sync_state.put(wtxn, KEY_ROOT_SV, &vv)?;
            self.vault
                .store
                .sync_state
                .put(wtxn, KEY_ROOT_SVF, &[SVF_FRESH])?;
            crate::sync::lease::mirror_leases_from_root_in_txn(&self.vault, wtxn, &self.root_doc)?;
            Ok(())
        }) {
            if let Err(revert_err) = self.root_doc.revert_to(&frontiers_before) {
                return Err(Error::sync_engine_rollback(
                    SyncEngineContext::LoroRevert,
                    err,
                    revert_err,
                ));
            }
            return Err(err);
        }
        Ok(())
    }
}

/// Loads the persisted root doc: `d:root` snapshot + pending `u:root:*`
/// replay (ARCH-0023b startup step 1). Fresh doc when nothing is persisted.
fn load_root_doc(vault: &Vault) -> Result<LoroDoc> {
    let rtxn = vault.store.env.read_txn()?;
    let doc = match vault.store.sync_state.get(&rtxn, KEY_ROOT_DOC)? {
        Some(snapshot) => doc_from_snapshot(&snapshot)?,
        None => LoroDoc::new(),
    };
    let iter = vault
        .store
        .sync_state
        .prefix_iter(&rtxn, ROOT_UPDATE_PREFIX)?;
    for entry in iter {
        let (_k, v) = entry?;
        doc.import(&v).map_err(|source| Error::CrdtDecodeError {
            context: "import pending root update",
            source,
        })?;
    }
    Ok(doc)
}

// `load_or_mint_client_id` / `mint_client_id` were RELOCATED to the base
// `crate::identity` module (ONE-1140, OD-2): base receipt-mint paths need
// the same stable device id, and the Ed25519 attestation keypair mints
// alongside it. Semantics preserved — u64 LE, minted once, nonzero;
// malformed/zero rows fail closed (ONE-1155 zero-check composed there).

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

fn map_federated_admission_err(e: crate::error::Error) -> TransportError {
    match e {
        crate::error::Error::CrdtDecodeError { .. } => {
            TransportError::InvalidPayload("federated update import failed")
        }
        crate::error::Error::GateWriteRejected {
            outcome,
            reason_codes,
        } => TransportError::Storage(format!(
            "federated admission rejected: outcome={outcome}, reasons={reason_codes:?}"
        )),
        crate::error::Error::SyncProtocolError {
            context: SyncProtocolValidation::FederatedTombstoneAdmission,
        } => TransportError::InvalidPayload("federated tombstone update rejected"),
        e if is_local_federated_admission_failure(&e) => {
            TransportError::Storage(format!("federated admission failed: {e}"))
        }
        _ => TransportError::InvalidPayload("federated update admission failed"),
    }
}

fn is_local_federated_admission_failure(e: &crate::error::Error) -> bool {
    matches!(
        e,
        crate::error::Error::Storage(_)
            | crate::error::Error::Io(_)
            | crate::error::Error::MapFull
            | crate::error::Error::InvalidConfig(_)
            | crate::error::Error::EmbeddingModelChanged { .. }
            | crate::error::Error::HnswConfigChanged { .. }
            | crate::error::Error::StorageAbiVersionChanged { .. }
            | crate::error::Error::StorageSchemaVersionChanged { .. }
            | crate::error::Error::DbManifestMismatch { .. }
            | crate::error::Error::VaultRootPreflight { .. }
            | crate::error::Error::WindowNotFound { .. }
            | crate::error::Error::WindowBusy { .. }
    )
}

/// Computes the next backoff delay with exponential growth capped at max.
pub fn next_backoff(current_ms: u32, max_ms: u32) -> u32 {
    std::cmp::min(current_ms.saturating_mul(2), max_ms)
}

#[cfg(test)]
mod tests;
