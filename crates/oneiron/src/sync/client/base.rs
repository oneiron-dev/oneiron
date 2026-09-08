//! SyncClient construction, window and ephemeral accessors, and root persistence.

use std::collections::HashMap;
use std::sync::Arc;

use loro::{LoroDoc, VersionVector};
use tokio::sync::mpsc;

use super::types::{
    EphemeralChangeOrigin, KEY_LAST_SYNC, KEY_ROOT_DOC, KEY_ROOT_SV, KEY_ROOT_SVF,
    ROOT_UPDATE_PREFIX, SVF_FRESH, SyncClientConfig, SyncEvent, SyncStatus,
};
use crate::Vault;
use crate::error::{Error, Result, SyncConfigField, SyncEngineContext, SyncProtocolValidation};
use crate::sync::loro_support::{doc_from_snapshot, doc_version_vector, export_snapshot};
use crate::sync::manager::WindowManager;
use crate::sync::schema::read_window_list;
use crate::sync::transport;
use crate::sync::transport::TransportError;
use crate::sync::types::{WindowKey, parse_window_key_str};
use crate::sync::window::LoadedWindow;
use crate::sync::{
    EphemeralEventTrigger, EphemeralStore, EphemeralStoreEvent, LoroValue, Subscription,
};

/// Client-side sync engine.
pub struct SyncClient {
    pub(crate) vault: Arc<Vault>,
    pub(crate) manager: Arc<WindowManager>,
    pub(crate) root_doc: LoroDoc,
    pub(crate) client_id: u64,
    /// This device's Ed25519 attestation key (ONE-1140, OD-2): signs the
    /// lease-request proof of possession on every connect. Receipt signing
    /// happens vault-side at mint, not here.
    pub(crate) device_signing_key: ed25519_dalek::SigningKey,
    pub(crate) config: SyncClientConfig,
    /// Last server VV observed per window from `VV_REQUEST` / `VV_RESPONSE`
    /// frames. This is the convergence witness (ONE-1128): the offline queue
    /// may only be cleared once the server's OWN vv proves it holds every op
    /// the local doc holds.
    pub(crate) server_vvs: HashMap<String, VersionVector>,
    pub(crate) ephemeral_store: EphemeralStore,
    pub(crate) _ephemeral_subscription: Subscription,
    pub(crate) status: SyncStatus,
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

    /// Persists the root doc to sync_state: `d:root` snapshot + `sv:root`
    /// state vector + `svf:root` freshness, in one txn — plus the ONE-1140
    /// (OD-3) lease-registry mirror: every `leases` map entry is upserted
    /// into its `ls:` row in the SAME txn, so the replay doors' lease reads
    /// can never observe a root state without its registry rows. Malformed
    /// entries quarantine (x: row) and keep any previous good `ls:` row.
    pub(crate) fn persist_root_state(&self) -> Result<()> {
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

    /// Builds this device's TAG_LEASE_REQUEST frame (ONE-1140, OD-5/OD-6):
    /// Ed25519 proof of possession over
    /// `"oneiron/lease-pop/v1" || client_id:8 BE || pubkey:32`.
    pub(crate) fn lease_request_frame(&self) -> Vec<u8> {
        use ed25519_dalek::Signer;
        let pubkey = self.device_signing_key.verifying_key().to_bytes();
        let transcript = crate::sync::lease::lease_pop_transcript(self.client_id, &pubkey);
        let pop_sig = self.device_signing_key.sign(&transcript).to_bytes();
        transport::encode_lease_request(self.client_id, &pubkey, &pop_sig)
    }
}

/// Loads the persisted root doc: `d:root` snapshot + pending `u:root:*`
/// replay (ARCH-0023b startup step 1). Fresh doc when nothing is persisted.
pub(crate) fn load_root_doc(vault: &Vault) -> Result<LoroDoc> {
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
