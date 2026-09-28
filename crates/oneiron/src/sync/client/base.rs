//! SyncClient construction, window and ephemeral accessors, and root persistence.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::sync::Mutex;

use loro::{LoroDoc, VersionVector};
use tokio::sync::mpsc;

use super::types::{
    EphemeralChangeOrigin, KEY_LAST_SYNC, KEY_ROOT_DOC, KEY_ROOT_SV, KEY_ROOT_SVF,
    ROOT_UPDATE_PREFIX, SVF_FRESH, SyncClientConfig, SyncEvent, SyncStatus,
};
use crate::Vault;
use crate::error::{
    Error, Result, SyncConfigField, SyncEngineContext, SyncError, SyncProtocolValidation,
};
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
    pub(crate) note_session_bound: bool,
    pub(crate) document_updates: tokio::sync::broadcast::Receiver<Vec<u8>>,
    pub(crate) client_id: u64,
    pub(crate) config: SyncClientConfig,
    /// Last server VV observed per window from `VV_REQUEST` / `VV_RESPONSE`
    /// frames. This is the convergence witness (ONE-1128): the offline queue
    /// may only be cleared once the server's OWN vv proves it holds every op
    /// the local doc holds.
    pub(crate) server_vvs: HashMap<String, VersionVector>,
    pub(crate) requested_windows: Mutex<HashSet<WindowKey>>,
    pub(crate) pending_world_windows: Mutex<HashSet<WindowKey>>,
    /// Unacknowledged cross-month deltas. Lost on process death, re-fetched by VV.
    pub(crate) staged_world_updates: Vec<(WindowKey, Vec<u8>)>,
    pub(crate) root_bootstrapped: bool,
    /// Durable home ACKs of opened-item queue updates, keyed by queue sequence.
    pub(crate) residence_acks: HashMap<u64, [u8; 32]>,
    pub(crate) ephemeral_store: EphemeralStore,
    pub(crate) _ephemeral_subscription: Subscription,
    pub(crate) _message_stream_subscription: Subscription,
    pub(crate) lfs_download: Option<crate::sync::chunks::ChunkDownload>,
    pub(crate) last_lfs_download: Option<crate::origin::lfs::LfsPutOutcome>,
    pub(crate) status: SyncStatus,
    pub(crate) event_tx: mpsc::UnboundedSender<SyncEvent>,
}

impl SyncClient {
    /// Creates a new sync client over manager-owned windows.
    ///
    /// Loads the stable CRDT client id, then root state. Transport never
    /// reads or mints a device signing key; capability pairing owns enrollment.
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

        if config.note_session.is_some() {
            let uri: tokio_tungstenite::tungstenite::http::Uri =
                config.server_url.parse().map_err(|_| {
                    Error::sync_protocol(SyncProtocolValidation::DocumentAdmissionDenied)
                })?;
            let loopback = uri.host().is_some_and(|host| {
                host.trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
            });
            if uri.scheme_str() != Some("wss") && !(uri.scheme_str() == Some("ws") && loopback) {
                return Err(Error::sync_protocol(
                    SyncProtocolValidation::DocumentAdmissionDenied,
                ));
            }
        }
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let vault = Arc::clone(manager.vault());

        let client_id = crate::identity::load_or_mint_client_id(&vault)?;
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

        let stream_event_tx = event_tx.clone();
        let message_stream_subscription = vault.message_streams.presence.store.subscribe(Box::new(
            move |event: &EphemeralStoreEvent| {
                let _ = stream_event_tx.send(SyncEvent::EphemeralChanged {
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
            },
        ));
        let document_updates = manager.documents().subscribe();
        let mut client = Self {
            note_session_bound: false,
            document_updates,
            vault,
            manager,
            root_doc,
            client_id,
            config,
            server_vvs: HashMap::new(),
            requested_windows: Mutex::new(HashSet::new()),
            pending_world_windows: Mutex::new(HashSet::new()),
            staged_world_updates: Vec::new(),
            root_bootstrapped: false,
            residence_acks: HashMap::new(),
            ephemeral_store,
            _ephemeral_subscription: ephemeral_subscription,
            _message_stream_subscription: message_stream_subscription,
            lfs_download: None,
            last_lfs_download: None,
            status: SyncStatus::Disconnected,
            event_tx,
        };

        client
            .replay_deferred_federation_update()
            .map_err(|e| Error::sync_engine(SyncEngineContext::FederationReplayStartup, e))?;
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
        self.vault
            .message_streams
            .presence
            .store
            .get(key)
            .or_else(|| self.ephemeral_store.get(key))
    }

    /// Returns all currently stored non-deleted ephemeral keys.
    pub fn ephemeral_keys(&self) -> Vec<String> {
        let mut keys = self.ephemeral_store.keys();
        keys.extend(self.vault.message_streams.presence.store.keys());
        keys.sort();
        keys.dedup();
        keys
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
        self.vault.message_streams.presence.store.remove_outdated();
    }

    /// Follow another project. The next sync negotiation requests all its known
    /// historical windows, so following late backfills rather than starting now.
    pub fn follow_world(&mut self, world: crate::EntityId) {
        if let Some(worlds) = &mut self.config.followed_worlds
            && !worlds.contains(&world)
        {
            worlds.push(world);
        }
    }

    /// Home-node / explicit sync-all mode.
    pub fn follow_all_worlds(&mut self) {
        self.config.followed_worlds = None;
    }

    /// Effective subscription = host request ∩ trusted manifest ceiling.
    /// Fail closed when a loaded manifest is malformed; the caller request
    /// is never rewritten, so `follow_all_worlds` cannot bypass the cap.
    pub(crate) fn effective_worlds(
        &self,
    ) -> std::result::Result<Option<BTreeSet<crate::EntityId>>, TransportError> {
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(|error| TransportError::Storage(error.to_string()))?;
        let resolution = crate::gate::resolve_policy_manifest(&self.vault.store, &txn)
            .map_err(|error| TransportError::Storage(error.to_string()))?;
        let ceiling = resolution
            .sync_world_ceiling()
            .map_err(|error| TransportError::Storage(error.to_string()))?;
        let default_all = resolution
            .sync_default_all_worlds()
            .map_err(|error| TransportError::Storage(error.to_string()))?;
        // `Some([])` from a fresh SyncClientConfig means "use the manifest's
        // shipped default". An explicit `None` from follow_all_worlds is a
        // request for all, still capped by the trusted manifest ceiling.
        let requested = if self
            .config
            .followed_worlds
            .as_ref()
            .is_some_and(Vec::is_empty)
            && default_all
        {
            None
        } else {
            self.config.followed_worlds.as_ref()
        };
        Ok(match (requested, ceiling) {
            (None, None) => None,
            (None, Some(cap)) => Some(cap.clone()),
            (Some(worlds), None) => Some(worlds.iter().copied().collect()),
            (Some(worlds), Some(cap)) => Some(
                worlds
                    .iter()
                    .filter(|world| cap.contains(world))
                    .copied()
                    .collect(),
            ),
        })
    }

    pub(crate) fn follows_window(
        key: &WindowKey,
        worlds: &Option<BTreeSet<crate::EntityId>>,
    ) -> bool {
        match (key.world(), worlds) {
            (None, _) | (_, None) => true,
            (Some(world), Some(worlds)) => worlds.contains(&world),
        }
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
    pub(super) fn persist_root_state(&self) -> Result<()> {
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
pub(super) fn load_root_doc(vault: &Vault) -> Result<LoroDoc> {
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
        doc.import(&v).map_err(|source| {
            Error::Sync(SyncError::CrdtDecodeError {
                context: "import pending root update",
                source,
            })
        })?;
    }
    Ok(doc)
}

// `load_or_mint_client_id` / `mint_client_id` were RELOCATED to the base
// `crate::identity` module (ONE-1140, OD-2): base receipt-mint paths need
// the same stable device id, and the Ed25519 attestation keypair mints
// alongside it. Semantics preserved — u64 LE, minted once, nonzero;
// malformed/zero rows fail closed (ONE-1155 zero-check composed there).
