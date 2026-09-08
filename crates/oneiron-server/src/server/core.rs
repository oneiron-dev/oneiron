//! Core server state: the `SyncServer` struct, construction, and shared helpers.
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use loro::LoroDoc;
use oneiron::DreamerAttemptProgressProducer;
use oneiron::SyncEngineContext;
#[cfg(test)]
use oneiron::sync::WindowKey;
use oneiron::sync::bridge::Materializer;
use oneiron::sync::lease::ROOT_LEASES_MAP;
use oneiron::sync::schema::{
    add_window_to_root, init_window_list, read_window_list, schema_version_bytes,
};
use oneiron::sync::server_state;
use oneiron::sync::{EphemeralStore, WindowManager};
use tokio::sync::{Mutex, broadcast};

use crate::api::DeepRetrievalHost;
use crate::config::SyncServerConfig;
use crate::mcp::{McpConnectorActorRegistry, McpCredentialHashKey};
use crate::usage::UsageLedger;

use super::lifecycle::{LifecycleJobKey, NEXT_LIFECYCLE_SESSION_ID};
use super::windows::{SERVER_USER_ID, spawn_local_change_producer};

/// Broadcast payload: (conn_id, encoded_message).
/// conn_id 0 = local/bridge writes (broadcast to all devices).
/// conn_id >= 1 = specific connection (echo suppression skips sender).
pub(crate) type BroadcastPayload = (u32, Vec<u8>);

/// Core sync server state shared across all connections.
pub struct SyncServer {
    pub(crate) vault: Arc<oneiron::Vault>,
    /// Root LoroDoc (server-authoritative, contains meta.windows).
    pub(crate) root_doc: LoroDoc,
    /// Hub-held Loro ephemeral state for late join/reconnect snapshots.
    pub(crate) ephemeral_store: EphemeralStore,
    /// Producer state for Dreamer live attempt-progress rows on the ephemeral lane.
    pub(crate) dreamer_progress: Mutex<DreamerAttemptProgressProducer>,
    /// Broadcast channel for fan-out to all connected clients.
    pub(crate) broadcast_tx: broadcast::Sender<BroadcastPayload>,
    /// Monotonic connection ID counter. 0 = reserved for bridge/local writes.
    pub(crate) next_conn_id: AtomicU32,
    /// Serializes lease-registry mutations (ONE-1140, OD-3): two concurrent
    /// connects racing the same client id must observe first-binding-wins,
    /// never a read-modify-write interleave.
    pub(crate) lease_registrar: Mutex<()>,
    /// Window manager used by server-side safe-point maintenance jobs.
    pub(crate) reassert_manager: Arc<WindowManager>,
    /// Process-local session component for lifecycle job debounce keys.
    pub(super) lifecycle_session_id: u64,
    /// In-flight lifecycle jobs keyed by `(kind, vault_id, session_id)`.
    pub(super) lifecycle_in_flight: Mutex<HashSet<LifecycleJobKey>>,
    /// Server configuration.
    pub(crate) config: SyncServerConfig,
    /// Tenant usage ledger over the server vault.
    pub(crate) usage_ledger: UsageLedger,
    /// Process-local connector actor registry for the MCP gateway.
    pub(crate) mcp_registry: Mutex<McpConnectorActorRegistry>,
    /// ONE-207: the optional deep-retrieval host.
    ///
    /// `None` on every server [`SyncServer::new`] builds, and that is the
    /// shipped posture: this crate injects no backend, pins no model and mints
    /// no deep budget, exactly as the MCP endpoints bind no `execute_code`
    /// host. A `depth=deep` request against a `None` here is refused with
    /// `DEEP_RETRIEVAL_UNAVAILABLE` rather than quietly served at standard
    /// effort, so "deep" never names a read that was not deep.
    pub(crate) deep_retrieval: Option<Arc<DeepRetrievalHost>>,
}

impl SyncServer {
    // ─── Device-lease registry (ONE-1140, OD-3) ──────────────────────────

    /// Creates a SyncServer over the vault, reloading persisted CRDT state.
    ///
    /// Startup ordering per ARCH-0023b: (1) the root Doc loads from `d:root`
    /// plus pending `u:root:*`; (2) window Docs load on demand from
    /// `d:w:{key}` plus pending `u:w:{key}:*` in `Self::get_or_create_window`.
    /// A fresh vault initializes and persists a new root Doc.
    ///
    /// Boot also reconciles `meta.windows` against the persisted `d:w:*`
    /// snapshots, so a crash between window-snapshot persistence and root
    /// persistence cannot permanently hide a window from clients.
    ///
    /// Errors (fail-closed) on corrupt persisted state: the server must not
    /// boot empty over an undecodable snapshot — that silently discards
    /// relayed updates, including tombstones.
    pub fn new(
        vault: Arc<oneiron::Vault>,
        config: SyncServerConfig,
    ) -> Result<Self, oneiron::Error> {
        config.validate()?;

        let root_doc = match server_state::load_root_from_state(&vault)? {
            Some(doc) => doc,
            None => {
                let doc = LoroDoc::new();
                // Initialize root doc meta map
                let meta = doc.get_map("meta");
                // i64-LE BYTES (Loro Binary), conforming to the shared schema
                // (`schema::create_root_doc`) — NOT a Loro i64, which the
                // byte-only schema readers would not decode.
                meta.insert("schema_version", schema_version_bytes().as_slice())
                    .map_err(|e| {
                        oneiron::Error::sync_engine(SyncEngineContext::LoroMapInsert, e)
                    })?;
                // `meta.windows` must use the shared schema-owned encoding so
                // fresh server docs, root-doc creation, and client decoding
                // cannot drift.
                init_window_list(&doc, &[]);
                // Device-lease registry map (ONE-1140, OD-3) — server-write
                // only; lazily present on docs persisted before v2.
                let _leases = doc.get_map(ROOT_LEASES_MAP);
                doc.commit();
                // Boot is pre-connection/single-threaded; no root-writer
                // mutex can race this initial persist.
                server_state::persist_root_snapshot(&vault, &doc)?;
                doc
            }
        };

        // Reconcile meta.windows with the persisted window snapshots.
        let known: HashSet<String> = read_window_list(&root_doc)
            .iter()
            .map(|k| k.as_str().to_string())
            .collect();
        let mut reconciled = false;
        for key in server_state::persisted_window_keys(&vault)? {
            if !known.contains(key.as_str()) {
                add_window_to_root(&root_doc, &key);
                reconciled = true;
            }
        }
        if reconciled {
            // Boot reconciliation is pre-connection/single-threaded; no
            // root-writer mutex can race this persist.
            server_state::persist_root_snapshot(&vault, &root_doc)?;
        }

        let (broadcast_tx, _) = broadcast::channel(256);
        let mcp_registry = Mutex::new(McpConnectorActorRegistry::new(
            McpCredentialHashKey::from_bytes(mcp_registry_hash_key(&config)),
        ));

        let reassert_manager = Arc::new(WindowManager::new(
            vault.clone(),
            Arc::new(Materializer::with_lease_vault_id(config.lease_vault_id)),
            SERVER_USER_ID,
        ));
        reassert_manager.attach_to_vault();
        // Detached on purpose: the relay ends by itself when the manager (and
        // with it the outbound sink holding the sender) drops with this server.
        spawn_local_change_producer(&reassert_manager, &broadcast_tx);

        Ok(Self {
            usage_ledger: UsageLedger::new(vault.clone()),
            vault,
            root_doc,
            ephemeral_store: EphemeralStore::new(config.ephemeral_timeout_ms),
            broadcast_tx,
            next_conn_id: AtomicU32::new(1),
            lease_registrar: Mutex::new(()),
            reassert_manager,
            lifecycle_session_id: NEXT_LIFECYCLE_SESSION_ID.fetch_add(1, Ordering::Relaxed),
            lifecycle_in_flight: Mutex::new(HashSet::new()),
            dreamer_progress: Mutex::new(DreamerAttemptProgressProducer::new()),
            config,
            mcp_registry,
            deep_retrieval: None,
        })
    }

    /// Attaches the ONE-207 deep-retrieval host.
    ///
    /// Crate-visible on purpose: the host carries a `BudgetGuard`, so wiring
    /// one is a spend decision, and this release exposes no public seam for
    /// making it. Tests take this door; production servers keep the `None`
    /// [`Self::new`] builds until a hosted binding lands with its own ticket.
    #[allow(dead_code)] // No in-tree production host yet; the tests are its only caller.
    pub(crate) fn with_deep_retrieval_host(mut self, host: Arc<DeepRetrievalHost>) -> Self {
        self.deep_retrieval = Some(host);
        self
    }

    /// Returns the vault backing this server (used by integration tests to
    /// assert sync_state durability).
    pub fn vault(&self) -> &Arc<oneiron::Vault> {
        &self.vault
    }

    /// Allocates a new unique nonzero connection ID.
    ///
    /// `conn_id = 0` is reserved as the bridge/local-broadcast sender
    /// sentinel; a real connection returning 0 would silently bypass echo
    /// suppression. `fetch_update` skips 0 on wraparound.
    pub(crate) fn alloc_conn_id(&self) -> u32 {
        self.next_conn_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                let next = current.wrapping_add(1);
                Some(if next == 0 { 1 } else { next })
            })
            .expect("fetch_update closure always returns Some")
    }

    /// Returns the window key (YYYY-MM) for a Unix timestamp.
    #[cfg(test)]
    pub(crate) fn window_key_for_timestamp(ts: u64) -> String {
        WindowKey::from_timestamp(ts).as_str().to_string()
    }
}

fn mcp_registry_hash_key(config: &SyncServerConfig) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron-server:mcp-connector-registry:v1");
    if let Some(secret) = config.auth_secret.as_deref() {
        hasher.update(secret.as_bytes());
    } else if config.allow_unauthenticated {
        hasher.update(b"unauthenticated-dev");
    } else {
        hasher.update(b"no-auth-secret-configured");
    }
    *hasher.finalize().as_bytes()
}

/// Wall-clock Unix seconds, saturating to 0 pre-epoch (matches the
/// client-side SystemTime uses).
pub(super) fn unix_seconds_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
