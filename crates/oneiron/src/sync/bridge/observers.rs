//! Observer A/B registration and the shared Materializer/OutboundSink state.

use std::cell::Cell;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use loro::{ContainerTrait, LoroDoc, LoroMap, Subscription};
use tokio::sync::mpsc;

use super::edges::materialize_edges_from_delta;
use super::entities::materialize_entities_from_delta;
use super::tombstones::materialize_tombstones_from_delta;

use crate::entity_id::EntityId;
use crate::sync::queue::SyncQueue;
use crate::sync::types::LocalUpdate;
use crate::{Error, Result, Vault};

thread_local! {
    /// `write_crdt_tombstone` commits a live-doc update before it can assemble
    /// the snapshot/delta inputs for its one LMDB TXN1. Suppress Observer A
    /// only for that synchronous commit; the deletion path stages gate
    /// recovery first, then atomically persists the exact snapshot + queue
    /// delta.
    static SUPPRESS_OBSERVER_A_FOR_DELETION_TOMBSTONE: Cell<usize> = const { Cell::new(0) };
}

/// Origin tag used for LMDB→CRDT bridge writes.
pub const BRIDGE_ORIGIN: &str = "bridge";

/// Origin for a local deletion tombstone whose durable LMDB carrier is
/// authored explicitly by the deletion TXN1, not Observer A. Observer B also
/// skips it, preserving the tombstone-first → local-purge ordering.
pub(crate) const DELETION_TOMBSTONE_ORIGIN: &str = "deletion_tombstone";

struct DeletionTombstoneObserverASuppression;

impl DeletionTombstoneObserverASuppression {
    fn enter() -> Self {
        SUPPRESS_OBSERVER_A_FOR_DELETION_TOMBSTONE.with(|depth| {
            depth.set(depth.get().saturating_add(1));
        });
        Self
    }
}

impl Drop for DeletionTombstoneObserverASuppression {
    fn drop(&mut self) {
        SUPPRESS_OBSERVER_A_FOR_DELETION_TOMBSTONE.with(|depth| {
            depth.set(depth.get().saturating_sub(1));
        });
    }
}

fn observer_a_suppressed_for_deletion_tombstone() -> bool {
    SUPPRESS_OBSERVER_A_FOR_DELETION_TOMBSTONE.with(|depth| depth.get() != 0)
}

/// Runs a synchronous live-doc deletion tombstone commit without Observer A
/// persisting a separate `u:w:` transaction in the middle. The caller must
/// immediately persist the returned snapshot/delta in its own TXN1.
pub(crate) fn with_deletion_tombstone_observer_a_suppressed<T>(commit: impl FnOnce() -> T) -> T {
    let _guard = DeletionTombstoneObserverASuppression::enter();
    commit()
}

/// Shared materializer state for serializing LMDB writes across observers.
pub struct Materializer {
    /// Mutex serializing all Observer B callbacks + direct bridge-origin deletes.
    /// Uses `std::sync::Mutex` (NOT `tokio::sync::Mutex`) per spec.
    mutex: Mutex<()>,
    lease_vault_id: u64,
    live_query_tees: Mutex<Vec<std::sync::Weak<dyn LiveQueryTee>>>,
}

impl Default for Materializer {
    fn default() -> Self {
        Self {
            mutex: Mutex::new(()),
            lease_vault_id: crate::sync::lease::DEFAULT_LEASE_VAULT_ID,
            live_query_tees: Mutex::new(Vec::new()),
        }
    }
}

impl Materializer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_lease_vault_id(lease_vault_id: u64) -> Self {
        Self {
            mutex: Mutex::new(()),
            lease_vault_id,
            live_query_tees: Mutex::new(Vec::new()),
        }
    }

    /// Attaches a late server consumer to the existing Observer B instances.
    /// Weak ownership avoids retaining a disconnected subscription owner and
    /// never installs a second materializer on a live document.
    pub fn attach_live_query_tee(&self, tee: &Arc<dyn LiveQueryTee>) {
        let mut tees = self
            .live_query_tees
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        tees.retain(|entry| entry.strong_count() != 0);
        tees.push(Arc::downgrade(tee));
    }

    pub(crate) fn notify_live_queries(
        &self,
        path: &str,
        diff: &MaterializedDiffSummary,
        by: &OriginMark,
    ) {
        let tees: Vec<_> = self
            .live_query_tees
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter_map(std::sync::Weak::upgrade)
            .collect();
        for tee in tees {
            tee.on_materialized(path, diff, by);
        }
    }

    pub fn lease_vault_id(&self) -> u64 {
        self.lease_vault_id
    }

    /// Acquires the materializer lock.
    ///
    /// Recovers from a poisoned mutex (prior panic in Observer B callback)
    /// instead of cascading the panic to all future callbacks.
    pub fn lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.mutex
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Outbound update sink: Observer A routes every persisted local update
/// here (ONE-1126, closes the "nothing feeds `local_rx`" gap).
///
/// While a connection is attached ([`OutboundSink::attach`]) the update is
/// sent to the connection's `local_rx` channel (debounce → WindowSync
/// UPDATE on the wire). With no live connection — never attached, detached
/// on shutdown, or the receiver dropped — the update is pushed onto the
/// durable [`SyncQueue`] (`q:{seq}` rows, db #25) and replayed on the next
/// connect. Updates are additionally durable as `u:w:` rows either way, so
/// a crash loses nothing; the queue only decides *when* the server hears
/// about them.
#[derive(Default)]
pub struct OutboundSink {
    sender: Mutex<Option<mpsc::UnboundedSender<LocalUpdate>>>,
}

impl OutboundSink {
    pub fn new() -> Self {
        Self::default()
    }

    /// Attaches a live connection's local-update channel.
    pub fn attach(&self, sender: mpsc::UnboundedSender<LocalUpdate>) {
        *self.lock() = Some(sender);
    }

    /// Detaches the connection channel; subsequent updates fall back to the
    /// durable [`SyncQueue`].
    pub fn detach(&self) {
        *self.lock() = None;
    }

    /// Acquires the sender slot, recovering from poisoning (mirrors
    /// [`Materializer::lock`]).
    fn lock(&self) -> std::sync::MutexGuard<'_, Option<mpsc::UnboundedSender<LocalUpdate>>> {
        self.sender
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Routes one persisted update: live channel when attached, durable
    /// queue otherwise. Failures are logged, never propagated — this runs
    /// inside Observer A, which cannot abort a committed CRDT change.
    pub(crate) fn route(&self, vault: &Arc<Vault>, window_key: &str, update_bytes: &[u8]) {
        if self.route_live(window_key, update_bytes) {
            return;
        }

        let queue_result = SyncQueue::new(Arc::clone(vault))
            .and_then(|queue| queue.push(window_key, update_bytes))
            .map(|_seq| ());
        if let Err(e) = queue_result {
            tracing::error!(
                window = %window_key,
                error = %e,
                "outbound-sink: failed to buffer offline update in sync_queue"
            );
        }
    }

    /// Routes an update only to an attached steady-state connection. The
    /// deletion path uses this after atomically writing its own durable
    /// delete-bearing queue row, avoiding both a missed live broadcast and a
    /// duplicate offline queue entry.
    pub(crate) fn route_live(&self, window_key: &str, update_bytes: &[u8]) -> bool {
        {
            let mut guard = self.lock();
            if let Some(sender) = guard.as_ref() {
                let send_result = sender.send(LocalUpdate {
                    window_key: window_key.to_string(),
                    update_bytes: update_bytes.to_vec(),
                });
                if send_result.is_ok() {
                    return true;
                }
                // Receiver dropped — clear the stale sender and fall through
                // to the durable queue.
                *guard = None;
            }
        }
        false
    }
}

/// Observer A state: tracks pending bytes for compaction signaling.
pub struct ObserverAState {
    /// Pending bytes since last compaction (AtomicU32 for Send+Sync).
    pub pending_bytes: AtomicU32,
}

impl Default for ObserverAState {
    fn default() -> Self {
        Self {
            pending_bytes: AtomicU32::new(0),
        }
    }
}

impl ObserverAState {
    pub fn new() -> Self {
        Self::default()
    }
}

pub(super) const ERR_OBSERVER_A_U_SEQ_ROW: &str = "observer a u_seq row";

pub(super) fn decode_observer_u_seq(raw: &[u8]) -> Result<u32> {
    let bytes: [u8; 4] = raw
        .try_into()
        .map_err(|_| Error::CorruptedIndex(ERR_OBSERVER_A_U_SEQ_ROW))?;
    Ok(u32::from_le_bytes(bytes))
}

/// Persists one window update to `sync_state` in a single write txn:
/// `u:w:{key}:{seq:08x}` row + `m:u_seq:w:{key}` counter bump +
/// `svf:w:{key}` staleness flip (the persisted `sv:w:` no longer reflects
/// the doc once an update lands on top of it).
///
/// Shared by Observer A (local commits) and the SyncClient remote-import
/// path: remote updates never fire `subscribe_local_update`, but they must
/// survive restart through the same `d:w:` + `u:w:` replay (ARCH-0023b
/// startup step 2), so they ride the same row family and counter.
pub(crate) fn persist_window_update(
    vault: &Vault,
    window_key: &str,
    update_bytes: &[u8],
) -> Result<()> {
    vault.with_write_txn(|wtxn| persist_window_update_in_txn(vault, wtxn, window_key, update_bytes))
}

/// In-transaction form of [`persist_window_update`]. A live deletion
/// tombstone uses this from its TXN1 so its `u:w:` carrier cannot become
/// durable before the matching gate-decision recovery sidecar.
pub(crate) fn persist_window_update_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    window_key: &str,
    update_bytes: &[u8],
) -> Result<()> {
    let seq_key = format!("m:u_seq:w:{window_key}");
    // Distinguish a missing key (fresh window — start at 0) from a
    // present-but-malformed seq row (on-disk corruption). The latter
    // must not silently reset to 0; doing so would let next_seq=1
    // collide with whatever update was already persisted at
    // `u:w:{window}:00000001` before the row was corrupted.
    let seq: u32 = match vault.store.sync_state.get(wtxn, &seq_key)? {
        None => 0,
        Some(raw) => decode_observer_u_seq(&raw)?,
    };
    // checked_add surfaces overflow as a typed error rather than
    // `wrapping_add`-ing to 0 and silently overwriting update key
    // `u:w:{window}:00000000`. Matches SyncQueue's update-seq policy.
    // u32 widening to u64 is tracked as a follow-up schema change.
    let next_seq = seq
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("observer a u_seq"))?;
    vault
        .store
        .sync_state
        .put(wtxn, &seq_key, &next_seq.to_le_bytes())?;

    let update_key = format!("u:w:{window_key}:{next_seq:08x}");
    vault
        .store
        .sync_state
        .put(wtxn, &update_key, update_bytes)?;

    let svf_key = format!("svf:w:{window_key}");
    vault.store.sync_state.put(wtxn, &svf_key, &[0u8])?;

    Ok(())
}

/// Registers Observer A on a Doc: persists all local updates to sync_state
/// and routes them outbound (live connection channel or durable queue)
/// when an [`OutboundSink`] is provided.
///
/// Returns the Subscription handle (must be kept alive for the observer to fire).
pub fn register_observer_a(
    doc: &LoroDoc,
    vault: &Arc<Vault>,
    window_key: &str,
    state: Arc<ObserverAState>,
    outbound: Option<Arc<OutboundSink>>,
) -> Subscription {
    let vault = vault.clone();
    let window_key = window_key.to_string();

    doc.subscribe_local_update(Box::new(move |update_bytes| {
        if observer_a_suppressed_for_deletion_tombstone() {
            return true;
        }
        let result = persist_window_update(&vault, &window_key, update_bytes);

        if let Err(e) = result {
            tracing::error!(
                window = %window_key,
                error = %e,
                "observer-a: CRITICAL — failed to persist update, CRDT committed but LMDB may diverge"
            );
        }

        // Outbound routing happens even if the u:w: persist failed: the
        // update bytes are valid CRDT data either way, and the queue
        // fallback gives them a second durable home.
        if let Some(sink) = &outbound {
            sink.route(&vault, &window_key, update_bytes);
        }

        state
            .pending_bytes
            .fetch_add(update_bytes.len() as u32, Ordering::Relaxed);

        true // keep subscription alive
    }))
}

/// Whether the destructive LMDB transaction of a local hard delete committed.
/// Publication and purge are separate transactions; app invalidations must not
/// infer purge completion from a missing header (headerless residue is legal).
pub fn local_deletion_is_materialized(vault: &Vault, id: &EntityId) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    vault.local_hard_delete_marker_exists_in_txn(&txn, id)
}

/// Post-commit notification consumer. Implementations must not write to the
/// observed Loro document or re-enter materialization from this callback.
pub trait LiveQueryTee: Send + Sync {
    /// Called once per committed container batch, never for an aborted batch.
    fn on_materialized(
        &self,
        container_path: &str,
        diff: &MaterializedDiffSummary,
        by: &OriginMark,
    );
}

/// Coarse read dependencies invalidated by one committed container batch.
#[derive(Clone, Debug)]
pub struct MaterializedDiffSummary {
    /// Changed paths (`w:<window>/<container>/<key>`), not entity bodies.
    pub containers: Vec<String>,
    /// Total changed key and binary-value bytes, for accounting only.
    pub bytes: usize,
}

/// Transport correlation only; never actor authority.
#[derive(Clone, Debug, Default)]
pub struct OriginMark {
    /// Parsed only from the server's existing `conn:<id>` import marker.
    pub conn_id: Option<u32>,
    /// Exact Loro origin, when present.
    pub origin: Option<String>,
}

/// Registers Observer B on a window Doc: materializes CRDT changes to LMDB.
///
/// Loro subscriptions work on
/// container IDs. We subscribe to each of the three maps (entities, edges,
/// tombstones) and skip events whose origin matches `BRIDGE_ORIGIN`.
///
/// `window_key` identifies the window for quarantine records (`x:` family)
/// and needs-rematerialization markers (`rm:w:{window}:{entity_hex}`).
///
/// Returns three Subscription handles (entities, edges, tombstones).
pub fn register_observer_b(
    doc: &LoroDoc,
    vault: &Arc<Vault>,
    materializer: &Arc<Materializer>,
    window_key: &str,
) -> (Subscription, Subscription, Subscription) {
    register_observer_b_with_tee(doc, vault, materializer, window_key, None)
}

/// Registers the same materializer with an optional server-side live-query tee.
/// The frozen entrypoint above retains precisely the no-tee behavior.
pub fn register_observer_b_with_tee(
    doc: &LoroDoc,
    vault: &Arc<Vault>,
    materializer: &Arc<Materializer>,
    window_key: &str,
    tee: Option<Arc<dyn LiveQueryTee>>,
) -> (Subscription, Subscription, Subscription) {
    let entities_map = doc.get_map("entities");
    let edges_map = doc.get_map("edges");
    let tombstones_map = doc.get_map("tombstones");

    let entity_sub = subscribe_map_observer(
        doc,
        &entities_map,
        vault,
        materializer,
        window_key,
        materialize_entities_from_delta,
        ("entities", tee.clone()),
    );
    let edge_sub = subscribe_map_observer(
        doc,
        &edges_map,
        vault,
        materializer,
        window_key,
        materialize_edges_from_delta,
        ("edges", tee.clone()),
    );
    let tombstone_sub = subscribe_map_observer(
        doc,
        &tombstones_map,
        vault,
        materializer,
        window_key,
        materialize_tombstones_from_delta,
        ("tombstones", tee.clone()),
    );

    (entity_sub, edge_sub, tombstone_sub)
}

/// Subscribes to a map's changes, filtering out bridge-origin events and
/// delegating to a materializer function under the materializer lock.
fn subscribe_map_observer(
    doc: &LoroDoc,
    map: &LoroMap,
    vault: &Arc<Vault>,
    materializer: &Arc<Materializer>,
    window_key: &str,
    materialize: fn(&LoroDoc, &loro::event::MapDelta<'_>, &Vault, &str, u64) -> bool,
    live_query: (&'static str, Option<Arc<dyn LiveQueryTee>>),
) -> Subscription {
    let callback_doc = doc.clone();
    let subscription_doc = doc.clone();
    let vault = vault.clone();
    let materializer = materializer.clone();
    let lease_vault_id = materializer.lease_vault_id();
    let window_key = window_key.to_string();
    let cid = map.id();
    subscription_doc.subscribe(
        &cid,
        Arc::new(move |event| {
            if event.origin == DELETION_TOMBSTONE_ORIGIN {
                // The owning LMDB transaction is still open. Publication owns
                // its post-commit notification; never invalidate on this event.
                return;
            }
            if event.origin == BRIDGE_ORIGIN {
                // The bridge mirrors an already committed LMDB write.
                materializer.notify_live_queries(
                    &format!("w:{window_key}/{}", live_query.0),
                    &MaterializedDiffSummary {
                        containers: Vec::new(),
                        bytes: 0,
                    },
                    &OriginMark {
                        conn_id: None,
                        origin: Some(event.origin.to_owned()),
                    },
                );
                return;
            }
            let _guard = materializer.lock();
            for cdiff in &event.events {
                if let Some(map_delta) = cdiff.diff.as_map() {
                    let committed = materialize(
                        &callback_doc,
                        map_delta,
                        &vault,
                        &window_key,
                        lease_vault_id,
                    );
                    if committed {
                        let path = format!("w:{window_key}/{}", live_query.0);
                        let mut bytes = 0usize;
                        let containers = map_delta
                            .updated
                            .iter()
                            .map(|(key, value)| {
                                bytes = bytes.saturating_add(key.len());
                                if let Some(loro::ValueOrContainer::Value(
                                    loro::LoroValue::Binary(blob),
                                )) = value
                                {
                                    bytes = bytes.saturating_add(blob.len());
                                }
                                format!("{path}/{key}")
                            })
                            .collect();
                        let by = OriginMark {
                            conn_id: event
                                .origin
                                .strip_prefix("conn:")
                                .and_then(|id| id.parse().ok()),
                            origin: (!event.origin.is_empty()).then(|| event.origin.to_owned()),
                        };
                        let diff = MaterializedDiffSummary { containers, bytes };
                        if let Some(tee) = &live_query.1 {
                            tee.on_materialized(&path, &diff, &by);
                        }
                        materializer.notify_live_queries(&path, &diff, &by);
                    }
                }
            }
        }),
    )
}
