//! Entity bridge: CRDT ↔ LMDB materialization observers.
//!
//! **Observer A** (`subscribe_local_update`): Fires for local commits and
//! persists update bytes to sync_state/broadcasts, except a deletion's
//! explicitly-suppressed live commit. Its authority recovery data is staged
//! first; the following TXN1 atomically persists the exact snapshot/delta.
//!
//! **Observer B** (`doc.subscribe(container_id)` × 3): Fires for all commits.
//! Subscribes to each of the three map containers (entities, edges, tombstones)
//! via the doc's container event system. Materializes key-level changes to LMDB,
//! skipping bridge-origin writes.
//!
//! Origin tracking: bridge writes use `commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN))`.
//! Observer B callbacks check the event origin and skip bridge-tagged events
//! to avoid circular LMDB→CRDT→LMDB loops.

use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use loro::{CommitOptions, ContainerTrait, LoroDoc, LoroMap, Subscription};
use tokio::sync::mpsc;

use super::loro_support::{
    map_delete, map_for_each_bytes, map_get_bytes, tombstone_map_contains_id,
    tombstone_values_for_id,
};
use super::quarantine::{
    self, QuarantineContainer, quarantine_rejected_op, quarantine_rejected_op_in_txn,
    remote_rejection_reason,
};
use super::queue::{SyncQueue, scrub_receiver_outbox_on_remote_hard_delete_in_txn};
use super::quota;
use super::types::LocalUpdate;
use crate::affect::Vad;
use crate::batch::{self, BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::companion::{
    CompanionExportClassification, ENTITY_TYPE_COMPANION_REGISTER, decode_companion_record_body,
};
use crate::edge::{
    DecodedEdgeValue, EdgeKind, EdgeProvenanceFlags, decode_edge_value, decode_edge_value_for_kind,
    encode_edge_value,
};
use crate::entity_id::EntityId;
use crate::registry::ENTITY_TYPE_AUTHORITY_LOG;
use crate::store::Store;
use crate::{Error, Result, SyncProtocolValidation, Vault};

/// Origin tag used for LMDB→CRDT bridge writes.
pub const BRIDGE_ORIGIN: &str = "bridge";
/// Origin for a local deletion tombstone whose durable LMDB carrier is
/// authored explicitly by the deletion TXN1, not Observer A. Observer B also
/// skips it, preserving the tombstone-first → local-purge ordering.
pub(crate) const DELETION_TOMBSTONE_ORIGIN: &str = "deletion_tombstone";

thread_local! {
    /// `write_crdt_tombstone` commits a live-doc update before it can assemble
    /// the snapshot/delta inputs for its one LMDB TXN1. Suppress Observer A
    /// only for that synchronous commit; the deletion path stages gate
    /// recovery first, then atomically persists the exact snapshot + queue
    /// delta.
    static SUPPRESS_OBSERVER_A_FOR_DELETION_TOMBSTONE: Cell<usize> = const { Cell::new(0) };
}

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
}

impl Default for Materializer {
    fn default() -> Self {
        Self {
            mutex: Mutex::new(()),
            lease_vault_id: crate::sync::lease::DEFAULT_LEASE_VAULT_ID,
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

const ERR_OBSERVER_A_U_SEQ_ROW: &str = "observer a u_seq row";

fn decode_observer_u_seq(raw: &[u8]) -> Result<u32> {
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
    );
    let edge_sub = subscribe_map_observer(
        doc,
        &edges_map,
        vault,
        materializer,
        window_key,
        materialize_edges_from_delta,
    );
    let tombstone_sub = subscribe_map_observer(
        doc,
        &tombstones_map,
        vault,
        materializer,
        window_key,
        materialize_tombstones_from_delta,
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
    materialize: fn(&LoroDoc, &loro::event::MapDelta<'_>, &Vault, &str, u64),
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
            if matches!(event.origin, BRIDGE_ORIGIN | DELETION_TOMBSTONE_ORIGIN) {
                return;
            }
            let _guard = materializer.lock();
            for cdiff in &event.events {
                if let Some(map_delta) = cdiff.diff.as_map() {
                    materialize(
                        &callback_doc,
                        map_delta,
                        &vault,
                        &window_key,
                        lease_vault_id,
                    );
                }
            }
        }),
    )
}

/// Materialize entity changes from a Loro MapDelta to LMDB.
///
/// Accumulates all entity ops from the delta into a single LMDB write
/// transaction instead of committing per-entity.
///
/// Write-gate rejections of REMOTE ops persist a quarantine record (`x:`
/// family, ONE-1124) and never abort the batch; LOCAL failures (the
/// engine's own LMDB errors) propagate fail-closed and abort the txn.
///
/// A whole-txn failure flags the durable entity-scoped
/// `rm:w:{window}:{entity_hex}` needs-remat marker for every op the dead
/// txn had applied (ONE-1147, parity with the hardened tombstone path) —
/// the ops stay committed in the CRDT doc, so a bare log would leave a
/// silent LMDB↔CRDT divergence until the next full window recovery.
fn materialize_entities_from_delta(
    doc: &LoroDoc,
    delta: &loro::event::MapDelta<'_>,
    vault: &Vault,
    window_key: &str,
    lease_vault_id: u64,
) {
    let tombstones_map = doc.get_map("tombstones");
    // ONE-1147: ids + op bytes applied into the batch txn, retained outside
    // it — on whole-txn failure there is no surviving per-entity failure
    // point (unlike the tombstone path), so the swallow site below needs
    // the full list to flag retry markers.
    let mut applied_ops: Vec<(EntityId, Vec<u8>)> = Vec::new();
    let mut pending_companion_scrubs = Vec::new();
    let result = ensure_companion_register_kind_for_entity_delta(vault, delta).and_then(|()| {
        vault.with_write_txn(|wtxn| {
        for (key, new_val) in &delta.updated {
            match new_val {
                Some(loro::ValueOrContainer::Value(loro::LoroValue::Binary(blob))) => {
                    // Pre-validate the REMOTE bytes structurally BEFORE any
                    // local read, so a later `CorruptedIndex` bubbling out of
                    // the engine's own rows is never conflated with a bad
                    // remote blob (LOCAL corruption = typed error, never
                    // quarantine-and-continue).
                    let Some(header) = EntityMetadataHeader::parse(blob) else {
                        quarantine_rejected_op_in_txn(
                            vault,
                            wtxn,
                            window_key,
                            QuarantineContainer::Entities,
                            key.as_ref(),
                            &Error::CorruptedIndex("entity metadata"),
                            blob,
                        )?;
                        continue;
                    };
                    let id = match EntityId::from_hex(key.as_ref()) {
                        Ok(id) => id,
                        Err(_) => {
                            quarantine_rejected_op_in_txn(
                                vault,
                                wtxn,
                                window_key,
                                QuarantineContainer::Entities,
                                key.as_ref(),
                                &Error::InvalidKey,
                                blob,
                            )?;
                            continue;
                        }
                    };
                    // ONE-1158: a non-canonical (case-shifted) hex alias key
                    // is a protocol violation — no engine version ever emits
                    // one (`to_hex()` is lowercase). Materializing it would
                    // leave the alias KEY live in the entities map while
                    // tombstone-commit removal deletes only the
                    // canonical-lowercase key: suppressed live-map byte
                    // residue (handoff §8c.2 family). Fail closed at the
                    // door: quarantine, never materialize.
                    if key.as_ref() != id.to_hex() {
                        quarantine_rejected_op_in_txn(
                            vault,
                            wtxn,
                            window_key,
                            QuarantineContainer::Entities,
                            key.as_ref(),
                            &Error::InvalidKey,
                            blob,
                        )?;
                        continue;
                    }
                    // ONE-1133 (ARCH-0038): a tombstone always wins over
                    // concurrent entities-map state. A re-put merged after
                    // the delete must never (re)materialize the body — no
                    // further tombstone event would fire to scrub it. The
                    // check is entity-canonical (a case-shifted hex
                    // tombstone key still names this id). Presence is
                    // value-agnostic (a non-binary tombstone decodes HARD
                    // downstream).
                    let delete_protected =
                        crate::registry::is_delete_protected_engine_record(header.entity_type);
                    if !delete_protected && tombstone_map_contains_id(&tombstones_map, &id) {
                        tracing::debug!(
                            entity = %key,
                            "observer-b: entity update suppressed by tombstone (delete wins)"
                        );
                        continue;
                    }
                    // `dt:` local hard-delete marker gate (ONE-1122),
                    // checked SECOND (LMDB point read) only when the map
                    // says absent: a hostile peer that REMOVES the
                    // tombstone and re-puts the entity key cannot resurrect
                    // the body. A failed marker read fails CLOSED
                    // (suppress); a refusal is the crafted-removal attack
                    // signal, surfaced at WARN.
                    let locally_hard_deleted = if delete_protected {
                        false
                    } else {
                        match vault.local_hard_delete_marker_exists_in_txn(wtxn, &id) {
                            Ok(present) => present,
                            Err(e) => {
                                tracing::warn!(
                                    entity = %key,
                                    error = %e,
                                    "observer-b: dt: marker read failed — failing closed"
                                );
                                true
                            }
                        }
                    };
                    if locally_hard_deleted {
                        tracing::warn!(
                            entity = %key,
                            "observer-b: entity locally hard-deleted (dt: marker), refusing materialization"
                        );
                        continue;
                    }
                    if matches!(companion_register_blob_is_local_only(blob), Ok(true)) {
                        pending_companion_scrubs
                            .push(CompanionCrdtScrub::new(key.as_ref(), id));
                        continue;
                    }
                    let materialize_result = materialize_entity_blob_in_txn(
                        vault,
                        wtxn,
                        &tombstones_map,
                        window_key,
                        key.as_ref(),
                        blob,
                        lease_vault_id,
                    );
                    match materialize_result {
                        Ok(true) => applied_ops.push((id, blob.to_vec())),
                        Ok(false) => {}
                        Err(e) => {
                            if remote_rejection_reason(&e).is_some() {
                                quarantine_rejected_op_in_txn(
                                    vault,
                                    wtxn,
                                    window_key,
                                    QuarantineContainer::Entities,
                                    key.as_ref(),
                                    &e,
                                    blob,
                                )?;
                            } else {
                                // LOCAL failure — fail closed, abort the batch.
                                return Err(e);
                            }
                        }
                    }
                }
                None => {
                    // Deleted — no action for entities (use tombstones instead)
                }
                _ => {
                    // Non-binary value where an entity blob belongs —
                    // undecodable remote op, quarantined (never a bare log).
                    quarantine_rejected_op_in_txn(
                        vault,
                        wtxn,
                        window_key,
                        QuarantineContainer::Entities,
                        key.as_ref(),
                        &Error::InvalidKey,
                        &[],
                    )?;
                }
            }
        }
        #[cfg(test)]
        if take_injected_batch_commit_failure() {
            return Err(Error::Io(std::io::Error::other(
                "injected batch commit failure (test hook)",
            )));
        }
        Ok(())
        })
    });

    if result.is_ok()
        && let Err(e) = scrub_local_only_companions_from_crdt(doc, &pending_companion_scrubs)
    {
        tracing::error!(
            error = %e,
            window = %window_key,
            "observer-b: local-only companion CRDT scrub failed after entity batch commit"
        );
    }

    if let Err(e) = result {
        // ONE-1147: the whole batch txn aborted — every applied op's write
        // (and any quarantine row staged alongside) is lost while the ops
        // stay committed in the CRDT doc. Flag each affected id with the
        // durable entity-scoped rm: marker so the drain re-runs forward
        // remat for this window. Ids whose COMMITTED bytes already equal
        // the op's bytes are skipped: nothing was lost for them, and an
        // at-parity marker could never discharge (discharge requires the
        // actual healing re-write to land — never mere byte-parity, which
        // a failed GDPR purge also exhibits).
        //
        // Layering: markers are BEST-EFFORT durability on an already-failing
        // env — a marker write that itself fails (env down hard) is logged
        // at ERROR and dropped; window recovery's forward remat on the
        // pinned open order remains the backstop.
        let mut seen = HashSet::new();
        let mut marked = 0usize;
        for (id, blob) in &applied_ops {
            // Parity-check BEFORE dedupe: a src/id whose first op is at
            // parity must not shadow a later diverged op for the same id.
            if committed_entity_state_matches(vault, id, blob) || !seen.insert(*id) {
                continue;
            }
            if set_remat_marker_logged(vault, window_key, id) {
                marked += 1;
            }
        }
        tracing::error!(
            error = %e,
            window = %window_key,
            applied_ops = applied_ops.len(),
            marked,
            "observer-b: entity batch commit failed — flagged entity-scoped rm: markers for durable retry"
        );
    }
}

/// Materialize edge changes from a Loro MapDelta to LMDB.
///
/// Accumulates all edge ops from the delta into a single LMDB write
/// transaction instead of committing per-edge.
///
/// Write-gate rejections of REMOTE ops persist a quarantine record (`x:`
/// family, ONE-1124) and never abort the batch; LOCAL failures (the
/// engine's own LMDB errors) propagate fail-closed and abort the txn.
///
/// A whole-txn failure flags the durable `rm:w:{window}:{entity_hex}`
/// needs-remat marker for each batched edge upsert's SOURCE entity
/// (ONE-1147): the drain is window-scoped — any marker makes forward remat
/// re-walk the whole window's entities/edges maps, so the source id is
/// sufficient to get the edge re-processed, and the marker discharges when
/// the healing edge write lands.
fn materialize_edges_from_delta(
    doc: &LoroDoc,
    delta: &loro::event::MapDelta<'_>,
    vault: &Vault,
    window_key: &str,
    lease_vault_id: u64,
) {
    // ONE-1147: source id + LMDB edge key + op bytes for every UPSERT
    // pushed into the batch, retained outside the txn for the swallow site
    // below (no surviving per-op failure point on whole-txn failure).
    let mut applied_edges: Vec<(EntityId, [u8; 33], Vec<u8>)> = Vec::new();
    // ONE-1147 fix-wave: id + written blob for every endpoint whose body this
    // batch HYDRATED-AND-WROTE into LMDB (the `Hydrated` outcome below),
    // retained outside the txn alongside `applied_edges`. A whole-txn
    // rollback erases those hydration writes too; the swallow site flags each
    // for durable remat. Without this, an endpoint hydrated inside the edge
    // batch and rolled back is silently lost — no edge need even have been
    // tracked (e.g. the partner endpoint failed LOCALLY and aborted the batch
    // BEFORE `applied_edges.push`).
    let mut hydrated_endpoints: Vec<(EntityId, Vec<u8>)> = Vec::new();
    let mut pending_companion_scrubs = Vec::new();
    let result = vault.with_write_txn(|wtxn| {
        let entities_map = doc.get_map("entities");
        let tombstones_map = doc.get_map("tombstones");
        let mut ops = Vec::<BatchOp>::new();
        let mut metas = Vec::<EdgeOpMeta>::new();
        for (key, new_val) in &delta.updated {
            match new_val {
                Some(loro::ValueOrContainer::Value(loro::LoroValue::Binary(buf))) => {
                    let Some((src, kind, tgt)) = parse_edge_key(key.as_ref()) else {
                        quarantine_rejected_op_in_txn(
                            vault,
                            wtxn,
                            window_key,
                            QuarantineContainer::Edges,
                            key.as_ref(),
                            &Error::InvalidKey,
                            buf,
                        )?;
                        continue;
                    };

                    // Decode BEFORE endpoint hydration: a malformed value is
                    // a remote rejection regardless of endpoint state, and
                    // decode has no side effects.
                    let decoded = match decode_edge_value_for_kind(kind, buf) {
                        Ok(v) => v,
                        Err(e) => {
                            quarantine_rejected_op_in_txn(
                                vault,
                                wtxn,
                                window_key,
                                QuarantineContainer::Edges,
                                key.as_ref(),
                                &e,
                                buf,
                            )?;
                            continue;
                        }
                    };

                    let reserved_rejection = crate::edge::validate_public_edge_kind(kind).err();
                    let src_ready = ensure_entity_materialized_from_crdt(
                        vault,
                        wtxn,
                        &entities_map,
                        &tombstones_map,
                        window_key,
                        &src,
                        lease_vault_id,
                    );
                    let tgt_ready = ensure_entity_materialized_from_crdt(
                        vault,
                        wtxn,
                        &entities_map,
                        &tombstones_map,
                        window_key,
                        &tgt,
                        lease_vault_id,
                    );
                    // ONE-1147 fix-wave: record every endpoint this batch
                    // ACTUALLY wrote (Hydrated) BEFORE the match may
                    // abort/defer/quarantine the edge — the hydration write
                    // has already landed in the txn and a rollback erases it
                    // regardless of the edge's fate. Already-present (Ready)
                    // endpoints wrote nothing and are never recorded. `src`
                    // and `tgt` are `Copy`, so the moves into the match below
                    // are unaffected.
                    if let Ok(EndpointHydration::Hydrated(blob)) = &src_ready {
                        hydrated_endpoints.push((src, blob.clone()));
                    }
                    if let Ok(EndpointHydration::Hydrated(blob)) = &tgt_ready {
                        hydrated_endpoints.push((tgt, blob.clone()));
                    }
                    if matches!(&src_ready, Ok(EndpointHydration::LocalOnly)) {
                        pending_companion_scrubs.push(CompanionCrdtScrub::new(src.to_hex(), src));
                    }
                    if matches!(&tgt_ready, Ok(EndpointHydration::LocalOnly)) {
                        pending_companion_scrubs.push(CompanionCrdtScrub::new(tgt.to_hex(), tgt));
                    }

                    // ARCH-0055 reserved-kind gate: `merged_into` /
                    // `split_into` carry redirect-shell lifecycle meaning,
                    // and the raw edges CRDT map is peer-controlled input
                    // with no write authority over them. Hydrate BOTH
                    // endpoints first: a successful endpoint put retriggers
                    // the shared deferred-topology reconciliation, so this
                    // mandate read sees the participant types the edge delta
                    // just revealed. The edge is then admitted ONLY as the
                    // BYTE-EXACT echo of a door side-effect: the local
                    // validated type-76 ledger must mandate exactly this
                    // pair AND the value must carry the door-written bytes
                    // (default weight, the event's `at` as `created_at`). A
                    // missing mandate or peer-chosen bytes remain a
                    // quarantine-and-continue rejection; no reserved edge
                    // lands merely because hydration ran first.
                    if let Some(reserved) = &reserved_rejection {
                        let mandated_at = vault.identity_topology_mandated_shell_edge_in_txn(
                            &*wtxn, &src, kind, &tgt,
                        )?;
                        let door_echo = mandated_at.is_some_and(|at| {
                            decoded.created_at == at
                                && kind.default_weight() == Some(decoded.weight)
                        });
                        if !door_echo {
                            quarantine_rejected_op_in_txn(
                                vault,
                                wtxn,
                                window_key,
                                QuarantineContainer::Edges,
                                key.as_ref(),
                                reserved,
                                buf,
                            )?;
                            continue;
                        }
                    }

                    match (src_ready, tgt_ready) {
                        // Both endpoints present — already there (`Ready`) or
                        // just hydrated this batch (`Hydrated`): the edge may
                        // proceed in either case.
                        (
                            Ok(EndpointHydration::Ready | EndpointHydration::Hydrated(_)),
                            Ok(EndpointHydration::Ready | EndpointHydration::Hydrated(_)),
                        ) => {}
                        (Ok(EndpointHydration::LocalOnly), Ok(_))
                        | (Ok(_), Ok(EndpointHydration::LocalOnly)) => {
                            tracing::warn!(
                                edge = %key,
                                "observer-b: edge scrubbed because it touches a local-only companion register row"
                            );
                            continue;
                        }
                        (Ok(EndpointHydration::RejectedBlob), Ok(_))
                        | (Ok(_), Ok(EndpointHydration::RejectedBlob)) => {
                            // The endpoint's CRDT blob is undecodable REMOTE
                            // garbage — the edge op is rejected with it:
                            // quarantine and continue, never abort the batch
                            // (the blob came from the remote doc, not the
                            // engine's own rows).
                            quarantine_rejected_op_in_txn(
                                vault,
                                wtxn,
                                window_key,
                                QuarantineContainer::Edges,
                                key.as_ref(),
                                &Error::CorruptedIndex("entity metadata"),
                                buf,
                            )?;
                            continue;
                        }
                        (Ok(_), Ok(_)) => {
                            // Endpoint absent or tombstoned in the CRDT — a
                            // deferral (cross-window endpoints arrive later;
                            // tombstoned endpoints never resurrect), not a
                            // write-gate rejection. The edge stays in the
                            // CRDT and re-materializes when its endpoints do.
                            tracing::debug!(
                                edge = %key,
                                "observer-b: edge deferred — endpoint absent or tombstoned"
                            );
                            continue;
                        }
                        // Fail-closed split (ONE-1124 fix wave 2): a LOCAL
                        // (non-remote-classifiable) error on EITHER endpoint
                        // aborts the batch FIRST. Matching
                        // `(Err(e), _) | (_, Err(e))` unconditionally would
                        // bind a remote-rejectable src error and silently
                        // swallow a local tgt failure behind an x: row that
                        // pretends the edge was handled.
                        (Err(e), _) if remote_rejection_reason(&e).is_none() => {
                            return Err(e);
                        }
                        (_, Err(e)) if remote_rejection_reason(&e).is_none() => {
                            return Err(e);
                        }
                        (Err(e), _) | (_, Err(e)) => {
                            // Every endpoint error left here is
                            // remote-rejectable: the endpoint's CRDT blob
                            // failed the entity write gate, so this edge op
                            // is rejected with it — quarantine and continue.
                            quarantine_rejected_op_in_txn(
                                vault,
                                wtxn,
                                window_key,
                                QuarantineContainer::Edges,
                                key.as_ref(),
                                &e,
                                buf,
                            )?;
                            continue;
                        }
                    }

                    // ONE-1645 `FacetOf` type table, Observer-B door.
                    //
                    // This is the SYNCHRONOUS path a member/guest import takes
                    // into a LOADED window: `import_federated_window_update`
                    // imports the admitted bytes into the live doc, Observer B
                    // fires inline, and the edge lands through the
                    // deliberately UNGATED `BatchOp::EdgeWithCreatedAt` arm —
                    // never crossing forward rematerialization, where the
                    // replay gate lives. Without this call the whole table is
                    // absent from production's hottest federation path.
                    //
                    // Ordered AFTER endpoint hydration/readiness for the same
                    // reason as the remat gate: the table reads endpoint types
                    // from entity ROWS, and the match above has just proved
                    // both endpoints present (hydrating them from the CRDT
                    // when needed). Running it earlier would read `None` for a
                    // legitimate same-frame endpoint and reject it.
                    //
                    // Guarded (ONE-1124): only a remote-classifiable rejection
                    // quarantines; a LOCAL fault (corrupted stored header,
                    // heed read error) aborts the batch. An `x:` row for our
                    // own defect would be permanent false evidence against the
                    // peer.
                    match crate::batch::validate_facet_of_edge(
                        &vault.store,
                        &*wtxn,
                        src,
                        kind,
                        tgt,
                    ) {
                        Ok(()) => {}
                        Err(off_table)
                            if remote_rejection_reason(&off_table).is_some() =>
                        {
                            quarantine_rejected_op_in_txn(
                                vault,
                                wtxn,
                                window_key,
                                QuarantineContainer::Edges,
                                key.as_ref(),
                                &off_table,
                                buf,
                            )?;
                            continue;
                        }
                        Err(local) => return Err(local),
                    }

                    applied_edges.push((
                        src,
                        Store::encode_edge_key(&src, kind, &tgt),
                        buf.to_vec(),
                    ));
                    ops.push(BatchOp::EdgeWithCreatedAt {
                        src,
                        kind,
                        tgt,
                        weight: decoded.weight,
                        created_at: decoded.created_at,
                        vad: decoded.vad.unwrap_or(Vad::NEUTRAL),
                        provenance: decoded.provenance,
                    });
                    metas.push(EdgeOpMeta::for_key(key.as_ref(), buf));
                }
                None => {
                    // Deleted.
                    //
                    // ONE-1147: bare edge-map removals are deliberately NOT
                    // flagged with rm: markers on batch failure — forward
                    // remat (the drain's only heal step) iterates the
                    // CURRENT edges map and has no delete leg, so such a
                    // marker could never discharge; recovery's reverse pass
                    // re-mirrors the surviving in-range LMDB edge back into
                    // the CRDT (LMDB wins for absent-from-CRDT records), so
                    // a lost removal converges edge-alive rather than
                    // staying silently divergent. Entity deletions ride the
                    // tombstone path, which has its own hardened rm:
                    // producer.
                    let Some((src, kind, tgt)) = parse_edge_key(key.as_ref()) else {
                        quarantine_rejected_op_in_txn(
                            vault,
                            wtxn,
                            window_key,
                            QuarantineContainer::Edges,
                            key.as_ref(),
                            &Error::InvalidKey,
                            &[],
                        )?;
                        continue;
                    };
                    // ARCH-0055 reserved-kind gate, removal side: a raw
                    // edges-map removal must not tear a shell edge the
                    // validated ledger still mandates (an unledgered
                    // merge/split teardown → EntityNotFound-shaped wedge).
                    // The honest undo path deletes the edge as the
                    // ingested counter-event's door side-effect; after
                    // that the fold no longer mandates it and the removal
                    // echo passes through as a no-op delete.
                    if let Err(reserved) = crate::edge::validate_public_edge_kind(kind)
                        && vault
                            .identity_topology_mandated_shell_edge_in_txn(&*wtxn, &src, kind, &tgt)?
                            .is_some()
                    {
                        quarantine_rejected_op_in_txn(
                            vault,
                            wtxn,
                            window_key,
                            QuarantineContainer::Edges,
                            key.as_ref(),
                            &reserved,
                            &[],
                        )?;
                        continue;
                    }
                    ops.push(BatchOp::DeleteEdge { src, kind, tgt });
                    metas.push(EdgeOpMeta::for_key(key.as_ref(), &[]));
                }
                _ => {
                    // Non-binary value where an edge value belongs —
                    // undecodable remote op, quarantined (never a bare log).
                    quarantine_rejected_op_in_txn(
                        vault,
                        wtxn,
                        window_key,
                        QuarantineContainer::Edges,
                        key.as_ref(),
                        &Error::InvalidKey,
                        &[],
                    )?;
                }
            }
        }
        apply_materialized_edge_ops(vault, wtxn, ops, &metas, window_key)?;
        #[cfg(test)]
        if take_injected_batch_commit_failure() {
            return Err(Error::Io(std::io::Error::other(
                "injected batch commit failure (test hook)",
            )));
        }
        Ok(())
    });

    if result.is_ok()
        && let Err(e) = scrub_local_only_companions_from_crdt(doc, &pending_companion_scrubs)
    {
        tracing::error!(
            error = %e,
            window = %window_key,
            "observer-b: local-only companion CRDT scrub failed after edge batch commit"
        );
    }

    if let Err(e) = result {
        // ONE-1147: whole-txn failure — same marker semantics and
        // best-effort layering as the entity swallow site above. Two classes
        // of write the dead txn rolled back get a durable entity-scoped rm:
        // marker, de-duped through ONE shared `seen` set so an id that is
        // both is marked exactly once:
        //   (1) ONE-1147 fix-wave — every endpoint this batch HYDRATED-AND-
        //       WROTE (`hydrated_endpoints`): the rolled-back hydration write
        //       is otherwise silently lost, even when no edge was tracked
        //       (a partner endpoint may have aborted the batch before the
        //       edge reached `applied_edges`); and
        //   (2) the SOURCE entity of every lost edge upsert (`applied_edges`).
        // The committed_*_state_matches guards skip any id whose COMMITTED
        // bytes already equal the op's bytes (nothing lost; an at-parity
        // marker could never discharge — forward remat heals on the actual
        // healing write only, never on parity).
        let mut seen = HashSet::new();
        let mut marked = 0usize;
        for (id, blob) in &hydrated_endpoints {
            if committed_entity_state_matches(vault, id, blob) || !seen.insert(*id) {
                continue;
            }
            if set_remat_marker_logged(vault, window_key, id) {
                marked += 1;
            }
        }
        for (src, edge_key, buf) in &applied_edges {
            if committed_edge_state_matches(vault, edge_key, buf) || !seen.insert(*src) {
                continue;
            }
            if set_remat_marker_logged(vault, window_key, src) {
                marked += 1;
            }
        }
        tracing::error!(
            error = %e,
            window = %window_key,
            applied_ops = applied_edges.len(),
            hydrated_endpoints = hydrated_endpoints.len(),
            marked,
            "observer-b: edge batch commit failed — flagged entity-scoped rm: markers for durable retry"
        );
    }
}

/// ONE-1147 (best-effort, post-abort): `true` ONLY when the committed
/// entity bytes provably equal the op's bytes — the failed txn lost nothing
/// for this id. Any read error reports `false`: over-marking is the
/// conservative direction (forward remat is idempotent and byte-compares
/// before writing).
fn committed_entity_state_matches(vault: &Vault, id: &EntityId, blob: &[u8]) -> bool {
    let Ok(rtxn) = vault.store.env.read_txn() else {
        return false;
    };
    matches!(
        vault.store.entities.get(&rtxn, id.as_bytes()),
        Ok(Some(existing)) if *existing == *blob
    )
}

/// ONE-1147 (best-effort, post-abort): `true` ONLY when the committed
/// `edges_out` bytes provably equal the op's bytes. Read errors report
/// `false` (mark — conservative direction).
fn committed_edge_state_matches(vault: &Vault, edge_key: &[u8; 33], buf: &[u8]) -> bool {
    let Ok(rtxn) = vault.store.env.read_txn() else {
        return false;
    };
    matches!(
        vault.store.edges_out.get(&rtxn, edge_key),
        Ok(Some(existing)) if *existing == *buf
    )
}

/// Writes one `rm:w:{window}:{entity_hex}` marker in its OWN txn (the
/// failed batch txn is dead). A marker-write failure is logged at ERROR and
/// swallowed. Batch-failure markers carry replay provenance so terminal
/// quarantine can discharge them without clearing delete-safety markers.
/// Window recovery's forward remat remains the backstop (see the batch
/// swallow sites for the layering).
fn set_remat_marker_logged(vault: &Vault, window_key: &str, id: &EntityId) -> bool {
    match quarantine::set_replay_remat_marker(vault, window_key, id) {
        Ok(()) => true,
        Err(marker_err) => {
            tracing::error!(
                entity = %id.to_hex(),
                window = %window_key,
                error = %marker_err,
                "observer-b: CRITICAL — failed to set rm: marker after batch commit failure"
            );
            false
        }
    }
}

// Test-only whole-batch commit failure injection for the ONE-1147 rm:
// marker round-trip tests: when armed, the next entity/edge materialization
// batch returns a LOCAL (non-remote-classifiable) error from inside the
// write closure AFTER all ops were applied — the txn aborts exactly like an
// env-level commit failure. Counts down per batch on the current thread
// (Loro observer callbacks fire synchronously on the committing thread).
#[cfg(test)]
thread_local! {
    pub(crate) static INJECT_BATCH_COMMIT_FAILURES: std::cell::Cell<u32> =
        const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn take_injected_batch_commit_failure() -> bool {
    INJECT_BATCH_COMMIT_FAILURES.with(|cell| {
        let remaining = cell.get();
        if remaining > 0 {
            cell.set(remaining - 1);
            true
        } else {
            false
        }
    })
}

#[derive(Clone)]
struct PendingChildOfOp {
    index: usize,
    src: EntityId,
    tgt: EntityId,
    op: BatchOp,
}

/// Quarantine bookkeeping for one edge op, index-aligned with the ops vec.
/// Carries bounded non-content metadata only: the CRDT map key is
/// attacker-controlled, so it is hashed up front and never retained
/// (ONE-1124 — `x:` rows are hash+metadata, never content).
#[derive(Clone)]
struct EdgeOpMeta {
    crdt_key_hash: u64,
    crdt_key_len: u32,
    payload_hash: u64,
    remat_marker_entity: Option<EntityId>,
}

impl EdgeOpMeta {
    fn for_key(crdt_key: &str, payload: &[u8]) -> Self {
        let (crdt_key_hash, crdt_key_len) = quarantine::crdt_key_metadata(crdt_key);
        Self {
            crdt_key_hash,
            crdt_key_len,
            payload_hash: quarantine::payload_hash(payload),
            remat_marker_entity: quarantine::remat_marker_entity_for_quarantine(
                QuarantineContainer::Edges,
                crdt_key,
            ),
        }
    }
}

fn quarantine_edge_apply_failure(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    window_key: &str,
    meta: &EdgeOpMeta,
    error: &Error,
) -> Result<()> {
    quarantine::record_in_txn(
        vault,
        wtxn,
        &quarantine::QuarantineRecord {
            window_key: window_key.to_string(),
            container: QuarantineContainer::Edges,
            crdt_key_hash: meta.crdt_key_hash,
            crdt_key_len: meta.crdt_key_len,
            reason_code: quarantine::reason_code_for(error),
            payload_hash: meta.payload_hash,
            quarantined_at: crate::unix_seconds_now(),
        },
    )?;
    if let Some(id) = meta.remat_marker_entity {
        quarantine::set_replay_remat_marker_in_txn(vault, wtxn, window_key, &id)?;
    }
    Ok(())
}

/// Applies materialized edge ops. A write-gate rejection quarantines the
/// rejected op (every op of a rejected ChildOf component) and continues;
/// a LOCAL failure propagates fail-closed.
fn apply_materialized_edge_ops(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    ops: Vec<BatchOp>,
    metas: &[EdgeOpMeta],
    window_key: &str,
) -> Result<()> {
    debug_assert_eq!(ops.len(), metas.len());
    let mut child_of_adds = Vec::<PendingChildOfOp>::new();
    let mut child_of_deletes = Vec::<PendingChildOfOp>::new();

    for (index, op) in ops.into_iter().enumerate() {
        // ARCH-0052 P6: no incident-edge membership walk here. A replicated
        // edge naming a live overlay member is refused by the K4 taint guard
        // inside the applying transaction and quarantined as
        // `OffRecordTaintedBaseWrite` on the ordinary rejection path, so a
        // second endpoint probe would only duplicate that verdict earlier.
        match &op {
            BatchOp::EdgeWithCreatedAt { src, kind, tgt, .. }
            | BatchOp::Edge { src, kind, tgt, .. }
                if *kind == EdgeKind::ChildOf =>
            {
                child_of_adds.push(PendingChildOfOp {
                    index,
                    src: *src,
                    tgt: *tgt,
                    op,
                });
            }
            BatchOp::DeleteEdge { src, kind, tgt } if *kind == EdgeKind::ChildOf => {
                child_of_deletes.push(PendingChildOfOp {
                    index,
                    src: *src,
                    tgt: *tgt,
                    op,
                });
            }
            _ => {
                let apply_result = batch::apply_ops(
                    &vault.store,
                    &vault.config,
                    &vault.analyzer,
                    wtxn,
                    vec![op],
                    vault
                        .text_index_trusted
                        .load(std::sync::atomic::Ordering::Acquire),
                    false,
                    false,
                );
                match apply_result {
                    Err(e) if remote_rejection_reason(&e).is_none() => return Err(e),
                    Err(e) => {
                        quarantine_edge_apply_failure(vault, wtxn, window_key, &metas[index], &e)?;
                    }
                    Ok(()) => {}
                }
            }
        }
    }

    child_of_deletes.sort_by(cmp_pending_child_of_ops);
    for pending in child_of_deletes {
        let index = pending.index;
        let apply_result = batch::apply_ops(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            wtxn,
            vec![pending.op],
            vault
                .text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            false,
        );
        match apply_result {
            Err(e) if remote_rejection_reason(&e).is_none() => return Err(e),
            Err(e) => {
                quarantine_edge_apply_failure(vault, wtxn, window_key, &metas[index], &e)?;
            }
            Ok(()) => {}
        }
    }

    let mut components = child_of_components(&child_of_adds);
    components.sort_by(|left, right| {
        child_of_component_sort_key(left)
            .cmp(&child_of_component_sort_key(right))
            .then_with(|| left.len().cmp(&right.len()))
    });
    for component in components {
        let mut component_ops = component;
        component_ops.sort_by(cmp_pending_child_of_ops);
        let ops: Vec<BatchOp> = component_ops.iter().map(|entry| entry.op.clone()).collect();
        let apply_result = batch::apply_ops(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            wtxn,
            ops,
            vault
                .text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            false,
        );
        match apply_result {
            Err(e) if remote_rejection_reason(&e).is_none() => return Err(e),
            Err(_) => {
                // The component was rejected as a unit (a remote ChildOf cycle
                // or single-parent violation — both up-front validation gates,
                // nothing staged). Re-apply per-op in the same deterministic
                // order so only the ops that individually fail a gate are
                // quarantined — never falsely recording siblings that are valid
                // on their own.
                for pending in component_ops {
                    let apply_result = batch::apply_ops(
                        &vault.store,
                        &vault.config,
                        &vault.analyzer,
                        wtxn,
                        vec![pending.op],
                        vault
                            .text_index_trusted
                            .load(std::sync::atomic::Ordering::Acquire),
                        false,
                        false,
                    );
                    match apply_result {
                        Err(e) if remote_rejection_reason(&e).is_none() => return Err(e),
                        Err(e) => {
                            quarantine_edge_apply_failure(
                                vault,
                                wtxn,
                                window_key,
                                &metas[pending.index],
                                &e,
                            )?;
                        }
                        Ok(()) => {}
                    }
                }
            }
            Ok(()) => {}
        }
    }
    Ok(())
}

fn child_of_components(ops: &[PendingChildOfOp]) -> Vec<Vec<PendingChildOfOp>> {
    let mut adjacency = HashMap::<EntityId, HashSet<EntityId>>::new();
    for op in ops {
        adjacency.entry(op.src).or_default().insert(op.tgt);
        adjacency.entry(op.tgt).or_default().insert(op.src);
    }

    let mut components = Vec::new();
    let mut visited = HashSet::<EntityId>::new();
    let mut starts = adjacency.keys().copied().collect::<Vec<_>>();
    starts.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    for start in starts {
        if !visited.insert(start) {
            continue;
        }

        let mut stack = vec![start];
        let mut nodes = HashSet::from([start]);
        while let Some(node) = stack.pop() {
            if let Some(neighbors) = adjacency.get(&node) {
                let mut sorted_neighbors = neighbors.iter().copied().collect::<Vec<_>>();
                sorted_neighbors.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
                for neighbor in sorted_neighbors {
                    if visited.insert(neighbor) {
                        stack.push(neighbor);
                        nodes.insert(neighbor);
                    }
                }
            }
        }

        components.push(
            ops.iter()
                .filter(|op| nodes.contains(&op.src))
                .cloned()
                .collect(),
        );
    }

    components
}

fn pending_child_of_sort_key(op: &PendingChildOfOp) -> [u8; 33] {
    Store::encode_edge_key(&op.src, EdgeKind::ChildOf, &op.tgt)
}

fn cmp_pending_child_of_ops(
    left: &PendingChildOfOp,
    right: &PendingChildOfOp,
) -> std::cmp::Ordering {
    pending_child_of_sort_key(left)
        .cmp(&pending_child_of_sort_key(right))
        .then_with(|| left.index.cmp(&right.index))
}

fn child_of_component_sort_key(component: &[PendingChildOfOp]) -> [u8; 33] {
    component
        .iter()
        .map(pending_child_of_sort_key)
        .min()
        .expect("child-of component must be non-empty")
}

/// Materialize tombstone changes — apply deletes to LMDB.
///
/// ONE-1133 (ARCH-0038): each tombstone routes through the reason-aware
/// replay primitive [`Vault::apply_replayed_tombstone`], never a bare
/// purge. The VALUE decides the effect: a known-soft `user_delete` value
/// keeps the 25 B shell (SoftErase + D16 refresh); every other shape —
/// hard reasons, legacy 8-byte, reserved 0, unknown bytes, malformed,
/// and non-binary values — hard-purges and, when local state was erased,
/// writes the LOCAL REDACTION_AUDIT receipt and `h:` sweep row.
///
/// A replay failure is the fail-OPEN delete hole: hard-deleted content stays
/// live locally with no retry. It now writes the ARCH-0023b
/// needs-rematerialization marker `rm:w:{window}:{entity_hex}` ("set on
/// Observer B failure", entity-scoped) so maintain/doctor retries it
/// durably (ONE-1124 AC4) — a GDPR SLA breach signal until drained.
fn materialize_tombstones_from_delta(
    doc: &LoroDoc,
    delta: &loro::event::MapDelta<'_>,
    vault: &Vault,
    window_key: &str,
    _lease_vault_id: u64,
) {
    let entities_map = doc.get_map("entities");
    for (key, new_val) in &delta.updated {
        match new_val {
            Some(value) => {
                // New tombstone added
                let id = match EntityId::from_hex(key.as_ref()) {
                    Ok(id) => id,
                    Err(_) => {
                        let payload = match value {
                            loro::ValueOrContainer::Value(loro::LoroValue::Binary(bytes)) => {
                                bytes.to_vec()
                            }
                            _ => Vec::new(),
                        };
                        if let Err(e) = quarantine_rejected_op(
                            vault,
                            window_key,
                            QuarantineContainer::Tombstones,
                            key.as_ref(),
                            &Error::InvalidKey,
                            &payload,
                        ) {
                            tracing::error!(
                                tombstone = %key,
                                error = %e,
                                "observer-b: failed to persist tombstone quarantine record"
                            );
                        }
                        continue;
                    }
                };

                // A non-binary tombstone value has no decodable reason —
                // it replays as the empty value, which decodes HARD
                // (fail-closed: over-purge, never under-delete).
                let raw_value: &[u8] = match value {
                    loro::ValueOrContainer::Value(loro::LoroValue::Binary(blob)) => blob,
                    _ => &[],
                };

                // Protection must not depend on observer callback order.
                // A concurrent engine-authored blob may not have reached
                // LMDB yet, so inspect its envelope directly and quarantine
                // the tombstone before the headerless hard-delete path can
                // mint a permanent `dt:` marker.
                if matches!(vault.read_entity_header(&id), Ok(None))
                    && let Some(entity_blob) = map_get_bytes(&entities_map, &id.to_hex())
                    && let Some(header) = admitted_concurrent_delete_protected_header(&entity_blob)
                {
                    let rejection = Error::MaintenanceKindNotWritable(header.entity_type);
                    if let Err(quarantine_err) = quarantine_rejected_op(
                        vault,
                        window_key,
                        QuarantineContainer::Tombstones,
                        key.as_ref(),
                        &rejection,
                        raw_value,
                    ) {
                        tracing::error!(
                            tombstone = %key,
                            window = %window_key,
                            error = %quarantine_err,
                            "observer-b: failed to quarantine concurrent protected-record tombstone"
                        );
                    }
                    continue;
                }

                let hard_tombstone = crate::deletion::decode_tombstone_value(raw_value).is_hard();
                match quarantine::apply_replayed_tombstone_for_sync(vault, &id, raw_value) {
                    Ok(_) if hard_tombstone => {
                        let scrub_result = vault.with_write_txn(|wtxn| {
                            scrub_receiver_outbox_on_remote_hard_delete_in_txn(
                                vault, wtxn, window_key,
                            )
                        });
                        if let Err(e) = scrub_result {
                            tracing::error!(
                                tombstone = %key,
                                window = %window_key,
                                error = %e,
                                "observer-b: receiver outbox scrub FAILED after hard tombstone replay; flagging entity-scoped rm: marker for durable retry"
                            );
                            if let Err(marker_err) =
                                quarantine::set_remat_marker(vault, window_key, &id)
                            {
                                tracing::error!(
                                    tombstone = %key,
                                    error = %marker_err,
                                    "observer-b: CRITICAL — failed to set rm: marker after receiver outbox scrub failure"
                                );
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(e) if quarantine::remote_rejection_reason(&e).is_some() => {
                        if let Err(quarantine_err) = quarantine_rejected_op(
                            vault,
                            window_key,
                            QuarantineContainer::Tombstones,
                            key.as_ref(),
                            &e,
                            raw_value,
                        ) {
                            tracing::error!(
                                tombstone = %key,
                                window = %window_key,
                                error = %quarantine_err,
                                "observer-b: failed to quarantine rejected protected-record tombstone"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::error!(
                            tombstone = %key,
                            window = %window_key,
                            error = %e,
                            "observer-b: tombstone replay FAILED — hard-deleted content may still be live; flagging entity-scoped rm: marker for durable retry"
                        );
                        if let Err(marker_err) =
                            quarantine::set_remat_marker(vault, window_key, &id)
                        {
                            tracing::error!(
                                tombstone = %key,
                                error = %marker_err,
                                "observer-b: CRITICAL — failed to set rm: marker after purge failure"
                            );
                        }
                    }
                }

                // ONE-1156(c) / WAVE-C OD-11, §8c.1 doc residue: a SOFT
                // value arriving over a locally hard-deleted id (`dt:`
                // present) can WIN the Loro map merge — LMDB stays safe
                // above (the replay primitive never downgrades), but the
                // doc now shows soft to every peer. Re-asserting here
                // would write into the doc INSIDE an observer callback
                // (the re-entrancy bar), so enqueue the durable
                // `ra:w:{window}:{entity_hex}` marker (value = the `dt:`
                // row's exact 25 B — local HARD truth) for the
                // safe-commit-point drain. No `dt:` row ⇒ no marker (the
                // helper checks).
                if !hard_tombstone
                    && let Err(marker_err) =
                        quarantine::enqueue_tombstone_reassert_marker(vault, window_key, &id)
                {
                    tracing::error!(
                        tombstone = %key,
                        window = %window_key,
                        error = %marker_err,
                        "observer-b: CRITICAL — failed to enqueue ra: re-assertion marker for soft-over-hard doc residue"
                    );
                }
            }
            None => {
                // Tombstone REMOVAL delta: no engine version ever emits one
                // — tombstones are permanent (never-downgrade,
                // hard-once-seen), so a removal is a protocol violation by
                // definition. The `dt:` marker gate keeps the local hard
                // delete closed regardless. Quarantine it (x: row,
                // hash+metadata only) and continue. The tombstone is NOT
                // re-asserted here — a doc write inside an observer
                // callback re-enters Loro (handoff §8c.1); instead, for a
                // locally hard-deleted id, the durable `ra:` marker below
                // queues the re-assertion for the safe-commit-point drain
                // (ONE-1156(c), WAVE-C OD-11).
                if let Err(e) = quarantine_rejected_op(
                    vault,
                    window_key,
                    QuarantineContainer::Tombstones,
                    key.as_ref(),
                    &Error::sync_protocol(SyncProtocolValidation::TombstoneRemovalDelta),
                    &[],
                ) {
                    tracing::error!(
                        tombstone = %key,
                        error = %e,
                        "observer-b: failed to persist tombstone-removal quarantine record"
                    );
                }
                // OD-11, HARD-only: a dt:-backed marker carries the
                // faithful 25 B local truth; a soft removal stays
                // quarantine-only (residual R4 — a reconstructed soft
                // value cannot be faithful, and an incorrectly decoded value would
                // HARD-purge a user-kept shell at peers). An unparsable
                // key cannot name a `dt:` row at all — quarantine above
                // already recorded it.
                if let Ok(id) = EntityId::from_hex(key.as_ref())
                    && let Err(marker_err) =
                        quarantine::enqueue_tombstone_reassert_marker(vault, window_key, &id)
                {
                    tracing::error!(
                        tombstone = %key,
                        window = %window_key,
                        error = %marker_err,
                        "observer-b: CRITICAL — failed to enqueue ra: re-assertion marker after tombstone removal"
                    );
                }
            }
        }
    }
}

fn materialize_entity_blob_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    tombstones_map: &LoroMap,
    window_key: &str,
    key: &str,
    blob: &[u8],
    lease_vault_id: u64,
) -> Result<bool> {
    let id = EntityId::from_hex(key).map_err(|_| crate::Error::InvalidKey)?;
    let Some(header) = EntityMetadataHeader::parse(blob) else {
        return Err(crate::Error::CorruptedIndex("entity metadata"));
    };
    let delete_protected = crate::registry::is_delete_protected_engine_record(header.entity_type);

    // Tombstone gate — fires BEFORE the put, never heals after (ARCH-0023b:
    // "If tombstoned in CRDT → never resurrect"; contracts.ts
    // `user_hard_delete`: "Tombstone-first prevents sync resurrection").
    // Hard delete purges LMDB but leaves the stale blob in the live CRDT
    // entities map (`write_crdt_tombstone` only inserts into `tombstones`),
    // so ANY later commit touching this entity key would otherwise
    // rematerialize the purged body into LMDB with no compensating purge —
    // tombstone deltas only fire when the tombstones map CHANGES.
    // Presence is ANY-value (fail closed): non-binary tombstones gate too —
    // and entity-canonical: a case-shifted hex key still names this id.
    if !delete_protected && tombstone_map_contains_id(tombstones_map, &id) {
        tracing::debug!(entity = %key, "observer-b: entity tombstoned in CRDT, skipping put");
        return Ok(false);
    }

    // `dt:` local hard-delete marker gate (ONE-1122): the CRDT tombstones
    // map is MUTABLE remote input — a crafted update can REMOVE a tombstone
    // and re-put the entity key, passing the map check above and resurrecting
    // a hard-deleted body permanently (no tombstone left to re-fire). The
    // dt: row is local-only truth written in the origin purge txn; checked
    // SECOND (LMDB point read) only when the in-memory map says absent.
    // PRESENCE-ONLY — never decode the value. Canonical lowercase hex via
    // the parsed id, so a case-shifted map key cannot dodge the point read.
    if !delete_protected && vault.local_hard_delete_marker_exists_in_txn(wtxn, &id)? {
        tracing::warn!(
            entity = %key,
            "observer-b: entity locally hard-deleted (dt: marker), refusing materialization"
        );
        return Ok(false);
    }

    let data = if blob.len() > ENTITY_METADATA_HEADER_LEN {
        &blob[ENTITY_METADATA_HEADER_LEN..]
    } else {
        &[]
    };

    if header.entity_type == ENTITY_TYPE_COMPANION_REGISTER
        && !companion_register_sync_admitted(data)?
    {
        tracing::warn!(
            entity = %key,
            "observer-b: refused local-only companion register materialization"
        );
        return Ok(false);
    }

    // ONE-1134 + ONE-1140: REDACTION_AUDIT (type 120) replay door. Receipts
    // are immutable audit records (contracts.ts `redactionAuditReceipt`;
    // ARCH-0023b audit/guardrail stream class: quarantine divergence, never
    // silent LWW), so before any byte is staged, in pinned order:
    //
    // 1. the body must satisfy the pinned receipt field set, now including
    //    the four-entry att_ verification grammar (ONE-1140 v2) — a blob
    //    that fails receipt decode is a remote rejection (quarantined by
    //    the callers via `remote_rejection_reason`);
    // 2. immutability (UNCHANGED, before any crypto — accepted local bytes
    //    always win): id absent locally → fall through to the origin
    //    predicate; id present with byte-identical envelope → idempotent
    //    no-op (own-receipt CRDT round-trips stay green); id present with
    //    DIVERGENT bytes → typed rejection, LOCAL bytes are kept and the
    //    remote payload is quarantined;
    // 3. NEW id: Ed25519 transcript verification against the embedded
    //    att_pk (ONE-1140 OD-6), and
    // 4. `ls:` lease-binding point read in the SAME txn (OD-3/OD-7: absent
    //    → ReceiptLeaseUnknown; pubkey mismatch → ReceiptAttestationInvalid;
    //    revoked → ReceiptLeaseRevoked; active|expired → accept).
    //
    // All checks run before `put_replicated` stages anything, so a rejected
    // receipt never leaves partial writes in the transaction. A quarantined
    // receipt's bytes remain in the CRDT map, so the next forward
    // rematerialization re-admits it once the lease mirror catches up
    // (OD-10 lazy re-admission — no new scheduling machinery).
    let quota_debit = if header.entity_type == crate::registry::ENTITY_TYPE_REDACTION_AUDIT {
        crate::deletion::validate_redaction_receipt_body(data)?;
        if let Some(existing) = vault.store.entities.get(&*wtxn, id.as_bytes())? {
            if *existing == *blob {
                return Ok(false);
            }
            // ONE-1087 designed exception: the sweep executor's receipt
            // finalization (`sweep_complete_at` None→Some) is LOCAL-LMDB
            // -only, so the CRDT mirror keeps replaying the PRE-finalization
            // bytes forever. That one monotone shape — identical envelope
            // and fields, local Some vs incoming nil — is the own node's
            // stale echo: idempotent skip, never quarantine, never
            // overwrite local. Every other divergence stays on the M4-07
            // quarantine path.
            if crate::deletion::redaction_receipt_is_stale_finalization_echo(&existing, blob) {
                tracing::debug!(
                    entity = %key,
                    "observer-b: stale pre-finalization receipt echo — keeping finalized local"
                );
                return Ok(false);
            }
            return Err(crate::Error::RedactionReceiptDivergence { id });
        }
        let pubkey = crate::sync::lease::verify_new_receipt_origin_for_vault_in_txn(
            vault,
            wtxn,
            lease_vault_id,
            &id,
            blob,
        )?;
        quota::try_accept_maintenance_ingest_peer_in_txn(
            vault,
            wtxn,
            quota::peer_key_from_redaction_pubkey(&pubkey),
            crate::unix_seconds_now(),
        )?
    } else if header.entity_type == ENTITY_TYPE_AUTHORITY_LOG {
        if let Some(existing) = vault.store.entities.get(&*wtxn, id.as_bytes())?
            && *existing == *blob
        {
            quarantine_and_neutralize_protected_tombstone_in_txn(
                vault,
                wtxn,
                tombstones_map,
                window_key,
                &id,
                header.entity_type,
            )?;
            return Ok(false);
        }
        let validation = crate::batch::validate_replicated_authority_log_for_local_vault(
            &vault.store,
            wtxn,
            &id,
            data,
        )?;
        let peer_key = if validation.signer_known {
            quota::peer_key_from_authority_key(&validation.signer_key)
        } else {
            quota::peer_key_from_unknown_authority_signer(validation.local_vault_id)
        };
        quota::try_accept_maintenance_ingest_peer_in_txn(
            vault,
            wtxn,
            peer_key,
            crate::unix_seconds_now(),
        )?
    } else if header.entity_type == crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT {
        // ARCH-0055 identity-topology ledger events route through the ONE
        // shared fail-closed ingest door (validation, per-stream quota,
        // seq-clock join, shell-edge reconciliation) — the same door
        // forward rematerialization uses, so no sync entry point admits
        // the byte outside the ruled trust model.
        let materialized = ingest_replicated_identity_topology_event_in_txn(
            vault,
            wtxn,
            &id,
            &header,
            blob,
            data,
            lease_vault_id,
        )?;
        quarantine_and_neutralize_protected_tombstone_in_txn(
            vault,
            wtxn,
            tombstones_map,
            window_key,
            &id,
            header.entity_type,
        )?;
        return Ok(materialized);
    } else {
        None
    };

    // Replicated put: Observer B mirrors whatever the unfiltered CRDT
    // entities map holds, including the engine-authored maintenance band
    // (REDACTION_AUDIT = 120) and reserved-predicate `edge.provenance`
    // truth-Claims. The public gate would warn-skip those, losing GDPR
    // receipts / edge-provenance truth on sync; `put_replicated` admits both
    // engine-authored bands while still validating structure: unknown type
    // bytes, ungrammatical predicates, and malformed CLAIM bodies fail the
    // D18 gate typed, and `edge.provenance` Claims additionally get full
    // value-record + actor-class-evidence validation at the same write
    // chokepoint (ONE-1159) — a D18-valid wrapper around a structurally
    // invalid provenance record is a typed rejection HERE (quarantined by
    // the callers via `remote_rejection_reason`, exactly like a rejected
    // receipt above), no longer a stored Claim that fails closed only at
    // read/supersede time.
    let apply_result = vault
        .batch_in()
        .put_replicated(
            &id,
            header.entity_type,
            crate::temporal::TimeRange {
                start: header.occurred_start,
                end: header.occurred_end,
            },
            header.learned_at,
            data,
        )
        .apply(wtxn);
    if let Err(err) = apply_result {
        if let Some(quota_debit) = quota_debit {
            quota::rollback_maintenance_ingest_debit_in_txn(vault, wtxn, quota_debit)?;
        }
        return Err(err);
    }
    if delete_protected {
        quarantine_and_neutralize_protected_tombstone_in_txn(
            vault,
            wtxn,
            tombstones_map,
            window_key,
            &id,
            header.entity_type,
        )?;
    }
    Ok(true)
}

fn quarantine_and_neutralize_protected_tombstone_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    tombstones_map: &LoroMap,
    window_key: &str,
    id: &EntityId,
    entity_type: u8,
) -> Result<()> {
    let rejection = Error::MaintenanceKindNotWritable(entity_type);
    let crdt_key = id.to_hex();
    for tombstone in tombstone_values_for_id(tombstones_map, id) {
        quarantine_rejected_op_in_txn(
            vault,
            wtxn,
            window_key,
            QuarantineContainer::Tombstones,
            &crdt_key,
            &rejection,
            &tombstone,
        )?;
    }
    vault.neutralize_delete_protected_marker_in_txn(wtxn, id, entity_type)?;
    Ok(())
}

/// Classifies a concurrent peer envelope for tombstone protection only after
/// running the same deterministic body predicate as replicated type-76
/// ingestion. Other established protected kinds retain their existing
/// classification; type-76 must never gain protection from its header alone.
pub(crate) fn admitted_concurrent_delete_protected_header(
    blob: &[u8],
) -> Option<EntityMetadataHeader> {
    let header = EntityMetadataHeader::parse(blob)?;
    if !crate::registry::is_delete_protected_engine_record(header.entity_type) {
        return None;
    }
    if header.entity_type == crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT {
        let data = &blob[ENTITY_METADATA_HEADER_LEN..];
        crate::identity_topology::decode_replicated_identity_topology_event_body(data).ok()?;
    }
    Some(header)
}

/// Shared fail-closed ingest door for replicated type-76 identity-topology
/// event records (ARCH-0023b single-writer stream class, AUTHORITY_LOG
/// shape). Observer B's entity pass and forward rematerialization BOTH
/// route here, so every sync entry point enforces the same trust model:
///
/// * byte-identical replay → idempotent short-circuit after validation and
///   seq-clock join, before quota or full-family reconciliation; derived
///   shell healing rides the bounded edge echo/materialization paths rather
///   than making unchanged startup replay quadratic;
/// * divergent bytes for an existing id → typed
///   [`crate::Error::IdentityTopologyEventDivergence`] (equivocation on an
///   immutable single-writer record: local bytes win; callers quarantine
///   via `remote_rejection_reason`, never abort, never silent-LWW);
/// * a fresh id → fail-closed D18 body validation, per-stream ingest
///   quota, the replicated put, then `seq = max(local, incoming)` and
///   shell-edge reconciliation from the ledger fold — the sync twin of the
///   local door's atomic record+edges commit (the ruled invariant:
///   `merged_into` / `split_into` edges only move as a door side-effect of
///   a validated type-76 event).
pub(crate) fn ingest_replicated_identity_topology_event_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    header: &EntityMetadataHeader,
    blob: &[u8],
    data: &[u8],
    lease_vault_id: u64,
) -> Result<bool> {
    let byte_identical_replay = vault
        .store
        .entities
        .get(&*wtxn, id.as_bytes())?
        .map(|existing| *existing == *blob);
    match byte_identical_replay {
        Some(true) => {
            // The stored bytes equal the replayed bytes, so a decode
            // failure here is on-disk corruption — LOCAL, fail-closed —
            // never a rejectable remote input.
            let record =
                crate::identity_topology::decode_replicated_identity_topology_event_body(data)
                    .map_err(|_| crate::Error::CorruptedIndex("identity topology event body"))?;
            validate_replicated_identity_topology_record_before_mutation(vault, &*wtxn, &record)?;
            vault.advance_identity_topology_seq_in_txn(wtxn, record.seq)?;
            vault.neutralize_delete_protected_marker_in_txn(
                wtxn,
                id,
                crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
            )?;
            return Ok(false);
        }
        Some(false) => {
            return Err(crate::Error::IdentityTopologyEventDivergence { id: *id });
        }
        None => {}
    }
    let record = crate::identity_topology::decode_replicated_identity_topology_event_body(data)?;
    validate_replicated_identity_topology_record_before_mutation(vault, &*wtxn, &record)?;
    let quota_debit = quota::try_accept_maintenance_ingest_peer_in_txn(
        vault,
        wtxn,
        quota::peer_key_from_identity_topology_stream(lease_vault_id),
        crate::unix_seconds_now(),
    )?;
    let apply_result = vault
        .batch_in()
        .put_replicated(
            id,
            header.entity_type,
            crate::temporal::TimeRange {
                start: header.occurred_start,
                end: header.occurred_end,
            },
            header.learned_at,
            data,
        )
        .apply(wtxn);
    if let Err(err) = apply_result {
        if let Some(quota_debit) = quota_debit {
            quota::rollback_maintenance_ingest_debit_in_txn(vault, wtxn, quota_debit)?;
        }
        return Err(err);
    }
    vault.advance_identity_topology_seq_in_txn(wtxn, record.seq)?;
    vault.reconcile_identity_topology_edges_in_txn(wtxn)?;
    vault.neutralize_delete_protected_marker_in_txn(
        wtxn,
        id,
        crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
    )?;
    Ok(true)
}

/// Maps the shared local-door participant rejection into the existing
/// type-76 remote-input class. This runs before quota, put, seq join, or
/// reconciliation, so quarantine-and-continue can never commit a rejected
/// event row as a side effect of handling the rejection.
fn validate_replicated_identity_topology_record_before_mutation(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    record: &crate::identity_topology::StoredIdentityOpEvent,
) -> Result<()> {
    vault
        .validate_replicated_identity_topology_event_in_txn(rtxn, record)
        .map_err(|err| match err {
            Error::IdentityTopologyRejected(
                crate::identity_topology::IdentityTopologyRejection::NotStructural { .. }
                | crate::identity_topology::IdentityTopologyRejection::FacetMerge { .. },
            ) => Error::InvalidIdentityTopologyEventBody(
                "identity topology event participant is not merge-eligible structural state",
            ),
            Error::ActorClassMismatch { .. } => Error::InvalidIdentityTopologyEventBody(
                "identity topology event actor class does not match the available actor",
            ),
            other => other,
        })
}

fn ensure_companion_register_kind_for_entity_delta(
    vault: &Vault,
    delta: &loro::event::MapDelta<'_>,
) -> Result<()> {
    for new_val in delta.updated.values() {
        let Some(loro::ValueOrContainer::Value(loro::LoroValue::Binary(blob))) = new_val else {
            continue;
        };
        let Some(header) = EntityMetadataHeader::parse(blob) else {
            continue;
        };
        if header.entity_type != ENTITY_TYPE_COMPANION_REGISTER {
            continue;
        }
        let data = if blob.len() > ENTITY_METADATA_HEADER_LEN {
            &blob[ENTITY_METADATA_HEADER_LEN..]
        } else {
            &[]
        };
        if companion_register_sync_admitted(data).unwrap_or(false) {
            vault.ensure_companion_register_kind()?;
            return Ok(());
        }
    }
    Ok(())
}

fn companion_register_sync_admitted(data: &[u8]) -> Result<bool> {
    let record = decode_companion_record_body(data)?;
    Ok(record.export_classification != CompanionExportClassification::LocalOnly)
}

fn companion_register_blob_is_local_only(blob: &[u8]) -> Result<bool> {
    let Some(header) = EntityMetadataHeader::parse(blob) else {
        return Err(Error::CorruptedIndex("entity metadata"));
    };
    if header.entity_type != ENTITY_TYPE_COMPANION_REGISTER {
        return Ok(false);
    }
    let data = if blob.len() > ENTITY_METADATA_HEADER_LEN {
        &blob[ENTITY_METADATA_HEADER_LEN..]
    } else {
        &[]
    };
    Ok(!companion_register_sync_admitted(data)?)
}

struct CompanionCrdtScrub {
    entity_key: String,
    id: EntityId,
}

impl CompanionCrdtScrub {
    fn new(entity_key: impl Into<String>, id: EntityId) -> Self {
        Self {
            entity_key: entity_key.into(),
            id,
        }
    }
}

fn scrub_local_only_companions_from_crdt(
    doc: &LoroDoc,
    scrubs: &[CompanionCrdtScrub],
) -> Result<()> {
    if scrubs.is_empty() {
        return Ok(());
    }

    let entities_map = doc.get_map("entities");
    let edges_map = doc.get_map("edges");
    let mut changed = false;
    let mut ids = HashSet::new();

    for scrub in scrubs {
        ids.insert(scrub.id);
        if entities_map.get(scrub.entity_key.as_str()).is_some() {
            map_delete(&entities_map, scrub.entity_key.as_str())?;
            changed = true;
        }
    }

    let mut edge_keys = Vec::new();
    map_for_each_bytes(&edges_map, |edge_key, _| {
        if let Some((src, _, tgt)) = parse_edge_key(edge_key)
            && (ids.contains(&src) || ids.contains(&tgt))
        {
            edge_keys.push(edge_key.to_owned());
        }
    });
    for edge_key in &edge_keys {
        map_delete(&edges_map, edge_key)?;
        changed = true;
    }

    if changed {
        doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
    }
    Ok(())
}

/// Endpoint hydration outcome for Observer B edge materialization.
enum EndpointHydration {
    /// Endpoint already present in LMDB — NO write was performed, so a batch
    /// rollback loses nothing for this endpoint (never flagged for remat).
    Ready,
    /// Endpoint body was just hydrated into LMDB from the CRDT entities map —
    /// an ACTUAL write. Carries the written blob so the edge-batch swallow
    /// site can flag a durable `rm:` marker for this endpoint if the whole
    /// txn rolls back (ONE-1147 fix-wave): the rolled-back hydration write
    /// would otherwise vanish silently — unmarked, and with no edge
    /// necessarily tracked to carry it. The caller treats it identically to
    /// `Ready` for the edge's own fate (the edge proceeds).
    Hydrated(Vec<u8>),
    /// Endpoint absent or tombstoned — defer the edge (it stays in the CRDT
    /// and re-materializes when its endpoint does).
    Deferred,
    /// Endpoint is a local-only companion register row. Edges touching it
    /// must not materialize or remain in a shared CRDT window.
    LocalOnly,
    /// The endpoint's CRDT entities-map blob is structurally undecodable —
    /// REMOTE garbage by construction (the blob came from the remote doc),
    /// so the edge op is rejected with it (quarantined by the caller). Never
    /// conflated with the engine's own LOCAL `CorruptedIndex`, which stays a
    /// fail-closed typed error.
    RejectedBlob,
}

// Test-only LOCAL endpoint-hydration failure injection for the fail-closed
// split tests: when set to an entity id, the next hydration of that id
// returns a non-remote-classifiable error (the engine's own read failing).
// One-shot, thread-local (Loro observer callbacks fire synchronously on the
// committing thread).
#[cfg(test)]
thread_local! {
    pub(crate) static INJECT_LOCAL_ENDPOINT_FAILURE: std::cell::Cell<Option<EntityId>> =
        const { std::cell::Cell::new(None) };
}

fn ensure_entity_materialized_from_crdt(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entities_map: &LoroMap,
    tombstones_map: &LoroMap,
    window_key: &str,
    id: &EntityId,
    lease_vault_id: u64,
) -> Result<EndpointHydration> {
    #[cfg(test)]
    {
        let inject = INJECT_LOCAL_ENDPOINT_FAILURE.with(|cell| {
            if cell.get() == Some(*id) {
                cell.set(None);
                true
            } else {
                false
            }
        });
        if inject {
            return Err(Error::Io(std::io::Error::other(
                "injected local endpoint read failure (test hook)",
            )));
        }
    }

    // Tombstone gate FIRST: a tombstoned OR locally hard-deleted (`dt:`
    // marker) endpoint must never count as "ready", even while a stale LMDB
    // row survives (crash window between the tombstone CRDT commit and the
    // purge txn, or a failed purge). Checking row existence first would
    // materialize an edge onto the stale row — re-adding an active carrier
    // ARCH-0038 requires purged. Presence is ANY-value (fail closed):
    // non-binary tombstones gate too. Without the dt: leg, a crafted
    // tombstone removal would make the silent gate-skip read as "ready" and
    // push an edge op against a missing endpoint;
    // `materialize_entity_blob_in_txn` re-checks both as the structural
    // fail-closed gate before its put.
    //
    // Value-agnostic, entity-canonical tombstone presence (a non-binary
    // tombstone decodes HARD downstream; a case-shifted hex key still
    // names this id) OR the permanent local `dt:` marker: an edge whose
    // endpoint was hard-deleted must not hydrate the endpoint body back
    // into LMDB even after hostile tombstone-map manipulation.
    if tombstone_map_contains_id(tombstones_map, id)
        || vault.local_hard_delete_marker_exists_in_txn(wtxn, id)?
    {
        return Ok(EndpointHydration::Deferred);
    }

    if let Some(raw) = vault.store.entities.get(&*wtxn, id.as_bytes())? {
        if companion_register_blob_is_local_only(&raw)? {
            return Ok(EndpointHydration::LocalOnly);
        }
        return Ok(EndpointHydration::Ready);
    }

    let hex_id = id.to_hex();
    let Some(blob) = map_get_bytes(entities_map, &hex_id) else {
        return Ok(EndpointHydration::Deferred);
    };
    // Structural pre-validation of the REMOTE blob (mirrors the entity
    // delta path's decode-before-local-read ordering): an unparsable
    // endpoint blob is remote garbage, distinguished from the LOCAL
    // `CorruptedIndex` that `materialize_entity_blob_in_txn` would conflate
    // it with at the caller's classification.
    if EntityMetadataHeader::parse(&blob).is_none() {
        return Ok(EndpointHydration::RejectedBlob);
    }
    if companion_register_blob_is_local_only(&blob)? {
        return Ok(EndpointHydration::LocalOnly);
    }
    if !materialize_entity_blob_in_txn(
        vault,
        wtxn,
        tombstones_map,
        window_key,
        &hex_id,
        &blob,
        lease_vault_id,
    )? {
        return Ok(EndpointHydration::Deferred);
    }
    // ONE-1147 fix-wave: distinguish an ACTUAL hydration write from the
    // already-present `Ready` above, carrying the written bytes so the
    // edge-batch swallow site can flag a durable rm: marker (parity guard +
    // heal-on-write discharge) if this write is later rolled back. `blob` is
    // moved into the variant after `materialize_entity_blob_in_txn` borrowed
    // it.
    Ok(EndpointHydration::Hydrated(blob))
}

/// Parses an edge key: `{src_hex}:{kind_u8:02}:{tgt_hex}` → (src, kind, tgt).
///
/// Uses `:` delimiter splitting instead of byte-index slicing for panic safety.
pub fn parse_edge_key(key: &str) -> Option<(EntityId, EdgeKind, EntityId)> {
    let mut parts = key.splitn(3, ':');
    let src_hex = parts.next()?;
    let kind_str = parts.next()?;
    let tgt_hex = parts.next()?;

    // Validate expected segment lengths (32-char hex IDs, 2-char kind)
    if src_hex.len() != 32 || kind_str.len() != 2 || tgt_hex.len() != 32 {
        return None;
    }

    let src = EntityId::from_hex(src_hex).ok()?;
    let kind_u8: u8 = kind_str.parse().ok()?;
    let kind = EdgeKind::try_from_u8(kind_u8)?;
    let tgt = EntityId::from_hex(tgt_hex).ok()?;
    Some((src, kind, tgt))
}

/// Parses a 12/24/26-byte edge value.
pub fn parse_edge_value(buf: &[u8]) -> Option<DecodedEdgeValue> {
    decode_edge_value(buf).ok()
}

/// Encodes an edge value for CRDT map storage using the ARCH-0034 layout class.
pub fn encode_edge_value_for_crdt(
    kind: EdgeKind,
    weight: f32,
    created_at: u64,
    vad: Option<Vad>,
    provenance: Option<EdgeProvenanceFlags>,
) -> Result<Vec<u8>> {
    encode_edge_value(
        kind,
        weight,
        created_at,
        vad.unwrap_or(Vad::NEUTRAL),
        provenance,
    )
}

/// Formats an edge key for CRDT map: `{src_hex}:{kind:02}:{tgt_hex}`.
pub fn format_edge_key(src: &EntityId, kind: EdgeKind, tgt: &EntityId) -> String {
    format!("{}:{:02}:{}", src.to_hex(), kind as u8, tgt.to_hex())
}

#[cfg(test)]
mod tests;
