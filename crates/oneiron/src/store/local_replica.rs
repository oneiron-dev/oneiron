//! Local-only removal of one canonical window's replica (OF-534 demotion).
//!
//! The physical delete tear writes deletion-shaped state (audit rows,
//! retirement markers, withdrawal stamps), so this door does not call it. It
//! runs the tear's pure local leaves for each removable member, then drops
//! the window's persisted document rows. Nothing replicated is written: no
//! tombstone, deletion marker, audit row, Loro op, outbox row or receipt. An
//! epoch summary's session floor is the one local row it raises.
//! [`purge_left_shared_env_in_txn`] empties a left shared vault's whole
//! environment the same way (OF-158).
//!
//! The local derivations of a removed TURN (its tag set, its sieve working
//! state, its projection rounds) also reach other turns: a provisional
//! entity it named, a round it shares. Their owners' demotion leaves settle
//! them over the call's whole set before any row or edge goes, unerased,
//! and never retag or reread a kept turn. A promotion that brings a TURN
//! back owes it a tag pass and a sieve read ([`owe_promoted_turn_in_txn`]).

mod left_env;

#[allow(unused_imports, reason = "L03's OF-158 leave calls these")]
pub(crate) use left_env::{LEFT_ENV_KEPT_SAMPLE, LeftEnvPurge, purge_left_shared_env_in_txn};

use std::collections::{BTreeSet, HashSet};
use std::ops::Bound;

use heed::{RoTxn, RwTxn};
use loro::{LoroDoc, LoroMap};

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::dreamer_runner::authority::is_base_agent_actor;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::{
    EdgeDirection, EdgeStoreRead, EdgeStoreStaging, EntityStoreRead, EntityStoreStaging,
    ShortIdStoreRead, TimelineQuery, WindowAddress, WindowDeletionRows,
};
use crate::registry;
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;
use crate::sync::WindowKey;
use crate::sync::bridge::format_edge_key;
use crate::sync::loro_support::{
    TombstoneIndex, doc_from_snapshot, import_doc, map_contains_binary,
};
use crate::sync::residence::residence_window_for_blob;
use crate::sync::window_rows::{
    OFF_RECORD_PROMOTE_PICKUP, WINDOW_SHALLOW_FENCE, WINDOW_SNAPSHOT, WINDOW_STATE_VECTOR,
    WINDOW_UPDATE, WindowEntityKey,
};
use crate::temporal::TimeRange;

/// Unacknowledged local text-document frames (`qd:e:{id}:{seq}`), read for
/// presence only.
const PENDING_DOCUMENT_FRAMES: SideTable<Vec<u8>, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_QD_E);
/// NOTE requests awaiting their receipt (`qn:e:{id}:{request}`), read for
/// presence only.
const PENDING_NOTE_REQUESTS: SideTable<Vec<u8>, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_QN_E);

/// Authority, grant, policy, key, consent, receipt and identity-ledger kinds,
/// plus the machine, world and agent-definition rows they govern.
const KEPT_KINDS: &[u8] = &[
    registry::ENTITY_TYPE_AUTHORITY_LOG,
    registry::ENTITY_TYPE_POLICY_MANIFEST,
    registry::ENTITY_TYPE_FEDERATION_GRANT,
    registry::ENTITY_TYPE_ACCESS_GRANT,
    registry::ENTITY_TYPE_SECRET_CUSTODY,
    registry::ENTITY_TYPE_WORLD_KEY_PAD,
    registry::ENTITY_TYPE_REDACTION_AUDIT,
    registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
    registry::ENTITY_TYPE_CONNECTOR_KEY,
    registry::ENTITY_TYPE_CHANNEL_IDENTITY,
    registry::ENTITY_TYPE_COUNTERPARTY_CONTACT,
    registry::ENTITY_TYPE_OUTBOUND_GRANT,
    registry::ENTITY_TYPE_COMM_RECORD,
    registry::ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT,
    registry::ENTITY_TYPE_RECEIPT_RECORD,
    registry::ENTITY_TYPE_SKILL_CONTENT_ANCHOR,
    registry::ENTITY_TYPE_SKILL_HUB,
    registry::ENTITY_TYPE_MACHINE,
    registry::ENTITY_TYPE_WORLD,
    registry::ENTITY_TYPE_AGENT_DEF,
];

/// What [`remove_local_replica_window_in_txn`] leaves in place.
#[allow(dead_code, reason = "L03's OF-534 demotion calls this")]
#[derive(Debug, Clone)]
pub(crate) struct KeepControls {
    /// Entity kinds kept whole.
    pub(crate) kinds: Vec<u8>,
    /// Keep every actor the authority fold binds, the embedded owner and the
    /// base agents.
    pub(crate) bound_actors: bool,
    /// Keep rows an engine delete guard refuses: controls inside ordinary
    /// kinds.
    pub(crate) guarded_rows: bool,
    /// Remove nothing while the outbox queues a write for this window.
    pub(crate) defer_on_queued_writes: bool,
    /// Most entity rows one call removes.
    pub(crate) max_removals: usize,
}

impl Default for KeepControls {
    fn default() -> Self {
        Self {
            kinds: KEPT_KINDS.to_vec(),
            bound_actors: true,
            guarded_rows: true,
            defer_on_queued_writes: true,
            max_removals: 1024,
        }
    }
}

/// Why a member stayed.
#[allow(dead_code, reason = "L03's OF-534 demotion calls this")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeepReason {
    /// Its kind is in [`KeepControls::kinds`].
    Kind(u8),
    /// A bound actor, the embedded owner or a base agent.
    BoundActor,
    /// The window document holds a tombstone for it: deletion state.
    Tombstoned,
    /// The window document does not carry it (a local-only or unmirrored
    /// row), so no server copy could give it back.
    NotCarried,
    /// A pending tombstone, pickup marker, document frame or NOTE request
    /// names it.
    Pending,
    /// An engine delete guard refuses it.
    Guarded,
    /// A standing legal hold names it (OF-470).
    LegalHold,
    /// A TURN that is the origin of a provisional entity a kept tag set or a
    /// legal hold still needs, which no kept turn's text can take over: its
    /// tag set is that entity's only readable source here.
    ProvisionalOrigin,
}

/// What one call removed and kept, for the caller's log.
#[allow(dead_code, reason = "L03's OF-534 demotion calls this")]
#[derive(Debug, Default)]
pub(crate) struct RemovedReplica {
    /// Entity rows removed with their projections, in learned order.
    pub(crate) removed: Vec<EntityId>,
    /// Members left in place, each with its reason.
    pub(crate) kept: Vec<(EntityId, KeepReason)>,
    /// Removable members past `max_removals`, left for the next call.
    pub(crate) remaining: usize,
    /// Edge pairs removed.
    pub(crate) edges: usize,
    /// Text vectors removed.
    pub(crate) vectors: usize,
    /// `u:w:` rows removed.
    pub(crate) update_rows: usize,
    /// Whether a `d:w:` snapshot was removed.
    pub(crate) snapshot: bool,
    /// Outbox rows queued for this window. They are never touched.
    pub(crate) queued_writes: usize,
    /// The window rows went with the last removable member. `false` when the
    /// outbox deferred the call or `remaining` is not zero: call again.
    pub(crate) complete: bool,
}

/// Removes one canonical window's local LMDB replica in the caller's write
/// transaction. Run it with the window closed
/// (`WindowManager::while_window_closed`); `rp:w:` stays the caller's.
///
/// Members are the rows learned in the window's month whose canonical window
/// is this one. A member goes, with its type/time/edge/claim/text/vector
/// projections, only when the window's persisted document carries it (so
/// promotion can give it back) and no keep rule holds it. When the last such
/// member is gone, `d:w:`, its state vector and freshness byte and every
/// `u:w:` row go too. Unconfirmed queued writes stay: with the default
/// controls a queued `q:` row for the window defers the whole call.
///
/// A removed TURN leaves its tag set, its sieve working state and its
/// projection rounds through their owners' demotion leaves, which run over
/// the call's whole set first; a kept TURN that loses a MESSAGE keeps its
/// own, which read as absent until the message is back.
///
/// One call removes at most `keep.max_removals` rows. Loop until `complete`,
/// holding the window closed across the calls.
#[allow(dead_code, reason = "L03's OF-534 demotion calls this")]
pub(crate) fn remove_local_replica_window_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    window: &WindowKey,
    keep: KeepControls,
) -> Result<RemovedReplica> {
    let queued_writes =
        crate::sync::queue::queued_window_update_count_in_txn(store, txn, window.as_str())?;
    let mut report = RemovedReplica {
        queued_writes,
        ..RemovedReplica::default()
    };
    if keep.defer_on_queued_writes && queued_writes > 0 {
        return Ok(report);
    }
    let doc = persisted_window_doc(store, txn, window)?;
    let census = Census::new(store, txn, window, &keep, &doc)?;
    let removable = census.sort(txn, &mut report)?;
    report.remaining = removable.len().saturating_sub(keep.max_removals);
    let batch = &removable[..removable.len().min(keep.max_removals)];
    let removal = Removal::plan(store, txn, batch, &mut report)?;
    // The leaves read the removed rows, their edges and other turns' sets.
    crate::tagging::demote_tags_in_txn(store, txn, &removal.gone, &removal.partial)?;
    crate::dreamer_wake::demote_in_txn(store, txn, &removal.gone)?;
    let edges = doc.get_map("edges");
    for id in &removal.order {
        remove_member(store, txn, &edges, id, &mut report)?;
    }
    if report.vectors > 0 {
        crate::hnsw::increment_vector_version(store, txn)?;
    }
    if !report.removed.is_empty() {
        crate::ppr::increment_graph_version(store, txn)?;
    }
    if report.remaining == 0 {
        remove_window_rows(store, txn, window, &mut report)?;
        report.complete = true;
    }
    Ok(report)
}

/// The window's persisted document, read in the caller's transaction: the
/// `d:w:` snapshot, or a fresh document, with every `u:w:` row on top, as the
/// manager's open path loads it.
fn persisted_window_doc(store: &Store, txn: &RoTxn<'_>, window: &WindowKey) -> Result<LoroDoc> {
    let address = WindowAddress::new(window.as_str());
    let doc = store
        .port_window_doc_with_raw(txn, address, doc_from_snapshot)?
        .unwrap_or_else(LoroDoc::new);
    for row in store.port_window_updates(txn, address, |_, update| import_doc(&doc, update))? {
        row??;
    }
    Ok(doc)
}

/// One pass's keep rules over the window's members.
struct Census<'a> {
    store: &'a Store,
    window: &'a WindowKey,
    keep: &'a KeepControls,
    bound: BTreeSet<EntityId>,
    entities: LoroMap,
    tombstones: TombstoneIndex,
}

impl<'a> Census<'a> {
    fn new(
        store: &'a Store,
        txn: &RoTxn<'_>,
        window: &'a WindowKey,
        keep: &'a KeepControls,
        doc: &LoroDoc,
    ) -> Result<Self> {
        let mut bound = BTreeSet::new();
        if keep.bound_actors {
            let fold = crate::authority::authority_fold_readonly_for_store_in_txn(
                store,
                store.privacy_posture,
                txn,
            )?;
            for binding in fold.actor_bindings.values() {
                bound.insert(binding.actor_ref);
            }
            bound.insert(crate::vault::embedded_owner_actor_id()?);
        }
        Ok(Self {
            store,
            window,
            keep,
            bound,
            entities: doc.get_map("entities"),
            tombstones: TombstoneIndex::build(&doc.get_map("tombstones")),
        })
    }

    /// Walks the month on the learned-time index, records each kept member in
    /// `report` and returns the removable ones in learned order.
    fn sort(&self, txn: &RoTxn<'_>, report: &mut RemovedReplica) -> Result<Vec<EntityId>> {
        let start = self.window.start_timestamp();
        let end = self.window.end_timestamp();
        let (Some(start), Some(end)) = (start, end) else {
            return Err(Error::InvalidConfig("invalid window key".to_string()));
        };
        let query = TimelineQuery {
            start: Bound::Included(start),
            end: Bound::Excluded(end),
            ..TimelineQuery::default()
        };
        let mut seen = HashSet::new();
        let mut removable = Vec::new();
        for row in self.store.port_entity_timeline(txn, query)? {
            let id = row?.id;
            if !seen.insert(id) {
                continue;
            }
            let Some(raw) = self.store.port_entity_raw(txn, &id)? else {
                continue;
            };
            // A world window's month also holds base rows and other worlds.
            if residence_window_for_blob(&raw).ok().as_ref() != Some(self.window) {
                continue;
            }
            match self.keep_reason(txn, &id, &raw)? {
                Some(reason) => report.kept.push((id, reason)),
                None => removable.push(id),
            }
        }
        Ok(removable)
    }

    fn keep_reason(
        &self,
        txn: &RoTxn<'_>,
        id: &EntityId,
        raw: &[u8],
    ) -> Result<Option<KeepReason>> {
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity metadata"))?;
        let kind = header.entity_type;
        let reason = if self.keep.kinds.contains(&kind) {
            KeepReason::Kind(kind)
        } else if crate::store::legal_hold::held_in_txn(self.store, txn, id.as_bytes())? {
            KeepReason::LegalHold
        } else if self.keep.bound_actors && (self.bound.contains(id) || is_base_agent_actor(id)?) {
            KeepReason::BoundActor
        } else if self.tombstones.contains(id) {
            KeepReason::Tombstoned
        } else if !map_contains_binary(&self.entities, &id.to_hex()) {
            KeepReason::NotCarried
        } else if self.pending(txn, id)? {
            KeepReason::Pending
        } else if self.keep.guarded_rows && guarded(self.store, txn, id) {
            KeepReason::Guarded
        } else {
            return Ok(None);
        };
        Ok(Some(reason))
    }

    /// Local intent the window document does not hold yet.
    fn pending(&self, txn: &RoTxn<'_>, id: &EntityId) -> Result<bool> {
        let window = self.window.as_str().to_owned();
        let pickup = WindowEntityKey {
            window,
            entity: *id,
        };
        if self.store.port_pending_tombstone_present(
            txn,
            WindowAddress::new(self.window.as_str()),
            id,
        )? || OFF_RECORD_PROMOTE_PICKUP.contains(self.store, txn, &pickup)?
        {
            return Ok(true);
        }
        let prefix = format!("{}:", id.to_hex());
        let mut frames =
            PENDING_DOCUMENT_FRAMES.iter_raw_from(self.store, txn, prefix.as_bytes())?;
        let mut notes = PENDING_NOTE_REQUESTS.iter_raw_from(self.store, txn, prefix.as_bytes())?;
        Ok(frames.next().is_some() || notes.next().is_some())
    }
}

/// One call's removals, planned whole before any row or edge goes.
struct Removal {
    /// The members this call removes, in learned order.
    order: Vec<EntityId>,
    /// The same members, for the demotion leaves.
    gone: BTreeSet<EntityId>,
    /// The kept TURNs a removed MESSAGE is part of: their words read partly
    /// here until promotion, so their own rows stay as they are.
    partial: BTreeSet<EntityId>,
}

impl Removal {
    /// Plans `batch`, the census's removable members this call takes. A TURN
    /// a provisional entity still needs as its origin stays whole, and the
    /// rest is planned again without it, until no such turn is left.
    fn plan(
        store: &Store,
        txn: &RoTxn<'_>,
        batch: &[EntityId],
        report: &mut RemovedReplica,
    ) -> Result<Self> {
        let mut order = batch.to_vec();
        loop {
            let gone: BTreeSet<EntityId> = order.iter().copied().collect();
            let partial = partial_turns(store, txn, &gone)?;
            let kept = crate::tagging::demotion_kept_origins_in_txn(store, txn, &gone, &partial)?;
            if kept.is_empty() {
                return Ok(Self {
                    order,
                    gone,
                    partial,
                });
            }
            order.retain(|id| !kept.contains(id));
            for id in kept {
                report.kept.push((id, KeepReason::ProvisionalOrigin));
            }
        }
    }
}

/// The kept TURNs a MESSAGE in `gone` is part of, read before its edges go.
fn partial_turns(
    store: &Store,
    txn: &RoTxn<'_>,
    gone: &BTreeSet<EntityId>,
) -> Result<BTreeSet<EntityId>> {
    let mut turns = BTreeSet::new();
    for id in gone {
        if store
            .port_entity_record(txn, id)?
            .is_none_or(|row| row.entity_type != registry::ENTITY_TYPE_MESSAGE)
        {
            continue;
        }
        for edge in store.port_edges(txn, id, EdgeDirection::Out, Some(EdgeKind::PartOf), None)? {
            let turn = edge?.target;
            if !gone.contains(&turn)
                && store
                    .port_entity_record(txn, &turn)?
                    .is_some_and(|row| row.entity_type == registry::ENTITY_TYPE_TURN)
            {
                turns.insert(turn);
            }
        }
    }
    Ok(turns)
}

/// What a promotion owes a TURN it brings back (OF-534), in the transaction
/// that lands the row: demotion dropped its tag set and its sieve reading,
/// which never sync, so an armed vault owes it a tag pass, and the sieve,
/// whose cursor has passed it, a read. A kept TURN whose MESSAGE comes back
/// is owed neither: its stored set and spans read again with the message.
#[allow(dead_code, reason = "L03's OF-534 promotion calls this")]
pub(crate) fn owe_promoted_turn_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    turn: &EntityId,
) -> Result<()> {
    crate::tagging::mark_turn_in_txn(vault, txn, *turn)?;
    crate::dreamer_wake::owe_sieve_read_in_txn(&vault.store, txn, turn)
}

/// The engine's own delete guards mark controls inside ordinary kinds: task
/// authority facts, project revisions and goals, federation rulings, MACHINE
/// history, identity-topology participants and the pack-map carrier. A
/// refusal keeps the row, and so does a guard that cannot read it: keeping is
/// always safe.
fn guarded(store: &Store, txn: &RoTxn<'_>, id: &EntityId) -> bool {
    crate::task_authority::reject_fact_delete(store, txn, id).is_err()
        || crate::workspace_roster::refuse_revision_delete(store, txn, id).is_err()
        || crate::workspace_roster::guard_goal_delete(store, txn, *id).is_err()
        || crate::federation::reject_ruling_delete(store, txn, id).is_err()
        || crate::claim::history_store::reject_machine_history_delete(store, txn, id).is_err()
        || store.guard_pack_map_carrier_delete_in_txn(txn, id).is_err()
        || crate::identity_topology::guard_batch_identity_delete_in_txn(store, txn, id).is_err()
}

/// Tears one member's local rows. Every step is a local index or projection
/// leaf of the physical tear; custody, provenance, document and control rows
/// stay.
fn remove_member(
    store: &Store,
    txn: &mut RwTxn<'_>,
    edges: &LoroMap,
    id: &EntityId,
    report: &mut RemovedReplica,
) -> Result<()> {
    let Some(raw) = store.port_entity_raw(txn, id)? else {
        return Ok(());
    };
    let header =
        EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity metadata"))?;
    // Thread meta reads the RepliesTo edges, so it is marked dirty first.
    crate::conversation_dag::invalidate_thread_meta_for_turn_put(store, txn, *id)?;
    crate::task_verb::index_owner_fact(store, txn, id, None)?;
    crate::bm25::deindex_text(store, txn, id)?;
    crate::vault::entity_revision::remove_entity_revisions(store, txn, id)?;
    crate::batch::delete_from_phonetic_postings(store, txn, id)?;
    crate::code_symbol::delete_code_symbol_manifest_in_txn(store, txn, id)?;
    crate::counterparty_contact::drop_contact_index_rows_in_txn(store, txn, id)?;
    remove_vectors(store, txn, id, report)?;
    let neighbors = remove_carried_edges(store, txn, edges, id, report)?;
    if let Some((short_id, hash)) = store.port_short_id_reference(txn, id)? {
        let forward = crate::batch::encode_short_id_forward_key(&short_id, hash);
        store.short_ids.delete(txn, &forward)?;
        store.short_ids_reverse.delete(txn, id.as_bytes())?;
    }
    if header.entity_type == registry::ENTITY_TYPE_SKILL
        && let Ok(record) = crate::skill::decode_skill_record(&raw[ENTITY_METADATA_HEADER_LEN..])
        && let Some(content_hash) = record.content_hash
    {
        crate::skill_hub::maintain_skill_content_hash_index_for_delete(
            store,
            txn,
            id,
            content_hash,
        )?;
    }
    let occurred = TimeRange {
        start: header.occurred_start,
        end: header.occurred_end,
    };
    crate::batch::delete_entity_index_rows(
        store,
        txn,
        id,
        header.entity_type,
        occurred,
        header.learned_at,
    )?;
    crate::dreamer_runner::deindex_dreamer_milestone_claim(store, txn, id)?;
    crate::llm::deindex_dreamer_step_claim(store, txn, id)?;
    // Both read the stored row, so they run before it goes.
    crate::ingest::reindex_identity_hints(store, txn, id, None)?;
    crate::ports::reindex_named_entities(store, txn, id, None)?;
    crate::ingest::invalidate_blob_fingerprint(store, txn, id)?;
    crate::claim::remove_claim_projection_index(store, txn, *id)?;
    // A demoted epoch summary keeps its place in its session's count, so a
    // local mint never numbers under it (OF-013).
    crate::compaction::raise_epoch_floor_in_txn(store, txn, &raw)?;
    store.port_remove_entity_row(txn, id)?;
    store
        .l2_base_cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .erase(id, store.env.info().last_txn_id);
    crate::ppr::invalidate_ppr_for_delete(store, txn, id, &neighbors)?;
    report.removed.push(*id);
    Ok(())
}

fn remove_vectors(
    store: &Store,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
    report: &mut RemovedReplica,
) -> Result<()> {
    store.clear_pending_embedding(txn, id)?;
    if store.vectors.delete(txn, id.as_bytes())? {
        report.vectors += 1;
    }
    crate::embed::record_embedding_device_in_txn(store, txn, id, None)?;
    crate::embed::delete_media_vectors_in_txn(store, txn, id)?;
    crate::hnsw::hnsw_deindex(store, txn, id)?;
    Ok(())
}

/// Removes the edges touching `id` that this window's document carries. An
/// edge another window carries stays, as partial residence leaves it, and so
/// does a local-only edge, which no server copy could give back. Returns
/// every neighbour, for cache invalidation.
fn remove_carried_edges(
    store: &Store,
    txn: &mut RwTxn<'_>,
    edges: &LoroMap,
    id: &EntityId,
    report: &mut RemovedReplica,
) -> Result<Vec<EntityId>> {
    let mut incident = Vec::new();
    for direction in [EdgeDirection::Out, EdgeDirection::In] {
        for row in store.port_edges(txn, id, direction, None, None)? {
            let edge = row?;
            let (source, target) = if direction == EdgeDirection::Out {
                (*id, edge.target)
            } else {
                (edge.target, *id)
            };
            incident.push((source, edge.kind, target));
        }
    }
    let mut neighbors = Vec::with_capacity(incident.len());
    for (source, kind, target) in incident {
        neighbors.push(if source == *id { target } else { source });
        if map_contains_binary(edges, &format_edge_key(&source, kind, &target))
            && store.port_remove_edge_rows(txn, &source, kind, &target)?
        {
            report.edges += 1;
        }
    }
    neighbors.sort_unstable();
    neighbors.dedup();
    Ok(neighbors)
}

/// Drops the window's persisted document rows. `m:u_seq:w:` stays so a later
/// update can never reuse a sequence number, and every marker, fence and
/// resync row stays with it.
fn remove_window_rows(
    store: &Store,
    txn: &mut RwTxn<'_>,
    window: &WindowKey,
    report: &mut RemovedReplica,
) -> Result<()> {
    let key = window.as_str().to_owned();
    report.snapshot = WINDOW_SNAPSHOT.delete(store, txn, &key)?;
    report.update_rows = WINDOW_UPDATE.delete_from(store, txn, format!("{key}:").as_bytes())?;
    // A state vector left behind would tell the server this machine still
    // holds the ops it just dropped.
    WINDOW_STATE_VECTOR.delete(store, txn, &key)?;
    WINDOW_SHALLOW_FENCE.delete(store, txn, &key)?;
    Ok(())
}
