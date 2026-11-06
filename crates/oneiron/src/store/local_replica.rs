//! Local-only removal of one canonical window's replica (OF-534 demotion).
//!
//! The physical delete tear writes deletion-shaped state (audit rows,
//! retirement markers, withdrawal stamps), so this door does not call it. It
//! runs the tear's pure local leaves for each removable member, then drops
//! the window's persisted document rows. Nothing replicated is written: no
//! tombstone, deletion marker, audit row, Loro op, outbox row or receipt. An
//! epoch summary's session floor is the one local row it raises, and a sealed
//! window's landed mark the one it moves back (FIX 5506).
//!
//! Demotion drops what the home can give back, never local truth. A removed
//! member's entity-document history (heads, forks, pins, citation floors),
//! row provenance, custody and lifecycle sidecars (blob versions, LFS, code
//! revisions and snapshots, code memory, receipt archive, birth custody, hub
//! packages and refinements), gate decisions, task mirror, scope stamp, VAD
//! metadata and project-room indexes stay in place, and promotion brings its
//! rows back beside them. The owner's discard of a world copy
//! ([`KeepControls::release_local_members`], FIX 14534) also takes each
//! removed member's owned payload: its entity document and typed body, a
//! NOTE's text slots, review workflow and deck outline, a BLOB_ARTIFACT's
//! retained edit proposals, a CLAIM's Gate decisions (to their skeletons)
//! and tray row, and its read caches (`member_removal::discard_owned_payload`).
//! [`purge_left_shared_env_in_txn`] empties a left shared vault's whole
//! environment the same way (OF-158).
//!
//! The local derivations of a removed TURN (its tag set, its sieve working
//! state, its projection rounds) also reach other turns: a provisional
//! entity it named, a round it shares. Their owners' demotion leaves settle
//! them over the call's whole set before any row or edge goes, unerased,
//! and never retag or reread a kept turn. A promotion that brings a TURN
//! back owes it a tag pass and a sieve read ([`owe_promoted_turn_in_txn`]).
//! A kept TURN that loses a MESSAGE keeps a list of what it lacks
//! ([`crate::store::turn_missing`], FIX 3859): its work waits until each is
//! back with its `PartOf` edge, and is owed then.

mod left_env;
mod member_removal;

pub(crate) use member_removal::discard_bundle_payload_in_txn;

#[allow(unused_imports, reason = "L03's OF-158 leave calls these")]
pub(crate) use left_env::{LEFT_ENV_KEPT_SAMPLE, LeftEnvPurge, purge_left_shared_env_in_txn};
use member_removal::{discard_owned_payload, remove_member, shared_carriers};

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::ops::Bound;

use heed::{RoTxn, RwTxn};
use loro::{LoroDoc, LoroMap};

use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::{
    EdgeDirection, EdgeStoreRead, EntityStoreRead, TimelineQuery, WindowAddress, WindowDeletionRows,
};
use crate::registry;
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;
use crate::store::base_agent::is_base_agent_actor;
use crate::store::loro_document::{doc_from_snapshot, import_doc, map_contains_binary};
use crate::store::loro_tombstones::TombstoneIndex;
use crate::store::window_rows::{
    OFF_RECORD_PROMOTE_PICKUP, WINDOW_SHALLOW_FENCE, WINDOW_SNAPSHOT, WINDOW_STATE_VECTOR,
    WINDOW_UPDATE, WindowEntityKey,
};
use crate::sync::residence::residence_window_for_blob;
use crate::window_key::WindowKey;

/// Unacknowledged local text-document frames (`qd:e:{id}:{seq}`), read for
/// presence, and discarded only with a member a caller releases (FIX 14534).
const PENDING_DOCUMENT_FRAMES: SideTable<Vec<u8>, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_QD_E);
/// NOTE requests awaiting their receipt (`qn:e:{id}:{request}`), read for
/// presence, and discarded only with a member a caller releases (FIX 14534).
const PENDING_NOTE_REQUESTS: SideTable<Vec<u8>, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_QN_E);

/// Authority, grant, policy, claim-class vocabulary, key, consent, receipt and
/// identity-ledger kinds, plus the machine, world and agent-definition rows
/// they govern.
const KEPT_KINDS: &[u8] = &[
    registry::ENTITY_TYPE_AUTHORITY_LOG,
    registry::ENTITY_TYPE_POLICY_MANIFEST,
    registry::ENTITY_TYPE_CLAIM_CLASS_DESCRIPTOR,
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
    /// Remove nothing while a member the window document does not carry, or
    /// one with local work pending, stays: the window is left whole, so a
    /// caller that may not drop what only this install holds can find it
    /// again (FIX 14534).
    pub(crate) defer_on_local_members: bool,
    /// Take members the window document does not carry, and members whose
    /// only pending local work is their promotion pickup, document frames or
    /// NOTE requests, with that work and every edge they touch: the owner's
    /// discard of a world copy (FIX 14534, Engine 11-06 08:34). A pending
    /// tombstone, or a delete this vault's markers record, still keeps its
    /// member, and every other keep rule holds. Each member it removes takes
    /// its document payload with it (call 4 = A).
    pub(crate) release_local_members: bool,
    /// Keep each removed member's own `FacetOf` edge, the birth facet its
    /// retained scope stamp names, so the row is admitted again against that
    /// stamp when its world comes back (FIX 14534).
    pub(crate) keep_birth_facets: bool,
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
            defer_on_local_members: false,
            release_local_members: false,
            keep_birth_facets: false,
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
    /// The window document holds a tombstone for it, or, for a caller that
    /// releases members, this vault's own markers delete it: deletion state.
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
    /// A content-addressed byte carrier ASSET whose bytes a holder this call
    /// does not remove still reads, for a caller that releases members (FIX
    /// 14534): the bytes stay while it does.
    SharedBytes,
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
/// own, which read as absent until the message is back. What each kept turn
/// loses is recorded before any row goes, tagged or not (FIX 3859).
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
        store
            .sync_hooks
            .queued_window_update_count_in_txn(store, txn, window.as_str())?;
    let mut report = RemovedReplica {
        queued_writes,
        ..RemovedReplica::default()
    };
    if keep.defer_on_queued_writes && queued_writes > 0 {
        return Ok(report);
    }
    let doc = persisted_window_doc(store, txn, window)?;
    let census = Census::new(store, txn, window, &keep, &doc)?;
    let members = census.sort(txn, &mut report)?;
    if defers_on_local_members(&keep, &report) {
        return Ok(report);
    }
    tear_members(store, txn, window, &doc, &members, &keep, &mut report)?;
    if report.remaining == 0 {
        remove_window_rows(store, txn, window, &mut report)?;
        report.complete = true;
    }
    Ok(report)
}

/// Removes the members `ids` of `window` named one by one, in the caller's
/// write transaction (FIX 14534): the same keep rules, removal plan and local
/// leaves as [`remove_local_replica_window_in_txn`], for members a caller
/// found after the window's own rows went (a world's CLAIMs, by its claim
/// posting list). An id whose row is not in `window` is passed over. The
/// window's rows are not touched; `complete` says every removable named
/// member is gone. Run it with the window closed.
pub(crate) fn remove_local_members_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    window: &WindowKey,
    ids: &[EntityId],
    keep: KeepControls,
) -> Result<RemovedReplica> {
    let queued_writes =
        store
            .sync_hooks
            .queued_window_update_count_in_txn(store, txn, window.as_str())?;
    let mut report = RemovedReplica {
        queued_writes,
        ..RemovedReplica::default()
    };
    if keep.defer_on_queued_writes && queued_writes > 0 {
        return Ok(report);
    }
    let doc = persisted_window_doc(store, txn, window)?;
    let census = Census::new(store, txn, window, &keep, &doc)?;
    let members = census.sort_ids(txn, ids, &mut report)?;
    if defers_on_local_members(&keep, &report) {
        return Ok(report);
    }
    tear_members(store, txn, window, &doc, &members, &keep, &mut report)?;
    report.complete = report.remaining == 0;
    Ok(report)
}

/// Whether the caller defers the whole call: it may not drop what only this
/// install holds, and a member its document does not carry, or one with local
/// work pending, stays (FIX 14534).
fn defers_on_local_members(keep: &KeepControls, report: &RemovedReplica) -> bool {
    keep.defer_on_local_members
        && report
            .kept
            .iter()
            .any(|(_, reason)| matches!(reason, KeepReason::NotCarried | KeepReason::Pending))
}

/// The removable members a census found: in learned order, and the ones it
/// released ([`KeepControls::release_local_members`]).
struct Members {
    removable: Vec<EntityId>,
    released: BTreeSet<EntityId>,
}

/// Removes one call's batch of `members` with their local leaves.
fn tear_members(
    store: &Store,
    txn: &mut RwTxn<'_>,
    window: &WindowKey,
    doc: &LoroDoc,
    members: &Members,
    keep: &KeepControls,
    report: &mut RemovedReplica,
) -> Result<()> {
    let removable = &members.removable;
    // The next take of a sealed window's mirror lands its rows again, from
    // the first call that may remove one (FIX 5506).
    crate::world_keys::unland_window_in_txn(store, txn, window)?;
    report.remaining = removable.len().saturating_sub(keep.max_removals);
    let batch = &removable[..removable.len().min(keep.max_removals)];
    let removal = Removal::plan(store, txn, batch, keep.release_local_members, report)?;
    super::turn_missing::record_in_txn(store, txn, &removal.missing)?;
    // The leaves read the removed rows, their edges and other turns' sets.
    crate::tagging::demote_tags_in_txn(store, txn, &removal.gone, &removal.partial)?;
    crate::dreamer_wake::demote_in_txn(store, txn, &removal.gone)?;
    let edges = doc.get_map("edges");
    if keep.release_local_members {
        discard_owned_payload(store, txn, &removal.order)?;
    }
    for id in &removal.order {
        let released = members.released.contains(id);
        remove_member(
            store,
            txn,
            &edges,
            id,
            released,
            keep.keep_birth_facets,
            report,
        )?;
        if released {
            release_local_work(store, txn, window, id)?;
        }
    }
    if report.vectors > 0 {
        crate::store::vector_index::increment_vector_version(store, txn)?;
    }
    if !report.removed.is_empty() {
        crate::store::graph_version::increment_graph_version(store, txn)?;
    }
    Ok(())
}

/// Discards the local work a released member `id` of `window` still had:
/// its promotion pickup, its document frames and its NOTE requests, gone
/// with the copy the owner discarded (FIX 14534). Its pending tombstone, an
/// id-only delete that still travels, is never released.
fn release_local_work(
    store: &Store,
    txn: &mut RwTxn<'_>,
    window: &WindowKey,
    id: &EntityId,
) -> Result<()> {
    let pickup = WindowEntityKey {
        window: window.as_str().to_owned(),
        entity: *id,
    };
    OFF_RECORD_PROMOTE_PICKUP.delete(store, txn, &pickup)?;
    let prefix = format!("{}:", id.to_hex());
    PENDING_DOCUMENT_FRAMES.delete_from(store, txn, prefix.as_bytes())?;
    PENDING_NOTE_REQUESTS.delete_from(store, txn, prefix.as_bytes())?;
    Ok(())
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

/// Whether a hold stands on BLOB_ARTIFACT `id`, stored as `raw`, or on a
/// claim or the bytes of any of its versions.
fn artifact_payload_held(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
    raw: &[u8],
) -> Result<bool> {
    let hashes = crate::blob_artifact::held_content_hashes_in_txn(store, txn, id, raw)?;
    crate::blob_artifact::artifact_payload_held_in_txn(store, txn, id, &hashes)
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
    fn sort(&self, txn: &RoTxn<'_>, report: &mut RemovedReplica) -> Result<Members> {
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
        let mut members = Members {
            removable: Vec::new(),
            released: BTreeSet::new(),
        };
        for row in self.store.port_entity_timeline(txn, query)? {
            let id = row?.id;
            if !seen.insert(id) {
                continue;
            }
            self.place(txn, id, &mut members, report)?;
        }
        Ok(members)
    }

    /// [`Self::sort`] over the members `ids` names, in that order.
    fn sort_ids(
        &self,
        txn: &RoTxn<'_>,
        ids: &[EntityId],
        report: &mut RemovedReplica,
    ) -> Result<Members> {
        let mut seen = HashSet::new();
        let mut members = Members {
            removable: Vec::new(),
            released: BTreeSet::new(),
        };
        for id in ids {
            if seen.insert(*id) {
                self.place(txn, *id, &mut members, report)?;
            }
        }
        Ok(members)
    }

    /// Places the row `id`, when it is a member of this window: kept with its
    /// reason, or removable, released when only the caller's release takes it.
    fn place(
        &self,
        txn: &RoTxn<'_>,
        id: EntityId,
        members: &mut Members,
        report: &mut RemovedReplica,
    ) -> Result<()> {
        let Some(raw) = self.store.port_entity_raw(txn, &id)? else {
            return Ok(());
        };
        // A world window's month also holds base rows and other worlds.
        if residence_window_for_blob(&raw).ok().as_ref() != Some(self.window) {
            return Ok(());
        }
        match self.keep_reason(txn, &id, &raw)? {
            Some(reason) => report.kept.push((id, reason)),
            None => {
                if self.keep.release_local_members && self.local_member(txn, &id)? {
                    members.released.insert(id);
                }
                members.removable.push(id);
            }
        }
        Ok(())
    }

    /// Whether `id` is one only a release takes: the window document does
    /// not carry it, or local work it has is pending.
    fn local_member(&self, txn: &RoTxn<'_>, id: &EntityId) -> Result<bool> {
        Ok(!map_contains_binary(&self.entities, &id.to_hex()) || self.pending_work(txn, id)?)
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
        } else if crate::store::legal_hold::legal_hold_held_in_txn(self.store, txn, id.as_bytes())?
            || crate::world_keys::legal_hold_pad_world_in_txn(self.store, txn, raw)?
        {
            // A pad whose world or sealed claim is held stays too, whatever
            // kinds the caller keeps (OF-470).
            KeepReason::LegalHold
        } else if crate::store::legal_hold::held_in_txn(self.store, txn, id.as_bytes())?
            || crate::world_keys::held_pad_world_in_txn(self.store, txn, raw)?
            || (self.keep.release_local_members
                && kind == registry::ENTITY_TYPE_BLOB_ARTIFACT
                && artifact_payload_held(self.store, txn, id, raw)?)
        {
            // The owner's discard takes an artifact's version chain with it:
            // a hold on any of its versions' claims or bytes keeps the
            // artifact, and so its byte carriers (FIX 14534).
            KeepReason::Guarded
        } else if self.keep.bound_actors && (self.bound.contains(id) || is_base_agent_actor(id)?) {
            KeepReason::BoundActor
        } else if self.tombstones.contains(id)
            || (self.keep.release_local_members
                && crate::deletion::row_deletion_marked(self.store, txn, id, Some(raw))?)
        {
            // A discard that releases members reads this vault's own delete
            // markers too: they outlive the window rows whose tombstone kept
            // the member, so a later call keeps it the same (FIX 14534).
            KeepReason::Tombstoned
        } else if crate::store::ASSET_FILE_PLANE
            && let Some(manifest) =
                crate::store::asset_file_of_raw_in_txn(self.store, txn, id, raw)?
            && !(self.keep.release_local_members
                && crate::sync::asset_body::home_proof::received_from_home_in(
                    self.store,
                    txn,
                    *id,
                    &manifest.facts.blake3,
                    manifest.facts.len,
                )?)
        {
            // A file-plane ASSET's body moves outside Loro; the home's
            // window ack does not durably hold the body (FIX 5393). The
            // owner's discard lets go of one whose body this machine took
            // from its home (FIX 14534, Engine 11-06 19:59 call).
            KeepReason::NotCarried
        } else if !self.keep.release_local_members
            && !map_contains_binary(&self.entities, &id.to_hex())
        {
            KeepReason::NotCarried
        } else if self.pending_delete(txn, id)?
            || (!self.keep.release_local_members && self.pending_work(txn, id)?)
        {
            KeepReason::Pending
        } else if self
            .store
            .delete_guards
            .reject_audience_edit_delete(self.store, txn, id)
            .is_err()
        {
            // A kept audience edit stays whatever the caller keeps (FIX 5639).
            KeepReason::Guarded
        } else if self.keep.guarded_rows && guarded(self.store, txn, id) {
            KeepReason::Guarded
        } else {
            return Ok(None);
        };
        Ok(Some(reason))
    }

    /// A delete of `id` this window's document does not hold yet: a pending
    /// tombstone, which travels as an id.
    fn pending_delete(&self, txn: &RoTxn<'_>, id: &EntityId) -> Result<bool> {
        self.store
            .port_pending_tombstone_present(txn, WindowAddress::new(self.window.as_str()), id)
    }

    /// Other local intent the window document does not hold yet: a promotion
    /// pickup, document frames or NOTE requests.
    fn pending_work(&self, txn: &RoTxn<'_>, id: &EntityId) -> Result<bool> {
        let window = self.window.as_str().to_owned();
        let pickup = WindowEntityKey {
            window,
            entity: *id,
        };
        if OFF_RECORD_PROMOTE_PICKUP.contains(self.store, txn, &pickup)? {
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
    /// The stored kept TURNs a removed MESSAGE is part of: their words read
    /// partly here until promotion, so their own rows stay as they are.
    partial: BTreeSet<EntityId>,
    /// Each of those TURNs with the removed MESSAGEs it is part of, for its
    /// missing-membership marker, plus the PartOf targets whose TURN row is
    /// already gone (FIX 6263).
    missing: BTreeMap<EntityId, BTreeSet<EntityId>>,
}

impl Removal {
    /// Plans `batch`, the census's removable members this call takes. A TURN
    /// a provisional entity still needs as its origin stays whole, and the
    /// rest is planned again without it, until no such turn is left. A caller
    /// that releases members (`release`) keeps each byte carrier a holder it
    /// does not remove still reads ([`shared_carriers`]).
    fn plan(
        store: &Store,
        txn: &RoTxn<'_>,
        batch: &[EntityId],
        release: bool,
        report: &mut RemovedReplica,
    ) -> Result<Self> {
        let mut order = batch.to_vec();
        // A kept carrier can hold another carrier's bytes in turn: to a
        // fixed point.
        if release {
            loop {
                let shared = shared_carriers(store, txn, &order)?;
                if shared.is_empty() {
                    break;
                }
                order.retain(|id| !shared.contains(id));
                for id in shared {
                    report.kept.push((id, KeepReason::SharedBytes));
                }
            }
        }
        loop {
            let gone: BTreeSet<EntityId> = order.iter().copied().collect();
            let missing = partial_turns(store, txn, &gone)?;
            // The demotion leaves only know stored turns; the marker keeps
            // the absent targets too (FIX 6263).
            let mut partial = BTreeSet::new();
            for turn in missing.keys() {
                if store
                    .port_entity_record(txn, turn)?
                    .is_some_and(|row| row.entity_type == registry::ENTITY_TYPE_TURN)
                {
                    partial.insert(*turn);
                }
            }
            let kept = crate::tagging::demotion_kept_origins_in_txn(store, txn, &gone, &partial)?;
            if kept.is_empty() {
                return Ok(Self {
                    order,
                    gone,
                    partial,
                    missing,
                });
            }
            order.retain(|id| !kept.contains(id));
            for id in kept {
                report.kept.push((id, KeepReason::ProvisionalOrigin));
            }
        }
    }
}

/// The TURN targets a MESSAGE in `gone` is part of, each with those
/// MESSAGEs, read before their edges go. A target whose TURN row is already
/// demoted (FIX 6263) is recorded too: a later promotion of its window alone
/// must know what it still lacks.
fn partial_turns(
    store: &Store,
    txn: &RoTxn<'_>,
    gone: &BTreeSet<EntityId>,
) -> Result<BTreeMap<EntityId, BTreeSet<EntityId>>> {
    let mut turns: BTreeMap<EntityId, BTreeSet<EntityId>> = BTreeMap::new();
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
                    .is_none_or(|row| row.entity_type == registry::ENTITY_TYPE_TURN)
            {
                turns.entry(turn).or_default().insert(*id);
            }
        }
    }
    Ok(turns)
}

/// What a promotion owes a TURN it brings back (OF-534), in the transaction
/// that lands the row: demotion dropped its tag set and its sieve reading,
/// which never sync, so an armed vault owes it a tag pass, and the sieve,
/// whose cursor has passed it, a read. A kept TURN whose MESSAGEs come back
/// is owed both once the last one its missing-membership marker lists is
/// back with its `PartOf` edge ([`crate::store::turn_missing`], FIX 3859).
pub(crate) fn owe_promoted_turn_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    turn: &EntityId,
) -> Result<()> {
    crate::tagging::mark_turn_in_txn(vault, txn, *turn, crate::store::ExtractionWork::Bulk)?;
    crate::dreamer_wake::owe_sieve_read_in_txn(&vault.store, txn, turn)
}

/// The engine's own delete guards mark controls inside ordinary kinds: task
/// authority facts, project revisions and goals, federation rulings, MACHINE
/// history, identity-topology participants and the pack-map carrier. A
/// refusal keeps the row, and so does a guard that cannot read it: keeping is
/// always safe.
fn guarded(store: &Store, txn: &RoTxn<'_>, id: &EntityId) -> bool {
    crate::store::task_authority_guard::reject_fact_delete(store, txn, id).is_err()
        || store
            .delete_guards
            .refuse_revision_delete(store, txn, id)
            .is_err()
        || store
            .delete_guards
            .guard_goal_delete(store, txn, *id)
            .is_err()
        || store
            .delete_guards
            .reject_ruling_delete(store, txn, id)
            .is_err()
        || crate::claim::history_store::reject_machine_history_delete(store, txn, id).is_err()
        || store.guard_pack_map_carrier_delete_in_txn(txn, id).is_err()
        || store
            .delete_guards
            .guard_batch_identity_delete_in_txn(store, txn, id)
            .is_err()
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
