//! Derives and reconciles the canonical `merged_into` / `split_into` shell edge
//! set from the ledger fold — the store-level reconcile passes and the vault
//! wrappers the sync-ingest and post-eviction doors call them through.

use std::collections::BTreeSet;

use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT;
use crate::store::Store;
use crate::vault::Vault;

use super::decode_identity_topology_event_body;
use super::ledger_fold::{
    IdentityTopologyAction, IdentityTopologyFold,
    fold_effective_identity_topology_events_for_store_in_txn, fold_identity_topology_log,
};
use super::lifecycle_state::EntityLifecycleState;
use super::reassignment_map::maintain_split_reassignment_projection_in_txn;
use super::store_entity_helpers::{
    desired_shell_edges_for_store_entity_in_txn, identity_topology_event_for_store_in_txn,
    identity_topology_events_for_store_in_txn, topology_edge_weight,
};
use super::stored_event::StoredIdentityOpAction;
use super::{
    identity_topology_shell_peers_for_store_in_txn, shell_edge_sources_for_store_in_txn,
    zero_head_split_shells_for_store_in_txn,
};

fn reconcile_identity_topology_edges_for_store_in_txn(
    store: &Store,
    config: &crate::config::VaultConfig,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    text_index_trusted: bool,
    wtxn: &mut heed::RwTxn<'_>,
) -> Result<()> {
    #[cfg(test)]
    test_hooks::note_full_reconciliation();
    let touched = shell_edge_sources_for_store_in_txn(store, &*wtxn)?;
    reconcile_shell_edges_for_sources_in_txn(
        store,
        config,
        analyzer,
        text_index_trusted,
        wtxn,
        &touched,
    )
}

/// Post-eviction shell reconciliation for ONE-1604-D1 authority dominance:
/// the sources to recompute are the UNION of `evicted_sources` (the removed
/// type-76 row's own participants, captured by
/// [`identity_topology_shell_sources_for_store_in_txn`] before the row went)
/// and the SURVIVING family's sources, all against one final fold.
///
/// Neither half is sufficient alone, because removing an event replays the
/// WHOLE fold:
///
/// - The surviving-family derivation cannot see the removed event's
///   participants — it enumerates rows, and that row is gone. Only the
///   explicit capture reaches them (fix-leg 4).
/// - The explicit capture reaches only DIRECT participants, but deleting an
///   event changes which LATER events apply, and those events have their own
///   sources. Concretely: merge `T(A→B)`, a squatter undo `U(T)` (so `T` is
///   reverted and a later `M([A,C]→D)` applies), then dominance evicts `U`.
///   `T` becomes effective again, `M` folds to rejected — and `C`, which `U`
///   never named, is left holding a `merged_into D` edge no ledger event
///   justifies. That is the same ARCH-0055 wedge the eviction unwind exists
///   to prevent, one hop further out. The union closes the set: any event
///   whose effectiveness the replay can flip is, by definition, a surviving
///   event, so its sources are in the surviving half.
///
/// Runs only when `evicted_sources` is non-empty — a batch without an
/// eviction is append-only, where the surviving derivation is already exact
/// and the ordinary reconciler has already run.
pub(crate) fn reconcile_shell_edges_after_eviction_in_txn(
    store: &Store,
    config: &crate::config::VaultConfig,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    text_index_trusted: bool,
    wtxn: &mut heed::RwTxn<'_>,
    evicted_sources: &BTreeSet<EntityId>,
) -> Result<()> {
    if evicted_sources.is_empty() {
        return Ok(());
    }
    let mut sources = shell_edge_sources_for_store_in_txn(store, &*wtxn)?;
    sources.extend(evicted_sources.iter().copied());
    reconcile_shell_edges_for_sources_in_txn(
        store,
        config,
        analyzer,
        text_index_trusted,
        wtxn,
        &sources,
    )
}

/// Reconciles the canonical shell edges of EXACTLY `sources` against the
/// current ledger fold: edges the fold no longer mandates are deleted,
/// mandated edges are (re)written when both endpoints are materialized.
///
/// Callers own the derivation of `sources`, and the two derivations are NOT
/// interchangeable. Append-only batches use the surviving-family set
/// ([`shell_edge_sources_for_store_in_txn`]); an eviction batch
/// must use the union in
/// [`reconcile_shell_edges_after_eviction_in_txn`], because a removed row is
/// no longer enumerable AND its removal replays the whole fold.
fn reconcile_shell_edges_for_sources_in_txn(
    store: &Store,
    config: &crate::config::VaultConfig,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    text_index_trusted: bool,
    wtxn: &mut heed::RwTxn<'_>,
    sources: &BTreeSet<EntityId>,
) -> Result<()> {
    if sources.is_empty() {
        return Ok(());
    }

    let effective_events = fold_effective_identity_topology_events_for_store_in_txn(store, &*wtxn)?;
    let fold = fold_identity_topology_log(&effective_events);
    let mut ops = Vec::new();
    for entity in sources {
        let desired = desired_shell_edges_for_store_entity_in_txn(store, &*wtxn, &fold, entity)?;
        for kind in [EdgeKind::MergedInto, EdgeKind::SplitInto] {
            let existing =
                identity_topology_shell_peers_for_store_in_txn(store, &*wtxn, entity, kind)?;
            for peer in &existing {
                if !desired
                    .iter()
                    .any(|(desired_kind, target, _)| *desired_kind == kind && target == peer)
                {
                    ops.push(BatchOp::DeleteEdge {
                        src: *entity,
                        kind,
                        tgt: *peer,
                    });
                }
            }
            for (desired_kind, target, created_at) in &desired {
                if *desired_kind != kind {
                    continue;
                }
                if store.entities.get(&*wtxn, entity.as_bytes())?.is_none()
                    || store.entities.get(&*wtxn, target.as_bytes())?.is_none()
                {
                    continue;
                }
                let weight = topology_edge_weight(kind)?;
                let canonical = crate::edge::encode_edge_value(
                    kind,
                    weight,
                    *created_at,
                    crate::affect::Vad::NEUTRAL,
                    None,
                )?;
                let out_key = Store::encode_edge_key(entity, kind, target);
                let in_key = Store::encode_edge_key(target, kind, entity);
                let out_matches = store
                    .edges_out
                    .get(&*wtxn, &out_key)?
                    .is_some_and(|value| value == canonical.as_slice());
                let in_matches = store
                    .edges_in
                    .get(&*wtxn, &in_key)?
                    .is_some_and(|value| value == canonical.as_slice());
                if out_matches && in_matches {
                    continue;
                }
                ops.push(BatchOp::EdgeWithCreatedAt {
                    src: *entity,
                    kind,
                    tgt: *target,
                    weight,
                    created_at: *created_at,
                    vad: crate::affect::Vad::NEUTRAL,
                    provenance: None,
                });
            }
        }
    }
    if !ops.is_empty() {
        apply_ops(
            store,
            config,
            analyzer,
            wtxn,
            ops,
            text_index_trusted,
            false,
            true,
        )?;
    }
    // ONE-1744 redirect maintenance runs for EVERY reconciled source, past
    // the no-edge-ops case on purpose: a zero-head split moves no edge at
    // all, so an empty op list is exactly the shape whose redirect row would
    // otherwise never be written. This is the chokepoint BOTH reconcile
    // paths share (sync ingest and ONE-1604-D1 post-eviction unwind), so
    // hooking it covers both without duplicating the hook.
    // The reconcile path pays the UNGATED fold: it is the sync-ingest door,
    // so it must DISCOVER a replicated zero-head split (and arm the marker)
    // on a vault that has never recorded one locally. It already folds for
    // its own edge derivation, so this costs nothing extra.
    let zero_head_shells = zero_head_split_shells_for_store_in_txn(store, &*wtxn)?;
    crate::identity_redirect::maintain_redirect_projection_in_txn(
        store,
        wtxn,
        sources,
        &zero_head_shells,
    )?;
    // ONE-1745 assignment maintenance rides the same chokepoint and the same
    // already-computed fold: a replicated split arrives here with its map and
    // never touches the apply door, so this is where its assignment rows are
    // born (and where an evicted or superseded split's rows die).
    maintain_split_reassignment_projection_in_txn(store, wtxn, sources, &fold)
}

/// The shell-edge SOURCES a stored type-76 record induces — the entities
/// whose `merged_into` / `split_into` rows the reconciler derives from it.
/// `Ok(None)` when `id` holds no type-76 row (any other kind, or nothing).
///
/// An undo counter-event names no source of its own; its effect is on the
/// sources of the event it reverts, so this resolves through to the TARGET
/// record. Losing an undo row un-reverts its target, which is a shell-edge
/// change on exactly those entities. The walk is ONE hop: an undo of an undo
/// is rejected at the door ([`IdentityTopologyRejection::NotUndoable`](super::IdentityTopologyRejection::NotUndoable)), so a
/// second hop reaches nothing new and no cycle can be entered.
///
/// A squatter's undo may name any id at all, so the hop is fail-SOFT: a
/// target that is missing, another kind, or undecodable contributes no
/// sources instead of failing the caller. The caller is an AUTHORITY
/// admission — letting a planted body abort it with a local-class error would
/// be exactly the ONE-1604-D1 revocation suppression dominance exists to
/// close. Only the row being evicted is read fail-closed: it passed a door
/// that decoded it, so a decode failure there is on-disk corruption.
///
/// Read this BEFORE the row is removed — afterwards the action is gone and
/// the induced sources are unrecoverable.
pub(crate) fn identity_topology_shell_sources_for_store_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<BTreeSet<EntityId>>> {
    let Some(raw) = store.entities.get(rtxn, id.as_bytes())? else {
        return Ok(None);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT {
        return Ok(None);
    }
    let record = decode_identity_topology_event_body(&raw[ENTITY_METADATA_HEADER_LEN..])
        .map_err(|_| Error::CorruptedIndex("identity topology event body"))?;
    let action = match &record.action {
        StoredIdentityOpAction::Undo { target } => {
            match identity_topology_event_for_store_in_txn(store, rtxn, target) {
                Ok(Some(target_record)) => target_record.action,
                Ok(None) | Err(_) => return Ok(Some(BTreeSet::new())),
            }
        }
        action => action.clone(),
    };
    Ok(Some(match action {
        StoredIdentityOpAction::Merge { sources, .. } => sources.into_iter().collect(),
        StoredIdentityOpAction::Split { entity, .. } => BTreeSet::from([entity]),
        // A resolution shells nothing of its own: an approving ruling's
        // effects ride the applied op's OWN event, which induces its own
        // sources when evicted. Nor does a facet or assert_distinct op — both
        // leave every participant `Active` (r6 / §6), so neither induces a
        // `merged_into`/`split_into` row for this reconciler to own.
        StoredIdentityOpAction::Undo { .. }
        | StoredIdentityOpAction::Facet { .. }
        | StoredIdentityOpAction::AssertDistinct { .. }
        | StoredIdentityOpAction::ProposalResolution { .. } => BTreeSet::new(),
    }))
}

/// Shared successful-put boundary for every `apply_ops` caller. All puts in
/// one batch are considered together and trigger at most one full topology
/// reconciliation; no pending-participant index is introduced.
#[allow(clippy::too_many_arguments)]
pub(crate) fn reconcile_identity_topology_for_materialized_entities_in_txn(
    store: &Store,
    config: &crate::config::VaultConfig,
    analyzer: &crate::analyzer::MultilingualAnalyzer,
    text_index_trusted: bool,
    wtxn: &mut heed::RwTxn<'_>,
    materialized: &BTreeSet<EntityId>,
) -> Result<()> {
    if materialized.is_empty() {
        return Ok(());
    }
    let events = identity_topology_events_for_store_in_txn(store, &*wtxn)?;
    for event in events {
        let action_relevant = match &event.action {
            // The trigger set is WIDER than the participants: a claim the
            // op's reassignment map names is not a participant, but its
            // arrival is what lets the reconcile door finally record its
            // row ([`IdentityTopologyOp::deferred_reassignment_items`]).
            IdentityTopologyAction::Apply(op) => {
                let participants = op.participants();
                let deferred = op.deferred_reassignment_items();
                participants
                    .iter()
                    .chain(deferred.iter())
                    .any(|id| materialized.contains(id))
            }
            // Type-76 targets are engine-authored and their replicated ingest
            // door performs the full reconciliation after the seq join. Do
            // not duplicate that pass from the generic put hook. A
            // resolution moves no shell edge at all.
            IdentityTopologyAction::Undo { .. }
            | IdentityTopologyAction::ResolveProposal { .. } => false,
        };
        let record = identity_topology_event_for_store_in_txn(store, &*wtxn, &event.event_id)?
            .ok_or(Error::CorruptedIndex("identity topology event index"))?;
        let actor_relevant = record
            .actor
            .is_some_and(|actor| materialized.contains(&actor.entity_ref()));
        if action_relevant || actor_relevant {
            return reconcile_identity_topology_edges_for_store_in_txn(
                store,
                config,
                analyzer,
                text_index_trusted,
                wtxn,
            );
        }
    }
    Ok(())
}

impl Vault {
    /// The shell edges the ledger fold currently mandates for `entity`, as
    /// `(kind, target, created_at)` rows derived from its current topology
    /// writer — empty for `Active`. `created_at` is the current event's
    /// recorded `at`, matching the bytes the origin door wrote so replicas
    /// converge byte-identically.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    fn desired_shell_edges_for_entity_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        fold: &IdentityTopologyFold,
        entity: &EntityId,
    ) -> Result<Vec<(EdgeKind, EntityId, u64)>> {
        let state = fold
            .states
            .get(entity)
            .copied()
            .unwrap_or(EntityLifecycleState::Active);
        if state == EntityLifecycleState::Active {
            return Ok(Vec::new());
        }
        let event_id = fold
            .current_event
            .get(entity)
            .ok_or(Error::CorruptedIndex("identity topology fold"))?;
        let record = self
            .identity_topology_event_in_txn(rtxn, event_id)?
            .ok_or(Error::CorruptedIndex("identity topology event index"))?;
        Ok(match (&record.action, state) {
            (StoredIdentityOpAction::Merge { survivor, .. }, EntityLifecycleState::Merged) => {
                vec![(EdgeKind::MergedInto, *survivor, record.at)]
            }
            (StoredIdentityOpAction::Split { heads, .. }, EntityLifecycleState::Split) => heads
                .iter()
                .map(|head| (EdgeKind::SplitInto, *head, record.at))
                .collect(),
            _ => return Err(Error::CorruptedIndex("identity topology fold")),
        })
    }

    /// When the current ledger fold mandates exactly this shell edge,
    /// returns the mandating event's `at` (the `created_at` the door
    /// writes); `None` otherwise. This is the sync doors' admission
    /// predicate for the reserved kinds (`merged_into` / `split_into`): a
    /// replicated 21/22 edge may land ONLY as the byte-exact echo of a
    /// validated, locally ingested type-76 event that is the source
    /// entity's current topology writer — callers must also pin the value
    /// bytes (default weight + this `at`), because peer-chosen bytes on a
    /// mandated pair are still a forgery (weight 0 silently drops the
    /// shell's PPR mass, unledgered). Folds the whole (rare,
    /// quota-bounded) event family per call.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn identity_topology_mandated_shell_edge_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        src: &EntityId,
        kind: EdgeKind,
        tgt: &EntityId,
    ) -> Result<Option<u64>> {
        let events = self.fold_effective_identity_topology_events_in_txn(rtxn)?;
        let fold = fold_identity_topology_log(&events);
        let desired = self.desired_shell_edges_for_entity_in_txn(rtxn, &fold, src)?;
        Ok(desired
            .iter()
            .find(|(desired_kind, target, _)| *desired_kind == kind && target == tgt)
            .map(|(_, _, at)| *at))
    }

    /// Reconciles the canonical shell edges of every source entity named by
    /// the event family to the CURRENT ledger fold, inside the caller's write txn —
    /// the sync-ingest twin of the local door's edge side-effects (the
    /// ruled invariant: a `merged_into` / `split_into` edge only ever moves
    /// as the side-effect of a validated type-76 event). Edges the fold no
    /// longer mandates are deleted; mandated edges are written when both
    /// endpoints are materialized locally — a deferred endpoint leaves the
    /// edge to the sync edges-map pass, whose admission runs the same
    /// ledger predicate after hydrating endpoints. An undo counter-event
    /// arriving before its target reconciles nothing yet: the target's own
    /// ingest reruns this with the full fold, and the seq join makes the
    /// outcome order-independent.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) fn reconcile_identity_topology_edges_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
    ) -> Result<()> {
        reconcile_identity_topology_edges_for_store_in_txn(
            &self.store,
            &self.config,
            &self.analyzer,
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            wtxn,
        )
    }
}

#[cfg(test)]
pub(crate) mod test_hooks {
    use std::sync::atomic::{AtomicUsize, Ordering};

    static FULL_RECONCILIATIONS: AtomicUsize = AtomicUsize::new(0);

    pub(crate) fn reset_full_reconciliations() {
        FULL_RECONCILIATIONS.store(0, Ordering::SeqCst);
    }

    pub(crate) fn full_reconciliations() -> usize {
        FULL_RECONCILIATIONS.load(Ordering::SeqCst)
    }

    pub(super) fn note_full_reconciliation() {
        FULL_RECONCILIATIONS.fetch_add(1, Ordering::SeqCst);
    }
}
