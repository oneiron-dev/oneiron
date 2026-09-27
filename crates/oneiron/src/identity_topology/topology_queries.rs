//! Read-only vault queries over the ledger and the reassignment projection:
//! one event record, the claims a decision routed, and an entity's masks.

use std::collections::BTreeSet;

use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncError};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_FACET};
use crate::vault::Vault;

use super::ledger_fold::fold_identity_topology_log;
use super::reassignment_map::reassignment_claims_for_prefix_in_txn;
use super::stored_event::{StoredIdentityOpAction, StoredIdentityOpEvent};
use super::transition_table::IdentityTopologyRejection;
use super::{REASSIGNMENT_ORIGIN_META_PREFIX, REASSIGNMENT_TARGET_META_PREFIX};

/// Role relative to the currently applied merge (not old/undone events).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActiveMergeDeleteRole {
    None,
    Source,
    Survivor,
    Actor,
}

impl Vault {
    /// The delete precondition for an active merge. Both source shells and
    /// the survivor are participants: tearing either row/edge before undo
    /// would make the merge un-undoable. Actor-only deletes instead retain a
    /// tombstone; the actor stamp in the event remains self-contained.
    pub(crate) fn active_merge_delete_role_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<ActiveMergeDeleteRole> {
        let events = self.fold_effective_identity_topology_events_in_txn(rtxn)?;
        let fold = fold_identity_topology_log(&events);
        let mut actor = false;
        let mut survivor_role = false;
        for event in events {
            let record = self
                .identity_topology_event_in_txn(rtxn, &event.event_id)?
                .ok_or(Error::CorruptedIndex("identity topology event index"))?;
            let StoredIdentityOpAction::Merge { sources, survivor } = &record.action else {
                continue;
            };
            if !sources
                .iter()
                .any(|source| fold.current_event.get(source) == Some(&event.event_id))
            {
                continue;
            }
            // A head of one merge may be a source in a later merge. Only a
            // current source is a hard-delete refusal, so scan ALL current
            // events before returning a lesser survivor/actor role.
            if sources.contains(id) {
                return Ok(ActiveMergeDeleteRole::Source);
            }
            survivor_role |= *id == *survivor;
            actor |= record
                .actor
                .is_some_and(|author| author.entity_ref() == *id);
        }
        Ok(if survivor_role {
            ActiveMergeDeleteRole::Survivor
        } else if actor {
            ActiveMergeDeleteRole::Actor
        } else {
            ActiveMergeDeleteRole::None
        })
    }

    /// A hard purge of a live source would remove its canonical shell edge.
    /// The survivor hard-erase instead walks/scrubs its whole redirect tree.
    pub(crate) fn guard_active_merge_hard_delete_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<()> {
        if self.active_merge_delete_role_in_txn(rtxn, id)? == ActiveMergeDeleteRole::Source {
            return Err(Error::Sync(SyncError::IdentityTopologyRejected(
                IdentityTopologyRejection::ActiveMergeParticipantDeletion { entity: *id },
            )));
        }
        Ok(())
    }

    /// Reads one type-76 ledger event record. `Ok(None)` when the id is
    /// absent; a present id of another type is a typed mismatch; a present
    /// record that fails decode is corruption (the family is engine-
    /// authored and door-validated).
    pub fn identity_topology_event(&self, id: &EntityId) -> Result<Option<StoredIdentityOpEvent>> {
        let rtxn = self.store.env.read_txn()?;
        self.identity_topology_event_in_txn(&rtxn, id)
    }

    /// CLAIM ids a topology decision assigned to `target` (ARCH-0055 r2/r5),
    /// ascending and deduplicated.
    ///
    /// TWO witnesses, because the two arms record assignment differently and
    /// a target is at most one of them, so the union is exact:
    /// - a SPLIT HEAD reads the reassignment index — a split assignment has
    ///   no structural witness at all (no edge moves, and r6 forbids
    ///   rewriting the claim's subject), so the engine-authored index IS the
    ///   record;
    /// - a FACET reads its canonical `facet_of` stamps, the same rows the
    ///   local query filter and the federation selector already honor.
    ///
    /// This is a READ over records ABOUT the claims. The claims themselves
    /// are untouched: every returned claim still carries the subject its
    /// writer stated, which is what keeps an unmerge possible (r6).
    pub fn claims_assigned_to(&self, target: &EntityId) -> Result<Vec<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        // The destination half of the index carries no payload — the key is
        // the whole row — so every scanned row is kept.
        let mut claims = reassignment_claims_for_prefix_in_txn(
            &self.store,
            &rtxn,
            REASSIGNMENT_TARGET_META_PREFIX,
            target,
            |_| true,
        )?;
        claims.extend(self.filtered_edge_peers(
            &rtxn,
            crate::ports::EdgeDirection::In,
            target,
            EdgeKind::FacetOf,
            Some(ENTITY_TYPE_CLAIM),
            "facet scoped claims",
        )?);
        Ok(claims.into_iter().collect())
    }

    /// CLAIM ids a split left on `origin` as EXPLICIT ambiguous residue
    /// (r2): the decision looked at them and declined to attribute them, so
    /// they stay where they are and stay countable as unresolved.
    ///
    /// Distinct from "unmapped": a claim the map never named is simply not
    /// part of the decision, while a residue row is a recorded judgment that
    /// the claim could not be attributed. Never force-assigned to a head.
    pub fn ambiguous_residue_claims(&self, origin: &EntityId) -> Result<Vec<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        let assigned = self.assigned_away_from_in_txn(&rtxn, origin)?;
        let residue = reassignment_claims_for_prefix_in_txn(
            &self.store,
            &rtxn,
            REASSIGNMENT_ORIGIN_META_PREFIX,
            origin,
            |target| target.is_none(),
        )?;
        Ok(residue
            .into_iter()
            .filter(|claim| !assigned.contains(claim))
            .collect())
    }

    /// CLAIM ids that still read as `origin`'s after its splits: everything
    /// subject-bound to it MINUS everything a split assigned to a head.
    ///
    /// The subtraction is why this is not [`Vault::claims_for_subject`]: a
    /// fully-mapped split assigns every claim away and leaves ZERO here,
    /// while the claims' stored subjects still all say `origin` (r6). The
    /// subject is provenance; the assignment is the current reading.
    pub fn claims_remaining_on_origin(&self, origin: &EntityId) -> Result<Vec<EntityId>> {
        let rtxn = self.store.env.read_txn()?;
        let assigned = self.assigned_away_from_in_txn(&rtxn, origin)?;
        Ok(self
            .claims_for_subject_in_txn(&rtxn, origin)?
            .into_iter()
            .filter(|claim| !assigned.contains(claim))
            .collect())
    }

    /// The claims some split routed AWAY from `origin` to a head.
    fn assigned_away_from_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        origin: &EntityId,
    ) -> Result<BTreeSet<EntityId>> {
        reassignment_claims_for_prefix_in_txn(
            &self.store,
            rtxn,
            REASSIGNMENT_ORIGIN_META_PREFIX,
            origin,
            |target| target.is_some(),
        )
    }

    /// The ARCH-0022 FACET (type-13) masks minted for `base`, read from the
    /// canonical `has_facet` edges the facet op wired.
    ///
    /// Masks are LIVE entities, not shells: `resolve_entity` of a facet is
    /// the facet itself, and no redirect row is minted for one.
    pub fn facets_of(&self, base: &EntityId) -> Result<Vec<EntityId>> {
        self.targets(base, EdgeKind::HasFacet, Some(ENTITY_TYPE_FACET))
    }
}
