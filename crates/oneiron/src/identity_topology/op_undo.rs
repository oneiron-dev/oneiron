//! The undo door: a counter-event appended over an applied merge, split or
//! facet, never a rewrite of the event it reverts (ARCH-0055 r1).

use crate::batch::BatchOp;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, ClaimSuccession,
};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::vault::Vault;

use super::ledger_fold::fold_identity_topology_log;
use super::lifecycle_state::EntityLifecycleState;
use super::op_apply::{IdentityOpOutcome, IdentityOpWrite, facet_fork_id};
use super::reassignment_map::{
    ReassignmentMap, ReassignmentTarget, clear_reassignment_rows_in_txn,
};
use super::stored_event::StoredIdentityOpAction;
use super::transition_table::IdentityTopologyRejection;
use crate::error::SyncError;

impl Vault {
    /// Undoes one applied merge/split event: appends the counter-event to
    /// the ledger (never rewriting the original) and removes the shell
    /// edges it wrote, restoring `Active`. Currency is judged by the FOLD
    /// over the whole event family ordered by the engine-stamped `seq` —
    /// the event must still be the current topology writer for every entity
    /// it shelled; an already-undone, superseded, or parked event is
    /// rejected with [`IdentityTopologyRejection::NotCurrent`]. A FACET event
    /// undoes by forking its claims home and archiving its masks (see
    /// `undo_facet_event_in_txn`). Undo of a counter-event is rejected with
    /// [`IdentityTopologyRejection::NotUndoable`]. The consent axis applies
    /// like the apply door: `Proposed` parks the counter-event with the
    /// shell edges untouched; `Rejected` is the consent no-op.
    pub fn undo_identity_topology_event(
        &self,
        event: &EntityId,
        write: &IdentityOpWrite,
        now: u64,
    ) -> Result<IdentityOpOutcome> {
        let mut wtxn = self.store.env.write_txn()?;
        let outcome = self.undo_identity_topology_event_in_txn(&mut wtxn, event, write, now)?;
        wtxn.commit()?;
        Ok(outcome)
    }

    /// Transaction-composable [`Vault::undo_identity_topology_event`].
    fn undo_identity_topology_event_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        event: &EntityId,
        write: &IdentityOpWrite,
        now: u64,
    ) -> Result<IdentityOpOutcome> {
        if write.approval == ClaimApprovalStatus::Rejected {
            return Ok(IdentityOpOutcome::Noop);
        }
        self.validate_identity_op_actor_in_txn(&*wtxn, write)?;

        let record = self
            .identity_topology_event_in_txn(&*wtxn, event)?
            .ok_or(Error::EntityNotFound)?;
        let (shelled, removed_edges) = match &record.action {
            // A counter-event is not undoable (r1: re-apply, don't unwind).
            // A resolution is not undoable either — a ruling is retracted by
            // ruling again on a fresh proposal, never by erasing the record
            // that a review happened.
            StoredIdentityOpAction::Undo { .. }
            | StoredIdentityOpAction::ProposalResolution { .. }
            | StoredIdentityOpAction::ProposalCancellation { .. }
            | StoredIdentityOpAction::AdmissionDisposition(_)
            | StoredIdentityOpAction::AuthorAttribution { .. }
            | StoredIdentityOpAction::AuthorRedaction { .. } => {
                return Err(Error::Sync(SyncError::IdentityTopologyRejected(
                    IdentityTopologyRejection::NotUndoable { event: *event },
                )));
            }
            StoredIdentityOpAction::Facet {
                entity,
                facets,
                reassignment,
                applied_assigned,
                forked,
                ..
            } => {
                // A facet event from before forks existed restamped its claims
                // and recorded no forks, so there is nothing to send home.
                if *applied_assigned != forked.len() as u64 {
                    return Err(Error::Sync(SyncError::IdentityTopologyRejected(
                        IdentityTopologyRejection::NotUndoable { event: *event },
                    )));
                }
                return self.undo_facet_event_in_txn(
                    wtxn,
                    event,
                    (*entity, facets, forked),
                    reassignment,
                    write,
                    now,
                );
            }
            // An assert_distinct event is not undoable: its retraction door
            // already exists. The assertion lives in a public CLAIM whose own
            // lifecycle (supersede / retract) lifts suppression. Unwinding it
            // from here would need a second, shadow retraction path over the
            // same row.
            StoredIdentityOpAction::AssertDistinct { .. } => {
                return Err(Error::Sync(SyncError::IdentityTopologyRejected(
                    IdentityTopologyRejection::NotUndoable { event: *event },
                )));
            }
            StoredIdentityOpAction::Merge { sources, survivor } => (
                sources.clone(),
                sources
                    .iter()
                    .map(|source| (*source, EdgeKind::MergedInto, *survivor))
                    .collect::<Vec<_>>(),
            ),
            StoredIdentityOpAction::Split { entity, heads, .. } => (
                vec![*entity],
                heads
                    .iter()
                    .map(|head| (*entity, EdgeKind::SplitInto, *head))
                    .collect::<Vec<_>>(),
            ),
        };

        let events = self.fold_effective_identity_topology_events_in_txn(&*wtxn)?;
        let fold = fold_identity_topology_log(&events);
        for entity in &shelled {
            if fold.current_event.get(entity) != Some(event) {
                return Err(Error::Sync(SyncError::IdentityTopologyRejected(
                    IdentityTopologyRejection::NotCurrent { event: *event },
                )));
            }
        }

        let mut effects = Vec::new();
        if write.is_effective() {
            for (src, kind, tgt) in removed_edges {
                effects.push(BatchOp::DeleteEdge { src, kind, tgt });
            }
            // ONE-1745: the reverted event's assignment rows go with its shell
            // edges — same lifecycle, same door. Scoped to THIS event's rows,
            // so a sibling event's assignments on the same origin survive.
            // Derived from the stored rows rather than re-resolved from the
            // map, so a claim deleted since the apply cannot strand a row.
            if let StoredIdentityOpAction::Split { entity, .. } = &record.action {
                clear_reassignment_rows_in_txn(&self.store, wtxn, entity, Some(event))?;
            }
        }
        let transitions = shelled
            .into_iter()
            .map(|entity| (entity, EntityLifecycleState::Active))
            .collect();
        self.write_identity_event_in_txn(
            wtxn,
            self.store.clock.entity_id()?,
            write,
            now,
            StoredIdentityOpAction::Undo { target: *event },
            None,
            effects,
            transitions,
        )
    }

    /// Undoes one applied FACET event (ARCH-0055 trio, r9). The facet op
    /// forked each reassigned claim under its mask and the fork superseded
    /// its origin, so the undo forks each one home: a restore claim under the
    /// origin's facet, derived from the origin, supersedes the fork. The
    /// minted masks are archived, not deleted: detached from the entity, with
    /// their rows kept, because the closed forks still name them.
    ///
    /// The event must not be undone already, every fork it lists must be
    /// present (a replica may not have received them all yet), and no later
    /// write may have touched one (closed, demoted, re-weighted, unlinked or
    /// edited it); otherwise [`IdentityTopologyRejection::NotCurrent`].
    /// `Proposed` parks the counter-event and moves nothing.
    fn undo_facet_event_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        event: &EntityId,
        (entity, facets, forked): (EntityId, &[EntityId], &[EntityId]),
        reassignment: &ReassignmentMap,
        write: &IdentityOpWrite,
        now: u64,
    ) -> Result<IdentityOpOutcome> {
        let not_current = || {
            Error::Sync(SyncError::IdentityTopologyRejected(
                IdentityTopologyRejection::NotCurrent { event: *event },
            ))
        };
        let events = self.fold_effective_identity_topology_events_in_txn(&*wtxn)?;
        if fold_identity_topology_log(&events)
            .undone_events
            .contains(event)
        {
            return Err(not_current());
        }
        let mut forks = Vec::new();
        for origin in forked {
            let mask = reassignment
                .entries
                .iter()
                .find_map(|entry| match (&entry.item, entry.target) {
                    (ClaimSubject::Entity(item), ReassignmentTarget::Facet { index })
                        if item == origin =>
                    {
                        facets.get(index as usize).copied()
                    }
                    _ => None,
                })
                .ok_or_else(not_current)?;
            let fork = facet_fork_id(event, origin)?;
            // A listed fork that is absent has not replicated here yet, or was
            // deleted since: the undo would strand it under an archived mask.
            let fork_body = self
                .get_claim_in_txn(&*wtxn, &fork)?
                .ok_or_else(not_current)?;
            let origin_body = self
                .get_claim_in_txn(&*wtxn, origin)?
                .ok_or_else(not_current)?;
            if !fork_untouched(&origin_body, &fork_body, mask)
                || self.claim_of_weight_in_txn(&*wtxn, origin, &origin_body)?
                    != self.claim_of_weight_in_txn(&*wtxn, &fork, &fork_body)?
                || !self.fork_links_intact_in_txn(&*wtxn, &fork, origin, mask)?
            {
                return Err(not_current());
            }
            forks.push((*origin, fork, origin_body.scope_facet));
        }

        let mut effects = Vec::new();
        if write.is_effective() {
            for (origin, fork, home) in forks {
                let restore = self.store.clock.entity_id()?;
                // The restore wears its origin's stamp exactly: a `facet_of`
                // edge only where the origin carried one.
                let stamp = crate::ports::EdgeStoreRead::port_edge_get(
                    &self.store,
                    &*wtxn,
                    &origin,
                    EdgeKind::FacetOf,
                    &home,
                )?
                .is_some();
                crate::batch::ClaimMaterialization::apply_successor(
                    self,
                    wtxn,
                    &fork,
                    &restore,
                    ClaimSuccession::Fork { facet: home, stamp },
                    now,
                )?;
                self.batch_in()
                    .edge(&restore, EdgeKind::DerivedFrom, &origin, 1.0)
                    .apply(wtxn)?;
                self.supersede_claim_in_txn(wtxn, &restore, &fork, now)?;
            }
            for mask in facets {
                effects.push(BatchOp::DeleteEdge {
                    src: entity,
                    kind: EdgeKind::HasFacet,
                    tgt: *mask,
                });
            }
        }
        self.write_identity_event_in_txn(
            wtxn,
            self.store.clock.entity_id()?,
            write,
            now,
            StoredIdentityOpAction::Undo { target: *event },
            None,
            effects,
            Vec::new(),
        )
    }
}

impl Vault {
    /// The links the facet op gave a fork: its mask stamp, its lineage to
    /// the origin, and the supersession that closed the origin.
    fn fork_links_intact_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fork: &EntityId,
        origin: &EntityId,
        mask: EntityId,
    ) -> Result<bool> {
        for (kind, target) in [
            (EdgeKind::FacetOf, mask),
            (EdgeKind::DerivedFrom, *origin),
            (EdgeKind::Supersedes, *origin),
        ] {
            if crate::ports::EdgeStoreRead::port_edge_get(&self.store, txn, fork, kind, &target)?
                .is_none()
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// The claim's `claim_of` weight onto its entity subject, if it has one.
    fn claim_of_weight_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        claim: &EntityId,
        body: &ClaimBody,
    ) -> Result<Option<f32>> {
        let ClaimSubject::Entity(subject) = body.subject else {
            return Ok(None);
        };
        Ok(crate::ports::EdgeStoreRead::port_edge_get(
            &self.store,
            txn,
            claim,
            EdgeKind::ClaimOf,
            &subject,
        )?
        .map(|edge| edge.weight))
    }
}

/// A fork is current while it still carries exactly the origin's content
/// under its mask: active, never demoted, edited or closed. Lifecycle,
/// `valid_to` and the MACHINE proof legitimately differ between the two.
fn fork_untouched(origin: &ClaimBody, fork: &ClaimBody, mask: EntityId) -> bool {
    if fork.lifecycle != ClaimLifecycleStatus::Active || fork.scope_facet != mask {
        return false;
    }
    let mut expected = origin.clone();
    expected.lifecycle = fork.lifecycle;
    expected.valid_to = fork.valid_to;
    expected.scope_facet = mask;
    expected.evidence = crate::authority::evidence_without_machine_signature(origin);
    let mut actual = fork.clone();
    actual.evidence = crate::authority::evidence_without_machine_signature(fork);
    expected == actual
}
