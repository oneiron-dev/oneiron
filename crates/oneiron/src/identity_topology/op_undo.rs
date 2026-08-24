//! The undo door: a counter-event appended over an applied merge/split, never
//! a rewrite of the event it reverts (ARCH-0055 r1).

use crate::batch::BatchOp;
use crate::claim::ClaimApprovalStatus;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::vault::Vault;

use super::ledger_fold::fold_identity_topology_log;
use super::lifecycle_state::EntityLifecycleState;
use super::op_apply::{IdentityOpOutcome, IdentityOpWrite};
use super::reassignment_map::clear_reassignment_rows_in_txn;
use super::stored_event::StoredIdentityOpAction;
use super::transition_table::IdentityTopologyRejection;

impl Vault {
    /// Undoes one applied merge/split event: appends the counter-event to
    /// the ledger (never rewriting the original) and removes the shell
    /// edges it wrote, restoring `Active`. Currency is judged by the FOLD
    /// over the whole event family ordered by the engine-stamped `seq` —
    /// the event must still be the current topology writer for every entity
    /// it shelled; an already-undone, superseded, or parked event is
    /// rejected with [`IdentityTopologyRejection::NotCurrent`]. Undo of a
    /// counter-event is rejected with
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
    pub(crate) fn undo_identity_topology_event_in_txn(
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
            | StoredIdentityOpAction::ProposalResolution { .. } => {
                return Err(Error::IdentityTopologyRejected(
                    IdentityTopologyRejection::NotUndoable { event: *event },
                ));
            }
            // A FACET event is not undoable either, and the fold's own undo
            // rule ([`evaluate_fold_undo`]) already says so — the door only
            // repeats it. A facet op moves NO lifecycle state (r6: the base
            // stays `Active`), so this family's undo currency test — "is this
            // event still the topology writer for the entities it shelled?" —
            // has nothing to test, and every facet event would be undoable
            // forever, repeatedly. Reversing one is also not an edge
            // retraction but an ENTITY retraction: the minted masks are live
            // ARCH-0022 entities that other records may already reference, and
            // deleting entities is ARCH-0038's door, not this one. Retiring a
            // mask is a split of that FACET, which this family already
            // expresses.
            // An assert_distinct event is not undoable for the same reason,
            // and its retraction door already exists: the assertion lives in
            // a public CLAIM whose own lifecycle (supersede / retract) lifts
            // suppression. Unwinding it from here would need a second,
            // shadow retraction path over the same row.
            StoredIdentityOpAction::Facet { .. }
            | StoredIdentityOpAction::AssertDistinct { .. } => {
                return Err(Error::IdentityTopologyRejected(
                    IdentityTopologyRejection::NotUndoable { event: *event },
                ));
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
                return Err(Error::IdentityTopologyRejected(
                    IdentityTopologyRejection::NotCurrent { event: *event },
                ));
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
            EntityId::now(),
            write,
            now,
            StoredIdentityOpAction::Undo { target: *event },
            None,
            effects,
            transitions,
        )
    }
}
