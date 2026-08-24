//! The deterministic fold over the append-only op log: the action/event/fold
//! shapes, the undo-currency rule, and the store/vault readers that feed the
//! fold its EFFECTIVE event projection.

use std::collections::{BTreeMap, BTreeSet};

use crate::claim::ClaimApprovalStatus;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT;
use crate::store::Store;
use crate::vault::Vault;

use super::lifecycle_state::EntityLifecycleState;
use super::op_apply::IdentityTopologyParticipantValidation;
use super::op_vocabulary::IdentityTopologyOp;
use super::store_entity_helpers::{
    identity_topology_actor_complete_for_store_in_txn,
    identity_topology_entity_type_for_store_in_txn, identity_topology_event_for_store_in_txn,
    identity_topology_events_for_store_in_txn, validate_identity_op_participants_for_store_in_txn,
};
use super::transition_table::{IdentityTopologyRejection, ProposalOutcome, evaluate_transition};

/// One ledger action: apply an op, or undo a previously applied event.
#[derive(Debug, Clone, PartialEq)]
pub enum IdentityTopologyAction {
    /// Apply the op through the transition table.
    Apply(IdentityTopologyOp),
    /// Counter-event reverting a previously applied event (r1: undo is an
    /// append, never a rewrite).
    Undo {
        /// The ledger event being reverted.
        target: EntityId,
    },
    /// Resolution of a parked `Proposed` event (r7, ONE-1747). Carries ZERO
    /// lifecycle effects of its own: an approving ruling applies the op as
    /// its own ordinary event, which the fold already folds. The fold
    /// tracks resolutions solely to answer "is this proposal still open?".
    ResolveProposal {
        /// The resolved proposal event.
        proposal: EntityId,
        /// The recorded outcome.
        outcome: ProposalOutcome,
    },
}

/// One identity-topology ledger event, ready for folding.
#[derive(Debug, Clone, PartialEq)]
pub struct IdentityTopologyEvent {
    /// The event's type-76 record entity id (unique per event).
    pub event_id: EntityId,
    /// Engine-stamped monotonic sequence — the causality axis the fold
    /// orders by. Caller wall time is data, never ordering.
    pub seq: u64,
    /// Consent axis the event was recorded under. The fold evaluates
    /// EFFECTIVE events only (`Auto` / `Approved`); a `Proposed` event is
    /// parked legibility with zero topology effects.
    pub approval: ClaimApprovalStatus,
    /// The action the event records.
    pub action: IdentityTopologyAction,
}

/// Deterministic fold result over an identity-topology op log.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct IdentityTopologyFold {
    /// Folded lifecycle state per touched entity (absent = `Active`).
    pub states: BTreeMap<EntityId, EntityLifecycleState>,
    /// For each entity in a shell state, the event that put it there — the
    /// undo-currency witness.
    pub current_event: BTreeMap<EntityId, EntityId>,
    /// Resolved `Proposed` events keyed by proposal, with the r7 outcome the
    /// ruling recorded (ONE-1747) — the "is this park still open?" witness.
    /// First resolution wins: a resolution naming an already-resolved
    /// proposal is a fold rejection, never a silent overwrite.
    pub resolved_proposals: BTreeMap<EntityId, ProposalOutcome>,
    /// Per-event rejections, in fold order.
    pub rejections: Vec<(EntityId, IdentityTopologyRejection)>,
}

/// Folds identity-topology events into lifecycle states — the
/// `fold_authority_log` analogue. Events are ordered by `(seq, event_id)`
/// so the fold is independent of input order AND of caller-supplied wall
/// time (a backdated counter-event cannot reorder history); non-effective
/// events (`Proposed` parks, `Rejected` is never recorded) change nothing.
#[must_use]
pub fn fold_identity_topology_log(events: &[IdentityTopologyEvent]) -> IdentityTopologyFold {
    let mut ordered: Vec<&IdentityTopologyEvent> = events.iter().collect();
    ordered.sort_by_key(|event| (event.seq, event.event_id));

    let mut fold = IdentityTopologyFold::default();
    let mut applied: BTreeMap<EntityId, &IdentityTopologyOp> = BTreeMap::new();
    let mut undo_events: BTreeSet<EntityId> = BTreeSet::new();

    for event in ordered {
        if !matches!(
            event.approval,
            ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
        ) {
            continue;
        }
        match &event.action {
            IdentityTopologyAction::Apply(op) => match evaluate_transition(&fold.states, op) {
                Ok(transitions) => {
                    for (entity, state) in transitions {
                        fold.states.insert(entity, state);
                        if state == EntityLifecycleState::Active {
                            fold.current_event.remove(&entity);
                        } else {
                            fold.current_event.insert(entity, event.event_id);
                        }
                    }
                    applied.insert(event.event_id, op);
                }
                Err(rejection) => fold.rejections.push((event.event_id, rejection)),
            },
            IdentityTopologyAction::Undo { target } => {
                match evaluate_fold_undo(&fold.current_event, &applied, &undo_events, target) {
                    Ok(reverted) => {
                        for entity in reverted {
                            fold.states.insert(entity, EntityLifecycleState::Active);
                            fold.current_event.remove(&entity);
                        }
                        undo_events.insert(event.event_id);
                    }
                    Err(rejection) => {
                        fold.rejections.push((event.event_id, rejection));
                        undo_events.insert(event.event_id);
                    }
                }
            }
            // A resolution carries no lifecycle effect of its own (the
            // approved op rides its own event). It only retires the park —
            // first resolution in `(seq, event_id)` order wins, so a
            // duplicate is a deterministic rejection on every replica.
            IdentityTopologyAction::ResolveProposal { proposal, outcome } => {
                if fold.resolved_proposals.contains_key(proposal) {
                    fold.rejections.push((
                        event.event_id,
                        IdentityTopologyRejection::ProposalAlreadyResolved {
                            proposal: *proposal,
                        },
                    ));
                } else {
                    fold.resolved_proposals.insert(*proposal, *outcome);
                }
            }
        }
    }
    fold
}

/// Undo legality against the fold state: the target must be an applied
/// merge/split whose shell entities all still name it as their current
/// topology writer.
fn evaluate_fold_undo(
    current_event: &BTreeMap<EntityId, EntityId>,
    applied: &BTreeMap<EntityId, &IdentityTopologyOp>,
    undo_events: &BTreeSet<EntityId>,
    target: &EntityId,
) -> std::result::Result<Vec<EntityId>, IdentityTopologyRejection> {
    if undo_events.contains(target) {
        return Err(IdentityTopologyRejection::NotUndoable { event: *target });
    }
    let Some(op) = applied.get(target) else {
        return Err(IdentityTopologyRejection::NotCurrent { event: *target });
    };
    let shelled = match op {
        IdentityTopologyOp::Merge(merge) => merge.sources.clone(),
        IdentityTopologyOp::Split(split) => vec![split.entity],
        // Facet and assert_distinct applies move no lifecycle state, so this
        // family's undo currency test — "is this event still the topology
        // writer for the entities it shelled?" — has nothing to test for
        // either. Both are retracted through the door that owns their
        // effect: a mask by splitting that FACET, an assertion by
        // superseding or retracting its own CLAIM.
        IdentityTopologyOp::Facet(_) | IdentityTopologyOp::AssertDistinct(_) => {
            return Err(IdentityTopologyRejection::NotUndoable { event: *target });
        }
    };
    for entity in &shelled {
        if current_event.get(entity) != Some(target) {
            return Err(IdentityTopologyRejection::NotCurrent { event: *target });
        }
    }
    Ok(shelled)
}

pub(super) fn fold_effective_identity_topology_events_for_store_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
) -> Result<Vec<IdentityTopologyEvent>> {
    let events = identity_topology_events_for_store_in_txn(store, rtxn)?;
    let mut effective = Vec::with_capacity(events.len());
    for event in events {
        let references_complete = match &event.action {
            IdentityTopologyAction::Apply(op) => matches!(
                validate_identity_op_participants_for_store_in_txn(store, rtxn, op)?,
                IdentityTopologyParticipantValidation::Complete
            ),
            IdentityTopologyAction::Undo { target } => {
                identity_topology_entity_type_for_store_in_txn(store, rtxn, target)?
                    .is_some_and(|kind| kind == ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT)
            }
            IdentityTopologyAction::ResolveProposal { proposal, .. } => {
                identity_topology_entity_type_for_store_in_txn(store, rtxn, proposal)?
                    .is_some_and(|kind| kind == ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT)
            }
        };
        let record = identity_topology_event_for_store_in_txn(store, rtxn, &event.event_id)?
            .ok_or(Error::CorruptedIndex("identity topology event index"))?;
        let actor_complete =
            match identity_topology_actor_complete_for_store_in_txn(store, rtxn, &record) {
                Ok(complete) => complete,
                Err(Error::ActorClassMismatch { .. }) => false,
                Err(err) => return Err(err),
            };
        if references_complete && actor_complete {
            effective.push(event);
        }
    }
    Ok(effective)
}

impl Vault {
    /// Event projection used wherever topology authority is consumed.
    /// Stored records remain immutable ledger evidence, but an apply record
    /// with an available invalid participant (or an undo naming an
    /// available non-event) is excluded from the effective fold. Missing
    /// references remain deferred and are reconsidered on materialization.
    /// `pub(crate)`: the receipt projection folds the same projection to
    /// suppress fold-rejected duplicate rulings.
    pub(crate) fn fold_effective_identity_topology_events_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
    ) -> Result<Vec<IdentityTopologyEvent>> {
        let events = self.identity_topology_events_in_txn(rtxn)?;
        let mut effective = Vec::with_capacity(events.len());
        for event in events {
            let references_complete = match &event.action {
                IdentityTopologyAction::Apply(op) => matches!(
                    self.validate_identity_op_participants_in_txn(rtxn, op)?,
                    IdentityTopologyParticipantValidation::Complete
                ),
                IdentityTopologyAction::Undo { target } => self
                    .get_entity_type_in_txn(rtxn, target)?
                    .is_some_and(|entity_type| entity_type == ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT),
                IdentityTopologyAction::ResolveProposal { proposal, .. } => self
                    .get_entity_type_in_txn(rtxn, proposal)?
                    .is_some_and(|entity_type| entity_type == ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT),
            };
            let actor_complete = match self.identity_topology_event_in_txn(rtxn, &event.event_id)? {
                Some(record) => {
                    match self.validate_replicated_identity_topology_actor_in_txn(rtxn, &record) {
                        Ok(complete) => complete,
                        Err(Error::ActorClassMismatch { .. }) => false,
                        Err(err) => return Err(err),
                    }
                }
                None => return Err(Error::CorruptedIndex("identity topology event index")),
            };
            if references_complete && actor_complete {
                effective.push(event);
            }
        }
        Ok(effective)
    }
}
