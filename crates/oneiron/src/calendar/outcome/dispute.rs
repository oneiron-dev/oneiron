//! The machine outcomes that dispute the owner's standing answer
//! (CAL-07-OUTCOME-CONFLICT = A): evidence kept beside the answer, never in its
//! place.

use super::{
    EventOutcomeBasis, EventOutcomeClaimValue, PREDICATE_CALENDAR_EVENT_OUTCOME, current_head,
    live_outcome_heads_in,
};
use crate::calendar::claims::decode_event_outcome_value;
use crate::claim::{ClaimApprovalStatus, ScopedRead};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::vault::Vault;

/// The machine outcomes that dispute the EVENT's current owner answer, oldest
/// first: each machine claim the answer superseded that disagrees with it, and
/// each readable machine head beside it across a sync fork that disagrees.
///
/// A superseded claim is either evidence that arrived after the answer, or the
/// machine head the answer corrected. Empty when the current outcome is no owner
/// answer. A new answer settles the dispute: the evidence stays linked to the
/// answer it disputed, which the new answer supersedes.
///
/// # Errors
///
/// Storage errors, and [`crate::error::Error::InvalidClaimBody`] when a stored
/// outcome value does not match the ratified wire shape.
pub fn read_disputing_machine_outcomes(
    vault: &Vault,
    event_ref: EntityId,
) -> Result<Vec<EventOutcomeClaimValue>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(disputing_machine_outcomes_in(vault, &rtxn, &event_ref)?
        .into_iter()
        .map(|(_, value)| value)
        .collect())
}

/// [`read_disputing_machine_outcomes`] as a caller's read may see it. Most of
/// these are claims the answer superseded, which no surfaceable read admits, so
/// each one is admitted through `lane`, the caller's own lane at the record
/// verbs' status (`ClaimReadStatus::Recorded`); one it does not admit is left
/// out.
pub(in crate::calendar) fn readable_disputing_machine_outcomes_in(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    lane: &ScopedRead<'_>,
    event_ref: &EntityId,
) -> Result<Vec<EventOutcomeClaimValue>> {
    let disputing = disputing_machine_outcomes_in(vault, rtxn, event_ref)?;
    let claims: Vec<EntityId> = disputing.iter().map(|(claim, _)| *claim).collect();
    let readable = lane.entities_readable_in_txn(rtxn, &claims)?;
    Ok(disputing
        .into_iter()
        .zip(readable)
        .filter_map(|((_, value), readable)| readable.then_some(value))
        .collect())
}

/// Each disputing machine outcome with the claim it is read from, oldest first.
fn disputing_machine_outcomes_in(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    event_ref: &EntityId,
) -> Result<Vec<(EntityId, EventOutcomeClaimValue)>> {
    let heads = live_outcome_heads_in(vault, rtxn, event_ref)?;
    let Some(answer) = current_head(&heads).filter(|head| head.is_owner_answer()) else {
        return Ok(Vec::new());
    };
    let disputes = |value: &EventOutcomeClaimValue| {
        value.basis == EventOutcomeBasis::Machine && value.outcome != answer.value.outcome
    };
    let mut disputing: Vec<(EntityId, EventOutcomeClaimValue)> = heads
        .iter()
        .filter(|head| head.surfaceable && disputes(&head.value))
        .map(|head| (head.claim_id, head.value))
        .collect();
    for superseded in vault.port_edge_peers(
        rtxn,
        &answer.claim_id,
        EdgeDirection::Out,
        EdgeKind::Supersedes,
    )? {
        let claim = superseded?;
        let Some(body) = vault.get_claim_in_txn(rtxn, &claim)? else {
            continue;
        };
        if body.predicate != PREDICATE_CALENDAR_EVENT_OUTCOME
            || !matches!(
                body.approval,
                ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
            )
        {
            continue;
        }
        let value = decode_event_outcome_value(&body.value)?;
        if disputes(&value) {
            disputing.push((claim, value));
        }
    }
    disputing.sort_by_key(|(_, value)| value.recorded_at);
    Ok(disputing)
}
