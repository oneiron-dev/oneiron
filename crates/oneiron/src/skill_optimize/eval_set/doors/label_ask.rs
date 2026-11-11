//! `vault.evals.labels.ask` (LEARNING-06, FIX 4731): the producer that asks
//! the owner for one eval label because a real decision waits on a set too
//! small to settle it (EVAL-COLDSTART = C: labels "only when a real decision
//! waits on a set that is too small, for example a switch offer").
//!
//! The waiting decision is a stock-switch training offer that is still
//! pending in the writer: unanswered and not repeated by a newer offer. The
//! card the ask reads is the one the offer stored, never one the caller
//! supplies; an offer that stored no card is refused. The case must be for
//! the offer's seat and, when the offer names the cohort it was measured on,
//! in that cohort. The ask goes to the owner who calls, or, for an agent, to
//! the live owner who gave the Grant that admits it. Admission, the offer,
//! the card and the ask are read and written in one writer, on a repeat too.

use serde::{Deserialize, Serialize};

use super::super::cohort::cohort_in_txn;
use super::super::{EvalLabelAsk, WaitingDecision, case_in_txn};
use crate::EdgeActorClass;
use crate::authority::{NoStanding, PACT_STANDING_LAPSED, principal_standing_or_lapse_in_txn};
use crate::entity_id::EntityId;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::skill_optimize::{OfferCandidate, TrainingOffer, pending_training_offer_in_txn};

/// The verb a Grant lists to name the ask: the row's own name.
const ASK_VERB: &str = "vault.evals.labels.ask";

/// Why an agent with no conferring Grant is refused.
const NO_GRANT: &str = "no live Grant from a live owner names this agent and lists the verb";

/// `vault.evals.labels.ask`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalLabelAskRequest {
    /// The pending stock-switch training offer that waits on the label.
    pub offer: EntityId,
    /// The case the responsible owner is asked to label.
    pub case: EntityId,
    /// The two answers the owner picks between.
    pub option_a: String,
    pub option_b: String,
}

/// The decision an ask on `offer` names: what `vault.evals.labels.blocked`
/// filters on and `vault.evals.labels.pick` answers.
#[must_use]
pub fn training_offer_decision(offer: &EntityId) -> String {
    format!("training_offer:{}", offer.to_hex())
}

/// `vault.evals.labels.ask` on the caller's handle: the ask, or `None` when
/// the offer's card is known, or unknown for a reason no label settles. A
/// repeat on the same offer and case returns the first ask.
///
/// # Errors
///
/// FORBIDDEN for a caller that is neither the vault owner nor an agent with
/// a live owner Grant listing the verb; BAD_REQUEST for an offer that is not
/// pending, is not a stock switch or stored no card, and for a case of
/// another seat or outside the offer's cohort; the ask's own refusals
/// (unbounded or identical options, a missing case); storage errors.
pub fn ask_label(
    memory: &Memory<'_>,
    input: EvalLabelAskRequest,
) -> MemoryResult<Option<EvalLabelAsk>> {
    let vault = memory.vault();
    let at = vault.now_recorded_at();
    vault.try_with_write_txn_grouped(|txn| {
        let responsible = admit_asker_in_txn(memory, txn)?;
        let TrainingOffer {
            seat,
            candidate,
            evidence,
            ..
        } = pending_training_offer_in_txn(vault, txn, &input.offer)?.ok_or_else(|| {
            MemoryError::bad_request(
                "no pending training offer has this id: an answered or repeated offer waits on no label",
            )
        })?;
        if !matches!(candidate, OfferCandidate::Stock { .. }) {
            return Err(MemoryError::bad_request(
                "a label ask waits on a stock switch offer",
            ));
        }
        let Some(card) = evidence.card else {
            return Err(MemoryError::bad_request(
                "the offer stored no sufficiency card: a label ask reads the offer's own card",
            ));
        };
        let case = case_in_txn(vault, txn, &input.case)?.ok_or(crate::Error::EntityNotFound)?;
        if case.seat != seat {
            return Err(MemoryError::bad_request(
                "the case is for another seat than the offer",
            ));
        }
        if let Some(cohort) = &evidence.cohort
            && !cohort_in_txn(vault, txn, cohort)?.cases.contains(&input.case)
        {
            return Err(MemoryError::bad_request(
                "the case is not in the cohort the offer was measured on",
            ));
        }
        let waiting = WaitingDecision {
            reference: training_offer_decision(&input.offer),
            card,
        };
        Ok(vault.ask_eval_label_in_txn(
            txn,
            &waiting,
            &input.case,
            responsible,
            &input.option_a,
            &input.option_b,
            at,
        )?)
    })
}

/// The person an admitted caller's ask goes to, in `txn`: the vault owner
/// who calls while a live person, or the live owner whose Grant names the
/// calling agent and lists [`ASK_VERB`]. The caller's actor binding and any
/// credential it presented are checked here first, so a repeat that returns
/// a stored ask is admitted on the same terms as a first ask.
fn admit_asker_in_txn(memory: &Memory<'_>, txn: &heed::RoTxn<'_>) -> MemoryResult<EntityId> {
    let vault = memory.vault();
    crate::memory::verify_actor_binding_in_txn(vault, txn, memory.actor(), memory.actor_class())?;
    if let Some(slip) = memory.presented_credential()
        && !vault.capability_slip_is_live_in_txn(txn, slip)?
    {
        return Err(refused("the caller's credential is no longer live"));
    }
    if crate::memory::actor_is_vault_owner_in_txn(vault, txn, memory.actor(), memory.actor_class())?
    {
        if !crate::consent::person_is_live_in_txn(vault, txn, &memory.actor())? {
            return Err(refused("the vault owner is not a live person"));
        }
        return Ok(memory.actor());
    }
    if memory.actor_class() != EdgeActorClass::Agent {
        return Err(refused(
            "the caller is neither the vault owner nor an agent",
        ));
    }
    match principal_standing_or_lapse_in_txn(
        vault,
        txn,
        memory.actor(),
        EdgeActorClass::Agent,
        ASK_VERB,
    )? {
        Ok(standing) => {
            let grant = standing.grant.ok_or_else(|| refused(NO_GRANT))?;
            vault
                .agent_grants_in_txn(txn)?
                .into_iter()
                .find(|row| row.id == grant)
                .map(|row| row.delegated_by)
                .ok_or_else(|| refused(NO_GRANT))
        }
        Err(NoStanding::PactStandingLapsed) => Err(refused(PACT_STANDING_LAPSED)),
        Err(NoStanding::NotStanding) => Err(refused(NO_GRANT)),
    }
}

/// The verb's refusal of a caller it does not admit.
fn refused(why: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!(
            "{ASK_VERB} takes the vault owner's own proof or an agent's own Grant that lists it: {why}"
        ),
        &["Call as the owner, or have the owner grant this agent the verb by name."],
    )
}
