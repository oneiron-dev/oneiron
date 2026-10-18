//! Typed owner doors for the production Coach offer pass and its evidence.
//! No caller supplies a finished offer or a private runner lease.
use serde::{Deserialize, Serialize};

use super::{
    EvalSeat, OfferAnswer, OfferAnswerRecord, OfferCheck, TrainingOffer,
    settle_training_offer, training_offer, training_offer_checks, training_offers,
    undo_training_offer_switch,
};
use crate::attempt_queue::{AttemptId, AttemptState};
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::maintenance::coach::{
    COACH_HOST_QUEUE_KIND, COACH_TRAINING_OFFER_FACET,
};
use crate::dreamer_runner::{DreamerAttemptPayload, DreamerRunnerStore, EnqueueDreamerAttemptOutcome};
use crate::{EntityId, Error, Result, Vault};

#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferPassRequest {}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferPassRef {
    pub attempt: EntityId,
}

/// Completion is the actual host attempt's terminal state, not the presence
/// of an offer: the skill may choose to raise none.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferPassResult {
    pub attempt: EntityId,
    pub state: AttemptState,
    pub terminal: bool,
    pub offers: Vec<TrainingOffer>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferListRequest {
    #[serde(default)]
    pub seat: Option<EvalSeat>,
    #[serde(default)]
    pub pending_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferRef {
    pub offer: EntityId,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferView {
    pub offer: TrainingOffer,
    pub answer: Option<OfferAnswerRecord>,
    pub checks: Vec<OfferCheck>,
}

/// All five engine choices are served, not just the switch approval.
/// A train yes records intent; the existing training-offer owner routes
/// prepare and authorize its run and retain the separate result-swap choice.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferAnswerRequest {
    pub offer: EntityId,
    pub digest: String,
    pub answer: OfferAnswer,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferUndoReceipt {
    pub offer: EntityId,
    pub at: u64,
    pub restored_model: String,
}

pub fn trigger(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    _input: OfferPassRequest,
) -> Result<OfferPassRef> {
    let now = vault.now_recorded_at();
    vault.with_write_txn_grouped(|txn| {
        owner.revalidate_in_txn(vault, txn)?;
        // The nightly pass and the public trigger coalesce on the same
        // production facet. Admission stamps it for the Coach, as usual.
        let outcome = DreamerRunnerStore::new(vault).enqueue_kind_in_txn(
            txn,
            COACH_HOST_QUEUE_KIND,
            DreamerAttemptPayload {
                attempt_type: COACH_TRAINING_OFFER_FACET.into(),
                input: rmpv::Value::Nil,
                parent_attempt: None,
            },
            Some(COACH_TRAINING_OFFER_FACET.into()),
            None,
            now,
        )?;
        let status = match outcome {
            EnqueueDreamerAttemptOutcome::Enqueued(status)
            | EnqueueDreamerAttemptOutcome::Existing(status) => status,
        };
        Ok(OfferPassRef {
            attempt: EntityId::from_bytes(*status.attempt.id.as_bytes())?,
        })
    })
}

pub fn result(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: OfferPassRef,
) -> Result<Option<OfferPassResult>> {
    owner.revalidate_person(vault)?;
    let id = AttemptId::from_bytes(input.attempt.as_bytes())?;
    let Some(status) = DreamerRunnerStore::new(vault).status(id)? else {
        return Ok(None);
    };
    if status.payload.attempt_type != COACH_TRAINING_OFFER_FACET {
        return Err(Error::InvalidConfig("the attempt is not a Coach offer pass".into()));
    }
    let offers = training_offers(vault, None)?
        .into_iter()
        .filter(|(offer, _)| offer.attempt == id)
        .map(|(offer, _)| offer)
        .collect();
    Ok(Some(OfferPassResult {
        attempt: input.attempt,
        state: status.attempt.state,
        terminal: status.attempt.state.is_terminal(),
        offers,
    }))
}

pub fn list(vault: &Vault, owner: &AuthenticatedOwner, input: OfferListRequest) -> Result<Vec<OfferView>> {
    owner.revalidate_person(vault)?;
    let pending = if input.pending_only {
        Some(super::pending_training_offers(vault)?.into_iter().map(|row| row.id).collect::<std::collections::BTreeSet<_>>())
    } else {
        None
    };
    training_offers(vault, input.seat.as_ref())?
        .into_iter()
        .filter(|(offer, _)| pending.as_ref().is_none_or(|ids| ids.contains(&offer.id)))
        .map(|(offer, answer)| {
            let checks = training_offer_checks(vault, &offer.id)?;
            Ok(OfferView { offer, answer, checks })
        })
        .collect()
}

pub fn get(vault: &Vault, owner: &AuthenticatedOwner, input: OfferRef) -> Result<Option<OfferView>> {
    owner.revalidate_person(vault)?;
    let Some(offer) = training_offer(vault, &input.offer)? else { return Ok(None); };
    let answer = training_offers(vault, Some(&offer.seat))?
        .into_iter().find(|(row, _)| row.id == input.offer).and_then(|(_, answer)| answer);
    let checks = training_offer_checks(vault, &input.offer)?;
    Ok(Some(OfferView { offer, answer, checks }))
}

pub fn answer(vault: &Vault, owner: &AuthenticatedOwner, input: OfferAnswerRequest) -> Result<OfferAnswerRecord> {
    settle_training_offer(vault, owner, &input.offer, &input.digest, input.answer, None, vault.now_recorded_at())
}

pub fn undo(vault: &Vault, owner: &AuthenticatedOwner, input: OfferRef) -> Result<OfferUndoReceipt> {
    let receipt = undo_training_offer_switch(vault, owner, &input.offer, vault.now_recorded_at())?;
    Ok(OfferUndoReceipt {
        offer: receipt.offer,
        at: receipt.undone.map_or(receipt.at, |undo| undo.at),
        restored_model: receipt.previous.model.as_str().to_owned(),
    })
}
