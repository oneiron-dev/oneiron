//! Typed owner doors for the production Coach offer pass and its evidence.
//! No caller supplies a finished offer or a private runner lease.
use serde::{Deserialize, Serialize};

use super::{
    EvalSeat, OfferAnswer, OfferAnswerRecord, OfferCheck, TrainingOffer, settle_training_offer,
    training_offer, training_offer_checks, training_offers, undo_training_offer_switch,
    union_source_rows,
};
use crate::attempt_queue::{AttemptId, AttemptState};
use crate::claim::maintenance_kind::COACH_HOST_QUEUE_KIND;
use crate::claim::maintenance_kind::COACH_TRAINING_OFFER_FACET;
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::{
    DreamerAttemptPayload, DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
};
use crate::embed::PendingEmbedderBinding;
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
    /// The binding's current state, including settled and undone moves.
    /// `None` when this offer staged no embedder binding.
    pub staged: Option<PendingEmbedderBinding>,
}

/// A committed answer beside the embedder binding's current state.
/// The answer stays immutable; the binding is read for each reply.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferAnswerReply {
    pub answer: OfferAnswerRecord,
    /// Waiting, filling, applied, not applied or undone; `None` when absent.
    pub staged: Option<PendingEmbedderBinding>,
}

impl OfferAnswerReply {
    /// Projects a committed answer; never call from its uncommitted writer.
    ///
    /// # Errors
    /// Storage errors while reading the current binding.
    pub fn current(vault: &Vault, answer: OfferAnswerRecord) -> Result<Self> {
        let staged = vault.embedder_binding_move(&answer.offer)?;
        Ok(Self { answer, staged })
    }
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

/// The rows the offers and checks `views` serve were drafted and checked
/// from (FIX 5482): the union of the sets their snapshots keep, `None` when
/// any is unknown. No view serves no drafted content: a known empty set.
pub fn listed_views(views: &[OfferView]) -> Option<Vec<EntityId>> {
    union_source_rows(views.iter().flat_map(|view| {
        std::iter::once(view.offer.source_rows.as_deref())
            .chain(view.checks.iter().map(|check| check.source_rows.as_deref()))
    }))
}

/// The rows a pass's offers were drafted from (FIX 5482), as
/// [`listed_views`] reads them; a pass with no offer, or no such pass,
/// serves no drafted content.
pub fn listed_pass(pass: Option<&OfferPassResult>) -> Option<Vec<EntityId>> {
    union_source_rows(
        pass.into_iter()
            .flat_map(|pass| &pass.offers)
            .map(|offer| offer.source_rows.as_deref()),
    )
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
        return Err(Error::InvalidConfig(
            "the attempt is not a Coach offer pass".into(),
        ));
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

pub fn list(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: OfferListRequest,
) -> Result<Vec<OfferView>> {
    owner.revalidate_person(vault)?;
    let pending = if input.pending_only {
        Some(
            super::pending_training_offers(vault)?
                .into_iter()
                .map(|row| row.id)
                .collect::<std::collections::BTreeSet<_>>(),
        )
    } else {
        None
    };
    training_offers(vault, input.seat.as_ref())?
        .into_iter()
        .filter(|(offer, _)| pending.as_ref().is_none_or(|ids| ids.contains(&offer.id)))
        .map(|(offer, answer)| {
            let checks = training_offer_checks(vault, &offer.id)?;
            let staged = vault.embedder_binding_move(&offer.id)?;
            Ok(OfferView {
                offer,
                answer,
                checks,
                staged,
            })
        })
        .collect()
}

pub fn get(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: OfferRef,
) -> Result<Option<OfferView>> {
    owner.revalidate_person(vault)?;
    let Some(offer) = training_offer(vault, &input.offer)? else {
        return Ok(None);
    };
    let answer = training_offers(vault, Some(&offer.seat))?
        .into_iter()
        .find(|(row, _)| row.id == input.offer)
        .and_then(|(_, answer)| answer);
    let checks = training_offer_checks(vault, &input.offer)?;
    let staged = vault.embedder_binding_move(&input.offer)?;
    Ok(Some(OfferView {
        offer,
        answer,
        checks,
        staged,
    }))
}

pub fn answer(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: OfferAnswerRequest,
) -> Result<OfferAnswerReply> {
    let answer = settle_training_offer(
        vault,
        owner,
        &input.offer,
        &input.digest,
        input.answer,
        None,
        vault.now_recorded_at(),
    )?;
    OfferAnswerReply::current(vault, answer)
}

pub fn undo(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: OfferRef,
) -> Result<OfferUndoReceipt> {
    let receipt = undo_training_offer_switch(vault, owner, &input.offer, vault.now_recorded_at())?;
    Ok(OfferUndoReceipt {
        offer: receipt.offer,
        at: receipt.undone.map_or(receipt.at, |undo| undo.at),
        restored_model: receipt.previous.model.as_str().to_owned(),
    })
}

/// A training run, by id.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrainingRunRef {
    pub run: EntityId,
}

/// Cancels a staged trained embedder swap while its binding still waits or
/// fills (FIX 9459). The staged move is abandoned in the same owner write;
/// an applied swap keeps the existing space-move undo door.
pub fn cancel_training_run(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: TrainingRunRef,
) -> Result<PendingEmbedderBinding> {
    vault.cancel_training_embedder_swap(owner, &input.run)
}
