//! An approved training offer's run (OF-577; ARCH-0053 #training-offers: a
//! train yes runs the OF-552 pack, then shows the result for a separate swap
//! choice). The owner prepares a run for the offer's seat and base, and their
//! yes on that exact prepared spec authorizes it, with the answer or after
//! it. The handoff keeps the one run the yes started, and the promise check
//! follows that run. A bare train approval still records only its intent,
//! and nothing here binds a model.
use serde::{Deserialize, Serialize};

use super::{
    EvalSeat, OfferAnswer, OfferAnswerRecord, OfferCandidate, OfferIntent, OfferModelPin,
    training_offer,
};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::bytes_to_hex_lower;
use crate::side_table::{self, Named, SideTable};
use crate::training_pack::{TrainingAuthorizationSource, TrainingDeclarationPin, TrainingPlan};
use crate::{EntityId, Error, Result, Vault};

/// The run an approved Train offer handed off, keyed by offer id.
const HANDOFF: SideTable<EntityId, OfferTrainingHandoff, Named> =
    SideTable::new(&side_table::SKILL_OPTIMIZE_OFFER_TRAINING);
/// The owner's answer to an offer, read for the Train intent a later
/// handoff needs. Keyed by offer id; `offer` writes it.
const ANSWER: SideTable<EntityId, OfferAnswerRecord, Named> =
    SideTable::new(&side_table::SKILL_OPTIMIZE_OFFER_ANSWER);
/// The recipe form the host's offers name an earlier run with.
const RECIPE_RUN_PREFIX: &str = "training_run:";

/// The prepared run an approved Train offer handed off, at the exact spec
/// the owner authorized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfferTrainingHandoff {
    pub offer: EntityId,
    pub offer_digest: String,
    pub run: EntityId,
    pub spec_blake3: [u8; 32],
    pub owner: EntityId,
    pub at: u64,
}

/// The owner's training choice on a Train offer: the prepared run, the spec
/// they saw and the declaration the host admits that run under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrainingChoice {
    pub run: EntityId,
    pub spec_blake3: [u8; 32],
    pub declaration: TrainingDeclarationPin,
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.into())
}

/// A plan is for the offer's seat, from its base: the starting checkpoint's
/// model, and its first file's hash when the offer pins one, as the offer
/// derives it.
fn plan_matches(seat: &EvalSeat, base: &OfferModelPin, plan: &TrainingPlan) -> Result<()> {
    let first = plan
        .starting_checkpoint
        .files
        .first()
        .map(|file| bytes_to_hex_lower(&file.content.blake3));
    if plan.seat != *seat
        || plan.starting_checkpoint.model.as_str() != base.model
        || base
            .content_hash
            .as_ref()
            .is_some_and(|hash| first.as_ref() != Some(hash))
    {
        return Err(invalid(
            "the prepared run is not for the offer's seat and base model",
        ));
    }
    Ok(())
}

/// The vault owner's answer to the exact offer they saw, in its own writer.
/// `training` is the prepared run a train approval hands off with the
/// answer; `None` records the answer as before, and any other answer that
/// carries one is refused.
/// # Errors
/// A caller who is not the vault owner, an unknown offer, a digest for
/// another snapshot, an answered or repeated offer, an approval of the wrong
/// kind, a switch the seat's binding or the registry no longer admits, a
/// training choice the handoff refuses, or storage errors. An error writes
/// nothing.
pub fn settle_training_offer(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    offer: &EntityId,
    expected_digest: &str,
    answer: OfferAnswer,
    training: Option<&TrainingChoice>,
    at: u64,
) -> Result<OfferAnswerRecord> {
    vault.with_write_txn_grouped(|txn| {
        super::settle_training_offer_in_txn(
            vault,
            txn,
            owner,
            offer,
            expected_digest,
            answer,
            training,
            at,
            None,
        )
    })
}

/// Hands a train approval's prepared run off in `txn`: the owner's
/// authorization pins the exact choice and queues the run for the host, the
/// run is for the intent's seat and base, and the offer keeps that one run.
/// The same run and spec again return the stored handoff.
/// # Errors
/// An answer with no Train intent, another run already handed off for the
/// offer, a spec, declaration or run state the authorization refuses, a run
/// for another seat or base, or storage errors.
pub(super) fn hand_off_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    owner: &AuthenticatedOwner,
    answer: &OfferAnswerRecord,
    choice: &TrainingChoice,
    at: u64,
) -> Result<OfferTrainingHandoff> {
    let actor = owner.revalidate_in_txn(vault, txn)?;
    let Some(OfferIntent::Train { seat, base, .. }) = &answer.intent else {
        return Err(invalid("only a train approval hands off a training run"));
    };
    if let Some(stored) = HANDOFF.get(&vault.store, txn, &answer.offer)? {
        if stored.run == choice.run && stored.spec_blake3 == choice.spec_blake3 {
            return Ok(stored);
        }
        return Err(invalid("the offer already handed off another training run"));
    }
    let run = vault.authorize_training_pack_in_txn(
        txn,
        owner,
        &choice.run,
        &choice.spec_blake3,
        choice.declaration.clone(),
        TrainingAuthorizationSource::Offer {
            offer: answer.offer,
            offer_digest: answer.offer_digest.clone(),
        },
        at,
    )?;
    plan_matches(seat, base, &run.plan)?;
    let handoff = OfferTrainingHandoff {
        offer: answer.offer,
        offer_digest: answer.offer_digest.clone(),
        run: run.id,
        spec_blake3: run.spec_blake3,
        owner: actor,
        at,
    };
    HANDOFF.put(&vault.store, txn, &answer.offer, &handoff)?;
    Ok(handoff)
}

/// The owner's training choice after their train approval: the offer's
/// answer carries its Train intent, and the prepared run is handed off as
/// it would have been with the answer.
/// # Errors
/// An unanswered offer, and as the handoff.
pub fn authorize_offer_training(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    offer: &EntityId,
    choice: &TrainingChoice,
    at: u64,
) -> Result<OfferTrainingHandoff> {
    vault.with_write_txn_grouped(|txn| {
        let answer = ANSWER
            .get(&vault.store, txn, offer)?
            .ok_or(invalid("the training offer has no train approval"))?;
        hand_off_in_txn(vault, txn, owner, &answer, choice, at)
    })
}

/// Whether `plan` is for a Train offer's seat and base: the owner prepares
/// the offer's run before the yes that authorizes it.
/// # Errors
/// An unknown offer, a stock offer, a plan for another seat or base, or
/// storage errors.
pub fn check_offer_training_plan(
    vault: &Vault,
    offer: &EntityId,
    plan: &TrainingPlan,
) -> Result<()> {
    let row = training_offer(vault, offer)?.ok_or(invalid("no such training offer"))?;
    let OfferCandidate::TrainRecipe { base, .. } = &row.candidate else {
        return Err(invalid("a stock offer trains no run"));
    };
    plan_matches(&row.seat, base, plan)
}

/// The run an approved Train offer handed off, if any.
/// # Errors
/// Storage errors.
pub fn offer_training_handoff(
    vault: &Vault,
    offer: &EntityId,
) -> Result<Option<OfferTrainingHandoff>> {
    let txn = vault.store.env.read_txn()?;
    HANDOFF.get(&vault.store, &txn, offer)
}

/// The plan of the earlier run a Train offer's recipe names
/// (`training_run:<id>`), as a suggestion only: the owner confirms every
/// field, and an old run's compute choice, connector, quantity and split are
/// not part of a plan. Any other recipe or offer suggests nothing.
/// # Errors
/// Storage errors.
pub fn suggested_training_plan(vault: &Vault, offer: &EntityId) -> Result<Option<TrainingPlan>> {
    let Some(row) = training_offer(vault, offer)? else {
        return Ok(None);
    };
    let OfferCandidate::TrainRecipe { recipe_ref, .. } = &row.candidate else {
        return Ok(None);
    };
    let Some(run) = recipe_ref
        .strip_prefix(RECIPE_RUN_PREFIX)
        .and_then(|hex| EntityId::from_hex(hex).ok())
    else {
        return Ok(None);
    };
    Ok(vault.training_run(&run)?.map(|run| run.plan))
}
