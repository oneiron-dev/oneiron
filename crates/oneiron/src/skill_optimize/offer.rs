//! The Coach's training offer (OF-577): a cheaper stock model or a custom
//! one for a seat, which the owner approves. Nothing deploys by itself.
//!
//! The Coach reads each seat's receipts at night and its offer skill decides
//! whether a case is worth raising; how often is model policy, never a fixed
//! cooldown. An offer is an immutable snapshot of what the owner is shown:
//! the seat, today's baseline, the candidate (a stock switch or a training
//! recipe), the same projected workload priced for each option, the OF-578
//! evidence and sufficiency card, the compute destination with any rows
//! leaving the device, and a check date for the promise. An unknown cost
//! stays unknown, never zero.
//!
//! - "Do nothing is the default." An unanswered or closed offer keeps the
//!   baseline; only the vault owner's answer on the exact offer settles it.
//! - A decline is a label for the offer skill, and a postpone comes back
//!   later as a new offer with fresh numbers that says what changed.
//! - A switch approval binds the stock model in the owner's own answer
//!   transaction and keeps the replaced binding for undo (`offer_switch`). A
//!   train approval records an intent and may hand off a prepared run
//!   (`offer_training`); a trained model still needs its own swap choice.
//! - Each offer's prediction is checked against later receipts on or after
//!   its check date, which feeds the offer skill's own record.
use super::{EvalSeat, TrainingChoice};
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::authority::{BaseAgent, base_agent_for_facet};
use crate::learning::{Anchor, LearningCell, LearningEvidence, LearningPredicate, Observation};
use crate::limit_ask::EngineLimit;
use crate::ports::{DeletionMarker, TombstoneStoreRead};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Result, Vault};

mod snapshot;

pub use self::snapshot::{
    ComputeDestination, OfferAnswer, OfferAnswerRecord, OfferCandidate, OfferCheck,
    OfferCheckInput, OfferCheckOutcome, OfferCost, OfferEvidence, OfferIntent, OfferModelPin,
    OfferOption, SeatWorkload, TrainingOffer, TrainingOfferDraft, union_source_rows,
};
use self::snapshot::{amount, digest, invalid, measure_offer, named, refs};

/// One offer snapshot, keyed by offer id. Written once.
const OFFER: SideTable<EntityId, TrainingOffer, Named> =
    SideTable::new(&side_table::SKILL_OPTIMIZE_OFFER);
/// The owner's one answer to an offer, keyed by offer id.
const ANSWER: SideTable<EntityId, OfferAnswerRecord, Named> =
    SideTable::new(&side_table::SKILL_OPTIMIZE_OFFER_ANSWER);
/// One check of an offer's prediction against later receipts, keyed by offer
/// id then check id.
const CHECK: SideTable<(EntityId, EntityId), OfferCheck, Named> =
    SideTable::new(&side_table::SKILL_OPTIMIZE_OFFER_CHECK);

/// The shipped skill the Coach drafts its offers with, by name.
const TRAINING_OFFER_SKILL: &str = "training-offer";
/// The shipped skill the Coach keeps each seat's eval set with, by name.
const EVAL_AUTHORING_SKILL: &str = "eval-authoring";
/// The offer skill's outcome axis: whether a checked offer's promise held.
pub const OFFER_SKILL_AXIS: &str = "training_offer";

/// Record the Coach's offer for a seat. The attempt must be an admitted
/// Coach attempt; a repeat must follow an answered (or unanswered) earlier
/// offer for the same seat and say what changed.
/// # Errors
/// An attempt not stamped for the Coach, an invalid draft, a check date in
/// the past, an unknown or other-seat previous offer, or storage errors.
pub fn record_training_offer(
    vault: &Vault,
    attempt: AttemptId,
    draft: TrainingOfferDraft,
    at: u64,
) -> Result<TrainingOffer> {
    let authority = vault.dreamer_attempt_authority(attempt)?.ok_or(invalid(
        "a training offer comes from an admitted Coach attempt",
    ))?;
    if base_agent_for_facet(&authority.facet) != BaseAgent::Coach
        || authority.actor != vault.coach_authority()?.entity_ref()
    {
        return Err(invalid("a training offer runs under the Coach authority"));
    }
    draft.validate()?;
    if draft.check_at <= at {
        return Err(invalid("an offer's check date is after it is made"));
    }
    let drafted_on = match &draft.offer_skill {
        Some(_) => AttemptQueue::new(vault)
            .get(attempt)?
            .and_then(|record| record.executor_model),
        None => None,
    };
    let mut offer = TrainingOffer {
        id: vault.store.clock.entity_id()?,
        seat: draft.seat,
        offer_skill: draft.offer_skill,
        drafted_on,
        attempt,
        incumbent: draft.incumbent,
        candidate: draft.candidate,
        baseline: draft.baseline,
        alternatives: draft.alternatives,
        workload: draft.workload,
        cost: draft.cost,
        evidence: draft.evidence,
        destination: draft.destination,
        previous: draft.previous,
        what_changed: draft.what_changed,
        check_at: draft.check_at,
        offered_at: at,
        source_rows: draft.source_rows,
        digest: String::new(),
    };
    offer.digest = digest(&offer)?;
    vault.with_write_txn_grouped(|txn| {
        offer.source_rows = live_source_rows_in(vault, txn, offer.source_rows.take())?;
        if let Some(previous) = &offer.previous {
            let earlier = OFFER
                .get(&vault.store, txn, previous)?
                .ok_or(invalid("the repeated offer is unknown"))?;
            if earlier.seat != offer.seat {
                return Err(invalid("a repeated offer is for the same seat"));
            }
        }
        super::offer_pilot::validate_snapshot_in_txn(vault, txn, &offer)?;
        measure_offer(vault, &offer);
        OFFER.put(&vault.store, txn, &offer.id, &offer)?;
        if let Some(previous) = &offer.previous {
            crate::task_verb::void_training_offer_asks_in(vault, txn, previous, None, at)?;
        }
        Ok(offer)
    })
}

/// `rows` sorted and deduplicated, less every row already hard-erased in
/// `txn` (FIX 5482): a source an erase reached between the gather and this
/// write does not come back. Unknown stays unknown. Every engine writer of a
/// kept source set filters through it (FIX 6933).
pub(crate) fn live_source_rows_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    rows: Option<Vec<EntityId>>,
) -> Result<Option<Vec<EntityId>>> {
    let Some(rows) = union_source_rows([rows.as_deref()]) else {
        return Ok(None);
    };
    let mut live = Vec::with_capacity(rows.len());
    for row in rows {
        if !vault
            .store
            .port_deletion_marked(txn, DeletionMarker::HardDelete, &row)?
        {
            live.push(row);
        }
    }
    Ok(Some(live))
}

/// Drops an erased row from every offer's and every check's source rows
/// (FIX 5482), rewriting only the snapshots that named it; the rest of each
/// snapshot, its digest and any answer to it stay as they are. Registered
/// once, on the offer table's declaration. A source may be any row, so this
/// reads every snapshot for each erased id.
/// # Errors
/// Storage errors.
pub(crate) fn erase_offer_source_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let forget = |rows: &mut Option<Vec<EntityId>>| {
        let Some(rows) = rows else {
            return false;
        };
        let before = rows.len();
        rows.retain(|row| row != id);
        rows.len() != before
    };
    let mut offers = Vec::new();
    for (key, mut offer) in OFFER.scan(&vault.store, wtxn)? {
        if forget(&mut offer.source_rows) {
            offers.push((key, offer));
        }
    }
    for (key, offer) in offers {
        OFFER.put(&vault.store, wtxn, &key, &offer)?;
    }
    let mut checks = Vec::new();
    for (key, mut check) in CHECK.scan(&vault.store, wtxn)? {
        if forget(&mut check.source_rows) {
            checks.push((key, check));
        }
    }
    for (key, check) in checks {
        CHECK.put(&vault.store, wtxn, &key, &check)?;
    }
    Ok(())
}

/// One offer, if recorded.
/// # Errors
/// Storage errors.
pub fn training_offer(vault: &Vault, id: &EntityId) -> Result<Option<TrainingOffer>> {
    let txn = vault.store.env.read_txn()?;
    OFFER.get(&vault.store, &txn, id)
}

/// Every offer with its answer, oldest first: the offer skill reads its
/// declines and postpones here, and the inbox and digest read pending ones.
/// # Errors
/// Storage errors.
pub fn training_offers(
    vault: &Vault,
    seat: Option<&EvalSeat>,
) -> Result<Vec<(TrainingOffer, Option<OfferAnswerRecord>)>> {
    let txn = vault.store.env.read_txn()?;
    let mut rows = Vec::new();
    for (_, offer) in OFFER.scan(&vault.store, &txn)? {
        if seat.is_some_and(|seat| *seat != offer.seat) {
            continue;
        }
        let answer = ANSWER.get(&vault.store, &txn, &offer.id)?;
        rows.push((offer, answer));
    }
    rows.sort_by_key(|(offer, _)| (offer.offered_at, offer.id));
    Ok(rows)
}

/// The offers awaiting the owner: unanswered and not repeated by a newer one.
/// Leaving one unanswered keeps the baseline.
/// # Errors
/// Storage errors.
pub fn pending_training_offers(vault: &Vault) -> Result<Vec<TrainingOffer>> {
    let rows = training_offers(vault, None)?;
    let repeated: std::collections::BTreeSet<EntityId> = rows
        .iter()
        .filter_map(|(offer, _)| offer.previous)
        .collect();
    Ok(rows
        .into_iter()
        .filter(|(offer, answer)| answer.is_none() && !repeated.contains(&offer.id))
        .map(|(offer, _)| offer)
        .collect())
}

/// Whether a newer offer names `offer` as the one it repeats, read in `txn`.
fn repeated_in(vault: &Vault, txn: &heed::RoTxn<'_>, offer: &EntityId) -> Result<bool> {
    Ok(OFFER
        .scan(&vault.store, txn)?
        .iter()
        .any(|(_, row)| row.previous.as_ref() == Some(offer)))
}

/// One offer still awaiting the owner, read in `txn`: unanswered and not
/// repeated by a newer one. `None` for any other.
/// # Errors
/// Storage errors.
pub(crate) fn pending_training_offer_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    offer: &EntityId,
) -> Result<Option<TrainingOffer>> {
    if ANSWER.contains(&vault.store, txn, offer)? || repeated_in(vault, txn, offer)? {
        return Ok(None);
    }
    OFFER.get(&vault.store, txn, offer)
}

/// The vault owner's answer to the exact offer they saw, in `txn`. A switch
/// approval needs a stock candidate and binds it to the seat's role in this
/// transaction, keeping the old binding for undo; a train approval needs a
/// recipe and records its intent, and a `training` choice with it hands
/// that prepared run off in the same commit (`offer_training`). An answer
/// closes the offer's open asks: `settling_ask` is the ask group whose own
/// settlement carries it, if any, and every other one is cut stale.
/// # Errors
/// A caller who is not the vault owner, an unknown offer, a digest for
/// another snapshot, an answered or repeated offer, an approval of the wrong
/// kind, a switch the seat's binding or the registry no longer admits, a
/// training choice on another answer or one the handoff refuses, a failed
/// cut of an open ask, or storage errors.
#[expect(
    clippy::too_many_arguments,
    reason = "the settlement door's arguments, its writer and the settling ask"
)]
pub(crate) fn settle_training_offer_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    owner: &AuthenticatedOwner,
    offer: &EntityId,
    expected_digest: &str,
    answer: OfferAnswer,
    training: Option<&TrainingChoice>,
    at: u64,
    settling_ask: Option<&EntityId>,
) -> Result<OfferAnswerRecord> {
    if repeated_in(vault, txn, offer)? {
        return Err(invalid(
            "a newer offer replaced this one; answer that instead",
        ));
    }
    let actor = owner.revalidate_in_txn(vault, txn)?;
    let row = OFFER
        .get(&vault.store, txn, offer)?
        .ok_or(invalid("no such training offer"))?;
    if row.digest != expected_digest {
        return Err(invalid("the answer does not bind the offer that was shown"));
    }
    if ANSWER.contains(&vault.store, txn, offer)? {
        return Err(invalid("the training offer is already answered"));
    }
    let intent = match (answer, &row.candidate) {
        (OfferAnswer::ApproveSwitch, OfferCandidate::Stock { model, .. }) => {
            Some(OfferIntent::Switch {
                seat: row.seat.clone(),
                from: row.incumbent.clone(),
                to: model.clone(),
            })
        }
        (
            OfferAnswer::ApproveTrain,
            OfferCandidate::TrainRecipe {
                base, recipe_ref, ..
            },
        ) => Some(OfferIntent::Train {
            seat: row.seat.clone(),
            base: base.clone(),
            recipe_ref: recipe_ref.clone(),
            destination: row.destination.clone(),
        }),
        (OfferAnswer::ApproveSwitch | OfferAnswer::ApproveTrain, _) => {
            return Err(invalid("the approval does not match the offer's candidate"));
        }
        _ => None,
    };
    if let Some(OfferIntent::Switch { seat, from, to }) = &intent {
        super::offer_switch::apply_switch_in_txn(vault, txn, actor, offer, seat, from, to, at)?;
    }
    let record = OfferAnswerRecord {
        offer: *offer,
        answer,
        owner: actor,
        authentication: format!("{:?}", owner.decision_id()),
        offer_digest: row.digest,
        intent,
        at,
    };
    ANSWER.put(&vault.store, txn, offer, &record)?;
    if let Some(choice) = training {
        super::offer_training::hand_off_in_txn(vault, txn, owner, &record, choice, at)?;
    }
    crate::task_verb::void_training_offer_asks_in(vault, txn, offer, settling_ask, at)?;
    Ok(record)
}

/// Check an offer's promise against later receipts, on or after its check
/// date. Checks append. A check that read whether the promise held is a world
/// outcome for the offer skill that drafted it, on the model it ran on, in
/// the same transaction; an unknown one is none.
/// # Errors
/// An unknown offer, a check before the check date, bad refs, no refs on a
/// check that judged whether the promise held (an unknown one may name none),
/// a blank note, a negative or non-finite observation, or storage errors.
pub fn record_offer_check(
    vault: &Vault,
    offer: &EntityId,
    input: OfferCheckInput,
    at: u64,
) -> Result<OfferCheck> {
    refs(&input.receipt_refs, input.held.is_some())?;
    amount(input.observed_monthly_cost)?;
    amount(input.observed_score)?;
    if let Some(note) = &input.note {
        named(note, "an offer check note is not blank")?;
    }
    let root = crate::task_type::type_tree(vault, None)?.root();
    vault.with_write_txn_grouped(|txn| {
        let row = OFFER
            .get(&vault.store, txn, offer)?
            .ok_or(invalid("no such training offer"))?;
        if at < row.check_at {
            return Err(invalid("an offer is checked on or after its check date"));
        }
        let check = OfferCheck {
            id: vault.store.clock.entity_id()?,
            offer: *offer,
            receipt_refs: input.receipt_refs,
            observed_monthly_cost: input.observed_monthly_cost,
            observed_score: input.observed_score,
            held: input.held,
            outcome: input.outcome,
            note: input.note,
            at,
            source_rows: live_source_rows_in(vault, txn, input.source_rows)?,
        };
        let note = check.note.as_ref().map_or(0, String::len);
        let _ = vault.measure_limit(EngineLimit::MaintenanceTextBytes, note as u64);
        let items = check.receipt_refs.len();
        let _ = vault.measure_limit(EngineLimit::MaintenanceRowItems, items as u64);
        CHECK.put(&vault.store, txn, &(*offer, check.id), &check)?;
        if let (Some(held), Some((skill, _)), Some(executor)) =
            (check.held, row.offer_skill, row.drafted_on)
        {
            let cell = LearningCell::new(LearningPredicate::Reliability, skill)
                .executor(executor)
                .type_ref(root)
                .axis(OFFER_SKILL_AXIS);
            crate::learning::record_evidence_in_txn(
                vault,
                txn,
                &cell,
                &LearningEvidence::anchored(
                    format!("offer_check:{}", check.id.to_hex()),
                    check.at,
                    Anchor::WorldOutcome,
                    Observation::Success(held),
                ),
                at,
            )?;
        }
        Ok(check)
    })
}

/// The shipped offer skill (ARCH-0053 #training-offers): the Coach loads it
/// on its offer attempt, and each offer names the revision that drafted it.
/// # Errors
/// Never in practice: the id derives from a fixed name.
pub fn training_offer_skill_id() -> Result<EntityId> {
    EntityId::derive(
        crate::entity_id::derived_domains::BOOTSTRAP_SKILL,
        &[TRAINING_OFFER_SKILL.as_bytes()],
    )
}

/// The shipped eval-authoring skill (ARCH-0053 "Eval authoring", OF-578): the
/// Coach loads it on its eval-authoring attempt, and each cut and retirement
/// names the revision that decided it.
/// # Errors
/// Never in practice: the id derives from a fixed name.
pub fn eval_authoring_skill_id() -> Result<EntityId> {
    EntityId::derive(
        crate::entity_id::derived_domains::BOOTSTRAP_SKILL,
        &[EVAL_AUTHORING_SKILL.as_bytes()],
    )
}

/// The offer skill's record on one drafting model: its `learning.reliability`
/// cell at the vault tree's root, since an offer has no task type.
/// # Errors
/// Storage errors reading the vault's type tree.
pub fn offer_skill_cell(vault: &Vault, skill: EntityId, executor: &str) -> Result<LearningCell> {
    Ok(LearningCell::new(LearningPredicate::Reliability, skill)
        .executor(executor)
        .type_ref(crate::task_type::type_tree(vault, None)?.root())
        .axis(OFFER_SKILL_AXIS))
}

/// Every check of one offer, in id order.
/// # Errors
/// Storage errors.
pub fn training_offer_checks(vault: &Vault, offer: &EntityId) -> Result<Vec<OfferCheck>> {
    let txn = vault.store.env.read_txn()?;
    Ok(CHECK
        .scan_from(&vault.store, &txn, offer.as_bytes())?
        .into_iter()
        .map(|(_, check)| check)
        .collect())
}
