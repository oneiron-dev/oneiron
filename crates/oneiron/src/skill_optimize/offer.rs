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
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{EvalSeat, SufficiencyCard, TrainingChoice};
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::authority::{BaseAgent, base_agent_for_facet};
use crate::entity_id::bytes_to_hex_lower;
use crate::learning::{Anchor, LearningCell, LearningEvidence, LearningPredicate, Observation};
use crate::limit_ask::EngineLimit;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Error, Result, Vault};

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

const MAX_REF_BYTES: usize = 256;
const MAX_ALTERNATIVES: usize = 16;

/// A model asset as offered: identity, revision and, for a download, the
/// content hash it must load at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferModelPin {
    pub model: String,
    pub revision: String,
    pub content_hash: Option<String>,
}

/// Where a pilot or a training run would execute, and what leaves the device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ComputeDestination {
    OnDevice,
    SelfHosted { host: String },
    Hosted { provider: String, rows_leaving: u64 },
}

/// What the offer proposes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OfferCandidate {
    /// Switch the seat to a stock model that scores as well for less, or
    /// better for no more.
    Stock {
        model: OfferModelPin,
        licence: String,
        source: String,
    },
    /// Train a custom model from a base with a recipe.
    TrainRecipe {
        base: OfferModelPin,
        recipe_ref: String,
        licence: String,
    },
}

/// One option priced on the same projected workload. `None` is unknown.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferCost {
    pub currency: String,
    pub monthly_before: Option<f64>,
    pub monthly_after: Option<f64>,
    /// Pilot, migration or re-embed cost, paid once.
    pub one_off: Option<f64>,
    pub payback_months: Option<f64>,
}

/// The seat's dated workload the prices are projected from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SeatWorkload {
    pub from: u64,
    pub until: u64,
    pub calls: Option<u64>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    /// Whether the receipts cover the whole period; a partial month is never
    /// multiplied into a bill.
    pub complete: bool,
    pub receipt_refs: Vec<String>,
}

/// A comparison row: the baseline, the cheapest local option or an outside
/// one, in the same columns as the candidate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferOption {
    pub label: String,
    pub model: OfferModelPin,
    pub cost: OfferCost,
    pub score: Option<f64>,
    pub evidence_refs: Vec<String>,
}

/// The measured evidence behind the offer, read from OF-578's ledgers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferEvidence {
    pub cohort: Option<EntityId>,
    pub exposures: Vec<EntityId>,
    pub rubric_revision: Option<String>,
    /// `None` reads as unknown: nothing was measured yet.
    pub card: Option<SufficiencyCard>,
    /// Losses shown beside the gains (a general skill, a language, calibration).
    pub losses: Vec<String>,
    pub risk: Option<String>,
}

/// What the Coach's offer skill drafted.
#[derive(Debug, Clone, PartialEq)]
pub struct TrainingOfferDraft {
    pub seat: EvalSeat,
    /// The offer skill and the revision that drafted it.
    pub offer_skill: Option<(EntityId, String)>,
    pub incumbent: OfferModelPin,
    pub candidate: OfferCandidate,
    pub baseline: OfferOption,
    pub alternatives: Vec<OfferOption>,
    pub workload: SeatWorkload,
    pub cost: OfferCost,
    pub evidence: OfferEvidence,
    pub destination: ComputeDestination,
    /// The earlier offer this one repeats, and what changed since.
    pub previous: Option<EntityId>,
    pub what_changed: Option<String>,
    pub check_at: u64,
}

/// One immutable offer snapshot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrainingOffer {
    pub id: EntityId,
    pub seat: EvalSeat,
    pub offer_skill: Option<(EntityId, String)>,
    /// The model the offer skill ran on, as its load stamped the attempt.
    /// The skill's record is kept per model.
    pub drafted_on: Option<String>,
    /// The Coach attempt that drafted it.
    pub attempt: AttemptId,
    pub incumbent: OfferModelPin,
    pub candidate: OfferCandidate,
    pub baseline: OfferOption,
    pub alternatives: Vec<OfferOption>,
    pub workload: SeatWorkload,
    pub cost: OfferCost,
    pub evidence: OfferEvidence,
    pub destination: ComputeDestination,
    pub previous: Option<EntityId>,
    pub what_changed: Option<String>,
    pub check_at: u64,
    pub offered_at: u64,
    /// Digest of everything above: the question the owner answers.
    pub digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OfferAnswer {
    KeepBaseline,
    ApproveSwitch,
    ApproveTrain,
    Decline,
    Postpone,
}

/// What an approval asked for. A switch is bound with the answer; a train
/// intent waits for its training handoff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OfferIntent {
    /// Bind the stock model; the old binding stays for undo.
    Switch {
        seat: EvalSeat,
        from: OfferModelPin,
        to: OfferModelPin,
    },
    /// Start the training run; its result needs a separate swap choice.
    Train {
        seat: EvalSeat,
        base: OfferModelPin,
        recipe_ref: String,
        destination: ComputeDestination,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferAnswerRecord {
    pub offer: EntityId,
    pub answer: OfferAnswer,
    pub owner: EntityId,
    pub authentication: String,
    pub offer_digest: String,
    pub intent: Option<OfferIntent>,
    pub at: u64,
}

/// What later receipts showed against the offer's promise.
#[derive(Debug, Clone, PartialEq)]
pub struct OfferCheckInput {
    pub receipt_refs: Vec<String>,
    pub observed_monthly_cost: Option<f64>,
    pub observed_score: Option<f64>,
    /// Whether the promise held, as the checking observer read it.
    pub held: Option<bool>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferCheck {
    pub id: EntityId,
    pub offer: EntityId,
    pub receipt_refs: Vec<String>,
    pub observed_monthly_cost: Option<f64>,
    pub observed_score: Option<f64>,
    pub held: Option<bool>,
    pub note: Option<String>,
    pub at: u64,
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.into())
}

fn bounded(value: &str, max: usize, what: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > max {
        return Err(invalid(what));
    }
    Ok(())
}

/// Refuses a blank text; the offer keeps it whole and measures its size.
fn named(value: &str, what: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(invalid(what));
    }
    Ok(())
}

fn refs(values: &[String], required: bool) -> Result<()> {
    if (required && values.is_empty())
        || values
            .iter()
            .any(|value| value.trim().is_empty() || value.len() > MAX_REF_BYTES)
    {
        return Err(invalid("an offer names bounded receipt refs"));
    }
    Ok(())
}

fn amount(value: Option<f64>) -> Result<()> {
    if value.is_some_and(|value| !value.is_finite() || value < 0.0) {
        return Err(invalid(
            "an offer amount is finite and non-negative, or unknown",
        ));
    }
    Ok(())
}

impl OfferModelPin {
    fn validate(&self) -> Result<()> {
        named(&self.model, "an offered model names its id")?;
        named(&self.revision, "an offered model names its revision")?;
        if let Some(hash) = &self.content_hash {
            named(hash, "an offered model hash is not blank")?;
        }
        Ok(())
    }
}

impl OfferCost {
    fn validate(&self) -> Result<()> {
        bounded(&self.currency, 16, "an offer cost names its currency")?;
        for value in [
            self.monthly_before,
            self.monthly_after,
            self.one_off,
            self.payback_months,
        ] {
            amount(value)?;
        }
        Ok(())
    }
}

impl OfferOption {
    fn validate(&self) -> Result<()> {
        named(&self.label, "an offer option names its label")?;
        self.model.validate()?;
        self.cost.validate()?;
        amount(self.score)?;
        refs(&self.evidence_refs, false)
    }
}

impl TrainingOfferDraft {
    fn validate(&self) -> Result<()> {
        if let Some((_, version)) = &self.offer_skill {
            bounded(version, MAX_REF_BYTES, "the offer skill names its revision")?;
        }
        self.incumbent.validate()?;
        match &self.candidate {
            OfferCandidate::Stock {
                model,
                licence,
                source,
            } => {
                model.validate()?;
                if *model == self.incumbent {
                    return Err(invalid("a switch offers a model other than the incumbent"));
                }
                named(licence, "a stock candidate names its licence")?;
                bounded(source, MAX_REF_BYTES, "a stock candidate names its source")?;
            }
            OfferCandidate::TrainRecipe {
                base,
                recipe_ref,
                licence,
            } => {
                base.validate()?;
                bounded(
                    recipe_ref,
                    MAX_REF_BYTES,
                    "a training offer names its recipe",
                )?;
                named(licence, "a training offer names the base licence")?;
            }
        }
        self.baseline.validate()?;
        if self.baseline.model != self.incumbent {
            return Err(invalid("the baseline is today's incumbent"));
        }
        if self.alternatives.len() > MAX_ALTERNATIVES {
            return Err(invalid("an offer compares at most 16 alternatives"));
        }
        for option in &self.alternatives {
            option.validate()?;
        }
        if self.workload.from >= self.workload.until {
            return Err(invalid("the workload names a dated period"));
        }
        refs(&self.workload.receipt_refs, true)?;
        self.cost.validate()?;
        if self.cost.currency != self.baseline.cost.currency {
            return Err(invalid(
                "the offer and its baseline are priced in one currency",
            ));
        }
        if let Some(rubric) = &self.evidence.rubric_revision {
            named(rubric, "the evidence names its rubric revision")?;
        }
        for line in self.evidence.losses.iter().chain(&self.evidence.risk) {
            named(line, "an offer's loss and risk lines are not blank")?;
        }
        match &self.destination {
            ComputeDestination::OnDevice => {}
            ComputeDestination::SelfHosted { host } => {
                named(host, "a self-hosted run names its host")?;
            }
            ComputeDestination::Hosted { provider, .. } => {
                named(provider, "a hosted run names its provider")?;
            }
        }
        if self.previous.is_some() != self.what_changed.is_some() {
            return Err(invalid("a repeated offer says what changed since the last"));
        }
        if let Some(changed) = &self.what_changed {
            named(changed, "what changed is not blank")?;
        }
        Ok(())
    }
}

/// Measures an offer's longest list and longest text kept whole against the
/// engine's rows; the offer keeps both either way.
fn measure_offer(vault: &Vault, offer: &TrainingOffer) {
    let (evidence, refs) = (&offer.evidence, offer.workload.receipt_refs.len());
    let options = || std::iter::once(&offer.baseline).chain(&offer.alternatives);
    let lists = [refs, evidence.exposures.len(), evidence.losses.len()];
    let items = options().map(|option| option.evidence_refs.len());
    let items = items.chain(lists).max().unwrap_or(0);
    let (candidate, licence) = match &offer.candidate {
        OfferCandidate::Stock { model, licence, .. } => (model, licence),
        OfferCandidate::TrainRecipe { base, licence, .. } => (base, licence),
    };
    let place = match &offer.destination {
        ComputeDestination::OnDevice => None,
        ComputeDestination::SelfHosted { host } => Some(host),
        ComputeDestination::Hosted { provider, .. } => Some(provider),
    };
    // The incumbent is the baseline's model.
    let pins = || options().map(|option| &option.model).chain([candidate]);
    let longest = pins()
        .flat_map(|pin| [&pin.model, &pin.revision])
        .chain(pins().filter_map(|pin| pin.content_hash.as_ref()))
        .chain(options().map(|option| &option.label))
        .chain([licence])
        .chain(&evidence.rubric_revision)
        .chain(&evidence.losses)
        .chain(&evidence.risk)
        .chain(place)
        .chain(&offer.what_changed)
        .map(String::len)
        .max()
        .unwrap_or(0);
    let _ = vault.measure_limit(EngineLimit::MaintenanceRowItems, items as u64);
    let _ = vault.measure_limit(EngineLimit::MaintenanceTextBytes, longest as u64);
}

fn digest(offer: &TrainingOffer) -> Result<String> {
    let mut row = offer.clone();
    row.digest = String::new();
    let bytes = rmp_serde::to_vec_named(&row).map_err(|_| invalid("offer encoding failed"))?;
    let mut hash = Sha256::new();
    hash.update(b"skill_optimize:training_offer:v1\0");
    hash.update(bytes);
    Ok(bytes_to_hex_lower(&hash.finalize()))
}

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
        digest: String::new(),
    };
    offer.digest = digest(&offer)?;
    vault.with_write_txn_grouped(|txn| {
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
        Ok(offer)
    })
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
/// An unknown offer, a check before the check date, no or bad refs, a blank
/// note, a negative or non-finite observation, or storage errors.
pub fn record_offer_check(
    vault: &Vault,
    offer: &EntityId,
    input: OfferCheckInput,
    at: u64,
) -> Result<OfferCheck> {
    refs(&input.receipt_refs, true)?;
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
            note: input.note,
            at,
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
