//! The training offer's snapshot shapes (OF-577): what the Coach drafts,
//! the immutable offer the owner is shown, the owner's answer, a check of
//! the offer's promise, their validation, and the digest the answer binds.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::attempt_queue::AttemptId;
use crate::entity_id::bytes_to_hex_lower;
use crate::limit_ask::EngineLimit;
use crate::skill_optimize::{EvalSeat, SufficiencyCard};
use crate::{EntityId, Error, Result, Vault};

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
    /// The rows the brief was gathered from (FIX 5482), ids only: every row
    /// that fed it, the alternatives' included. `None` when they are not all
    /// known; `Some([])` is a proven empty set.
    pub source_rows: Option<Vec<EntityId>>,
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
    /// The rows the draft was gathered from (FIX 5482), ids only, sorted:
    /// `None` when they are not all known. An erased row leaves the list,
    /// and the digest leaves the list out, so an erase never changes the
    /// question the owner answers.
    pub source_rows: Option<Vec<EntityId>>,
    /// Digest of everything above but `source_rows`: the question the owner
    /// answers.
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
    /// The rows the check was read from (FIX 5482), ids only: `None` when
    /// they are not all known.
    pub source_rows: Option<Vec<EntityId>>,
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
    /// The rows the check was read from (FIX 5482), ids only, sorted: `None`
    /// when they are not all known. An erased row leaves the list.
    pub source_rows: Option<Vec<EntityId>>,
}

pub(super) fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.into())
}

fn bounded(value: &str, max: usize, what: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > max {
        return Err(invalid(what));
    }
    Ok(())
}

/// Refuses a blank text; the offer keeps it whole and measures its size.
pub(super) fn named(value: &str, what: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(invalid(what));
    }
    Ok(())
}

pub(super) fn refs(values: &[String], required: bool) -> Result<()> {
    if (required && values.is_empty())
        || values
            .iter()
            .any(|value| value.trim().is_empty() || value.len() > MAX_REF_BYTES)
    {
        return Err(invalid("an offer names bounded receipt refs"));
    }
    Ok(())
}

pub(super) fn amount(value: Option<f64>) -> Result<()> {
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
    pub(super) fn validate(&self) -> Result<()> {
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
pub(super) fn measure_offer(vault: &Vault, offer: &TrainingOffer) {
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

pub(super) fn digest(offer: &TrainingOffer) -> Result<String> {
    let mut row = offer.clone();
    row.digest = String::new();
    // The source rows are not part of the question (FIX 5482): an erase
    // drops ids from them without voiding a pending answer.
    row.source_rows = None;
    let bytes = rmp_serde::to_vec_named(&row).map_err(|_| invalid("offer encoding failed"))?;
    let mut hash = Sha256::new();
    hash.update(b"skill_optimize:training_offer:v1\0");
    hash.update(bytes);
    Ok(bytes_to_hex_lower(&hash.finalize()))
}

/// The union of source sets (FIX 5482), sorted and deduplicated: `None` once
/// any set is unknown; no set at all unions to a known empty one.
pub fn union_source_rows<S: AsRef<[EntityId]>>(
    sets: impl IntoIterator<Item = Option<S>>,
) -> Option<Vec<EntityId>> {
    let mut rows = Vec::new();
    for set in sets {
        rows.extend_from_slice(set?.as_ref());
    }
    rows.sort_unstable();
    rows.dedup();
    Some(rows)
}
