//! Moved from `crates/oneiron/src/skill_optimize/offer/snapshot.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::skill_optimize::eval_set::sufficiency::SufficiencyCard;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

pub const MAX_REF_BYTES: usize = 256;

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
    /// The native Final paired measurement that supplied this card, when its
    /// model/revision arms, exposures and card were verified in the offer's writer.
    /// This is historical provenance, not current auto-approval authority.
    pub paired_measurement: Option<[u8; 32]>,
    /// Losses shown beside the gains (a general skill, a language, calibration).
    pub losses: Vec<String>,
    pub risk: Option<String>,
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

/// What an offer check concluded, so readers tell a verified promise from
/// an unreadable window without parsing the note's head code (FIX 6315).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OfferCheckOutcome {
    /// The window's bill compared against the promise and held.
    Held,
    /// The window's bill compared against the promise and broke it.
    Broken,
    /// The window priced in another currency than the offer's, so no bill
    /// compared.
    CurrencyMismatch,
    /// The cost held but the promised score was never measured.
    PromisedScoreUnknown,
    /// The offer promised no monthly figure, so no bill compared.
    PromisedCostUnknown,
    /// The seat ran no call on the approved model in the window.
    UnverifiableNoCalls,
    /// No usage meter is bound for the vault.
    UnverifiableNoMeter,
    /// No handed-off run reached Bound.
    UnverifiableNotBound,
    /// The offer's seat names no model role.
    UnverifiableNoModelRole,
    /// The seat's other calls were counted out, so the approved model's are
    /// only part of its month.
    UnverifiableMixedModel,
    /// Calls measured no tokens.
    UnverifiableNoUsage,
    /// Calls had no list price frozen on them at admission.
    UnverifiableUnpricedModel,
    /// Calls carry a frozen price naming no currency.
    UnverifiableUnknownCurrency,
    /// Calls measured cached tokens their frozen price quotes no rate for.
    UnverifiableUnpricedCache,
    /// Calls priced in another currency than the window's.
    UnverifiableMixedCurrency,
    /// Calls priced past what the window's sum holds.
    UnverifiableSumOverflow,
    /// Calls with no price and a record naming no reason.
    UnverifiableUnclassified,
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
    /// What the check concluded.
    pub outcome: OfferCheckOutcome,
    pub note: Option<String>,
    pub at: u64,
    /// The rows the check was read from (FIX 5482), ids only, sorted: `None`
    /// when they are not all known. An erased row leaves the list.
    pub source_rows: Option<Vec<EntityId>>,
}

pub fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.into())
}

pub fn bounded(value: &str, max: usize, what: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > max {
        return Err(invalid(what));
    }
    Ok(())
}

/// Refuses a blank text; the offer keeps it whole and measures its size.
pub fn named(value: &str, what: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(invalid(what));
    }
    Ok(())
}

pub fn refs(values: &[String], required: bool) -> Result<()> {
    if (required && values.is_empty())
        || values
            .iter()
            .any(|value| value.trim().is_empty() || value.len() > MAX_REF_BYTES)
    {
        return Err(invalid("an offer names bounded receipt refs"));
    }
    Ok(())
}

pub fn amount(value: Option<f64>) -> Result<()> {
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
