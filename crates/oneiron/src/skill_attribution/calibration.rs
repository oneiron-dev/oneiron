//! OF-542: `attribution_unclear_floor` learned from the held-out judge audits
//! (ARCH-0056 §5: refit from judge audit receipts the same way as
//! `audit_rate`). Each audit run keeps its batch whole: every case's opaque
//! id and known answer, the judge's raw labels and probabilities before the
//! floor held any, the revision that gave them, and the floor in force. The
//! fitter replays the judged cases under each candidate floor through the
//! production gate and records the best one as one held-out check on the
//! knob's global subject at the root type, in the audit row's own
//! transaction. A run that argues for no floor records nothing.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::error::Result;
use crate::learning::{Anchor, TypeRef};
use crate::learning_setting::{
    ATTRIBUTION_UNCLEAR_FLOOR, SettingCheck, global_setting_subject, record_setting_check_in_txn,
};

use super::judge::JudgeTrace;
use super::split::held_reason;
use super::types::{AttributionLane, AttributionVerdict};

/// The rule a batch's target was chosen under. A batch keeps it, so a later
/// rule can tell its targets apart.
pub const UNCLEAR_FLOOR_FITTER_VERSION: u32 = 1;

/// Where one audited case's answer came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAnswerSource {
    /// The host's model tier, through the shared decision ladder.
    Model,
    /// The deterministic rule tier.
    Rule,
    /// A settled amendment cause, answered without asking a judge.
    SettledCause,
    /// No judge was asked: the amendment's cause was unsettled.
    NotJudged,
}

/// One region's answer as the judge gave it, before any floor or lane rule
/// held it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RawAnswer {
    /// The label it chose, as its wire string; `None` when it chose none.
    pub label: Option<String>,
    /// Its probability for that label; `None` when it gave none.
    pub confidence: Option<f64>,
}

/// One held-out case as the judge answered it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditCase {
    /// The fixture's opaque case id.
    pub case_id: String,
    /// The known answer's wire string; `None` when abstaining is the honest
    /// answer.
    pub expected: Option<String>,
    pub source: AuditAnswerSource,
    /// One per region, in hunk order; empty when no judge was asked.
    pub answers: Vec<RawAnswer>,
    /// `model@version` of the one provider that gave every answer; `None`
    /// when they differ or none was asked.
    pub revision: Option<String>,
}

impl AuditCase {
    pub(crate) fn new(
        case_id: &str,
        expected: Option<AttributionVerdict>,
        trace: JudgeTrace,
    ) -> Self {
        Self {
            case_id: case_id.to_owned(),
            expected: expected.map(|verdict| verdict.as_str().to_owned()),
            source: trace.source,
            answers: trace.answers,
            revision: trace.revision,
        }
    }
}

/// The floor one batch argued for, or why it argued for none.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FloorFit {
    /// The floor that scored best on the batch's judged cases: `passed` of
    /// `judged` answered right under it.
    Target {
        floor: f32,
        passed: u64,
        judged: u64,
    },
    /// No case a model answered under a known revision.
    NoJudgedCase,
    /// Every candidate floor scored the same, so the batch says nothing about
    /// where the floor sits.
    Uninformative,
}

/// One audit run, kept whole beside its aggregate report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditBatch {
    /// The `attribution_unclear_floor` the run judged under.
    pub floor_used: f32,
    pub cases: Vec<AuditCase>,
    pub fitter_version: u32,
    pub fit: FloorFit,
}

impl AuditBatch {
    /// `cases`, judged in `lane` with `floor_used` in force, and the floor
    /// they argue for.
    pub(crate) fn fitted(lane: AttributionLane, floor_used: f32, cases: Vec<AuditCase>) -> Self {
        let fit = fit_unclear_floor(lane, &cases, floor_used);
        Self {
            floor_used,
            cases,
            fitter_version: UNCLEAR_FLOOR_FITTER_VERSION,
            fit,
        }
    }
}

/// One judged case, parsed: each region's label and confidence, or `None`
/// when the outcome abstained before any label stood; and its known answer,
/// with a known `unclear` read as no attribution.
struct Judged {
    regions: Option<Vec<(AttributionVerdict, f32)>>,
    expected: Option<AttributionVerdict>,
}

/// The floor `cases` argue for, judged in `lane` with `floor_used` in force.
///
/// Only a model's answers under a known revision count: the rule tier and a
/// settled cause answer certain, so no floor moves them. Each candidate floor
/// replays every judged case through the production gate ([`held_reason`]):
/// a held, unparsed or missing answer is no attribution, and a case scores
/// when that matches its known answer. The candidates are the catalog's
/// bounds, the floor in force, and each recorded confidence with the next
/// f32 above it (a confidence equal to the floor stands, so only a floor
/// above it holds it). The best score wins; a tie goes to the floor nearest
/// the one in force, then the lower.
fn fit_unclear_floor(lane: AttributionLane, cases: &[AuditCase], floor_used: f32) -> FloorFit {
    let judged: Vec<Judged> = cases
        .iter()
        .filter(|case| case.source == AuditAnswerSource::Model && case.revision.is_some())
        .map(|case| Judged {
            regions: case
                .answers
                .iter()
                .map(|answer| {
                    let verdict = AttributionVerdict::parse(answer.label.as_deref()?)?;
                    Some((verdict, narrow(answer.confidence?)))
                })
                .collect(),
            expected: case
                .expected
                .as_deref()
                .and_then(AttributionVerdict::parse)
                .filter(|verdict| *verdict != AttributionVerdict::Unclear),
        })
        .collect();
    if judged.is_empty() {
        return FloorFit::NoJudgedCase;
    }
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the catalog's unit-interval bounds narrowed to the judge's f32 floor"
    )]
    let (min, max) = (
        ATTRIBUTION_UNCLEAR_FLOOR.min as f32,
        ATTRIBUTION_UNCLEAR_FLOOR.max as f32,
    );
    let mut candidates = vec![min, max, floor_used.clamp(min, max)];
    for (_, confidence) in judged.iter().flat_map(|case| case.regions.iter().flatten()) {
        if confidence.is_finite() {
            let confidence = confidence.clamp(min, max);
            candidates.push(confidence);
            candidates.push(confidence.next_up());
        }
    }
    candidates.retain(|floor| (min..=max).contains(floor));
    candidates.sort_by(f32::total_cmp);
    candidates.dedup();
    let scored: Vec<(f32, u64)> = candidates
        .into_iter()
        .map(|floor| {
            let passed = judged
                .iter()
                .filter(|case| replay(lane, case, floor) == case.expected)
                .count() as u64;
            (floor, passed)
        })
        .collect();
    let best = scored.iter().map(|(_, passed)| *passed).max().unwrap_or(0);
    if scored.iter().all(|(_, passed)| *passed == best) {
        return FloorFit::Uninformative;
    }
    let Some(floor) = scored
        .iter()
        .filter(|(_, passed)| *passed == best)
        .map(|(floor, _)| *floor)
        .min_by(|left, right| {
            (left - floor_used)
                .abs()
                .total_cmp(&(right - floor_used).abs())
                .then(left.total_cmp(right))
        })
    else {
        return FloorFit::Uninformative;
    };
    FloorFit::Target {
        floor,
        passed: best,
        judged: judged.len() as u64,
    }
}

/// The one label `case` attributes under `floor`, as the split would file
/// it: `None` when it abstained, when the regions disagree, or when the gate
/// holds them `unclear`.
fn replay(lane: AttributionLane, case: &Judged, floor: f32) -> Option<AttributionVerdict> {
    let mut labels = case.regions.as_ref()?.iter().map(|(verdict, confidence)| {
        if held_reason(lane, *verdict, *confidence, floor).is_some() {
            AttributionVerdict::Unclear
        } else {
            *verdict
        }
    });
    let first = labels.next()?;
    if !labels.all(|label| label == first) {
        return None;
    }
    (first != AttributionVerdict::Unclear).then_some(first)
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "a unit-interval probability narrowed to the judge's f32 confidence"
)]
fn narrow(probability: f64) -> f32 {
    probability as f32
}

/// Records `fit`'s target, when it has one, as one held-out check on the
/// vault-wide `attribution_unclear_floor`, filed under `receipt` (the audit
/// row the batch lives in), inside that row's own transaction `wtxn`.
///
/// # Errors
///
/// The global subject's derivation and [`record_setting_check_in_txn`].
pub(crate) fn record_unclear_floor_fit_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    fit: &FloorFit,
    receipt: &str,
    at: u64,
    now: u64,
) -> Result<()> {
    let FloorFit::Target { floor, .. } = fit else {
        return Ok(());
    };
    let check = SettingCheck {
        subject: global_setting_subject(ATTRIBUTION_UNCLEAR_FLOOR.key)?,
        key: ATTRIBUTION_UNCLEAR_FLOOR.key.to_owned(),
        // The vault-wide fit, whichever tree version the audit ran under.
        type_ref: TypeRef::root(0),
        observed: f64::from(*floor),
        receipt: receipt.to_owned(),
        at,
        anchor: Anchor::HeldOut,
    };
    record_setting_check_in_txn(vault, wtxn, &check, now)?;
    Ok(())
}
