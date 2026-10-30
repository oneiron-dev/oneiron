//! The one split path both lanes judge through (ARCH-0056 §5): per-hunk
//! answers in, a label + share vector out, with the lane's labels and the
//! `attribution_unclear_floor` setting applied by the engine.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::limit_ask::EngineLimit;
use crate::learning::TypeRef;
use crate::learning_setting::{
    ATTRIBUTION_UNCLEAR_FLOOR, setting_value, setting_value_in_scope_sourced_in_txn,
};

use super::judge::{Attributed, AttributionDecisions, AttributionRules, JudgeTrace};
use super::types::{
    AttributionLane, AttributionShare, AttributionSplit, AttributionVerdict, HunkVerdict,
    JudgeRequest, UnclearNote, UnclearReason,
};

/// The `attribution_unclear_floor` in force for this vault.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn unclear_floor(vault: &Vault) -> Result<f32> {
    // The catalog bounds the row to 0..=1, so the narrowing is exact enough.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "a unit-interval setting narrowed to the judge's f32 confidence"
    )]
    Ok(setting_value(vault, &ATTRIBUTION_UNCLEAR_FLOOR)? as f32)
}

/// The `attribution_unclear_floor` in force where the outcome on terminal
/// pack receipt `receipt` ran (FIX 2957): at the project and task type that
/// receipt records, beside the rows it stands on, from one snapshot
/// ([`setting_value_in_scope_sourced_in_txn`], FIX 7101). No receipt, or one
/// that records neither, reads the vault's.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn unclear_floor_sourced(
    vault: &Vault,
    receipt: Option<&str>,
) -> Result<(f32, Option<Vec<EntityId>>)> {
    let rtxn = vault.store.env.read_txn()?;
    let (project, type_ref) = match receipt {
        Some(receipt) => outcome_scope_in_txn(vault, &rtxn, receipt)?,
        None => (None, None),
    };
    let (floor, rows) = setting_value_in_scope_sourced_in_txn(
        vault,
        &rtxn,
        &ATTRIBUTION_UNCLEAR_FLOOR,
        project,
        type_ref.as_ref(),
    )?;
    #[expect(
        clippy::cast_possible_truncation,
        reason = "a unit-interval setting narrowed to the judge's f32 confidence"
    )]
    Ok((floor as f32, rows))
}

/// The project and task type terminal pack receipt `receipt` records: its
/// type stamp, else its frozen attribution's type, and that attribution's
/// project. Either is `None` where the receipt records none: unknown, never
/// read off its actor or session.
fn outcome_scope_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    receipt: &str,
) -> Result<(Option<EntityId>, Option<TypeRef>)> {
    let Some(receipt) = crate::receipt::attempt_pack_receipt_in_txn(&vault.store, txn, receipt)?
    else {
        return Ok((None, None));
    };
    let attribution = receipt.pack_attribution_fields().ok();
    let type_ref = receipt
        .task_type_ref()
        .map(|stamp| TypeRef::from(&stamp))
        .or_else(|| attribution.as_ref().map(|fields| fields.type_ref.clone()));
    Ok((attribution.and_then(|fields| fields.project), type_ref))
}

/// Asks about `request` and turns the answers into a split, beside the exact
/// revision that gave them, or `None` when the outcome abstains. With no host
/// decisions the rule tier answers; a host's decisions replace it. Beside it
/// stands the judge's trace: its raw answers before the floor held any, which
/// the held-out audit keeps as its calibration batch (OF-542), and its
/// decisions' receipts, which the attempt lane keeps beside its judgment
/// (FIX 11512).
///
/// `masses` is each hunk's edit mass, aligned with `request.hunks`; an outcome
/// with no edit passes none and is one region.
///
/// # Errors
///
/// Whatever the decision path returns, and [`Error::InvalidClaimBody`] when
/// the answers cover a different number of hunks than were shown, or leave a
/// hunk `unclear` without a note.
pub(crate) fn classify_split_traced(
    decisions: Option<&AttributionDecisions<'_>>,
    request: &JudgeRequest<'_>,
    masses: &[f64],
) -> Result<(Option<(AttributionSplit, Option<String>)>, JudgeTrace)> {
    if masses.len() != request.hunks.len() {
        return Err(Error::InvariantViolation("one edit mass per changed hunk"));
    }
    let (answered, trace) = match decisions {
        Some(decisions) => decisions.answer(request)?,
        None => AttributionRules::answer(request),
    };
    let Some(Attributed { answers, revision }) = answered else {
        return Ok((None, trace));
    };
    let split = split_from_answers(request.lane, masses, answers, request.floor)?;
    Ok((Some((split, revision)), trace))
}

/// A settled cause's split: its one label, certain, on every region.
///
/// # Errors
///
/// [`Error::InvariantViolation`] when `masses` does not align with the hunks.
pub(crate) fn settled_split(
    verdict: AttributionVerdict,
    request: &JudgeRequest<'_>,
    masses: &[f64],
) -> Result<AttributionSplit> {
    if masses.len() != request.hunks.len() {
        return Err(Error::InvariantViolation("one edit mass per changed hunk"));
    }
    let answers = vec![HunkVerdict::certain(verdict); request.regions()];
    split_from_answers(request.lane, masses, answers, request.floor)
}

/// Folds explicitly supplied per-hunk verdicts into a split, through the same
/// lane, floor and note rules a judge's answers meet. The owner settlement
/// door's scripted labels take this path; no share is ever caller-stamped.
///
/// # Errors
///
/// As the split path: a wrong verdict count, or a doubtful verdict without a
/// note.
pub(crate) fn split_from_verdicts(
    lane: AttributionLane,
    masses: &[f64],
    answers: Vec<HunkVerdict>,
    floor: f32,
) -> Result<AttributionSplit> {
    split_from_answers(lane, masses, answers, floor)
}

/// Folds per-hunk answers into one label + share vector.
///
/// Each hunk weighs its share of the edit mass; with no edit, or an edit that
/// measures nothing, the regions weigh alike. A hunk lands `unclear` when the
/// judge said so, held its label below `floor` — or gave no usable
/// confidence at all, whatever the floor — or named a label its lane does
/// not admit.
///
/// The first two are the judge's own doubt, and ARCH-0056 §5 has the judge
/// say why every time: the note is what the Dreamer clusters, so a doubt
/// without one is refused, not filed. A label outside its lane is the
/// engine's rule, not the judge's doubt; it holds with its reason code and the
/// label the judge named.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] when the judge answers a different number of
/// hunks than it was shown, or doubts a hunk without a note.
fn split_from_answers(
    lane: AttributionLane,
    masses: &[f64],
    answers: Vec<HunkVerdict>,
    floor: f32,
) -> Result<AttributionSplit> {
    let regions = masses.len().max(1);
    if answers.len() != regions {
        return Err(Error::InvalidClaimBody(
            "an attribution judge must answer once per changed hunk",
        ));
    }
    let total: f64 = masses.iter().sum();
    let weights: Vec<f64> = if total > 0.0 {
        masses.iter().map(|mass| mass / total).collect()
    } else {
        #[expect(
            clippy::cast_precision_loss,
            reason = "a hunk count far below f64's exact-integer range"
        )]
        let even = 1.0 / regions as f64;
        vec![even; regions]
    };

    let mut by_label = [0.0_f64; AttributionVerdict::ALL.len()];
    let mut unclear = Vec::new();
    let mut hunks = Vec::with_capacity(regions);
    for (weight, answer) in weights.into_iter().zip(answers) {
        if weight <= 0.0 {
            // A region that weighs nothing holds no share; its label stands
            // as answered, held by the same rule.
            hunks.push(
                match held_reason(lane, answer.verdict, answer.confidence, floor) {
                    Some(_) => AttributionVerdict::Unclear,
                    None => answer.verdict,
                },
            );
            continue;
        }
        let confidence = if answer.confidence.is_finite() {
            answer.confidence.clamp(0.0, 1.0)
        } else {
            0.0
        };
        let note = trimmed_note(answer.note);
        let reason = held_reason(lane, answer.verdict, answer.confidence, floor);
        if matches!(
            reason,
            Some(UnclearReason::NoLabelFits | UnclearReason::BelowFloor)
        ) && note.is_none()
        {
            return Err(Error::InvalidClaimBody(
                "an unclear answer must carry a note saying why",
            ));
        }
        let label = if reason.is_some() {
            AttributionVerdict::Unclear
        } else {
            answer.verdict
        };
        let slot = AttributionVerdict::ALL
            .iter()
            .position(|known| *known == label)
            .ok_or(Error::InvariantViolation("every label has a share slot"))?;
        by_label[slot] += weight;
        hunks.push(label);
        if let Some(reason) = reason {
            unclear.push(UnclearNote {
                reason,
                leaning: (answer.verdict != AttributionVerdict::Unclear).then_some(answer.verdict),
                confidence,
                share: narrow(weight),
                note,
            });
        }
    }
    let shares = AttributionVerdict::ALL
        .into_iter()
        .zip(by_label)
        .filter(|(_, share)| *share > 0.0)
        .map(|(verdict, share)| AttributionShare {
            verdict,
            share: narrow(share),
        })
        .collect();
    Ok(AttributionSplit {
        shares,
        unclear,
        hunks,
    })
}

/// Why one answer lands `unclear`, or `None` when its label stands: the judge
/// said so, named a label its lane does not admit, or gave no usable
/// confidence or one below `floor`. Equal to the floor stands.
pub(super) fn held_reason(
    lane: AttributionLane,
    verdict: AttributionVerdict,
    confidence: f32,
    floor: f32,
) -> Option<UnclearReason> {
    if verdict == AttributionVerdict::Unclear {
        Some(UnclearReason::NoLabelFits)
    } else if !verdict.valid_in(lane) {
        Some(UnclearReason::OutsideLane)
    } else if !confidence.is_finite() || confidence.clamp(0.0, 1.0) < floor {
        // A confidence that is not a number is no confidence: it holds even
        // under a floor the owner pinned at zero.
        Some(UnclearReason::BelowFloor)
    } else {
        None
    }
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "a unit-interval share narrowed to the stored f32"
)]
fn narrow(share: f64) -> f32 {
    share.clamp(0.0, 1.0) as f32
}

/// The judge's note, trimmed; an empty note is no note. The note is kept
/// whole: the vault-holding callers measure it (FIX 5465).
fn trimmed_note(note: Option<String>) -> Option<String> {
    let note = note?;
    let trimmed = note.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_owned())
}

/// Measures a split's unclear notes against the engine's text row (OF-520):
/// the longest note kept. The split keeps every note whole; past the row
/// the vault's port asks.
pub(crate) fn measure_split_notes(vault: &Vault, split: &AttributionSplit) {
    let longest = split
        .unclear
        .iter()
        .filter_map(|note| note.note.as_ref())
        .map(String::len)
        .max()
        .unwrap_or(0);
    let _ = vault.measure_limit(EngineLimit::MaintenanceTextBytes, longest as u64);
}
