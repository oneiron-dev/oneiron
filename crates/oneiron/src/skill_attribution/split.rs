//! The one split path both lanes judge through (ARCH-0056 §5): per-hunk
//! answers in, a label + share vector out, with the lane's labels and the
//! `attribution_unclear_floor` setting applied by the engine.

use crate::Vault;
use crate::error::{Error, Result};
use crate::learning_setting::{ATTRIBUTION_UNCLEAR_FLOOR, setting_value};

use super::judge::AttributionJudge;
use super::types::{
    AttributionLane, AttributionShare, AttributionSplit, AttributionVerdict, HunkVerdict,
    JudgeRequest, UnclearNote, UnclearReason,
};

/// Longest judge note one unclear hunk keeps, in bytes. A note is a short
/// reason for the Dreamer to cluster, not a transcript.
const MAX_NOTE_BYTES: usize = 1024;

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

/// Asks `judge` about `request` and turns its answers into a split, or `None`
/// when the judge abstains.
///
/// `masses` is each hunk's edit mass, aligned with `request.hunks`; an outcome
/// with no edit passes none and is one region.
///
/// # Errors
///
/// Whatever the judge returns, and [`Error::InvalidClaimBody`] when it answers
/// a different number of hunks than it was shown, or leaves a hunk `unclear`
/// without a note.
pub(crate) fn classify_split(
    judge: &dyn AttributionJudge,
    request: &JudgeRequest<'_>,
    masses: &[f64],
) -> Result<Option<AttributionSplit>> {
    if masses.len() != request.hunks.len() {
        return Err(Error::InvariantViolation("one edit mass per changed hunk"));
    }
    let Some(answers) = judge.judge_hunks(request)? else {
        return Ok(None);
    };
    split_from_answers(request.lane, masses, answers, request.floor).map(Some)
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
    for (weight, answer) in weights.into_iter().zip(answers) {
        if weight <= 0.0 {
            continue;
        }
        // A confidence that is not a number is no confidence: it holds even
        // under a floor the owner pinned at zero.
        let measured = answer.confidence.is_finite();
        let confidence = if measured {
            answer.confidence.clamp(0.0, 1.0)
        } else {
            0.0
        };
        let note = bounded_note(answer.note);
        let reason = if answer.verdict == AttributionVerdict::Unclear {
            Some(UnclearReason::NoLabelFits)
        } else if !answer.verdict.valid_in(lane) {
            Some(UnclearReason::OutsideLane)
        } else if !measured || confidence < floor {
            Some(UnclearReason::BelowFloor)
        } else {
            None
        };
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
    Ok(AttributionSplit { shares, unclear })
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "a unit-interval share narrowed to the stored f32"
)]
fn narrow(share: f64) -> f32 {
    share.clamp(0.0, 1.0) as f32
}

/// The judge's note, trimmed and cut at a character boundary within
/// [`MAX_NOTE_BYTES`]; an empty note is no note.
fn bounded_note(note: Option<String>) -> Option<String> {
    let note = note?;
    let trimmed = note.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut end = trimmed.len().min(MAX_NOTE_BYTES);
    while !trimmed.is_char_boundary(end) {
        end -= 1;
    }
    Some(trimmed[..end].to_owned())
}
