//! Receipt-only DecoEvo measurements, per-axis world-outcome calibration, and
//! the judge against the human picks in the skill's anchor.
use super::*;
use serde::{Deserialize, Serialize};

use crate::skill_optimize::JudgeLabel;

/// A response-only preference frozen before either rubric or scalar score is
/// shown to the judging callbacks. The host selects a near-tie rollout pair
/// from the held-out questions; this reference identifies that pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlindPreference {
    pub pair_ref: String,
    pub preferred: PreferredResponse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreferredResponse {
    First,
    Second,
}

pub(super) fn validate_blind(preferences: &[BlindPreference]) -> Result<()> {
    if preferences.is_empty() || preferences.len() > 32 {
        return Err(invalid(
            "contrastive audit requires 1..=32 frozen near-tie preferences",
        ));
    }
    let mut seen = BTreeSet::new();
    for preference in preferences {
        if preference.pair_ref.is_empty()
            || preference.pair_ref.len() > 256
            || !seen.insert(&preference.pair_ref)
        {
            return Err(invalid(
                "contrastive pair references must be distinct and bounded",
            ));
        }
    }
    Ok(())
}

/// A pair measured on the same held-out basis. Neither number votes at the scalar gate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditPair {
    pub before: f32,
    pub after: f32,
}

/// Judge agreement with the observed outcome on an axis with labels.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldAxisScore {
    pub before: f32,
    pub after: f32,
    pub labelled_receipts: u64,
}

/// The judge against the human picks in the skill's anchor (ARCH-0053: the
/// anchor grows through settled outcomes and human picks). A pick between the
/// judge's answer and another's scores it; a pick between two answers of one
/// judge, a retest flip, or of two other judges is counted but scores none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorLabelScore {
    /// The judge that answers now; `None` before a swap pass named one.
    pub judge: Option<String>,
    pub labels: u64,
    /// Picks between this judge's answer and another judge's.
    pub scored: u64,
    /// Of those, the picks that chose this judge's answer.
    pub agreed: u64,
    /// Hash of each label's ask id and chosen option, in anchor order.
    pub digest: String,
}

/// Score `judge` against `labels`, the skill's anchor.
pub(super) fn anchor_score(labels: &[JudgeLabel], judge: Option<&str>) -> AnchorLabelScore {
    let mut hash = Sha256::new();
    hash.update(b"skill_optimize:anchor_labels:v1\0");
    hash.update(
        u64::try_from(labels.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    let (mut scored, mut agreed) = (0_u64, 0_u64);
    for label in labels {
        hash.update(label.ask.id);
        hash.update(
            u64::try_from(label.chosen.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        hash.update(label.chosen.as_bytes());
        let Some(judge) = judge else {
            continue;
        };
        let by =
            |option: &str| crate::skill_optimize::judge_swap::label_judge(option) == Some(judge);
        let (own, other) = match (
            by(label.ask.option_a.as_str()),
            by(label.ask.option_b.as_str()),
        ) {
            (true, false) => (&label.ask.option_a, &label.ask.option_b),
            (false, true) => (&label.ask.option_b, &label.ask.option_a),
            _ => continue,
        };
        if crate::skill_optimize::judge_swap::label_judge(other).is_none() {
            continue;
        }
        scored += 1;
        agreed += u64::from(label.chosen == *own);
    }
    AnchorLabelScore {
        judge: judge.map(str::to_owned),
        labels: u64::try_from(labels.len()).unwrap_or(u64::MAX),
        scored,
        agreed,
        digest: bytes_to_hex_lower(&hash.finalize()),
    }
}

/// Measurements made outside the write transaction, sealed with the scored basis.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JudgeMeasurements {
    pub structural: AuditPair,
    pub contrastive: AuditPair,
    /// Response-only preferences fixed before scoring either rubric.
    pub blind_preferences: Vec<BlindPreference>,
    pub world_axes: BTreeMap<String, WorldAxisScore>,
    /// Hash of receipt ids AND their observed labels in the scored snapshot.
    pub world_labels_digest: String,
    /// The judge against the human picks in the skill's anchor, read before scoring.
    pub anchor: AnchorLabelScore,
}

/// One held-out replay as the honesty audit reads it: the run's task inputs and
/// rollout, and every objective the run took on. Each objective is one typed
/// hidden-flaw question on the decision path; the host only says what was taken on.
#[derive(Debug, Clone, PartialEq)]
pub struct HonestyReplay {
    pub receipt: String,
    pub state: serde_json::Value,
    pub objectives: Vec<String>,
}

/// A complete, independently checked held-out replay. Counts come from the
/// decided hidden-flaw findings, not from the executor's self-assessment. Every
/// objective is checked, so held-out honesty measurements have sampling probability one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HonestyReplayObservation {
    pub receipt: String,
    pub checked_objectives: u32,
    pub hidden_flaws: u32,
}

/// Higher is better. Both arms must check the same objectives, so an edit
/// cannot dilute its hidden flaws by adding more claimed objectives. Only
/// independently checked findings, not a confession, move this floor.
pub(super) fn measure_honesty(
    scorer: &dyn HeldOutReplayNotes,
    before: &HeldOutReplayCase<'_>,
    after: &HeldOutReplayCase<'_>,
) -> Result<AuditPair> {
    let old = scorer.replay_honesty(before)?;
    let new = scorer.replay_honesty(after)?;
    if before.held_out_receipts.is_empty()
        || before.held_out_receipts != after.held_out_receipts
        || old.len() != before.held_out_receipts.len()
        || new.len() != old.len()
    {
        return Err(invalid(
            "honesty replay must check the same held-out receipts",
        ));
    }
    let mut checked = 0_u64;
    let mut hidden = [0_u64; 2];
    for ((old, new), receipt) in old.iter().zip(&new).zip(before.held_out_receipts) {
        if old.receipt != *receipt
            || new.receipt != *receipt
            || old.checked_objectives == 0
            || old.checked_objectives != new.checked_objectives
            || old.hidden_flaws > old.checked_objectives
            || new.hidden_flaws > new.checked_objectives
        {
            return Err(invalid(
                "honesty replay findings do not match the held-out basis",
            ));
        }
        checked = checked
            .checked_add(u64::from(old.checked_objectives))
            .ok_or(invalid("honesty replay objective count overflow"))?;
        hidden[0] = hidden[0]
            .checked_add(u64::from(old.hidden_flaws))
            .ok_or(invalid("honesty replay finding count overflow"))?;
        hidden[1] = hidden[1]
            .checked_add(u64::from(new.hidden_flaws))
            .ok_or(invalid("honesty replay finding count overflow"))?;
    }
    Ok(AuditPair {
        before: validate_score((1.0 - hidden[0] as f64 / checked as f64) as f32)?,
        after: validate_score((1.0 - hidden[1] as f64 / checked as f64) as f32)?,
    })
}

fn checked(score: f32) -> Result<f32> {
    validate_score(score)
}

/// Run both independent audits, then compare the judge's predictions to labels
/// from the durable outcome ledger; `anchor` carries its score against the
/// skill's human picks. No audit result is passed to the scalar scorer, and no
/// audit result changes admission.
pub(super) fn measure(
    scorer: &dyn HeldOutReplayNotes,
    before: &HeldOutReplayCase<'_>,
    after: &HeldOutReplayCase<'_>,
    outcomes: &[(String, bool)],
    blind: &[BlindPreference],
    anchor: AnchorLabelScore,
) -> Result<JudgeMeasurements> {
    validate_blind(blind)?;
    // Coverage sees only the task identity and instructions: no responses,
    // outcome labels, or aggregate score. The contrastive host must freeze its
    // response-only preference before inspecting the rubric (instructions).
    let structural = AuditPair {
        before: checked(scorer.structural_audit(before.skill_id, before.instructions)?)?,
        after: checked(scorer.structural_audit(after.skill_id, after.instructions)?)?,
    };
    let contrastive = AuditPair {
        before: checked(scorer.contrastive_audit(before, blind)?)?,
        after: checked(scorer.contrastive_audit(after, blind)?)?,
    };
    let predictions_before = scorer.predict_task_success(before)?;
    let predictions_after = scorer.predict_task_success(after)?;
    if predictions_before.len() != outcomes.len() || predictions_after.len() != outcomes.len() {
        return Err(invalid(
            "judge world predictions must cover every labelled held-out receipt",
        ));
    }
    let mut sum_before = 0.0_f64;
    let mut sum_after = 0.0_f64;
    for (sum_index, ((receipt, won), (pred_before, pred_after))) in outcomes
        .iter()
        .zip(predictions_before.into_iter().zip(predictions_after))
        .enumerate()
    {
        // The snapshot's order is the scorer's held-out order, not the ledger's
        // key order. A missing or relabelled identity must not grade another row.
        if before.held_out_receipts.get(sum_index).map(String::as_str) != Some(receipt) {
            return Err(invalid("world outcome is outside the held-out basis"));
        }
        let truth = if *won { 1.0 } else { 0.0 };
        sum_before += f64::from(1.0 - (checked(pred_before)? - truth).abs());
        sum_after += f64::from(1.0 - (checked(pred_after)? - truth).abs());
    }
    let count = outcomes.len();
    if count == 0 {
        return Err(invalid("judge measurement has no world outcomes"));
    }
    #[expect(
        clippy::cast_precision_loss,
        reason = "a receipt count cannot approach the f64 precision limit in a vault"
    )]
    let n = count as f64;
    let mut world_axes = BTreeMap::new();
    world_axes.insert(
        "task_success".to_owned(),
        WorldAxisScore {
            before: (sum_before / n) as f32,
            after: (sum_after / n) as f32,
            labelled_receipts: u64::try_from(count).unwrap_or(u64::MAX),
        },
    );
    Ok(JudgeMeasurements {
        structural,
        contrastive,
        blind_preferences: blind.to_vec(),
        world_axes,
        world_labels_digest: world_labels_digest(outcomes),
        anchor,
    })
}

pub(super) fn world_labels_digest(outcomes: &[(String, bool)]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"skill_optimize:world_labels:v1\0");
    hash.update(
        u64::try_from(outcomes.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for (receipt, won) in outcomes {
        hash.update(
            u64::try_from(receipt.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        hash.update(receipt.as_bytes());
        hash.update([u8::from(*won)]);
    }
    bytes_to_hex_lower(&hash.finalize())
}

pub(super) fn validate_measurements(
    measurements: &JudgeMeasurements,
    held_out_count: u64,
) -> Result<()> {
    if measurements.world_labels_digest.len() != 64
        || !measurements
            .world_labels_digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(invalid("judge world label digest is malformed"));
    }
    validate_blind(&measurements.blind_preferences)?;
    let anchor = &measurements.anchor;
    if anchor.agreed > anchor.scored
        || anchor.scored > anchor.labels
        || (anchor.judge.is_none() && anchor.scored != 0)
        || anchor.digest.len() != 64
        || !anchor.digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(invalid("judge anchor score is malformed"));
    }
    for pair in [&measurements.structural, &measurements.contrastive] {
        checked(pair.before)?;
        checked(pair.after)?;
    }
    // This schema has exactly one world-labelled axis. A row must not claim
    // an arbitrary axis or an invented number of labels beside a valid basis.
    let Some(axis) = measurements.world_axes.get("task_success") else {
        return Err(invalid("judge measurement is missing task_success"));
    };
    if measurements.world_axes.len() != 1
        || held_out_count == 0
        || axis.labelled_receipts != held_out_count
    {
        return Err(invalid(
            "judge world axis does not match the held-out basis",
        ));
    }
    checked(axis.before)?;
    checked(axis.after)?;
    Ok(())
}
