//! Receipt-only DecoEvo measurements and per-axis world-outcome calibration.
use super::*;
use serde::{Deserialize, Serialize};

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
}

fn checked(score: f32) -> Result<f32> {
    validate_score(score)
}

/// Run both independent audits, then compare the judge's predictions to labels
/// from the durable outcome ledger. No audit result is passed to the scalar
/// scorer, and no audit result changes admission.
pub(super) fn measure(
    scorer: &dyn HeldOutReplayScorer,
    before: &HeldOutReplayCase<'_>,
    after: &HeldOutReplayCase<'_>,
    outcomes: &[(String, bool)],
    blind: &[BlindPreference],
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
