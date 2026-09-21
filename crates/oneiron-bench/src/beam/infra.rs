//! Vector-database cost framing. These rows are never inputs to accuracy scoring.
use super::{BeamError, BeamResult};
use serde::{Deserialize, Serialize};
use std::path::Path;
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InfraTriple {
    pub recall_at_k: f64,
    pub latency_us: u64,
    pub cost_usd: f64,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InfraRow {
    pub system: String,
    pub card_id: String,
    pub source: String,
    pub measurement: Option<InfraTriple>,
    pub caveat: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InfraInput {
    measurement_receipt: String,
    measured: InfraTriple,
    comparators: Vec<InfraRow>,
}
#[derive(Debug, Serialize)]
pub(super) struct InfraReport {
    pub purpose: &'static str,
    pub measurement_receipt: String,
    pub measured: InfraTriple,
    pub comparators: Vec<InfraRow>,
}
pub(super) fn run(path: &Path) -> BeamResult<InfraReport> {
    let input: InfraInput = serde_json::from_slice(&std::fs::read(path)?)?;
    if input.measurement_receipt.is_empty()
        || input
            .comparators
            .iter()
            .any(|row| row.card_id.is_empty() || row.source.is_empty() || row.system.is_empty())
    {
        return Err(invalid());
    }
    validate(&input.measured)?;
    for row in &input.comparators {
        if row.measurement.is_none() && row.caveat.trim().is_empty() {
            return Err(invalid());
        }
        if let Some(measurement) = &row.measurement {
            validate(measurement)?;
        }
    }
    Ok(InfraReport {
        purpose: "cost-framing-only",
        measurement_receipt: input.measurement_receipt,
        measured: input.measured,
        comparators: input.comparators,
    })
}
fn validate(value: &InfraTriple) -> BeamResult<()> {
    if value.recall_at_k.is_finite()
        && (0.0..=1.0).contains(&value.recall_at_k)
        && value.cost_usd.is_finite()
        && value.cost_usd >= 0.0
    {
        Ok(())
    } else {
        Err(invalid())
    }
}
fn invalid() -> BeamError {
    BeamError::Comparability {
        reason: "infra rows require carded provenance and finite measured values".into(),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn infra_framing_retains_unknown_vendor_measurements_without_inventing_scores() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("infra.json");
        std::fs::write(&path,serde_json::json!({"measurement_receipt":"fixture://real-run/1","measured":{"recall_at_k":0.95,"latency_us":1200,"cost_usd":0.0001},"comparators":[{"system":"Qdrant","card_id":"qdrant-infra-v1","source":"https://qdrant.tech/benchmarks/","measurement":null,"caveat":"no matched run published in the evidence pack"}]}).to_string()).unwrap();
        let report = run(&path).unwrap();
        assert_eq!(report.purpose, "cost-framing-only");
        assert!(report.comparators[0].measurement.is_none());
        assert_eq!(report.measured.recall_at_k, 0.95);
    }
    #[test]
    fn accuracy_scoring_is_independent_of_infra_rows() {
        use crate::beam::{
            nuggets::{NuggetJudgment, WedgeBucket},
            scorer::FixedBeamScorer,
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("infra.json");
        let judgments = [NuggetJudgment {
            ability: "updating".into(),
            wedge_bucket: WedgeBucket::KnowledgeUpdate,
            value: 0.5,
        }];
        let baseline = FixedBeamScorer.score_nuggets(&judgments).unwrap();
        for (recall, latency, cost) in [(0.0, 1, 0.0), (1.0, u64::MAX, 1_000_000.0)] {
            std::fs::write(
                &path,
                serde_json::json!({
                    "measurement_receipt": "fixture://infra-isolation",
                    "measured": { "recall_at_k": recall, "latency_us": latency, "cost_usd": cost },
                    "comparators": [],
                })
                .to_string(),
            )
            .unwrap();
            let infra = run(&path).unwrap();
            assert!(
                serde_json::from_value::<NuggetJudgment>(
                    serde_json::to_value(&infra.measured).unwrap()
                )
                .is_err()
            );
            assert_eq!(FixedBeamScorer.score_nuggets(&judgments).unwrap(), baseline);
        }
        assert_eq!(baseline.overall_score, Some(0.0));
        assert_eq!(baseline.beam.unwrap().aggregate.fixed_float_clamped, 0.5);
    }
}
