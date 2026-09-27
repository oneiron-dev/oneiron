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
    // An explicit list (including []) overrides the built-in v1 cards.
    comparators: Option<Vec<InfraRow>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InfraCardFile {
    schema: String,
    purpose: String,
    rows: Vec<InfraRow>,
}
pub(super) fn carded_rows() -> BeamResult<Vec<InfraRow>> {
    let file: InfraCardFile =
        serde_json::from_str(include_str!("../../fixtures/vector_db_infra.v1.json"))?;
    if file.schema != "vector-db-infra-v1" || file.purpose != "cost-framing-only" {
        return Err(invalid());
    }
    Ok(file.rows)
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
    let comparators = match input.comparators {
        Some(rows) => rows,
        None => carded_rows()?,
    };
    if input.measurement_receipt.is_empty()
        || comparators
            .iter()
            .any(|row| row.card_id.is_empty() || row.source.is_empty() || row.system.is_empty())
    {
        return Err(invalid());
    }
    validate(&input.measured)?;
    for row in &comparators {
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
        comparators,
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
    fn published_v1_cards_appear_beside_a_receipted_measurement() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("infra.json");
        // Omitting comparators selects the shipped, source-carded v1 rows.
        std::fs::write(
            &path,
            serde_json::json!({
                "measurement_receipt": "fixture://measured-run/1",
                "measured": { "recall_at_k": 0.9, "latency_us": 1200, "cost_usd": 0.0001 }
            })
            .to_string(),
        )
        .unwrap();
        let report = run(&path).unwrap();
        assert_eq!(report.purpose, "cost-framing-only");
        assert_eq!(report.measurement_receipt, "fixture://measured-run/1");
        assert_eq!(report.measured.recall_at_k, 0.9);
        assert_eq!(report.comparators.len(), 3);
        let zilliz = &report.comparators[0];
        assert_eq!(zilliz.system, "Zilliz Cloud Capacity 12CU");
        assert_eq!(zilliz.source, "https://zilliz.com/vdbbench-leaderboard-v2");
        let triple = zilliz.measurement.as_ref().unwrap();
        assert_eq!(triple.recall_at_k, 0.9723);
        assert_eq!(triple.latency_us, 299_316);
        assert!((triple.cost_usd - 2.976 / (376.007 * 3600.0)).abs() < 1e-12);
        assert!(zilliz.caveat.contains("modeled"));
        assert!(zilliz.caveat.contains("not the Oneiron corpus"));
        assert!(
            report
                .comparators
                .iter()
                .all(|row| row.measurement.is_some())
        );
        let citations = crate::beam::citations::corpus().unwrap();
        assert_eq!(citations.infra_cost_framing.len(), 3);
        assert!(citations.infra_status.contains("Cost-framing-only"));
        // Accuracy may cite a published BEAM card, but never an infra card.
        assert!(citations.main_table.iter().all(|row| {
            report
                .comparators
                .iter()
                .all(|infra| row.evidence["card_id"] != infra.card_id)
        }));
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
                })
                .to_string(),
            )
            .unwrap();
            let infra = run(&path).unwrap();
            assert_eq!(infra.comparators.len(), 3);
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
