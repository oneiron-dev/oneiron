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
