//! JSONL terminal retrieval outcome ingest for the explicit eval command.

use std::collections::BTreeMap;
use std::io::BufRead;

use oneiron::store::RetrievalEndOutcome;
use oneiron::{RetrievalRunId, Vault};

use super::{EndOutcomeRow, EvalError, EvalResult};

const METADATA_EVALUATOR_KEY: &str = "evaluator";
const METADATA_SOURCE_KEY: &str = "source";
const ID_LEN: usize = 16;

/// Applies terminal outcome rows in file order, stopping at the first rejected row.
///
/// Rows already applied stay applied: they are honest, retryable state — the
/// outcome write is idempotent per run id and key — and the returned error
/// names the failing row plus how many rows preceded it.
pub(super) fn ingest_outcomes(
    vault: &Vault,
    reader: impl BufRead,
    default_key: Option<&str>,
) -> EvalResult<usize> {
    let mut applied = 0_usize;
    for (index, line) in reader.lines().enumerate() {
        match apply_end_outcome_line(vault, line, default_key) {
            Ok(true) => applied += 1,
            Ok(false) => {}
            Err(reason) => {
                return Err(EvalError::RewardRow {
                    row: index + 1,
                    applied,
                    reason,
                });
            }
        }
    }
    Ok(applied)
}

/// Applies one JSONL line, reporting `false` for a blank separator line.
fn apply_end_outcome_line(
    vault: &Vault,
    line: std::io::Result<String>,
    default_key: Option<&str>,
) -> Result<bool, String> {
    let line = line.map_err(|error| error.to_string())?;
    if line.trim().is_empty() {
        return Ok(false);
    }
    let row: EndOutcomeRow = serde_json::from_str(&line)
        .map_err(|error| format!("invalid terminal outcome row: {error}"))?;
    let outcome = outcome_from_row(&row, default_key)?;
    vault
        .record_retrieval_end_outcome(outcome)
        .map_err(|error| error.to_string())?;
    Ok(true)
}

/// Vets evaluator provenance and decodes typed attribution without inventing
/// an approval from a legacy scalar. The engine checks the run/turn/memory link.
fn outcome_from_row(
    row: &EndOutcomeRow,
    default_key: Option<&str>,
) -> Result<RetrievalEndOutcome, String> {
    require_provenance(&row.metadata, METADATA_EVALUATOR_KEY)?;
    require_provenance(&row.metadata, METADATA_SOURCE_KEY)?;
    let key = resolve_outcome_key(row.key.as_deref(), default_key)?;
    Ok(RetrievalEndOutcome {
        run_id: parse_run_id(&row.run_id)?,
        key,
        turn_id: parse_id_bytes(&row.turn_id, "turn_id")?,
        activated_memory_id: parse_id_bytes(&row.activated_memory_id, "activated_memory_id")?,
        gate_score: row.gate_score,
        confirmed_fact_hit: row.confirmed_fact_hit,
        latency_scale_us: row.latency_scale_us,
        cost_weight: row.cost_weight,
        metadata: row.metadata.clone(),
    })
}

fn require_provenance(metadata: &BTreeMap<String, String>, field: &str) -> Result<(), String> {
    match metadata.get(field) {
        Some(value) if !value.trim().is_empty() => Ok(()),
        _ => Err(format!("metadata.{field} must be a non-empty string")),
    }
}

/// A per-row `key` overrides `--key`; exactly one key source must resolve.
fn resolve_outcome_key(row_key: Option<&str>, default_key: Option<&str>) -> Result<String, String> {
    match row_key.or(default_key) {
        Some(key) if !key.trim().is_empty() => Ok(key.to_owned()),
        Some(_) => Err("outcome key must not be empty".to_owned()),
        None => Err("no outcome key: supply a row `key` or --key".to_owned()),
    }
}

/// `RetrievalRunId` publishes no byte constructor, so its derived
/// `Deserialize` is the supported route from a hex run id back to the id.
fn parse_run_id(value: &str) -> Result<RetrievalRunId, String> {
    let bytes = parse_id_bytes(value, "run_id")?;
    serde_json::from_value(serde_json::json!({ "bytes": bytes }))
        .map_err(|error| format!("run_id could not be decoded: {error}"))
}

fn parse_id_bytes(value: &str, field: &str) -> Result<[u8; ID_LEN], String> {
    let raw = value.as_bytes();
    let expected = ID_LEN * 2;
    if raw.len() != expected {
        return Err(format!("{field} must be {expected} hex characters"));
    }

    let mut bytes = [0_u8; ID_LEN];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let high = decode_hex_nibble(raw[index * 2], field)?;
        let low = decode_hex_nibble(raw[index * 2 + 1], field)?;
        *byte = (high << 4) | low;
    }
    Ok(bytes)
}

fn decode_hex_nibble(byte: u8, field: &str) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!("{field} contains a non-hex character")),
    }
}
