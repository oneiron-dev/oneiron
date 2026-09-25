//! Dataset valid-time admission. Ingest time cannot substitute for source time.
use super::{BeamResult, report_model::ContractCorpusRecord, util::invalid_run_jsonl};
use std::path::Path;

/// run.jsonl adapters normalize source timestamps to Unix seconds. The
/// redundant occurredAt assertion is optional, but when supplied must match.
pub(super) fn occurred_at(
    item: &ContractCorpusRecord,
    path: &Path,
    line: usize,
) -> BeamResult<u64> {
    let source = item
        .metadata
        .as_ref()
        .and_then(|m| m.get("dataset_timestamp"))
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            invalid_run_jsonl(path, line, "corpus metadata.dataset_timestamp is required")
        })?;
    if let Some(assertion) = item.metadata.as_ref().and_then(|m| m.get("occurredAt"))
        && assertion.as_u64() != Some(source)
    {
        return Err(invalid_run_jsonl(
            path,
            line,
            "occurredAt does not match the dataset timestamp",
        ));
    }
    Ok(source)
}
