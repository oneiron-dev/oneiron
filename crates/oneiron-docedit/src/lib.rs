//! Native document editing organ crate: the retained OPC substrate and
//! native Word revisions over a pinned, Apache-2.0-selected stemma fork.
//!
//! The wrapper owns no global session or handle store. Its document value
//! facade addresses stable block IDs and staleness guards; the writer applies
//! a typed transaction and refuses bytes that fail the Word package linker.
//! `PROVENANCE.md` records the fork, licenses and local changes.

pub mod retained_opc;

pub use stemma::api::{Document, validate};
pub use stemma::docx::ArchiveLimits;
use stemma::edit::{EditTransaction, MaterializationMode};
pub use stemma::edit_v4::parse_transaction;
pub use stemma::{ExportMode, ExportOptions, ValidatorLevel};

/// A native revision failed before it could become a valid Word package.
#[derive(Debug, thiserror::Error)]
pub enum DoceditError {
    #[error("invalid DOCX transaction: {0}")]
    InvalidTransaction(String),
    #[error(transparent)]
    Document(#[from] stemma::runtime::RuntimeError),
}

/// Parse the native writer's transaction grammar and refuse direct mode before
/// any edit can resolve an earlier author's pending redlines.
fn parse_native_revision(transaction_json: &str) -> Result<EditTransaction, DoceditError> {
    let transaction = parse_transaction(transaction_json)
        .map_err(|error| DoceditError::InvalidTransaction(error.to_string()))?
        .into_edit_transaction()
        .map_err(|error| DoceditError::InvalidTransaction(error.to_string()))?;
    if transaction.materialization_mode != MaterializationMode::TrackedChange {
        return Err(DoceditError::InvalidTransaction(
            "native revision transactions must use tracked_change materialization".to_owned(),
        ));
    }
    Ok(transaction)
}

/// Validate the same schema, adapter and tracked-only invariant used by
/// [`revise`]. Settlement calls this because proposals are caller-constructible:
/// a well-formed DOCX cannot prove its manifest describes a native revision.
pub fn validate_revision_transaction(transaction_json: &str) -> Result<(), DoceditError> {
    parse_native_revision(transaction_json).map(|_| ())
}

/// Return the validated tracked transaction with the actual revision date
/// pinned. Upstream fills an absent date from the clock while adapting JSON;
/// recording that date makes a later settlement replay the exact same edit.
pub fn prepare_revision_transaction(transaction_json: &str) -> Result<String, DoceditError> {
    let transaction = parse_native_revision(transaction_json)?;
    let date = transaction.revision.date.ok_or_else(|| {
        DoceditError::InvalidTransaction("tracked revision has no date".to_owned())
    })?;
    let mut value: serde_json::Value = serde_json::from_str(transaction_json)
        .map_err(|error| DoceditError::InvalidTransaction(error.to_string()))?;
    let revision = value
        .get_mut("revision")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| DoceditError::InvalidTransaction("missing revision".to_owned()))?;
    revision.insert("date".to_owned(), serde_json::Value::String(date));
    serde_json::to_string(&value)
        .map_err(|error| DoceditError::InvalidTransaction(error.to_string()))
}

/// Apply one schema-validated, guarded transaction and serialize Word-native
/// revisions. The input bytes are never mutated and no file is written.
/// Stale guards, unknown targets, and broken output fail closed.
pub fn revise(input: &[u8], transaction_json: &str) -> Result<Vec<u8>, DoceditError> {
    revise_with_limits(input, transaction_json, ArchiveLimits::DEFAULT)
}

/// Parse, apply, and export within the caller's effective archive policy.
/// Preflight precedes the fork's other readers and gates every output before
/// it can leave this door. A holder can only narrow the vault's ceiling.
pub fn revise_with_limits(
    input: &[u8],
    transaction_json: &str,
    limits: ArchiveLimits,
) -> Result<Vec<u8>, DoceditError> {
    preflight_with_limits(input, limits)?;
    let transaction = parse_native_revision(transaction_json)?;
    let edited = Document::parse(input)?.apply(&transaction)?;
    let output = edited.serialize(&ExportOptions {
        mode: ExportMode::Redline,
        validator_level: ValidatorLevel::Blocking,
        validator: None,
    })?;
    preflight_with_limits(&output, limits)?;
    Ok(output)
}

/// Re-run the blocking OOXML linker on caller-supplied output at settlement.
/// This is independent of a proposal's own `validation.ok` report field.
pub fn validate_blocking(bytes: &[u8]) -> Result<(), stemma::runtime::RuntimeError> {
    validate_blocking_with_limits(bytes, ArchiveLimits::DEFAULT)
}

/// Budgeted preflight across **all** package entries, before an XML parser or
/// the standalone linker's otherwise-unbounded `read_to_end` is reachable.
pub fn preflight_with_limits(
    bytes: &[u8],
    limits: ArchiveLimits,
) -> Result<(), stemma::runtime::RuntimeError> {
    stemma::docx::DocxArchive::read_with_limits(bytes, limits)
        .map_err(stemma::runtime::map_docx_error)?;
    Ok(())
}

/// The independent OOXML linker still runs, but only on bytes already proven
/// to fit the effective per-part and cumulative archive budgets.
pub fn validate_blocking_with_limits(
    bytes: &[u8],
    limits: ArchiveLimits,
) -> Result<(), stemma::runtime::RuntimeError> {
    preflight_with_limits(bytes, limits)?;
    stemma::runtime::gate_serialized_bytes(bytes, ValidatorLevel::Blocking)
}
