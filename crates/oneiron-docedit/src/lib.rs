//! Native Word revisions over a pinned, Apache-2.0-selected stemma fork.
//!
//! The wrapper owns no global session or handle store. Its document value
//! facade addresses stable block IDs and staleness guards; the writer applies
//! a typed transaction and refuses bytes that fail the Word package linker.
//! `PROVENANCE.md` records the fork, licenses and local changes.

pub use stemma::api::{Document, validate};
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

/// Apply one schema-validated, guarded transaction and serialize Word-native
/// revisions. The input bytes are never mutated and no file is written.
/// Stale guards, unknown targets, and broken output fail closed.
pub fn revise(input: &[u8], transaction_json: &str) -> Result<Vec<u8>, DoceditError> {
    let transaction = parse_native_revision(transaction_json)?;
    let edited = Document::parse(input)?.apply(&transaction)?;
    edited
        .serialize(&ExportOptions {
            mode: ExportMode::Redline,
            validator_level: ValidatorLevel::Blocking,
            validator: None,
        })
        .map_err(DoceditError::from)
}

/// Re-run the blocking OOXML linker on caller-supplied output at settlement.
/// This is independent of a proposal's own `validation.ok` report field.
pub fn validate_blocking(bytes: &[u8]) -> Result<(), stemma::runtime::RuntimeError> {
    stemma::runtime::gate_serialized_bytes(bytes, ValidatorLevel::Blocking)
}
