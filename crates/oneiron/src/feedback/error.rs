//! Feedback error type plus shared validation and framing helpers.

use std::collections::BTreeMap;

use crate::entity_id::EntityId;
use crate::outbound::OutboundDispatchError;

use super::bundle::FEEDBACK_EMBEDDING_MODEL_MAX_BYTES;
use super::consent::{FEEDBACK_FRAME_ABSENT, FEEDBACK_FRAME_PRESENT, FeedbackRedactionError};

/// Everything that can go wrong on the feedback channel.
#[derive(Debug, thiserror::Error)]
pub enum FeedbackError {
    /// A bundle field violated the wire contract.
    #[error("invalid feedback bundle: {0}")]
    InvalidBundle(String),
    /// Named MessagePack encoding failed.
    #[error("encoding the feedback bundle failed: {0}")]
    Encode(#[source] rmp_serde::encode::Error),
    /// Named MessagePack decoding failed.
    #[error("decoding the feedback bundle failed: {0}")]
    Decode(#[source] rmp_serde::decode::Error),
    /// Bytes remained after a complete bundle was decoded.
    #[error("feedback bundle carries trailing bytes: consumed {consumed} of {total}")]
    TrailingBytes {
        /// Bytes the decoder consumed.
        consumed: u64,
        /// Bytes supplied.
        total: u64,
    },
    /// Rendering the human-readable preview failed.
    #[error("rendering the feedback preview failed: {0}")]
    DisplayJson(#[source] serde_json::Error),
    /// The redactor refused or could not run.
    #[error("feedback redaction failed: {0}")]
    Redaction(#[source] FeedbackRedactionError),
    /// The consent evaluation was not an approve-once decision.
    #[error("feedback approval was not granted: consent outcome {outcome}")]
    ApprovalNotGranted {
        /// The consent outcome that was presented instead.
        outcome: &'static str,
    },
    /// The consent evaluation lacked a field the binding requires.
    #[error("feedback approval is missing the {field} field")]
    ApprovalFieldMissing {
        /// Field that was absent or blank.
        field: &'static str,
    },
    /// A consent field carried an unexpected value.
    #[error("feedback approval field {field} is {found:?}, expected {expected:?}")]
    ApprovalFieldMismatch {
        /// Field that disagreed.
        field: &'static str,
        /// Value the binding requires.
        expected: &'static str,
        /// Value that was presented.
        found: String,
    },
    /// The approval belongs to a different bundle or a different destination.
    #[error("feedback approval {found:?} does not authorize {expected:?}")]
    StalePreviewDigest {
        /// Component id this bundle and destination require.
        expected: String,
        /// Component id the approval carried.
        found: String,
    },
    /// The evaluation carried a widening grant. Feedback never widens.
    #[error("feedback approval cannot mint a standing or widening grant")]
    WideningNotPermitted,
    /// The caller-supplied export writer failed.
    #[error("writing the feedback bundle to the export writer failed: {0}")]
    ExportWrite(#[source] std::io::Error),
    /// The route names a carrier channel and verb this deployment does not
    /// register, so there is nothing to dispatch through.
    #[error("unsupported feedback carrier route: {0}")]
    UnsupportedRoute(String),
    /// The ordinary outbound dispatch failed.
    #[error("dispatching the feedback bundle failed: {0}")]
    Dispatch(#[source] Box<OutboundDispatchError>),
}

pub(super) fn push_len_prefixed(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value);
}

pub(super) fn push_framed_identity(out: &mut Vec<u8>, value: Option<&EntityId>) {
    match value {
        None => out.push(FEEDBACK_FRAME_ABSENT),
        Some(identity_ref) => {
            out.push(FEEDBACK_FRAME_PRESENT);
            out.extend_from_slice(identity_ref.as_bytes());
        }
    }
}

pub(super) fn push_framed_str(out: &mut Vec<u8>, value: Option<&str>) {
    match value {
        None => out.push(FEEDBACK_FRAME_ABSENT),
        Some(text) => {
            out.push(FEEDBACK_FRAME_PRESENT);
            push_len_prefixed(out, text.as_bytes());
        }
    }
}

pub(super) fn approval_field<'a>(
    fields: &'a BTreeMap<String, String>,
    field: &'static str,
) -> Result<&'a str, FeedbackError> {
    match fields.get(field).map(String::as_str).map(str::trim) {
        Some(value) if !value.is_empty() => Ok(value),
        _ => Err(FeedbackError::ApprovalFieldMissing { field }),
    }
}

pub(super) fn expect_field(
    fields: &BTreeMap<String, String>,
    field: &'static str,
    expected: &'static str,
) -> Result<(), FeedbackError> {
    let found = approval_field(fields, field)?;
    if found == expected {
        return Ok(());
    }
    Err(FeedbackError::ApprovalFieldMismatch {
        field,
        expected,
        found: found.to_owned(),
    })
}

/// A single-line, whitespace-free, length-bounded, already-trimmed token.
pub(super) fn checked_token(
    label: &str,
    value: &str,
    max_bytes: usize,
) -> Result<(), FeedbackError> {
    if value.is_empty() {
        return Err(FeedbackError::InvalidBundle(format!(
            "{label} must not be blank"
        )));
    }
    if value.trim() != value {
        return Err(FeedbackError::InvalidBundle(format!(
            "{label} must not carry leading or trailing whitespace"
        )));
    }
    if value.chars().any(char::is_whitespace) {
        return Err(FeedbackError::InvalidBundle(format!(
            "{label} must not contain whitespace"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(FeedbackError::InvalidBundle(format!(
            "{label} must not contain control characters"
        )));
    }
    bounded_bytes(label, value.len(), max_bytes)
}

/// A single-line, length-bounded sentence. Rejects multi-line text so a raw
/// trace or a configuration dump cannot ride in as a "mechanism".
pub(super) fn checked_sentence(
    label: &str,
    value: &str,
    max_bytes: usize,
) -> Result<(), FeedbackError> {
    if value.trim().is_empty() {
        return Err(FeedbackError::InvalidBundle(format!(
            "{label} must not be blank"
        )));
    }
    if value.trim() != value {
        return Err(FeedbackError::InvalidBundle(format!(
            "{label} must not carry leading or trailing whitespace"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(FeedbackError::InvalidBundle(format!(
            "{label} must be a single line without control characters"
        )));
    }
    bounded_bytes(label, value.len(), max_bytes)
}

/// Free text a person wrote. Newlines are allowed; other control characters
/// and blank-only text are not.
pub(super) fn checked_note(
    label: &str,
    value: &str,
    max_bytes: usize,
) -> Result<(), FeedbackError> {
    if value.trim().is_empty() {
        return Err(FeedbackError::InvalidBundle(format!(
            "{label} must not be blank"
        )));
    }
    if value.chars().any(|c| c.is_control() && c != '\n') {
        return Err(FeedbackError::InvalidBundle(format!(
            "{label} must not contain control characters other than newline"
        )));
    }
    bounded_bytes(label, value.len(), max_bytes)
}

pub(super) fn checked_embedding_model(model: &str) -> Result<String, FeedbackError> {
    checked_token("embedding_model", model, FEEDBACK_EMBEDDING_MODEL_MAX_BYTES)?;
    if model.contains("://") {
        return Err(FeedbackError::InvalidBundle(
            "embedding_model must be a model identifier, not a location".to_owned(),
        ));
    }
    Ok(model.to_owned())
}

fn bounded_bytes(label: &str, len: usize, max_bytes: usize) -> Result<(), FeedbackError> {
    if len > max_bytes {
        return Err(FeedbackError::InvalidBundle(format!(
            "{label} is {len} bytes, over the {max_bytes}-byte limit"
        )));
    }
    Ok(())
}

pub(super) fn bounded(label: &str, len: usize, max_len: usize) -> Result<(), FeedbackError> {
    if len > max_len {
        return Err(FeedbackError::InvalidBundle(format!(
            "{label} carries {len} entries, over the {max_len} limit"
        )));
    }
    Ok(())
}
