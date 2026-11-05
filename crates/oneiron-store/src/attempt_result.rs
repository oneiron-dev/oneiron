//! Validated durable result references for queued work.

use serde::{Deserialize, Serialize};

use oneiron_base::error::{ArtifactError, Error, Result};

pub const MAX_RESULT_REF_LEN: usize = MAX_RESUME_ARTIFACT_REF_LEN;

pub const MAX_RESUME_ARTIFACT_REF_LEN: usize = 512;

pub const ERR_RESULT_REF_EMPTY: &str = "attempt result reference must not be empty";

pub const ERR_RESULT_REF_TOO_LONG: &str = "attempt result reference exceeds 512 bytes";

pub const ERR_RESULT_REF_CONTROL: &str = "attempt result reference contains a control character";

/// Durable reference to the artifact version an attempt's result lives in.
///
/// The value is a REFERENCE, never a payload: an executor's actual output is
/// an appended artifact version, and this row carries only the string that
/// names it. It is validated at construction so a row can never point at an
/// empty or unprintable reference that no reader could resolve.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AttemptResultRef(String);

impl AttemptResultRef {
    /// Builds a validated result reference.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactError::InvalidAttemptQueueRecord`](crate::error::ArtifactError::InvalidAttemptQueueRecord) when the reference is
    /// empty, over-long, or carries a control character.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_result_ref(&value)?;
        Ok(Self(value))
    }

    /// The validated reference string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the reference, yielding its validated string.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

/// Refuses a result reference no reader could resolve.
///
/// Control characters are rejected in addition to the length/emptiness bounds
/// the other reference doors use: a result reference is projected onto read
/// surfaces verbatim (the run tree renders it under its own wire key), so an
/// embedded newline or terminal escape would be a rendering hazard carried on
/// a durable row.
pub fn validate_result_ref(result_ref: &str) -> Result<()> {
    if result_ref.is_empty() {
        return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_RESULT_REF_EMPTY,
        )));
    }
    if result_ref.len() > MAX_RESULT_REF_LEN {
        return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_RESULT_REF_TOO_LONG,
        )));
    }
    if result_ref.chars().any(char::is_control) {
        return Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(
            ERR_RESULT_REF_CONTROL,
        )));
    }
    Ok(())
}
