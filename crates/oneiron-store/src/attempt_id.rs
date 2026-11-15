//! Stable queued-attempt identifiers and their raw storage representation.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::side_table::codec::{CodecError, RawValue};
use crate::side_table::key::SideKey;
use oneiron_contracts::error::{ArtifactError, Error, Result};

const ERR_ATTEMPT_ID_LEN: &str = "attempt id must be 16 bytes";

/// Stable identifier for a queued attempt.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
    SideKey,
)]
pub struct AttemptId {
    pub(crate) bytes: [u8; 16],
}

impl AttemptId {
    /// Creates a new time-sortable v7 UUID-backed attempt id.
    #[must_use]
    pub fn now() -> Self {
        Self {
            bytes: Uuid::now_v7().into_bytes(),
        }
    }

    /// Returns the raw 16-byte storage key.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.bytes
    }

    /// Parses a raw 16-byte storage key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bytes: [u8; 16] = bytes.try_into().map_err(|_| {
            Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(ERR_ATTEMPT_ID_LEN))
        })?;
        Ok(Self { bytes })
    }
}

/// A side table that stores a bare attempt reference as its row's raw 16
/// bytes (as opposed to keying on it, bound above via `SideKey`).
impl RawValue for AttemptId {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(self.as_bytes().to_vec())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(Self::from_bytes(bytes)?)
    }
}
