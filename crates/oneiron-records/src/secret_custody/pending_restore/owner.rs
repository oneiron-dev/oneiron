//! Moved from `crates/oneiron/src/secret_custody/pending_restore/owner.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::secret_custody::pending_restore::PendingCredentialResult;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// What the receipt of a released batch says: the owner's election, never
/// a check of the source.
pub const PENDING_CREDENTIAL_RELEASE_NOTE: &str =
    "owner elected to keep without source verification";

/// The owner's one typed answer to a restore's pending credential batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingCredentialConfirmation {
    /// "The source is gone, keep these": every credential the batch holds
    /// pending on its source's evidence lands as the image carried it,
    /// unverified against that source.
    KeepWithoutSource,
}

impl PendingCredentialConfirmation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::KeepWithoutSource => "keep_without_source",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        (text == Self::KeepWithoutSource.as_str()).then_some(Self::KeepWithoutSource)
    }
}

/// What one credential of a released batch came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingCredentialOutcome {
    pub handle: String,
    pub generation: u32,
    pub result: PendingCredentialResult,
}

/// The receipt of a released batch: value-free.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingCredentialReleaseReceipt {
    pub batch: EntityId,
    /// The owner who confirmed; none once his identity is erased.
    pub by: Option<EntityId>,
    pub at: u64,
    pub confirmation: PendingCredentialConfirmation,
    pub outcomes: Vec<PendingCredentialOutcome>,
}

impl PendingCredentialReleaseReceipt {
    /// What the receipt says of the election
    /// ([`PENDING_CREDENTIAL_RELEASE_NOTE`]).
    pub fn note(&self) -> &'static str {
        PENDING_CREDENTIAL_RELEASE_NOTE
    }
}
