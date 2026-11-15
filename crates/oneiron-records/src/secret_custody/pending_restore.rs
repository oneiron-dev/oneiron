//! Moved from `crates/oneiron/src/secret_custody/pending_restore.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::secret_custody::pending_restore::owner::PENDING_CREDENTIAL_RELEASE_NOTE;
pub use crate::secret_custody::pending_restore::owner::PendingCredentialConfirmation;
pub use crate::secret_custody::pending_restore::owner::PendingCredentialOutcome;
pub use crate::secret_custody::pending_restore::owner::PendingCredentialReleaseReceipt;
use serde::Deserialize;
use serde::Serialize;

/// What a pending credential came to (FIX-LIST 10671).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingCredentialResult {
    /// Its row landed as the image carried it, and its value opens under
    /// its key here.
    Readable,
    /// Its row landed as the image carried it, but its key does not open it
    /// here: re-enter or reissue it.
    StillUnavailable,
    /// An erase fenced it: it stays withheld, its value unavailable.
    Erased,
    /// A revoke, an erase, a rotation or a newer write replaced its row
    /// since: the saved row went, unlanded.
    Superseded,
    /// Its fence or its row did not read: it stays pending.
    Pending,
}

impl PendingCredentialResult {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Readable => "readable",
            Self::StillUnavailable => "still_unavailable",
            Self::Erased => "erased",
            Self::Superseded => "superseded",
            Self::Pending => "pending",
        }
    }
}
pub mod owner;
