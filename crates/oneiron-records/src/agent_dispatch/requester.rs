//! Moved from `crates/oneiron/src/agent_dispatch/requester.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Why a queued dispatch's requester no longer stands: a positive
/// withdrawal, never a read that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequesterWithdrawn {
    /// The slip the request was admitted on, or an ancestor, was revoked.
    SlipRevoked,
    /// The attested owner is no longer the vault's live owner.
    OwnerNotLive,
    /// The owner withdrew the ask guest's grant the request stood on.
    GrantWithdrawn,
    /// The requester was hard-erased.
    RequesterErased,
}

impl RequesterWithdrawn {
    /// The stable reason the ended try and its TASK record.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::SlipRevoked => "requester_withdrawn:slip_revoked",
            Self::OwnerNotLive => "requester_withdrawn:owner_not_live",
            Self::GrantWithdrawn => "requester_withdrawn:grant_withdrawn",
            Self::RequesterErased => "requester_withdrawn:requester_erased",
        }
    }
}
