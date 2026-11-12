//! Moved from `crates/oneiron/src/deletion/coop_delivery/types.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::deletion::legal_hold::types::LegalHold;
use crate::deletion::legal_hold::types::LegalHoldKind;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
pub use oneiron_store::deletion::coop_delivery::types::*;
use oneiron_store::deletion::coop_reply::CooperativeDeletionReplyOutcome;
use serde::Deserialize;
use serde::Serialize;

/// The recipient owner's menu (BIZ-LEGAL-0004 B2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CooperativeDeletionDispositionKind {
    Delete,
    Redact,
    RestrictPendingReview,
    RetainUnderBasis,
    LegalHold,
    Decline,
}

impl CooperativeDeletionDispositionKind {
    /// What the requester learns of this choice.
    #[must_use]
    pub const fn reply_outcome(self) -> CooperativeDeletionReplyOutcome {
        match self {
            Self::Decline => CooperativeDeletionReplyOutcome::Declined,
            _ => CooperativeDeletionReplyOutcome::Acknowledged,
        }
    }
}
