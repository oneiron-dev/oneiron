//! Moved from `crates/oneiron/src/federation/shared_act/membership/invitation.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

/// Where an invitation stands. Only `Pending` before `expires_at` admits.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SharedInvitationState {
    Pending,
    Accepted {
        at: u64,
    },
    Declined {
        at: u64,
    },
    /// An `add_member` holder (`by`) took it back.
    Withdrawn {
        by: String,
        at: u64,
    },
}
