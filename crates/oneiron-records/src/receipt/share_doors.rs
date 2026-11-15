//! Moved from `crates/oneiron/src/receipt/share_doors.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::receipt::share_doors::SharedBriefCitation;
use serde::Deserialize;
use serde::Serialize;

/// `vault.shares.revoke`'s answer: the share, its status after the revoke,
/// and the instant it stopped. A share already revoked answers its first
/// revocation unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareRevokeReceipt {
    /// The share's id, as 32 hex.
    pub share_ref: String,
    /// The grant's stored status: `revoked`.
    pub status: String,
    /// When the share stopped, Unix seconds on the vault's clock.
    pub revoked_at: Option<u64>,
}
