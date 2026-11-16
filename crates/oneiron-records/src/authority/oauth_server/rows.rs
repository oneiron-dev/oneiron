//! Moved from `crates/oneiron/src/authority/oauth_server/rows.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::authority::oauth_server::OAUTH_ACCESS_TTL_SECS;
use serde::Deserialize;
use serde::Serialize;

/// Which kind of token a token row is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenKind {
    Access,
    Refresh,
}

/// Whether a token family's first access slip stood (FIX 22193, 22226). Only a family whose first
/// slip stood handed a token out, so only its grant outlives the family; the sign-in of one whose
/// first slip never stood is ended, its grant taken back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FamilyOpening {
    /// A code's exchange at `opened_at` opened the family, and its first access slip has not
    /// stood: no token of it was handed out.
    Pending { opened_at: u64 },
    /// Its first access slip landed and its first pair was handed out. Only a revoke or a lapse
    /// ends the family; its grant stays until the owner revokes it.
    Stood,
    /// Its first access slip did not stand and its sign-in was ended: the family is revoked, and
    /// its grant was taken back unless another family that is not revoked names it.
    Ended,
}

impl FamilyOpening {
    /// Whether the expiry sweep ends the family's sign-in at `now` (FIX 22226): its first access
    /// slip has not stood and the first access token, minted with the exchange, has lapsed, so
    /// no token request still minting that slip is cut short. A slip that lands after the end
    /// finds the family revoked and stands for nothing; one that landed first marked it
    /// [`Self::Stood`], and the end, judged again in its writer, leaves it.
    pub fn end_due_at(self, now: u64) -> bool {
        matches!(
            self,
            Self::Pending { opened_at } if now >= opened_at.saturating_add(OAUTH_ACCESS_TTL_SECS)
        )
    }
}
