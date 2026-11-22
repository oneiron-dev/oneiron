//! Moved from `crates/oneiron/src/genui/voice_offer.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Serialize;

/// A displayable offer. Neither the nonce nor the corroborating voice-print
/// result is a credential; only `confirm_voice_grant_offer` can mint a grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VoiceGrantOffer {
    pub grant_offer_nonce: String,
    pub owner_voice_print_verified: bool,
    pub principal_ref: String,
    pub bound_digest: String,
    pub expires_at: u64,
}
