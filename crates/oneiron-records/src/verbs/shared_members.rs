//! Moved from `crates/oneiron/src/verbs/shared_members.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::verbs::shared_members::GuestSlipMintRequest;
pub use oneiron_verb_wire::verbs::shared_members::GuestSlipMinted;
pub use oneiron_verb_wire::verbs::shared_members::InvitationCodeRequest;
pub use oneiron_verb_wire::verbs::shared_members::InvitationSlipRequest;
pub use oneiron_verb_wire::verbs::shared_members::SharedEraseAskCloseRequest;
pub use oneiron_verb_wire::verbs::shared_members::SharedEraseAskRequest;
pub use oneiron_verb_wire::verbs::shared_members::SharedInvitationAcceptWithCredentialRequest;
pub use oneiron_verb_wire::verbs::shared_members::SharedInvitationRequest;
pub use oneiron_verb_wire::verbs::shared_members::SharedInvitationWithdrawRequest;
use serde::Deserialize;
use serde::Serialize;

/// An owner's invitation pairing code (FIX 8745): the owner passes it to the
/// invitee by any channel, and the invitee redeems it once at the pairing
/// door with a key of their own, which binds the invitation to that key and
/// returns the invitation's slip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvitationCode {
    /// The single-use code.
    pub code: String,
    /// When the code expires: within the hour, and not after the invitation.
    pub expires_at: u64,
}
