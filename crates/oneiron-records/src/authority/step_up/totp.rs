//! Moved from `crates/oneiron/src/authority/step_up/totp.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::authority::step_up::totp::StepUpTotpReset;
pub use oneiron_verb_wire::authority::step_up::totp::StepUpTotpResetRequest;
use serde::Deserialize;
use serde::Serialize;
use zeroize::Zeroize;

/// A fresh provisioning secret, returned only to the enrolling person.
/// It has no Debug or Clone; its seed text is wiped on drop. Do not log it.
#[derive(Serialize)]
pub struct TotpEnrollment {
    pub enrollment_id: String,
    /// RFC 4648 base32, without padding; for an otpauth provisioning URI.
    pub secret: String,
    pub algorithm: &'static str,
    pub digits: usize,
    pub period_secs: u64,
    /// On the authority clock, like a passkey enrollment challenge.
    pub expires_at: u64,
}

impl Drop for TotpEnrollment {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// The first code confirms enrollment; subsequent codes step up a slip.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TotpCode {
    pub enrollment_id: String,
    pub code: String,
}

impl Drop for TotpCode {
    fn drop(&mut self) {
        self.code.zeroize();
    }
}

/// An enrolled authenticator's public metadata. Never its seed or seal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnrolledTotp {
    pub enrollment_id: String,
    pub enrolled_at: u64,
    pub last_used_at: u64,
}
