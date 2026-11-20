//! Moved from `crates/oneiron/src/authority/step_up/mod.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::authority::step_up::totp::EnrolledTotp;
pub use crate::authority::step_up::totp::TotpCode;
pub use crate::authority::step_up::totp::TotpEnrollment;
pub use oneiron_verb_wire::authority::step_up::StepUpPasskeysReset;
pub use oneiron_verb_wire::authority::step_up::StepUpPasskeysResetRequest;
pub use oneiron_verb_wire::authority::step_up::admin_inputs::WeaveAdminDigestRequest;
pub use oneiron_verb_wire::authority::step_up::admin_inputs::WeaveAdminLinkWrongRequest;
pub use oneiron_verb_wire::authority::step_up::totp::StepUpTotpReset;
pub use oneiron_verb_wire::authority::step_up::totp::StepUpTotpResetRequest;
use serde::Deserialize;
use serde::Serialize;

/// The kind of factor a step-up used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepUpFactor {
    /// A user-verified passkey or security key (WebAuthn).
    Passkey,
    /// An enrolled authenticator app (RFC 6238).
    Totp,
}

/// The two WebAuthn ceremonies a challenge opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepUpCeremony {
    /// `navigator.credentials.create`: enroll a passkey.
    Enroll,
    /// `navigator.credentials.get`: step up with an enrolled passkey.
    Assert,
}

/// One enrolled passkey as a ceremony's client names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PasskeyDescriptor {
    /// The credential id, base64url.
    pub credential_id: String,
    /// The RP id it was enrolled under.
    pub rp_id: String,
}

/// What a client needs to run one ceremony.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StepUpChallenge {
    /// The 32 challenge bytes, base64url: the client passes them as the
    /// ceremony's `challenge` and names them again in its answer.
    pub challenge: String,
    pub ceremony: StepUpCeremony,
    /// When the challenge closes, on the authority clock (seconds).
    pub expires_at: u64,
    /// The person's id bytes, base64url: `user.id` for `create`.
    pub user_id: String,
    /// The person's id, 32 hex: `user.name` for `create`.
    pub user_name: String,
    /// The person's enrolled passkeys: `excludeCredentials` for `create`,
    /// `allowCredentials` for `get`.
    pub credentials: Vec<PasskeyDescriptor>,
    /// The COSE algorithms an enrollment may use, in preference order.
    pub algorithms: Vec<i64>,
}

/// A passkey enrollment's answer, as the client read it from
/// `navigator.credentials.create` (every byte field base64url).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyRegistration {
    /// The challenge [`StepUpChallenge`] handed out for this enrollment.
    pub challenge: String,
    /// The RP id the client passed to `create` (its own effective domain).
    pub rp_id: String,
    pub credential_id: String,
    /// `response.clientDataJSON`.
    pub client_data_json: String,
    /// `response.getAuthenticatorData()`.
    pub authenticator_data: String,
    /// `response.getPublicKey()`: the SubjectPublicKeyInfo DER.
    pub public_key: String,
    /// `response.getPublicKeyAlgorithm()`: -7 (ES256) or -8 (EdDSA).
    pub algorithm: i64,
    /// The person's own name for this passkey.
    #[serde(default)]
    pub label: Option<String>,
}

/// A step-up's answer, as the client read it from
/// `navigator.credentials.get` (every byte field base64url).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyAssertion {
    /// The challenge [`StepUpChallenge`] handed out for this step-up.
    pub challenge: String,
    pub credential_id: String,
    /// `response.clientDataJSON`.
    pub client_data_json: String,
    /// `response.authenticatorData`.
    pub authenticator_data: String,
    /// `response.signature`.
    pub signature: String,
}

/// One enrolled passkey, as its person lists it. Holds no key material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnrolledPasskey {
    pub credential_id: String,
    pub label: Option<String>,
    pub rp_id: String,
    pub origin: String,
    /// The COSE algorithm.
    pub algorithm: i64,
    pub enrolled_at: u64,
    pub last_used_at: Option<u64>,
}

/// The receipt of a completed step-up on one slip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StepUpDone {
    pub factor: StepUpFactor,
    /// The passkey that verified, base64url.
    pub credential_id: String,
    /// When, on the authority clock (seconds).
    pub stepped_up_at: u64,
}
pub mod totp;
