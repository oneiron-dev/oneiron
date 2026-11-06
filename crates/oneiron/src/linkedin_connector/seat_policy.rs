//! Seat lifecycle operations and consent copy.
use super::normalize_keys::bounded_ref;
use super::{LINKEDIN_CONNECT_CONSENT_BODY, LinkedInSandboxHostConfig};
use crate::error::Result;
pub use crate::outbound::linkedin_policy::{
    LinkedInAccountRiskLimits, LinkedInKillSwitchState, LinkedInSeatDispatchState,
    LinkedInSeatPolicyAction, LinkedInSeatPolicyDecision, LinkedInSeatSandboxPolicy,
};

pub trait LinkedInSandboxHostHarness {
    fn destroy_sandbox(&mut self, host: &LinkedInSandboxHostConfig) -> Result<()>;
    fn revoke_verb_catalog(&mut self, seat_ref: &str) -> Result<()>;
}

pub fn run_linkedin_kill_switch<H: LinkedInSandboxHostHarness>(
    policy: LinkedInSeatSandboxPolicy,
    harness: &mut H,
    occurred_at: u64,
    reason_ref: impl Into<String>,
) -> Result<LinkedInSeatSandboxPolicy> {
    let reason_ref = bounded_ref(
        reason_ref.into(),
        "LinkedIn kill-switch reason ref must be non-empty",
        "LinkedIn kill-switch reason ref exceeds maximum length",
    )?;
    // Revoke first so a sandbox that refuses termination cannot still send.
    // Attempt destruction even when revocation fails; both operations are
    // idempotent so the host can retry after a partial failure.
    let revoked = harness.revoke_verb_catalog(&policy.host.seat_ref);
    let destroyed = harness.destroy_sandbox(&policy.host);
    revoked?;
    destroyed?;
    policy.mark_killed(occurred_at, reason_ref)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedInConsentScreenCopy {
    pub title: String,
    pub body: String,
    pub acknowledgements: Vec<String>,
}

#[must_use]
pub fn linkedin_connect_consent_screen_copy() -> LinkedInConsentScreenCopy {
    LinkedInConsentScreenCopy {
        title: "Connect LinkedIn".to_owned(),
        body: LINKEDIN_CONNECT_CONSENT_BODY.to_owned(),
        acknowledgements: vec![
            "I understand my LinkedIn account can be limited if sending looks automated."
                .to_owned(),
            "I will log in once through the remote browser and complete 2FA myself.".to_owned(),
            "I understand the default cap is 15 DMs per day, with no sweeps.".to_owned(),
            "I can turn this connector off and delete the sandbox at any time.".to_owned(),
        ],
    }
}
