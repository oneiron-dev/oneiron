//! Seat risk limits, sandbox policy evaluation, kill switch, and consent copy.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::normalize_keys::bounded_ref;
use super::{
    LINKEDIN_CHANNEL, LINKEDIN_CONNECT_CONSENT_BODY, LINKEDIN_DEFAULT_CADENCE_JITTER_MAX_SECONDS,
    LINKEDIN_DEFAULT_CADENCE_JITTER_MIN_SECONDS, LINKEDIN_DEFAULT_DAILY_DM_CAP,
    LINKEDIN_DEFAULT_DAILY_PROFILE_READ_CAP, LINKEDIN_SEAT_VERB_CATALOG, LINKEDIN_SEND_DM_VERB,
    LinkedInSandboxHostConfig,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkedInAccountRiskLimits {
    pub daily_dm_cap: u16,
    pub daily_profile_read_cap: u16,
    pub cadence_jitter_min_seconds: u32,
    pub cadence_jitter_max_seconds: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_warning_ack_ref: Option<String>,
}

impl Default for LinkedInAccountRiskLimits {
    fn default() -> Self {
        Self {
            daily_dm_cap: LINKEDIN_DEFAULT_DAILY_DM_CAP,
            daily_profile_read_cap: LINKEDIN_DEFAULT_DAILY_PROFILE_READ_CAP,
            cadence_jitter_min_seconds: LINKEDIN_DEFAULT_CADENCE_JITTER_MIN_SECONDS,
            cadence_jitter_max_seconds: LINKEDIN_DEFAULT_CADENCE_JITTER_MAX_SECONDS,
            owner_warning_ack_ref: None,
        }
    }
}

impl LinkedInAccountRiskLimits {
    pub fn capped_down(mut self, daily_dm_cap: u16) -> Result<Self> {
        if daily_dm_cap == 0 || daily_dm_cap > LINKEDIN_DEFAULT_DAILY_DM_CAP {
            return Err(Error::InvalidConfig(
                "LinkedIn seat-level DM cap can only be lowered from the default".to_owned(),
            ));
        }
        self.daily_dm_cap = daily_dm_cap;
        Ok(self)
    }

    pub fn with_owner_approved_daily_dm_cap(
        mut self,
        daily_dm_cap: u16,
        warning_ack_ref: impl Into<String>,
    ) -> Result<Self> {
        if daily_dm_cap == 0 {
            return Err(Error::InvalidConfig(
                "LinkedIn daily DM cap must be non-zero".to_owned(),
            ));
        }
        self.daily_dm_cap = daily_dm_cap;
        self.owner_warning_ack_ref = Some(bounded_ref(
            warning_ack_ref.into(),
            "LinkedIn owner warning acknowledgement ref must be non-empty",
            "LinkedIn owner warning acknowledgement ref exceeds maximum length",
        )?);
        Ok(self)
    }

    #[must_use]
    pub fn jittered_next_send_not_before(&self, sent_at: u64, jitter_seed: u64) -> u64 {
        let min = u64::from(self.cadence_jitter_min_seconds);
        let max = u64::from(
            self.cadence_jitter_max_seconds
                .max(self.cadence_jitter_min_seconds),
        );
        let span = max.saturating_sub(min).saturating_add(1);
        sent_at.saturating_add(min.saturating_add(jitter_seed % span))
    }

    fn validate(&self) -> Result<()> {
        if self.daily_dm_cap == 0 {
            return Err(Error::InvalidConfig(
                "LinkedIn daily DM cap must be non-zero".to_owned(),
            ));
        }
        if self.daily_dm_cap > LINKEDIN_DEFAULT_DAILY_DM_CAP && self.owner_warning_ack_ref.is_none()
        {
            return Err(Error::InvalidConfig(
                "LinkedIn DM caps above the default require owner warning acknowledgement"
                    .to_owned(),
            ));
        }
        if self.daily_profile_read_cap == 0 {
            return Err(Error::InvalidConfig(
                "LinkedIn daily profile-read cap must be non-zero".to_owned(),
            ));
        }
        if self.cadence_jitter_min_seconds == 0
            || self.cadence_jitter_min_seconds > self.cadence_jitter_max_seconds
        {
            return Err(Error::InvalidConfig(
                "LinkedIn cadence jitter window must be ordered and non-zero".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkedInSeatDispatchState {
    pub dm_sends_today: u16,
    pub profile_reads_today: u16,
    pub session_active: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_send_not_before: Option<u64>,
    pub request_is_sweep: bool,
}

impl LinkedInSeatDispatchState {
    #[must_use]
    pub const fn active() -> Self {
        Self {
            dm_sends_today: 0,
            profile_reads_today: 0,
            session_active: true,
            next_send_not_before: None,
            request_is_sweep: false,
        }
    }

    #[must_use]
    pub const fn with_dm_sends_today(mut self, dm_sends_today: u16) -> Self {
        self.dm_sends_today = dm_sends_today;
        self
    }

    #[must_use]
    pub const fn with_profile_reads_today(mut self, profile_reads_today: u16) -> Self {
        self.profile_reads_today = profile_reads_today;
        self
    }

    #[must_use]
    pub const fn with_next_send_not_before(mut self, not_before: u64) -> Self {
        self.next_send_not_before = Some(not_before);
        self
    }

    #[must_use]
    pub const fn as_sweep(mut self) -> Self {
        self.request_is_sweep = true;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkedInKillSwitchState {
    pub destroyed_at: u64,
    pub sandbox_destroyed: bool,
    pub verb_catalog_revoked: bool,
    pub reason_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkedInSeatSandboxPolicy {
    pub host: LinkedInSandboxHostConfig,
    pub limits: LinkedInAccountRiskLimits,
    pub state: LinkedInSeatDispatchState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kill_switch: Option<LinkedInKillSwitchState>,
}

impl LinkedInSeatSandboxPolicy {
    pub fn new(host: LinkedInSandboxHostConfig) -> Self {
        Self {
            host,
            limits: LinkedInAccountRiskLimits::default(),
            state: LinkedInSeatDispatchState::default(),
            kill_switch: None,
        }
    }

    pub fn active(host: LinkedInSandboxHostConfig) -> Self {
        Self {
            state: LinkedInSeatDispatchState::active(),
            ..Self::new(host)
        }
    }

    pub fn with_limits(mut self, limits: LinkedInAccountRiskLimits) -> Result<Self> {
        limits.validate()?;
        self.limits = limits;
        Ok(self)
    }

    #[must_use]
    pub fn with_state(mut self, state: LinkedInSeatDispatchState) -> Self {
        self.state = state;
        self
    }

    pub fn mark_killed(mut self, destroyed_at: u64, reason_ref: impl Into<String>) -> Result<Self> {
        self.kill_switch = Some(LinkedInKillSwitchState {
            destroyed_at,
            sandbox_destroyed: true,
            verb_catalog_revoked: true,
            reason_ref: bounded_ref(
                reason_ref.into(),
                "LinkedIn kill-switch reason ref must be non-empty",
                "LinkedIn kill-switch reason ref exceeds maximum length",
            )?,
        });
        Ok(self)
    }

    #[must_use]
    pub fn verb_catalog(&self) -> &'static [&'static str] {
        if self.kill_switch_engaged() {
            &[]
        } else {
            LINKEDIN_SEAT_VERB_CATALOG
        }
    }

    #[must_use]
    pub fn kill_switch_engaged(&self) -> bool {
        self.kill_switch
            .as_ref()
            .is_some_and(|state| state.sandbox_destroyed && state.verb_catalog_revoked)
    }

    pub fn evaluate_outbound(
        &self,
        channel: &str,
        verb: &str,
        occurred_at: u64,
    ) -> LinkedInSeatPolicyDecision {
        if channel != LINKEDIN_CHANNEL {
            return LinkedInSeatPolicyDecision::allow(BTreeMap::new());
        }

        let mut fields = self.receipt_fields();
        if self.kill_switch_engaged() {
            return LinkedInSeatPolicyDecision::suppress("linkedin.kill_switch_engaged", fields);
        }
        if self.state.request_is_sweep {
            return LinkedInSeatPolicyDecision::suppress("linkedin.no_sweeps", fields);
        }
        if !self.state.session_active {
            return LinkedInSeatPolicyDecision::hold("linkedin.session_inactive", fields);
        }
        if verb == LINKEDIN_SEND_DM_VERB {
            if self.state.dm_sends_today >= self.limits.daily_dm_cap {
                return LinkedInSeatPolicyDecision::hold("linkedin.daily_dm_cap", fields);
            }
            if let Some(not_before) = self.state.next_send_not_before
                && occurred_at < not_before
            {
                fields.insert(
                    "linkedin_next_send_not_before".to_owned(),
                    not_before.to_string(),
                );
                return LinkedInSeatPolicyDecision::hold("linkedin.cadence_not_ready", fields);
            }
        }
        LinkedInSeatPolicyDecision::allow(fields)
    }

    pub fn evaluate_profile_read(&self) -> LinkedInSeatPolicyDecision {
        let fields = self.receipt_fields();
        if self.kill_switch_engaged() {
            return LinkedInSeatPolicyDecision::suppress("linkedin.kill_switch_engaged", fields);
        }
        if self.state.request_is_sweep {
            return LinkedInSeatPolicyDecision::suppress("linkedin.no_sweeps", fields);
        }
        if !self.state.session_active {
            return LinkedInSeatPolicyDecision::hold("linkedin.session_inactive", fields);
        }
        if self.state.profile_reads_today >= self.limits.daily_profile_read_cap {
            return LinkedInSeatPolicyDecision::hold("linkedin.daily_profile_read_cap", fields);
        }
        LinkedInSeatPolicyDecision::allow(fields)
    }

    fn receipt_fields(&self) -> BTreeMap<String, String> {
        let mut fields = BTreeMap::new();
        fields.insert(
            "linkedin_policy_enforced_engine_side".to_owned(),
            "true".to_owned(),
        );
        fields.insert("linkedin_seat_ref".to_owned(), self.host.seat_ref.clone());
        fields.insert(
            "linkedin_sandbox_ref".to_owned(),
            self.host.sandbox_ref.clone(),
        );
        fields.insert(
            "linkedin_daily_dm_cap".to_owned(),
            self.limits.daily_dm_cap.to_string(),
        );
        fields.insert(
            "linkedin_dm_sends_today".to_owned(),
            self.state.dm_sends_today.to_string(),
        );
        fields.insert(
            "linkedin_daily_profile_read_cap".to_owned(),
            self.limits.daily_profile_read_cap.to_string(),
        );
        fields.insert(
            "linkedin_profile_reads_today".to_owned(),
            self.state.profile_reads_today.to_string(),
        );
        fields.insert(
            "linkedin_cadence_jitter_seconds".to_owned(),
            format!(
                "{}..{}",
                self.limits.cadence_jitter_min_seconds, self.limits.cadence_jitter_max_seconds
            ),
        );
        fields.insert(
            "linkedin_session_active".to_owned(),
            self.state.session_active.to_string(),
        );
        fields.insert("linkedin_sweeps_allowed".to_owned(), "false".to_owned());
        fields.insert(
            "linkedin_verb_catalog_revoked".to_owned(),
            self.kill_switch_engaged().to_string(),
        );
        if let Some(kill_switch) = &self.kill_switch {
            fields.insert(
                "linkedin_sandbox_destroyed".to_owned(),
                kill_switch.sandbox_destroyed.to_string(),
            );
            fields.insert(
                "linkedin_kill_switch_reason_ref".to_owned(),
                kill_switch.reason_ref.clone(),
            );
        }
        fields
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkedInSeatPolicyAction {
    Allow,
    Hold,
    Suppress,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedInSeatPolicyDecision {
    pub action: LinkedInSeatPolicyAction,
    pub reason_code: Option<String>,
    pub receipt_fields: BTreeMap<String, String>,
    pub policy_trace: Vec<String>,
}

impl LinkedInSeatPolicyDecision {
    fn allow(mut receipt_fields: BTreeMap<String, String>) -> Self {
        if !receipt_fields.is_empty() {
            receipt_fields.insert(
                "linkedin_engine_policy_decision".to_owned(),
                "allow".to_owned(),
            );
        }
        Self {
            action: LinkedInSeatPolicyAction::Allow,
            reason_code: None,
            receipt_fields,
            policy_trace: Vec::new(),
        }
    }

    fn hold(reason_code: &str, receipt_fields: BTreeMap<String, String>) -> Self {
        Self::blocked(LinkedInSeatPolicyAction::Hold, reason_code, receipt_fields)
    }

    fn suppress(reason_code: &str, receipt_fields: BTreeMap<String, String>) -> Self {
        Self::blocked(
            LinkedInSeatPolicyAction::Suppress,
            reason_code,
            receipt_fields,
        )
    }

    fn blocked(
        action: LinkedInSeatPolicyAction,
        reason_code: &str,
        mut receipt_fields: BTreeMap<String, String>,
    ) -> Self {
        let decision = match action {
            LinkedInSeatPolicyAction::Allow => "allow",
            LinkedInSeatPolicyAction::Hold => "hold",
            LinkedInSeatPolicyAction::Suppress => "suppress",
        };
        receipt_fields.insert(
            "linkedin_engine_policy_decision".to_owned(),
            decision.to_owned(),
        );
        receipt_fields.insert(
            "linkedin_engine_policy_reason".to_owned(),
            reason_code.to_owned(),
        );
        Self {
            action,
            reason_code: Some(reason_code.to_owned()),
            receipt_fields,
            policy_trace: vec![reason_code.to_owned()],
        }
    }
}

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
    harness.destroy_sandbox(&policy.host)?;
    harness.revoke_verb_catalog(&policy.host.seat_ref)?;
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
