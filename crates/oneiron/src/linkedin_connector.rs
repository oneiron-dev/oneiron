//! LinkedIn connector adapter surface (ONE-1563 / LNKD-1).
//!
//! The first LinkedIn implementation rides the session-bound
//! `stickerdaniel/linkedin-mcp-server` tool surface. This module keeps that
//! boundary local and testable: it maps recorded MCP read outputs into
//! OF-247 `InboundSurfaceEventInput` values without starting a browser or
//! touching a live LinkedIn session.

use std::collections::{BTreeMap, HashSet};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Vault;
use crate::attempt_queue::{AttemptQueue, EnqueueAttempt, EnqueueOutcome};
use crate::error::{Error, Result};
use crate::outbound::{OutboundExecutionOutcome, OutboundExecutionRequest, OutboundExecutionSink};
use crate::surface_event::{
    InboundSurfaceEventInput, InboundSurfaceRouteOutcome, InboundSurfaceRouteReceipt,
    SurfaceCounterpartyStamp,
};

/// Stable Oneiron channel key for LinkedIn.
pub const LINKEDIN_CHANNEL: &str = "linkedin";

/// Stable connector key for the wrapped LinkedIn MCP server.
pub const LINKEDIN_MCP_CONNECTOR_KEY: &str = "linkedin_mcp";

/// OF-327 connector verb for direct messages.
pub const LINKEDIN_SEND_DM_VERB: &str = "send_dm";

/// OF-327 connector verb for connection requests.
pub const LINKEDIN_CONNECT_REQUEST_VERB: &str = "connect_request";

/// Upstream MCP tool backing `linkedin.send_dm`.
pub const LINKEDIN_MCP_SEND_MESSAGE_TOOL: &str = "send_message";

/// Upstream MCP tool backing `linkedin.connect_request`.
pub const LINKEDIN_MCP_CONNECT_WITH_PERSON_TOOL: &str = "connect_with_person";

/// Default D5 account-risk wall for one seat.
pub const LINKEDIN_DEFAULT_DAILY_DM_CAP: u16 = 15;

/// Default D5 profile-read wall for one seat.
pub const LINKEDIN_DEFAULT_DAILY_PROFILE_READ_CAP: u16 = 25;

/// Lower bound for human-cadence jitter between sends.
pub const LINKEDIN_DEFAULT_CADENCE_JITTER_MIN_SECONDS: u32 = 180;

/// Upper bound for human-cadence jitter between sends.
pub const LINKEDIN_DEFAULT_CADENCE_JITTER_MAX_SECONDS: u32 = 900;

/// Plain-words first-connect disclosure copy reviewed against OF-373 D5.
pub const LINKEDIN_CONNECT_CONSENT_BODY: &str = "LinkedIn does not officially support this kind of automated sending. Oneiron will use your own logged-in browser session in a private sandbox; it does not need or store your password. Automated patterns can still get your LinkedIn account limited. The default cap is 15 DMs per day, sends are paced like a person, sweeps are not allowed, and you can turn LinkedIn off at any time. Turning it off deletes the sandbox and removes LinkedIn send/connect verbs for this seat.";

const LINKEDIN_SEAT_VERB_CATALOG: &[&str] = &[LINKEDIN_SEND_DM_VERB, LINKEDIN_CONNECT_REQUEST_VERB];

/// Durable attempt kind used by the scheduled LinkedIn inbox poller.
pub const LINKEDIN_INBOX_SYNC_ATTEMPT_KIND: &str = "linkedin_inbox_sync";

/// Default initial lookback for timestamped LinkedIn messages.
pub const DEFAULT_LINKEDIN_INBOX_BACKFILL_WINDOW_SECS: u64 = 7 * 24 * 60 * 60;

const LINKEDIN_MCP_GET_INBOX_TOOL: &str = "get_inbox";
const LINKEDIN_MCP_GET_CONVERSATION_TOOL: &str = "get_conversation";
const LINKEDIN_INBOX_SYNC_SEEN_PREFIX: &str = "linkedin:inbox_sync:seen:v1:";
const LINKEDIN_INBOX_SYNC_PROVENANCE_PREFIX: &str = "linkedin:inbox_sync:provenance:v1:";
const LINKEDIN_INBOX_SYNC_DEDUPE_PREFIX: &str = "linkedin:inbox_sync:";
const LINKEDIN_INBOX_SYNC_SOURCE: &str = "imported";
const LINKEDIN_INBOX_SYNC_TIER: &str = "external";
const LINKEDIN_INBOX_SYNC_CLAIMED_VALUE: &[u8] = b"claimed";

const MAX_LINKEDIN_ADDRESS_BYTES: usize = 512;
const MAX_LINKEDIN_SESSION_REF_BYTES: usize = 512;
const MAX_LINKEDIN_THREAD_ID_BYTES: usize = 256;
const MAX_LINKEDIN_MESSAGE_ID_BYTES: usize = 512;
const MAX_LINKEDIN_EVENT_ID_BYTES: usize = 384;
const MAX_LINKEDIN_PAYLOAD_REF_BYTES: usize = 384;
const MAX_LINKEDIN_COUNTERPARTY_KEY_BYTES: usize = 320;
const MAX_LINKEDIN_RECIPIENT_KEY_BYTES: usize = 512;
const MAX_LINKEDIN_MESSAGE_TEXT_BYTES: usize = 16 * 1024;
const MAX_LINKEDIN_INTENT_REF_BYTES: usize = 512;
const MAX_LINKEDIN_ERROR_CODE_BYTES: usize = 96;
const MAX_LINKEDIN_INBOX_BACKFILL_WINDOW_SECS: u64 = 366 * 24 * 60 * 60;
const MAX_LINKEDIN_INBOX_THREADS_PER_POLL: usize = 250;
const MAX_LINKEDIN_CONVERSATION_MESSAGES_PER_THREAD: usize = 1_000;
const DEFAULT_LINKEDIN_SEND_VERIFY_ATTEMPTS: usize = 3;
const MAX_LINKEDIN_SEND_VERIFY_ATTEMPTS: usize = 25;
const LINKEDIN_SEND_VERIFY_BACKOFF_INITIAL_MS: u64 = 25;
const LINKEDIN_SEND_VERIFY_BACKOFF_MAX_MS: u64 = 250;

const RECEIPT_FIELD_LINKEDIN_THREAD_REF: &str = "linkedin_thread_ref";
const RECEIPT_FIELD_ARTIFACT_THREAD_MESSAGE_REF: &str = "artifact_thread_message_ref";
const RECEIPT_FIELD_SEND_MESSAGE_RETURN_TRUSTED: &str = "send_message_return_trusted";
const RECEIPT_FIELD_SEND_MESSAGE_CALLED: &str = "send_message_called";
const RECEIPT_FIELD_SEND_MESSAGE_RESULT: &str = "send_message_result";
const RECEIPT_FIELD_SEND_MESSAGE_TOOL_ERROR: &str = "send_message_tool_error";
const RECEIPT_FIELD_VERIFY_TOOL: &str = "verify_tool";
const RECEIPT_FIELD_VERIFICATION_STATE: &str = "linkedin_send_verification";
const RECEIPT_FIELD_VERIFICATION_ATTEMPTS: &str = "verification_attempts";
const RECEIPT_FIELD_DUPLICATE_SEND_GUARD: &str = "duplicate_send_guard";
const RECEIPT_FIELD_RETRY_WINDOW: &str = "retry_window";
const RECEIPT_FIELD_PRE_SEND_MATCH_COUNT: &str = "pre_send_match_count";
const RECEIPT_FIELD_POST_SEND_MATCH_COUNT: &str = "post_send_match_count";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkedInSandboxRuntime {
    Container,
    MicroVm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkedInSelectorDriver {
    DeterministicMcp,
    BrowserUse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkedInNetworkRoute {
    StableDedicatedIp,
    Browserbase,
    ResidentialBox,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkedInManagedTransport {
    Unipile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkedInPasswordCustody {
    MemberOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkedInMcpServerHarness {
    pub command_ref: String,
    pub persistent_browser_profile: bool,
}

impl LinkedInMcpServerHarness {
    pub fn new(command_ref: impl Into<String>) -> Result<Self> {
        Ok(Self {
            command_ref: normalize_non_blank(
                command_ref.into(),
                MAX_LINKEDIN_SESSION_REF_BYTES,
                "LinkedIn MCP server command ref must be non-empty",
                "LinkedIn MCP server command ref exceeds maximum length",
            )?,
            persistent_browser_profile: true,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkedInLoginHandoff {
    pub one_time_remote_browser: bool,
    pub member_completes_2fa: bool,
    pub password_custody: LinkedInPasswordCustody,
}

impl LinkedInLoginHandoff {
    #[must_use]
    pub const fn one_time_remote_browser() -> Self {
        Self {
            one_time_remote_browser: true,
            member_completes_2fa: true,
            password_custody: LinkedInPasswordCustody::MemberOnly,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkedInEscalationConfig {
    pub selector_driver: LinkedInSelectorDriver,
    pub network_route: LinkedInNetworkRoute,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_transport: Option<LinkedInManagedTransport>,
}

impl Default for LinkedInEscalationConfig {
    fn default() -> Self {
        Self {
            selector_driver: LinkedInSelectorDriver::DeterministicMcp,
            network_route: LinkedInNetworkRoute::StableDedicatedIp,
            managed_transport: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkedInSandboxHostConfig {
    pub seat_ref: String,
    pub sandbox_ref: String,
    pub runtime: LinkedInSandboxRuntime,
    pub mcp_server: LinkedInMcpServerHarness,
    pub browser_profile_ref: String,
    pub session_cookie_secret_ref: String,
    pub login_handoff: LinkedInLoginHandoff,
    pub escalation: LinkedInEscalationConfig,
}

impl LinkedInSandboxHostConfig {
    pub fn new(
        seat_ref: impl Into<String>,
        sandbox_ref: impl Into<String>,
        browser_profile_ref: impl Into<String>,
        session_cookie_secret_ref: impl Into<String>,
    ) -> Result<Self> {
        Ok(Self {
            seat_ref: bounded_ref(
                seat_ref.into(),
                "LinkedIn seat ref must be non-empty",
                "LinkedIn seat ref exceeds maximum length",
            )?,
            sandbox_ref: bounded_ref(
                sandbox_ref.into(),
                "LinkedIn sandbox ref must be non-empty",
                "LinkedIn sandbox ref exceeds maximum length",
            )?,
            runtime: LinkedInSandboxRuntime::Container,
            mcp_server: LinkedInMcpServerHarness::new("harness:linkedin-mcp-server")?,
            browser_profile_ref: bounded_ref(
                browser_profile_ref.into(),
                "LinkedIn browser profile ref must be non-empty",
                "LinkedIn browser profile ref exceeds maximum length",
            )?,
            session_cookie_secret_ref: vault_scoped_secret_ref(session_cookie_secret_ref.into())?,
            login_handoff: LinkedInLoginHandoff::one_time_remote_browser(),
            escalation: LinkedInEscalationConfig::default(),
        })
    }

    #[must_use]
    pub const fn with_runtime(mut self, runtime: LinkedInSandboxRuntime) -> Self {
        self.runtime = runtime;
        self
    }

    #[must_use]
    pub fn with_escalation(mut self, escalation: LinkedInEscalationConfig) -> Self {
        self.escalation = escalation;
        self
    }
}

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

/// Adapter for recorded `stickerdaniel/linkedin-mcp-server` messaging outputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedInMcpConnectorAdapter {
    receiving_address_or_handle: String,
    session_ref: Option<String>,
}

/// Config persisted in each scheduled LinkedIn inbox-sync attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkedInInboxSyncConfig {
    pub receiving_address_or_handle: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_ref: Option<String>,
    pub backfill_window_secs: u64,
}

impl LinkedInInboxSyncConfig {
    pub fn new(receiving_address_or_handle: impl Into<String>) -> Result<Self> {
        let receiving_address_or_handle = normalize_non_blank(
            receiving_address_or_handle.into(),
            MAX_LINKEDIN_ADDRESS_BYTES,
            "LinkedIn receiving identity must be non-empty",
            "LinkedIn receiving identity exceeds maximum length",
        )?;
        Ok(Self {
            receiving_address_or_handle,
            session_ref: None,
            backfill_window_secs: DEFAULT_LINKEDIN_INBOX_BACKFILL_WINDOW_SECS,
        })
    }

    pub fn from_adapter(adapter: &LinkedInMcpConnectorAdapter) -> Self {
        Self {
            receiving_address_or_handle: adapter.receiving_address_or_handle.clone(),
            session_ref: adapter.session_ref.clone(),
            backfill_window_secs: DEFAULT_LINKEDIN_INBOX_BACKFILL_WINDOW_SECS,
        }
    }

    pub fn with_session_ref(mut self, session_ref: impl Into<String>) -> Result<Self> {
        self.session_ref = Some(normalize_non_blank(
            session_ref.into(),
            MAX_LINKEDIN_SESSION_REF_BYTES,
            "LinkedIn session ref must be non-empty",
            "LinkedIn session ref exceeds maximum length",
        )?);
        Ok(self)
    }

    pub fn with_backfill_window_secs(mut self, backfill_window_secs: u64) -> Result<Self> {
        if backfill_window_secs > MAX_LINKEDIN_INBOX_BACKFILL_WINDOW_SECS {
            return Err(Error::InvalidConfig(
                "LinkedIn inbox backfill window exceeds maximum length".to_owned(),
            ));
        }
        self.backfill_window_secs = backfill_window_secs;
        Ok(self)
    }

    fn adapter(&self) -> Result<LinkedInMcpConnectorAdapter> {
        let adapter = LinkedInMcpConnectorAdapter::new(self.receiving_address_or_handle.clone())?;
        if let Some(session_ref) = &self.session_ref {
            adapter.with_session_ref(session_ref.clone())
        } else {
            Ok(adapter)
        }
    }

    fn validate(&self) -> Result<()> {
        Self::new(self.receiving_address_or_handle.clone())?;
        if let Some(session_ref) = &self.session_ref {
            normalize_non_blank(
                session_ref.clone(),
                MAX_LINKEDIN_SESSION_REF_BYTES,
                "LinkedIn session ref must be non-empty",
                "LinkedIn session ref exceeds maximum length",
            )?;
        }
        if self.backfill_window_secs > MAX_LINKEDIN_INBOX_BACKFILL_WINDOW_SECS {
            return Err(Error::InvalidConfig(
                "LinkedIn inbox backfill window exceeds maximum length".to_owned(),
            ));
        }
        Ok(())
    }
}

/// One normalized LinkedIn conversation message selected by the inbox sync attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedInConversationMessage {
    pub thread_id: String,
    pub message_id: String,
    pub occurred_at: Option<u64>,
    pub text: Option<String>,
}

/// Message plus the SurfaceEvent input that will be routed if not yet seen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedInConversationMessageEvent {
    pub message: LinkedInConversationMessage,
    pub event_input: InboundSurfaceEventInput,
}

/// Stable provenance marker persisted beside each seen LinkedIn message row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkedInInboxSyncProvenanceRow {
    pub schema_version: u64,
    pub source: String,
    pub tier: String,
    pub channel: String,
    pub receiving_address_or_handle: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_ref: Option<String>,
    pub thread_id: String,
    pub message_id: String,
    pub surface_event_id: String,
    pub payload_ref: Option<String>,
    pub received_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub occurred_at: Option<u64>,
}

/// Result of one LinkedIn inbox sync execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedInInboxSyncReport {
    pub threads_seen: usize,
    pub messages_seen: usize,
    pub new_messages: usize,
    pub duplicate_messages: usize,
    pub backfill_skipped_messages: usize,
    pub receipts: Vec<InboundSurfaceRouteReceipt>,
}

impl LinkedInInboxSyncReport {
    fn empty() -> Self {
        Self {
            threads_seen: 0,
            messages_seen: 0,
            new_messages: 0,
            duplicate_messages: 0,
            backfill_skipped_messages: 0,
            receipts: Vec::new(),
        }
    }
}

/// Minimal host transport for scheduled LinkedIn inbox sync.
pub trait LinkedInMcpInboxSyncTransport {
    fn get_inbox(&mut self) -> std::result::Result<Value, String>;

    fn get_conversation(&mut self, thread_id: &str) -> std::result::Result<Value, String>;
}

/// Engine-side scheduled inbox sync runner.
pub struct LinkedInInboxSyncRunner<'a, T> {
    vault: &'a Vault,
    adapter: LinkedInMcpConnectorAdapter,
    transport: T,
    config: LinkedInInboxSyncConfig,
}

impl LinkedInMcpConnectorAdapter {
    /// Builds a LinkedIn adapter for one authenticated member/session identity.
    pub fn new(receiving_address_or_handle: impl Into<String>) -> Result<Self> {
        let receiving_address_or_handle = normalize_non_blank(
            receiving_address_or_handle.into(),
            MAX_LINKEDIN_ADDRESS_BYTES,
            "LinkedIn receiving identity must be non-empty",
            "LinkedIn receiving identity exceeds maximum length",
        )?;
        Ok(Self {
            receiving_address_or_handle,
            session_ref: None,
        })
    }

    /// Attaches a vault-local session or sandbox reference to emitted events.
    pub fn with_session_ref(mut self, session_ref: impl Into<String>) -> Result<Self> {
        self.session_ref = Some(normalize_non_blank(
            session_ref.into(),
            MAX_LINKEDIN_SESSION_REF_BYTES,
            "LinkedIn session ref must be non-empty",
            "LinkedIn session ref exceeds maximum length",
        )?);
        Ok(self)
    }

    /// Returns the channel identity address this adapter routes into.
    #[must_use]
    pub fn receiving_address_or_handle(&self) -> &str {
        &self.receiving_address_or_handle
    }

    /// Returns the session/sandbox ref stamped into LinkedIn inbound events.
    #[must_use]
    pub fn session_ref(&self) -> Option<&str> {
        self.session_ref.as_deref()
    }

    /// Enqueues one scheduled inbox poll for this LinkedIn seat/session.
    pub fn enqueue_inbox_sync_poll(
        &self,
        vault: &Vault,
        config: LinkedInInboxSyncConfig,
        now: u64,
    ) -> Result<EnqueueOutcome> {
        config.validate()?;
        validate_inbox_sync_config_matches_adapter(self, &config)?;
        let payload = serde_json::to_vec(&config).map_err(|err| {
            Error::InvalidConfig(format!("LinkedIn inbox sync config did not encode: {err}"))
        })?;
        AttemptQueue::new(vault).enqueue(EnqueueAttempt {
            kind: LINKEDIN_INBOX_SYNC_ATTEMPT_KIND.to_owned(),
            payload,
            dedupe_key: Some(linkedin_inbox_sync_dedupe_key(&config)),
            run_id: None,
            now,
        })
    }

    /// Returns the supported OF-327 verb keys advertised for this connector.
    #[must_use]
    pub const fn supported_outbound_verbs(&self) -> &'static [&'static str] {
        &[LINKEDIN_SEND_DM_VERB, LINKEDIN_CONNECT_REQUEST_VERB]
    }

    /// Maps an OF-327 LinkedIn verb to the upstream MCP tool name.
    #[must_use]
    pub fn mcp_tool_for_verb(&self, verb: &str) -> Option<&'static str> {
        let verb = normalize_verb_key(verb);
        let verb = verb.strip_prefix("linkedin_").unwrap_or(&verb);
        match verb {
            LINKEDIN_SEND_DM_VERB => Some(LINKEDIN_MCP_SEND_MESSAGE_TOOL),
            LINKEDIN_CONNECT_REQUEST_VERB => Some(LINKEDIN_MCP_CONNECT_WITH_PERSON_TOOL),
            _ => None,
        }
    }

    /// Normalizes a recorded `get_inbox` MCP result into SurfaceEvent inputs.
    ///
    /// Upstream returns a single `sections.inbox` text block plus conversation
    /// references captured by click-visiting visible rows. We emit one stable
    /// event per referenced thread.
    pub fn normalize_get_inbox_tool_output(
        &self,
        output: &Value,
        received_at: u64,
    ) -> Result<Vec<InboundSurfaceEventInput>> {
        let payload = mcp_payload(output)?;
        let Some(inbox_text) = optional_section_text(&payload, "inbox")? else {
            return Ok(Vec::new());
        };
        if inbox_text.trim().is_empty() {
            return Ok(Vec::new());
        }

        let mut events = Vec::new();
        let mut seen_thread_ids = HashSet::new();
        for reference in section_references(&payload, "inbox") {
            if !reference_kind_is(reference, "conversation") {
                continue;
            }
            let Some(thread_id) = thread_id_from_reference(reference)? else {
                continue;
            };
            if !seen_thread_ids.insert(thread_id.clone()) {
                continue;
            };
            let hash = event_hash(["get_inbox", &thread_id].as_slice());
            events.push(self.surface_event_input(
                format!("linkedin:inbox:{thread_id}:{hash}"),
                counterparty_key(&thread_id),
                format!("linkedin:mcp:get_inbox:{thread_id}:{hash}"),
                received_at,
            )?);
        }
        Ok(events)
    }

    /// Extracts deduplicated conversation thread ids from `get_inbox` output.
    pub fn inbox_thread_ids_from_tool_output(&self, output: &Value) -> Result<Vec<String>> {
        let payload = mcp_payload(output)?;
        let Some(inbox_text) = optional_section_text(&payload, "inbox")? else {
            return Ok(Vec::new());
        };
        if inbox_text.trim().is_empty() {
            return Ok(Vec::new());
        }

        let mut thread_ids = Vec::new();
        let mut seen_thread_ids = HashSet::new();
        for reference in section_references(&payload, "inbox") {
            if !reference_kind_is(reference, "conversation") {
                continue;
            }
            let Some(thread_id) = thread_id_from_reference(reference)? else {
                continue;
            };
            if seen_thread_ids.insert(thread_id.clone()) {
                thread_ids.push(thread_id);
            }
            if thread_ids.len() > MAX_LINKEDIN_INBOX_THREADS_PER_POLL {
                return Err(Error::IndexOverflow("LinkedIn inbox threads"));
            }
        }
        Ok(thread_ids)
    }

    /// Normalizes a recorded `get_conversation` MCP result into SurfaceEvent input.
    pub fn normalize_get_conversation_tool_output(
        &self,
        output: &Value,
        received_at: u64,
    ) -> Result<Vec<InboundSurfaceEventInput>> {
        let payload = mcp_payload(output)?;
        let Some(conversation_text) = optional_section_text(&payload, "conversation")? else {
            return Ok(Vec::new());
        };
        if conversation_text.trim().is_empty() {
            return Ok(Vec::new());
        }

        let conversation_references = section_references(&payload, "conversation");
        let thread_id = match thread_id_from_payload_url(&payload)? {
            Some(thread_id) => thread_id,
            None => first_conversation_thread_id(&conversation_references)?.ok_or_else(|| {
                Error::InvalidConfig(
                    "LinkedIn get_conversation output did not include a thread id".to_owned(),
                )
            })?,
        };
        let hash = event_hash(["get_conversation", &thread_id, conversation_text].as_slice());
        Ok(vec![self.surface_event_input(
            format!("linkedin:conversation:{thread_id}:{hash}"),
            counterparty_key(&thread_id),
            format!("linkedin:mcp:get_conversation:{thread_id}:{hash}"),
            received_at,
        )?])
    }

    /// Normalizes a `get_conversation` MCP result into message-level events.
    pub fn normalize_get_conversation_message_events(
        &self,
        output: &Value,
        received_at: u64,
        backfill_window_secs: u64,
    ) -> Result<Vec<LinkedInConversationMessageEvent>> {
        let messages = conversation_messages_from_tool_output(output, None)?;
        self.normalize_conversation_messages(messages, received_at, backfill_window_secs)
    }

    fn normalize_conversation_messages(
        &self,
        messages: Vec<LinkedInConversationMessage>,
        received_at: u64,
        backfill_window_secs: u64,
    ) -> Result<Vec<LinkedInConversationMessageEvent>> {
        if backfill_window_secs > MAX_LINKEDIN_INBOX_BACKFILL_WINDOW_SECS {
            return Err(Error::InvalidConfig(
                "LinkedIn inbox backfill window exceeds maximum length".to_owned(),
            ));
        }
        let mut events = Vec::new();
        for message in messages {
            if !message_in_backfill_window(&message, received_at, backfill_window_secs) {
                continue;
            }
            let message_hash =
                event_hash([message.thread_id.as_str(), message.message_id.as_str()].as_slice());
            let event_input = self.surface_event_input(
                format!(
                    "linkedin:conversation:{}:message:{message_hash}",
                    message.thread_id
                ),
                counterparty_key(&message.thread_id),
                format!(
                    "linkedin:mcp:get_conversation:{}:message:{message_hash}",
                    message.thread_id
                ),
                received_at,
            )?;
            events.push(LinkedInConversationMessageEvent {
                message,
                event_input,
            });
        }
        Ok(events)
    }

    fn surface_event_input(
        &self,
        event_id: String,
        counterparty_key: String,
        payload_ref: String,
        received_at: u64,
    ) -> Result<InboundSurfaceEventInput> {
        let event_id = bounded_identifier(
            event_id,
            MAX_LINKEDIN_EVENT_ID_BYTES,
            "LinkedIn surface event id exceeds maximum length",
        )?;
        let counterparty_key = bounded_identifier(
            counterparty_key,
            MAX_LINKEDIN_COUNTERPARTY_KEY_BYTES,
            "LinkedIn counterparty key exceeds maximum length",
        )?;
        let payload_ref = bounded_identifier(
            payload_ref,
            MAX_LINKEDIN_PAYLOAD_REF_BYTES,
            "LinkedIn payload ref exceeds maximum length",
        )?;
        let input = InboundSurfaceEventInput::new(
            event_id,
            LINKEDIN_CHANNEL,
            self.receiving_address_or_handle.clone(),
            SurfaceCounterpartyStamp::unknown(counterparty_key),
            received_at,
            true,
        )
        .with_payload_ref(payload_ref);
        if let Some(session_ref) = &self.session_ref {
            Ok(input.with_workspace_ref(session_ref.clone()))
        } else {
            Ok(input)
        }
    }
}

impl<'a, T> LinkedInInboxSyncRunner<'a, T> {
    #[must_use]
    pub fn new(
        vault: &'a Vault,
        adapter: LinkedInMcpConnectorAdapter,
        transport: T,
        config: LinkedInInboxSyncConfig,
    ) -> Self {
        Self {
            vault,
            adapter,
            transport,
            config,
        }
    }

    #[must_use]
    pub const fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub const fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
}

impl<T: LinkedInMcpInboxSyncTransport> LinkedInInboxSyncRunner<'_, T> {
    /// Executes one scheduled inbox poll.
    pub fn run_once(&mut self, now: u64) -> Result<LinkedInInboxSyncReport> {
        self.config.validate()?;
        validate_inbox_sync_config_matches_adapter(&self.adapter, &self.config)?;
        let inbox_output = self
            .transport
            .get_inbox()
            .map_err(|err| linkedin_tool_failure(LINKEDIN_MCP_GET_INBOX_TOOL, &err))?;
        let thread_ids = self
            .adapter
            .inbox_thread_ids_from_tool_output(&inbox_output)?;
        let mut report = LinkedInInboxSyncReport::empty();
        report.threads_seen = thread_ids.len();

        for thread_id in thread_ids {
            let conversation_output = self
                .transport
                .get_conversation(&thread_id)
                .map_err(|err| linkedin_tool_failure(LINKEDIN_MCP_GET_CONVERSATION_TOOL, &err))?;
            let messages =
                conversation_messages_from_tool_output(&conversation_output, Some(&thread_id))?;
            let all_message_count = messages.len();
            let events = self.adapter.normalize_conversation_messages(
                messages,
                now,
                self.config.backfill_window_secs,
            )?;
            report.messages_seen = report.messages_seen.saturating_add(all_message_count);
            report.backfill_skipped_messages = report
                .backfill_skipped_messages
                .saturating_add(all_message_count.saturating_sub(events.len()));

            for event in events {
                if !claim_linkedin_inbox_message(self.vault, &self.config, &event.message)? {
                    report.duplicate_messages = report.duplicate_messages.saturating_add(1);
                    continue;
                }

                let receipt = match self
                    .vault
                    .route_inbound_surface_event(event.event_input.clone())
                {
                    Ok(receipt) => receipt,
                    Err(err) => {
                        release_linkedin_inbox_message_claim(
                            self.vault,
                            &self.config,
                            &event.message,
                        )?;
                        return Err(err);
                    }
                };
                if receipt.outcome == InboundSurfaceRouteOutcome::Routed {
                    finalize_linkedin_inbox_seen_message(
                        self.vault,
                        &self.config,
                        &event.message,
                        &event.event_input,
                    )?;
                    report.new_messages = report.new_messages.saturating_add(1);
                } else {
                    release_linkedin_inbox_message_claim(self.vault, &self.config, &event.message)?;
                }
                report.receipts.push(receipt);
            }
        }

        Ok(report)
    }
}

/// Builds a runner from a scheduled attempt payload.
pub fn linkedin_inbox_sync_runner_from_attempt<'a, T>(
    vault: &'a Vault,
    payload: &[u8],
    transport: T,
) -> Result<LinkedInInboxSyncRunner<'a, T>> {
    let config: LinkedInInboxSyncConfig = serde_json::from_slice(payload).map_err(|err| {
        Error::InvalidConfig(format!(
            "LinkedIn inbox sync attempt payload did not decode: {err}"
        ))
    })?;
    config.validate()?;
    let adapter = config.adapter()?;
    Ok(LinkedInInboxSyncRunner::new(
        vault, adapter, transport, config,
    ))
}

/// Host-resolved plan for one `linkedin.send_dm` intent.
///
/// The outbound intent carries references; the host owns the final message
/// body and selected LinkedIn thread. This plan is the explicit seam between
/// those host-local values and the connector's verify-after-send law.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedInVerifiedSendPlan {
    pub recipient_key: String,
    pub thread_id: String,
    pub message_text: String,
    pub max_observation_attempts: usize,
    pub guard_retry: bool,
}

impl LinkedInVerifiedSendPlan {
    pub fn new(
        recipient_key: impl Into<String>,
        thread_id: impl AsRef<str>,
        message_text: impl Into<String>,
    ) -> Result<Self> {
        Ok(Self {
            recipient_key: normalize_non_blank(
                recipient_key.into(),
                MAX_LINKEDIN_RECIPIENT_KEY_BYTES,
                "LinkedIn recipient key must be non-empty",
                "LinkedIn recipient key exceeds maximum length",
            )?,
            thread_id: normalize_thread_id(thread_id.as_ref())?,
            message_text: normalize_non_blank(
                message_text.into(),
                MAX_LINKEDIN_MESSAGE_TEXT_BYTES,
                "LinkedIn message text must be non-empty",
                "LinkedIn message text exceeds maximum length",
            )?,
            max_observation_attempts: DEFAULT_LINKEDIN_SEND_VERIFY_ATTEMPTS,
            guard_retry: false,
        })
    }

    pub fn with_max_observation_attempts(mut self, attempts: usize) -> Result<Self> {
        if attempts == 0 || attempts > MAX_LINKEDIN_SEND_VERIFY_ATTEMPTS {
            return Err(Error::InvalidConfig(format!(
                "LinkedIn verify-after-send attempts must be 1..={MAX_LINKEDIN_SEND_VERIFY_ATTEMPTS}"
            )));
        }
        self.max_observation_attempts = attempts;
        Ok(self)
    }

    #[must_use]
    pub const fn retry_guarded(mut self) -> Self {
        self.guard_retry = true;
        self
    }
}

/// Exact MCP call payload the host transport should issue for `send_message`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedInMcpSendMessageRequest {
    pub recipient_key: String,
    pub thread_id: String,
    pub message_text: String,
    pub idempotency_key: Option<String>,
    pub intent_ref: String,
}

/// Minimal host transport used by the verified-send sink.
///
/// Implementors should return stable error codes, not raw provider output or
/// secrets. `send_message` return values are intentionally ignored for success.
pub trait LinkedInMcpSendTransport {
    fn send_message(
        &mut self,
        request: &LinkedInMcpSendMessageRequest,
    ) -> std::result::Result<Value, String>;

    fn get_conversation(&mut self, thread_id: &str) -> std::result::Result<Value, String>;
}

/// OF-327 execution sink for `linkedin.send_dm` with D2 verify-after-send.
pub struct LinkedInMcpVerifiedSendSink<T> {
    adapter: LinkedInMcpConnectorAdapter,
    transport: T,
    plans: BTreeMap<String, LinkedInVerifiedSendPlan>,
}

impl<T> LinkedInMcpVerifiedSendSink<T> {
    #[must_use]
    pub fn new(adapter: LinkedInMcpConnectorAdapter, transport: T) -> Self {
        Self {
            adapter,
            transport,
            plans: BTreeMap::new(),
        }
    }

    pub fn with_plan(
        mut self,
        intent_ref: impl Into<String>,
        plan: LinkedInVerifiedSendPlan,
    ) -> Result<Self> {
        self.add_plan(intent_ref, plan)?;
        Ok(self)
    }

    pub fn add_plan(
        &mut self,
        intent_ref: impl Into<String>,
        plan: LinkedInVerifiedSendPlan,
    ) -> Result<()> {
        let intent_ref = normalize_non_blank(
            intent_ref.into(),
            MAX_LINKEDIN_INTENT_REF_BYTES,
            "LinkedIn verified-send intent ref must be non-empty",
            "LinkedIn verified-send intent ref exceeds maximum length",
        )?;
        self.plans.insert(intent_ref, plan);
        Ok(())
    }

    #[must_use]
    pub const fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub const fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
}

impl<T: LinkedInMcpSendTransport> OutboundExecutionSink for LinkedInMcpVerifiedSendSink<T> {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        if request.intent.channel != LINKEDIN_CHANNEL
            || request.verb_contract.kind != LINKEDIN_SEND_DM_VERB
            || self.adapter.mcp_tool_for_verb(&request.verb_contract.kind)
                != Some(LINKEDIN_MCP_SEND_MESSAGE_TOOL)
        {
            return OutboundExecutionOutcome::failed("linkedin_verified_send_requires_send_dm");
        }

        let Some(plan) = self.plans.get(request.intent_ref).cloned() else {
            return OutboundExecutionOutcome::failed("linkedin_verified_send_plan_missing");
        };

        let gated_counterparty = request.counterparty_ref.unwrap_or(&request.intent.target);
        if !plan_matches_gated_counterparty(&plan, gated_counterparty) {
            let mut fields = verified_send_receipt_fields(&plan);
            fields.insert(
                RECEIPT_FIELD_SEND_MESSAGE_CALLED.to_owned(),
                "false".to_owned(),
            );
            fields.insert(
                RECEIPT_FIELD_VERIFICATION_STATE.to_owned(),
                "target_mismatch".to_owned(),
            );
            return OutboundExecutionOutcome::failed("linkedin_verified_send_target_mismatch")
                .with_receipt_fields(fields);
        }

        let outcome = self.execute_plan(request, &plan);
        if outcome.kind == crate::outbound::OutboundExecutionOutcomeKind::Failed
            && outcome
                .receipt_fields
                .get(RECEIPT_FIELD_SEND_MESSAGE_CALLED)
                .is_some_and(|called| called == "true")
        {
            outcome.with_possible_delivery()
        } else {
            outcome
        }
    }
}

impl<T: LinkedInMcpSendTransport> LinkedInMcpVerifiedSendSink<T> {
    fn execute_plan(
        &mut self,
        request: &OutboundExecutionRequest<'_>,
        plan: &LinkedInVerifiedSendPlan,
    ) -> OutboundExecutionOutcome {
        let mut fields = verified_send_receipt_fields(plan);
        fields.insert(
            RECEIPT_FIELD_SEND_MESSAGE_RETURN_TRUSTED.to_owned(),
            "false".to_owned(),
        );
        fields.insert(
            RECEIPT_FIELD_VERIFY_TOOL.to_owned(),
            "get_conversation".to_owned(),
        );
        fields.insert(
            RECEIPT_FIELD_RETRY_WINDOW.to_owned(),
            plan.max_observation_attempts.to_string(),
        );

        let pre_send_match_count = match self.transport.get_conversation(&plan.thread_id) {
            Ok(output) => match observed_message(&output, &plan.thread_id, &plan.message_text) {
                Ok(Some(observation)) => {
                    fields.insert(
                        RECEIPT_FIELD_PRE_SEND_MATCH_COUNT.to_owned(),
                        observation.occurrence_count.to_string(),
                    );
                    if plan.guard_retry && observation.tail_matches {
                        fields.insert(
                            RECEIPT_FIELD_DUPLICATE_SEND_GUARD.to_owned(),
                            "observed_existing".to_owned(),
                        );
                        fields.insert(
                            RECEIPT_FIELD_SEND_MESSAGE_CALLED.to_owned(),
                            "false".to_owned(),
                        );
                        fields.insert(
                            RECEIPT_FIELD_VERIFICATION_STATE.to_owned(),
                            "content_observed".to_owned(),
                        );
                        fields.insert(
                            RECEIPT_FIELD_VERIFICATION_ATTEMPTS.to_owned(),
                            "1".to_owned(),
                        );
                        return OutboundExecutionOutcome::delivered_to_channel(
                            observation.message_ref,
                        )
                        .with_receipt_fields(fields);
                    }
                    if plan.guard_retry {
                        fields.insert(
                            RECEIPT_FIELD_DUPLICATE_SEND_GUARD.to_owned(),
                            "observed_existing_not_tail".to_owned(),
                        );
                    }
                    observation.occurrence_count
                }
                Ok(None) => {
                    fields.insert(
                        RECEIPT_FIELD_PRE_SEND_MATCH_COUNT.to_owned(),
                        "0".to_owned(),
                    );
                    if plan.guard_retry {
                        fields.insert(
                            RECEIPT_FIELD_DUPLICATE_SEND_GUARD.to_owned(),
                            "observed_absent".to_owned(),
                        );
                    }
                    0
                }
                Err(err) => {
                    fields.insert(
                        RECEIPT_FIELD_DUPLICATE_SEND_GUARD.to_owned(),
                        "precheck_failed".to_owned(),
                    );
                    fields.insert(
                        RECEIPT_FIELD_SEND_MESSAGE_CALLED.to_owned(),
                        "false".to_owned(),
                    );
                    fields.insert(
                        "verify_precheck_error".to_owned(),
                        receipt_error_code(&err.to_string()),
                    );
                    return OutboundExecutionOutcome::failed("verify_after_send_precheck_failed")
                        .with_receipt_fields(fields);
                }
            },
            Err(err) => {
                fields.insert(
                    RECEIPT_FIELD_DUPLICATE_SEND_GUARD.to_owned(),
                    "precheck_failed".to_owned(),
                );
                fields.insert(
                    RECEIPT_FIELD_SEND_MESSAGE_CALLED.to_owned(),
                    "false".to_owned(),
                );
                fields.insert("verify_precheck_error".to_owned(), receipt_error_code(&err));
                return OutboundExecutionOutcome::failed("verify_after_send_precheck_failed")
                    .with_receipt_fields(fields);
            }
        };

        let send_request = LinkedInMcpSendMessageRequest {
            recipient_key: plan.recipient_key.clone(),
            thread_id: plan.thread_id.clone(),
            message_text: plan.message_text.clone(),
            idempotency_key: request.idempotency_key.map(str::to_owned),
            intent_ref: request.intent_ref.to_owned(),
        };
        fields.insert(
            RECEIPT_FIELD_SEND_MESSAGE_CALLED.to_owned(),
            "true".to_owned(),
        );
        match self.transport.send_message(&send_request) {
            Ok(_) => {
                fields.insert(
                    RECEIPT_FIELD_SEND_MESSAGE_RESULT.to_owned(),
                    "ignored".to_owned(),
                );
            }
            Err(err) => {
                fields.insert(
                    RECEIPT_FIELD_SEND_MESSAGE_RESULT.to_owned(),
                    "failed".to_owned(),
                );
                fields.insert(
                    RECEIPT_FIELD_SEND_MESSAGE_TOOL_ERROR.to_owned(),
                    receipt_error_code(&err),
                );
                fields.insert(
                    RECEIPT_FIELD_VERIFICATION_STATE.to_owned(),
                    "send_message_failed".to_owned(),
                );
                fields.insert(
                    RECEIPT_FIELD_VERIFICATION_ATTEMPTS.to_owned(),
                    "0".to_owned(),
                );
                return OutboundExecutionOutcome::failed("verify_after_send_send_message_failed")
                    .with_receipt_fields(fields);
            }
        }

        let mut last_get_error = None;
        let mut observed_stale = false;
        let mut post_send_match_count = 0;
        for attempt in 1..=plan.max_observation_attempts {
            match self.transport.get_conversation(&plan.thread_id) {
                Ok(output) => {
                    match observed_message(&output, &plan.thread_id, &plan.message_text) {
                        Ok(Some(observation))
                            if observation.tail_matches
                                && observation.occurrence_count > pre_send_match_count =>
                        {
                            fields.insert(
                                RECEIPT_FIELD_POST_SEND_MATCH_COUNT.to_owned(),
                                observation.occurrence_count.to_string(),
                            );
                            fields.insert(
                                RECEIPT_FIELD_VERIFICATION_STATE.to_owned(),
                                "content_observed".to_owned(),
                            );
                            fields.insert(
                                RECEIPT_FIELD_VERIFICATION_ATTEMPTS.to_owned(),
                                attempt.to_string(),
                            );
                            return OutboundExecutionOutcome::delivered_to_channel(
                                observation.message_ref,
                            )
                            .with_receipt_fields(fields);
                        }
                        Ok(Some(observation)) => {
                            observed_stale = true;
                            post_send_match_count =
                                post_send_match_count.max(observation.occurrence_count);
                            last_get_error = None;
                        }
                        Ok(None) => {
                            last_get_error = None;
                        }
                        Err(err) => {
                            last_get_error = Some(receipt_error_code(&err.to_string()));
                        }
                    }
                }
                Err(err) => {
                    last_get_error = Some(receipt_error_code(&err));
                }
            }
            if attempt < plan.max_observation_attempts {
                sleep_before_next_linkedin_observation(attempt);
            }
        }

        if post_send_match_count > 0 {
            fields.insert(
                RECEIPT_FIELD_POST_SEND_MATCH_COUNT.to_owned(),
                post_send_match_count.to_string(),
            );
        }
        fields.insert(
            RECEIPT_FIELD_VERIFICATION_STATE.to_owned(),
            if last_get_error.is_some() {
                "get_conversation_failed"
            } else if observed_stale {
                "observed_stale"
            } else {
                "observed_absent"
            }
            .to_owned(),
        );
        fields.insert(
            RECEIPT_FIELD_VERIFICATION_ATTEMPTS.to_owned(),
            plan.max_observation_attempts.to_string(),
        );
        if let Some(error) = last_get_error {
            fields.insert("verify_get_conversation_error".to_owned(), error);
            OutboundExecutionOutcome::failed("verify_after_send_get_conversation_failed")
                .with_receipt_fields(fields)
        } else if observed_stale {
            OutboundExecutionOutcome::failed("verify_after_send_observed_stale")
                .with_receipt_fields(fields)
        } else {
            OutboundExecutionOutcome::failed("verify_after_send_observed_absent")
                .with_receipt_fields(fields)
        }
    }
}

fn mcp_payload(output: &Value) -> Result<Value> {
    if output.get("sections").is_some() {
        return Ok(output.clone());
    }
    if let Some(messages) = output.get("messages") {
        if !messages.is_array() {
            return Err(Error::InvalidConfig(
                "LinkedIn MCP messages must be an array".to_owned(),
            ));
        }
        return Ok(output.clone());
    }
    if let Some(structured) = output.get("structuredContent") {
        return Ok(structured.clone());
    }
    if let Some(content) = output.get("content").and_then(Value::as_array)
        && let Some(text) = content.iter().find_map(|entry| {
            entry
                .get("text")
                .and_then(Value::as_str)
                .filter(|text| !text.trim().is_empty())
        })
    {
        return serde_json::from_str(text).map_err(|err| {
            Error::InvalidConfig(format!("LinkedIn MCP content text was not JSON: {err}"))
        });
    }
    Err(Error::InvalidConfig(
        "LinkedIn MCP output did not match a recognized shape".to_owned(),
    ))
}

fn validate_inbox_sync_config_matches_adapter(
    adapter: &LinkedInMcpConnectorAdapter,
    config: &LinkedInInboxSyncConfig,
) -> Result<()> {
    if adapter.receiving_address_or_handle != config.receiving_address_or_handle {
        return Err(Error::InvalidConfig(
            "LinkedIn inbox sync config does not match adapter receiving identity".to_owned(),
        ));
    }
    if adapter.session_ref != config.session_ref {
        return Err(Error::InvalidConfig(
            "LinkedIn inbox sync config does not match adapter session ref".to_owned(),
        ));
    }
    Ok(())
}

fn linkedin_tool_failure(tool: &'static str, err: &str) -> Error {
    Error::UpstreamToolFailure {
        tool,
        code: receipt_error_code(err),
    }
}

fn conversation_messages_from_tool_output(
    output: &Value,
    fallback_thread_id: Option<&str>,
) -> Result<Vec<LinkedInConversationMessage>> {
    let payload = mcp_payload(output)?;
    let conversation_references = section_references(&payload, "conversation");
    let thread_id = match thread_id_from_payload_url(&payload)? {
        Some(thread_id) => thread_id,
        None => match first_conversation_thread_id(&conversation_references)? {
            Some(thread_id) => thread_id,
            None => fallback_thread_id
                .map(normalize_thread_id)
                .transpose()?
                .ok_or_else(|| {
                    Error::InvalidConfig(
                        "LinkedIn get_conversation output did not include a thread id".to_owned(),
                    )
                })?,
        },
    };

    let mut messages =
        if let Some(message_values) = payload.get("messages").and_then(Value::as_array) {
            explicit_conversation_messages(&thread_id, message_values)?
        } else {
            Vec::new()
        };
    if messages.is_empty()
        && let Some(conversation_text) = optional_section_text(&payload, "conversation")?
    {
        messages = fallback_conversation_messages(&thread_id, conversation_text)?;
    }
    if messages.len() > MAX_LINKEDIN_CONVERSATION_MESSAGES_PER_THREAD {
        return Err(Error::IndexOverflow("LinkedIn conversation messages"));
    }
    Ok(messages)
}

fn explicit_conversation_messages(
    thread_id: &str,
    message_values: &[Value],
) -> Result<Vec<LinkedInConversationMessage>> {
    let mut messages = Vec::new();
    let mut seen_message_ids = HashSet::new();
    for value in message_values {
        let Some(object) = value.as_object() else {
            return Err(Error::InvalidConfig(
                "LinkedIn conversation messages must be objects".to_owned(),
            ));
        };
        let Some(message_id) = first_string_field(
            object,
            &["id", "message_id", "messageId", "urn", "entity_urn"],
        ) else {
            continue;
        };
        let message_id = normalize_message_id(message_id)?;
        if !seen_message_ids.insert(message_id.clone()) {
            continue;
        }
        let text = first_string_field(object, &["text", "body", "content", "message"])
            .map(normalize_whitespace)
            .filter(|text| !text.is_empty());
        let occurred_at = first_timestamp_field(
            object,
            &["occurred_at", "timestamp", "created_at", "sent_at"],
        )?;
        messages.push(LinkedInConversationMessage {
            thread_id: thread_id.to_owned(),
            message_id,
            occurred_at,
            text,
        });
    }
    Ok(messages)
}

fn fallback_conversation_messages(
    thread_id: &str,
    conversation_text: &str,
) -> Result<Vec<LinkedInConversationMessage>> {
    let lines = conversation_text
        .lines()
        .map(normalize_whitespace)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    if lines.is_empty() {
        return Ok(Vec::new());
    }

    let mut start = 0;
    if lines.len() >= 3 && lines[0] == lines[1] && looks_like_linkedin_time(&lines[2]) {
        start = 1;
    }

    let mut messages = Vec::new();
    let mut index = start;
    while index < lines.len() {
        if index + 2 < lines.len() && looks_like_linkedin_time(&lines[index + 1]) {
            let timestamp = &lines[index + 1];
            index += 2;
            let body_start = index;
            while index < lines.len() {
                if index + 1 < lines.len() && looks_like_linkedin_time(&lines[index + 1]) {
                    break;
                }
                index += 1;
            }
            let body = lines[body_start..index].join(" ");
            if !body.is_empty() {
                messages.push(fallback_message(
                    thread_id,
                    [timestamp.as_str(), body.as_str()].as_slice(),
                    Some(body.clone()),
                )?);
            }
            continue;
        }

        let body = lines[index].clone();
        messages.push(fallback_message(
            thread_id,
            [body.as_str()].as_slice(),
            Some(body.clone()),
        )?);
        index += 1;
    }
    Ok(messages)
}

fn fallback_message(
    thread_id: &str,
    hash_parts: &[&str],
    text: Option<String>,
) -> Result<LinkedInConversationMessage> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(thread_id.as_bytes());
    for part in hash_parts {
        hasher.update(&[0]);
        hasher.update(part.as_bytes());
    }
    let digest = hasher.finalize().to_hex().to_string();
    Ok(LinkedInConversationMessage {
        thread_id: thread_id.to_owned(),
        message_id: normalize_message_id(&format!("fallback-{}", &digest[..16]))?,
        occurred_at: None,
        text,
    })
}

fn first_string_field<'a>(
    object: &'a serde_json::Map<String, Value>,
    keys: &[&str],
) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn first_u64_field(object: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<u64> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_u64))
}

fn first_timestamp_field(
    object: &serde_json::Map<String, Value>,
    keys: &[&str],
) -> Result<Option<u64>> {
    first_u64_field(object, keys)
        .map(normalize_epoch_timestamp_secs)
        .transpose()
}

fn normalize_epoch_timestamp_secs(value: u64) -> Result<u64> {
    if value >= 1_000_000_000_000_000 {
        return Err(Error::InvalidConfig(
            "LinkedIn timestamp unit exceeds supported epoch milliseconds".to_owned(),
        ));
    }
    if value >= 10_000_000_000 {
        return Ok(value / 1_000);
    }
    Ok(value)
}

fn looks_like_linkedin_time(value: &str) -> bool {
    let lower = value.trim().to_ascii_lowercase();
    if lower.contains(':') && (lower.ends_with("am") || lower.ends_with("pm")) {
        return true;
    }
    lower == "today"
        || lower == "yesterday"
        || lower.contains(" ago")
        || looks_like_linkedin_date_label(&lower)
}

fn looks_like_linkedin_date_label(lower: &str) -> bool {
    let mut parts = lower.split_whitespace();
    let Some(month) = parts.next() else {
        return false;
    };
    if !matches!(
        month.trim_end_matches('.'),
        "jan"
            | "january"
            | "feb"
            | "february"
            | "mar"
            | "march"
            | "apr"
            | "april"
            | "may"
            | "jun"
            | "june"
            | "jul"
            | "july"
            | "aug"
            | "august"
            | "sep"
            | "sept"
            | "september"
            | "oct"
            | "october"
            | "nov"
            | "november"
            | "dec"
            | "december"
    ) {
        return false;
    }
    let Some(day) = parts.next() else {
        return false;
    };
    let day = day.trim_end_matches(',');
    if !matches!(day.parse::<u8>(), Ok(1..=31)) {
        return false;
    }
    match parts.next() {
        None => true,
        Some(year) if year.len() == 4 && year.parse::<u16>().is_ok() => parts.next().is_none(),
        Some(_) => false,
    }
}

fn message_in_backfill_window(
    message: &LinkedInConversationMessage,
    now: u64,
    backfill_window_secs: u64,
) -> bool {
    let Some(occurred_at) = message.occurred_at else {
        return true;
    };
    occurred_at.saturating_add(backfill_window_secs) >= now
}

fn claim_linkedin_inbox_message(
    vault: &Vault,
    config: &LinkedInInboxSyncConfig,
    message: &LinkedInConversationMessage,
) -> Result<bool> {
    let seen_key = linkedin_inbox_seen_key(config, message);
    vault.with_write_txn(|wtxn| {
        if vault.store.sync_state.get(wtxn, &seen_key)?.is_some() {
            return Ok(false);
        }
        vault
            .store
            .sync_state
            .put(wtxn, &seen_key, LINKEDIN_INBOX_SYNC_CLAIMED_VALUE)?;
        Ok(true)
    })
}

fn release_linkedin_inbox_message_claim(
    vault: &Vault,
    config: &LinkedInInboxSyncConfig,
    message: &LinkedInConversationMessage,
) -> Result<()> {
    let seen_key = linkedin_inbox_seen_key(config, message);
    vault.with_write_txn(|wtxn| {
        if vault
            .store
            .sync_state
            .get(wtxn, &seen_key)?
            .is_some_and(|value| *value == *LINKEDIN_INBOX_SYNC_CLAIMED_VALUE)
        {
            vault.store.sync_state.delete(wtxn, &seen_key)?;
        }
        Ok(())
    })
}

fn finalize_linkedin_inbox_seen_message(
    vault: &Vault,
    config: &LinkedInInboxSyncConfig,
    message: &LinkedInConversationMessage,
    event_input: &InboundSurfaceEventInput,
) -> Result<()> {
    let seen_key = linkedin_inbox_seen_key(config, message);
    let provenance_key = linkedin_inbox_provenance_key(config, message);
    let row = LinkedInInboxSyncProvenanceRow {
        schema_version: 1,
        source: LINKEDIN_INBOX_SYNC_SOURCE.to_owned(),
        tier: LINKEDIN_INBOX_SYNC_TIER.to_owned(),
        channel: LINKEDIN_CHANNEL.to_owned(),
        receiving_address_or_handle: config.receiving_address_or_handle.clone(),
        session_ref: config.session_ref.clone(),
        thread_id: message.thread_id.clone(),
        message_id: message.message_id.clone(),
        surface_event_id: event_input.event_id.clone(),
        payload_ref: event_input.payload_ref.clone(),
        received_at: event_input.received_at,
        occurred_at: message.occurred_at,
    };
    let encoded = serde_json::to_vec(&row).map_err(|err| {
        Error::InvalidConfig(format!(
            "LinkedIn inbox sync provenance row did not encode: {err}"
        ))
    })?;

    vault.with_write_txn(|wtxn| {
        if vault
            .store
            .sync_state
            .get(wtxn, &seen_key)?
            .is_none_or(|value| *value != *LINKEDIN_INBOX_SYNC_CLAIMED_VALUE)
        {
            return Err(Error::ConcurrentWrite(
                "LinkedIn inbox sync claim missing before finalization",
            ));
        }
        vault
            .store
            .sync_state
            .put(wtxn, &seen_key, event_input.event_id.as_bytes())?;
        vault
            .store
            .sync_state
            .put(wtxn, &provenance_key, &encoded)?;
        Ok(())
    })
}

/// Reads durable LinkedIn inbox-sync provenance rows for diagnostics/tests.
pub fn linkedin_inbox_sync_provenance_rows(
    vault: &Vault,
) -> Result<Vec<LinkedInInboxSyncProvenanceRow>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut rows = Vec::new();
    for row in vault
        .store
        .sync_state
        .prefix_iter(&rtxn, LINKEDIN_INBOX_SYNC_PROVENANCE_PREFIX)?
    {
        let (_, value) = row?;
        let decoded: LinkedInInboxSyncProvenanceRow =
            serde_json::from_slice(&value).map_err(|err| {
                Error::CorruptedIndex(match err.classify() {
                    serde_json::error::Category::Io => "LinkedIn inbox provenance io",
                    serde_json::error::Category::Syntax => "LinkedIn inbox provenance syntax",
                    serde_json::error::Category::Data => "LinkedIn inbox provenance data",
                    serde_json::error::Category::Eof => "LinkedIn inbox provenance eof",
                })
            })?;
        rows.push(decoded);
    }
    rows.sort_by(|a, b| {
        a.thread_id
            .cmp(&b.thread_id)
            .then_with(|| a.message_id.cmp(&b.message_id))
    });
    Ok(rows)
}

fn linkedin_inbox_seen_key(
    config: &LinkedInInboxSyncConfig,
    message: &LinkedInConversationMessage,
) -> String {
    format!(
        "{LINKEDIN_INBOX_SYNC_SEEN_PREFIX}{}",
        linkedin_inbox_message_key_hash(config, message)
    )
}

fn linkedin_inbox_provenance_key(
    config: &LinkedInInboxSyncConfig,
    message: &LinkedInConversationMessage,
) -> String {
    format!(
        "{LINKEDIN_INBOX_SYNC_PROVENANCE_PREFIX}{}",
        linkedin_inbox_message_key_hash(config, message)
    )
}

fn linkedin_inbox_message_key_hash(
    config: &LinkedInInboxSyncConfig,
    message: &LinkedInConversationMessage,
) -> String {
    let (session_kind, session_ref) = match config.session_ref.as_deref() {
        Some(session_ref) => ("session", session_ref),
        None => ("no-session", ""),
    };
    event_hash(
        [
            config.receiving_address_or_handle.as_str(),
            session_kind,
            session_ref,
            message.thread_id.as_str(),
            message.message_id.as_str(),
        ]
        .as_slice(),
    )
}

fn linkedin_inbox_sync_dedupe_key(config: &LinkedInInboxSyncConfig) -> String {
    let session_ref = config.session_ref.as_deref().unwrap_or("no-session");
    format!(
        "{LINKEDIN_INBOX_SYNC_DEDUPE_PREFIX}{}:{}",
        event_hash([&config.receiving_address_or_handle, session_ref].as_slice()),
        config.backfill_window_secs
    )
}

fn optional_section_text<'a>(payload: &'a Value, section: &str) -> Result<Option<&'a str>> {
    let Some(sections) = payload.get("sections") else {
        return Ok(None);
    };
    let Some(sections) = sections.as_object() else {
        return Err(Error::InvalidConfig(
            "LinkedIn MCP sections must be an object".to_owned(),
        ));
    };
    let Some(section_value) = sections.get(section) else {
        return Ok(None);
    };
    section_value.as_str().map(Some).ok_or_else(|| {
        Error::InvalidConfig(format!("LinkedIn MCP sections.{section} must be a string"))
    })
}

fn section_references<'a>(payload: &'a Value, section: &str) -> Vec<&'a Value> {
    payload
        .get("references")
        .and_then(|references| references.get(section))
        .and_then(Value::as_array)
        .map(|references| references.iter().collect())
        .unwrap_or_default()
}

fn reference_kind_is(reference: &Value, kind: &str) -> bool {
    reference.get("kind").and_then(Value::as_str) == Some(kind)
}

fn first_conversation_thread_id(references: &[&Value]) -> Result<Option<String>> {
    for reference in references {
        if !reference_kind_is(reference, "conversation") {
            continue;
        }
        if let Some(thread_id) = thread_id_from_reference(reference)? {
            return Ok(Some(thread_id));
        }
    }
    Ok(None)
}

fn thread_id_from_reference(reference: &Value) -> Result<Option<String>> {
    if let Some(thread_id) = reference.get("thread_id").and_then(Value::as_str) {
        return normalize_thread_id(thread_id).map(Some);
    }
    if let Some(url) = reference.get("url").and_then(Value::as_str) {
        return thread_id_from_url(url);
    }
    Ok(None)
}

fn thread_id_from_payload_url(payload: &Value) -> Result<Option<String>> {
    if let Some(url) = payload.get("url").and_then(Value::as_str) {
        return thread_id_from_url(url);
    }
    Ok(None)
}

fn thread_id_from_url(url: &str) -> Result<Option<String>> {
    let marker = "/messaging/thread/";
    let Some((_, rest)) = url.split_once(marker) else {
        return Ok(None);
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    normalize_thread_id(&rest[..end]).map(Some)
}

fn normalize_thread_id(thread_id: &str) -> Result<String> {
    let thread_id = thread_id.trim();
    if thread_id.is_empty() {
        return Err(Error::InvalidConfig(
            "LinkedIn thread id must be non-empty".to_owned(),
        ));
    }
    if thread_id.len() > MAX_LINKEDIN_THREAD_ID_BYTES {
        return Err(Error::InvalidConfig(
            "LinkedIn thread id exceeds maximum length".to_owned(),
        ));
    }
    if thread_id
        .bytes()
        .any(|byte| byte.is_ascii_whitespace() || matches!(byte, b'/' | b'?' | b'#' | b':'))
    {
        return Err(Error::InvalidConfig(
            "LinkedIn thread id contains a reserved delimiter".to_owned(),
        ));
    }
    Ok(thread_id.to_owned())
}

fn normalize_message_id(message_id: &str) -> Result<String> {
    let message_id = message_id.trim();
    if message_id.is_empty() {
        return Err(Error::InvalidConfig(
            "LinkedIn message id must be non-empty".to_owned(),
        ));
    }
    if message_id.len() > MAX_LINKEDIN_MESSAGE_ID_BYTES {
        return Err(Error::InvalidConfig(
            "LinkedIn message id exceeds maximum length".to_owned(),
        ));
    }
    Ok(message_id.to_owned())
}

fn counterparty_key(thread_id: &str) -> String {
    format!("linkedin:thread:{thread_id}")
}

fn verified_send_receipt_fields(plan: &LinkedInVerifiedSendPlan) -> BTreeMap<String, String> {
    let message_ref = linkedin_thread_message_ref(&plan.thread_id, &plan.message_text);
    BTreeMap::from([
        (
            RECEIPT_FIELD_LINKEDIN_THREAD_REF.to_owned(),
            counterparty_key(&plan.thread_id),
        ),
        (
            RECEIPT_FIELD_ARTIFACT_THREAD_MESSAGE_REF.to_owned(),
            message_ref,
        ),
    ])
}

fn plan_matches_gated_counterparty(
    plan: &LinkedInVerifiedSendPlan,
    gated_counterparty: &str,
) -> bool {
    gated_counterparty == plan.recipient_key
        || gated_counterparty == counterparty_key(&plan.thread_id)
}

struct LinkedInObservedMessage {
    message_ref: String,
    occurrence_count: usize,
    tail_matches: bool,
}

fn observed_message(
    output: &Value,
    expected_thread_id: &str,
    message_text: &str,
) -> Result<Option<LinkedInObservedMessage>> {
    let payload = mcp_payload(output)?;
    let observed_thread_id = match thread_id_from_payload_url(&payload)? {
        Some(thread_id) => thread_id,
        None => first_conversation_thread_id(&section_references(&payload, "conversation"))?
            .unwrap_or_else(|| expected_thread_id.to_owned()),
    };
    if observed_thread_id != expected_thread_id {
        return Ok(None);
    }
    let Some(conversation_text) = optional_section_text(&payload, "conversation")? else {
        return Ok(None);
    };
    let occurrence_count = conversation_message_occurrence_count(conversation_text, message_text);
    if occurrence_count == 0 {
        return Ok(None);
    }
    Ok(Some(LinkedInObservedMessage {
        message_ref: linkedin_thread_message_ref(expected_thread_id, message_text),
        occurrence_count,
        tail_matches: conversation_ends_with_message(conversation_text, message_text),
    }))
}

fn linkedin_thread_message_ref(thread_id: &str, message_text: &str) -> String {
    format!(
        "{}@message:{}",
        counterparty_key(thread_id),
        event_hash(["send_message", thread_id, message_text].as_slice())
    )
}

fn conversation_message_occurrence_count(conversation_text: &str, message_text: &str) -> usize {
    let message = normalize_whitespace(message_text);
    if message.is_empty() {
        return 0;
    }
    let conversation_lines = conversation_text
        .lines()
        .map(normalize_whitespace)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    if conversation_lines.is_empty() {
        return 0;
    }
    let message_line_count = message_text
        .lines()
        .map(normalize_whitespace)
        .filter(|line| !line.is_empty())
        .count()
        .max(1);
    if message_line_count > conversation_lines.len() {
        return 0;
    }
    conversation_lines
        .windows(message_line_count)
        .filter(|window| normalize_whitespace(&window.join(" ")) == message)
        .count()
}

fn conversation_ends_with_message(conversation_text: &str, message_text: &str) -> bool {
    let message = normalize_whitespace(message_text);
    if message.is_empty() {
        return false;
    }
    let conversation_lines = conversation_text
        .lines()
        .map(normalize_whitespace)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    let message_line_count = message_text
        .lines()
        .map(normalize_whitespace)
        .filter(|line| !line.is_empty())
        .count()
        .max(1);
    if message_line_count > conversation_lines.len() {
        return false;
    }
    let tail = conversation_lines[conversation_lines.len() - message_line_count..].join(" ");
    normalize_whitespace(&tail) == message
}

fn normalize_whitespace(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn sleep_before_next_linkedin_observation(attempt: usize) {
    let attempt = u64::try_from(attempt).unwrap_or(u64::MAX);
    let delay_ms = LINKEDIN_SEND_VERIFY_BACKOFF_INITIAL_MS
        .saturating_mul(attempt)
        .min(LINKEDIN_SEND_VERIFY_BACKOFF_MAX_MS);
    if delay_ms > 0 {
        std::thread::sleep(Duration::from_millis(delay_ms));
    }
}

fn receipt_error_code(value: &str) -> String {
    let normalized = value
        .trim()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | ':') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    let normalized = normalized.trim_matches('_');
    if normalized.is_empty() {
        return "unknown".to_owned();
    }
    normalized
        .chars()
        .take(MAX_LINKEDIN_ERROR_CODE_BYTES)
        .collect()
}

fn bounded_identifier(
    value: String,
    max_bytes: usize,
    too_long_message: &'static str,
) -> Result<String> {
    if value.len() > max_bytes {
        return Err(Error::InvalidConfig(too_long_message.to_owned()));
    }
    Ok(value)
}

fn bounded_ref(
    value: String,
    blank_message: &'static str,
    too_long_message: &'static str,
) -> Result<String> {
    normalize_non_blank(
        value,
        MAX_LINKEDIN_SESSION_REF_BYTES,
        blank_message,
        too_long_message,
    )
}

fn vault_scoped_secret_ref(value: String) -> Result<String> {
    let value = bounded_ref(
        value,
        "LinkedIn session cookie secret ref must be non-empty",
        "LinkedIn session cookie secret ref exceeds maximum length",
    )?;
    if !value.starts_with("vault-secret:") {
        return Err(Error::InvalidConfig(
            "LinkedIn session cookie secret ref must be vault-scoped".to_owned(),
        ));
    }
    Ok(value)
}

fn event_hash(parts: &[&str]) -> String {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update(&[0]);
    }
    let hex = hasher.finalize().to_hex().to_string();
    hex[..16].to_owned()
}

fn normalize_non_blank(
    value: String,
    max_bytes: usize,
    blank_message: &'static str,
    too_long_message: &'static str,
) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(Error::InvalidConfig(blank_message.to_owned()));
    }
    if value.len() > max_bytes {
        return Err(Error::InvalidConfig(too_long_message.to_owned()));
    }
    Ok(value.to_owned())
}

fn normalize_verb_key(verb: &str) -> String {
    verb.trim().to_ascii_lowercase().replace(['-', '.'], "_")
}
