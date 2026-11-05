//! LinkedIn seat policy values consumed by outbound admission.
use oneiron_contracts::error::{Error, Result};
use serde::{Deserialize, Serialize};

mod seat;
pub use seat::{
    LinkedInAccountRiskLimits, LinkedInKillSwitchState, LinkedInSeatDispatchState,
    LinkedInSeatPolicyAction, LinkedInSeatPolicyDecision, LinkedInSeatSandboxPolicy,
};

/// Stable Oneiron channel key for LinkedIn.
pub const LINKEDIN_CHANNEL: &str = "linkedin";

/// OF-327 connector verb for direct messages.
pub const LINKEDIN_SEND_DM_VERB: &str = "send_dm";

/// OF-327 connector verb for connection requests.
pub const LINKEDIN_CONNECT_REQUEST_VERB: &str = "connect_request";

/// Default D5 account-risk wall for one seat.
pub const LINKEDIN_DEFAULT_DAILY_DM_CAP: u16 = 15;

/// Default D5 profile-read wall for one seat.
pub const LINKEDIN_DEFAULT_DAILY_PROFILE_READ_CAP: u16 = 25;

/// Lower bound for human-cadence jitter between sends.
pub const LINKEDIN_DEFAULT_CADENCE_JITTER_MIN_SECONDS: u32 = 180;

/// Upper bound for human-cadence jitter between sends.
pub const LINKEDIN_DEFAULT_CADENCE_JITTER_MAX_SECONDS: u32 = 900;

pub const LINKEDIN_SEAT_VERB_CATALOG: &[&str] =
    &[LINKEDIN_SEND_DM_VERB, LINKEDIN_CONNECT_REQUEST_VERB];

pub const MAX_LINKEDIN_SESSION_REF_BYTES: usize = 512;

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

pub fn bounded_ref(
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

pub fn vault_scoped_secret_ref(value: String) -> Result<String> {
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

pub fn normalize_non_blank(
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
