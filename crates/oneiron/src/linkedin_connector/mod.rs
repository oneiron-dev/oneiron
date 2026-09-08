//! LinkedIn connector adapter surface (ONE-1563 / LNKD-1).
//!
//! The first LinkedIn implementation rides the session-bound
//! `stickerdaniel/linkedin-mcp-server` tool surface. This module keeps that
//! boundary local and testable: it maps recorded MCP read outputs into
//! OF-247 `InboundSurfaceEventInput` values without starting a browser or
//! touching a live LinkedIn session.

mod inbox_sync;
mod normalize_keys;
mod seat_policy;
mod verified_send;

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Vault;
use crate::attempt_queue::{AttemptQueue, EnqueueAttempt, EnqueueOutcome};
use crate::error::{Error, Result};
use crate::surface_event::{InboundSurfaceEventInput, SurfaceCounterpartyStamp};

pub use self::inbox_sync::{
    LinkedInConversationMessage, LinkedInConversationMessageEvent, LinkedInInboxSyncConfig,
    LinkedInInboxSyncReport, LinkedInInboxSyncRunner, LinkedInMcpInboxSyncTransport,
    linkedin_inbox_sync_provenance_rows, linkedin_inbox_sync_runner_from_attempt,
};
use self::inbox_sync::{
    conversation_messages_from_tool_output, mcp_payload, message_in_backfill_window,
    validate_inbox_sync_config_matches_adapter,
};
use self::normalize_keys::{
    bounded_identifier, bounded_ref, counterparty_key, event_hash, first_conversation_thread_id,
    linkedin_inbox_sync_dedupe_key, normalize_non_blank, normalize_verb_key, optional_section_text,
    reference_kind_is, section_references, thread_id_from_payload_url, thread_id_from_reference,
    vault_scoped_secret_ref,
};
pub use self::seat_policy::{
    LinkedInAccountRiskLimits, LinkedInConsentScreenCopy, LinkedInKillSwitchState,
    LinkedInSandboxHostHarness, LinkedInSeatDispatchState, LinkedInSeatPolicyAction,
    LinkedInSeatPolicyDecision, LinkedInSeatSandboxPolicy, linkedin_connect_consent_screen_copy,
    run_linkedin_kill_switch,
};
pub use self::verified_send::{
    LinkedInMcpSendMessageRequest, LinkedInMcpSendTransport, LinkedInMcpVerifiedSendSink,
    LinkedInVerifiedSendPlan,
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

/// Adapter for recorded `stickerdaniel/linkedin-mcp-server` messaging outputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedInMcpConnectorAdapter {
    receiving_address_or_handle: String,
    session_ref: Option<String>,
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
