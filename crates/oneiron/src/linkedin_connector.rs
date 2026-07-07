//! LinkedIn connector adapter surface (ONE-1563 / LNKD-1).
//!
//! The first LinkedIn implementation rides the session-bound
//! `stickerdaniel/linkedin-mcp-server` tool surface. This module keeps that
//! boundary local and testable: it maps recorded MCP read outputs into
//! OF-247 `InboundSurfaceEventInput` values without starting a browser or
//! touching a live LinkedIn session.

use std::collections::{BTreeMap, HashSet};
use std::time::Duration;

use serde_json::Value;

use crate::error::{Error, Result};
use crate::outbound::{OutboundExecutionOutcome, OutboundExecutionRequest, OutboundExecutionSink};
use crate::surface_event::{InboundSurfaceEventInput, SurfaceCounterpartyStamp};

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

const MAX_LINKEDIN_ADDRESS_BYTES: usize = 512;
const MAX_LINKEDIN_SESSION_REF_BYTES: usize = 512;
const MAX_LINKEDIN_THREAD_ID_BYTES: usize = 256;
const MAX_LINKEDIN_EVENT_ID_BYTES: usize = 384;
const MAX_LINKEDIN_PAYLOAD_REF_BYTES: usize = 384;
const MAX_LINKEDIN_COUNTERPARTY_KEY_BYTES: usize = 320;
const MAX_LINKEDIN_RECIPIENT_KEY_BYTES: usize = 512;
const MAX_LINKEDIN_MESSAGE_TEXT_BYTES: usize = 16 * 1024;
const MAX_LINKEDIN_INTENT_REF_BYTES: usize = 512;
const MAX_LINKEDIN_ERROR_CODE_BYTES: usize = 96;
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

        self.execute_plan(request, &plan)
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

        if plan.guard_retry {
            match self.transport.get_conversation(&plan.thread_id) {
                Ok(output) => {
                    match observed_message_ref(&output, &plan.thread_id, &plan.message_text) {
                        Ok(Some(message_ref)) => {
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
                            return OutboundExecutionOutcome::delivered_to_channel(message_ref)
                                .with_receipt_fields(fields);
                        }
                        Ok(None) => {
                            fields.insert(
                                RECEIPT_FIELD_DUPLICATE_SEND_GUARD.to_owned(),
                                "observed_absent".to_owned(),
                            );
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
                            return OutboundExecutionOutcome::failed(
                                "verify_after_send_precheck_failed",
                            )
                            .with_receipt_fields(fields);
                        }
                    }
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
                    fields.insert("verify_precheck_error".to_owned(), receipt_error_code(&err));
                    return OutboundExecutionOutcome::failed("verify_after_send_precheck_failed")
                        .with_receipt_fields(fields);
                }
            }
        }

        let send_request = LinkedInMcpSendMessageRequest {
            recipient_key: plan.recipient_key.clone(),
            thread_id: plan.thread_id.clone(),
            message_text: plan.message_text.clone(),
            idempotency_key: request.intent.idempotency_key.clone(),
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
        for attempt in 1..=plan.max_observation_attempts {
            match self.transport.get_conversation(&plan.thread_id) {
                Ok(output) => {
                    match observed_message_ref(&output, &plan.thread_id, &plan.message_text) {
                        Ok(Some(message_ref)) => {
                            fields.insert(
                                RECEIPT_FIELD_VERIFICATION_STATE.to_owned(),
                                "content_observed".to_owned(),
                            );
                            fields.insert(
                                RECEIPT_FIELD_VERIFICATION_ATTEMPTS.to_owned(),
                                attempt.to_string(),
                            );
                            return OutboundExecutionOutcome::delivered_to_channel(message_ref)
                                .with_receipt_fields(fields);
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

        fields.insert(
            RECEIPT_FIELD_VERIFICATION_STATE.to_owned(),
            if last_get_error.is_some() {
                "get_conversation_failed"
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

fn observed_message_ref(
    output: &Value,
    expected_thread_id: &str,
    message_text: &str,
) -> Result<Option<String>> {
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
    if conversation_contains_message(conversation_text, message_text) {
        Ok(Some(linkedin_thread_message_ref(
            expected_thread_id,
            message_text,
        )))
    } else {
        Ok(None)
    }
}

fn linkedin_thread_message_ref(thread_id: &str, message_text: &str) -> String {
    format!(
        "{}@message:{}",
        counterparty_key(thread_id),
        event_hash(["send_message", thread_id, message_text].as_slice())
    )
}

fn conversation_contains_message(conversation_text: &str, message_text: &str) -> bool {
    let message = normalize_whitespace(message_text);
    if message.is_empty() {
        return false;
    }
    let conversation_lines = conversation_text
        .lines()
        .map(normalize_whitespace)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    if conversation_lines.is_empty() {
        return false;
    }
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
