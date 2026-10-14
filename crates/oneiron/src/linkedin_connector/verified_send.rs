//! Verify-after-send plan, sink, observation, and receipt helpers.

use std::collections::BTreeMap;
use std::time::Duration;

use serde_json::Value;

use crate::error::{Error, Result};
use crate::outbound::{OutboundExecutionOutcome, OutboundExecutionRequest, OutboundExecutionSink};

use super::inbox_sync::mcp_payload;
use super::normalize_keys::{
    counterparty_key, event_hash, first_conversation_thread_id, normalize_non_blank,
    normalize_thread_id, optional_section_text, section_references, thread_id_from_payload_url,
};
use super::{
    DEFAULT_LINKEDIN_SEND_VERIFY_ATTEMPTS, LINKEDIN_CHANNEL, LINKEDIN_MCP_SEND_MESSAGE_TOOL,
    LINKEDIN_SEND_DM_VERB, LINKEDIN_SEND_VERIFY_BACKOFF_INITIAL_MS,
    LINKEDIN_SEND_VERIFY_BACKOFF_MAX_MS, LinkedInMcpConnectorAdapter,
    MAX_LINKEDIN_ERROR_CODE_BYTES, MAX_LINKEDIN_INTENT_REF_BYTES, MAX_LINKEDIN_MESSAGE_TEXT_BYTES,
    MAX_LINKEDIN_RECIPIENT_KEY_BYTES, MAX_LINKEDIN_SEND_VERIFY_ATTEMPTS,
    RECEIPT_FIELD_ARTIFACT_THREAD_MESSAGE_REF, RECEIPT_FIELD_DUPLICATE_SEND_GUARD,
    RECEIPT_FIELD_LINKEDIN_THREAD_REF, RECEIPT_FIELD_POST_SEND_MATCH_COUNT,
    RECEIPT_FIELD_PRE_SEND_MATCH_COUNT, RECEIPT_FIELD_RETRY_WINDOW,
    RECEIPT_FIELD_SEND_MESSAGE_CALLED, RECEIPT_FIELD_SEND_MESSAGE_RESULT,
    RECEIPT_FIELD_SEND_MESSAGE_RETURN_TRUSTED, RECEIPT_FIELD_SEND_MESSAGE_TOOL_ERROR,
    RECEIPT_FIELD_VERIFICATION_ATTEMPTS, RECEIPT_FIELD_VERIFICATION_STATE,
    RECEIPT_FIELD_VERIFY_TOOL,
};

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

        let self_key = self.adapter.receiving_address_or_handle().to_owned();
        let (pre_send_match_count, pre_send_ids) =
            match self.transport.get_conversation(&plan.thread_id) {
                Ok(output) => {
                    // Every id the thread held before the send, in order,
                    // whatever its sender or text: a message that was already
                    // there, even one edited to the text since, is never the
                    // new send, and the new send follows the last of them.
                    let pre_send_ids = transcript_message_ids(&output, &plan.thread_id);
                    match observed_message(&output, &plan.thread_id, &plan.message_text, &self_key)
                    {
                        Ok(Some(observation)) => {
                            fields.insert(
                                RECEIPT_FIELD_PRE_SEND_MATCH_COUNT.to_owned(),
                                observation.occurrence_count.to_string(),
                            );
                            if plan.guard_retry && observation.tail_matches {
                                fields.insert(
                                    RECEIPT_FIELD_SEND_MESSAGE_CALLED.to_owned(),
                                    "false".to_owned(),
                                );
                                fields.insert(
                                    RECEIPT_FIELD_VERIFICATION_ATTEMPTS.to_owned(),
                                    "1".to_owned(),
                                );
                                // A matching tail stops a second send, but it is
                                // never this intent's delivery: text alone may be
                                // the recipient's echo, and even this seat's own
                                // message may be an older one that no earlier
                                // attempt of this intent can be shown to have sent.
                                let (guard, state, reason) = if observation.own_tail_id.is_some() {
                                    (
                                        "observed_existing",
                                        "content_observed_unbound",
                                        "verify_after_send_existing_unbound",
                                    )
                                } else {
                                    (
                                        "observed_existing_unattributed",
                                        "content_observed_unattributed",
                                        "verify_after_send_unattributed_existing",
                                    )
                                };
                                fields.insert(
                                    RECEIPT_FIELD_DUPLICATE_SEND_GUARD.to_owned(),
                                    guard.to_owned(),
                                );
                                fields.insert(
                                    RECEIPT_FIELD_VERIFICATION_STATE.to_owned(),
                                    state.to_owned(),
                                );
                                return OutboundExecutionOutcome::failed(reason)
                                    .with_possible_delivery()
                                    .with_receipt_fields(fields);
                            }
                            if plan.guard_retry {
                                fields.insert(
                                    RECEIPT_FIELD_DUPLICATE_SEND_GUARD.to_owned(),
                                    "observed_existing_not_tail".to_owned(),
                                );
                            }
                            (observation.occurrence_count, pre_send_ids)
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
                            (0, pre_send_ids)
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
        let mut observed_unattributed = false;
        let mut post_send_match_count = 0;
        for attempt in 1..=plan.max_observation_attempts {
            match self.transport.get_conversation(&plan.thread_id) {
                Ok(output) => {
                    let post_send_ids = transcript_message_ids(&output, &plan.thread_id);
                    match observed_message(&output, &plan.thread_id, &plan.message_text, &self_key)
                    {
                        // Delivered means the thread now ends with a message
                        // this seat sent, with the text, under an id the thread
                        // did not hold before the send, after the last message
                        // the precheck saw. Text the transcript does not
                        // attribute proves nothing (the recipient can write the
                        // same words); without a complete pre-send id list no id
                        // can be shown new; and a page that no longer holds the
                        // precheck's last message may be another page of older
                        // messages.
                        Ok(Some(observation))
                            if is_the_new_send(
                                observation.own_tail_id.as_deref(),
                                pre_send_ids.as_deref(),
                                post_send_ids.as_deref(),
                            ) =>
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
                            if (!observation.attributed || pre_send_ids.is_none())
                                && observation.tail_matches
                                && observation.occurrence_count > pre_send_match_count
                            {
                                observed_unattributed = true;
                            } else {
                                observed_stale = true;
                            }
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
            } else if observed_unattributed {
                "content_observed_unattributed"
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
        } else if observed_unattributed {
            OutboundExecutionOutcome::failed("verify_after_send_unattributed")
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

struct LinkedInObservedMessage {
    message_ref: String,
    occurrence_count: usize,
    tail_matches: bool,
    /// The transcript names who sent each message. `false` for page text.
    attributed: bool,
    /// The provider id of the last message, when it matches, the transcript
    /// says this seat sent it, and it carries an id.
    own_tail_id: Option<String>,
}

fn observed_message(
    output: &Value,
    expected_thread_id: &str,
    message_text: &str,
    self_key: &str,
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
    let message_ref = linkedin_thread_message_ref(expected_thread_id, message_text);
    if let Some(messages) = payload.get("messages").and_then(Value::as_array) {
        return Ok(
            attributed_observation(messages, message_text, self_key).map(|observation| {
                LinkedInObservedMessage {
                    message_ref,
                    ..observation
                }
            }),
        );
    }
    let Some(conversation_text) = optional_section_text(&payload, "conversation")? else {
        return Ok(None);
    };
    let occurrence_count = conversation_message_occurrence_count(conversation_text, message_text);
    if occurrence_count == 0 {
        return Ok(None);
    }
    Ok(Some(LinkedInObservedMessage {
        message_ref,
        occurrence_count,
        tail_matches: conversation_ends_with_message(conversation_text, message_text),
        attributed: false,
        own_tail_id: None,
    }))
}

/// The id of every message in a structured transcript of `expected_thread_id`,
/// in transcript order, whatever its sender or text. `None` when no later id
/// can be shown new against it: the transport supplies page text only, a
/// transcript of another thread, an empty page, or a message with no id (that
/// message may come back with one on a later read).
fn transcript_message_ids(output: &Value, expected_thread_id: &str) -> Option<Vec<String>> {
    let payload = mcp_payload(output).ok()?;
    let observed_thread_id = match thread_id_from_payload_url(&payload).ok()? {
        Some(thread_id) => thread_id,
        None => first_conversation_thread_id(&section_references(&payload, "conversation"))
            .ok()?
            .unwrap_or_else(|| expected_thread_id.to_owned()),
    };
    if observed_thread_id != expected_thread_id {
        return None;
    }
    let messages = payload.get("messages").and_then(Value::as_array)?;
    let ids = messages
        .iter()
        .map(message_id)
        .collect::<Option<Vec<_>>>()?;
    (!ids.is_empty()).then_some(ids)
}

/// `tail` is the new send: the post-send transcript `after` ends with it, the
/// precheck `before` did not hold it, and `after` still holds the precheck's
/// last message, so the page is the same thread read later, not another page
/// of older messages. Any of the three unknown proves nothing.
fn is_the_new_send(
    tail: Option<&str>,
    before: Option<&[String]>,
    after: Option<&[String]>,
) -> bool {
    let (Some(tail), Some(before), Some(after)) = (tail, before, after) else {
        return false;
    };
    let Some(high_water) = before.last() else {
        return false;
    };
    after.last().is_some_and(|last| last == tail)
        && !before.iter().any(|id| id == tail)
        && after.iter().any(|id| id == high_water)
}

/// A message's provider id: the first non-blank id field, trimmed.
fn message_id(message: &Value) -> Option<String> {
    let object = message.as_object()?;
    ["id", "message_id", "messageId", "urn", "entity_urn"]
        .iter()
        .find_map(|key| {
            let id = object.get(*key)?.as_str()?.trim();
            (!id.is_empty()).then(|| id.to_owned())
        })
}

/// Reads a transcript whose messages carry an id and a sender. A message is
/// this seat's only when its `sender` is the seat's own key; a message with
/// no id, or a blank one, cannot be told apart from an earlier one, so it is
/// never counted as this seat's.
fn attributed_observation(
    messages: &[Value],
    message_text: &str,
    self_key: &str,
) -> Option<LinkedInObservedMessage> {
    let wanted = normalize_whitespace(message_text);
    let mut occurrence_count = 0;
    let mut tail = (false, None);
    for message in messages {
        let object = message.as_object();
        let field = |keys: &[&str]| {
            object.and_then(|object| keys.iter().find_map(|key| object.get(*key)?.as_str()))
        };
        let matches = field(&["text", "body", "content", "message"])
            .is_some_and(|text| normalize_whitespace(text) == wanted);
        let own_id = if matches && field(&["sender"]) == Some(self_key) {
            message_id(message)
        } else {
            None
        };
        tail = (matches, own_id);
        if matches {
            occurrence_count += 1;
        }
    }
    (occurrence_count > 0).then(|| LinkedInObservedMessage {
        message_ref: String::new(),
        occurrence_count,
        tail_matches: tail.0,
        attributed: true,
        own_tail_id: tail.1,
    })
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

pub(super) fn normalize_whitespace(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub(super) fn sleep_before_next_linkedin_observation(attempt: usize) {
    let attempt = u64::try_from(attempt).unwrap_or(u64::MAX);
    let delay_ms = LINKEDIN_SEND_VERIFY_BACKOFF_INITIAL_MS
        .saturating_mul(attempt)
        .min(LINKEDIN_SEND_VERIFY_BACKOFF_MAX_MS);
    if delay_ms > 0 {
        std::thread::sleep(Duration::from_millis(delay_ms));
    }
}

pub(super) fn receipt_error_code(value: &str) -> String {
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

fn linkedin_thread_message_ref(thread_id: &str, message_text: &str) -> String {
    format!(
        "{}@message:{}",
        counterparty_key(thread_id),
        event_hash(["send_message", thread_id, message_text].as_slice())
    )
}
