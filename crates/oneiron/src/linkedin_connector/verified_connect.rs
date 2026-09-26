//! Connect-request execution with fresh profile observations and fail-closed retries.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::error::{Error, Result};
use crate::outbound::{OutboundExecutionOutcome, OutboundExecutionRequest, OutboundExecutionSink};

use super::normalize_keys::normalize_non_blank;
use super::verified_send::{receipt_error_code, sleep_before_next_linkedin_observation};
use super::{
    DEFAULT_LINKEDIN_SEND_VERIFY_ATTEMPTS, LINKEDIN_CHANNEL, LINKEDIN_CONNECT_REQUEST_VERB,
    LINKEDIN_MCP_CONNECT_WITH_PERSON_TOOL, LinkedInMcpConnectorAdapter,
    MAX_LINKEDIN_INTENT_REF_BYTES, MAX_LINKEDIN_MESSAGE_TEXT_BYTES,
    MAX_LINKEDIN_RECIPIENT_KEY_BYTES, MAX_LINKEDIN_SEND_VERIFY_ATTEMPTS,
    RECEIPT_FIELD_DUPLICATE_SEND_GUARD, RECEIPT_FIELD_VERIFICATION_ATTEMPTS,
    RECEIPT_FIELD_VERIFY_TOOL,
};

const CONNECT_CALLED: &str = "connect_with_person_called";
const CONNECT_VERIFICATION: &str = "linkedin_connect_verification";

/// A fresh provider profile read, normalized by the trusted host adapter.
/// A cached `connect_with_person` result is not an observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkedInConnectionState {
    Connectable,
    Pending,
    Connected,
}

impl LinkedInConnectionState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Connectable => "connectable",
            Self::Pending => "pending",
            Self::Connected => "connected",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedInConnectionObservation {
    pub recipient_key: String,
    pub state: LinkedInConnectionState,
}

/// Host-resolved recipient and optional note for one intent. The host must
/// resolve `content_ref` before sending and mark resumed attempts retry-guarded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedInVerifiedConnectPlan {
    pub recipient_key: String,
    pub note: Option<String>,
    pub max_observation_attempts: usize,
    pub guard_retry: bool,
}

impl LinkedInVerifiedConnectPlan {
    pub fn new(recipient_key: impl Into<String>, note: Option<String>) -> Result<Self> {
        Ok(Self {
            recipient_key: normalize_non_blank(
                recipient_key.into(),
                MAX_LINKEDIN_RECIPIENT_KEY_BYTES,
                "LinkedIn recipient key must be non-empty",
                "LinkedIn recipient key exceeds maximum length",
            )?,
            note: note
                .map(|note| {
                    normalize_non_blank(
                        note,
                        MAX_LINKEDIN_MESSAGE_TEXT_BYTES,
                        "LinkedIn connection note must be non-empty",
                        "LinkedIn connection note exceeds maximum length",
                    )
                })
                .transpose()?,
            max_observation_attempts: DEFAULT_LINKEDIN_SEND_VERIFY_ATTEMPTS,
            guard_retry: false,
        })
    }

    pub fn with_max_observation_attempts(mut self, attempts: usize) -> Result<Self> {
        if attempts == 0 || attempts > MAX_LINKEDIN_SEND_VERIFY_ATTEMPTS {
            return Err(Error::InvalidConfig(format!(
                "LinkedIn verify-after-connect attempts must be 1..={MAX_LINKEDIN_SEND_VERIFY_ATTEMPTS}"
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

/// Exact call arguments passed to the member-session transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedInMcpConnectRequest {
    pub recipient_key: String,
    pub note: Option<String>,
    pub intent_ref: String,
}

/// The profile read must query the provider again, not echo the connect result.
/// The host maps missing/ambiguous profile state to Err (never Connectable).
pub trait LinkedInMcpConnectTransport {
    fn connect_with_person(
        &mut self,
        request: &LinkedInMcpConnectRequest,
    ) -> std::result::Result<Value, String>;

    fn get_person_profile(
        &mut self,
        recipient_key: &str,
    ) -> std::result::Result<LinkedInConnectionObservation, String>;
}

/// OF-327 execution sink for `linkedin.connect_request`.
pub struct LinkedInMcpVerifiedConnectSink<T> {
    adapter: LinkedInMcpConnectorAdapter,
    transport: T,
    plans: BTreeMap<String, LinkedInVerifiedConnectPlan>,
    attempted: std::collections::BTreeSet<String>,
}

impl<T> LinkedInMcpVerifiedConnectSink<T> {
    #[must_use]
    pub fn new(adapter: LinkedInMcpConnectorAdapter, transport: T) -> Self {
        Self {
            adapter,
            transport,
            plans: BTreeMap::new(),
            attempted: std::collections::BTreeSet::new(),
        }
    }

    pub fn with_plan(
        mut self,
        intent_ref: impl Into<String>,
        plan: LinkedInVerifiedConnectPlan,
    ) -> Result<Self> {
        self.add_plan(intent_ref, plan)?;
        Ok(self)
    }

    pub fn add_plan(
        &mut self,
        intent_ref: impl Into<String>,
        plan: LinkedInVerifiedConnectPlan,
    ) -> Result<()> {
        let intent_ref = normalize_non_blank(
            intent_ref.into(),
            MAX_LINKEDIN_INTENT_REF_BYTES,
            "LinkedIn verified-connect intent ref must be non-empty",
            "LinkedIn verified-connect intent ref exceeds maximum length",
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

impl<T: LinkedInMcpConnectTransport> OutboundExecutionSink for LinkedInMcpVerifiedConnectSink<T> {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        if request.intent.channel != LINKEDIN_CHANNEL
            || request.verb_contract.kind != LINKEDIN_CONNECT_REQUEST_VERB
            || self.adapter.mcp_tool_for_verb(&request.verb_contract.kind)
                != Some(LINKEDIN_MCP_CONNECT_WITH_PERSON_TOOL)
        {
            return OutboundExecutionOutcome::failed(
                "linkedin_verified_connect_requires_connect_request",
            );
        }
        let Some(plan) = self.plans.get(request.intent_ref).cloned() else {
            return OutboundExecutionOutcome::failed("linkedin_verified_connect_plan_missing");
        };
        let mut fields = BTreeMap::from([
            (CONNECT_CALLED.to_owned(), "false".to_owned()),
            (
                "connect_with_person_return_trusted".to_owned(),
                "false".to_owned(),
            ),
            (
                RECEIPT_FIELD_VERIFY_TOOL.to_owned(),
                "get_person_profile".to_owned(),
            ),
        ]);
        if request.counterparty_ref.unwrap_or(&request.intent.target) != plan.recipient_key
            || request.intent.target != plan.recipient_key
        {
            fields.insert(
                CONNECT_VERIFICATION.to_owned(),
                "target_mismatch".to_owned(),
            );
            return OutboundExecutionOutcome::failed("linkedin_verified_connect_target_mismatch")
                .with_receipt_fields(fields);
        }
        let attempted_before = self.attempted.contains(request.intent_ref);
        let guard_retry = plan.guard_retry || attempted_before;
        let pre = match self.read_state(&plan.recipient_key) {
            Ok(state) => state,
            Err(err) => {
                fields.insert(
                    CONNECT_VERIFICATION.to_owned(),
                    "precheck_failed".to_owned(),
                );
                fields.insert("verify_precheck_error".to_owned(), err);
                return OutboundExecutionOutcome::failed("verify_after_connect_precheck_failed")
                    .with_receipt_fields(fields);
            }
        };
        fields.insert(
            "connection_state_before".to_owned(),
            pre.as_str().to_owned(),
        );
        if matches!(
            pre,
            LinkedInConnectionState::Pending | LinkedInConnectionState::Connected
        ) {
            fields.insert(
                RECEIPT_FIELD_DUPLICATE_SEND_GUARD.to_owned(),
                "observed_existing".to_owned(),
            );
            fields.insert(
                CONNECT_VERIFICATION.to_owned(),
                "connection_observed".to_owned(),
            );
            fields.insert(
                RECEIPT_FIELD_VERIFICATION_ATTEMPTS.to_owned(),
                "1".to_owned(),
            );
            if guard_retry {
                return verified_connection(&plan, pre, fields);
            }
            return OutboundExecutionOutcome::failed("verify_after_connect_existing_connection")
                .with_receipt_fields(fields);
        }
        if guard_retry {
            fields.insert(
                RECEIPT_FIELD_DUPLICATE_SEND_GUARD.to_owned(),
                "retry_unconfirmed".to_owned(),
            );
            fields.insert(
                CONNECT_VERIFICATION.to_owned(),
                "retry_unconfirmed".to_owned(),
            );
            return OutboundExecutionOutcome::failed("verify_after_connect_retry_unconfirmed")
                .with_receipt_fields(fields);
        }

        // Record the attempted intent before calling the provider. A failed or
        // ambiguous tool response may still have sent the request.
        self.attempted.insert(request.intent_ref.to_owned());
        fields.insert(CONNECT_CALLED.to_owned(), "true".to_owned());
        let call = LinkedInMcpConnectRequest {
            recipient_key: plan.recipient_key.clone(),
            note: plan.note.clone(),
            intent_ref: request.intent_ref.to_owned(),
        };
        match self.transport.connect_with_person(&call) {
            Ok(_) => {
                fields.insert(
                    "connect_with_person_result".to_owned(),
                    "ignored".to_owned(),
                );
            }
            Err(err) => {
                fields.insert("connect_with_person_result".to_owned(), "failed".to_owned());
                fields.insert(
                    "connect_with_person_tool_error".to_owned(),
                    receipt_error_code(&err),
                );
            }
        }
        let mut last_error = None;
        for attempt in 1..=plan.max_observation_attempts {
            match self.read_state(&plan.recipient_key) {
                Ok(
                    state @ (LinkedInConnectionState::Pending | LinkedInConnectionState::Connected),
                ) => {
                    fields.insert(
                        RECEIPT_FIELD_VERIFICATION_ATTEMPTS.to_owned(),
                        attempt.to_string(),
                    );
                    fields.insert(
                        CONNECT_VERIFICATION.to_owned(),
                        "connection_observed".to_owned(),
                    );
                    return verified_connection(&plan, state, fields);
                }
                Ok(LinkedInConnectionState::Connectable) => {
                    last_error = None;
                }
                Err(err) => {
                    last_error = Some(err);
                }
            }
            if attempt < plan.max_observation_attempts {
                sleep_before_next_linkedin_observation(attempt);
            }
        }
        fields.insert(
            RECEIPT_FIELD_VERIFICATION_ATTEMPTS.to_owned(),
            plan.max_observation_attempts.to_string(),
        );
        let reason = if let Some(err) = last_error {
            fields.insert(
                CONNECT_VERIFICATION.to_owned(),
                "profile_read_failed".to_owned(),
            );
            fields.insert("verify_profile_error".to_owned(), err);
            "verify_after_connect_profile_read_failed"
        } else {
            fields.insert(
                CONNECT_VERIFICATION.to_owned(),
                "connection_not_observed".to_owned(),
            );
            "verify_after_connect_not_observed"
        };
        OutboundExecutionOutcome::failed(reason)
            .with_receipt_fields(fields)
            .with_possible_delivery()
    }
}

impl<T: LinkedInMcpConnectTransport> LinkedInMcpVerifiedConnectSink<T> {
    fn read_state(
        &mut self,
        recipient_key: &str,
    ) -> std::result::Result<LinkedInConnectionState, String> {
        let observed = self
            .transport
            .get_person_profile(recipient_key)
            .map_err(|err| receipt_error_code(&err))?;
        if observed.recipient_key != recipient_key {
            return Err("profile_target_mismatch".to_owned());
        }
        Ok(observed.state)
    }
}

fn verified_connection(
    plan: &LinkedInVerifiedConnectPlan,
    state: LinkedInConnectionState,
    mut fields: BTreeMap<String, String>,
) -> OutboundExecutionOutcome {
    fields.insert(
        "connection_state_after".to_owned(),
        state.as_str().to_owned(),
    );
    let provider_ref = format!("{}@connection", plan.recipient_key);
    fields.insert("linkedin_connection_ref".to_owned(), provider_ref.clone());
    OutboundExecutionOutcome::delivered_to_channel(provider_ref).with_receipt_fields(fields)
}
