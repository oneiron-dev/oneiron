//! Connection requests: observe, durably claim, send once, then observe again.
use std::collections::BTreeMap;

use serde_json::Value;

use super::normalize_keys::{event_hash, normalize_non_blank};
use super::{LINKEDIN_CHANNEL, LINKEDIN_CONNECT_REQUEST_VERB};
use crate::outbound::{OutboundExecutionOutcome, OutboundExecutionRequest, OutboundExecutionSink};
use crate::{
    Vault,
    error::{Error, Result},
};

/// Provider state obtained by a fresh profile/connection read, never a send result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkedInConnectionState {
    NotConnected,
    RequestPending { provider_ref: String },
    Connected { provider_ref: String },
}

/// Host-resolved recipient and optional note for exactly one admitted intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedInVerifiedConnectPlan {
    recipient_key: String,
    note: Option<String>,
}

impl LinkedInVerifiedConnectPlan {
    pub fn new(recipient_key: impl Into<String>, note: Option<String>) -> Result<Self> {
        let recipient_key = normalize_non_blank(
            recipient_key.into(),
            super::MAX_LINKEDIN_RECIPIENT_KEY_BYTES,
            "LinkedIn recipient key must be non-empty",
            "LinkedIn recipient key exceeds maximum length",
        )?;
        if note
            .as_ref()
            .is_some_and(|note| note.trim().is_empty() || note.chars().count() > 300)
        {
            return Err(Error::InvalidConfig(
                "LinkedIn connection note must contain 1..=300 scalars".into(),
            ));
        }
        Ok(Self {
            recipient_key,
            note,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedInMcpConnectRequest {
    pub recipient_key: String,
    pub note: Option<String>,
    pub intent_ref: String,
}

/// MCP host adapter. Implementors re-read connection state after every send.
pub trait LinkedInMcpConnectTransport {
    fn connect_with_person(
        &mut self,
        request: &LinkedInMcpConnectRequest,
    ) -> std::result::Result<Value, String>;
    fn connection_state(
        &mut self,
        recipient: &str,
    ) -> std::result::Result<LinkedInConnectionState, String>;
}

/// OF-327 execution sink. A durable vault-local guard also covers a process crash
/// between provider execution and receipt persistence. An ambiguous send is never retried.
pub struct LinkedInMcpVerifiedConnectSink<'a, T> {
    vault: &'a Vault,
    transport: T,
    plans: BTreeMap<String, LinkedInVerifiedConnectPlan>,
}

impl<'a, T> LinkedInMcpVerifiedConnectSink<'a, T> {
    pub fn new(vault: &'a Vault, transport: T) -> Self {
        Self {
            vault,
            transport,
            plans: BTreeMap::new(),
        }
    }

    pub fn with_plan(
        mut self,
        intent_ref: impl Into<String>,
        plan: LinkedInVerifiedConnectPlan,
    ) -> Result<Self> {
        let key = normalize_non_blank(
            intent_ref.into(),
            super::MAX_LINKEDIN_INTENT_REF_BYTES,
            "LinkedIn connect intent must be non-empty",
            "LinkedIn connect intent exceeds maximum length",
        )?;
        if self.plans.contains_key(&key) {
            return Err(Error::InvalidConfig(
                "LinkedIn connect plan is already bound".into(),
            ));
        }
        self.plans.insert(key, plan);
        Ok(self)
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    fn claim(
        &self,
        request: &OutboundExecutionRequest<'_>,
        plan: &LinkedInVerifiedConnectPlan,
    ) -> Result<bool> {
        let key = format!("linkedin:connect:v1:{}", event_hash(&[request.intent_ref]));
        let binding = event_hash(&[
            &request.intent.actor,
            &plan.recipient_key,
            plan.note.as_deref().unwrap_or(""),
        ]);
        self.vault.with_write_txn(|txn| {
            if let Some(prior) = self.vault.store.vault_meta.get(txn, key.as_bytes())? {
                if prior != binding.as_bytes() {
                    return Err(Error::InvalidConfig(
                        "LinkedIn connect binding changed".into(),
                    ));
                }
                return Ok(false);
            }
            self.vault
                .store
                .vault_meta
                .put(txn, key.as_bytes(), binding.as_bytes())?;
            Ok(true)
        })
    }
}

fn observation(state: LinkedInConnectionState) -> Option<(String, &'static str)> {
    match state {
        LinkedInConnectionState::RequestPending { provider_ref }
            if !provider_ref.trim().is_empty() =>
        {
            Some((provider_ref, "request_pending"))
        }
        LinkedInConnectionState::Connected { provider_ref } if !provider_ref.trim().is_empty() => {
            Some((provider_ref, "connected"))
        }
        _ => None,
    }
}

impl<T: LinkedInMcpConnectTransport> OutboundExecutionSink
    for LinkedInMcpVerifiedConnectSink<'_, T>
{
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        if request.intent.channel != LINKEDIN_CHANNEL
            || request.verb_contract.kind != LINKEDIN_CONNECT_REQUEST_VERB
        {
            return OutboundExecutionOutcome::failed("linkedin_connect_requires_connect_request");
        }
        let Some(plan) = self.plans.get(request.intent_ref).cloned() else {
            return OutboundExecutionOutcome::failed("linkedin_connect_plan_missing");
        };
        if request.counterparty_ref.unwrap_or(&request.intent.target) != plan.recipient_key
            || request.intent.target != plan.recipient_key
        {
            return OutboundExecutionOutcome::failed("linkedin_connect_target_mismatch");
        }
        let key = format!("linkedin:connect:v1:{}", event_hash(&[request.intent_ref]));
        let binding = event_hash(&[
            &request.intent.actor,
            &plan.recipient_key,
            plan.note.as_deref().unwrap_or(""),
        ]);
        let binding_matches = (|| -> Result<bool> {
            let txn = self.vault.store.env.read_txn()?;
            Ok(self
                .vault
                .store
                .vault_meta
                .get(&txn, key.as_bytes())?
                .is_none_or(|prior| prior == binding.as_bytes()))
        })();
        if !matches!(binding_matches, Ok(true)) {
            return OutboundExecutionOutcome::failed("linkedin_connect_binding_changed");
        }
        let mut fields = BTreeMap::from([
            ("connect_with_person_called".into(), "false".into()),
            ("connect_with_person_return_trusted".into(), "false".into()),
            ("verify_tool".into(), "connection_state".into()),
        ]);
        let before = match self.transport.connection_state(&plan.recipient_key) {
            Ok(state) => state,
            Err(_) => {
                return OutboundExecutionOutcome::failed("linkedin_connect_precheck_failed")
                    .with_receipt_fields(fields);
            }
        };
        if !matches!(before, LinkedInConnectionState::NotConnected)
            && observation(before.clone()).is_none()
        {
            return OutboundExecutionOutcome::failed("linkedin_connect_invalid_observation")
                .with_receipt_fields(fields);
        }
        if let Some((provider_ref, state)) = observation(before) {
            fields.insert("duplicate_send_guard".into(), "observed_existing".into());
            fields.insert("linkedin_connect_verification".into(), state.into());
            return OutboundExecutionOutcome::delivered_to_channel(provider_ref)
                .with_receipt_fields(fields);
        }
        match self.claim(request, &plan) {
            Ok(true) => {}
            Ok(false) => {
                return OutboundExecutionOutcome::failed("linkedin_connect_already_attempted")
                    .with_possible_delivery()
                    .with_receipt_fields(fields);
            }
            Err(_) => {
                return OutboundExecutionOutcome::failed("linkedin_connect_guard_failed")
                    .with_receipt_fields(fields);
            }
        }
        fields.insert("connect_with_person_called".into(), "true".into());
        let sent = self
            .transport
            .connect_with_person(&LinkedInMcpConnectRequest {
                recipient_key: plan.recipient_key.clone(),
                note: plan.note,
                intent_ref: request.intent_ref.into(),
            });
        fields.insert(
            "connect_with_person_result".into(),
            if sent.is_ok() { "ignored" } else { "error" }.into(),
        );
        // Even a tool timeout may have sent. Only a fresh provider read can settle it.
        match self
            .transport
            .connection_state(&plan.recipient_key)
            .ok()
            .and_then(observation)
        {
            Some((provider_ref, state)) => {
                fields.insert("linkedin_connect_verification".into(), state.into());
                OutboundExecutionOutcome::delivered_to_channel(provider_ref)
                    .with_receipt_fields(fields)
            }
            None => OutboundExecutionOutcome::failed("linkedin_connect_not_observed")
                .with_possible_delivery()
                .with_receipt_fields(fields),
        }
    }
}
