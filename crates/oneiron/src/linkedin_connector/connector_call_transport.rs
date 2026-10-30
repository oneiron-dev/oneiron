//! The production LinkedIn transports (FIX 1168): every MCP tool the inbox
//! sync and the verified send use is one admitted installed-tool call to the
//! LinkedIn connector the owner installed, made for its caller through the
//! host's connector calls: the caller's standing grant, the approved schema,
//! the gate and the intent ledger, as every connector tool call. Nothing here
//! speaks HTTP to LinkedIn.
//!
//! The connector's `send_message` names its recipient by member name, never
//! by thread. A send whose recipient is a thread key goes to the one member
//! other than the seat that the thread's last read links to; a thread that
//! links to none or to several sends nothing.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{Map, Value, json};

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::outbound::ServedConnectorCalls;
use crate::outbound_consent::tool_call::MutationIntent;
use crate::outbound_consent::{
    ConnectorCallInvocation, ConnectorCallOutcome, ConnectorCallRequest, ConnectorResultAbsence,
    UntrustedToolResult,
};
use crate::outbound_intent_ledger::IntentLedgerError;

use super::inbox_sync::{LinkedInMcpInboxSyncTransport, mcp_payload};
use super::normalize_keys::{normalize_thread_id, section_references};
use super::verified_send::{
    LINKEDIN_TOOL_NOT_SENT_PREFIX, LinkedInMcpSendMessageRequest, LinkedInMcpSendTransport,
};
use super::{
    LINKEDIN_CHANNEL, LINKEDIN_MCP_GET_CONVERSATION_TOOL, LINKEDIN_MCP_GET_INBOX_TOOL,
    LINKEDIN_MCP_SEND_MESSAGE_TOOL, LinkedInMcpConnectorAdapter,
};

/// The key prefix a LinkedIn member is named by.
const LINKEDIN_MEMBER_KEY_PREFIX: &str = "linkedin:member:";
/// The key prefix a LinkedIn thread is named by, as its counterparty.
const LINKEDIN_THREAD_KEY_PREFIX: &str = "linkedin:thread:";
/// Where a member's name sits in a LinkedIn profile link.
const LINKEDIN_PROFILE_PATH: &str = "/in/";
/// The domain one logical `send_message` call's identity is derived in.
const SEND_MESSAGE_INVOCATION_DOMAIN: &[u8] = b"oneiron.linkedin.send-message.v1\0";

/// The LinkedIn MCP tools of the connector installed under `catalog_name`,
/// each called for `caller` through the host's connector calls. It is both
/// the inbox sync's transport and the verified send's.
pub struct LinkedInConnectorCallTransport {
    calls: Arc<dyn ServedConnectorCalls>,
    caller: EntityId,
    caller_class: EdgeActorClass,
    catalog_name: String,
    /// The seat's own member name, never taken as a thread's recipient.
    own_member: String,
    /// Per thread, the members other than the seat its last read linked to.
    members: BTreeMap<String, Vec<String>>,
}

impl LinkedInConnectorCallTransport {
    /// The transport for `caller` on the LinkedIn connector the owner
    /// installed: the catalog entry of the connector key that governs
    /// LinkedIn for `caller`, for the seat `adapter` names.
    ///
    /// # Errors
    ///
    /// No LinkedIn connector key governs `caller`, or it has no catalog
    /// entry to call.
    pub fn installed(
        vault: &Vault,
        calls: Arc<dyn ServedConnectorCalls>,
        caller: EntityId,
        caller_class: EdgeActorClass,
        adapter: &LinkedInMcpConnectorAdapter,
    ) -> Result<Self> {
        let catalog_name = vault
            .connector_key_for(LINKEDIN_CHANNEL, Some(&caller))?
            .and_then(|(_, key)| key.catalog)
            .map(|entry| entry.name)
            .ok_or_else(|| {
                Error::InvalidConfig(
                    "no installed LinkedIn connector serves this caller".to_owned(),
                )
            })?;
        let seat = adapter.receiving_address_or_handle();
        Ok(Self {
            calls,
            caller,
            caller_class,
            catalog_name,
            own_member: seat
                .strip_prefix(LINKEDIN_MEMBER_KEY_PREFIX)
                .unwrap_or(seat)
                .to_owned(),
            members: BTreeMap::new(),
        })
    }

    /// One tool call, its reply as the MCP output the LinkedIn readers take.
    fn call(
        &self,
        tool: &str,
        arguments: Value,
        mutation: MutationIntent,
        invocation: Option<ConnectorCallInvocation>,
    ) -> std::result::Result<Value, String> {
        let request = ConnectorCallRequest {
            name: self.catalog_name.clone(),
            tool: tool.to_owned(),
            arguments,
            mutation,
        };
        tool_output(
            self.calls
                .call(self.caller, self.caller_class, request, invocation),
        )
    }

    /// The member a send to `request` goes to: the member its recipient
    /// key names, else the one member other than the seat its thread links
    /// to, read now when no read of the thread is kept.
    fn recipient_member(
        &mut self,
        request: &LinkedInMcpSendMessageRequest,
    ) -> std::result::Result<String, String> {
        if let Some(member) = request
            .recipient_key
            .strip_prefix(LINKEDIN_MEMBER_KEY_PREFIX)
            .filter(|member| !member.is_empty())
        {
            return Ok(member.to_owned());
        }
        if !self.members.contains_key(&request.thread_id) {
            LinkedInMcpInboxSyncTransport::get_conversation(self, &request.thread_id)
                .map_err(|code| not_sent(&code))?;
        }
        match self.members.get(&request.thread_id).map(Vec::as_slice) {
            Some([member]) => Ok(member.clone()),
            _ => Err(not_sent("linkedin_thread_recipient_unresolved")),
        }
    }
}

impl LinkedInMcpInboxSyncTransport for LinkedInConnectorCallTransport {
    fn get_inbox(&mut self) -> std::result::Result<Value, String> {
        self.call(
            LINKEDIN_MCP_GET_INBOX_TOOL,
            json!({}),
            MutationIntent::Preview,
            None,
        )
    }

    fn get_conversation(&mut self, thread_id: &str) -> std::result::Result<Value, String> {
        let output = self.call(
            LINKEDIN_MCP_GET_CONVERSATION_TOOL,
            json!({ "thread_id": thread_id }),
            MutationIntent::Preview,
            None,
        )?;
        let others = conversation_members(&output)
            .into_iter()
            .filter(|member| !member.eq_ignore_ascii_case(&self.own_member))
            .collect();
        self.members.insert(thread_id.to_owned(), others);
        Ok(output)
    }
}

impl LinkedInMcpSendTransport for LinkedInConnectorCallTransport {
    fn send_message(
        &mut self,
        request: &LinkedInMcpSendMessageRequest,
    ) -> std::result::Result<Value, String> {
        let member = self.recipient_member(request)?;
        self.call(
            LINKEDIN_MCP_SEND_MESSAGE_TOOL,
            json!({
                "linkedin_username": member,
                "message": request.message_text,
                "confirm_send": true,
            }),
            MutationIntent::ExplicitMutation,
            send_message_invocation(&request.intent_ref),
        )
    }

    fn get_conversation(&mut self, thread_id: &str) -> std::result::Result<Value, String> {
        LinkedInMcpInboxSyncTransport::get_conversation(self, thread_id)
    }
}

/// The thread a `linkedin:thread:<id>` key names.
#[must_use]
pub fn linkedin_thread_id_from_key(key: &str) -> Option<String> {
    normalize_thread_id(key.strip_prefix(LINKEDIN_THREAD_KEY_PREFIX)?).ok()
}

/// The identity of the one logical `send_message` call an outbound intent
/// makes: every send of the intent names the same call, which the connector
/// call's ledger replays, or resumes once its hold clears, instead of
/// sending twice.
fn send_message_invocation(intent_ref: &str) -> Option<ConnectorCallInvocation> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SEND_MESSAGE_INVOCATION_DOMAIN);
    hasher.update(intent_ref.as_bytes());
    AttemptId::from_bytes(&hasher.finalize().as_bytes()[..16])
        .ok()
        .map(|attempt_id| ConnectorCallInvocation {
            attempt_id,
            call_seq: 0,
        })
}

/// What one connector call came to, as a LinkedIn transport answers: the
/// connector's reply, or a stable code. A call held or refused before it
/// sent answers a code that says so.
fn tool_output(
    outcome: std::result::Result<ConnectorCallOutcome, IntentLedgerError>,
) -> std::result::Result<Value, String> {
    match outcome {
        Ok(ConnectorCallOutcome::Delivered {
            result: Some(result),
            ..
        }) => tool_result_output(result),
        Ok(ConnectorCallOutcome::Delivered { result_absence, .. }) => Err(match result_absence {
            Some(ConnectorResultAbsence::CredentialClearFailed) => "connector_result_withheld",
            _ => "connector_result_not_retained",
        }
        .to_owned()),
        Ok(ConnectorCallOutcome::Held { reasons, .. }) => {
            Err(not_sent(&with_reason("connector_call_held", &reasons)))
        }
        Ok(ConnectorCallOutcome::Refused { reasons, .. }) => {
            Err(not_sent(&with_reason("connector_call_refused", &reasons)))
        }
        Ok(ConnectorCallOutcome::PendingDelivery { reasons, .. }) => {
            Err(with_reason("connector_call_pending_delivery", &reasons))
        }
        Ok(ConnectorCallOutcome::AwaitingInput { .. }) => {
            Err("connector_call_awaiting_input".to_owned())
        }
        Err(error) => {
            tracing::info!(%error, "LinkedIn connector call did not complete");
            Err("connector_call_failed".to_owned())
        }
    }
}

/// A connector's reply as the MCP output the LinkedIn readers take: its
/// content blocks and its structured content. A tool error is a code; its
/// text is the connector's and stays out of every receipt.
fn tool_result_output(result: UntrustedToolResult) -> std::result::Result<Value, String> {
    if result.is_error {
        return Err(
            match result
                .rpc_error
                .as_ref()
                .and_then(|error| error.get("code"))
                .and_then(Value::as_i64)
            {
                Some(code) => format!("connector_tool_error:{code}"),
                None => "connector_tool_error".to_owned(),
            },
        );
    }
    let mut output = Map::new();
    output.insert("content".to_owned(), result.content);
    if let Some(structured) = result.structured_content {
        output.insert("structuredContent".to_owned(), structured);
    }
    Ok(Value::Object(output))
}

/// `code`, beside the first reason that came with it.
fn with_reason(code: &str, reasons: &[String]) -> String {
    match reasons.first() {
        Some(reason) => format!("{code}:{reason}"),
        None => code.to_owned(),
    }
}

/// `code` as a tool that was never called answers.
fn not_sent(code: &str) -> String {
    if code.starts_with(LINKEDIN_TOOL_NOT_SENT_PREFIX) {
        code.to_owned()
    } else {
        format!("{LINKEDIN_TOOL_NOT_SENT_PREFIX}{code}")
    }
}

/// The members a `get_conversation` reply's conversation links to, in page
/// order, each once.
fn conversation_members(output: &Value) -> Vec<String> {
    let Ok(payload) = mcp_payload(output) else {
        return Vec::new();
    };
    let mut members: Vec<String> = Vec::new();
    for reference in section_references(&payload, "conversation") {
        let Some(member) = reference
            .get("url")
            .and_then(Value::as_str)
            .and_then(profile_member)
        else {
            continue;
        };
        if !members
            .iter()
            .any(|known| known.eq_ignore_ascii_case(&member))
        {
            members.push(member);
        }
    }
    members
}

/// The member name a profile link (`/in/<name>/`) carries.
fn profile_member(url: &str) -> Option<String> {
    let (_, rest) = url.split_once(LINKEDIN_PROFILE_PATH)?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let member = rest[..end].trim();
    (!member.is_empty()).then(|| member.to_owned())
}
