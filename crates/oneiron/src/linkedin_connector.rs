//! LinkedIn connector adapter surface (ONE-1563 / LNKD-1).
//!
//! The first LinkedIn implementation rides the session-bound
//! `stickerdaniel/linkedin-mcp-server` tool surface. This module keeps that
//! boundary local and testable: it maps recorded MCP read outputs into
//! OF-247 `InboundSurfaceEventInput` values without starting a browser or
//! touching a live LinkedIn session.

use serde_json::Value;

use crate::error::{Error, Result};
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
        for reference in section_references(&payload, "inbox") {
            if !reference_kind_is(reference, "conversation") {
                continue;
            }
            let Some(thread_id) = thread_id_from_reference(reference) else {
                continue;
            };
            let participant = reference_text(reference);
            let hash = event_hash(["get_inbox", &thread_id, inbox_text].as_slice());
            events.push(self.surface_event_input(
                format!("linkedin:inbox:{thread_id}:{hash}"),
                counterparty_key(&thread_id, participant),
                format!("linkedin:mcp:get_inbox:{thread_id}:{hash}"),
                received_at,
            ));
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

        let thread_id = thread_id_from_payload_url(&payload)
            .or_else(|| {
                section_references(&payload, "conversation")
                    .iter()
                    .find_map(|reference| thread_id_from_reference(reference))
            })
            .ok_or_else(|| {
                Error::InvalidConfig(
                    "LinkedIn get_conversation output did not include a thread id".to_owned(),
                )
            })?;
        let participant = section_references(&payload, "conversation")
            .iter()
            .find_map(|reference| reference_text(reference));
        let hash = event_hash(["get_conversation", &thread_id, conversation_text].as_slice());
        Ok(vec![self.surface_event_input(
            format!("linkedin:conversation:{thread_id}:{hash}"),
            counterparty_key(&thread_id, participant),
            format!("linkedin:mcp:get_conversation:{thread_id}:{hash}"),
            received_at,
        )])
    }

    fn surface_event_input(
        &self,
        event_id: String,
        counterparty_key: String,
        payload_ref: String,
        received_at: u64,
    ) -> InboundSurfaceEventInput {
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
            input.with_workspace_ref(session_ref.clone())
        } else {
            input
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
    Ok(output.clone())
}

fn optional_section_text<'a>(payload: &'a Value, section: &str) -> Result<Option<&'a str>> {
    let Some(sections) = payload.get("sections") else {
        return Ok(None);
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

fn reference_text(reference: &Value) -> Option<&str> {
    reference
        .get("text")
        .or_else(|| reference.get("title"))
        .or_else(|| reference.get("name"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
}

fn thread_id_from_reference(reference: &Value) -> Option<String> {
    reference
        .get("thread_id")
        .and_then(Value::as_str)
        .and_then(normalize_thread_id)
        .or_else(|| {
            reference
                .get("url")
                .and_then(Value::as_str)
                .and_then(thread_id_from_url)
        })
}

fn thread_id_from_payload_url(payload: &Value) -> Option<String> {
    payload
        .get("url")
        .and_then(Value::as_str)
        .and_then(thread_id_from_url)
}

fn thread_id_from_url(url: &str) -> Option<String> {
    let marker = "/messaging/thread/";
    let (_, rest) = url.split_once(marker)?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    normalize_thread_id(&rest[..end])
}

fn normalize_thread_id(thread_id: &str) -> Option<String> {
    let thread_id = thread_id.trim();
    if thread_id.is_empty()
        || thread_id
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || matches!(byte, b'/' | b'?' | b'#'))
    {
        return None;
    }
    Some(thread_id.to_owned())
}

fn counterparty_key(thread_id: &str, participant: Option<&str>) -> String {
    match participant {
        Some(participant) => format!("linkedin:thread:{thread_id}:participant:{participant}"),
        None => format!("linkedin:thread:{thread_id}"),
    }
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
