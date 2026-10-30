//! Inbox-sync config, runner, and claim/provenance helpers.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Vault;
use crate::error::{Error, Result};
use crate::side_table::{self, LegacyJson, Raw, SideTable};
use crate::surface_event::{
    InboundSurfaceEventInput, InboundSurfaceRouteOutcome, InboundSurfaceRouteReceipt,
    SurfaceEventAck, SurfaceEventAdmission,
};

use super::conversation_parse::{explicit_conversation_messages, fallback_conversation_messages};
use super::normalize_keys::{
    first_conversation_thread_id, linkedin_inbox_message_key_hash, normalize_non_blank,
    normalize_thread_id, optional_section_text, section_references, thread_id_from_payload_url,
};
use super::verified_send::receipt_error_code;
use super::{
    DEFAULT_LINKEDIN_INBOX_BACKFILL_WINDOW_SECS, LINKEDIN_CHANNEL,
    LINKEDIN_INBOX_SYNC_CLAIMED_VALUE, LINKEDIN_INBOX_SYNC_SOURCE, LINKEDIN_INBOX_SYNC_TIER,
    LINKEDIN_MCP_GET_CONVERSATION_TOOL, LINKEDIN_MCP_GET_INBOX_TOOL, LinkedInMcpConnectorAdapter,
    MAX_LINKEDIN_ADDRESS_BYTES, MAX_LINKEDIN_CONVERSATION_MESSAGES_PER_THREAD,
    MAX_LINKEDIN_INBOX_BACKFILL_WINDOW_SECS, MAX_LINKEDIN_SESSION_REF_BYTES,
};

/// The inbox-sync SEEN/claim marker for one message: a fixed presence flag
/// during claim, then the surface-event id after finalization. Keyed by the
/// message's stable hash.
const INBOX_SYNC_SEEN: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::LINKEDIN_INBOX_SYNC_SEEN);

/// The durable provenance marker persisted beside each seen message.
const INBOX_SYNC_PROVENANCE: SideTable<String, LinkedInInboxSyncProvenanceRow, LegacyJson> =
    SideTable::new(&side_table::LINKEDIN_INBOX_SYNC_PROVENANCE);

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

    pub(super) fn validate(&self) -> Result<()> {
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
    /// The durable handoff each new message was admitted under, before its
    /// seen marker was written.
    pub admitted: Vec<SurfaceEventAck>,
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
            admitted: Vec::new(),
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
                    // The durable handoff commits before the seen marker: a
                    // crash between them re-polls the message, and the
                    // handoff's correlation id dedupes the second admission.
                    let admission = match self
                        .vault
                        .enqueue_inbound_surface_event(event.event_input.clone(), now)
                    {
                        Ok(admission) => admission,
                        Err(err) => {
                            release_linkedin_inbox_message_claim(
                                self.vault,
                                &self.config,
                                &event.message,
                            )?;
                            return Err(err);
                        }
                    };
                    let SurfaceEventAdmission::Accepted(ack) = admission else {
                        // The identity stopped routing between the two reads.
                        release_linkedin_inbox_message_claim(
                            self.vault,
                            &self.config,
                            &event.message,
                        )?;
                        report.receipts.push(receipt);
                        continue;
                    };
                    finalize_linkedin_inbox_seen_message(
                        self.vault,
                        &self.config,
                        &event.message,
                        &event.event_input,
                    )?;
                    report.new_messages = report.new_messages.saturating_add(1);
                    report.admitted.push(ack);
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

pub(super) fn mcp_payload(output: &Value) -> Result<Value> {
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

pub(super) fn validate_inbox_sync_config_matches_adapter(
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

pub(super) fn conversation_messages_from_tool_output(
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

pub(super) fn message_in_backfill_window(
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
    let seen_key = linkedin_inbox_message_key_hash(config, message);
    vault.with_write_txn_grouped(|wtxn| {
        if INBOX_SYNC_SEEN.contains(&vault.store, wtxn, &seen_key)? {
            return Ok(false);
        }
        INBOX_SYNC_SEEN.put(
            &vault.store,
            wtxn,
            &seen_key,
            &LINKEDIN_INBOX_SYNC_CLAIMED_VALUE.to_vec(),
        )?;
        Ok(true)
    })
}

fn release_linkedin_inbox_message_claim(
    vault: &Vault,
    config: &LinkedInInboxSyncConfig,
    message: &LinkedInConversationMessage,
) -> Result<()> {
    let seen_key = linkedin_inbox_message_key_hash(config, message);
    vault.with_write_txn_grouped(|wtxn| {
        if INBOX_SYNC_SEEN
            .get(&vault.store, wtxn, &seen_key)?
            .is_some_and(|value| value == LINKEDIN_INBOX_SYNC_CLAIMED_VALUE)
        {
            INBOX_SYNC_SEEN.delete(&vault.store, wtxn, &seen_key)?;
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
    let seen_key = linkedin_inbox_message_key_hash(config, message);
    let provenance_key = linkedin_inbox_message_key_hash(config, message);
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
    vault.with_write_txn_grouped(|wtxn| {
        if INBOX_SYNC_SEEN
            .get(&vault.store, wtxn, &seen_key)?
            .is_none_or(|value| value != LINKEDIN_INBOX_SYNC_CLAIMED_VALUE)
        {
            return Err(Error::ConcurrentWrite(
                "LinkedIn inbox sync claim missing before finalization",
            ));
        }
        INBOX_SYNC_SEEN.put(
            &vault.store,
            wtxn,
            &seen_key,
            &event_input.event_id.as_bytes().to_vec(),
        )?;
        INBOX_SYNC_PROVENANCE.put(&vault.store, wtxn, &provenance_key, &row)?;
        Ok(())
    })
}

/// Reads durable LinkedIn inbox-sync provenance rows for diagnostics/tests.
pub fn linkedin_inbox_sync_provenance_rows(
    vault: &Vault,
) -> Result<Vec<LinkedInInboxSyncProvenanceRow>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut rows: Vec<LinkedInInboxSyncProvenanceRow> = INBOX_SYNC_PROVENANCE
        .scan(&vault.store, &rtxn)?
        .into_iter()
        .map(|(_, row)| row)
        .collect();
    rows.sort_by(|a, b| {
        a.thread_id
            .cmp(&b.thread_id)
            .then_with(|| a.message_id.cmp(&b.message_id))
    });
    Ok(rows)
}
