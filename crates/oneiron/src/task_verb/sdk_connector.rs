//! The `connector.*` rows over the foreign surface's catalog
//! (`connector.list`, the discovery lens; `connector.status`, the history
//! lens) and `connector.outbound.schedule`. The wire shapes here mirror the
//! connector key records without their budgets, charters or manifests, and
//! carry a key's custody record name, never a secret.
use serde::{Deserialize, Serialize};

use crate::connector_key::{ConnectorCatalogEntry, ConnectorDescription};
use crate::memory::{Memory, MemoryResult, OutboundDraftInput, OutboundIntentReceipt};

/// `connector.list`'s input: a name or summary fragment; every live
/// connector when blank.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorListRequest {
    #[serde(default)]
    pub query: Option<String>,
}

/// One catalogued connector, as discovery lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorEntry {
    pub name: String,
    pub connector: String,
    pub summary: String,
    pub verbs: Vec<String>,
    /// `counterparty_comm`, `read_only` or `scoped_mcp`.
    pub call_class: String,
    pub registered_at: u64,
}

impl From<ConnectorCatalogEntry> for ConnectorEntry {
    fn from(entry: ConnectorCatalogEntry) -> Self {
        Self {
            name: entry.name,
            connector: entry.connector,
            summary: entry.summary,
            verbs: entry.verbs,
            call_class: entry.call_class.as_str().to_owned(),
            registered_at: entry.registered_at,
        }
    }
}

/// `connector.status`'s input: a catalogued connector's name.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorNameRequest {
    pub name: String,
}

/// One connector's history lens: its entry and the key that governs it. A
/// removed connector still describes, as `revoked`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorView {
    pub key_ref: String,
    pub entry: ConnectorEntry,
    /// `pending`, `active`, `suspended` or `revoked`.
    pub status: String,
    /// The custody record the key's secret lives in, by name.
    pub secret_ref: Option<String>,
    pub key_generation: u32,
    pub registered_at: u64,
    pub status_changed_at: Option<u64>,
    pub budgeted_as_sends: bool,
}

impl From<ConnectorDescription> for ConnectorView {
    fn from(description: ConnectorDescription) -> Self {
        Self {
            key_ref: description.key_ref.to_hex(),
            entry: description.entry.into(),
            status: description.status.as_str().to_owned(),
            secret_ref: description.secret_ref,
            key_generation: description.key_generation,
            registered_at: description.registered_at,
            status_changed_at: description.status_changed_at,
            budgeted_as_sends: description.budgeted_as_sends,
        }
    }
}

/// `connector.list`: every live catalogued connector the query matches.
pub fn connector_catalog(
    memory: &Memory<'_>,
    input: ConnectorListRequest,
) -> MemoryResult<Vec<ConnectorEntry>> {
    let entries = memory
        .vault()
        .search_connector_catalog(input.query.as_deref().unwrap_or(""))?;
    Ok(entries.into_iter().map(Into::into).collect())
}

/// `connector.status`: one connector by name, removed ones included.
pub fn connector_description(
    memory: &Memory<'_>,
    input: ConnectorNameRequest,
) -> MemoryResult<Option<ConnectorView>> {
    Ok(memory
        .vault()
        .describe_connector(&input.name)?
        .map(Into::into))
}

/// `connector.outbound.schedule`'s input: one send through a granted
/// outbound connector, scheduled, gated and held for delivery.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OutboundScheduleRequest {
    /// The verb (`send`).
    pub verb: String,
    /// The channel (`email`).
    pub channel: String,
    /// The delivery target (address or handle).
    pub target: String,
    #[serde(default)]
    pub on_behalf_of: Option<String>,
    /// The content entity to send.
    #[serde(default)]
    pub content_ref: Option<String>,
    /// A second schedule with the same key coalesces onto the first.
    #[serde(default)]
    pub idempotency_key: Option<String>,
    #[serde(default)]
    pub dedupe_key: Option<String>,
    /// `commitment_timer_wake`, `gap_queue` or `agent_immediate`.
    pub trigger: String,
    /// What fired the trigger.
    pub trigger_ref: String,
    #[serde(default)]
    pub job_ref: Option<String>,
    /// Unix seconds; now when absent.
    #[serde(default)]
    pub occurred_at: Option<u64>,
    /// The saved mention `target` came from, when the agent named the
    /// person: the send refuses while it is unsettled, so settle it with
    /// `self.identity.settle` first.
    #[serde(default)]
    pub mention: Option<crate::outbound::MentionProvenance>,
}

impl From<OutboundScheduleRequest> for OutboundDraftInput {
    fn from(request: OutboundScheduleRequest) -> Self {
        Self {
            verb: request.verb,
            channel: request.channel,
            target: request.target,
            on_behalf_of: request.on_behalf_of,
            content_ref: request.content_ref,
            idempotency_key: request.idempotency_key,
            dedupe_key: request.dedupe_key,
            trigger: request.trigger,
            trigger_ref: request.trigger_ref,
            job_ref: request.job_ref,
            occurred_at: request.occurred_at,
            mention: request.mention,
        }
    }
}

/// `connector.outbound.schedule`: the gated schedule `Memory` already serves.
pub fn connector_outbound_schedule_draft(
    memory: &Memory<'_>,
    input: OutboundScheduleRequest,
) -> MemoryResult<OutboundIntentReceipt> {
    memory.schedule_outbound(&input.into())
}
