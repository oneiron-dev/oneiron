//! Connector discovery, catalog-key history and outbound scheduling.
//! `connector.list` distinguishes catalogued keys from first-party interfaces;
//! `connector.status` describes a catalogued key without its budgets, charter
//! or manifest. A key's custody record name is carried, never its secret.
use serde::{Deserialize, Serialize};

use crate::connector_key::{ConnectorCatalogEntry, ConnectorDescription};
use crate::memory::{Memory, MemoryResult, OutboundDraftInput, OutboundIntentReceipt};

/// `connector.list`'s input: a name or summary fragment; all catalogued
/// keys and first-party interfaces in the discovery lens when blank.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorListRequest {
    #[serde(default)]
    pub query: Option<String>,
}

/// A catalogued key or a first-party connector interface. Discovery does
/// not authorize a call or promise that its provider is available.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum ConnectorEntry {
    Catalog {
        name: String,
        connector: String,
        summary: String,
        verbs: Vec<String>,
        /// `counterparty_comm`, `read_only` or `scoped_mcp`.
        call_class: String,
        registered_at: u64,
    },
    Builtin {
        name: String,
        connector: String,
        summary: String,
        verbs: Vec<String>,
    },
}

impl From<ConnectorCatalogEntry> for ConnectorEntry {
    fn from(entry: ConnectorCatalogEntry) -> Self {
        Self::Catalog {
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

/// `connector.list`: matching live catalogued keys and first-party interfaces.
/// Includes built-in `google.sheets` while its pack's connection is checked
/// (FIX 4862), in name order.
pub fn connector_catalog(
    memory: &Memory<'_>,
    input: ConnectorListRequest,
) -> MemoryResult<Vec<ConnectorEntry>> {
    let query = input.query.as_deref().unwrap_or("");
    let mut catalog = memory.vault().search_connector_catalog(query)?;
    if let Some(sheets) =
        crate::channel_identity_provider::sheets::sheets_catalog_entry(memory.vault(), query)?
    {
        let at = catalog.partition_point(|entry| entry.name < sheets.name);
        catalog.insert(at, sheets);
    }
    let mut entries: Vec<ConnectorEntry> = catalog.into_iter().map(Into::into).collect();
    if let Some(web) = builtin_web_entry(query) {
        let position = entries.partition_point(|entry| entry.name() < web.name());
        entries.insert(position, web);
    }
    Ok(entries)
}

impl ConnectorEntry {
    fn name(&self) -> &str {
        match self {
            Self::Catalog { name, .. } | Self::Builtin { name, .. } => name,
        }
    }
}

fn builtin_web_entry(query: &str) -> Option<ConnectorEntry> {
    use crate::web_connector::{WEB_CONNECTOR_NAME, WebTool};

    let summary = "Web search and page fetch through the configured provider.";
    let name_query = crate::connector_key::normalize_connector_key(query);
    let summary_query = query.trim().to_lowercase();
    if !WEB_CONNECTOR_NAME.contains(&name_query) && !summary.to_lowercase().contains(&summary_query)
    {
        return None;
    }
    Some(ConnectorEntry::Builtin {
        name: WEB_CONNECTOR_NAME.to_owned(),
        connector: WEB_CONNECTOR_NAME.to_owned(),
        summary: summary.to_owned(),
        verbs: [WebTool::Search, WebTool::Fetch]
            .into_iter()
            .map(|tool| tool.as_str().to_owned())
            .collect(),
    })
}

/// `connector.status`: one connector by name, removed ones included. The
/// OpenAI proxy's keys have no endpoint to call, so none is described.
pub fn connector_description(
    memory: &Memory<'_>,
    input: ConnectorNameRequest,
) -> MemoryResult<Option<ConnectorView>> {
    Ok(memory
        .vault()
        .describe_connector(&input.name)?
        .filter(|described| described.connector != crate::connector_key::PROXY_CONNECTOR)
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
    /// The sender-selection question this send answers: the gate dispatch
    /// selects its sender by the vault's selection rules over its identity
    /// faces.
    #[serde(default)]
    pub selection: Option<crate::memory::channel_doors::ChannelSelectionRequest>,
    /// The counterparty class passed explicitly on this send.
    #[serde(default)]
    pub counterparty_class: Option<String>,
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
    if let Some(selection) = input.selection.clone() {
        let continuation = crate::outbound::OutboundScheduleContinuation {
            selection: Some(crate::outbound::OutboundSendSelection {
                request: selection,
                counterparty_class: input.counterparty_class.clone(),
            }),
            ..Default::default()
        };
        let draft = OutboundDraftInput::from(input);
        memory.schedule_outbound_with_continuation(
            &draft,
            &crate::memory::OutboundScheduleContext::default(),
            &continuation,
            None,
        )
    } else {
        memory.schedule_outbound(&input.into())
    }
}
