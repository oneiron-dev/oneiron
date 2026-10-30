//! Typed OpenAI memory-proxy requests, replies and owner admission views (OF-445).
use std::collections::BTreeMap;

use crate::connector_key::qualification::ConnectorQualificationReceipt;
use crate::connector_key::{
    ConnectorGrantSlate, ConnectorIssuerHaltView, ConnectorKeyRecord, SlateRow, SlateToolManifest,
};
use crate::vault_shape::ShapePlanReach;
use crate::{ContentPart, EntityId, LlmMessage, LlmMessageRole, Vault};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// `POST /v1/chat/completions`'s body. A field the proxy cannot honour
/// (tools, images, logprobs, a response format, ...) is refused by name,
/// never dropped.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChatCompletionRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    #[serde(default)]
    pub stream: Option<bool>,
    #[serde(default)]
    pub n: Option<u32>,
    #[serde(default)]
    pub temperature: Option<f64>,
    #[serde(default)]
    pub top_p: Option<f64>,
    #[serde(default)]
    pub max_tokens: Option<u64>,
    #[serde(default)]
    pub max_completion_tokens: Option<u64>,
    #[serde(default)]
    pub stop: Option<ChatStop>,
    #[serde(default)]
    pub presence_penalty: Option<f64>,
    #[serde(default)]
    pub frequency_penalty: Option<f64>,
    #[serde(default)]
    pub seed: Option<i64>,
    /// Read and ignored: the credential names who calls, never a body field.
    #[serde(default)]
    pub user: Option<String>,
    /// The caller's own deadline, in milliseconds from when the call
    /// arrives (FIX 8189). One clock for the whole call, never renewed: its
    /// recall, every choice and each wait for a resting offer end by then,
    /// and a call it cuts answers `timeout`. Omitted, a choice waits for an
    /// offer as long as the vault's longest wait allows, as before.
    #[serde(default)]
    pub deadline_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum ChatStop {
    One(String),
    Many(Vec<String>),
}

impl ChatCompletionRequest {
    /// The sampling and output params the body sets, by their OpenAI names.
    pub fn params(&self) -> BTreeMap<String, Value> {
        let stop = self.stop.clone().map(|stop| match stop {
            ChatStop::One(stop) => json!(stop),
            ChatStop::Many(stops) => json!(stops),
        });
        [
            ("temperature", self.temperature.map(Value::from)),
            ("top_p", self.top_p.map(Value::from)),
            ("max_tokens", self.max_tokens.map(Value::from)),
            (
                "max_completion_tokens",
                self.max_completion_tokens.map(Value::from),
            ),
            ("stop", stop),
            ("presence_penalty", self.presence_penalty.map(Value::from)),
            ("frequency_penalty", self.frequency_penalty.map(Value::from)),
            ("seed", self.seed.map(Value::from)),
        ]
        .into_iter()
        .filter_map(|(key, value)| Some((key.to_owned(), value?)))
        .collect()
    }
}

/// One history message. Its role says where the text sits in the
/// conversation; it never names an author.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChatMessage {
    pub role: ChatRole,
    pub content: ChatContent,
    /// A participant's display name: read and ignored, never an identity.
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ChatRole {
    System,
    Developer,
    User,
    Assistant,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum ChatContent {
    Text(String),
    Parts(Vec<ChatPart>),
}

/// Text parts only: an image or audio part is refused, not dropped.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ChatPart {
    Text { text: String },
}

impl ChatMessage {
    pub fn is_user(&self) -> bool {
        self.role == ChatRole::User
    }

    pub fn text(&self) -> String {
        match &self.content {
            ChatContent::Text(text) => text.clone(),
            ChatContent::Parts(parts) => parts
                .iter()
                .map(|ChatPart::Text { text }| text.as_str())
                .collect::<Vec<_>>()
                .join("\n"),
        }
    }

    pub fn to_llm(&self) -> LlmMessage {
        let role = match self.role {
            ChatRole::System | ChatRole::Developer => LlmMessageRole::System,
            ChatRole::User => LlmMessageRole::User,
            ChatRole::Assistant => LlmMessageRole::Assistant,
        };
        LlmMessage {
            role,
            content: vec![ContentPart::Text { text: self.text() }],
        }
    }
}

/// A buffered OpenAI chat-completion reply, including the memory loop's outcome.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ChatCompletionResponse {
    pub id: String,
    pub object: ChatCompletionObject,
    pub created: u64,
    pub model: String,
    pub choices: Vec<ChatCompletionChoice>,
    pub usage: ChatCompletionUsage,
    pub oneiron: ChatCompletionMemory,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub enum ChatCompletionObject {
    #[serde(rename = "chat.completion")]
    ChatCompletion,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ChatCompletionChoice {
    pub index: u32,
    pub message: ChatCompletionMessage,
    pub finish_reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ChatCompletionMessage {
    pub role: ChatCompletionRole,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ChatCompletionRole {
    Assistant,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ChatCompletionUsage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ChatCompletionMemory {
    pub injected: bool,
    pub remembered: ChatCompletionRemembered,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum ChatCompletionRemembered {
    Saved { claim: String, approval: String },
    Refused { error: ChatCompletionRememberError },
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ChatCompletionRememberError {
    pub code: String,
    pub message: String,
}

/// The paired actor whose OpenAI proxy registration the owner admits.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProxyConnectorAdmitRequest {
    pub actor: String,
}

/// The owner revokes only the remember leg, against the exact key and slate reviewed.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProxyConnectorRevokeWriteRequest {
    pub actor: String,
    pub key: String,
    pub revision: u64,
}

/// The proxy's existing owner-route result: its catalog name, key and stamped slate.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProxyConnectorRegistration {
    pub connector: String,
    pub key: ConnectorKeyView,
    pub slate: ConnectorSlateView,
}

impl ProxyConnectorRegistration {
    pub fn from_registration(
        vault: &Vault,
        registration: crate::connector_key::ActorConnectorRegistration,
    ) -> crate::Result<Self> {
        let connector = registration
            .key
            .catalog
            .as_ref()
            .ok_or(crate::Error::InvariantViolation("proxy catalog missing"))?
            .name
            .clone();
        let halt = vault.open_issuer_halt_for_connector(&connector)?;
        Ok(Self {
            connector,
            key: ConnectorKeyView::new(registration.key_ref, registration.key)?
                .with_issuer_halt(halt),
            slate: ConnectorSlateView::new(vault, registration.slate_ref, &registration.slate)?,
        })
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConnectorSlateView {
    pub id: String,
    pub revision: u64,
    /// An owner stamp whose manifest and grant still hold.
    pub stamped: bool,
    pub facet_limit: Option<Vec<String>>,
    pub manifest: Vec<SlateToolManifest>,
    pub rows: Vec<SlateRow>,
    /// What every actor can send now, and once a stamp of these rows lands
    /// and its keys qualify (ARCH-0070 `shape:reach-line`). It informs the
    /// stamp and never blocks it.
    pub reach: ShapePlanReach,
}

impl ConnectorSlateView {
    /// `slate` with the reach a stamp of its rows as they stand brings.
    pub fn new(vault: &Vault, id: EntityId, slate: &ConnectorGrantSlate) -> crate::Result<Self> {
        let reach = vault.slate_stamp_reach(id, &BTreeMap::new())?;
        Ok(Self::with_reach(id, slate, reach))
    }

    pub fn with_reach(id: EntityId, slate: &ConnectorGrantSlate, reach: ShapePlanReach) -> Self {
        Self {
            id: id.to_hex(),
            revision: slate.revision(),
            stamped: slate.owner_actor().is_some() && slate.stamp_holds(),
            facet_limit: slate
                .facet_limit()
                .map(|facets| facets.iter().map(EntityId::to_hex).collect()),
            manifest: slate.manifest().to_vec(),
            rows: slate.rows().to_vec(),
            reach,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConnectorKeyView {
    pub id: String,
    pub status: String,
    /// The connector's open issuer transition, if one halts its rows.
    pub issuer_halt: Option<ConnectorIssuerHaltView>,
    pub secret_ref: Option<String>,
    pub protocol_revision: Option<String>,
    /// The slate revision the last qualification accepted.
    pub accepted_slate_revision: Option<u64>,
    pub consent_required: bool,
    pub qualification: Option<ConnectorQualificationReceipt>,
    /// The approved resolved manifest's hash, as 64 hex.
    pub manifest_hash: Option<String>,
    pub pending_manifest: Option<ConnectorPendingManifestView>,
}

impl ConnectorKeyView {
    pub fn new(id: EntityId, record: ConnectorKeyRecord) -> crate::Result<Self> {
        let manifest_hash = record
            .retained_manifest
            .as_ref()
            .map(|manifest| manifest.hash().map(|hash| hex(&hash)))
            .transpose()?;
        Ok(Self {
            id: id.to_hex(),
            status: record.status.as_str().to_owned(),
            issuer_halt: None,
            secret_ref: record.secret_ref,
            protocol_revision: record.protocol_revision,
            accepted_slate_revision: record.slate_revision,
            consent_required: record.consent_required,
            qualification: record.qualification_receipt,
            manifest_hash,
            pending_manifest: record
                .pending_manifest
                .map(|pending| ConnectorPendingManifestView {
                    candidate: hex(&pending.candidate_id),
                    protocol_revision: pending.protocol_revision,
                    report_hash: pending.qualification_report_hash,
                }),
        })
    }

    /// The view with the connector's open issuer transition attached.
    pub fn with_issuer_halt(self, halt: Option<ConnectorIssuerHaltView>) -> Self {
        Self {
            issuer_halt: halt,
            ..self
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConnectorPendingManifestView {
    pub candidate: String,
    pub protocol_revision: String,
    pub report_hash: Option<String>,
}

fn hex(bytes: &[u8; 32]) -> String {
    blake3::Hash::from(*bytes).to_hex().to_string()
}
