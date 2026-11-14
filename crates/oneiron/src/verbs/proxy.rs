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

#[doc(hidden)]
use oneiron_verb_wire::verbs::proxy::hex;
#[doc(hidden)]
pub use oneiron_verb_wire::verbs::proxy::{
    ChatCompletionChoice, ChatCompletionMemory, ChatCompletionMessage, ChatCompletionObject,
    ChatCompletionRememberError, ChatCompletionRemembered, ChatCompletionRequest,
    ChatCompletionResponse, ChatCompletionRole, ChatCompletionUsage, ChatContent, ChatMessage,
    ChatPart, ChatRole, ChatStop, ConnectorPendingManifestView, ProxyConnectorAdmitRequest,
    ProxyConnectorRevokeWriteRequest,
};

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
