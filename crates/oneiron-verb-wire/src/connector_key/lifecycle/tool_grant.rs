//! Moved from `crates/oneiron/src/connector_key/lifecycle/tool_grant.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::connector_key::credential_binding::ConnectorIssuerHaltView;
use crate::connector_key::slate::SlateDataClass;
use crate::connector_key::slate::SlateDisposition;
use oneiron_consent_state::consent::tool_scope::DataClass;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// One tool's grant and the per-grant key that governs its calls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct ConnectorToolGrant {
    pub tool: String,
    pub grant_id: String,
    pub key_id: String,
    /// `mcp:{server}:grant:{grant_id}`.
    pub key_connector: String,
}

/// One tool row as the owner sees it before consenting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConnectorConsentRowView {
    pub tool: String,
    pub data_class: SlateDataClass,
    pub setting: SlateDisposition,
    pub header_parameters: Vec<String>,
    pub destroys: bool,
    /// The actor's live grant for this tool, with its ceiling.
    pub grant_id: Option<String>,
    pub grant_ceiling: Option<DataClass>,
}

/// One catalog connector's consent view for one actor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConnectorConsentView {
    pub connector: String,
    pub actor: String,
    pub status: String,
    /// The connector's open issuer transition, if one halts its rows.
    pub issuer_halt: Option<ConnectorIssuerHaltView>,
    pub protocol_revision: Option<String>,
    /// Active, qualified and owner-stamped: a consent can be written now.
    pub ready: bool,
    pub rows: Vec<ConnectorConsentRowView>,
    /// The slate's elicitation row setting, apart from the tool rows: the
    /// owner sets it on the slate, and no consent mints a tool grant for it.
    /// `None`: the slate holds no such row.
    pub elicitation: Option<SlateDisposition>,
}
