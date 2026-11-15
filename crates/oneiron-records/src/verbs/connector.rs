//! Moved from `crates/oneiron/src/verbs/connector.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_verb_wire::connector_key::credential_binding::ConnectorIssuerHaltView;
pub use oneiron_verb_wire::verbs::connector::ConnectorListRequest;
pub use oneiron_verb_wire::verbs::connector::ConnectorNameRequest;
use serde::Deserialize;
use serde::Serialize;

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

/// One connector's history lens: its entry and the key that governs it. A
/// removed connector still describes, as `revoked`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorView {
    pub key_ref: String,
    pub entry: ConnectorEntry,
    /// `pending`, `active`, `suspended` or `revoked`.
    pub status: String,
    /// The connector's open issuer transition, if one halts its rows.
    pub issuer_halt: Option<ConnectorIssuerHaltView>,
    /// The custody record the key's secret lives in, by name.
    pub secret_ref: Option<String>,
    pub key_generation: u32,
    pub registered_at: u64,
    pub status_changed_at: Option<u64>,
    pub budgeted_as_sends: bool,
}

impl ConnectorEntry {
    fn name(&self) -> &str {
        match self {
            Self::Catalog { name, .. } | Self::Builtin { name, .. } => name,
        }
    }
}
