//! Moved from `crates/oneiron/src/verbs/connector_call.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::code_run::dispatcher::connector_answer::ConnectorAnswerAction;
pub use crate::code_run::dispatcher::connector_answer::ConnectorAnswerRequest;
pub use crate::code_run::dispatcher::connector_answer::ConnectorQuestionAnswer;
use crate::outbound_consent::connector_call_types::ConnectorSource;
use serde::Deserialize;
use serde::Serialize;

/// `connector.schema`'s input: a selected connector and one of its tools.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorSchemaRequest {
    /// The connector's name within the selected source.
    pub name: String,
    /// Explicit catalog or builtin selection. When absent, `web` selects
    /// the builtin and other names select their catalog entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<ConnectorSource>,
    /// The tool, as the connector's approved manifest names it.
    pub tool: String,
}

/// `connector.call_status`'s input: the call ref a `held` or
/// `pending_delivery` reply named (FIX 2279).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorCallStatusRequest {
    /// The `call_ref` a `held`, `pending_delivery` or `awaiting_input`
    /// `connector.call` reply named, 32 hex.
    pub call_ref: String,
}

/// `vault.connectors.calls.approve_once` (FIX 990): the owner's press on one
/// held connector call, by its ref and the exact digest he reviewed.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorCallApproveOnceRequest {
    /// The held call's ref, 32 hex.
    pub call_ref: String,
    /// The approve-once digest the call's current ask names (its status and
    /// its owner question), 64 lower-hex.
    pub approval_digest: String,
}
