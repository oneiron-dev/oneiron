//! Moved from `crates/oneiron/src/verbs/can.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// `can({verb: ...})`: what one call of a catalog verb would meet at its
/// gate now, for one actor (FIX [UI-GATE-PREVIEW]; GENUI-WIRE-GAPS section 4
/// item 1). ARCH-0082: "`can(effect)` is the same call with no side effects".
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CanVerbRequest {
    pub verb: CanVerb,
}

/// The call a `can({verb})` judges: the verb's catalog name, the input the
/// call would carry, and whose call it would be.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CanVerb {
    /// The verb's catalog name, for example `vault.rooms.pins.pin`.
    pub name: String,
    /// The input the call would carry, as the verb takes it. A verb whose
    /// gate reads its input refuses a missing or malformed one.
    #[serde(default)]
    pub params: serde_json::Value,
    /// The actor whose call it would be. Omitted: the caller. Only the
    /// vault's owner names another actor, and only one of the vault's own
    /// agents.
    #[serde(default)]
    pub actor: Option<EntityId>,
}

/// `{connector_call: ...}`: the tool call `connector.call` with this same
/// input would make, judged as its first chokepoint admission judges it (FIX
/// 22102).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CanConnectorCall {
    pub connector_call: crate::outbound_consent::connector_call_types::ConnectorCallRequest,
}
