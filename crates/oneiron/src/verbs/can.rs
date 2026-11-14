//! `can`'s typed input: the read-only preflight of an ask, the dated
//! preflight of one effect (C2:207, FIX 22102), or one verb's gate for an
//! actor (FIX [UI-GATE-PREVIEW]).
use serde::{Deserialize, Serialize};

use super::{OutboundScheduleRequest, TaskCanAskRequest};
use crate::EntityId;

/// `can`'s input: `{ask: ...}`, one read-only preflight of a typed ask
/// spec, `{effect: ...}`, the dated preflight of one effect (C2:207, FIX
/// 22102), or `{verb: ...}`, one verb's gate for an actor (FIX
/// [UI-GATE-PREVIEW]). Untagged, so an ask's input keeps its wire shape;
/// each shape refuses the others' fields, so an input that names two matches
/// none.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum CanRequest {
    Ask(Box<TaskCanAskRequest>),
    Effect(Box<CanEffectRequest>),
    Verb(Box<CanVerbRequest>),
}

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

/// `can({effect: ...})`: the dated preflight of one effect (C2:207, FIX
/// 22102). It answers allow, deny, would-ask or a named hold, judged as the
/// act would be judged; the act itself is judged again when it runs.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CanEffectRequest {
    pub effect: CanEffect,
}

/// The one effect a `can({effect})` judges, named by the verb that would
/// perform it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum CanEffect {
    OutboundSchedule(CanOutboundSchedule),
    ConnectorCall(CanConnectorCall),
}

/// `{outbound_schedule: ...}`: the send `connector.outbound.schedule` with
/// this same input would schedule, judged as its first executing admission
/// judges it (FIX 22102).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CanOutboundSchedule {
    pub outbound_schedule: OutboundScheduleRequest,
}

/// `{connector_call: ...}`: the tool call `connector.call` with this same
/// input would make, judged as its first chokepoint admission judges it (FIX
/// 22102).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CanConnectorCall {
    pub connector_call: crate::outbound_consent::ConnectorCallRequest,
}
