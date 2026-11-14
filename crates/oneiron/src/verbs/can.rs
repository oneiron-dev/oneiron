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

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::can::{CanConnectorCall, CanVerb, CanVerbRequest};

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
