//! `can`'s typed input: the read-only preflight of an ask, or the dated
//! preflight of one effect (C2:207, FIX 22102).
use serde::{Deserialize, Serialize};

use super::{OutboundScheduleRequest, TaskCanAskRequest};

/// `can`'s input: `{ask: ...}`, one read-only preflight of a typed ask
/// spec, or `{effect: ...}`, the dated preflight of one effect (C2:207, FIX
/// 22102). Untagged, so an ask's input keeps its wire shape; each shape
/// refuses the other's field, so an input that names both matches neither.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum CanRequest {
    Ask(Box<TaskCanAskRequest>),
    Effect(Box<CanEffectRequest>),
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
