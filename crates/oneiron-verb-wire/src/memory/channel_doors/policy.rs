//! Moved from `crates/oneiron/src/memory/channel_doors/policy.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::memory::channel_doors::*;
use oneiron_contracts::entity_id::EntityId;
use oneiron_delivery_vocabulary::delivery_window::types::DeliveryWindowApnsInterruptionLevel;
use oneiron_delivery_vocabulary::delivery_window::types::DeliveryWindowContextCondition;
use oneiron_delivery_vocabulary::delivery_window::types::DeliveryWindowResolution;
use oneiron_delivery_vocabulary::delivery_window::types::DeliveryWindowVerbClass;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value as JsonValue;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeliveryWindowPolicyRequest {
    pub subject_ref: EntityId,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeliveryWindowPolicyRetractRequest {
    pub claim_ref: EntityId,
}

/// A read-only policy preview. This cannot schedule, approve or release a
/// send; dispatch always evaluates live policy again at its own effect door.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeliveryWindowEvaluateRequest {
    pub subject_refs: Vec<EntityId>,
    pub delivery_epoch_secs: u64,
    pub local_minute_of_day: u16,
    pub verb_class: DeliveryWindowVerbClass,
    pub channel: String,
    #[serde(default)]
    pub active_contexts: Vec<DeliveryWindowContextCondition>,
    #[serde(default)]
    pub interrupt_surface: Option<String>,
    #[serde(default)]
    pub degrade_to: Option<String>,
    #[serde(default)]
    #[schemars(with = "Option<String>")]
    pub apns_interruption_level: Option<DeliveryWindowApnsInterruptionLevel>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeliveryWindowPreview {
    pub policy_refs: Vec<EntityId>,
    pub resolution: DeliveryWindowResolution,
}
