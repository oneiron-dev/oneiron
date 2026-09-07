//! Outbound action capability manifests and dispatch spine for OF-327.
//!
//! Capability discovery is the O1 field contract. The O2 dispatcher below is
//! intentionally connector-agnostic: concrete adapters plug in through
//! [`OutboundExecutionSink`], while delivery-window policy is evaluated as a
//! delivery-time request stage.

mod capability;
mod connector_task;
mod dispatch_pipeline;
mod dispatch_types;
mod executor;
mod intent;
mod manifests;
mod receipt_fields;
mod retry_audit;
mod window_door;

#[cfg(test)]
mod tests;

pub use crate::delivery_window::DeliveryWindowDecision as OutboundDeliveryWindowDecision;

pub use self::capability::{
    COMMON_OUTBOUND_VERB_KINDS, OUTBOUND_CAPABILITY_MANIFEST_VERSION, OUTBOUND_VERB_FIELD_CONTRACT,
    OutboundCapabilityManifest, OutboundCapabilityPermission, OutboundDeliverySemantics,
    OutboundDeliverySemanticsKind, OutboundInterruptionClass, OutboundPermissionState,
    OutboundRetryClass, OutboundVerbContract, UnsupportedOutboundCapability,
    outbound_capability_manifest, outbound_capability_manifests, outbound_verb_contract,
    unsupported_outbound_connector,
};
pub use self::connector_task::{
    CONNECTOR_SEND_TASK_SUBKIND, ConnectorSendTask, ConnectorSendTaskOutcome, connector_actor_id,
};
pub use self::dispatch_pipeline::OutboundDispatchPipeline;
pub use self::dispatch_types::{
    OutboundDispatchActor, OutboundDispatchError, OutboundDispatchGate, OutboundDispatchOutcome,
    OutboundDispatchPolicyRisk, OutboundDispatchRequest, OutboundDispatchResult,
    OutboundExecutionOutcome, OutboundExecutionOutcomeKind, OutboundExecutionRequest,
    OutboundExecutionSink,
};
pub use self::executor::ConnectorTaskExecutorError;
pub use self::intent::{
    OUTBOUND_INTENT_SCHEMA_VERSION, OutboundIntent, OutboundIntentDraft, OutboundIntentSource,
    OutboundIntentTrigger,
};

pub(crate) use self::connector_task::{
    connector_send_attempt_payload, put_connector_send_task_in_txn,
};
#[cfg(test)]
pub(crate) use self::window_door::local_minute_of_day_at;

// The flat outbound.rs module used to provide these names to the test module
// through `use super::*`; after the directory split the seam re-imports them so
// the sibling `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use self::connector_task::{
    CONNECTOR_ACTOR_KIND, CONNECTOR_ACTOR_SCHEMA_VERSION, CONNECTOR_SEND_TASK_SCHEMA_VERSION,
    ConnectorActorBody, ConnectorSendTaskBody, connector_actor_matches,
    delivered_projection_receipt_observation, failed_projection_receipt_observation,
    reset_delivered_projection_receipt_observation, reset_failed_projection_receipt_observation,
    send_receipt_exists_for_task,
};
#[cfg(test)]
use self::window_door::{
    most_restrictive_delivery_window_decision, outbound_delivery_window_is_chat_like_ambient,
    stored_delivery_window_policy_claims,
};
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::delivery_window::{
    DeliveryWindowEvaluationContext, DeliveryWindowEvaluator, DeliveryWindowPolicyClaim,
    DeliveryWindowResolvedLevel, DeliveryWindowVerbClass,
};
#[cfg(test)]
use crate::edge::EdgeActorClass;
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::Error;
#[cfg(test)]
use crate::habit::TaskRole;
#[cfg(test)]
use crate::receipt::{ContextReceiptFields, SendReceiptOutcome};
#[cfg(test)]
use crate::temporal::TimeRange;
