//! Outbound action capability manifests and dispatch spine for OF-327.
//!
//! Capability discovery is the O1 field contract. The O2 dispatcher below is
//! intentionally connector-agnostic: concrete adapters plug in through
//! [`OutboundExecutionSink`], while delivery-window policy is evaluated as a
//! delivery-time request stage.

mod ambient_alternative;
mod capability;
mod connector_reply;
mod connector_task;
mod dispatch_attempt_id;
mod dispatch_pipeline;
mod dispatch_types;
mod executor;
mod intent;
mod manifests;
mod receipt_fields;
mod recovery_suggestions;
mod reply_content;
mod reply_job;
mod retry_audit;
mod served_sink;
mod window_door;

#[cfg(test)]
mod tests;

pub use crate::delivery_window::DeliveryWindowDecision as OutboundDeliveryWindowDecision;

pub use self::ambient_alternative::{OutboundAmbientAlternative, OutboundScheduleContinuation};
pub(crate) use self::capability::OutboundReplaySafety;
pub(crate) use self::capability::is_canonical_outbound_verb;
pub use self::capability::{
    COMMON_OUTBOUND_VERB_KINDS, OUTBOUND_CAPABILITY_MANIFEST_VERSION, OUTBOUND_VERB_FIELD_CONTRACT,
    OutboundCapabilityManifest, OutboundCapabilityPermission, OutboundDeliverySemantics,
    OutboundDeliverySemanticsKind, OutboundInterruptionClass, OutboundPermissionState,
    OutboundRetryClass, OutboundVerbContract, UnsupportedOutboundCapability,
    outbound_capability_manifest, outbound_capability_manifests, outbound_verb_contract,
    unsupported_outbound_connector,
};
pub use self::connector_reply::{ConnectorReply, ConnectorReplyDispatch, connector_reply_request};
pub use self::connector_task::{
    CONNECTOR_SEND_TASK_SUBKIND, ConnectorSendTask, ConnectorSendTaskOutcome, connector_actor_id,
};
pub(crate) use self::dispatch_attempt_id::{
    connector_logical_send_ref, outbound_dispatch_attempt_id,
};
pub(crate) use self::dispatch_pipeline::FrozenDispatchIdentity;
pub(crate) use self::dispatch_pipeline::outbound_gate_effect;
pub(crate) use self::dispatch_pipeline::resolve_channel_identity_ref_for_connector;
pub(crate) use self::dispatch_pipeline::validate_publisher_signature_in_txn;
pub(crate) use self::dispatch_pipeline::{
    EsignDeliveryCall, esign_approval_digest_from_frozen_payload, esign_delivery_call_in_txn,
    esign_delivery_grant_in_txn, failure_signals_approval_digest_from_frozen_payload,
};
pub use self::dispatch_pipeline::{
    OutboundDispatchPipeline, PublisherSignatureAuthorization, outbound_approve_once_digest,
    outbound_step_approve_once_digest,
};
pub use self::dispatch_types::{
    OutboundDispatchActor, OutboundDispatchError, OutboundDispatchGate, OutboundDispatchOutcome,
    OutboundDispatchPolicyRisk, OutboundDispatchRequest, OutboundDispatchResult,
    OutboundExecutionOutcome, OutboundExecutionOutcomeKind, OutboundExecutionRequest,
    OutboundExecutionSink,
};
pub use self::executor::ConnectorTaskExecutorError;
pub use self::intent::{
    MentionProvenance, OUTBOUND_INTENT_SCHEMA_VERSION, OutboundIntent, OutboundIntentDraft,
    OutboundIntentSource, OutboundIntentTrigger,
};
pub use self::recovery_suggestions::OutboundRecoverySuggestion;
pub use self::reply_content::{CONNECTOR_REPLY_BODY_PREFIX, ConnectorReplyBody};
pub use self::reply_job::{
    CONNECTOR_REPLY_JOB_KIND, CONNECTOR_REPLY_RESULT_PREFIX, ConnectorReplyJob,
    ConnectorReplyJobResult, ConnectorReplyStage,
};
pub use self::served_sink::{
    LINE_API_BASE, OwnedServedChannelSink, SLACK_API_BASE, ServedChannelSink, ServedEndpoints,
    ServedTransports, TELEGRAM_API_BASE,
};

pub(crate) use self::connector_task::{
    connector_send_attempt_payload, put_connector_send_task_in_txn,
};
pub(crate) use self::receipt_fields::APPROVAL_DIGEST_FIELD;
pub(crate) use self::reply_job::{
    erase_connector_reply_job_payload, erase_connector_reply_results_in_txn,
};
pub(crate) use self::window_door::stored_delivery_window_policy_claims;

/// Runs `hook` once, on this thread, when the next new outbound effect has
/// passed every check before admission and has not yet taken the vault's
/// writer: the window in which a concurrent write can land first.
#[cfg(feature = "test-hooks")]
#[doc(hidden)]
pub fn before_next_admission_for_test(hook: impl FnOnce() + 'static) {
    crate::outbound_chokepoint::BEFORE_NEW_ADMISSION.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(hook));
    });
}

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
use self::window_door::outbound_delivery_window_is_chat_like_ambient;
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
use crate::receipt::SendReceiptOutcome;
#[cfg(test)]
use crate::temporal::TimeRange;
