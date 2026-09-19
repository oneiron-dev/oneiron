//! The one production publish door: OF-327 dispatch and its durable receipts.
use super::*;
use crate::consent::{AuthenticatedOwner, ConsentReceipt};
use crate::outbound::{
    OutboundDispatchActor, OutboundDispatchGate, OutboundDispatchOutcome, OutboundDispatchRequest,
    OutboundExecutionOutcome, OutboundExecutionRequest, OutboundExecutionSink, OutboundIntent,
    OutboundIntentDraft, OutboundIntentTrigger,
};
use crate::receipt::ReceiptRecord;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactPublishVerbRequest {
    pub artifact: String,
    pub channel: ArtifactPointerChannel,
    pub version: ArtifactPinnedVersion,
    pub actor: OutboundDispatchActor,
    pub intent_ref: String,
    pub occurred_at: u64,
}
impl ArtifactPublishVerbRequest {
    pub fn new(
        artifact: impl Into<String>,
        channel: ArtifactPointerChannel,
        version: ArtifactPinnedVersion,
        actor: OutboundDispatchActor,
        intent_ref: impl Into<String>,
        occurred_at: u64,
    ) -> Self {
        Self {
            artifact: artifact.into(),
            channel,
            version,
            actor,
            intent_ref: intent_ref.into(),
            occurred_at,
        }
    }

    fn dispatch_request(&self) -> Result<OutboundDispatchRequest> {
        validate_artifact_id(&self.artifact)?;
        let content_ref = format!(
            "artifact-export:{}:{}",
            self.channel.as_str(),
            artifact_hex(&self.version.encode(false))
        );
        // The shared consent composer target-pins job_ref. Bind the complete
        // publish, not just its artifact transport channel. The timestamp is
        // deliberately absent: it is observation time, not effect identity.
        let binding = serde_json::to_vec(&(
            "oneiron.artifact.publish.approval.v1",
            &self.artifact,
            &content_ref,
            &self.actor.actor_class,
            &self.actor.actor_ref,
            self.actor.actor_entity_ref.map(|id| id.to_hex()),
            &self.intent_ref,
        ))
        .map_err(|_| Error::InvariantViolation("artifact approval binding encode"))?;
        let target = format!("artifact-publish:{}", blake3::hash(&binding).to_hex());
        let intent = OutboundIntent::from_trigger(
            OutboundIntentDraft::new(
                self.actor.actor_ref.clone().unwrap_or_default(),
                "publish",
                "artifact",
                &self.artifact,
            )
            .content_ref(content_ref),
            OutboundIntentTrigger::agent_immediate(&self.intent_ref).job_ref(target),
        );
        Ok(OutboundDispatchRequest::new(
            format!("publish:{}", self.intent_ref),
            &self.intent_ref,
            intent,
            self.actor.clone(),
            OutboundDispatchGate::allow_when_policy_grants(),
            self.occurred_at,
            crate::outbound::OutboundDeliveryWindowDecision::DeliverNow,
        ))
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactPublishVerbStatus {
    Proposed,
    Published,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactPublishVerbOutcome {
    pub status: ArtifactPublishVerbStatus,
    pub pointer: Option<ArtifactPointer>,
    pub receipt: ReceiptRecord,
    pub share_receipt: Option<ReceiptRecord>,
}

struct PublishSink<'a> {
    vault: &'a Vault,
    request: &'a ArtifactPublishVerbRequest,
    intent: OutboundIntent,
}
impl OutboundExecutionSink for PublishSink<'_> {
    fn execute(&mut self, execution: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        if execution.intent != &self.intent
            || execution.intent_ref != self.request.intent_ref
            || execution.verb_contract.kind != "publish"
        {
            return OutboundExecutionOutcome::failed("artifact_publish_binding_mismatch");
        }
        let Some(outbound_intent_id) = execution.idempotency_key else {
            return OutboundExecutionOutcome::failed("artifact_publish_missing_intent_id");
        };
        match self
            .vault
            .publish_with_receipt(self.request, outbound_intent_id)
        {
            Ok(receipt) => OutboundExecutionOutcome::delivered_to_channel(
                receipt.fields["artifact_id"].clone(),
            )
            .with_receipt_field("artifact_publish", "true")
            .with_receipt_field("share_receipt_ref", receipt.receipt_id),
            Err(_) => OutboundExecutionOutcome::failed("artifact_publish_refused"),
        }
    }
}
impl Vault {
    /// Approves only this artifact, pointer channel, pinned version, actor and
    /// intent through the existing authenticated, consume-once consent door.
    /// This creates no standing grant and cannot re-arm a consumed approval.
    pub fn approve_artifact_publish(
        &self,
        owner: &AuthenticatedOwner,
        request: &ArtifactPublishVerbRequest,
    ) -> Result<ConsentReceipt> {
        let dispatch = request.dispatch_request()?;
        self.resolve_pinned_artifact(&request.artifact, request.version)?
            .ok_or(Error::EntityNotFound)?;
        let digest = dispatch.approval_digest().map_err(publish_dispatch_error)?;
        self.approve_once(owner, digest)
    }

    /// Requests a local publish. No caller boolean supplies authority.
    /// The normal dispatcher resolves a live grant or an exact approve-once
    /// marker, and parks unapproved work. A committed share receipt also closes
    /// a crash before the outbound acknowledgement, without publishing again.
    pub fn request_artifact_publish(
        &self,
        request: &ArtifactPublishVerbRequest,
    ) -> Result<ArtifactPublishVerbOutcome> {
        let dispatch = request.dispatch_request()?;
        let artifact_id = self
            .resolve_pinned_artifact(&request.artifact, request.version)?
            .ok_or(Error::EntityNotFound)?;
        let mut sink = PublishSink {
            vault: self,
            request,
            intent: dispatch.intent.clone(),
        };
        let result = self
            .dispatch_outbound_intent(dispatch, &mut sink)
            .map_err(publish_dispatch_error)?;
        let published = result.outcome == OutboundDispatchOutcome::DeliveredToChannel;
        let share_receipt =
            if published {
                Some(self.committed_artifact_publication(request)?.ok_or(
                    Error::InvariantViolation("delivered publication has no receipt"),
                )?)
            } else {
                None
            };
        let pointer = published.then(|| ArtifactPointer {
            artifact: request.artifact.clone(),
            channel: request.channel,
            version: request.version,
            artifact_id,
            stale_taint_override: share_receipt
                .as_ref()
                .and_then(|receipt| receipt.fields.get("stale_taint_override"))
                .is_some_and(|value| value == "true"),
        });
        Ok(ArtifactPublishVerbOutcome {
            status: if published {
                ArtifactPublishVerbStatus::Published
            } else {
                ArtifactPublishVerbStatus::Proposed
            },
            pointer,
            receipt: result.receipt,
            share_receipt,
        })
    }
}

fn publish_dispatch_error(error: crate::outbound::OutboundDispatchError) -> Error {
    match error {
        crate::outbound::OutboundDispatchError::Engine(error) => error,
        other => Error::InvalidConfig(other.to_string()),
    }
}

#[cfg(test)]
mod tests;
