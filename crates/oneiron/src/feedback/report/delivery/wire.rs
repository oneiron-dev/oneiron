//! The wire side of an issue signature (OF-420, FIX 739): the canonical
//! `oneiron.issue_signature.v1` body built from an ED-08 signature and read
//! back through its only constructor, the dispatch request one frozen send
//! carries, and the sink that hands the host carrier those exact bytes.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{
    REPORT_SIGNATURE_SCHEMA, REPORT_SIGNATURE_VERB, ReportDeliveryKey, ReportFrozenSend,
    ReportFrozenSignature, ReportPublisherEndpoint, ReportSignatureTransport,
    ReportSignatureTransportRequest,
};
use crate::edit_distance::publisher::{CountKey, IssueCategory, IssueSignature};
use crate::outbound::{
    OutboundDeliveryWindowDecision, OutboundDispatchActor, OutboundDispatchGate,
    OutboundDispatchRequest, OutboundExecutionOutcome, OutboundExecutionRequest,
    OutboundExecutionSink, OutboundIntent, OutboundIntentDraft, OutboundIntentTrigger,
    PublisherSignatureAuthorization,
};
use crate::settings::default_model_stack_registry;
use crate::{EntityId, Error, Result};

/// The wire shape of `oneiron.issue_signature.v1`: ED-08's fields and the
/// schema token, nothing else. No issue reference or actor crosses.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireSignature {
    schema: String,
    category: String,
    artifact: String,
    version: u32,
    model_id: String,
    counts: BTreeMap<String, u32>,
    content_hash: String,
}

/// The outbound sink of one frozen send: it hands the host carrier exactly
/// the frozen bytes, and only on the frozen verb, channel and endpoint.
pub(super) struct SignatureSink<'a, T: ?Sized> {
    pub(super) transport: &'a mut T,
    pub(super) signature: &'a ReportFrozenSignature,
    pub(super) destination: &'a ReportPublisherEndpoint,
}

impl<T: ReportSignatureTransport + ?Sized> OutboundExecutionSink for SignatureSink<'_, T> {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        // Only the frozen verb, channel and endpoint carry the frozen bytes.
        let intent = request.intent;
        if intent.verb != REPORT_SIGNATURE_VERB
            || intent.channel != self.destination.channel
            || intent.target != self.destination.endpoint
        {
            return OutboundExecutionOutcome::failed("issue_signature_route_mismatch");
        }
        let digest = self.signature.digest.as_str();
        self.transport
            .send_issue_signature(&ReportSignatureTransportRequest {
                execution: request,
                body: self.signature.body.as_bytes(),
                digest,
            })
            .with_receipt_field("issue_signature_digest", digest)
    }
}

/// The dispatch request for one frozen send: the same refs, actor and gate
/// on every run, so a retry is the same logical send.
pub(super) fn signature_request(
    sender: EntityId,
    key: &ReportDeliveryKey,
    signature: &ReportFrozenSignature,
    send: &ReportFrozenSend,
    now: u64,
) -> OutboundDispatchRequest {
    let intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new(
            sender.to_hex(),
            REPORT_SIGNATURE_VERB,
            send.destination.channel.as_str(),
            send.destination.endpoint.as_str(),
        )
        .content_ref(format!("{REPORT_SIGNATURE_SCHEMA}:{}", signature.digest))
        .idempotency_key(send.send_ref.clone()),
        OutboundIntentTrigger::agent_immediate(send.send_ref.clone()),
    );
    let mut request = OutboundDispatchRequest::new(
        send.send_ref.clone(),
        send.send_ref.clone(),
        intent,
        // An engine-owned send: first-party is the class whose ceiling is
        // Auto, and the participation grant still decides what it may send.
        OutboundDispatchActor {
            actor_class: "first_party".to_owned(),
            actor_ref: Some(sender.to_hex()),
            actor_entity_ref: Some(sender),
        },
        OutboundDispatchGate::allow_when_policy_grants(),
        now,
        OutboundDeliveryWindowDecision::DeliverNow,
    );
    request.ledger_identity_ref = Some(send.send_ref.clone());
    request.publisher_signature = Some(PublisherSignatureAuthorization::new(
        key.issue_ref.clone(),
        key.publisher_ref.clone(),
        send.destination.channel.clone(),
        send.destination.endpoint.clone(),
        signature.digest.clone(),
        send.send_ref.clone(),
    ));
    request
}

/// The canonical `oneiron.issue_signature.v1` body of a signature.
pub(super) fn wire_body(signature: &IssueSignature) -> Result<String> {
    let wire = WireSignature {
        schema: REPORT_SIGNATURE_SCHEMA.to_owned(),
        category: signature.category().as_str().to_owned(),
        artifact: signature.artifact().to_hex(),
        version: signature.version(),
        model_id: signature.model_id().as_str().to_owned(),
        counts: signature
            .counts()
            .map(|(key, value)| (key.as_str().to_owned(), value))
            .collect(),
        content_hash: signature.content_hash().to_owned(),
    };
    crate::llm::canonical_json_bytes(&wire)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .ok_or(Error::InvariantViolation("issue signature wire encode"))
}

/// The ED-08 signature a frozen body still is, checked again through its
/// only constructor; `None` unless it is one byte for byte.
pub(super) fn wire_signature(body: &str) -> Option<IssueSignature> {
    let wire: WireSignature = serde_json::from_str(body).ok()?;
    if wire.schema != REPORT_SIGNATURE_SCHEMA {
        return None;
    }
    let counts = wire
        .counts
        .iter()
        .map(|(key, value)| Some((CountKey::parse(key)?, *value)))
        .collect::<Option<Vec<_>>>()?;
    let signature = IssueSignature::new(
        IssueCategory::parse(&wire.category)?,
        EntityId::from_hex(&wire.artifact).ok()?,
        wire.version,
        &default_model_stack_registry(),
        &wire.model_id,
        &counts,
        &wire.content_hash,
    )
    .ok()?;
    (wire_body(&signature).ok()? == body).then_some(signature)
}
