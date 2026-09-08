//! Feedback dispatch and export: send context, transport adapter, dispatch request building, send, and air-gapped export.

use std::collections::BTreeMap;

use crate::genui::ConsentActionEvaluation;
use crate::outbound::{
    OutboundDeliveryWindowDecision, OutboundDispatchActor, OutboundDispatchGate,
    OutboundDispatchRequest, OutboundDispatchResult, OutboundExecutionOutcome,
    OutboundExecutionRequest, OutboundExecutionSink, OutboundIntent, OutboundIntentDraft,
    OutboundIntentTrigger, outbound_verb_contract,
};

use super::bundle::{FEEDBACK_BUNDLE_ENCODING, FEEDBACK_SEND_VERB};
use super::consent::{
    FeedbackApproval, FeedbackApprovalScope, FeedbackPreview, FeedbackSendRoute,
    feedback_logical_send_ref, validate_feedback_approval,
};
use super::error::FeedbackError;

/// Receipt field naming the typed feedback verb behind an outbound effect.
pub const FEEDBACK_RECEIPT_FIELD_VERB: &str = "feedback_verb";

/// Receipt field naming the bundle encoding that crossed the wire.
pub const FEEDBACK_RECEIPT_FIELD_BUNDLE_ENCODING: &str = "feedback_bundle_encoding";

/// Receipt field carrying the lowercase hex bundle digest.
pub const FEEDBACK_RECEIPT_FIELD_BUNDLE_DIGEST: &str = "feedback_bundle_digest";

/// Receipt field referencing the approval receipt that authorized the send.
pub const FEEDBACK_RECEIPT_FIELD_APPROVAL_RECEIPT_REF: &str = "feedback_approval_receipt_ref";

/// Everything the send needs beyond the bundle and the approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedbackSendContext {
    /// Where the bundle is allowed to go.
    pub route: FeedbackSendRoute,
    /// Who is dispatching.
    pub actor: OutboundDispatchActor,
    /// Principal the actor acts for, when there is one.
    pub on_behalf_of: Option<String>,
    /// When the send happens.
    pub occurred_at: u64,
    /// Delivery-window decision supplied by the caller.
    pub window_decision: OutboundDeliveryWindowDecision,
}

impl FeedbackSendContext {
    /// Builds a send context that delivers now.
    #[must_use]
    pub fn new(
        route: FeedbackSendRoute,
        actor: OutboundDispatchActor,
        occurred_at: u64,
        window_decision: OutboundDeliveryWindowDecision,
    ) -> Self {
        Self {
            route,
            actor,
            on_behalf_of: None,
            occurred_at,
            window_decision,
        }
    }

    /// Names the principal this send acts for.
    #[must_use]
    pub fn on_behalf_of(mut self, principal: impl Into<String>) -> Self {
        self.on_behalf_of = Some(principal.into());
        self
    }
}

/// What a feedback transport is handed when the pipeline reaches execution.
pub struct FeedbackTransportRequest<'a> {
    /// The ordinary outbound execution request, unmodified.
    pub execution: &'a OutboundExecutionRequest<'a>,
    /// The exact previewed bundle bytes.
    pub bundle_bytes: &'a [u8],
    /// Lowercase hex digest of those bytes.
    pub bundle_digest: &'a str,
    /// Encoding token those bytes were produced under.
    pub bundle_encoding: &'static str,
    /// Approval receipt that authorized this send.
    pub approval_receipt_ref: &'a str,
}

/// A transport that can carry feedback bundle bytes.
///
/// This is the feedback-shaped face of the ordinary outbound execution sink.
/// The adapter that wraps it is private, so a transport can never be reached
/// except through an approved, gated dispatch.
pub trait FeedbackTransport {
    /// Delivers the bundle and reports an ordinary execution outcome.
    fn send_feedback_bundle(
        &mut self,
        request: &FeedbackTransportRequest<'_>,
    ) -> OutboundExecutionOutcome;
}

/// Wraps a feedback transport as an ordinary outbound execution sink.
///
/// This is the only place the four feedback receipt fields are appended, and
/// it only runs when the pipeline actually executes. A replay that
/// short-circuits before execution never reaches here, so it never reinserts
/// transport fields onto a receipt that did not transport anything.
struct FeedbackOutboundAdapter<'a, T> {
    transport: &'a mut T,
    bundle_bytes: &'a [u8],
    bundle_digest: &'a str,
    approval_receipt_ref: &'a str,
    calls: usize,
}

impl<T: FeedbackTransport> OutboundExecutionSink for FeedbackOutboundAdapter<'_, T> {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        self.calls += 1;
        let feedback_request = FeedbackTransportRequest {
            execution: request,
            bundle_bytes: self.bundle_bytes,
            bundle_digest: self.bundle_digest,
            bundle_encoding: FEEDBACK_BUNDLE_ENCODING,
            approval_receipt_ref: self.approval_receipt_ref,
        };
        let mut outcome = self.transport.send_feedback_bundle(&feedback_request);
        append_feedback_receipt_fields(
            &mut outcome.receipt_fields,
            self.bundle_digest,
            self.approval_receipt_ref,
        );
        outcome
    }
}

/// Appends the four feedback transport fields, if absent.
///
/// Append-if-absent with blank keys and blank values dropped, matching the
/// engine's own execution-field merge. An adapter cannot overwrite a field the
/// dispatcher already stamped.
fn append_feedback_receipt_fields(
    fields: &mut BTreeMap<String, String>,
    digest: &str,
    approval_receipt_ref: &str,
) {
    let entries = [
        (FEEDBACK_RECEIPT_FIELD_VERB, FEEDBACK_SEND_VERB),
        (
            FEEDBACK_RECEIPT_FIELD_BUNDLE_ENCODING,
            FEEDBACK_BUNDLE_ENCODING,
        ),
        (FEEDBACK_RECEIPT_FIELD_BUNDLE_DIGEST, digest),
        (
            FEEDBACK_RECEIPT_FIELD_APPROVAL_RECEIPT_REF,
            approval_receipt_ref,
        ),
    ];
    for (key, value) in entries {
        if key.trim().is_empty() || value.trim().is_empty() {
            continue;
        }
        fields
            .entry(key.to_owned())
            .or_insert_with(|| value.to_owned());
    }
}

/// Builds the outbound dispatch request for one approved feedback send.
///
/// Validates the approval FIRST, so a stale digest or a different destination
/// fails before an outbound contract is resolved, before the gate runs, and
/// before any transport exists. The route's carrier pair is then resolved
/// against the carriers this deployment already registers, so a channel and
/// verb it cannot dispatch through fails typed here instead of travelling as
/// far as the dispatch pipeline. The logical send identity is written
/// byte-for-byte into the request receipt id, the intent reference, the ledger
/// identity, and the intent idempotency key, so every replay of one approved
/// send is one send.
pub fn feedback_dispatch_request(
    preview: &FeedbackPreview,
    context: &FeedbackSendContext,
    evaluation: &ConsentActionEvaluation,
) -> Result<OutboundDispatchRequest, FeedbackError> {
    context.route.validate()?;
    let scope = FeedbackApprovalScope::Send(context.route.clone());
    let approval = validate_feedback_approval(preview, &scope, evaluation)?;
    let actor_ref = context
        .actor
        .actor_ref
        .as_deref()
        .map(str::trim)
        .filter(|reference| !reference.is_empty())
        .ok_or_else(|| {
            FeedbackError::InvalidBundle(
                "feedback send requires a dispatch actor with an actor_ref".to_owned(),
            )
        })?;
    outbound_verb_contract(&context.route.channel, &context.route.verb)
        .map_err(|capability| FeedbackError::UnsupportedRoute(capability.to_string()))?;
    let logical_send_ref =
        feedback_logical_send_ref(&preview.digest, approval.approval_receipt_ref());
    let intent = feedback_intent(preview, context, &approval, actor_ref, &logical_send_ref);
    Ok(feedback_request_envelope(context, intent, logical_send_ref))
}

fn feedback_intent(
    preview: &FeedbackPreview,
    context: &FeedbackSendContext,
    approval: &FeedbackApproval,
    actor_ref: &str,
    logical_send_ref: &str,
) -> OutboundIntent {
    let mut draft = OutboundIntentDraft::new(
        actor_ref,
        context.route.verb.clone(),
        context.route.channel.clone(),
        context.route.target.clone(),
    )
    .content_ref(preview.content_ref())
    .idempotency_key(logical_send_ref);
    if let Some(principal) = context.on_behalf_of.as_deref() {
        draft = draft.on_behalf_of(principal);
    }
    OutboundIntent::from_trigger(
        draft,
        OutboundIntentTrigger::agent_immediate(approval.approval_receipt_ref()),
    )
}

fn feedback_request_envelope(
    context: &FeedbackSendContext,
    intent: OutboundIntent,
    logical_send_ref: String,
) -> OutboundDispatchRequest {
    let mut request = OutboundDispatchRequest::new(
        logical_send_ref.clone(),
        logical_send_ref.clone(),
        intent,
        context.actor.clone(),
        OutboundDispatchGate::allow_when_policy_grants(),
        context.occurred_at,
        context.window_decision.clone(),
    );
    if let Some(identity_ref) = context.route.channel_identity_ref {
        request = request.channel_identity_ref(identity_ref);
    }
    if let Some(counterparty) = context.route.counterparty_ref.as_deref() {
        request = request.counterparty_ref(counterparty);
    }
    request.ledger_identity_ref = Some(logical_send_ref);
    request
}

/// What one feedback send produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedbackSendOutcome {
    /// The ordinary dispatch result, gate lineage and receipt included.
    pub dispatch: OutboundDispatchResult,
    /// The logical send identity this send was keyed by.
    pub logical_send_ref: String,
    /// Digest of the bytes that were authorized.
    pub bundle_digest: String,
    /// Approval receipt that authorized the send.
    pub approval_receipt_ref: String,
    /// How many times the transport was actually called.
    pub transport_calls: usize,
}

/// Sends one approved feedback bundle as an ordinary outbound effect.
///
/// Nothing here is a feedback-specific escape hatch. The dispatch crosses the
/// ordinary pipeline, and the gate stays authoritative: the gate facts this
/// function supplies are the host's per-bundle opt-in and permission, freshly
/// granted by the principal for this exact bundle and this exact route. Policy
/// class, opt-out where a contact is addressable, and budget arms all still
/// decide the outcome, and a held or denied dispatch never reaches the
/// transport.
pub fn send_feedback<T>(
    vault: &crate::Vault,
    preview: &FeedbackPreview,
    context: &FeedbackSendContext,
    evaluation: &ConsentActionEvaluation,
    transport: &mut T,
) -> Result<FeedbackSendOutcome, FeedbackError>
where
    T: FeedbackTransport,
{
    let request = feedback_dispatch_request(preview, context, evaluation)?;
    let logical_send_ref = request.receipt_id.clone();
    let approval_receipt_ref = request.intent.trigger_ref.clone();
    let mut adapter = FeedbackOutboundAdapter {
        transport,
        bundle_bytes: &preview.bytes,
        bundle_digest: &preview.digest,
        approval_receipt_ref: &approval_receipt_ref,
        calls: 0,
    };
    let dispatch = vault
        .dispatch_outbound_intent(request, &mut adapter)
        .map_err(|error| FeedbackError::Dispatch(Box::new(error)))?;
    let transport_calls = adapter.calls;
    Ok(FeedbackSendOutcome {
        dispatch,
        logical_send_ref,
        bundle_digest: preview.digest.clone(),
        approval_receipt_ref,
        transport_calls,
    })
}

/// What one air-gapped export produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedbackExportOutcome {
    /// Digest of the exported bytes.
    pub bundle_digest: String,
    /// Encoding token those bytes were produced under.
    pub bundle_encoding: &'static str,
    /// Approval receipt that authorized the export.
    pub approval_receipt_ref: String,
    /// How many bytes were written.
    pub bytes_written: usize,
}

/// Writes the exact previewed bytes to a caller-supplied writer.
///
/// This is the air-gapped path: it opens no path, no socket, and no
/// subprocess, and it acquires nothing from the ambient environment. The
/// caller owns the destination completely — a buffer, a file it already
/// opened, whatever it chose. An approval scoped to a SEND is not an approval
/// to export, and is rejected before a single byte is written.
pub fn export_feedback_bundle<W>(
    preview: &FeedbackPreview,
    evaluation: &ConsentActionEvaluation,
    writer: &mut W,
) -> Result<FeedbackExportOutcome, FeedbackError>
where
    W: std::io::Write + ?Sized,
{
    let approval = validate_feedback_approval(preview, &FeedbackApprovalScope::Export, evaluation)?;
    writer
        .write_all(&preview.bytes)
        .map_err(FeedbackError::ExportWrite)?;
    Ok(FeedbackExportOutcome {
        bundle_digest: preview.digest.clone(),
        bundle_encoding: FEEDBACK_BUNDLE_ENCODING,
        approval_receipt_ref: approval.approval_receipt_ref().to_owned(),
        bytes_written: preview.bytes.len(),
    })
}
