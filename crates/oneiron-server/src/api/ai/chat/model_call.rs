//! Model-call evidence from the actual answering leg, independent of delivery,
//! and the drafter's view of the same leg (FIX 15128, FIX 15129): its call as
//! its rung sent it and the span it generated.

use std::sync::{Arc, Mutex};

use futures_util::StreamExt;
use oneiron::llm::run_admission::RunAdmission;
use oneiron::{
    ContentPart, EntityId, FinishReason, LlmMessage, LlmMessageRole, LlmRequest, LlmResponse,
    LlmResult, LlmStream, LlmStreamEvent, Vault,
};
use tokio::sync::{mpsc, oneshot};

use super::TurnCredential;
use crate::models::{ModelCallBinding, OfferLadder, RoleCall};

/// Retention for evidence written directly to base, not the session overlay.
pub(crate) fn model_call_keeps_no_record(
    vault: &Vault,
    caller: EntityId,
    session: Option<&str>,
    room: Option<EntityId>,
    container: Option<EntityId>,
) -> bool {
    vault.model_call_keeps_no_record_for(session, Some(caller))
        || room
            .into_iter()
            .chain(container)
            .any(|room| vault.room_has_unrecorded_stretch(room))
}

struct CompletedCall {
    run: RunAdmission,
    request: LlmRequest,
    ladder: Arc<OfferLadder>,
    binding: oneshot::Receiver<ModelCallBinding>,
}

#[derive(Clone)]
pub(super) struct Recorder(mpsc::Sender<CompletedCall>);

pub(super) struct Capture {
    caller: EntityId,
    room: Option<EntityId>,
    no_record_at_arrival: bool,
    terminal: mpsc::Receiver<CompletedCall>,
    answered: AnsweredSlot,
}

/// The answering leg's call as its rung sent it and what it generated, for
/// the drafter's training example (FIX 15128, FIX 15129). Taken at the
/// terminal, before the reply is saved, only for a call whose model-call
/// record is kept.
pub(super) struct AnsweredCall {
    /// The request exactly as the answering rung sent it.
    pub(super) request: LlmRequest,
    /// The model the answering rung's wire named.
    pub(super) wire_model: String,
    /// The weights identity the answering worker reported for the call
    /// (its inference receipt's `CacheIdentity` model digest), the identity
    /// a drafter target names; `None` when no receipt names one.
    pub(super) target_model: Option<String>,
    /// The terminal's message: its reasoning, tool calls and text, in order.
    pub(super) generated: LlmMessage,
    pub(super) finish_reason: FinishReason,
}

/// Where the producer leaves the answering call for the reply's post-save
/// hooks.
pub(super) type AnsweredSlot = Arc<Mutex<Option<AnsweredCall>>>;

/// `request` as the rung `binding` names sent it, as the ladder binds a
/// rung's call: its model at that rung's locality, its route prompt as the
/// first message, each cache boundary moved past it. The segment manifest
/// is never serialized and stays as it was.
fn sent_request(request: &LlmRequest, binding: &ModelCallBinding) -> LlmRequest {
    let mut sent = request.clone();
    sent.model = binding.rung.model.clone();
    sent.envelope.locality = binding.rung.locality;
    if let Some(prompt) = &binding.rung.prompt {
        sent.messages.insert(
            0,
            LlmMessage {
                role: LlmMessageRole::System,
                content: vec![ContentPart::Text {
                    text: prompt.clone(),
                }],
            },
        );
        oneiron::code_run::shift_cache_boundaries(&mut sent);
    }
    sent
}

pub(super) fn channel(
    caller: EntityId,
    room: Option<EntityId>,
    no_record_at_arrival: bool,
) -> (Recorder, Capture) {
    // Only the answering leg yields a terminal; failed prefix attempts send none.
    let (send, terminal) = mpsc::channel(1);
    (
        Recorder(send),
        Capture {
            caller,
            room,
            no_record_at_arrival,
            terminal,
            answered: AnsweredSlot::default(),
        },
    )
}

impl Recorder {
    pub(super) fn stream(
        &self,
        run: &RunAdmission,
        call: RoleCall,
    ) -> LlmResult<LlmStream<'static>> {
        let request = call.request.clone();
        let (stream, binding) = call.ladder.stream_recorded(run, call.request, None)?;
        let mut completed = Some(CompletedCall {
            run: run.clone(),
            request,
            ladder: call.ladder,
            binding,
        });
        let send = self.0.clone();
        Ok(LlmStream::new(stream.map(move |item| {
            if matches!(&item, Ok(LlmStreamEvent::Done { .. }))
                && let Some(call) = completed.take()
            {
                // The ladder sends its binding before Done; forward this leg's
                // context before the independent producer sees that same Done.
                let _ = send.try_send(call);
            }
            item
        })))
    }
}

impl Capture {
    /// Where [`Self::record`] leaves the answering call for the drafter.
    pub(super) fn answered(&self) -> AnsweredSlot {
        Arc::clone(&self.answered)
    }

    pub(super) fn record(
        &mut self,
        vault: &Vault,
        credential: &TurnCredential,
        container: Option<EntityId>,
        event: &LlmStreamEvent,
    ) {
        let LlmStreamEvent::Done {
            message,
            usage,
            finish_reason,
            reply_assertions,
            ..
        } = event
        else {
            return;
        };
        let session = match credential {
            TurnCredential::Request { auth, .. } => auth.off_record_session(),
            TurnCredential::Action { .. } => None,
        };
        if self.no_record_at_arrival
            || !credential.live()
            || model_call_keeps_no_record(vault, self.caller, session, self.room, container)
        {
            return;
        }
        let Ok(mut call) = self.terminal.try_recv() else {
            tracing::warn!("chat terminal has no answering model-call context");
            return;
        };
        let binding = call.binding.try_recv().ok();
        // FIX 15128: the drafter's view of the leg, by the rung that
        // answered; a leg that names no route is no example.
        if let Some(binding) = binding.as_ref()
            && let Some(route) = binding.route.as_ref()
            && let Ok(mut slot) = self.answered.lock()
        {
            *slot = Some(AnsweredCall {
                request: sent_request(&call.request, binding),
                wire_model: route.wire_model.clone(),
                target_model: usage
                    .inference_calls()
                    .last()
                    .and_then(|receipt| receipt.worker.identity.model.as_ref())
                    .map(|model| model.as_str().to_owned()),
                generated: message.clone(),
                finish_reason: finish_reason.clone(),
            });
        }
        let response = LlmResponse {
            message: message.clone(),
            usage: usage.clone(),
            finish_reason: finish_reason.clone(),
            reply_assertions: reply_assertions.clone(),
            token_scores: None,
        };
        // Attribution is added only after the provider terminal. The live run
        // must keep its original resident-share admission and charging.
        let evidence = call.run.initiated_by(Some(self.caller));
        crate::server::blocking(|| {
            crate::api::record_raw_response(
                vault,
                &call.ladder,
                &evidence,
                &call.request,
                &response,
                binding.as_ref(),
                false,
            );
        });
    }
}
