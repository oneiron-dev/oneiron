//! Model-call evidence from the actual answering leg, independent of delivery.

use std::sync::Arc;

use futures_util::StreamExt;
use oneiron::llm::run_admission::RunAdmission;
use oneiron::{EntityId, LlmRequest, LlmResponse, LlmResult, LlmStream, LlmStreamEvent, Vault};
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
