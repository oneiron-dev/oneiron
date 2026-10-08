//! One role's ladder as one backend: the engine sees a single seat model;
//! the ladder hands each call to its rungs in order until one answers.
use std::sync::Arc;

use futures_util::StreamExt;
use oneiron::{
    BudgetLease, ContentPart, LlmBackend, LlmCapability, LlmError, LlmGenerateFuture, LlmMessage,
    LlmMessageRole, LlmRequest, LlmResult, LlmStream, LlmStreamEvent, LlmStreamResult, ModelId,
};

use super::served::served_receipt;

/// One rung: a provider backend, the engine id of its model, and the
/// instruction prepended to every call it serves.
pub(super) struct LadderRung {
    pub(super) provider: String,
    pub(super) model: ModelId,
    pub(super) wire_model: String,
    pub(super) prompt: Option<String>,
    pub(super) backend: Arc<dyn LlmBackend>,
}

impl LadderRung {
    fn bind(&self, mut request: LlmRequest) -> LlmRequest {
        request.model = self.model.clone();
        if let Some(prompt) = &self.prompt {
            request.messages.insert(
                0,
                LlmMessage {
                    role: LlmMessageRole::System,
                    content: vec![ContentPart::Text {
                        text: prompt.clone(),
                    }],
                },
            );
        }
        request
    }

    fn stamp(&self, rung: usize, raw_provider: serde_json::Value) -> serde_json::Value {
        served_receipt(&self.provider, &self.wire_model, rung, raw_provider)
    }
}

/// A rung that fails hands the call on, unless the budget said no: a denied
/// lease is the same lease on every rung.
fn falls_through(error: &LlmError) -> bool {
    !matches!(error, LlmError::BudgetDenied(_))
}

/// The seat backend. Its only model is the seat id; every rung model is
/// private to it.
pub(super) struct LadderBackend {
    seat: ModelId,
    rungs: Vec<LadderRung>,
}

impl LadderBackend {
    pub(super) fn new(seat: ModelId, rungs: Vec<LadderRung>) -> Self {
        Self { seat, rungs }
    }

    fn admits(&self, request: &LlmRequest) -> LlmResult<()> {
        if request.model == self.seat && !self.rungs.is_empty() {
            Ok(())
        } else {
            Err(oneiron::FatalLlmError::InvalidRequest.into())
        }
    }
}

impl LlmBackend for LadderBackend {
    /// A capability holds only if every rung has it: a fallback rung must
    /// be able to serve the very request the first rung was sent.
    fn supports(&self, model: &ModelId, capability: LlmCapability) -> bool {
        *model == self.seat
            && !self.rungs.is_empty()
            && self
                .rungs
                .iter()
                .all(|rung| rung.backend.supports(&rung.model, capability.clone()))
    }

    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            self.admits(&request)?;
            let mut last = None;
            for (index, rung) in self.rungs.iter().enumerate() {
                match rung
                    .backend
                    .generate(rung.bind(request.clone()), lease)
                    .await
                {
                    Ok(mut response) => {
                        let raw = std::mem::take(&mut response.usage.raw_provider);
                        response.usage.raw_provider = rung.stamp(index, raw);
                        return Ok(response);
                    }
                    Err(error) if falls_through(&error) => {
                        tracing::warn!(seat = %self.seat, rung = index, provider = %rung.provider, ?error, "rung failed; trying the next");
                        last = Some(error);
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(last.unwrap_or_else(|| oneiron::FatalLlmError::InvalidRequest.into()))
        })
    }

    /// Falls through only before the first event: once a rung has spoken,
    /// its stream is the answer, cut or whole.
    fn stream<'a>(&'a self, request: LlmRequest, lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        self.admits(&request)?;
        let state = StreamState {
            ladder: self,
            request,
            lease,
            next_rung: 0,
            live: None,
            last_error: None,
            done: false,
        };
        Ok(LlmStream::new(futures_util::stream::unfold(
            state, next_event,
        )))
    }
}

struct StreamState<'a> {
    ladder: &'a LadderBackend,
    request: LlmRequest,
    lease: &'a BudgetLease,
    next_rung: usize,
    /// The rung streaming now, and whether it has produced an event yet.
    live: Option<(usize, LlmStream<'a>, bool)>,
    last_error: Option<LlmError>,
    /// Set after a terminal item; no further rung is tried.
    done: bool,
}

async fn next_event(
    mut state: StreamState<'_>,
) -> Option<(LlmResult<LlmStreamEvent>, StreamState<'_>)> {
    if state.done {
        return None;
    }
    loop {
        let Some((index, mut stream, started)) = state.live.take() else {
            let index = state.next_rung;
            let Some(rung) = state.ladder.rungs.get(index) else {
                let error = state
                    .last_error
                    .take()
                    .unwrap_or_else(|| oneiron::FatalLlmError::InvalidRequest.into());
                return Some((Err(error), state.finished()));
            };
            state.next_rung += 1;
            match rung
                .backend
                .stream(rung.bind(state.request.clone()), state.lease)
            {
                Ok(stream) => state.live = Some((index, stream, false)),
                Err(error) if falls_through(&error) => state.last_error = Some(error),
                Err(error) => return Some((Err(error), state.finished())),
            }
            continue;
        };
        match stream.next().await {
            Some(Ok(LlmStreamEvent::Done {
                message,
                mut usage,
                finish_reason,
            })) => {
                let raw = std::mem::take(&mut usage.raw_provider);
                usage.raw_provider = state.ladder.rungs[index].stamp(index, raw);
                let done = LlmStreamEvent::Done {
                    message,
                    usage,
                    finish_reason,
                };
                return Some((Ok(done), state.finished()));
            }
            Some(Ok(event)) => {
                state.live = Some((index, stream, true));
                return Some((Ok(event), state));
            }
            Some(Err(error)) if !started && falls_through(&error) => {
                tracing::warn!(seat = %state.ladder.seat, rung = index, ?error, "rung stream failed before its first event; trying the next");
                state.last_error = Some(error);
            }
            Some(Err(error)) => return Some((Err(error), state.finished())),
            None => return None,
        }
    }
}

impl StreamState<'_> {
    fn finished(mut self) -> Self {
        self.done = true;
        self.live = None;
        self
    }
}
