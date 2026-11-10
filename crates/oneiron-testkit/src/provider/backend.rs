//! [`ScriptedBackend`]: the script as an in-process [`LlmBackend`], for door
//! tests that hand the engine a backend instead of an HTTP provider.
//!
//! The prompt digest is taken over the typed request's prompt fields
//! (`messages`, `tools`, `envelope.response_format`) as JSON, so it differs
//! from the HTTP body's digest of the same prompt:
//! [`ScriptedBackend::digest_of`] names the key.
//! `generate` is a buffered call and `stream` a streamed one.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use futures_core::Stream;
use oneiron::{
    BudgetLease, ContentPart, FatalLlmError, FinishReason, LlmBackend, LlmCapability, LlmError,
    LlmGenerateFuture, LlmInputUsage, LlmMessage, LlmMessageRole, LlmOutputUsage, LlmRequest,
    LlmResponse, LlmResult, LlmStream, LlmStreamEvent, LlmStreamResult, LlmUsage, ModelId,
    RetryableLlmError,
};
use serde_json::Value;

use super::digest::PromptDigest;
use super::script::{ProviderMismatch, Script, SeenCall};
use super::{Reply, Step, Usage};

/// The text part id every scripted stream uses.
const PART: &str = "0";

/// The in-process scripted model. See the module docs of
/// [`crate::provider`] for the script's rules.
pub struct ScriptedBackend {
    script: Script,
    finished: AtomicBool,
}

impl std::fmt::Debug for ScriptedBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScriptedBackend").finish_non_exhaustive()
    }
}

fn fatal(message: String) -> LlmError {
    LlmError::Fatal(FatalLlmError::InvalidRequestDetail {
        message: format!("oneiron-testkit: {message}"),
        code: None,
    })
}

fn status_error(status: u16) -> LlmError {
    if status == 429 || status >= 500 {
        LlmError::Retryable(RetryableLlmError::ServerError)
    } else {
        fatal(format!("scripted status {status}"))
    }
}

fn usage_of(usage: Option<Usage>) -> LlmUsage {
    let usage = usage.unwrap_or(Usage {
        input_tokens: 0,
        output_tokens: 0,
    });
    LlmUsage {
        input: LlmInputUsage {
            total: usage.input_tokens,
            cache_read: 0,
            cache_write: 0,
        },
        output: LlmOutputUsage {
            total: usage.output_tokens,
            text: usage.output_tokens,
            reasoning: 0,
        },
        raw_provider: Value::Null,
        call_metadata: None,
    }
}

fn assistant(text: String) -> LlmMessage {
    LlmMessage {
        role: LlmMessageRole::Assistant,
        content: vec![ContentPart::Text {
            text,
            signature: None,
        }],
    }
}

/// A stream over events already decided.
struct Events(VecDeque<LlmResult<LlmStreamEvent>>);

impl Stream for Events {
    type Item = LlmResult<LlmStreamEvent>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(self.get_mut().0.pop_front())
    }
}

impl ScriptedBackend {
    /// A backend answering from `steps`.
    ///
    /// # Errors
    /// Two steps share an id, or a step is held (barriers are HTTP-only).
    pub fn new(steps: Vec<Step>) -> io::Result<Self> {
        let (script, barriers) = Script::new(steps)?;
        if !barriers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "held steps need the HTTP ScriptedProvider; an in-process call cannot wait at a barrier",
            ));
        }
        Ok(Self {
            script,
            finished: AtomicBool::new(false),
        })
    }

    /// The digest a step must name to answer `request`.
    #[must_use]
    pub fn digest_of(request: &LlmRequest) -> PromptDigest {
        PromptDigest::of_request(&serde_json::to_value(request).unwrap_or(Value::Null))
    }

    /// Every call so far, in order.
    #[must_use]
    pub fn seen(&self) -> Vec<SeenCall> {
        self.script.seen()
    }

    /// The violations so far, plus every step that answers once and was
    /// never called.
    ///
    /// # Errors
    /// Any violation.
    pub fn check(&self) -> Result<(), ProviderMismatch> {
        self.script.check()
    }

    /// Ends the script: returns every call it saw.
    ///
    /// # Panics
    /// On any violation (see [`Self::check`]).
    pub fn finish(&self) -> Vec<SeenCall> {
        self.finished.store(true, Ordering::Release);
        if let Err(mismatch) = self.check() {
            panic!("{mismatch}");
        }
        self.seen()
    }

    fn call(&self, request: &LlmRequest, streamed: bool) -> LlmResult<Step> {
        let body = serde_json::to_value(request).unwrap_or(Value::Null);
        let model = body.get("model").and_then(Value::as_str).map(str::to_owned);
        let mut seen = SeenCall {
            step: None,
            method: if streamed { "stream" } else { "generate" }.to_owned(),
            path: model.clone().unwrap_or_default(),
            digest: None,
            streamed,
            model,
            body: body.clone(),
        };
        let answered = self.script.answer(&mut seen, &body);
        self.script.see(seen);
        let step = answered.map_err(fatal)?;
        if matches!(
            step.reply,
            Reply::Json(_) | Reply::Events(_) | Reply::Body { .. }
        ) {
            let violation = format!(
                "step {:?} answers with an HTTP-only reply; an in-process call takes Text, Deltas, Status or CutStream",
                step.id
            );
            self.script.violate(violation.clone());
            return Err(fatal(violation));
        }
        Ok(step)
    }
}

impl Drop for ScriptedBackend {
    fn drop(&mut self) {
        if self.finished.load(Ordering::Acquire) || std::thread::panicking() {
            return;
        }
        if let Err(mismatch) = self.check() {
            panic!("{mismatch}");
        }
    }
}

impl LlmBackend for ScriptedBackend {
    /// The script answers whatever it is asked; capability checks are the
    /// engine's to make against its own catalog.
    fn supports(&self, _model: &ModelId, _capability: LlmCapability) -> bool {
        true
    }

    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let answer = self.call(&request, false).and_then(|step| {
            let usage = usage_of(step.usage);
            match step.reply {
                Reply::Text(text) => Ok((text, usage)),
                Reply::Deltas(deltas) => Ok((deltas.concat(), usage)),
                Reply::Status(status) => Err(status_error(status)),
                _ => Err(fatal(format!(
                    "step {:?} cannot answer a buffered call",
                    step.id
                ))),
            }
        });
        Box::pin(async move {
            let (text, usage) = answer?;
            // A finished answer with no content is no answer: the real
            // adapters refuse it, and so does the script.
            if text.is_empty() {
                return Err(LlmError::Fatal(FatalLlmError::EmptyResponse));
            }
            Ok(LlmResponse {
                message: assistant(text),
                usage,
                finish_reason: FinishReason::Stop,
                reply_assertions: Default::default(),
                token_scores: None,
            })
        })
    }

    fn stream<'a>(&'a self, request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        let step = self.call(&request, true)?;
        let (deltas, complete) = match &step.reply {
            Reply::Text(text) => (vec![text.clone()], true),
            Reply::Deltas(deltas) => (deltas.clone(), true),
            Reply::Status(status) => return Err(status_error(*status)),
            Reply::CutStream { deltas, after } => {
                (deltas[..(*after).min(deltas.len())].to_vec(), false)
            }
            _ => {
                return Err(fatal(format!(
                    "step {:?} cannot answer a streamed call",
                    step.id
                )));
            }
        };
        if complete && deltas.concat().is_empty() {
            return Err(LlmError::Fatal(FatalLlmError::EmptyResponse));
        }
        let mut events: VecDeque<LlmResult<LlmStreamEvent>> = VecDeque::new();
        events.push_back(Ok(LlmStreamEvent::TextStart {
            part_id: PART.to_owned(),
        }));
        for text in &deltas {
            events.push_back(Ok(LlmStreamEvent::TextDelta {
                part_id: PART.to_owned(),
                text: text.clone(),
            }));
        }
        if complete {
            events.push_back(Ok(LlmStreamEvent::TextEnd {
                part_id: PART.to_owned(),
                signature: None,
            }));
            events.push_back(Ok(LlmStreamEvent::Done {
                message: assistant(deltas.concat()),
                usage: usage_of(step.usage),
                finish_reason: FinishReason::Stop,
                reply_assertions: Default::default(),
            }));
        }
        // With no Done, the engine's stream wrapper ends the cut stream with
        // its own StreamCut error, as it does for a provider that died.
        Ok(LlmStream::new(Events(events)))
    }
}
