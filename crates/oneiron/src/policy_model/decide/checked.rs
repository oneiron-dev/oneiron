//! The safeguard read's reply checks and its answer's output need (FIX 7803,
//! FIX 1202).
use std::sync::atomic::{AtomicBool, Ordering};

use crate::llm::decision::{AnswerContract, DecisionQuestion};
use crate::llm::{
    BudgetLease, ContentPart, FinishReason, LlmBackend, LlmCapability, LlmGenerateFuture,
    LlmRequest, LlmResponse, LlmStreamResult, ModelId,
};

/// The output tokens the read's JSON answer takes beside its questions'
/// entries: its braces (FIX 1202).
const READ_ANSWER_BASE_TOKENS: u64 = 32;
/// The output tokens one question's entry takes in the read's JSON answer
/// beside its labels: its id key and braces, and its paired entry.
const READ_ANSWER_TOKENS_PER_QUESTION: u64 = 64;
/// The output tokens one label's weight takes in the read's JSON answer: the
/// label, its number and their punctuation.
const READ_ANSWER_TOKENS_PER_LABEL: u64 = 16;

/// The output tokens the read's JSON answer to `questions` takes: each
/// question's entry and its labels' weights, and its paired entry when
/// `paired` rides the read.
pub(super) fn answer_tokens(questions: &[DecisionQuestion], paired: bool) -> u64 {
    let labels: u64 = questions
        .iter()
        .map(|question| match &question.contract {
            AnswerContract::Choice { options } => options.len() as u64,
            _ => 2,
        })
        .sum();
    let entries = questions.len() as u64 * if paired { 2 } else { 1 };
    READ_ANSWER_BASE_TOKENS
        .saturating_add(entries.saturating_mul(READ_ANSWER_TOKENS_PER_QUESTION))
        .saturating_add(labels.saturating_mul(READ_ANSWER_TOKENS_PER_LABEL))
}

/// The safeguard model's backend with its decision replies checked at the
/// read boundary (FIX 7803): a reply that did not finish with Stop, or that
/// carries a tool call, marks the read unusable, so no weight it carries
/// becomes a verdict. Every reply passes on unchanged, and settles its spend
/// as any reply does.
pub(super) struct CheckedReplies<'a> {
    backend: &'a dyn LlmBackend,
    unusable: AtomicBool,
    replied: AtomicBool,
}

impl<'a> CheckedReplies<'a> {
    pub(super) fn new(backend: &'a dyn LlmBackend) -> Self {
        Self {
            backend,
            unusable: AtomicBool::new(false),
            replied: AtomicBool::new(false),
        }
    }

    /// Whether any reply through it was unusable.
    pub(super) fn unusable(&self) -> bool {
        self.unusable.load(Ordering::Acquire)
    }

    /// Whether the backend gave any reply through it (FIX 1202).
    pub(super) fn replied(&self) -> bool {
        self.replied.load(Ordering::Acquire)
    }
}

/// A finished decision reply: stopped, with no tool call among its parts.
fn finished(response: &LlmResponse) -> bool {
    response.finish_reason == FinishReason::Stop
        && !response
            .message
            .content
            .iter()
            .any(|part| matches!(part, ContentPart::ToolCall { .. }))
}

impl LlmBackend for CheckedReplies<'_> {
    fn supports(&self, model: &ModelId, capability: LlmCapability) -> bool {
        self.backend.supports(model, capability)
    }

    fn generate<'b>(
        &'b self,
        request: LlmRequest,
        lease: &'b BudgetLease,
    ) -> LlmGenerateFuture<'b> {
        Box::pin(async move {
            let reply = self.backend.generate(request, lease).await;
            if let Ok(response) = &reply {
                self.replied.store(true, Ordering::Release);
                if !finished(response) {
                    self.unusable.store(true, Ordering::Release);
                }
            }
            reply
        })
    }

    fn stream<'b>(&'b self, request: LlmRequest, lease: &'b BudgetLease) -> LlmStreamResult<'b> {
        self.backend.stream(request, lease)
    }
}
