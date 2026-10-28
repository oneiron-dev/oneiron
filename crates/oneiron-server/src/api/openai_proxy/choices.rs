//! FIX 8188, 8189: every choice a call asks for, on the caller's own clock.
//!
//! Each choice is its own admitted model call on the call's one run, sent in
//! index order once the one before it settles, so `n` choices pace through
//! the ladder one call at a time and hold no more of it at once than one call
//! does. The caller's `deadline_ms`, counted once from when the call arrived
//! (before its caller is resolved), is the one clock for its recall, every
//! choice and each wait for a resting offer; nothing renews it. With no
//! deadline a choice waits for an offer as `generate` does, for the vault's
//! longest wait. Release and remember run after the last answer, outside the
//! clock, so an answer the model finished is never lost to it.

use std::time::Duration;

use axum::response::Response;
use oneiron::llm::run_admission::RunAdmission;
use oneiron::task_verb::sdk::{
    ChatCompletionChoice, ChatCompletionMemory, ChatCompletionMessage, ChatCompletionResponse,
    ChatCompletionRole,
};
use oneiron::{FatalLlmError, LlmError, LlmRequest, LlmResponse, RetryableLlmError};
use tokio::time::Instant;

use crate::models::OfferLadder;

/// The code a call the caller's clock cut answers with, raw (504) and on the
/// typed facade, which gives it the same status.
pub(in crate::api) const TIMEOUT_CODE: &str = "timeout";

/// The refusal of a call the caller's clock cut: 504 [`TIMEOUT_CODE`], as a
/// model call that ran out of time answers.
pub(super) fn timeout() -> Response {
    super::wire::upstream_error(RetryableLlmError::Timeout.into())
}

/// How many choices the body asks for: one when it names none. A count of
/// zero asks for nothing and is refused, as a malformed one is.
pub(super) fn choice_count(n: Option<u32>) -> Result<u32, Response> {
    match n {
        None => Ok(1),
        Some(0) => Err(super::wire::invalid(
            "n_unsupported",
            "n must be at least 1",
        )),
        Some(count) => Ok(count),
    }
}

/// The caller's clock: the instant its `deadline_ms` runs out, counted from
/// when the call arrived; none when it named none.
#[derive(Clone, Copy, Debug)]
pub(super) struct CallerClock {
    deadline: Option<Instant>,
}

impl CallerClock {
    /// The clock of a call that arrived at `arrived` with `deadline_ms`. A
    /// deadline past what the clock can count is as good as none being near:
    /// the call waits until `u32::MAX` seconds (about 136 years) after it
    /// arrived.
    pub(super) fn starting(arrived: Instant, deadline_ms: Option<u64>) -> Self {
        let deadline = deadline_ms.map(|ms| {
            arrived
                .checked_add(Duration::from_millis(ms))
                .unwrap_or_else(|| arrived + Duration::from_secs(u64::from(u32::MAX)))
        });
        Self { deadline }
    }

    /// Whether the caller's deadline has passed.
    pub(super) fn ran_out(&self) -> bool {
        self.deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
    }

    /// The recall's own `deadline_ms`: what is left of the caller's, when it
    /// is shorter than the call-mode deadline the recall takes otherwise.
    /// `None` keeps the call-mode deadline, as a call with no clock does.
    pub(super) fn recall_deadline_ms(&self, call_mode: Duration) -> Option<u64> {
        let left = self.deadline?.saturating_duration_since(Instant::now());
        (left < call_mode).then(|| {
            u64::try_from(left.as_millis())
                .unwrap_or(u64::MAX)
                .clamp(1, oneiron::memory::caps::MAX_RECALL_DEADLINE_MS)
        })
    }

    /// One choice's model call. With no deadline it is `generate`. With one,
    /// it waits for a resting offer only as long as the clock has left, sends
    /// no rung once the clock has run out, and is cut there if it is still
    /// out: a call the clock ended before any rung went out is a `timeout`,
    /// and one whose offers rested to the end says when they are back.
    async fn generate(
        self,
        ladder: &OfferLadder,
        run: &RunAdmission,
        request: LlmRequest,
    ) -> Result<LlmResponse, LlmError> {
        let Some(deadline) = self.deadline else {
            return ladder.generate(run, request, None).await;
        };
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(RetryableLlmError::Timeout.into());
        }
        let may_send = move || Instant::now() < deadline;
        let answered = tokio::time::timeout_at(
            deadline,
            ladder.generate_within(run, request, None, &may_send, left),
        )
        .await;
        match answered {
            Ok(Err(LlmError::Fatal(FatalLlmError::InvalidRequest))) if !may_send() => {
                Err(RetryableLlmError::Timeout.into())
            }
            Ok(answered) => answered,
            Err(_) => Err(RetryableLlmError::Timeout.into()),
        }
    }
}

/// The call's answers, choice 0 first: `count` answers to `request`, each
/// its own admitted call on `run`, in index order, on `clock`. A reply lists
/// every choice it asked for or none: any choice's failure is the call's
/// error, with its own code and timing, and a choice the clock cut is a
/// `timeout`.
pub(super) async fn answer_choices(
    ladder: &OfferLadder,
    run: &RunAdmission,
    request: LlmRequest,
    count: u32,
    clock: CallerClock,
) -> Result<(LlmResponse, Vec<LlmResponse>), LlmError> {
    let first = clock.generate(ladder, run, request.clone()).await?;
    let mut rest = Vec::new();
    for _ in 1..count {
        rest.push(clock.generate(ladder, run, request.clone()).await?);
    }
    Ok((first, rest))
}

/// Each answer's text, in choice order: what the reply releases and the
/// exchange proposes.
pub(super) fn answer_texts(first: &LlmResponse, rest: &[LlmResponse]) -> Vec<String> {
    std::iter::once(first)
        .chain(rest)
        .map(|answer| super::wire::answer_text(&answer.message))
        .collect()
}

/// The `chat.completion` object for every settled answer: choice 0 as
/// [`super::wire::completion`] builds it, each later choice under its own
/// index, and the usage every choice's call reported, summed.
pub(super) fn completion(
    id: &str,
    created: u64,
    model: &str,
    (first, rest): (&LlmResponse, &[LlmResponse]),
    oneiron: ChatCompletionMemory,
) -> ChatCompletionResponse {
    let mut reply = super::wire::completion(id, created, model, first, oneiron);
    for (index, answer) in (1u32..).zip(rest) {
        let usage = &mut reply.usage;
        usage.prompt_tokens = usage.prompt_tokens.saturating_add(answer.usage.input.total);
        usage.completion_tokens = usage
            .completion_tokens
            .saturating_add(answer.usage.output.total);
        usage.total_tokens = usage.prompt_tokens.saturating_add(usage.completion_tokens);
        reply.choices.push(ChatCompletionChoice {
            index,
            message: ChatCompletionMessage {
                role: ChatCompletionRole::Assistant,
                content: super::wire::answer_text(&answer.message),
            },
            finish_reason: super::wire::finish_reason(&answer.finish_reason).to_owned(),
        });
    }
    reply
}
