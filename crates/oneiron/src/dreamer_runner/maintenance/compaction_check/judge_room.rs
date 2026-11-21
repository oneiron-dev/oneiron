//! The judge's input room (FIX-LIST
//! COMPACTION-CHECK-JUDGE-READS-WHOLE-OVER-ROOM-TURN; Engine ruling
//! COMPACTION-CHECK-OVER-JUDGE-ROOM-INTENT = A). The judge reads the summary
//! and its span whole, so a span past its model's context reached a call the
//! provider refuses. That refusal parked the check, and every later pass sent
//! the identical request again. The host now lends the judge model's input
//! window, and a check whose judge input does not fit it settles before any
//! call (the diagnostic request and the typed read's, each as it is sent):
//! `unreadable_evidence`, reason `span_past_judge_room`, its words
//! standing. The check gates nothing, so one settled finding is the honest
//! answer, and the summary stays as it is.

use oneiron_model::llm::{ContentPart, LlmRequest};

use super::support::{self, Ask};
use super::{CompactionCheckModel, CompactionCheckVerdict, Settled};
use crate::Result;
use crate::dreamer_wake::DreamerAttemptExecution;

/// The reason a check settles with when its judge input does not fit the
/// judge's input window.
pub(super) const SPAN_PAST_JUDGE_ROOM: &str = "span_past_judge_room";

/// The finding a check settles with before it sends `request`, the
/// diagnostic step, when it or the typed read about `ask` does not fit the
/// window `model` lends: `unreadable_evidence`, the evidence it read as
/// `evidence_now`, its words standing. `None` when both fit, or when the host
/// lends no window.
///
/// # Errors
///
/// The support question's own errors.
pub(super) fn exceeded(
    model: &CompactionCheckModel<'_>,
    request: &LlmRequest,
    ask: &Ask<'_>,
    evidence_now: &str,
) -> Result<Option<Settled>> {
    let Some(window) = model.window_tokens else {
        return Ok(None);
    };
    let typed = support::typed_request(model, ask)?;
    if std::iter::once(request)
        .chain(typed.as_ref())
        .all(|request| input_tokens(request) <= window)
    {
        return Ok(None);
    }
    let mut settled = Settled::new(
        CompactionCheckVerdict::UnreadableEvidence,
        SPAN_PAST_JUDGE_ROOM,
    );
    settled.evidence_now = Some(evidence_now.to_owned());
    settled.words_live = true;
    Ok(Some(settled))
}

/// What a check that settled with no judge call ends as: completed, having
/// spent nothing.
pub(super) const fn completed_without_judge() -> DreamerAttemptExecution {
    DreamerAttemptExecution::Completed {
        completed_units: 0,
        step_bindings: Vec::new(),
    }
}

/// The input `request` sends the judge's model, by the context-pack
/// tokenizer: every text of its messages. The diagnostic step sends the
/// rubric and the span; the typed read sends the same rubric and the span
/// inside its question turn, as the ladder renders it on the same model.
fn input_tokens(request: &LlmRequest) -> u64 {
    request
        .messages
        .iter()
        .flat_map(|message| &message.content)
        .map(|part| match part {
            ContentPart::Text { text, .. } => crate::count_context_pack_tokens(text) as u64,
            _ => 0,
        })
        .fold(0, u64::saturating_add)
}
