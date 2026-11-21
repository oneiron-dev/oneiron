//! The judge's input room (FIX-LIST
//! COMPACTION-CHECK-JUDGE-READS-WHOLE-OVER-ROOM-TURN; Engine ruling
//! COMPACTION-CHECK-OVER-JUDGE-ROOM-INTENT = A). The judge reads the summary
//! and its span whole, so a span past its model's context reached a call the
//! provider refuses. That refusal parked the check, and every later pass sent
//! the identical request again. The host now lends the judge model's input
//! window, and a check whose judge input does not fit it settles before any
//! call: `unreadable_evidence`, reason `span_past_judge_room`, its words
//! standing. The check gates nothing, so one settled finding is the honest
//! answer, and the summary stays as it is.

use oneiron_model::llm::{ContentPart, LlmRequest};

use super::{CompactionCheckModel, CompactionCheckVerdict, Settled};
use crate::dreamer_wake::DreamerAttemptExecution;

/// The reason a check settles with when its judge input does not fit the
/// judge's input window.
pub(super) const SPAN_PAST_JUDGE_ROOM: &str = "span_past_judge_room";

/// The finding a check settles with before it sends `request`, whose input
/// does not fit the window `model` lends: `unreadable_evidence`, the
/// evidence it read as `evidence_now`, its words standing. `None` when the
/// input fits, or when the host lends no window.
pub(super) fn exceeded(
    model: &CompactionCheckModel<'_>,
    request: &LlmRequest,
    evidence_now: &str,
) -> Option<Settled> {
    let window = model.window_tokens?;
    if judge_input_tokens(model, request) <= window {
        return None;
    }
    let mut settled = Settled::new(
        CompactionCheckVerdict::UnreadableEvidence,
        SPAN_PAST_JUDGE_ROOM,
    );
    settled.evidence_now = Some(evidence_now.to_owned());
    settled.words_live = true;
    Some(settled)
}

/// What a check that settled with no judge call ends as: completed, having
/// spent nothing.
pub(super) const fn completed_without_judge() -> DreamerAttemptExecution {
    DreamerAttemptExecution::Completed {
        completed_units: 0,
        step_bindings: Vec::new(),
    }
}

/// The input the judge's model is sent for one check, by the context-pack
/// tokenizer: every text of `request`, the rubric and the span as the
/// diagnostic step sends them, and, with the host's decisions lent, the
/// support question's wording, which the typed read sends beside the same
/// rubric and span on the same model.
fn judge_input_tokens(model: &CompactionCheckModel<'_>, request: &LlmRequest) -> u64 {
    let wording = model.decisions.as_ref().map_or(0, |decisions| {
        crate::count_context_pack_tokens(&decisions.wording) as u64
    });
    request
        .messages
        .iter()
        .flat_map(|message| &message.content)
        .map(|part| match part {
            ContentPart::Text { text, .. } => crate::count_context_pack_tokens(text) as u64,
            _ => 0,
        })
        .fold(wording, u64::saturating_add)
}
