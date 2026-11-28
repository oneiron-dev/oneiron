//! What a chat call's request was assembled from (UNBUILT3-41, FIX
//! HANDOFF-CONTEXT), taken where `start_turn` assembles it and kept on the
//! call's record. A thread reader marks where the model changed by adjacent
//! calls (`vault.conversations.turns.models`) and reads here what context
//! the new model got. Each form follows the branch the request took, never
//! a digest: two requests whose bytes differ keep the forms their assembly
//! gave them.

use oneiron::code_run::model_call::{ModelCallBoard, ModelCallContext, ModelCallHistory};
use oneiron::compaction::ChatLog;

/// The earlier lines of a self agent's turn: its retained log, read as its
/// caller reads it. A log with no line is a first turn. Its raw turns are
/// every turn whose lines the request carried, pinned or not: a reply cut
/// at the token limit keeps its saved text in the next request, and no
/// projection pins it.
pub(super) fn retained_log(log: &ChatLog) -> ModelCallHistory {
    if log.lines.is_empty() {
        return ModelCallHistory::Cold;
    }
    ModelCallHistory::RetainedLog {
        summaries: log.summaries.clone(),
        raw_turns: log.raw_turns.clone(),
    }
}

/// The earlier lines of any other turn: the latest `bound` of the `sent`
/// lines the caller sent. None sent is a first turn.
pub(super) fn caller_lines(sent: usize, bound: usize) -> ModelCallHistory {
    if sent == 0 {
        return ModelCallHistory::Cold;
    }
    let kept = sent.min(bound);
    ModelCallHistory::CallerLines {
        kept: u64::try_from(kept).unwrap_or(u64::MAX),
        dropped: u64::try_from(sent - kept).unwrap_or(u64::MAX),
    }
}

/// A chat turn's form: its earlier lines, and whether its board rode the
/// admitted call (`recalled`), was read and left out (`omitted`), or was
/// none.
pub(super) fn turn(history: ModelCallHistory, recalled: bool, omitted: bool) -> ModelCallContext {
    let board = if recalled {
        ModelCallBoard::Rode
    } else if omitted {
        ModelCallBoard::Omitted
    } else {
        ModelCallBoard::Absent
    };
    ModelCallContext::Turn { history, board }
}
