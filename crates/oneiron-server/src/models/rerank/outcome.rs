//! A rerank call that stops short (FIX 11228). Its batches share the call's
//! one admitted permit, so the call settles once, on what it used. Before
//! each later batch the line the call's caller admitted it on is asked
//! whether that batch still fits ([`RerankLine`]); one that would overrun it
//! is not sent. The call then answers the scores its finished batches gave,
//! with their usage, and settles on that usage as an answer: the finished
//! work is kept, and the call is never charged its whole reservation as a
//! failure for a batch it never sent. A later batch that fails ends the call
//! the same way ([`LATER_BATCH_FAILURE_ENDS_PARTIAL`]).
//! Entry: `rerank_outcome`, `on_line`.
use std::future::Future;
use std::sync::Arc;

use oneiron::{BudgetLease, ContentPart, LlmResponse};
use serde::{Deserialize, Serialize};

/// Whether a later batch's failure ends the call with its finished batches'
/// scores and usage (the Engine's call, 10-30 06:29), or fails the whole
/// call, unsettled work and all, so the ladder may try another rung for it.
pub(super) const LATER_BATCH_FAILURE_ENDS_PARTIAL: bool = true;

/// Why a rerank call stopped before its last batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RerankStop {
    /// The next batch would have overrun the call's admitted line.
    Line,
    /// A later batch failed.
    Failed,
}

/// The answer of a rerank call that stopped short: each document's score
/// from the batches that finished, `None` for every document no batch
/// scored, in document order, and why it stopped. A call that scored every
/// document answers the plain list of scores instead.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RerankPartial {
    pub(crate) scores: Vec<Option<f32>>,
    pub(crate) stopped: RerankStop,
}

impl RerankPartial {
    /// How many documents the finished batches scored.
    pub(crate) fn scored(&self) -> usize {
        self.scores.iter().filter(|score| score.is_some()).count()
    }
}

/// What a rerank call's answer holds.
pub(crate) enum RerankOutcome {
    /// One score per document, in order.
    Scored(Vec<f32>),
    /// The call stopped short.
    Partial(RerankPartial),
}

/// What a rerank call's answer holds: one score per document, in order, or
/// the partial of a call that stopped short.
pub(crate) fn rerank_outcome(response: &LlmResponse) -> Option<RerankOutcome> {
    let [ContentPart::Text { text }] = response.message.content.as_slice() else {
        return None;
    };
    if let Ok(scores) = serde_json::from_str(text) {
        return Some(RerankOutcome::Scored(scores));
    }
    serde_json::from_str(text).ok().map(RerankOutcome::Partial)
}

/// The line a rerank call's later batches go on, as the caller that
/// admitted the call answers for it.
pub(crate) trait RerankLine: Send + Sync {
    /// Whether the batch `next` may go on the permit `lease`, after the
    /// call's earlier batches sent `sent` and reported `used` units.
    fn admits(
        &self,
        lease: &BudgetLease,
        used: u64,
        query: &str,
        sent: &[&str],
        next: &[&str],
    ) -> bool;
}

tokio::task_local! {
    /// The line of the rerank call this task drives ([`on_line`]).
    static BATCH_LINE: Arc<dyn RerankLine>;
}

/// Drives `call`, a rerank call through its seat's ladder, with `line`
/// asked before each of its later batches. A rerank call driven outside one
/// sends every batch.
pub(crate) async fn on_line<F: Future>(line: Arc<dyn RerankLine>, call: F) -> F::Output {
    BATCH_LINE.scope(line, call).await
}

/// Whether the line of the call this task drives, when it set one, lets
/// the batch `next` go.
pub(super) fn line_admits(
    lease: &BudgetLease,
    used: u64,
    query: &str,
    sent: &[&str],
    next: &[&str],
) -> bool {
    BATCH_LINE
        .try_with(|line| line.admits(lease, used, query, sent, next))
        .unwrap_or(true)
}
