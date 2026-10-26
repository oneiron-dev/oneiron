//! An admitted block of any size, scored in batches of [`BATCH_SIZE`] taken
//! one after another in candidate order, each in its turn on the host's line.

use std::time::Instant;

use super::{BATCH_SIZE, CrossEncoder, invalid};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::rerank::RerankCandidate;
use crate::retrieval_depth::{BackendSpend, RetrievalResult};
use crate::work_line::{LinePermit, WorkLine};

/// The host's fair line for crossencoder requests, and the caller's place in
/// it. Each batch takes one permit under `key`, outside any engine
/// transaction, and holds it through that batch's transport call. A wait ends
/// at the caller's request deadline, or at the line's own wait without one.
#[derive(Clone)]
pub struct CrossEncoderWork {
    line: WorkLine<EntityId>,
    key: EntityId,
    deadline: Option<Instant>,
}

impl CrossEncoderWork {
    /// `line` is shared by every crossencoder request the host serves, `key`
    /// is the caller the line is fair across, and `deadline` is that caller's
    /// existing request deadline, if it has one.
    pub fn new(line: WorkLine<EntityId>, key: EntityId, deadline: Option<Instant>) -> Self {
        Self {
            line,
            key,
            deadline,
        }
    }
}

impl CrossEncoder {
    /// Sends every batch through the host's fair line.
    pub fn with_work(mut self, work: CrossEncoderWork) -> Self {
        self.work = Some(work);
        self
    }

    /// One batch's turn on the host's line; `None` when the host gave none.
    pub(super) fn admit_turn(&self) -> Result<Option<LinePermit>> {
        let Some(work) = &self.work else {
            return Ok(None);
        };
        let admitted = match work.deadline {
            Some(deadline) => work
                .line
                .admit_blocking_for(work.key, deadline.saturating_duration_since(Instant::now())),
            None => work.line.admit_blocking(work.key),
        };
        admitted
            .map(Some)
            .map_err(|_| invalid("crossencoder request deadline passed before its turn"))
    }

    /// Scores every admitted candidate in batches of [`BATCH_SIZE`], in
    /// candidate order, one batch after another; the scores keep that order.
    /// Each batch is passed what remains of `token_budget` after the batches
    /// before it. A failed batch's error carries its own usage and every
    /// completed batch's, once.
    pub(super) fn score_batches(
        &self,
        query: &str,
        candidates: &[RerankCandidate<'_>],
        token_budget: Option<u64>,
    ) -> RetrievalResult<BackendSpend<Vec<f32>>> {
        let mut scores = Vec::with_capacity(candidates.len());
        let mut spent = 0_u64;
        for batch in candidates.chunks(BATCH_SIZE) {
            let remaining = token_budget.map(|budget| budget.saturating_sub(spent));
            let scored = self.score(query, batch, remaining).map_err(|mut failure| {
                failure.tokens_used = failure.tokens_used.saturating_add(spent);
                failure
            })?;
            spent = spent.saturating_add(scored.tokens_used);
            scores.extend(scored.value);
        }
        Ok(BackendSpend {
            value: scores,
            tokens_used: spent,
        })
    }
}
