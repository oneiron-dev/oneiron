//! The agent's complete diary read/review log view (OF-490): the persisted
//! read rows and review requests, newest first, with no hidden count cut.
//! An omitted limit returns everything; an explicit one is the caller's own
//! recent-window choice, and spent requests join only on `include_used`.

use super::{
    DIARY_READ_LOG, DIARY_READ_REQUEST, DiaryReadsRequest, DiaryReadsView, DiaryReviewState,
    agent_reviews_diary_reads_in_txn,
};
use crate::error::Error;
use crate::memory::{Memory, MemoryResult, verify_actor_binding};

impl Memory<'_> {
    /// `self.memory.diary.reads`: this agent's read log and review requests,
    /// newest first. An omitted `limit` reads everything persisted; an
    /// explicit one keeps the caller's own newest-rows window. `requests`
    /// holds pending, approved or declined rows, and spent ones too when
    /// the input sets `include_used`.
    pub fn diary_reads(&self, input: &DiaryReadsRequest) -> MemoryResult<DiaryReadsView> {
        verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        let prefix = self.actor.as_bytes();
        let limit = input.limit.map(|limit| limit as usize);
        let mut reads: Vec<_> = DIARY_READ_LOG
            .scan_from(&self.vault.store, &txn, prefix)?
            .into_iter()
            .rev()
            .map(|(_, record)| record)
            .collect();
        if let Some(limit) = limit {
            reads.truncate(limit);
        }
        let mut requests: Vec<_> = DIARY_READ_REQUEST
            .scan_from(&self.vault.store, &txn, prefix)?
            .into_iter()
            .rev()
            .map(|(_, request)| request)
            .filter(|request| input.include_used || request.state != DiaryReviewState::Used)
            .collect();
        if let Some(limit) = limit {
            requests.truncate(limit);
        }
        Ok(DiaryReadsView {
            review: agent_reviews_diary_reads_in_txn(self.vault, &txn, &self.actor)?,
            reads,
            requests,
        })
    }
}
