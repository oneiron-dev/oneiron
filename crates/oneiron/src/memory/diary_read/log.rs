//! The agent's complete diary read/review log view (OF-490): the persisted
//! read rows and review requests, newest first, with no hidden count cut.
//! An omitted limit returns everything; an explicit one is the caller's own
//! recent-window choice, and spent requests join only on `include_used`.
//! Beside it, the companion's owner's view of a work vault Admin's reads of
//! the agent's sealed pads (ARCH-0032 #private-reads).

use super::{
    DIARY_READ_LOG, DIARY_READ_REQUEST, DiaryReadRecord, DiaryReadsRequest, DiaryReadsView,
    DiaryReviewState, SealedPadReader, agent_reviews_diary_reads_in_txn,
};
use crate::EntityId;
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::error::Error;
use crate::memory::authorship::authority_denied;
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

impl Memory<'_> {
    /// The reads a work vault's Admin made of `agent`'s sealed pads, newest
    /// first, as the companion's owner sees them: in a work vault Admins
    /// read through a logged access step, and the companion's owner sees the
    /// log (ARCH-0032 #private-reads). The caller is a person with their
    /// authentication, and the companion's owner: the PERSON `agent`'s
    /// subject anchor names, or, for an agent anchored to no person (an
    /// ORG's, the vault's own), a live owner of the vault. Anyone else is
    /// refused. The agent sees the same rows in its own log.
    pub fn admin_pad_reads(
        &self,
        owner: &AuthenticatedOwner,
        agent: EntityId,
    ) -> MemoryResult<Vec<DiaryReadRecord>> {
        verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        if self.actor_class != EdgeActorClass::Human
            || self.actor != owner.revalidate_person_in_txn(self.vault, &txn)?
        {
            return Err(authority_denied(
                "the companion's owner reads the admin log with their own authentication",
            )
            .into());
        }
        let at = crate::ports::job_recorded_at_in_txn(&self.vault.store, &txn)?;
        let companion_owner =
            match crate::workspace_roster::person_of_actor_in_txn(self.vault, &txn, agent, at)? {
                Some(person) => person == self.actor,
                None => {
                    crate::policy_model::is_live_vault_owner_in_txn(self.vault, &txn, &self.actor)?
                }
            };
        if !companion_owner {
            return Err(authority_denied("only the companion's owner reads its admin log").into());
        }
        Ok(DIARY_READ_LOG
            .scan_from(&self.vault.store, &txn, agent.as_bytes())?
            .into_iter()
            .rev()
            .map(|(_, record)| record)
            .filter(|record| record.ruled_reader == Some(SealedPadReader::Admin))
            .collect())
    }
}
