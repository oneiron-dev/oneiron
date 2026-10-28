//! The read door to a Dreamer attempt's decided candidates (FIX 11306): every
//! candidate it decided a correction for, kept before the branch built,
//! filtered or selected it, with its kept decisions and their receipts. It
//! answers under the scope the open-conflict read uses, since a decided
//! candidate is a correction's record as a parked conflict is: the root
//! owner and the vault's own Dreamer read every one, and anyone else the
//! candidates whose subject an owner-delegated conflict review Grant covers.
//! Ids and decisions only, never a candidate's value.

use serde::Serialize;

use super::super::outbound::parse_job_ref;
use super::super::{Memory, MemoryResult};
use crate::EntityId;
use crate::consent::AuthenticatedOwner;
use crate::dreamer_consolidation::KeptDecision;
use crate::error::Error;

/// One candidate a Dreamer attempt decided a correction for.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DreamerDecidedCandidateView {
    /// 32-hex attempt id.
    pub job_ref: String,
    /// Its position in the attempt's extraction.
    pub position: u64,
    #[serde(with = "crate::entity_id::serde_hex")]
    pub subject: EntityId,
    /// The listed claim its decisions bound it to; none when they bound none.
    #[serde(with = "crate::entity_id::serde_hex::optional")]
    pub corrects: Option<EntityId>,
    /// Its kept decisions, each with its receipt and, when it went up the
    /// role chain, that ask.
    pub decisions: Vec<KeptDecision>,
}

impl Memory<'_> {
    /// The candidates attempt `job_ref` decided a correction for, in their
    /// extraction order, that this caller may read: every one for the root
    /// owner, authenticated by `reviewer`, and for the vault's Dreamer; those
    /// whose subject a live conflict review Grant covers for anyone else. An
    /// attempt that decided none, or one this caller reads none of, is empty.
    pub fn dreamer_candidate_decisions(
        &self,
        reviewer: Option<&AuthenticatedOwner>,
        job_ref: &str,
    ) -> MemoryResult<Vec<DreamerDecidedCandidateView>> {
        let attempt = parse_job_ref(job_ref)?;
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        let every = self.conflict_responder_is_owner(&txn, reviewer)?
            || self.conflict_responder_is_dreamer()?;
        let mut read = Vec::new();
        for (position, candidate) in self.vault.decided_candidates_in_txn(&txn, attempt)? {
            if every
                || self
                    .conflict_review_grant(&txn, candidate.subject)?
                    .is_some()
            {
                read.push(DreamerDecidedCandidateView {
                    job_ref: crate::entity_id::bytes_to_hex_lower(attempt.as_bytes()),
                    position,
                    subject: candidate.subject,
                    corrects: candidate.corrects,
                    decisions: candidate.decisions,
                });
            }
        }
        Ok(read)
    }
}
