//! Typed cross-kind review settlements and run compensation (ARCH-0040).
//!
//! Membership is explicit, never guessed from actor or time. Review binds the
//! exact members and policy frontier; settlement keeps their inverse handles.

mod actor_erase;
mod changes;
mod receipts;
mod restore_group;
mod revert;
mod settle;
mod snapshot;
mod topology;

pub(crate) use actor_erase::erase_run_review_actor_in_txn;
pub use changes::{RunChanges, RunChangesRequest};
#[cfg(oneiron_test_support)]
pub(crate) use changes::{journal_changes, journal_row_sizes};
pub(crate) use changes::{record_run_claim_in_txn, record_run_topology_in_txn};
pub(crate) use receipts::run_settlement_receipts;

use crate::consent::AuthenticatedOwner;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::side_table::{self, Named, SideTable};
use crate::{EdgeActorClass, EntityId, WriteActor};
use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub use oneiron_verb_wire::memory::run_review::{
    RevertRunOutcome, RevertRunRequest, RunAnsweredBy, RunChangeOutcome, RunChangeVerdict,
    RunCompensation, RunNotUndone, RunNotUndoneReason, RunReview, RunReviewChange,
    RunReviewExplainer, RunReviewRequest, RunSettleDecision, RunSettleRequest, RunSettlement,
    RunSettlementKind, RunSettlementReason, RunSettlementRequest,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredRun {
    settlement: RunSettlement,
    changes: Vec<StoredChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredChange {
    member: RunReviewChange,
    verdict: RunChangeVerdict,
    inverse: Option<RunInverse>,
    compensation: Option<String>,
    unrestored: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum RunInverse {
    Authored {
        author: String,
        fingerprint: String,
    },
    /// The change's author was erased (FIX 4727): no undo names it, and the
    /// change is one-way.
    AuthorErased,
    Note(crate::note::RunNoteUndo),
    Topology {
        event: String,
    },
    /// A restored claim with raw evidence, which names no author: its undo
    /// retracts it while its row is unchanged (RULING 02:26 13 Nov, R5).
    Restored {
        fingerprint: String,
    },
}

const SETTLEMENTS: SideTable<String, StoredRun, Named> =
    SideTable::new(&side_table::RUN_REVIEW_SETTLEMENT);

fn run_key(run: &str) -> MemoryResult<String> {
    let run = run.strip_prefix("run:").unwrap_or(run);
    if run.trim().is_empty() || run.len() > 1024 {
        return Err(MemoryError::bad_request(
            "run_id is a nonempty job id of at most 1024 bytes",
        ));
    }
    Ok(run.to_owned())
}

fn require_owner(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
    owner: &AuthenticatedOwner,
) -> MemoryResult<WriteActor> {
    let person = super::authorship::verify_owner(memory.vault(), txn, owner)?;
    if person != memory.actor() || memory.actor_class() != EdgeActorClass::Human {
        return Err(MemoryError::new(
            super::MEMORY_CODE_FORBIDDEN,
            "run review acts through the caller's own owner credential",
            &[],
        ));
    }
    memory.verify_actor_write_in_txn(txn)?;
    Ok(WriteActor::new(person, EdgeActorClass::Human))
}

fn fingerprint(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

impl Memory<'_> {
    /// The durable result of this job's one cross-kind settlement.
    pub fn run_settlement_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &RunSettlementRequest,
    ) -> MemoryResult<RunSettlement> {
        let run = run_key(&input.run_id)?;
        let txn = self
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        require_owner(self, &txn, owner)?;
        let journal = SETTLEMENTS
            .get(&self.vault().store, &txn, &run)?
            .ok_or_else(|| MemoryError::not_found("no run settlement has that id"))?;
        self.produced_from(
            journal
                .changes
                .iter()
                .map(|m| m.member.rows())
                .collect::<MemoryResult<Vec<_>>>()?
                .into_iter()
                .flatten(),
        );
        Ok(journal.settlement)
    }

    /// Reads exactly the explicit set and the live policy in one snapshot.
    pub fn review_run_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &RunReviewRequest,
    ) -> MemoryResult<RunReview> {
        let txn = self
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        require_owner(self, &txn, owner)?;
        let reviewed = snapshot::review_in_txn(self, &txn, input)?;
        self.produced_from(
            input
                .changes
                .iter()
                .map(RunReviewChange::rows)
                .collect::<MemoryResult<Vec<_>>>()?
                .into_iter()
                .flatten(),
        );
        Ok(reviewed)
    }
}
