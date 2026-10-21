//! Repository conflicts mint one linked reconciliation TASK and realizing attempt.
//! The merge queue's overlap handoff mints it under its real creator's
//! authority (`queue`, FIX 6868 G2 PR2).
mod queue;

use super::create_spec::TaskCreateRateLimit;
use super::rate_limit::{record_task_create, task_actor_ceiling};
use crate::Vault;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{CodeError, Error, Result};
use crate::gate::PolicyApprovalCeiling;
use crate::repo_mutation::RepoConflictClaim;
use crate::side_table::{self, Raw, SideTable};

/// Repo-conflict claim to its reconciliation TASK. Key: id16 (claim id).
const RECONCILIATION_TASKS: SideTable<EntityId, EntityId, Raw> =
    SideTable::new(&side_table::REPO_CONFLICT_RECONCILIATION_INDEX);

fn map_error(error: crate::memory::MemoryError) -> Error {
    Error::Code(CodeError::RepoMutationFailed(error.to_string()))
}
impl Vault {
    /// The TASK owning the open conflict. This is an index into ordinary TASKs,
    /// never a second task store.
    pub fn repo_reconciliation_task(&self, conflict: EntityId) -> Result<Option<EntityId>> {
        let txn = self.store.env.read_txn()?;
        self.repo_reconciliation_task_in_txn(&txn, conflict)
    }

    pub(crate) fn repo_reconciliation_task_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        conflict: EntityId,
    ) -> Result<Option<EntityId>> {
        RECONCILIATION_TASKS.get(&self.store, txn, &conflict)
    }
    /// Called only after the conflict claim has been written in this transaction.
    /// The local owner is bootstrapped outside the transaction by the admin queue.
    pub(crate) fn create_repo_reconciliation_task_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        conflict: &RepoConflictClaim,
        owner: EntityId,
        now: u64,
    ) -> Result<EntityId> {
        if let Some(task) = RECONCILIATION_TASKS.get(&self.store, txn, &conflict.claim_id)? {
            return Ok(task);
        }
        if !crate::ports::EntityStoreRead::port_entity_present(
            &self.store,
            txn,
            &conflict.claim_id,
        )? {
            return Err(Error::EntityNotFound);
        }
        if task_actor_ceiling(self, txn, owner, EdgeActorClass::Human).map_err(map_error)?
            != PolicyApprovalCeiling::Auto
        {
            return Err(Error::Code(CodeError::RepoMutationFailed(
                "reconciliation task requires owner Auto ceiling".into(),
            )));
        }
        record_task_create(
            self,
            txn,
            owner,
            self.now_recorded_at(),
            TaskCreateRateLimit::default(),
        )?;
        queue::mint_reconciliation_task_in_txn(
            self,
            txn,
            conflict,
            owner,
            EdgeActorClass::Human,
            now,
        )
    }
}
