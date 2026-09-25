//! Repository conflicts mint one linked reconciliation TASK and realizing attempt.
use super::create_spec::TaskCreateRateLimit;
use super::create_validation::ValidatedTaskCreate;
use super::rate_limit::{record_task_create, task_actor_ceiling};
use super::verb_kind::{TaskAssignee, TaskKind};
use crate::Vault;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{CodeError, Error, Result};
use crate::gate::PolicyApprovalCeiling;
use crate::repo_mutation::RepoConflictClaim;
use rmpv::Value;

const PREFIX: &[u8] = b"repo_conflict:reconciliation:v1:";
fn key(id: EntityId) -> Vec<u8> {
    [PREFIX, id.as_bytes()].concat()
}
fn map_error(error: crate::memory::MemoryError) -> Error {
    Error::Code(CodeError::RepoMutationFailed(error.to_string()))
}
impl Vault {
    /// The TASK owning the open conflict. This is an index into ordinary TASKs,
    /// never a second task store.
    pub fn repo_reconciliation_task(&self, conflict: EntityId) -> Result<Option<EntityId>> {
        let txn = self.store.env.read_txn()?;
        self.store
            .vault_meta
            .get(&txn, &key(conflict))?
            .map(|raw| {
                EntityId::from_bytes(
                    raw.as_ref()
                        .try_into()
                        .map_err(|_| Error::CorruptedIndex("repo reconciliation task index"))?,
                )
            })
            .transpose()
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
        if let Some(raw) = self.store.vault_meta.get(txn, &key(conflict.claim_id))? {
            return EntityId::from_bytes(
                raw.as_ref()
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("repo reconciliation task index"))?,
            );
        }
        if self
            .store
            .entities
            .get(txn, conflict.claim_id.as_bytes())?
            .is_none()
        {
            return Err(Error::EntityNotFound);
        }
        let memory = self.memory(owner, EdgeActorClass::Human);
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
            crate::unix_seconds_now(),
            TaskCreateRateLimit::default(),
        )?;
        let spec = Value::Map(vec![
            (
                Value::from("open_conflict_claim_id"),
                Value::from(conflict.claim_id.to_hex()),
            ),
            (
                Value::from("branch_subject"),
                Value::from(conflict.subject.to_hex()),
            ),
            (
                Value::from("repo_ref"),
                Value::from(conflict.repo_ref.canonical()),
            ),
            (Value::from("branch"), Value::from(conflict.branch.clone())),
            (
                Value::from("conflicted_paths"),
                Value::Array(
                    conflict
                        .conflicted_paths
                        .iter()
                        .cloned()
                        .map(Value::from)
                        .collect(),
                ),
            ),
            (
                Value::from("base_tree"),
                Value::from(conflict.base_tree.clone()),
            ),
            (
                Value::from("ours_tree"),
                Value::from(conflict.ours_tree.clone()),
            ),
            (
                Value::from("theirs_tree"),
                Value::from(conflict.theirs_tree.clone()),
            ),
        ]);
        let validated = ValidatedTaskCreate {
            kind: TaskKind::Reconciliation,
            assignee: Some(TaskAssignee::Dreamer),
            consult: None,
            ttl: None,
            spec,
        };
        let provenance = Value::Map(vec![
            (Value::from("source"), Value::from("repo.conflict")),
            (
                Value::from("claim_id"),
                Value::from(conflict.claim_id.to_hex()),
            ),
        ]);
        let task = memory
            .mint_task_in_txn(
                txn,
                &validated,
                Some(format!("reconcile:{}", conflict.branch)),
                owner,
                &provenance,
                now,
            )
            .map_err(map_error)?;
        memory
            .route_created_task_in_txn(txn, task, &validated, now)
            .map_err(map_error)?;
        self.store
            .vault_meta
            .put(txn, &key(conflict.claim_id), task.as_bytes())?;
        Ok(task)
    }
}
