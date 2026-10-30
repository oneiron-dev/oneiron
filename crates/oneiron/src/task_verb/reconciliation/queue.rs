//! The reconciliation TASK of a merge queue overlap (FIX 6868, G2 PR2) and
//! the one TASK builder both conflict paths share.
//!
//! The queue's handoff mints its TASK under the real creator the sealed
//! [`QueueReconciliationAdmission`] names, at that creator's own task
//! authority: a creator whose live Grant does not cover the repository, the
//! branch and every conflicted path (FIX 7308), or whose ceiling is below
//! Auto, gets no TASK, and the claim keeps a held disposition (CALL "queue
//! reconciliation TASK admission"). The hold is told to the creator in an
//! inbox notice that names its reason, so it shows on the creator's board. Nothing falls back to the embedded owner,
//! and no agent is promoted to a person or to the owner's ceiling. A later
//! policy change retries the same conflict, and the same index answers it.
use rmpv::Value;

use super::super::create_spec::TaskCreateRateLimit;
use super::super::create_validation::ValidatedTaskCreate;
use super::super::rate_limit::{record_task_create, task_actor_ceiling};
use super::super::verb_kind::{TaskAssignee, TaskKind};
use super::{RECONCILIATION_TASKS, map_error};
use crate::Vault;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::federation::QueueReconciliationAdmission;
use crate::gate::PolicyApprovalCeiling;
use crate::inbox::{NotificationEvent, NotificationKind, NotificationSource};
use crate::repo_mutation::RepoConflictClaim;

/// The producer of a held queue reconciliation's notice.
const QUEUE_RECONCILIATION_HOLD_PRODUCER: &str = "merge_queue.reconciliation_hold";

/// The producer of a queue reconciliation's notice held by its creator's
/// Grant (FIX 7308).
const QUEUE_RECONCILIATION_GRANT_HOLD_PRODUCER: &str = "merge_queue.reconciliation_grant_hold";

impl Vault {
    /// The reconciliation TASK of queue conflict `conflict`, written in its
    /// claim's transaction: the indexed one, or one minted now under the
    /// admission's real creator when that creator's live Grant covers the
    /// repository, the branch and every conflicted path and its ceiling is
    /// Auto. `Err(held)` keeps the conflict held (HeldTaskAuthority) with
    /// why; the creator is told why.
    ///
    /// # Errors
    /// A store failure, or a conflict claim this transaction has not written.
    pub(crate) fn create_queue_reconciliation_task_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        conflict: &RepoConflictClaim,
        admission: &QueueReconciliationAdmission,
        now: u64,
    ) -> Result<std::result::Result<EntityId, String>> {
        if let Some(task) = RECONCILIATION_TASKS.get(&self.store, txn, &conflict.claim_id)? {
            return Ok(Ok(task));
        }
        if !crate::ports::EntityStoreRead::port_entity_present(
            &self.store,
            txn,
            &conflict.claim_id,
        )? {
            return Err(Error::EntityNotFound);
        }
        // An erased creator has no board to be told on; the queue's own
        // observation keeps the hold.
        let Some((creator, class)) = admission.creator() else {
            return Ok(Err(QueueReconciliationAdmission::TASK_HELD.to_owned()));
        };
        // The spec's current repo/branch/path policy, by the run's own seam.
        if let Err(refused) = admission.creator_grant_in_txn(self, txn)? {
            let held = QueueReconciliationAdmission::grant_held(refused);
            let producer = QUEUE_RECONCILIATION_GRANT_HOLD_PRODUCER;
            self.record_held_notice_in_txn(txn, conflict, creator, producer, &held, now)?;
            return Ok(Err(held));
        }
        if task_actor_ceiling(self, txn, creator, class).map_err(map_error)?
            != PolicyApprovalCeiling::Auto
        {
            let held = QueueReconciliationAdmission::TASK_HELD;
            let producer = QUEUE_RECONCILIATION_HOLD_PRODUCER;
            self.record_held_notice_in_txn(txn, conflict, creator, producer, held, now)?;
            return Ok(Err(held.to_owned()));
        }
        // The vault's fan-out policy row names the threshold this create's
        // own_rate_burst check is recorded at (FIX 10187); a conflict names
        // no project or thread, so the vault scope's row answers. One that
        // does not read keeps the shipped 10 per 60 s. A crossing is a check
        // on its creator, never a refusal.
        let create_rate = super::super::consult_fanout_store::policy_in(
            self,
            txn,
            &super::super::ConsultFanOutScope::default(),
        )
        .map_or_else(
            |_| TaskCreateRateLimit::default(),
            |resolved| resolved.policy.create_rate,
        );
        record_task_create(self, txn, creator, self.now_recorded_at(), create_rate)?;
        mint_reconciliation_task_in_txn(self, txn, conflict, creator, class, now).map(Ok)
    }

    /// Tells `creator` why the reconciliation of `conflict` is held,
    /// `detail`, in its inbox from `producer`, on the conflict and both
    /// proposals.
    fn record_held_notice_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        conflict: &RepoConflictClaim,
        creator: EntityId,
        producer: &str,
        detail: &str,
        now: u64,
    ) -> Result<()> {
        let mut subject_refs = vec![conflict.claim_id];
        subject_refs.extend(conflict.proposals.iter().copied());
        self.record_notification_in_txn(
            txn,
            &NotificationEvent {
                kind: NotificationKind::Ask,
                source: NotificationSource {
                    producer: producer.to_owned(),
                    event: format!("{}:{}", conflict.claim_id.to_hex(), creator.to_hex()),
                    result: Some(conflict.claim_id.to_hex()),
                    detail: Some(detail.to_owned()),
                    ..NotificationSource::default()
                },
                subject_refs,
                recipient: Some(creator),
                created_at: now,
                origin_conversation: None,
            },
        )?;
        Ok(())
    }
}

/// Mints, routes and indexes the reconciliation TASK of `conflict` for
/// `creator`, whose authority the caller already checked.
pub(super) fn mint_reconciliation_task_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    conflict: &RepoConflictClaim,
    creator: EntityId,
    class: EdgeActorClass,
    now: u64,
) -> Result<EntityId> {
    let memory = vault.memory(creator, class);
    let spec = Value::Map(vec![
        (
            Value::from("proposals"),
            Value::Array(
                conflict
                    .proposals
                    .iter()
                    .map(|id| Value::from(id.to_hex()))
                    .collect(),
            ),
        ),
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
        type_ref: crate::task_type::TaskTypeRef::seed(
            crate::task_type::SeedTaskType::Solve,
            crate::task_type::SEEDED_TREE_VERSION,
        ),
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
            creator,
            &provenance,
            now,
        )
        .map_err(map_error)?;
    memory
        .route_created_task_in_txn(txn, task, &validated, now)
        .map_err(map_error)?;
    RECONCILIATION_TASKS.put(&vault.store, txn, &conflict.claim_id, &task)?;
    Ok(task)
}
