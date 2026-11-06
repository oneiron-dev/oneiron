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
use crate::inbox::{
    NotificationEvent, NotificationKind, NotificationSource, decode_notification_body,
    notification_id,
};
use crate::registry::ENTITY_TYPE_NOTIFICATION;
use crate::repo_mutation::RepoConflictClaim;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// The producer of a held queue reconciliation's notice.
const QUEUE_RECONCILIATION_HOLD_PRODUCER: &str = "merge_queue.reconciliation_hold";

/// Diagnostic reason when the source no longer names a creator.
const QUEUE_RECONCILIATION_CREATOR_ERASED: &str = "queue.reconciliation.creator_erased";

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
            return Ok(Err(QUEUE_RECONCILIATION_CREATOR_ERASED.to_owned()));
        };
        // The spec's current repo/branch/path policy, by the run's own seam.
        if let Err(refused) = admission.creator_grant_in_txn(self, txn)? {
            let held = QueueReconciliationAdmission::grant_held(refused);
            self.record_held_notice_in_txn(txn, conflict, creator, &held, now)?;
            return Ok(Err(held));
        }
        if task_actor_ceiling(self, txn, creator, class).map_err(map_error)?
            != PolicyApprovalCeiling::Auto
        {
            let held = QueueReconciliationAdmission::TASK_HELD;
            self.record_held_notice_in_txn(txn, conflict, creator, held, now)?;
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
        let task = mint_reconciliation_task_in_txn(self, txn, conflict, creator, class, now)?;
        self.clear_queue_held_notice_in_txn(txn, conflict, creator)?;
        Ok(Ok(task))
    }

    /// Tells `creator` why the reconciliation of `conflict` is held, on
    /// the conflict and both proposals. A changed reason reopens the same
    /// notice; a repeated reason preserves its seen and acknowledged state.
    fn record_held_notice_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        conflict: &RepoConflictClaim,
        creator: EntityId,
        detail: &str,
        now: u64,
    ) -> Result<()> {
        let mut subject_refs = vec![conflict.claim_id];
        subject_refs.extend(conflict.proposals.iter().copied());
        let event = NotificationEvent {
            kind: NotificationKind::Ask,
            source: NotificationSource {
                detail: Some(detail.to_owned()),
                ..queue_held_notice_source(conflict, creator)
            },
            subject_refs,
            recipient: Some(creator),
            created_at: now,
            origin_conversation: None,
        };
        let id = self.record_notification_in_txn(txn, &event)?;
        let LiveEntityRow::Live { entity_type, body } =
            live_entity_row_in_txn(&self.store, txn, &id)?
        else {
            return Ok(());
        };
        if entity_type != ENTITY_TYPE_NOTIFICATION {
            return Ok(());
        }
        let mut body = decode_notification_body(&body)?;
        let recipient = creator.to_hex();
        if body.recipient.as_ref() != Some(&recipient)
            || body.source.producer != event.source.producer
            || body.source.event != event.source.event
            || body.source.detail.as_deref() == Some(detail)
        {
            return Ok(());
        }
        body.source.detail = Some(detail.to_owned());
        body.seen_by.remove(&recipient);
        body.acked_by.remove(&recipient);
        self.put_notification_in_txn(txn, &id, &body)?;
        Ok(())
    }

    /// Clears this queue hold's notice when its TASK is minted, without
    /// deleting the row or changing another recipient's state.
    fn clear_queue_held_notice_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        conflict: &RepoConflictClaim,
        creator: EntityId,
    ) -> Result<()> {
        let source = queue_held_notice_source(conflict, creator);
        let id = notification_id(&source)?;
        let LiveEntityRow::Live { entity_type, body } =
            live_entity_row_in_txn(&self.store, txn, &id)?
        else {
            return Ok(());
        };
        if entity_type != ENTITY_TYPE_NOTIFICATION {
            return Ok(());
        }
        let mut body = decode_notification_body(&body)?;
        let recipient = creator.to_hex();
        if body.recipient.as_ref() != Some(&recipient)
            || body.source.producer != source.producer
            || body.source.event != source.event
            || body.acked_by.get(&recipient) == Some(&true)
        {
            return Ok(());
        }
        body.seen_by.insert(recipient.clone(), true);
        body.acked_by.insert(recipient, true);
        self.put_notification_in_txn(txn, &id, &body)?;
        Ok(())
    }
}

fn queue_held_notice_source(conflict: &RepoConflictClaim, creator: EntityId) -> NotificationSource {
    NotificationSource {
        producer: QUEUE_RECONCILIATION_HOLD_PRODUCER.to_owned(),
        event: format!("{}:{}", conflict.claim_id.to_hex(), creator.to_hex()),
        result: Some(conflict.claim_id.to_hex()),
        ..NotificationSource::default()
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
        type_parents: None,
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
