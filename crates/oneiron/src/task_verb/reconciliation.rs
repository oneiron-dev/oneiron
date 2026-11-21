//! Repository conflicts mint one linked reconciliation TASK and realizing attempt.
//! The merge queue's overlap handoff mints it under its real creator's
//! authority (`queue`, FIX 6868 G2 PR2). Below the creator's Auto ceiling the
//! conflict is kept and its reconciliation held, told to the creator, never
//! minted under a widened ceiling (FIX 8830). The queue completes the TASK
//! when its conflict's green successor supersedes the sources (FIX
//! QUEUE-RECONCILIATION-TASK-COMPLETION).
mod queue;

use super::create_spec::TaskCreateRateLimit;
use super::rate_limit::{record_task_create, task_actor_ceiling};
use super::terminal_state::{TaskExecutionState, TaskTerminalDisposition, TaskTerminalRecord};
use super::verb_kind::TaskKind;
use super::wire_decode::task_verb_body_in;
use super::wire_encode::encode_task_verb_body;
use crate::Vault;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{CodeError, Error, Result};
use crate::gate::PolicyApprovalCeiling;
use crate::inbox::{NotificationEvent, NotificationKind, NotificationSource};
use crate::registry::ENTITY_TYPE_TASK;
use crate::repo_mutation::RepoConflictClaim;
use crate::side_table::{self, Raw, SideTable};

/// Why a conflict's reconciliation TASK waits, as its view and its
/// creator's notice say it.
pub(crate) const REPO_RECONCILIATION_TASK_HELD: &str = "the reconciliation task waits: its \
     creator's task authority is below Auto, so no task is minted in its name; the conflict and \
     both proposed changes are kept, and recording the conflict again once that authority admits \
     it mints the task";

/// The producer of a held owner reconciliation's notice.
const REPO_RECONCILIATION_HOLD_PRODUCER: &str = "repo_mutation.reconciliation_hold";

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

    /// Completes the reconciliation TASK of queue conflict `conflict` in the
    /// write that supersedes its sources, once its green successor closed
    /// it (ARCH-0050:110; FIX QUEUE-RECONCILIATION-TASK-COMPLETION). Its
    /// result is `resolution`, the claim that closed the conflict (one of
    /// them when several closed it together; see
    /// `QueueConflictResolver::resolution`). With no closing claim read, it
    /// completes with no result.
    ///
    /// The write is the engine's own, through the internal TASK body door,
    /// as a watch TASK's tick settles it: no run is leased on a
    /// reconciliation TASK (RULING CODECUSTODY-RECONCILE-SUCCESSOR = A), so
    /// no executor's result door ever settles it. A held conflict has no
    /// TASK. A TASK already settled, its ladder settled, or cancelled is
    /// left alone, and so is a row that is not a reconciliation TASK.
    /// Answers the TASK it completed.
    pub(crate) fn complete_queue_reconciliation_task_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        conflict: EntityId,
        resolution: Option<EntityId>,
        now: u64,
    ) -> Result<Option<EntityId>> {
        let Some(task) = RECONCILIATION_TASKS.get(&self.store, txn, &conflict)? else {
            return Ok(None);
        };
        let Some(mut body) = task_verb_body_in(self, &*txn, task)? else {
            return Ok(None);
        };
        if body.task_kind() != TaskKind::Reconciliation
            || body.terminal().is_some()
            || body.settled_ladder_disposition().is_some()
            || self.task_authority_facts_in(&*txn, task)?.cancelled
        {
            return Ok(None);
        }
        body.state = Some(TaskExecutionState::Terminal(TaskTerminalRecord {
            disposition: TaskTerminalDisposition::Completed,
            result_ref: resolution,
            summary: None,
            finished_at: now,
            ladder: None,
            counter_task_ref: None,
        }));
        self.batch_in()
            .put_internal(
                &task,
                ENTITY_TYPE_TASK,
                crate::TimeRange {
                    start: now,
                    end: now,
                },
                now,
                &encode_task_verb_body(body),
            )
            .apply(txn)?;
        // As every settlement does: a review the owner accepted before the
        // TASK settled anchors it, and the routing folds count it. The
        // Dreamer lane realizes only Standard TASKs, so its queued attempt
        // is owed nothing. Like a watch tick, it sends no peer-result
        // signal: no run delegated this TASK (the Dreamer holds it).
        super::settlement_anchor::anchor_kept_review_in_txn(self, txn, task, None)?;
        crate::edit_distance::routing::refold_task_outcomes_in_txn(self, txn, task);
        Ok(Some(task))
    }
    /// Called only after the conflict claim has been written in this transaction.
    /// The local owner is bootstrapped outside the transaction by the admin queue.
    /// `None` keeps the conflict held: the owner's ceiling is below Auto, and
    /// the owner is told why in an inbox notice (FIX 8830).
    pub(crate) fn create_repo_reconciliation_task_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        conflict: &RepoConflictClaim,
        owner: EntityId,
        now: u64,
    ) -> Result<Option<EntityId>> {
        if let Some(task) = RECONCILIATION_TASKS.get(&self.store, txn, &conflict.claim_id)? {
            return Ok(Some(task));
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
            let mut subject_refs = vec![conflict.claim_id];
            subject_refs.extend(conflict.proposals.iter().copied());
            self.record_notification_in_txn(
                txn,
                &NotificationEvent {
                    kind: NotificationKind::Ask,
                    source: NotificationSource {
                        producer: REPO_RECONCILIATION_HOLD_PRODUCER.to_owned(),
                        event: format!("{}:{}", conflict.claim_id.to_hex(), owner.to_hex()),
                        result: Some(conflict.claim_id.to_hex()),
                        detail: Some(REPO_RECONCILIATION_TASK_HELD.to_owned()),
                        ..NotificationSource::default()
                    },
                    subject_refs,
                    recipient: Some(owner),
                    created_at: now,
                    origin_conversation: None,
                },
            )?;
            return Ok(None);
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
        .map(Some)
    }
}
