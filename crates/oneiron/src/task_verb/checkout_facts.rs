//! Checkout ACTs and their synced TASK FACTs share the credential's transaction.
use crate::authority::TaskActorVerb;
use crate::checkout::lease::{CheckoutLeaseAct, CheckoutSettlementDisposition};
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::task_authority::{TaskAuthorityFact, TaskAuthorityFactKind, put_task_authority_fact_in_txn};
use crate::EntityId;
use super::{TaskAssignee, TaskExecutionState, TaskTerminalDisposition, TaskTerminalRecord, TaskVia};
use super::create_validation::task_body_in_txn;
use super::highway_accept::require_live_standard;
use super::lifecycle_receipt;

#[derive(Clone, Copy)]
pub(crate) enum CheckoutTaskAccess { Claim, Holder, Reclaim, Takeover, Read }

impl Memory<'_> {
    pub(crate) fn checkout_task_in(
        &self, txn: &heed::RoTxn<'_>, task: EntityId, access: CheckoutTaskAccess,
    ) -> MemoryResult<()> {
        let verb = match access {
            CheckoutTaskAccess::Claim => TaskActorVerb::Accept,
            CheckoutTaskAccess::Holder => TaskActorVerb::Report,
            CheckoutTaskAccess::Takeover => TaskActorVerb::Owner,
            CheckoutTaskAccess::Read | CheckoutTaskAccess::Reclaim => TaskActorVerb::Status,
        };
        let standing = self.highway_task_actor_in(txn, task, verb,
            "Use your own credential as the task's assignee, taker or owner.")?;
        if matches!(access, CheckoutTaskAccess::Reclaim)
            && standing.assignee != Some(self.actor()) && standing.owner != self.actor()
        {
            return Err(MemoryError::new(crate::memory::MEMORY_CODE_FORBIDDEN,
                "only the assigned successor or task owner reclaims an expired checkout", &[]));
        }
        if matches!(access, CheckoutTaskAccess::Claim | CheckoutTaskAccess::Reclaim | CheckoutTaskAccess::Takeover) {
            require_live_standard(&task_body_in_txn(self.vault(), txn, task)?, &standing)?;
        }
        self.produced_from([task]);
        Ok(())
    }

    pub(crate) fn checkout_started_in(
        &self, txn: &mut heed::RwTxn<'_>, act: &CheckoutLeaseAct, now: u64,
    ) -> MemoryResult<()> {
        let mut body = task_body_in_txn(self.vault(), txn, act.task_ref)?;
        body.assignee = Some(if self.actor_class() == crate::EdgeActorClass::Human {
            TaskAssignee::Human { actor_ref: self.actor() }
        } else { TaskAssignee::Peer { actor_ref: self.actor() } });
        body.state = Some(TaskExecutionState::Working { started_at: now });
        self.rewrite_task_in_txn(txn, act.task_ref, body, now)?;
        let generation = self.vault().actor_binding_generation_in_txn(txn, self.actor())?;
        put_task_authority_fact_in_txn(self.vault(), txn, TaskAuthorityFact {
            task_ref: act.task_ref, kind: TaskAuthorityFactKind::Accepted,
            actor_ref: self.actor(), assigned_ref: None,
            actor_generation: generation,
            assigned_generation: None, occurred_at: now,
        })?;
        Ok(())
    }

    pub(crate) fn checkout_settled_fact_in(
        &self, txn: &mut heed::RwTxn<'_>, act: &CheckoutLeaseAct,
        disposition: CheckoutSettlementDisposition, candidate: EntityId, now: u64,
    ) -> MemoryResult<()> {
        let mut body = task_body_in_txn(self.vault(), txn, act.task_ref)?;
        if disposition == CheckoutSettlementDisposition::Release {
            if body.terminal().is_none() {
                body.state = Some(TaskExecutionState::Queued);
                self.rewrite_task_in_txn(txn, act.task_ref, body, now)?;
            }
        } else {
            let terminal = TaskTerminalRecord {
                disposition: if disposition == CheckoutSettlementDisposition::Discard {
                    TaskTerminalDisposition::Abandoned
                } else { TaskTerminalDisposition::Completed },
                result_ref: Some(candidate), summary: None, finished_at: now,
                ladder: None, counter_task_ref: None,
            };
            self.settle_task_terminal_in_txn(txn, act.task_ref, body, &terminal, now, None)?;
        }
        Ok(())
    }

    pub(crate) fn checkout_released_fact_in(
        &self, txn: &mut heed::RwTxn<'_>, task: EntityId, now: u64,
    ) -> MemoryResult<()> {
        let mut body = task_body_in_txn(self.vault(), txn, task)?;
        if body.terminal().is_none() {
            body.state = Some(TaskExecutionState::Queued);
            self.rewrite_task_in_txn(txn, task, body, now)?;
        }
        Ok(())
    }

    pub(crate) fn checkout_receipt_id(&self, act: &CheckoutLeaseAct, call: &str, identity: &[u8]) -> MemoryResult<String> {
        lifecycle_receipt::receipt_id(call, &[act.checkout_id.as_bytes(), &act.epoch.to_le_bytes(), identity])
    }

    pub(crate) fn checkout_receipt_in(
        &self, txn: &mut heed::RwTxn<'_>, act: &CheckoutLeaseAct,
        call: &str, identity: &[u8], now: u64,
    ) -> MemoryResult<String> {
        let id = self.checkout_receipt_id(act, call, identity)?;
        if let Some(id) = lifecycle_receipt::replayed_in(self.vault(), txn, id.clone())? { return Ok(id); }
        let mut record = self.lifecycle_record(&TaskVia::Wire, call, call, Some(act.task_ref), None, now);
        record.fields.insert("checkout".into(), act.checkout_id.to_string());
        record.fields.insert("epoch".into(), act.epoch.to_string());
        record.fields.insert("holder".into(), act.holder_ref.clone());
        record.fields.insert("result_identity".into(), identity.iter().map(|b| format!("{b:02x}")).collect());
        lifecycle_receipt::stamp_record_in(self.vault(), txn, &record, id, None)
    }

    pub(crate) fn checkout_receipt_exists_in(
        &self, txn: &heed::RoTxn<'_>, act: &CheckoutLeaseAct, call: &str, identity: &[u8],
    ) -> MemoryResult<Option<String>> {
        lifecycle_receipt::replayed_in(self.vault(), txn, self.checkout_receipt_id(act, call, identity)?)
    }

    pub(crate) fn checkout_signal_settled(&self, task: EntityId, now: u64) -> MemoryResult<()> {
        self.signal_task_settled(task, now)
    }
}
