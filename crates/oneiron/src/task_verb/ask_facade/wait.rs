//! Durable ask waits and waiter signals.
//! Entry: `signal_waiters`.
//! This module owns `WaitRow`; ask records belong to `ask_record`.

use super::*;

#[derive(serde::Serialize, serde::Deserialize)]
pub(in crate::task_verb) struct WaitRow {
    pub(super) trap_ref: Option<EntityId>,
    pub(super) step_hash: [u8; 32],
    pub(in crate::task_verb) actor: TaskActor,
    pub(in crate::task_verb) consumed: bool,
}

impl WaitRow {
    /// Consumes this wait once what it waits on is settled: its bound trap,
    /// when it has one not yet consumed, is signalled and consumed in the
    /// caller's write.
    pub(super) fn consume_in(
        &mut self,
        vault: &crate::Vault,
        txn: &mut heed::RwTxn<'_>,
        now_ms: u64,
    ) -> MemoryResult<()> {
        if let Some(trap_claim_id) = self.trap_ref
            && !self.consumed
        {
            let trap = crate::llm::TrapRef {
                trap_claim_id,
                kind: crate::llm::DreamerTrapKind::HumanResponse,
                step_hash: self.step_hash,
            };
            crate::llm::signal_step_wait_in_txn(vault, txn, &trap, now_ms)?;
            if !crate::llm::consume_step_wait_in_txn(vault, txn, &trap, now_ms)? {
                return Err(MemoryError::bad_request("wait signal was not consumable"));
            }
        }
        self.consumed = true;
        Ok(())
    }
}

/// Registered external ask wait: `(group id, step hash) -> WaitRow`.
pub(in crate::task_verb) const TASK_ASK_WAITS: SideTable<(EntityId, [u8; 32]), WaitRow, Named> =
    SideTable::new(&side_table::TASK_ASK_WAIT);

pub(in crate::task_verb) fn signal_waiters(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    group: EntityId,
    now: u64,
) -> MemoryResult<()> {
    let rows = TASK_ASK_WAITS.scan_from(&vault.store, txn, group.as_bytes())?;
    for (_, row) in rows {
        if !row.consumed {
            let trap = crate::llm::TrapRef {
                trap_claim_id: row
                    .trap_ref
                    .ok_or_else(|| MemoryError::bad_request("pending wait has no trap"))?,
                kind: crate::llm::DreamerTrapKind::HumanResponse,
                step_hash: row.step_hash,
            };
            crate::llm::signal_step_wait_in_txn(vault, txn, &trap, now)?;
        }
    }
    Ok(())
}

impl Memory<'_> {
    pub(in crate::task_verb) fn bind_external_wait(
        &self,
        txn: &mut heed::RwTxn<'_>,
        handle: TaskAskHandle,
        step_key: &str,
        status: TaskAskStatus,
    ) -> MemoryResult<TaskAskWait> {
        let mut hash = blake3::Hasher::new();
        hash.update(TASK_ASK_WAITS.decl().prefix);
        hash.update(self.actor().as_bytes());
        hash.update(handle.group_ref.as_bytes());
        hash.update(step_key.as_bytes());
        let step_hash = *hash.finalize().as_bytes();
        let key = (handle.group_ref, step_hash);
        let now_ms = self
            .vault()
            .store
            .clock
            .now_recorded_at()
            .saturating_mul(1000);
        let mut row = if let Some(row) = TASK_ASK_WAITS.get(&self.vault().store, txn, &key)? {
            row
        } else {
            // Every identity the ask holds counts, consumed ones too; past
            // its row the wait asks and is bound anyway.
            let held = TASK_ASK_WAITS
                .iter_from(&self.vault().store, txn, handle.group_ref.as_bytes())?
                .try_fold(0u64, |count, row| row.map(|_| count.saturating_add(1)))?;
            self.vault().limit_watch().measure(
                crate::limit_ask::EngineLimit::AskWaitIdentities,
                held.saturating_add(1),
            );
            // Answer-before-wait needs only bounded exactly-once bookkeeping.
            // Do not mint a detached step or a trap for a completed answer.
            let trap_ref = if matches!(status, TaskAskStatus::Pending { .. }) {
                let ctx = crate::llm::DurableStepContext {
                    vault: self.vault(),
                    attempt_id: crate::attempt_queue::AttemptId::from_bytes(
                        step_hash
                            .get(..16)
                            .ok_or_else(|| MemoryError::bad_request("wait identity"))?,
                    )?,
                    run_id: None,
                    envelope_actor: self.write_actor(),
                    subject: self.actor(),
                    deadline: None,
                    now_ms,
                };
                crate::llm::register_detached_step_in_txn(self.vault(), txn, &ctx, step_hash)?;
                Some(
                    crate::llm::open_step_wait_in_txn(self.vault(), txn, &ctx, step_hash)?
                        .trap_claim_id,
                )
            } else {
                None
            };
            WaitRow {
                trap_ref,
                step_hash,
                actor: TaskActor::Actor(self.actor()),
                consumed: false,
            }
        };
        if !row.actor.is(self.actor()) || row.step_hash != step_hash {
            return Err(MemoryError::bad_request("wait binding changed"));
        }
        let outcome = match status {
            TaskAskStatus::Pending { .. } => TaskAskWait::Pending {
                trap_ref: row
                    .trap_ref
                    .ok_or_else(|| MemoryError::bad_request("pending wait has no trap"))?
                    .to_hex(),
            },
            TaskAskStatus::Changed { voided, generation } => {
                TaskAskWait::Changed { voided, generation }
            }
            TaskAskStatus::Settled(result) => {
                row.consume_in(self.vault(), txn, now_ms)?;
                TaskAskWait::Ready(result)
            }
            TaskAskStatus::WorldPrivacy(request) => {
                row.consume_in(self.vault(), txn, now_ms)?;
                TaskAskWait::WorldPrivacyReady(request)
            }
        };
        TASK_ASK_WAITS
            .put(&self.vault().store, txn, &key, &row)
            .map_err(MemoryError::from)?;
        Ok(outcome)
    }
}

pub(crate) fn settle_waiting_asks(vault: &crate::Vault) -> crate::Result<()> {
    let txn = vault.store.env.read_txn()?;
    let mut groups = std::collections::BTreeSet::new();
    for ((group, _), row) in TASK_ASK_WAITS.scan(&vault.store, &txn)? {
        if !row.consumed {
            groups.insert(group);
        }
    }
    // OF-533: a canonical code run parked on an ask (a pumped `tasks.wait`) waits too.
    groups.extend(crate::code_run::canonical_wait_ids(vault, &txn)?);
    drop(txn);
    for group in groups {
        super::ask_settlement::settle_ask_if_due(vault, group)?;
        // FIX 4706: a world-privacy request's waits, from its LIVE status.
        super::world_privacy_wait::reconcile_world_privacy_wait(vault, group)?;
    }
    vault.retry_pending_ask_soft_confirms(usize::MAX)?;
    Ok(())
}
