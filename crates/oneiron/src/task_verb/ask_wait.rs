//! A wait suspends its calling C9 step, never the enclosing attempt or run.
use super::ask::{TaskAskAnswer, TaskAskHandle, read};
use crate::llm::{DreamerTrapKind, DurableStepContext, TrapRef};
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};
const WAITS: &[u8] = b"tasks.ask_wait.v1/";
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskWaitOutcome {
    Pending { trap_ref: String },
    Ready(TaskAskAnswer),
    AlreadyResumed(TaskAskAnswer),
}
#[derive(Serialize, Deserialize)]
struct WaitRow {
    trap_ref: String,
    step_hash: [u8; 32],
    actor: String,
    consumed: bool,
}
impl WaitRow {
    fn trap(&self) -> crate::Result<TrapRef> {
        Ok(TrapRef {
            trap_claim_id: EntityId::from_hex(&self.trap_ref)?,
            kind: DreamerTrapKind::HumanResponse,
            step_hash: self.step_hash,
        })
    }
}
fn prefix(id: EntityId) -> Vec<u8> {
    [WAITS, id.as_bytes()].concat()
}
pub(super) fn signal_waiters(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    task: EntityId,
    now: u64,
) -> MemoryResult<()> {
    let rows = vault
        .store
        .vault_meta
        .prefix_iter(txn, &prefix(task))?
        .map(|r| r.map(|(_, v)| v.to_vec()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for raw in rows {
        let row: WaitRow =
            serde_json::from_slice(&raw).map_err(|_| MemoryError::bad_request("wait record"))?;
        if !row.consumed {
            crate::llm::signal_step_wait_in_txn(vault, txn, &row.trap()?, now)?;
        }
    }
    Ok(())
}
fn require_answerable(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    task: EntityId,
    answered: bool,
) -> MemoryResult<()> {
    if !answered {
        let body = super::create_validation::task_body_in_txn(vault, txn, task)?;
        if body
            .state
            .as_ref()
            .is_some_and(|state| state.terminal().is_some())
            || vault
                .task_authority_state_in(txn, task)?
                .is_some_and(|state| state.cancelled)
        {
            return Err(MemoryError::bad_request("ask is terminal"));
        }
    }
    Ok(())
}

impl Memory<'_> {
    pub fn tasks_wait(
        &self,
        handle: &TaskAskHandle,
        ctx: &DurableStepContext<'_>,
        step_hash: [u8; 32],
    ) -> MemoryResult<TaskWaitOutcome> {
        if !std::ptr::eq(self.vault(), ctx.vault)
            || ctx.envelope_actor.entity_ref() != self.actor()
            || ctx.envelope_actor.actor_class() != self.actor_class()
        {
            return Err(MemoryError::bad_request("wait context actor mismatch"));
        }
        let task = EntityId::from_hex(&handle.task_ref)?;
        self.with_verified_actor_write_txn(|txn| {
            let ask = read(self.vault(), txn, task)?;
            if ask.owner != self.actor().to_hex() {
                return Err(MemoryError::bad_request("only the asking step may wait"));
            }
            require_answerable(self.vault(), txn, task, ask.answer.is_some())?;
            let key = [
                prefix(task).as_slice(),
                ctx.attempt_id.as_bytes(),
                step_hash.as_slice(),
            ]
            .concat();
            let mut row = if let Some(raw) = self.vault().store.vault_meta.get(txn, &key)? {
                serde_json::from_slice::<WaitRow>(&raw)
                    .map_err(|_| MemoryError::bad_request("wait record"))?
            } else {
                let trap = crate::llm::open_step_wait_in_txn(self.vault(), txn, ctx, step_hash)?;
                WaitRow {
                    trap_ref: trap.trap_claim_id.to_hex(),
                    step_hash,
                    actor: self.actor().to_hex(),
                    consumed: false,
                }
            };
            if row.actor != self.actor().to_hex() || row.step_hash != step_hash {
                return Err(MemoryError::bad_request("wait binding changed"));
            }
            let outcome = if let Some(answer) = ask.answer {
                if row.consumed {
                    TaskWaitOutcome::AlreadyResumed(answer)
                } else {
                    let trap = row.trap()?;
                    crate::llm::signal_step_wait_in_txn(self.vault(), txn, &trap, ctx.now_ms)?;
                    if !crate::llm::consume_step_wait_in_txn(self.vault(), txn, &trap, ctx.now_ms)?
                    {
                        return Err(MemoryError::bad_request("wait signal was not consumable"));
                    }
                    row.consumed = true;
                    TaskWaitOutcome::Ready(answer)
                }
            } else {
                TaskWaitOutcome::Pending {
                    trap_ref: row.trap_ref.clone(),
                }
            };
            self.vault().store.vault_meta.put(
                txn,
                &key,
                &serde_json::to_vec(&row).map_err(|_| MemoryError::bad_request("wait encoding"))?,
            )?;
            Ok(outcome)
        })
    }
}

impl Memory<'_> {
    /// External SDK clients have no engine-owned run. Their stable step key
    /// names a detached C9 step; native runners call tasks_wait with their
    /// own DurableStepContext instead. No queue row or run is suspended.
    pub fn tasks_wait_external(
        &self,
        handle: &TaskAskHandle,
        step_key: &str,
    ) -> MemoryResult<TaskWaitOutcome> {
        if step_key.is_empty() || step_key.len() > 256 {
            return Err(MemoryError::bad_request("invalid wait step key"));
        }
        let task = EntityId::from_hex(&handle.task_ref)?;
        let mut hash = blake3::Hasher::new();
        hash.update(b"tasks.external_step.v1");
        hash.update(self.actor().as_bytes());
        hash.update(task.as_bytes());
        hash.update(step_key.as_bytes());
        let step_hash = *hash.finalize().as_bytes();
        let ctx = DurableStepContext {
            vault: self.vault(),
            attempt_id: crate::attempt_queue::AttemptId::from_bytes(&step_hash[..16])?,
            run_id: None,
            envelope_actor: crate::write_envelope::WriteActor::new(
                self.actor(),
                self.actor_class(),
            ),
            subject: self.actor(),
            pinned_config: None,
            deadline: None,
            now_ms: crate::unix_seconds_now().saturating_mul(1000),
        };
        self.with_verified_actor_write_txn(|txn| {
            let ask = read(self.vault(), txn, task)?;
            if ask.owner != self.actor().to_hex() {
                return Err(MemoryError::bad_request("only the asking step may wait"));
            }
            require_answerable(self.vault(), txn, task, ask.answer.is_some())?;
            crate::llm::register_detached_step_in_txn(self.vault(), txn, &ctx, step_hash)?;
            Ok(())
        })?;
        self.tasks_wait(handle, &ctx, step_hash)
    }
}
