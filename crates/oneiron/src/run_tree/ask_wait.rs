//! Durable step-local wait bindings for run-branch ask handles.
//!
//! The private LMDB binding is local authority for a C9 step-only trap. It
//! never parks the queue attempt; another step and sibling branches can run.

use serde::{Deserialize, Serialize};

use crate::attempt_queue::{AttemptId, AttemptState};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::{DreamerTrapKind, DurableStepContext, TrapRef};
use crate::side_table::{self, Named, SideTable};

use super::adapter::RunTreeAdapter;
use super::signal::RunAsk;

const WAITS: SideTable<[u8; 80], WaitBinding, Named> =
    SideTable::new(&side_table::RUN_TREE_ASK_WAIT);
const WAIT_DOMAIN: &[u8] = side_table::RUN_TREE_ASK_WAIT.prefix;
const MAX_WAITS_PER_ASK: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunAskWait {
    /// The caller should suspend only this step on the durable trap.
    Pending { ask: RunAsk, trap: TrapRef },
    /// The answer is already available, or this exact wait was consumed.
    Available(RunAsk),
}

#[derive(Serialize, Deserialize)]
struct WaitBinding {
    handle: String,
    step_key: String,
    run_id: String,
    actor: EntityId,
    actor_class: u8,
    subject: EntityId,
    trap_claim_id: EntityId,
    step_hash: [u8; 32],
    consumed: bool,
}

impl WaitBinding {
    fn trap(&self) -> TrapRef {
        TrapRef {
            trap_claim_id: self.trap_claim_id,
            kind: DreamerTrapKind::HumanResponse,
            step_hash: self.step_hash,
        }
    }

    fn matches(&self, ctx: &DurableStepContext<'_>, handle: &str, step_key: &str) -> bool {
        self.handle == handle
            && self.step_key == step_key
            && ctx.run_id.as_deref() == Some(&self.run_id)
            && ctx.envelope_actor.entity_ref() == self.actor
            && ctx.envelope_actor.actor_class() as u8 == self.actor_class
            && ctx.subject == self.subject
    }
}

fn wait_prefix(branch: AttemptId, handle: &str) -> [u8; 48] {
    let mut prefix = [0; 48];
    prefix[..16].copy_from_slice(branch.as_bytes());
    prefix[16..].copy_from_slice(blake3::hash(handle.as_bytes()).as_bytes());
    prefix
}

fn wait_key(branch: AttemptId, handle: &str, step_key: &str) -> [u8; 80] {
    let mut key = [0; 80];
    key[..48].copy_from_slice(&wait_prefix(branch, handle));
    key[48..].copy_from_slice(blake3::hash(step_key.as_bytes()).as_bytes());
    key
}

fn read_wait(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    key: &[u8; 80],
    handle: &str,
) -> Result<Option<WaitBinding>> {
    let value = WAITS.get(store, txn, key).map_err(|error| {
        if error.kind() == crate::ErrorKind::SideTableRow {
            Error::InvalidConfig("invalid ask wait binding".into())
        } else {
            error
        }
    })?;
    if value
        .as_ref()
        .is_some_and(|binding| binding.handle != handle)
    {
        return Err(Error::InvalidConfig(
            "ask wait binding handle mismatch".into(),
        ));
    }
    Ok(value)
}

/// Co-transactionally wake each unconsumed step on ONE newly landed answer.
/// Calls after a settled replay do not reach this function.
pub(super) fn signal_waiters_in_txn(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    branch: AttemptId,
    handle: &str,
    at_ms: u64,
) -> Result<()> {
    let rows = WAITS.scan_from(&vault.store, txn, &wait_prefix(branch, handle))?;
    if rows.len() > MAX_WAITS_PER_ASK {
        return Err(Error::InvalidConfig(
            "ask wait binding limit exceeded".into(),
        ));
    }
    for (_, binding) in rows {
        if binding.handle != handle {
            return Err(Error::InvalidConfig(
                "ask wait binding handle mismatch".into(),
            ));
        }
        if !binding.consumed {
            crate::llm::signal_step_wait_in_txn(vault, txn, &binding.trap(), at_ms)?;
        }
    }
    Ok(())
}

impl RunTreeAdapter<'_> {
    /// Binds a single waiting STEP to an ask handle, not the queue branch.
    /// One `step_key` is an immutable wait identity; use a fresh key to park
    /// again after consuming a partial answer. A fully answered ask needs no
    /// trap (including when the answer arrived before this call).
    pub fn wait_ask(
        &self,
        ctx: &DurableStepContext<'_>,
        handle: &str,
        step_key: &str,
    ) -> Result<RunAskWait> {
        if ctx.vault.vault_id() != self.vault.vault_id()
            || ctx.run_id.is_none()
            || handle.is_empty()
            || step_key.is_empty()
            || handle.len() > 4096
            || step_key.len() > 4096
        {
            return Err(Error::InvalidConfig("invalid ask wait context".into()));
        }
        let mut txn = self.vault.store.env.write_txn()?;
        let record = self
            .queue
            .get_in_txn(&txn, ctx.attempt_id)?
            .ok_or_else(|| Error::InvalidConfig("ask wait attempt missing".into()))?;
        if record.run_id != ctx.run_id
            || !matches!(record.state, AttemptState::Leased | AttemptState::Landing)
        {
            return Err(Error::InvalidConfig("ask wait branch mismatch".into()));
        }
        let ask = record
            .asks
            .into_iter()
            .find(|ask| ask.handle == handle)
            .ok_or_else(|| Error::InvalidConfig("ask wait handle missing".into()))?;
        let key = wait_key(ctx.attempt_id, handle, step_key);
        if let Some(binding) = read_wait(&self.vault.store, &txn, &key, handle)? {
            if !binding.matches(ctx, handle, step_key) {
                return Err(Error::InvalidConfig("ask wait identity changed".into()));
            }
            return if binding.consumed {
                Ok(RunAskWait::Available(ask))
            } else {
                Ok(RunAskWait::Pending {
                    ask,
                    trap: binding.trap(),
                })
            };
        }
        if ask.answers.len() == ask.questions.len() {
            return Ok(RunAskWait::Available(ask));
        }
        let prefix = wait_prefix(ctx.attempt_id, handle);
        let count = WAITS
            .iter_from(&self.vault.store, &txn, &prefix)?
            .take(MAX_WAITS_PER_ASK)
            .try_fold(0, |count, row| row.map(|_| count + 1))?;
        if count >= MAX_WAITS_PER_ASK {
            return Err(Error::InvalidConfig(
                "ask wait binding limit exceeded".into(),
            ));
        }
        let mut hash = blake3::Hasher::new();
        hash.update(WAIT_DOMAIN);
        hash.update(ctx.attempt_id.as_bytes());
        hash.update(handle.as_bytes());
        hash.update(step_key.as_bytes());
        hash.update(ctx.envelope_actor.entity_ref().as_bytes());
        hash.update(ctx.subject.as_bytes());
        let step_hash = *hash.finalize().as_bytes();
        let trap = crate::llm::open_step_wait_in_txn(self.vault, &mut txn, ctx, step_hash)?;
        let binding = WaitBinding {
            handle: handle.into(),
            step_key: step_key.into(),
            run_id: ctx.run_id.clone().expect("checked run id"),
            actor: ctx.envelope_actor.entity_ref(),
            actor_class: ctx.envelope_actor.actor_class() as u8,
            subject: ctx.subject,
            trap_claim_id: trap.trap_claim_id,
            step_hash,
            consumed: false,
        };
        WAITS.put(&self.vault.store, &mut txn, &key, &binding)?;
        txn.commit()?;
        Ok(RunAskWait::Pending { ask, trap })
    }

    /// Consumes one step-only signal once. `None` means the matching answer
    /// has not arrived; `Some` carries the durable partial or complete answer
    /// snapshot. This never resumes or pauses the queue attempt.
    pub fn consume_ask_wait(
        &self,
        ctx: &DurableStepContext<'_>,
        handle: &str,
        step_key: &str,
    ) -> Result<Option<RunAsk>> {
        if ctx.vault.vault_id() != self.vault.vault_id() || ctx.run_id.is_none() {
            return Err(Error::InvalidConfig("invalid ask wait context".into()));
        }
        let mut txn = self.vault.store.env.write_txn()?;
        let record = self
            .queue
            .get_in_txn(&txn, ctx.attempt_id)?
            .ok_or_else(|| Error::InvalidConfig("ask wait attempt missing".into()))?;
        if record.run_id != ctx.run_id {
            return Err(Error::InvalidConfig("ask wait branch mismatch".into()));
        }
        let ask = record
            .asks
            .into_iter()
            .find(|ask| ask.handle == handle)
            .ok_or_else(|| Error::InvalidConfig("ask wait handle missing".into()))?;
        let key = wait_key(ctx.attempt_id, handle, step_key);
        let mut binding = read_wait(&self.vault.store, &txn, &key, handle)?
            .ok_or_else(|| Error::InvalidConfig("ask wait binding missing".into()))?;
        if !binding.matches(ctx, handle, step_key) {
            return Err(Error::InvalidConfig("ask wait identity changed".into()));
        }
        if binding.consumed {
            return Ok(Some(ask));
        }
        if !crate::llm::consume_step_wait_in_txn(self.vault, &mut txn, &binding.trap(), ctx.now_ms)?
        {
            return Ok(None);
        }
        binding.consumed = true;
        WAITS.put(&self.vault.store, &mut txn, &key, &binding)?;
        txn.commit()?;
        Ok(Some(ask))
    }
}
