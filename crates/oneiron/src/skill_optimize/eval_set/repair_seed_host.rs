//! The repair seed's measuring host (census L1-20 PR D): what fixed code
//! hands the host for one `Pending` seed, and the settle it runs through
//! the capture owner's own scoped read.
//!
//! "The task text is read only through the capture owner's own scoped
//! read": every door here resolves the capture's owner from its stored
//! file and compiles the task as that owner, as the Coach's apply does.
//! The release holds the leg input, the declared tools, the arms, the
//! source rows and the seat; never the expected answer, the grader or any
//! outcome text.

use serde_json::Value;

use super::repair_seed::{memory_read_refused, row_reads_in_txn};
use super::{
    EvalArmPin, EvalRepairLegAnswer, EvalRepairSeed, EvalRepairSeedLegs, EvalRepairSeedState,
    EvalRepairTask, EvalRepairTool, EvalSeat, bounded_ref, invalid,
};
use crate::EdgeActorClass;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ingest::ag_ui_capture_owner_in_txn;

/// What the measuring host is handed for one Pending seed. Never the expected answer, the grader or any outcome text.
#[derive(Debug, Clone)]
pub struct EvalRepairSeedRelease {
    /// The seed's key (the SEEDS side-table key).
    pub key: [u8; 32],
    pub seat: EvalSeat,
    /// The skill the repair corrected: its leg must fail.
    pub old: EvalArmPin,
    /// The proposed skill: its leg must pass.
    pub candidate: EvalArmPin,
    /// The leg input: `EvalRepairTask::response_input()`, whole.
    pub input: Value,
    /// The declared tools of a JSON-state-tools world; empty for a text-response world.
    pub tools: Vec<EvalRepairTool>,
    /// The capture rows the task was compiled from (a leg's stored output is sourced on them).
    pub source_rows: Vec<EntityId>,
    /// The capture's task no longer compiles to the seed's task hash: settle at once with no leg run
    /// (the settle door refuses it as TaskMoved).
    pub moved: bool,
}

/// The seed under `key` as its host job runs it: the seed, still `Pending`
/// with every source row reading, and the capture's owner, resolved from
/// its stored file. `None` where there is no such seed, it is not
/// `Pending`, a source row no longer reads, or no owner resolves.
fn pending_seed_for_host(
    vault: &Vault,
    key: &[u8; 32],
) -> Result<Option<(EvalRepairSeed, EntityId)>> {
    let txn = vault.store.env.read_txn()?;
    let Some(seed) = vault.eval_repair_seed_by_key_in_txn(&txn, key)? else {
        return Ok(None);
    };
    if seed.state != EvalRepairSeedState::Pending {
        return Ok(None);
    }
    for row in &seed.source_rows {
        if !row_reads_in_txn(vault, &txn, row)? {
            return Ok(None);
        }
    }
    let Ok(claim) = EntityId::from_hex(&seed.source.claim_ref) else {
        return Ok(None);
    };
    let owner = ag_ui_capture_owner_in_txn(vault, &txn, &claim)?;
    Ok(owner.map(|owner| (seed, owner)))
}

/// The seed's task through the capture owner's own scoped read, with an
/// adjudicated seed's label digest applied as the settle does. `None`
/// where the owner's read withholds the capture or refuses the task; other
/// `Memory` errors pass through.
fn owner_task(
    vault: &Vault,
    owner: EntityId,
    seed: &EvalRepairSeed,
) -> Result<Option<EvalRepairTask>> {
    let read = match vault
        .memory(owner, EdgeActorClass::Human)
        .read_eval_repair_task(&seed.source)
    {
        Ok(read) => read,
        Err(error) if memory_read_refused(&error) => return Ok(None),
        Err(error) => return Err(Error::Refused(error.message)),
    };
    let Some(mut task) = read.task else {
        return Ok(None);
    };
    if let Some(adjudication) = &seed.adjudication {
        task.adjudicate(adjudication.answer_digest);
    }
    Ok(Some(task))
}

impl Vault {
    /// The release of the seed under `key` for the measuring host: `None` when there is no such seed, it is not
    /// Pending, a source row no longer reads (row_reads_in_txn), or the capture owner's scoped read withholds it.
    /// The task is compiled through the capture OWNER's own scoped read.
    ///
    /// # Errors
    ///
    /// Storage errors, and a `Memory` error that is no refused read.
    pub fn eval_repair_seed_release(
        &self,
        key: &[u8; 32],
    ) -> Result<Option<EvalRepairSeedRelease>> {
        let Some((seed, owner)) = pending_seed_for_host(self, key)? else {
            return Ok(None);
        };
        let Some(task) = owner_task(self, owner, &seed)? else {
            return Ok(None);
        };
        Ok(Some(EvalRepairSeedRelease {
            key: *key,
            seat: seed.source.seat.clone(),
            old: seed.old.clone(),
            candidate: seed.candidate.clone(),
            input: task.response_input().clone(),
            tools: task.tools().to_vec(),
            source_rows: seed.source_rows.clone(),
            moved: task.task_hash != seed.task_hash,
        }))
    }

    /// Settles the seed under `key` through the capture owner's `Memory::settle_eval_repair_seed` (unchanged), and
    /// returns only the seed's state: never the seed, whose adjudication holds the adjudicated answer's digest.
    /// `None` when the owner's read withholds the capture.
    ///
    /// # Errors
    ///
    /// Unbounded or equal leg receipts, storage errors, and a `Memory`
    /// error that is no refused read.
    pub fn settle_eval_repair_seed_release(
        &self,
        key: &[u8; 32],
        old: &EvalRepairLegAnswer,
        candidate: &EvalRepairLegAnswer,
        legs: &EvalRepairSeedLegs,
        at: u64,
    ) -> Result<Option<EvalRepairSeedState>> {
        bounded_ref(&legs.old_receipt)?;
        bounded_ref(&legs.candidate_receipt)?;
        if legs.old_receipt == legs.candidate_receipt {
            return Err(invalid("a repair seed's two legs have their own receipts"));
        }
        let txn = self.store.env.read_txn()?;
        let Some(seed) = self.eval_repair_seed_by_key_in_txn(&txn, key)? else {
            return Ok(None);
        };
        for row in &seed.source_rows {
            if !row_reads_in_txn(self, &txn, row)? {
                return Ok(None);
            }
        }
        let Ok(claim) = EntityId::from_hex(&seed.source.claim_ref) else {
            return Ok(None);
        };
        let owner = ag_ui_capture_owner_in_txn(self, &txn, &claim)?;
        drop(txn);
        let Some(owner) = owner else {
            return Ok(None);
        };
        let read = match self
            .memory(owner, EdgeActorClass::Human)
            .settle_eval_repair_seed(&seed.source, old, candidate, legs, at)
        {
            Ok(read) => read,
            Err(error) if memory_read_refused(&error) => return Ok(None),
            Err(error) => return Err(Error::Refused(error.message)),
        };
        Ok(read.seed.map(|seed| seed.state))
    }
}
