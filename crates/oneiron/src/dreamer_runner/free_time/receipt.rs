//! Each free-time item's terminal receipt, and a cycle's floor (FIX 4453).
//!
//! An item ends in one receipt, by its label; the first stands, so a replay
//! records nothing twice. Retries and calls are spend, not more items. The
//! floor reads receipts alone: at least one for-human item that landed a
//! proposal and one own-time item that reflected or rested. A read that
//! could not enumerate every receipt of the cycle says Unknown, never
//! NotMet. Nothing here scores own time or presses on what is unspent.

use serde::{Deserialize, Serialize};

use super::cycle::{FreeTimeCycle, FreeTimeCycleState, close_cycle_in_txn};
use super::items::FreeTimeItemBinding;
use super::{CYCLE, FreeTimeKind, RECEIPT};
use crate::{EntityId, Result, Vault};

/// How one item ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FreeTimeItemOutcome {
    /// It did its work: a for-human item that landed its proposal, an
    /// own-time item whose reflection landed.
    Completed,
    /// Own time the agent chose to rest: no call, no spend, no text.
    Rested,
    /// It ran and landed nothing.
    Failed,
    /// It ended without doing its work: its cycle ended first, or it had
    /// nothing to run on.
    Cancelled,
}

/// One item's terminal receipt. It carries no prompt, no response, no diary
/// pointer and no score.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreeTimeItemReceipt {
    pub agent: EntityId,
    pub cycle: EntityId,
    pub item: EntityId,
    pub kind: FreeTimeKind,
    pub policy_revision: u64,
    pub outcome: FreeTimeItemOutcome,
    /// The attempt that ran it; `None` for rest chosen with no attempt.
    pub attempt: Option<[u8; 16]>,
    /// The Proposed claim a for-human item landed.
    pub proposal: Option<EntityId>,
    /// The code of a for-human item's read of its human's context that
    /// failed (FIX 5663): the item ran on its own records, as before. `None`
    /// when that context read, or there was none to read.
    #[serde(default)]
    pub context_unread: Option<String>,
    /// Vault clock seconds.
    pub at: u64,
}

impl FreeTimeItemReceipt {
    pub(super) fn of(
        binding: &FreeTimeItemBinding,
        outcome: FreeTimeItemOutcome,
        proposal: Option<EntityId>,
        at: u64,
    ) -> Self {
        Self {
            agent: binding.agent,
            cycle: binding.cycle,
            item: binding.item,
            kind: binding.kind,
            policy_revision: binding.policy_revision,
            outcome,
            attempt: Some(binding.attempt),
            proposal,
            context_unread: None,
            at,
        }
    }
}

/// Whether a cycle's floor holds, as its receipts show.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FreeTimeFloor {
    /// A for-human item landed a proposal, and an own-time item reflected
    /// or rested.
    Met,
    /// Every receipt was read, and one kind has none that meets it.
    NotMet,
    /// Not every receipt could be read: nothing is said either way.
    Unknown,
}

/// The floor of `agent`'s `cycle` from `receipts` alone. `complete` says the
/// read enumerated every receipt of that cycle in one snapshot; receipts of
/// any other agent or cycle count for nothing.
#[must_use]
pub fn free_time_floor(
    agent: EntityId,
    cycle: EntityId,
    receipts: &[FreeTimeItemReceipt],
    complete: bool,
) -> FreeTimeFloor {
    if !complete {
        return FreeTimeFloor::Unknown;
    }
    let mut for_human = false;
    let mut own_time = false;
    for receipt in receipts
        .iter()
        .filter(|receipt| receipt.agent == agent && receipt.cycle == cycle)
    {
        match (receipt.kind, receipt.outcome) {
            (FreeTimeKind::ForHuman, FreeTimeItemOutcome::Completed) => {
                for_human |= receipt.proposal.is_some();
            }
            (
                FreeTimeKind::OwnTime,
                FreeTimeItemOutcome::Completed | FreeTimeItemOutcome::Rested,
            ) => own_time = true,
            _ => {}
        }
    }
    if for_human && own_time {
        FreeTimeFloor::Met
    } else {
        FreeTimeFloor::NotMet
    }
}

/// Records `receipt` unless its item already has one; the first stands.
/// Returns whether it was recorded. An agent an erase removed records
/// nothing (FIX 5664): its erase took its free-time rows, and a writer that
/// lands after it keeps no copy, so neither the receipt nor the note and
/// cycle close each caller writes only after a recorded receipt land. A
/// home that froze its free-time rows for a move records none either: they
/// are history there, and the move carried them on (FIX 5661). A home move
/// lands carried receipts as they are, never through here.
pub(super) fn record_receipt_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    receipt: &FreeTimeItemReceipt,
) -> Result<bool> {
    #[cfg(feature = "sync")]
    if !super::items::settles_here_in_txn(vault, txn)? {
        return Ok(false);
    }
    let key = (receipt.agent, receipt.cycle, receipt.item);
    if RECEIPT.contains(&vault.store, txn, &key)?
        || crate::ports::removed_in_txn(&vault.store, txn, &receipt.agent)?
    {
        return Ok(false);
    }
    RECEIPT.put(&vault.store, txn, &key, receipt)?;
    Ok(true)
}

/// Ends `agent`'s cycle at `boundary` once every item it opened with has its
/// receipt.
pub(super) fn close_cycle_if_done_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    agent: EntityId,
    boundary: u64,
    at: u64,
) -> Result<()> {
    let Some(mut cycle) = CYCLE.get(&vault.store, txn, &(agent, boundary))? else {
        return Ok(());
    };
    if cycle.state == FreeTimeCycleState::Closed {
        return Ok(());
    }
    for item in &cycle.items {
        if !RECEIPT.contains(&vault.store, txn, &(agent, cycle.cycle, item.item))? {
            return Ok(());
        }
    }
    close_cycle_in_txn(vault, txn, &mut cycle, at)
}

/// One cycle as its owner reads it: the cycle with the agent's note, its
/// item receipts and its floor. Never the agent's diary or a stored
/// response; the spend shows in the spending records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreeTimeCycleSheet {
    pub cycle: FreeTimeCycle,
    pub receipts: Vec<FreeTimeItemReceipt>,
    pub floor: FreeTimeFloor,
}

/// Every receipt of `agent`'s `cycle` in one snapshot, and whether every
/// row read: a receipt row that does not read leaves the read incomplete.
pub(super) fn receipts_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    agent: EntityId,
    cycle: EntityId,
) -> Result<(Vec<FreeTimeItemReceipt>, bool)> {
    let mut prefix = agent.as_bytes().to_vec();
    prefix.extend_from_slice(cycle.as_bytes());
    let mut receipts = Vec::new();
    let mut complete = true;
    for row in RECEIPT.iter_from(&vault.store, txn, &prefix)? {
        match row {
            Ok((_, receipt)) => receipts.push(receipt),
            Err(_) => complete = false,
        }
    }
    Ok((receipts, complete))
}

/// `cycle`'s sheet in one snapshot. A receipt row that does not read leaves
/// the read incomplete, so its floor is Unknown.
fn sheet_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    cycle: FreeTimeCycle,
) -> Result<FreeTimeCycleSheet> {
    let (receipts, complete) = receipts_in_txn(vault, txn, cycle.agent, cycle.cycle)?;
    let floor = free_time_floor(cycle.agent, cycle.cycle, &receipts, complete);
    Ok(FreeTimeCycleSheet {
        cycle,
        receipts,
        floor,
    })
}

impl Vault {
    /// `agent`'s free-time cycles (FIX 4453), newest first: those whose
    /// boundary is before `before` when given, at most `limit`.
    ///
    /// # Errors
    /// A store read that fails or a cycle row that does not decode.
    pub fn free_time_cycles(
        &self,
        agent: EntityId,
        before: Option<u64>,
        limit: usize,
    ) -> Result<Vec<FreeTimeCycleSheet>> {
        let txn = self.store.env.read_txn()?;
        let mut sheets = Vec::new();
        for row in CYCLE.iter_rev_from(&self.store, &txn, agent.as_bytes())? {
            if sheets.len() >= limit {
                break;
            }
            let ((_, boundary), cycle) = row?;
            if before.is_some_and(|before| boundary >= before) {
                continue;
            }
            sheets.push(sheet_in_txn(self, &txn, cycle)?);
        }
        Ok(sheets)
    }

    /// One of `agent`'s free-time cycles by its id (FIX 4453); `None` when
    /// the agent has no such cycle.
    ///
    /// # Errors
    /// A store read that fails or a cycle row that does not decode.
    pub fn free_time_cycle(
        &self,
        agent: EntityId,
        cycle: EntityId,
    ) -> Result<Option<FreeTimeCycleSheet>> {
        let txn = self.store.env.read_txn()?;
        for row in CYCLE.iter_from(&self.store, &txn, agent.as_bytes())? {
            let (_, found) = row?;
            if found.cycle == cycle {
                return sheet_in_txn(self, &txn, found).map(Some);
            }
        }
        Ok(None)
    }
}
