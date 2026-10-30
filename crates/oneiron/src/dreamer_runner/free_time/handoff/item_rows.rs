//! FIX 5661: the free-time items a home move carries: each item with no
//! receipt whose try was queued on the old home and never started. The old
//! home's try stays queued and inert there (C1's guard admits no such try
//! while its home drains or after it froze), so nothing is cancelled and no
//! receipt is made for it. The new home queues the same try again, under its
//! attempt id, beside its binding. A try that started runs and settles on
//! its old home before the move freezes; a completed item is never queued
//! again.
//!
//! FIX 8875 stage 2: an item travels as its binding's facts, its agent in
//! its agent's partition. An item whose agent did not open here queues
//! nothing: no substitute try, no new allowance, never a Conflict.

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::super::cycle::{item_queue_kind, resume_item_in_txn};
use super::super::{CYCLE, FreeTimeItemBinding, FreeTimeKind, ITEM, RECEIPT};
use super::actor_content::{
    FreeTimeActorPartition, FreeTimeActorPiece, FreeTimeAdoptRow, FreeTimePartitioned,
    FreeTimeSlot, Joined, Pieces,
};
use super::{all_keys, erased_in_txn, free_time_item_waits_unstarted, invalid, settled_in_txn};
use crate::agent_dispatch::{AgentDispatcher, SpendScopeId};
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::side_table::{self, SideTableDecl};
use crate::sync::home_handoff::{HomeFence, HomeMove, HomeTable, TableAdopt};
use crate::{EntityId, Result, Vault};

/// The items a home move carries to queue again: each item's facts, its
/// agent apart.
#[derive(Serialize, Deserialize)]
pub(crate) struct FreeTimeItemRows {
    items: Vec<ItemFacts>,
}

/// One item and the try its old home queued and never started.
struct ItemRow {
    binding: FreeTimeItemBinding,
    /// The queue its try waits in.
    queue_kind: String,
    /// When its old home queued the try (Unix seconds).
    enqueued_at: u64,
}

/// One carried item without its agent: its place, its try and its scope.
#[derive(Serialize, Deserialize)]
struct ItemFacts {
    cycle: EntityId,
    boundary: u64,
    period_start: u64,
    item: EntityId,
    kind: FreeTimeKind,
    policy_revision: u64,
    attempt: [u8; 16],
    spend_scope: SpendScopeId,
    queue_kind: String,
    enqueued_at: u64,
}

impl FreeTimeItemRows {
    /// `items`, every carried item here, partitioned.
    fn partition(items: Vec<ItemRow>) -> Result<FreeTimePartitioned<Self>> {
        let mut pieces = Pieces::new(FreeTimeSlot::Item);
        let mut facts = Vec::with_capacity(items.len());
        for (index, item) in items.into_iter().enumerate() {
            let row = pieces.row(index)?;
            let binding = item.binding;
            pieces.push(binding.agent, FreeTimeActorPiece::Subject { row });
            facts.push(ItemFacts {
                cycle: binding.cycle,
                boundary: binding.boundary,
                period_start: binding.period_start,
                item: binding.item,
                kind: binding.kind,
                policy_revision: binding.policy_revision,
                attempt: binding.attempt,
                spend_scope: binding.spend_scope,
                queue_kind: item.queue_kind,
                enqueued_at: item.enqueued_at,
            });
        }
        Ok(pieces.partitioned(Self { items: facts }))
    }

    /// Each carried item rejoined with its agent, scrubbed-first.
    fn rejoin_in_txn(
        vault: &Vault,
        txn: &RoTxn<'_>,
        rows: FreeTimePartitioned<Self>,
    ) -> Result<Vec<FreeTimeAdoptRow<ItemRow, ItemFacts>>> {
        let joined = Joined::in_txn(vault, txn, FreeTimeSlot::Item, rows.actors)?;
        Ok((0u32..)
            .zip(rows.facts.items)
            .map(|(row, facts)| match joined.subject(row) {
                None => FreeTimeAdoptRow::Scrubbed(facts),
                Some(agent) => FreeTimeAdoptRow::Live(ItemRow {
                    binding: FreeTimeItemBinding {
                        agent,
                        cycle: facts.cycle,
                        boundary: facts.boundary,
                        period_start: facts.period_start,
                        item: facts.item,
                        kind: facts.kind,
                        policy_revision: facts.policy_revision,
                        attempt: facts.attempt,
                        spend_scope: facts.spend_scope,
                    },
                    queue_kind: facts.queue_kind,
                    enqueued_at: facts.enqueued_at,
                }),
            })
            .collect())
    }
}

impl HomeTable for FreeTimeItemRows {
    type Rows = Self;
    type Actor = FreeTimeActorPartition;
    const TABLE: &'static SideTableDecl = &side_table::DREAMER_FREE_TIME_ITEM;
    const SCHEMA_VERSION: u16 = 2;

    fn quiescent(vault: &Vault, txn: &RoTxn<'_>, _movement: &HomeMove) -> Result<bool> {
        settled_in_txn(vault, txn)
    }

    fn export(
        vault: &Vault,
        txn: &RoTxn<'_>,
        _fence: &HomeFence,
    ) -> Result<FreeTimePartitioned<Self>> {
        let queue = AttemptQueue::new(vault);
        let mut items = Vec::new();
        for row in ITEM.iter_from(&vault.store, txn, &[])? {
            let (attempt, binding) = row?;
            let key = (binding.agent, binding.cycle, binding.item);
            if RECEIPT.contains(&vault.store, txn, &key)? {
                continue;
            }
            if let Some(record) = queue.get_in_txn(txn, attempt)?
                && free_time_item_waits_unstarted(&record)
            {
                items.push(ItemRow {
                    binding,
                    queue_kind: record.kind,
                    enqueued_at: record.created_at,
                });
            }
        }
        Self::partition(items)
    }

    /// Lands each carried item after its cycle, its receipts and its spend
    /// tree. A binding here for its try that differs, a receipt here for
    /// it, a missing cycle or spend scope, or another try holding its place
    /// in the queue is a Conflict. An item whose agent did not open here
    /// queues nothing, before any of those checks.
    fn adopt(
        vault: &Vault,
        txn: &mut RwTxn<'_>,
        _fence: &HomeFence,
        rows: FreeTimePartitioned<Self>,
    ) -> Result<TableAdopt> {
        for row in Self::rejoin_in_txn(vault, txn, rows)? {
            let FreeTimeAdoptRow::Live(item) = row else {
                continue;
            };
            if !adopt_item_in_txn(vault, txn, item)? {
                return Ok(TableAdopt::Conflict);
            }
        }
        Ok(TableAdopt::Applied)
    }

    fn live_keys(vault: &Vault, txn: &RoTxn<'_>) -> Result<Vec<Vec<u8>>> {
        all_keys(ITEM, vault, txn)
    }
}

/// Lands one carried item: its binding, and its try queued again here as
/// itself. `false`: something here holds its place.
fn adopt_item_in_txn(vault: &Vault, txn: &mut RwTxn<'_>, item: ItemRow) -> Result<bool> {
    let ItemRow {
        binding,
        queue_kind,
        enqueued_at,
    } = item;
    if queue_kind != item_queue_kind(binding.kind) {
        return Err(invalid("a carried item waits in another kind's queue"));
    }
    if erased_in_txn(vault, txn, &binding.agent)? {
        return Ok(true);
    }
    let attempt = AttemptId::from_bytes(&binding.attempt)?;
    if ITEM
        .get(&vault.store, txn, &attempt)?
        .is_some_and(|local| local != binding)
    {
        return Ok(false);
    }
    let receipt = (binding.agent, binding.cycle, binding.item);
    if !CYCLE.contains(&vault.store, txn, &(binding.agent, binding.boundary))?
        || RECEIPT.contains(&vault.store, txn, &receipt)?
        || AgentDispatcher::new(vault)
            .attempt_spend_scope_in_txn(txn, attempt)?
            .is_none()
    {
        return Ok(false);
    }
    resume_item_in_txn(vault, txn, &binding, enqueued_at)
}
