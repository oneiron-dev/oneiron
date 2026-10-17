//! Durable soft-confirm outbox, retried independently of answer replay.
use std::ops::Bound::{Excluded, Unbounded};

use super::TaskAskSoftConfirmDelivery;
use crate::edge::EdgeActorClass;
use crate::scan_check::{EngineScan, ScanCount};
use crate::side_table::{self, Named, Raw, SideTable};
use crate::{EntityId, Result, Vault};

/// Soft-confirm notice delivery state of one guest. Key: id16 (group) + id16 (person).
const DELIVERIES: SideTable<(EntityId, EntityId), TaskAskSoftConfirmDelivery, Named> =
    SideTable::new(&side_table::TASK_ASK_SOFT_CONFIRM_DELIVERY);
/// The delivery key suffix (group id16 + person id16) the retry sweep visited last. Key: ().
const CURSOR: SideTable<(), Vec<u8>, Raw> =
    SideTable::new(&side_table::TASK_ASK_SOFT_CONFIRM_DELIVERY_CURSOR);

fn store(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    group: EntityId,
    person: EntityId,
    state: TaskAskSoftConfirmDelivery,
) -> Result<()> {
    DELIVERIES.put(&vault.store, txn, &(group, person), &state)
}

/// The delivery key the sweep visited last, read from its cursor; `None` from
/// the start.
fn cursor_after(cursor: &[u8]) -> Result<Option<(EntityId, EntityId)>> {
    if cursor.is_empty() {
        return Ok(None);
    }
    let corrupt = || crate::Error::CorruptedIndex("ask soft-confirm cursor");
    let (group, person) = cursor.split_first_chunk::<16>().ok_or_else(corrupt)?;
    let person: [u8; 16] = person.try_into().map_err(|_| corrupt())?;
    Ok(Some((
        EntityId::from_bytes(*group)?,
        EntityId::from_bytes(person)?,
    )))
}

/// One page of at most `limit` delivery rows past `after`, or from the start,
/// each counted as read.
fn page(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    after: Option<&(EntityId, EntityId)>,
    limit: usize,
    count: &mut ScanCount,
) -> Result<Vec<((EntityId, EntityId), TaskAskSoftConfirmDelivery)>> {
    DELIVERIES
        .iter_range(
            &vault.store,
            txn,
            after.map_or(Unbounded, Excluded),
            Unbounded,
        )?
        .take(limit)
        .inspect(|_| count.row())
        .collect()
}

/// Inserted atomically with the immutable notice and answer.
pub(super) fn register(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    group: EntityId,
    person: EntityId,
) -> Result<()> {
    store(
        vault,
        txn,
        group,
        person,
        TaskAskSoftConfirmDelivery::PendingRoute,
    )
}

impl Vault {
    /// Typed status, including a held/denied send. No state means no notice.
    pub fn ask_soft_confirm_delivery(
        &self,
        group: EntityId,
        person: EntityId,
    ) -> Result<Option<TaskAskSoftConfirmDelivery>> {
        let txn = self.store.env.read_txn()?;
        DELIVERIES.get(&self.store, &txn, &(group, person))
    }

    /// Retries one committed notice. The same outbound idempotency key closes
    /// the crash gap after scheduling but before recording Scheduled.
    pub fn retry_ask_soft_confirm_delivery(
        &self,
        group: EntityId,
        person: EntityId,
    ) -> Result<TaskAskSoftConfirmDelivery> {
        let (notice, companion, current) = {
            let txn = self.store.env.read_txn()?;
            let current = DELIVERIES
                .get(&self.store, &txn, &(group, person))?
                .ok_or_else(super::ask_record::invalid)?;
            let notice = super::ask_soft_confirm::notice(self, &txn, group, person)?;
            if notice.is_none() {
                drop(txn);
                return self.with_write_txn_grouped(|txn| {
                    store(self, txn, group, person, TaskAskSoftConfirmDelivery::Closed)?;
                    Ok(TaskAskSoftConfirmDelivery::Closed)
                });
            }
            let notice = notice.ok_or_else(super::ask_record::invalid)?;
            let ask = super::ask_record::read_group(self, &txn, group)?
                .ok_or_else(super::ask_record::invalid)?;
            let super::TaskAskTarget::Guests(guests) =
                ask.effective.who.ok_or_else(super::ask_record::invalid)?
            else {
                return Err(super::ask_record::invalid());
            };
            let companion = guests
                .get(&person)
                .ok_or_else(super::ask_record::invalid)?
                .companion_ref;
            (notice, companion, current)
        };
        if matches!(
            current,
            TaskAskSoftConfirmDelivery::Scheduled | TaskAskSoftConfirmDelivery::Closed
        ) {
            return Ok(current);
        }
        let outcome = match crate::human_task::resolve_native_human_route(self, person) {
            Err(_) => TaskAskSoftConfirmDelivery::PendingRoute,
            Ok(route) => {
                let content = crate::EntityId::derive(
                    crate::entity_id::derived_domains::TASK_ASK_SOFT_CONFIRM,
                    &[group.as_bytes(), person.as_bytes()],
                )?;
                let idempotency =
                    format!("ask-soft-confirm/{}/{}", group.to_hex(), person.to_hex());
                let draft = crate::memory::OutboundDraftInput {
                    verb: "send".to_owned(),
                    channel: route.channel,
                    target: route.target,
                    on_behalf_of: None,
                    content_ref: Some(content.to_hex()),
                    idempotency_key: Some(idempotency.clone()),
                    dedupe_key: Some(idempotency),
                    trigger: "agent_immediate".to_owned(),
                    trigger_ref: notice.task_ref.to_hex(),
                    job_ref: None,
                    occurred_at: None,
                    mention: None,
                };
                match self
                    .memory(companion, EdgeActorClass::Agent)
                    .schedule_outbound(&draft)
                {
                    Ok(receipt)
                        if receipt.gate_outcome.as_deref() == Some("allow")
                            || receipt.outcome == "already_sent" =>
                    {
                        TaskAskSoftConfirmDelivery::Scheduled
                    }
                    Ok(receipt) if receipt.outcome == "suppressed" => {
                        TaskAskSoftConfirmDelivery::Failed
                    }
                    Ok(_) => TaskAskSoftConfirmDelivery::PendingGate,
                    Err(_) => TaskAskSoftConfirmDelivery::Failed,
                }
            }
        };
        self.with_write_txn_grouped(|txn| {
            let stored = DELIVERIES
                .get(&self.store, txn, &(group, person))?
                .ok_or_else(super::ask_record::invalid)?;
            if matches!(
                stored,
                TaskAskSoftConfirmDelivery::Scheduled | TaskAskSoftConfirmDelivery::Closed
            ) {
                return Ok(stored);
            }
            store(self, txn, group, person, outcome)?;
            Ok(outcome)
        })
    }

    /// Restart/wake repair: each call reads one page of at most `limit`
    /// delivery rows past the sweep's cursor, from the start again once it
    /// has passed the last, and attempts normal gated outbound scheduling
    /// for the pending ones. A settled row counts toward the page and moves
    /// the cursor too. A failure remains pending; the queue is never
    /// consumed without a scheduled send.
    pub fn retry_pending_ask_soft_confirms(&self, limit: usize) -> Result<usize> {
        if limit == 0 {
            return Ok(0);
        }
        let txn = self.store.env.read_txn()?;
        let resolved = crate::gate::resolve_policy_manifest(&self.store, &txn)?;
        let limit = resolved
            .ask_operational_policy()
            .ok_or_else(super::ask_record::invalid)?
            .retry_limit(limit);
        let after = cursor_after(&CURSOR.get(&self.store, &txn, &())?.unwrap_or_default())?;
        // Every row the page reads counts, settled ones included; the check
        // is kept by the vault's next write, never this read.
        let mut count = ScanCount::start(
            &self.store,
            &txn,
            EngineScan::AskSoftConfirmDeliveryRows,
            &[],
        )?;
        let mut rows = page(self, &txn, after.as_ref(), limit, &mut count)?;
        if rows.is_empty() && after.is_some() {
            rows = page(self, &txn, None, limit, &mut count)?;
        }
        drop(txn);
        count.finish(self);
        let Some(&((group, person), _)) = rows.last() else {
            return Ok(0);
        };
        let last = [group.as_bytes().as_slice(), person.as_bytes()].concat();
        let pending: Vec<_> = rows
            .into_iter()
            .filter(|(_, state)| {
                !matches!(
                    state,
                    TaskAskSoftConfirmDelivery::Scheduled | TaskAskSoftConfirmDelivery::Closed
                )
            })
            .map(|(key, _)| key)
            .collect();
        self.with_write_txn_grouped(|txn| {
            CURSOR.put(&self.store, txn, &(), &last)?;
            Ok(())
        })?;
        for (group, person) in &pending {
            self.retry_ask_soft_confirm_delivery(*group, *person)?;
        }
        Ok(pending.len())
    }
}
