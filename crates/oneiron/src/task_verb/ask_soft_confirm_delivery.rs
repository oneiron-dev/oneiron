//! Durable soft-confirm outbox, retried independently of answer replay.
use super::TaskAskSoftConfirmDelivery;
use crate::edge::EdgeActorClass;
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
                return self.with_write_txn(|txn| {
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
                let content = super::ask_record::derived_id(
                    b"oneiron.tasks.ask.soft_confirm.v1",
                    group,
                    person.as_bytes(),
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
        self.with_write_txn(|txn| {
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

    /// Restart/wake repair: each call walks a bounded page of durable pending
    /// rows and attempts normal gated outbound scheduling. A failure remains
    /// pending; the queue is never consumed without a scheduled send.
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
        let cursor = CURSOR.get(&self.store, &txn, &())?.unwrap_or_default();
        let mut rows = Vec::new();
        for row in DELIVERIES.iter_from(&self.store, &txn, &[])? {
            let ((group, person), state) = row?;
            if matches!(
                state,
                TaskAskSoftConfirmDelivery::Scheduled | TaskAskSoftConfirmDelivery::Closed
            ) {
                continue;
            }
            let key = [group.as_bytes().as_slice(), person.as_bytes()].concat();
            rows.push((key, group, person));
        }
        drop(txn);
        if rows.is_empty() {
            return Ok(0);
        }
        let start = rows
            .iter()
            .position(|(key, _, _)| key > &cursor)
            .unwrap_or(0);
        let pending: Vec<_> = rows
            .iter()
            .cycle()
            .skip(start)
            .take(limit.min(rows.len()))
            .map(|(key, group, person)| (key.clone(), *group, *person))
            .collect();
        if let Some((last, _, _)) = pending.last() {
            self.with_write_txn(|txn| {
                CURSOR.put(&self.store, txn, &(), last)?;
                Ok(())
            })?;
        }
        for (_, group, person) in &pending {
            self.retry_ask_soft_confirm_delivery(*group, *person)?;
        }
        Ok(pending.len())
    }
}
