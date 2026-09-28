//! Durable soft-confirm outbox, retried independently of answer replay.
use super::TaskAskSoftConfirmDelivery;
use crate::edge::EdgeActorClass;
use crate::{EntityId, Result, Vault};

const PREFIX: &[u8] = b"tasks.ask.soft_confirm.delivery.v1/";
const CURSOR: &[u8] = b"tasks.ask.soft_confirm.delivery_cursor.v1";

fn key(group: EntityId, person: EntityId) -> Vec<u8> {
    let mut key = PREFIX.to_vec();
    key.extend_from_slice(group.as_bytes());
    key.extend_from_slice(person.as_bytes());
    key
}

fn decode(bytes: &[u8]) -> Result<TaskAskSoftConfirmDelivery> {
    rmp_serde::from_slice(bytes).map_err(|_| super::ask_record::invalid())
}

fn store(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    group: EntityId,
    person: EntityId,
    state: TaskAskSoftConfirmDelivery,
) -> Result<()> {
    vault.store.vault_meta.put(
        txn,
        &key(group, person),
        &rmp_serde::to_vec_named(&state).map_err(|_| super::ask_record::invalid())?,
    )?;
    Ok(())
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
        self.store
            .vault_meta
            .get(&txn, &key(group, person))?
            .map(|data| decode(&data))
            .transpose()
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
            let current = self
                .store
                .vault_meta
                .get(&txn, &key(group, person))?
                .ok_or_else(super::ask_record::invalid)
                .and_then(|data| decode(&data))?;
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
            let stored = self
                .store
                .vault_meta
                .get(&*txn, &key(group, person))?
                .ok_or_else(super::ask_record::invalid)
                .and_then(|data| decode(&data))?;
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
        let cursor = self
            .store
            .vault_meta
            .get(&txn, CURSOR)?
            .map(|bytes| bytes.to_vec())
            .unwrap_or_default();
        let mut rows = Vec::new();
        for row in self.store.vault_meta.prefix_iter(&txn, PREFIX)? {
            let (key, value) = row?;
            if matches!(
                decode(&value)?,
                TaskAskSoftConfirmDelivery::Scheduled | TaskAskSoftConfirmDelivery::Closed
            ) {
                continue;
            }
            let bytes = key
                .get(PREFIX.len()..)
                .ok_or_else(super::ask_record::invalid)?;
            if bytes.len() != 32 {
                return Err(super::ask_record::invalid());
            }
            rows.push((
                bytes.to_vec(),
                EntityId::from_bytes(
                    bytes[..16]
                        .try_into()
                        .map_err(|_| super::ask_record::invalid())?,
                )?,
                EntityId::from_bytes(
                    bytes[16..]
                        .try_into()
                        .map_err(|_| super::ask_record::invalid())?,
                )?,
            ));
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
                self.store.vault_meta.put(txn, CURSOR, last)?;
                Ok(())
            })?;
        }
        for (_, group, person) in &pending {
            self.retry_ask_soft_confirm_delivery(*group, *person)?;
        }
        Ok(pending.len())
    }
}
