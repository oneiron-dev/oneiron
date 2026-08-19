//! Outbound gate bindings, durable send receipts, and the delivered-send
//! idempotency index.

use std::str;

use heed::{RoTxn, RwTxn};

use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::*;

/// Maps a scheduled outbound attempt id to the gate surface its first dispatch
/// produced, so an idempotent replay can re-surface the original decision.
const OUTBOUND_GATE_BINDING_KEY_PREFIX: &[u8] = b"outbound_gate_binding:v0:";

/// Additive durable connector-send receipt rows. This keyspace is independent
/// of the ABI-pinned Gate decision ledger and carries its own record version.
pub(crate) const SEND_RECEIPT_RECORD_VERSION: u8 = 0;

const SEND_RECEIPT_KEY_PREFIX: &[u8] = b"send_receipt:v0:";

/// Additive delivered-send idempotency index. This is intentionally separate
/// from the attempt queue's lifecycle-scoped dedupe rows and from the
/// ABI-pinned Gate ledger.
pub(crate) const SEND_IDEMPOTENCY_INDEX_VERSION: u8 = 0;

const SEND_IDEMPOTENCY_KEY_PREFIX: &[u8] = b"send_idem:v0:";

const SEND_IDEMPOTENCY_HASH_DOMAIN: &[u8] = b"oneiron.send_idem.v0\0";

impl Store {
    /// Persists the opaque gate-surface bytes for a scheduled outbound attempt id
    /// (its own committed write txn). Overwrites any prior value for the id.
    pub(crate) fn put_outbound_gate_binding(
        &self,
        attempt_id: &[u8; 16],
        value: &[u8],
    ) -> Result<()> {
        let key = outbound_gate_binding_key(attempt_id);
        let mut wtxn = self.env.write_txn()?;
        self.vault_meta.put(&mut wtxn, &key, value)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Reads the persisted gate-surface bytes for a scheduled outbound attempt id.
    pub(crate) fn outbound_gate_binding(&self, attempt_id: &[u8; 16]) -> Result<Option<Vec<u8>>> {
        let key = outbound_gate_binding_key(attempt_id);
        let rtxn = self.env.read_txn()?;
        Ok(self
            .vault_meta
            .get(&rtxn, &key)?
            .map(|value| value.to_vec()))
    }

    /// Inserts one connector-send receipt keyed by its originating TASK.
    /// Existing rows are left intact so executor retries cannot duplicate the
    /// transport record.
    pub(crate) fn put_send_receipt_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        task_id: &EntityId,
        value: &[u8],
    ) -> Result<bool> {
        let key = send_receipt_key(task_id);
        if self.vault_meta.get(&*wtxn, &key)?.is_some() {
            return Ok(false);
        }
        self.vault_meta.put(wtxn, &key, value)?;
        Ok(true)
    }

    /// Replaces one connector-send receipt row. Receipt semantics decide
    /// whether replacement is legal before calling this storage-only helper.
    pub(crate) fn set_send_receipt_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        task_id: &EntityId,
        value: &[u8],
    ) -> Result<()> {
        self.vault_meta
            .put(wtxn, &send_receipt_key(task_id), value)?;
        Ok(())
    }

    /// Reads one connector-send receipt inside a caller-owned transaction.
    pub(crate) fn get_send_receipt_by_task_in_txn(
        &self,
        txn: &RoTxn<'_>,
        task_id: &EntityId,
    ) -> Result<Option<Vec<u8>>> {
        Ok(self
            .vault_meta
            .get(txn, &send_receipt_key(task_id))?
            .map(std::borrow::Cow::into_owned))
    }

    /// Reads one connector-send receipt directly by its originating TASK.
    pub(crate) fn get_send_receipt_by_task(&self, task_id: &EntityId) -> Result<Option<Vec<u8>>> {
        let rtxn = self.env.read_txn()?;
        self.get_send_receipt_by_task_in_txn(&rtxn, task_id)
    }

    /// Records the first delivered TASK for one actor-scoped client
    /// idempotency key. Later deliveries keep the original winner.
    pub(crate) fn put_delivered_send_idempotency_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        actor_ref: &EntityId,
        idempotency_key: &str,
        task_ref: &EntityId,
    ) -> Result<()> {
        let key = send_idempotency_key(actor_ref, idempotency_key);
        if let Some(existing) = self.vault_meta.get(&*wtxn, &key)? {
            send_idempotency_task_ref_from_value(&existing)?;
            return Ok(());
        }
        let value = send_idempotency_value(task_ref);
        self.vault_meta.put(wtxn, &key, &value)?;
        Ok(())
    }

    /// Point-reads the delivered TASK for one actor-scoped client
    /// idempotency key.
    pub(crate) fn get_delivered_send_task_by_idempotency(
        &self,
        actor_ref: &EntityId,
        idempotency_key: &str,
    ) -> Result<Option<EntityId>> {
        let key = send_idempotency_key(actor_ref, idempotency_key);
        let rtxn = self.env.read_txn()?;
        self.vault_meta
            .get(&rtxn, &key)?
            .map(|value| send_idempotency_task_ref_from_value(&value))
            .transpose()
    }

    /// Returns all opaque connector-send receipt rows in TASK-id order.
    pub(crate) fn send_receipt_rows(&self) -> Result<Vec<([u8; 16], Vec<u8>)>> {
        let rtxn = self.env.read_txn()?;
        let mut rows = Vec::new();
        for row in self
            .vault_meta
            .prefix_iter(&rtxn, SEND_RECEIPT_KEY_PREFIX)?
        {
            let (key, value) = row?;
            rows.push((send_receipt_task_id_from_key(&key)?, value.into_owned()));
        }
        Ok(rows)
    }
}

fn outbound_gate_binding_key(attempt_id: &[u8; 16]) -> Vec<u8> {
    let mut key = Vec::with_capacity(OUTBOUND_GATE_BINDING_KEY_PREFIX.len() + 16);
    key.extend_from_slice(OUTBOUND_GATE_BINDING_KEY_PREFIX);
    key.extend_from_slice(attempt_id);
    key
}

fn send_receipt_key(task_id: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(SEND_RECEIPT_KEY_PREFIX.len() + 16);
    key.extend_from_slice(SEND_RECEIPT_KEY_PREFIX);
    key.extend_from_slice(task_id.as_bytes());
    key
}

fn send_receipt_task_id_from_key(key: &[u8]) -> Result<[u8; 16]> {
    key.strip_prefix(SEND_RECEIPT_KEY_PREFIX)
        .ok_or(Error::CorruptedIndex("send receipt ledger"))?
        .try_into()
        .map_err(|_| Error::CorruptedIndex("send receipt ledger"))
}

fn send_idempotency_key(actor_ref: &EntityId, idempotency_key: &str) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SEND_IDEMPOTENCY_HASH_DOMAIN);
    hasher.update(actor_ref.as_bytes());
    hasher.update(&(idempotency_key.len() as u64).to_be_bytes());
    hasher.update(idempotency_key.as_bytes());
    let hash = hasher.finalize();
    let mut key = Vec::with_capacity(SEND_IDEMPOTENCY_KEY_PREFIX.len() + hash.as_bytes().len());
    key.extend_from_slice(SEND_IDEMPOTENCY_KEY_PREFIX);
    key.extend_from_slice(hash.as_bytes());
    key
}

fn send_idempotency_value(task_ref: &EntityId) -> [u8; 17] {
    let mut value = [0_u8; 17];
    value[0] = SEND_IDEMPOTENCY_INDEX_VERSION;
    value[1..].copy_from_slice(task_ref.as_bytes());
    value
}

fn send_idempotency_task_ref_from_value(value: &[u8]) -> Result<EntityId> {
    if value.len() != 17 || value[0] != SEND_IDEMPOTENCY_INDEX_VERSION {
        return Err(Error::CorruptedIndex("send idempotency index"));
    }
    EntityId::from_bytes(
        value[1..]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("send idempotency index"))?,
    )
    .map_err(|_| Error::CorruptedIndex("send idempotency index"))
}
