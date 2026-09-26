//! Outbound gate bindings, durable send receipts, and the delivered-send
//! idempotency index.

use heed::{RoTxn, RwTxn};

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};

use super::*;

/// Additive durable connector-send receipt rows. This keyspace is independent
/// of the ABI-pinned Gate decision ledger and carries its own record version.
pub(crate) const SEND_RECEIPT_RECORD_VERSION: u8 = 0;

/// Additive delivered-send idempotency index. This is intentionally separate
/// from the attempt queue's lifecycle-scoped dedupe rows and from the
/// ABI-pinned Gate ledger.
const SEND_IDEMPOTENCY_INDEX_VERSION: u8 = 0;

const SEND_IDEMPOTENCY_HASH_DOMAIN: &[u8] = b"oneiron.send_idem.v0\0";

/// Maps a scheduled outbound attempt id to the gate surface its first dispatch
/// produced, so an idempotent replay can re-surface the original decision.
/// The value stays opaque `Vec<u8>`: this door only ever relays bytes a
/// caller outside `store` (`crate::memory::outbound::dedupe`) already encoded
/// with its own `serde_json`, so the table cannot own a codec that re-encodes.
const OUTBOUND_GATE_BINDING: SideTable<[u8; 16], Vec<u8>, Raw> =
    SideTable::new(&side_table::OUTBOUND_GATE_BINDING);

// The TASK summary is a point-read cache, not the receipt-family audit source.
// Value stays opaque `Vec<u8>` for the same reason as `OUTBOUND_GATE_BINDING`:
// `crate::receipt::send_receipt_txn` hands in bytes it already ran through
// `rmp_serde::to_vec_named`.
const SEND_RECEIPT: SideTable<EntityId, Vec<u8>, Raw> =
    SideTable::new(&side_table::SEND_RECEIPT_SUMMARY);

/// All outcomes append here. Compact fixed-width keys contain TASK + receipt-id
/// hash, so caller-supplied receipt ids cannot exceed LMDB's key-size limit.
/// See [`SEND_RECEIPT`] for why the value is opaque bytes.
pub(super) const SEND_RECEIPT_AUDIT: SideTable<(EntityId, [u8; 32]), Vec<u8>, Raw> =
    SideTable::new(&side_table::SEND_RECEIPT_ATTEMPT_AUDIT);

const SEND_IDEMPOTENCY: SideTable<[u8; 32], SendIdempotencyValue, Raw> =
    SideTable::new(&side_table::SEND_IDEMPOTENCY_INDEX);

/// The idempotency row's hand-rolled one-byte-version-then-id layout. Kept as
/// the module's own codec behind [`Raw`], reusing the existing
/// encode/decode functions verbatim.
struct SendIdempotencyValue(EntityId);

impl RawValue for SendIdempotencyValue {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(send_idempotency_value(&self.0).to_vec())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(Self(send_idempotency_task_ref_from_value(bytes)?))
    }
}

impl Store {
    /// Persists the opaque gate-surface bytes for a scheduled outbound attempt id
    /// (its own committed write txn). Overwrites any prior value for the id.
    pub(crate) fn put_outbound_gate_binding(
        &self,
        attempt_id: &[u8; 16],
        value: &[u8],
    ) -> Result<()> {
        let mut wtxn = self.env.write_txn()?;
        OUTBOUND_GATE_BINDING.put(self, &mut wtxn, attempt_id, &value.to_vec())?;
        wtxn.commit()?;
        Ok(())
    }

    /// Reads the persisted gate-surface bytes for a scheduled outbound attempt id.
    pub(crate) fn outbound_gate_binding(&self, attempt_id: &[u8; 16]) -> Result<Option<Vec<u8>>> {
        let rtxn = self.env.read_txn()?;
        OUTBOUND_GATE_BINDING.get(self, &rtxn, attempt_id)
    }

    /// Inserts a connector-send TASK summary, leaving an existing row intact.
    pub(crate) fn put_send_receipt_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        task_id: &EntityId,
        value: &[u8],
    ) -> Result<bool> {
        if SEND_RECEIPT.contains(self, &*wtxn, task_id)? {
            return Ok(false);
        }
        SEND_RECEIPT.put(self, wtxn, task_id, &value.to_vec())?;
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
        SEND_RECEIPT.put(self, wtxn, task_id, &value.to_vec())?;
        Ok(())
    }

    /// Reads one connector-send receipt inside a caller-owned transaction.
    pub(crate) fn get_send_receipt_by_task_in_txn(
        &self,
        txn: &RoTxn<'_>,
        task_id: &EntityId,
    ) -> Result<Option<Vec<u8>>> {
        SEND_RECEIPT.get(self, txn, task_id)
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
        if SEND_IDEMPOTENCY.get(self, &*wtxn, &key)?.is_some() {
            // Decoding above already re-runs the same validation the old
            // stand-alone `send_idempotency_task_ref_from_value` call did.
            return Ok(());
        }
        SEND_IDEMPOTENCY.put(self, wtxn, &key, &SendIdempotencyValue(*task_ref))?;
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
        Ok(SEND_IDEMPOTENCY
            .get(self, &rtxn, &key)?
            .map(|value| value.0))
    }

    /// Returns all append-only connector-send audit rows in TASK/hash order.
    /// TASK summaries are never projected again as duplicate family receipts.
    pub(crate) fn send_receipt_rows(&self) -> Result<Vec<([u8; 16], Vec<u8>)>> {
        let rtxn = self.env.read_txn()?;
        let mut rows = Vec::new();
        for row in SEND_RECEIPT_AUDIT.iter_from(self, &rtxn, &[])? {
            let ((task_id, _hash), value) = row?;
            rows.push((*task_id.as_bytes(), value));
        }
        Ok(rows)
    }
}

pub(super) fn send_receipt_audit_key(task_id: &EntityId, receipt_id: &str) -> (EntityId, [u8; 32]) {
    (*task_id, *blake3::hash(receipt_id.as_bytes()).as_bytes())
}

fn send_idempotency_key(actor_ref: &EntityId, idempotency_key: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SEND_IDEMPOTENCY_HASH_DOMAIN);
    hasher.update(actor_ref.as_bytes());
    hasher.update(&(idempotency_key.len() as u64).to_be_bytes());
    hasher.update(idempotency_key.as_bytes());
    *hasher.finalize().as_bytes()
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
