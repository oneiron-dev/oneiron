//! Gate-decision ledger key prefixes, key constructors, and the id successor.

use crate::error::{Error, Result};
use crate::store::{index_key_with_id, string_index_prefix};

use super::types::GateDecisionId;

pub(in crate::store) const GATE_DECISION_KEY_PREFIX: &[u8] = b"gate_decision:v0:";

/// Pre-commit crash-recovery sidecar for a deletion authority record. This is
/// not the Gate decision ledger: TXN3 consumes it with
/// `append_gate_decision_in_txn` in the active-store purge transaction.
const PENDING_DELETION_GATE_DECISION_KEY_PREFIX: &[u8] = b"gate_delete_pending:v0:";

/// Durable proof that a locally-authored deletion tombstone requires an
/// authority sidecar before recovery may purge its target. Kept separate
/// from the sidecar so corruption/loss of the latter is detectable instead
/// of being mistaken for a legitimate sidecar-free remote tombstone.
const DELETION_GATE_REQUIRED_KEY_PREFIX: &[u8] = b"gate_delete_required:v0:";

pub(in crate::store) const GATE_DECISION_GRANT_REF_INDEX_PREFIX: &[u8] =
    b"gate_decision:grant_ref_index:v1:";

/// ERASE-A (ONE-1637) claim-keyed secondary index over the Gate decision
/// ledger: `prefix ‖ claim_id(16B) ‖ decision_id(16B)`, empty value.
///
/// ACCELERATION ONLY. Erase-completeness verification must never consult it —
/// an index cannot vouch for the completeness of the erase it accelerated (see
/// [`Store::verify_claim_erasure_by_scan_in_txn`]).
///
/// INVARIANT: every mutation of a `gate_decision:v0:` row MUST route through
/// `append_gate_decision_in_txn` (the sole write route) or
/// `delete_gate_decision_record_in_txn` (the sole primary-delete route, which
/// drops this index row and the grant-ref index row in the same transaction).
/// A future deleter loads/decodes the record and calls the latter; a raw
/// `vault_meta.delete` of a primary key orphans both indexes. The
/// `gate_delete_pending:v0:` recovery sidecar is a distinct keyspace and is not
/// covered by this rule.
pub(in crate::store) const GATE_DECISION_CLAIM_INDEX_PREFIX: &[u8] = b"gate_decision_by_claim:v0:";

/// Durable proof that every pre-existing ledger row is claim-indexed. While
/// ABSENT, per-claim discovery falls back to a full keyspace scan; erase is
/// never refused during backfill.
pub(in crate::store) const GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_KEY: &[u8] =
    b"gate_decision_by_claim_backfill_complete";

/// Only accepted value byte for the backfill-complete flag row.
pub(in crate::store) const GATE_DECISION_CLAIM_INDEX_BACKFILL_COMPLETE_VALUE: [u8; 1] = [1];

pub(in crate::store) const ATTEMPT_RUN_INDEX_PREFIX: &[u8] = b"job:run_index:v1:";

pub(in crate::store) fn gate_decision_key(decision_id: GateDecisionId) -> Vec<u8> {
    let mut key = Vec::with_capacity(GATE_DECISION_KEY_PREFIX.len() + 16);
    key.extend_from_slice(GATE_DECISION_KEY_PREFIX);
    key.extend_from_slice(&decision_id.as_bytes());
    key
}

pub(super) fn pending_deletion_gate_decision_key(decision_id: GateDecisionId) -> Vec<u8> {
    let mut key = Vec::with_capacity(PENDING_DELETION_GATE_DECISION_KEY_PREFIX.len() + 16);
    key.extend_from_slice(PENDING_DELETION_GATE_DECISION_KEY_PREFIX);
    key.extend_from_slice(&decision_id.as_bytes());
    key
}

pub(super) fn deletion_gate_required_key(decision_id: GateDecisionId) -> Vec<u8> {
    let mut key = Vec::with_capacity(DELETION_GATE_REQUIRED_KEY_PREFIX.len() + 16);
    key.extend_from_slice(DELETION_GATE_REQUIRED_KEY_PREFIX);
    key.extend_from_slice(&decision_id.as_bytes());
    key
}

pub(super) fn gate_decision_id_from_key(key: &[u8]) -> Result<GateDecisionId> {
    let bytes = key
        .strip_prefix(GATE_DECISION_KEY_PREFIX)
        .ok_or(Error::CorruptedIndex("gate decision ledger"))?;
    let bytes: [u8; 16] = bytes
        .try_into()
        .map_err(|_| Error::CorruptedIndex("gate decision ledger"))?;
    Ok(GateDecisionId { bytes })
}

pub(in crate::store) fn gate_decision_upper_bound() -> Vec<u8> {
    let mut key = Vec::from(GATE_DECISION_KEY_PREFIX);
    let last = key
        .last_mut()
        .expect("gate decision key prefix must be non-empty");
    *last = last
        .checked_add(1)
        .expect("gate decision key prefix upper bound must not overflow");
    key
}

/// Returns the next lexicographic UUIDv7 while retaining RFC version and
/// variant bits. Exhausting random bits carries into the logical timestamp.
pub(super) fn logical_uuid_v7_successor(id: GateDecisionId) -> Result<GateDecisionId> {
    let mut bytes = id.as_bytes();
    if bytes[6] >> 4 != 0x7 || bytes[8] >> 6 != 0b10 {
        return Err(Error::InvariantViolation("gate decision id is not UUIDv7"));
    }
    for index in [15_usize, 14, 13, 12, 11, 10, 9] {
        if bytes[index] != u8::MAX {
            bytes[index] += 1;
            return Ok(GateDecisionId::from_bytes(bytes));
        }
        bytes[index] = 0;
    }
    if bytes[8] & 0x3f != 0x3f {
        bytes[8] += 1;
        return Ok(GateDecisionId::from_bytes(bytes));
    }
    bytes[8] = 0x80;
    if bytes[7] != u8::MAX {
        bytes[7] += 1;
        return Ok(GateDecisionId::from_bytes(bytes));
    }
    bytes[7] = 0;
    if bytes[6] & 0x0f != 0x0f {
        bytes[6] += 1;
        return Ok(GateDecisionId::from_bytes(bytes));
    }
    bytes[6] = 0x70;
    for index in (0..6).rev() {
        if bytes[index] != u8::MAX {
            bytes[index] += 1;
            return Ok(GateDecisionId::from_bytes(bytes));
        }
        bytes[index] = 0;
    }
    Err(Error::InvariantViolation(
        "UUIDv7 logical timestamp exhausted",
    ))
}

pub(super) fn gate_decision_grant_ref_index_prefix(grant_ref: &str) -> Vec<u8> {
    string_index_prefix(GATE_DECISION_GRANT_REF_INDEX_PREFIX, grant_ref)
}

pub(in crate::store) fn gate_decision_grant_ref_index_key(
    grant_ref: &str,
    decision_id: GateDecisionId,
) -> Vec<u8> {
    index_key_with_id(
        &gate_decision_grant_ref_index_prefix(grant_ref),
        &decision_id.as_bytes(),
    )
}

/// Both key components are fixed 16-byte ids, so the index needs no
/// `string_index_prefix` length header to stay unambiguous.
pub(in crate::store) fn gate_decision_claim_index_prefix(claim_id: &[u8; 16]) -> Vec<u8> {
    index_key_with_id(GATE_DECISION_CLAIM_INDEX_PREFIX, claim_id)
}

pub(in crate::store) fn gate_decision_claim_index_key(
    claim_id: &[u8; 16],
    decision_id: GateDecisionId,
) -> Vec<u8> {
    index_key_with_id(
        &gate_decision_claim_index_prefix(claim_id),
        &decision_id.as_bytes(),
    )
}

pub(super) fn attempt_run_index_prefix(run_id: &str) -> Vec<u8> {
    string_index_prefix(ATTEMPT_RUN_INDEX_PREFIX, run_id)
}

pub(super) fn attempt_run_index_key(run_id: &str, attempt_id: &[u8; 16]) -> Vec<u8> {
    index_key_with_id(&attempt_run_index_prefix(run_id), attempt_id)
}
