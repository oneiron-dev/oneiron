//! Core half of `store::gate_decision::keys`: its store-layer items live in `oneiron_store::gate_decision::keys` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::gate_decision::keys::*;

use super::types::GateDecisionId;
use crate::error::{Error, Result};
use crate::store::{hashed_string_index_prefix, index_key_with_id, string_index_prefix};

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

/// The full raw key of one ledger row, for tests that plant rows directly;
/// production reads and writes go through the typed ledger table.
#[cfg(test)]
pub(crate) fn gate_decision_key(decision_id: GateDecisionId) -> Vec<u8> {
    let mut key = Vec::with_capacity(GATE_DECISION_KEY_PREFIX.len() + 16);
    key.extend_from_slice(GATE_DECISION_KEY_PREFIX);
    key.extend_from_slice(&decision_id.as_bytes());
    key
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

pub(in crate::store) fn gate_decision_claim_index_key(
    claim_id: &[u8; 16],
    decision_id: GateDecisionId,
) -> Vec<u8> {
    index_key_with_id(
        &gate_decision_claim_index_prefix(claim_id),
        &decision_id.as_bytes(),
    )
}
