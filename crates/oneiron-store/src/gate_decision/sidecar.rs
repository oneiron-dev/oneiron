//! Pending-deletion recovery sidecar Store methods and codec.

use heed::{RoTxn, RwTxn};

use crate::side_table::codec::CodecError;
use crate::side_table::codec::RawValue;
use oneiron_base::error::Error;
use oneiron_base::error::Result;

use crate::gate_decision::types::GateDecisionId;
use crate::gate_decision::types::PENDING_DELETION_GATE_DECISION_VERSION;

/// The deletion-gate-required marker's hand-rolled `version ‖
/// tombstone_reason ‖ target(16)` layout. Kept as the module's own codec
/// behind [`Raw`], reusing the existing encode/decode functions verbatim.
pub struct DeletionGateRequired {
    pub target: [u8; 16],
    pub tombstone_reason: u8,
}

impl RawValue for DeletionGateRequired {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(encode_deletion_gate_required(&self.target, self.tombstone_reason).to_vec())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let (target, tombstone_reason) = decode_deletion_gate_required(bytes)?;
        Ok(Self {
            target,
            tombstone_reason,
        })
    }
}

fn encode_deletion_gate_required(target: &[u8; 16], tombstone_reason: u8) -> [u8; 18] {
    let mut value = [0_u8; 18];
    value[0] = PENDING_DELETION_GATE_DECISION_VERSION;
    value[1] = tombstone_reason;
    value[2..].copy_from_slice(target);
    value
}

fn decode_deletion_gate_required(raw: &[u8]) -> Result<([u8; 16], u8)> {
    let raw: [u8; 18] = raw
        .try_into()
        .map_err(|_| Error::CorruptedIndex("deletion gate required marker"))?;
    if raw[0] != PENDING_DELETION_GATE_DECISION_VERSION || !matches!(raw[1], 1..=4) {
        return Err(Error::CorruptedIndex("deletion gate required marker"));
    }
    let mut target = [0_u8; 16];
    target.copy_from_slice(&raw[2..]);
    Ok((target, raw[1]))
}
