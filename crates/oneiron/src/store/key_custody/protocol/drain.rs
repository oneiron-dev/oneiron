//! Core half of `store::key_custody::protocol::drain`: its store-layer items live in `oneiron_store::key_custody::protocol::drain` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::key_custody::protocol::drain::*;

use super::super::identity::encode_native_path;
use super::{AckPosition, CustodyPosition, DeletionEvidence, TargetId, TargetSpec, hex};
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// The owner's begun drain of one member: what the member's ack must name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DrainTicket {
    pub target_id: TargetId,
    /// The set revision the member is drained out of.
    pub set_revision: u64,
    /// The local log position when the drain began.
    pub position: CustodyPosition,
    /// [`drain_operation_id`] of the three above.
    pub operation_id: [u8; 32],
    pub token: DrainToken,
}

#[doc(hidden)]
pub use oneiron_verb_wire::store::key_custody::protocol::drain::DrainAck;

/// The drain operation of member `target` out of set revision `revision`
/// at `position`.
#[must_use]
pub fn drain_operation_id(
    target: &TargetId,
    revision: u64,
    position: &CustodyPosition,
) -> [u8; 32] {
    let mut material = position.to_bytes().to_vec();
    material.extend_from_slice(&revision.to_be_bytes());
    material.extend_from_slice(target.as_str().as_bytes());
    blake3::derive_key(OPERATION_CONTEXT, &material)
}

/// Whose lineage a drain empties: its vault and namespace.
#[must_use]
pub fn drain_origin(position: &CustodyPosition) -> [u8; 32] {
    let mut material = position.vault.as_bytes().to_vec();
    material.extend_from_slice(position.namespace.as_bytes());
    blake3::derive_key(ORIGIN_CONTEXT, &material)
}

impl DrainTicket {
    /// The member's ack of this drain, once it deleted every head, version,
    /// stage and alias of the lineage it held at `spec`'s placement and
    /// listed it again: `evidence` names what it removed and zero heads
    /// left.
    ///
    /// # Errors
    /// The ack does not encode.
    pub fn ack(&self, spec: &TargetSpec, evidence: DeletionEvidence) -> Result<DrainAck> {
        let mut ack = DrainAck {
            version: DRAIN_VERSION,
            target_id: self.target_id.as_str().to_owned(),
            set_revision: self.set_revision,
            position: AckPosition::of(&self.position),
            operation_id: hex(&self.operation_id),
            evidence,
            placement: hex(&drain_placement(spec)),
            origin: hex(&drain_origin(&self.position)),
            mac: String::new(),
        };
        ack.mac = hex(&ack.mac_under(&self.token)?);
        Ok(ack)
    }
}
