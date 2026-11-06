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

/// A member's acknowledgement of its drain: named MessagePack at rest, JSON
/// on a wire. Ids, positions and digests only; never a key, a head or a
/// credential.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DrainAck {
    pub version: u8,
    pub target_id: String,
    pub set_revision: u64,
    pub position: AckPosition,
    /// [`DrainTicket::operation_id`], 64 hex.
    pub operation_id: String,
    /// The inventory after the deletions: zero heads left.
    pub evidence: DeletionEvidence,
    /// [`drain_placement`] of the member, 64 hex: where it keeps the lineage.
    pub placement: String,
    /// [`drain_origin`] of the lineage, 64 hex.
    pub origin: String,
    /// The keyed BLAKE3 (64 hex) of every field above under the drain's
    /// token.
    pub mac: String,
}

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

impl DrainAck {
    /// The MAC of every field but `mac` under `token`.
    pub(in crate::store::key_custody) fn mac_under(&self, token: &DrainToken) -> Result<[u8; 32]> {
        let unsigned = Self {
            mac: String::new(),
            ..self.clone()
        };
        let bytes = rmp_serde::to_vec_named(&unsigned)
            .map_err(|_| Error::InvalidConfig("the custody drain ack does not encode".into()))?;
        let mut hasher = blake3::Hasher::new_keyed(token.expose());
        hasher.update(MAC_DOMAIN);
        hasher.update(&bytes);
        Ok(*hasher.finalize().as_bytes())
    }
}
