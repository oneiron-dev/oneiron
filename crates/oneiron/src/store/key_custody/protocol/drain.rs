//! The custody member drain's contract (FIX 5843, ruled 10-20): how the
//! owner takes a member out of the required set. Never a forced unpin.
//!
//! The owner's begin fences the member ([`DrainTicket`]): no head goes to it
//! and no publication ack from it is accepted any more. The member then
//! deletes every head, version, stage and alias it holds of the lineage,
//! lists it again, and answers a [`DrainAck`] that names exactly the drain
//! (member, set revision, position, operation), zero heads left, where it
//! keeps the lineage and whose lineage it is, MACed with the drain's
//! generation token, never with attester text. The owner's commit takes
//! the member out of the set at the next revision, with its history row and
//! evidence, in one write. The keyless log stays, and a member drained once
//! comes back only by an explicit re-enrolment at a newer revision.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

use super::super::identity::encode_native_path;
use super::{AckPosition, CustodyPosition, DeletionEvidence, TargetId, TargetSpec, hex};

/// The drain grammar's version.
pub const DRAIN_VERSION: u8 = 1;
const OPERATION_CONTEXT: &str = "oneiron/custody-drain/operation/v1";
const PLACEMENT_CONTEXT: &str = "oneiron/custody-drain/placement/v1";
const ORIGIN_CONTEXT: &str = "oneiron/custody-drain/origin/v1";
const MAC_DOMAIN: &[u8] = b"oneiron/custody-drain/ack-mac/v1";

/// One drain's generation token: the secret its member's ack is MACed
/// with, sent to the member on its own authenticated channel. A retry of
/// the same drain keeps it; a new drain of the member gets a new one. It
/// prints redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct DrainToken(Zeroizing<[u8; 32]>);

impl DrainToken {
    /// The token whose 32 bytes are `bytes`.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Its 32 bytes, for the member's channel.
    #[must_use]
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for DrainToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DrainToken(..)")
    }
}

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

/// Where `spec`'s member keeps the lineage: its kind, its id and, for a
/// folder, its absolute folder's native bytes. A member answers with its
/// own; the owner's commit checks it against the set's record of it.
#[must_use]
pub fn drain_placement(spec: &TargetSpec) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(PLACEMENT_CONTEXT);
    let kind = spec.kind().name();
    hasher.update(&(kind.len() as u64).to_be_bytes());
    hasher.update(kind.as_bytes());
    let id = spec.id().as_str();
    hasher.update(&(id.len() as u64).to_be_bytes());
    hasher.update(id.as_bytes());
    if let Some(folder) = spec
        .folder_path()
        .and_then(|folder| std::path::absolute(folder).ok())
        .and_then(|folder| encode_native_path(&folder))
    {
        hasher.update(&folder);
    }
    *hasher.finalize().as_bytes()
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
