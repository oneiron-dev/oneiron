//! The subject of an authority entry's erasable overlay (census L5-22): the
//! one person, actor or device whose erase retires the key that seals the
//! entry's overlay record.
//!
//! The subject is read from the op's scaffold, never from an overlay leaf,
//! so every machine that holds the row names the same subject without its
//! overlay.

use oneiron_contracts::EntityId;

use crate::error::{Error, RecordError, Result};

use super::*;

/// The context a device key derives its overlay subject under.
const DEVICE_SUBJECT_CONTEXT: &str = "oneiron/authority-overlay/device-subject/v1";

/// The context a slip holder ref that is no entity id derives its overlay
/// subject under.
const HOLDER_SUBJECT_CONTEXT: &str = "oneiron/authority-overlay/holder-subject/v1";

/// The overlay subject of a device authority whose attestation evidence the
/// overlay holds: derived from the device's key, the one thing that names
/// the device across every row about it.
///
/// # Errors
/// A derived id in the reserved sentinel range.
pub fn authority_overlay_device_subject(key: &AuthorityKey) -> Result<EntityId> {
    let mut material = Vec::with_capacity(34);
    match key {
        AuthorityKey::Ed25519(bytes) => {
            material.push(1);
            material.extend_from_slice(bytes);
        }
        AuthorityKey::P256(bytes) => {
            material.push(2);
            material.extend_from_slice(bytes);
        }
    }
    derived_subject(DEVICE_SUBJECT_CONTEXT, &material)
}

/// The overlay subject of a slip whose holder ref is no entity id and that
/// names no minting member: derived from the holder ref.
///
/// # Errors
/// A derived id in the reserved sentinel range.
pub fn authority_overlay_holder_subject(holder_ref: &str) -> Result<EntityId> {
    derived_subject(HOLDER_SUBJECT_CONTEXT, holder_ref.as_bytes())
}

fn derived_subject(context: &str, material: &[u8]) -> Result<EntityId> {
    let derived = blake3::derive_key(context, material);
    let mut id = [0u8; 16];
    id.copy_from_slice(&derived[..16]);
    EntityId::from_bytes(id)
}

/// The subject whose erasable key seals `op`'s overlay record:
/// - SlipMint: its holder when `holder_ref` is an entity id's canonical hex,
///   else its minting member, else the holder ref's derived subject;
/// - AgentGrantAct Mint: the member granted;
/// - OwnerWorkResult: the executor; ResidenceResult: the machine;
/// - OwnerKeyEnroll: the owner whose act enrolls the key;
/// - Genesis, EnrollDevice, RotateKey, ReRoot: the device's derived subject.
///
/// # Errors
/// An op of a kind that holds no overlay leaf (it has no overlay record), or
/// a derived id in the reserved sentinel range.
pub fn authority_overlay_subject(op: &AuthorityOp) -> Result<EntityId> {
    match op {
        AuthorityOp::SlipMint(mint) => {
            let holder = &mint.claims.holder_ref;
            match EntityId::from_hex(holder) {
                Ok(id) if id.to_hex() == *holder => Ok(id),
                _ => match mint.minting_member {
                    Some(member) => Ok(member),
                    None => authority_overlay_holder_subject(holder),
                },
            }
        }
        AuthorityOp::AgentGrantAct(record) => match &record.change {
            AgentGrantChange::Mint { member, .. } => Ok(*member),
            AgentGrantChange::Revoke { .. } => Err(no_overlay_subject()),
        },
        AuthorityOp::OwnerWorkResult(result) => Ok(result.executor),
        AuthorityOp::ResidenceResult(result) => Ok(result.machine),
        AuthorityOp::OwnerKeyEnroll(enroll) => Ok(enroll.act.owner),
        AuthorityOp::Genesis { device, .. } | AuthorityOp::EnrollDevice { device } => {
            authority_overlay_device_subject(&device.key)
        }
        AuthorityOp::RotateKey { new_device, .. } | AuthorityOp::ReRoot { new_device } => {
            authority_overlay_device_subject(&new_device.key)
        }
        _ => Err(no_overlay_subject()),
    }
}

fn no_overlay_subject() -> Error {
    Error::Record(RecordError::InvalidAuthorityLogBody(
        "authority op kind holds no overlay leaf",
    ))
}
