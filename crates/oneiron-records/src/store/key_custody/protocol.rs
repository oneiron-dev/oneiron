//! Moved from `crates/oneiron/src/store/key_custody/protocol.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_store::key_custody::identity::CustodyNamespace;
pub use oneiron_store::key_custody::identity::CustodyVaultId;
use oneiron_store::key_custody::identity::hex_decode;
pub use oneiron_store::key_custody::log::CustodyEpoch;
pub use oneiron_store::key_custody::log::CustodyPosition;
pub use oneiron_store::key_custody::protocol::drain::DRAIN_VERSION;
pub use oneiron_store::key_custody::protocol::drain::DrainToken;
pub use oneiron_store::key_custody::protocol::drain::drain_placement;
pub use oneiron_store::key_custody::protocol::*;
pub use oneiron_verb_wire::store::key_custody::protocol::AckPosition;
pub use oneiron_verb_wire::store::key_custody::protocol::drain::DrainAck;
use serde::Deserialize;
use serde::Serialize;
use std::path::PathBuf;
use zeroize::Zeroizing;

/// One lineage a target holds: a vault's custody in one namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lineage {
    pub vault: CustodyVaultId,
    pub namespace: CustodyNamespace,
}

impl Lineage {
    pub fn of(position: &CustodyPosition) -> Self {
        Self {
            vault: position.vault,
            namespace: position.namespace,
        }
    }

    /// The lineage a wire names: vault (64 hex) and namespace (32 hex).
    pub fn from_hex(vault: &str, namespace: &str) -> Option<Self> {
        Some(Self {
            vault: CustodyVaultId::from_bytes(hex_decode(vault)?.try_into().ok()?),
            namespace: CustodyNamespace::from_bytes(hex_decode(namespace)?.try_into().ok()?),
        })
    }

    /// Its vault and namespace in hex, as a wire names them.
    pub fn to_hex(&self) -> (String, String) {
        (hex(self.vault.as_bytes()), hex(self.namespace.as_bytes()))
    }
}

/// The publish-and-delete-superseded operation of the head `head_object_id`
/// at `position`.
pub fn operation_id(position: &CustodyPosition, head_object_id: &[u8; 32]) -> [u8; 32] {
    let mut material = position.to_bytes().to_vec();
    material.extend_from_slice(head_object_id);
    blake3::derive_key(OPERATION_CONTEXT, &material)
}

/// A target's durable acknowledgement of one batch: named MessagePack
/// (`rmp_serde::to_vec_named`) at rest, JSON on a wire. Ids, positions and
/// digests only; never a key, a wrap, head bytes or a credential.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AckRecord {
    pub version: u8,
    pub target_id: String,
    pub set_revision: u64,
    pub position: AckPosition,
    /// The BLAKE3 (64 hex) of the head the target now holds as its latest.
    pub head_object_id: String,
    pub operation: AckOperation,
    /// [`CustodyBatch::operation_id`], 64 hex.
    pub operation_id: String,
    pub evidence: DeletionEvidence,
    /// Who attests: `this-install` for a local folder, the residence home's
    /// machine id (hex) as its socket proved it, a hosted adapter's own id.
    pub attester: String,
    /// Unix seconds the target persisted the ack.
    pub acked_at: u64,
}
