//! Moved from `crates/oneiron/src/store/key_custody/protocol/drain.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::store::key_custody::protocol::AckPosition;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_store::key_custody::protocol::DeletionEvidence;
pub use oneiron_store::key_custody::protocol::drain::*;
use serde::Deserialize;
use serde::Serialize;

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

impl DrainAck {
    /// The MAC of every field but `mac` under `token`.
    pub fn mac_under(&self, token: &DrainToken) -> Result<[u8; 32]> {
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
