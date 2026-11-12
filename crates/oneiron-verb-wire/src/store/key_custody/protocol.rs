//! Moved from `crates/oneiron/src/store/key_custody/protocol.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::store::key_custody::protocol::drain::DrainAck;
pub use oneiron_store::key_custody::identity::CustodyNamespace;
pub use oneiron_store::key_custody::identity::CustodyVaultId;
use oneiron_store::key_custody::identity::hex_decode;
pub use oneiron_store::key_custody::log::CustodyEpoch;
pub use oneiron_store::key_custody::log::CustodyPosition;
pub use oneiron_store::key_custody::protocol::drain::DRAIN_VERSION;
pub use oneiron_store::key_custody::protocol::drain::DrainToken;
pub use oneiron_store::key_custody::protocol::drain::drain_placement;
pub use oneiron_store::key_custody::protocol::*;
use serde::Deserialize;
use serde::Serialize;

/// A custody position in an ack: vault (64 hex), namespace (32 hex), writer
/// epoch, log sequence number and tip (64 hex).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AckPosition {
    pub vault: String,
    pub namespace: String,
    pub epoch: u64,
    pub seq: u64,
    pub tip: String,
}

impl AckPosition {
    pub fn of(position: &CustodyPosition) -> Self {
        Self {
            vault: hex(position.vault.as_bytes()),
            namespace: hex(position.namespace.as_bytes()),
            epoch: position.epoch.get(),
            seq: position.seq,
            tip: hex(&position.tip),
        }
    }

    /// The position this names; `None` when a field does not parse.
    pub fn position(&self) -> Option<CustodyPosition> {
        Some(CustodyPosition {
            vault: CustodyVaultId::from_bytes(hex_decode(&self.vault)?.try_into().ok()?),
            namespace: CustodyNamespace::from_bytes(hex_decode(&self.namespace)?.try_into().ok()?),
            epoch: CustodyEpoch(self.epoch),
            seq: self.seq,
            tip: hex_decode(&self.tip)?.try_into().ok()?,
        })
    }
}
pub mod drain;
