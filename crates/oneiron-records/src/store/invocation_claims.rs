//! Moved from `crates/oneiron/src/store/invocation_claims.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::machine_destination::PeerMachine;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The serializable form of [`oneiron::runtime_hooks::verb::InvocationRelease`].
#[doc(hidden)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvocationClaimRelease {
    pub peer: StoredPeerMachine,
    /// JSON bytes of the answer before its first destination release.
    pub value: Vec<u8>,
    #[serde(default)]
    pub rows: Option<Vec<EntityId>>,
}

/// `PeerMachine` deliberately has no serde surface; the claim row owns this
/// stable manual encoding instead of widening authority's wire types.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StoredPeerMachine {
    Unknown,
    Proven { machine: EntityId, key: [u8; 32] },
}

impl From<PeerMachine> for StoredPeerMachine {
    fn from(peer: PeerMachine) -> Self {
        match peer {
            PeerMachine::Unknown => Self::Unknown,
            PeerMachine::Proven { machine, key } => Self::Proven { machine, key },
        }
    }
}
