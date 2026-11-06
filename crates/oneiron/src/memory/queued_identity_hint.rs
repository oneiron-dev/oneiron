//! Durable identity-hint reads for the plain on-device Memory lane.

use serde::{Deserialize, Serialize};

use super::{Memory, MemoryError, MemoryResult};
use crate::authority::StoredReadProof;
use crate::claim::{ClaimReadStatus, ScopedRead};
use crate::edge::EdgeActorClass;
use crate::{EntityId, Vault};

/// Only the inputs of a plain on-device identity-hint read. Composed host
/// and room lanes are not represented by this record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OnDeviceIdentityHintReader {
    actor: EntityId,
    actor_class: u8,
    proof: StoredReadProof,
}

impl Memory<'_> {
    pub(crate) fn queued_identity_hint_reader(&self) -> Option<OnDeviceIdentityHintReader> {
        if self.host_action.is_some()
            || self.room_turn.is_some()
            || self.locality != crate::claim::CallerLocality::OnDevice
            || self.destination != crate::settings::ReadDestination::on_device()
        {
            return None;
        }
        let proof = self.read_proof.as_ref()?;
        Some(OnDeviceIdentityHintReader {
            actor: self.actor,
            actor_class: self.actor_class as u8,
            proof: StoredReadProof::of(proof),
        })
    }
}

impl OnDeviceIdentityHintReader {
    pub(crate) fn valid(&self) -> bool {
        EdgeActorClass::try_from_u8(self.actor_class).is_some()
    }

    pub(crate) fn open<'v>(&self, vault: &'v Vault) -> MemoryResult<Option<ScopedRead<'v>>> {
        let class = EdgeActorClass::try_from_u8(self.actor_class).ok_or_else(|| {
            MemoryError::from(crate::Error::CorruptedIndex("tagging hint actor class"))
        })?;
        let memory = vault
            .memory(self.actor, class)
            .with_read_proof(&self.proof.restore());
        let read = memory.read_lane_if_granted(ClaimReadStatus::Recorded)?;
        // This fresh plain lane has no audience, peer, session or owner
        // composition. Keep its actual native key, including its live guard.
        Ok(read.map(|read| {
            vault
                .scoped_read(read.actor_key().clone())
                .with_claim_status(ClaimReadStatus::Recorded)
        }))
    }
}
