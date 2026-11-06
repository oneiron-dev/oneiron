//! Durable identity-hint reads for the plain on-device Memory lane.

use serde::{Deserialize, Serialize};

use super::{Memory, MemoryError, MemoryResult};
use crate::authority::StoredReadProof;
use crate::claim::{ClaimReadStatus, ScopedRead, ScopedReadActorKey};
use crate::edge::EdgeActorClass;
use crate::{EntityId, Vault};

/// Only the inputs of a plain on-device identity-hint read. Composed host
/// and room lanes are not represented by this record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OnDeviceIdentityHintReader {
    actor: EntityId,
    actor_class: u8,
    authority: QueuedIdentityHintAuthority,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum QueuedIdentityHintAuthority {
    Credential(StoredReadProof),
    Uncredentialed,
    UncredentialedOwner,
}

impl Memory<'_> {
    pub(crate) fn queued_identity_hint_reader(
        &self,
        original_key: Option<&ScopedReadActorKey>,
    ) -> Option<OnDeviceIdentityHintReader> {
        if self.host_action.is_some()
            || self.room_turn.is_some()
            || self.locality != crate::claim::CallerLocality::OnDevice
            || self.destination != crate::settings::ReadDestination::on_device()
        {
            return None;
        }
        let authority = match &self.read_proof {
            Some(proof) => QueuedIdentityHintAuthority::Credential(StoredReadProof::of(proof)),
            None if original_key.is_some_and(ScopedReadActorKey::reads_as_vault_owner) => {
                QueuedIdentityHintAuthority::UncredentialedOwner
            }
            None => QueuedIdentityHintAuthority::Uncredentialed,
        };
        Some(OnDeviceIdentityHintReader {
            actor: self.actor,
            actor_class: self.actor_class as u8,
            authority,
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
        let memory = match &self.authority {
            QueuedIdentityHintAuthority::Credential(proof) => vault
                .memory(self.actor, class)
                .with_read_proof(&proof.restore()),
            QueuedIdentityHintAuthority::Uncredentialed
            | QueuedIdentityHintAuthority::UncredentialedOwner => vault.memory(self.actor, class),
        };
        let read = memory.read_lane_if_granted(ClaimReadStatus::Recorded)?;
        // A native read already held by this write may establish its Owner
        // position. A later promotion cannot widen a grant-bound position.
        if !matches!(&self.authority, QueuedIdentityHintAuthority::Credential(_)) {
            let was_owner = matches!(
                &self.authority,
                QueuedIdentityHintAuthority::UncredentialedOwner
            );
            let is_owner = read
                .as_ref()
                .is_some_and(|read| read.actor_key().reads_as_vault_owner());
            if was_owner != is_owner {
                return Ok(None);
            }
        }
        // This fresh plain lane has no audience, peer, session or owner
        // composition. Keep its actual native key, including its live guard.
        Ok(read.map(|read| {
            vault
                .scoped_read(read.actor_key().clone())
                .with_claim_status(ClaimReadStatus::Recorded)
        }))
    }
}
