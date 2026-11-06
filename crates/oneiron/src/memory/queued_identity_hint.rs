//! Durable identity-hint reads for plain Memory lanes.

use serde::{Deserialize, Serialize};

use super::{Memory, MemoryError, MemoryResult};
use crate::authority::StoredReadProof;
use crate::claim::{ClaimReadStatus, ScopedRead, ScopedReadActorKey};
use crate::edge::EdgeActorClass;
use crate::settings::StoredReadDestination;
use crate::{EntityId, Vault};

/// Only the inputs of a plain identity-hint read. Composed host
/// and room lanes are not represented by this record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct QueuedIdentityHintReader {
    actor: EntityId,
    actor_class: u8,
    authority: QueuedIdentityHintAuthority,
    destination: StoredReadDestination,
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
    ) -> Option<QueuedIdentityHintReader> {
        if self.host_action.is_some() || self.room_turn.is_some() {
            return None;
        }
        let authority = match &self.read_proof {
            Some(proof) => QueuedIdentityHintAuthority::Credential(StoredReadProof::of(proof)),
            None if original_key.is_some_and(ScopedReadActorKey::reads_as_vault_owner) => {
                QueuedIdentityHintAuthority::UncredentialedOwner
            }
            None => QueuedIdentityHintAuthority::Uncredentialed,
        };
        Some(QueuedIdentityHintReader {
            actor: self.actor,
            actor_class: self.actor_class as u8,
            authority,
            destination: StoredReadDestination::of(&self.destination),
        })
    }
}

impl QueuedIdentityHintReader {
    pub(crate) fn valid(&self) -> bool {
        EdgeActorClass::try_from_u8(self.actor_class).is_some()
    }

    pub(crate) fn open<'v>(&self, vault: &'v Vault) -> MemoryResult<Option<ScopedRead<'v>>> {
        let class = EdgeActorClass::try_from_u8(self.actor_class).ok_or_else(|| {
            MemoryError::from(crate::Error::CorruptedIndex("tagging hint actor class"))
        })?;
        let memory = vault
            .memory(self.actor, class)
            .for_destination(&self.destination.restore());
        let memory = match &self.authority {
            QueuedIdentityHintAuthority::Credential(proof) => {
                memory.with_read_proof(&proof.restore())
            }
            QueuedIdentityHintAuthority::Uncredentialed
            | QueuedIdentityHintAuthority::UncredentialedOwner => memory,
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
        // This fresh plain lane adds no audience, session or room composition.
        // Keep its native key and restored destination, including live guards.
        Ok(read.map(|read| {
            vault
                .scoped_read(read.actor_key().clone())
                .with_claim_status(ClaimReadStatus::Recorded)
        }))
    }
}
