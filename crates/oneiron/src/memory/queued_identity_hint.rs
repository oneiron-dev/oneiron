//! Queued identity-hint reads with their original native caller positions.

use serde::{Deserialize, Serialize};

use super::queued_room_hint::QueuedRoomHintReader;
use super::{Memory, MemoryError, MemoryResult};
use crate::authority::StoredReadProof;
use crate::claim::{ClaimReadStatus, ScopedRead, ScopedReadActorKey};
use crate::edge::EdgeActorClass;
use crate::settings::StoredReadDestination;
use crate::{EntityId, Vault};

/// The original inputs of an identity-hint read. A room position also
/// names its still-live native turn; a host action is not represented.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct QueuedIdentityHintReader {
    actor: EntityId,
    actor_class: u8,
    authority: QueuedIdentityHintAuthority,
    destination: StoredReadDestination,
    room: Option<QueuedRoomHintReader>,
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
        if self.host_action.is_some() {
            return None;
        }
        let room = match &self.room_turn {
            Some(_) => Some(QueuedRoomHintReader::capture(
                self.vault,
                original_key?.room_turn()?,
            )?),
            None => None,
        };
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
            room,
        })
    }
}

impl QueuedIdentityHintReader {
    pub(crate) fn hold_room_turn(
        &self,
        store: &crate::store::Store,
    ) -> Option<crate::claim::TurnTerms> {
        self.room.as_ref()?.hold_turn(store)
    }

    pub(crate) fn valid(&self) -> bool {
        EdgeActorClass::try_from_u8(self.actor_class).is_some()
            && self
                .room
                .as_ref()
                .is_none_or(|room| room.belongs_to(self.actor))
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
        let memory = match &self.room {
            Some(room) => match room.bind(memory)? {
                Some(memory) => memory,
                None => return Ok(None),
            },
            None => memory,
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
        // Keep the fresh native key, including its live room composition and
        // original shared terms when present, and every restored live guard.
        Ok(read.map(|read| {
            vault
                .scoped_read(read.actor_key().clone())
                .with_claim_status(ClaimReadStatus::Recorded)
        }))
    }
}
