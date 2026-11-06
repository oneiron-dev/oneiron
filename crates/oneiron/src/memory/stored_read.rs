//! Read-only request context kept by the engine, never a wire input.

use serde::{Deserialize, Serialize};

use super::{Memory, MemoryResult};
use crate::authority::{HostActionAuthority, HostActionIdentity, StoredReadProof};
use crate::claim::{CallerLocality, RoomTerms, TurnTerms};
use crate::settings::StoredReadDestination;
use crate::{EdgeActorClass, EntityId, Error, Vault};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoredReadContext {
    actor: EntityId,
    actor_class: u8,
    identity: ReadIdentity,
    locality: CallerLocality,
    destination: StoredReadDestination,
    room: StoredRoom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum ReadIdentity {
    Actor,
    Credential(StoredReadProof),
    HostAction(HostActionIdentity),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum StoredRoom {
    Unbound,
    Bound {
        room: EntityId,
        #[serde(deserialize_with = "required_branch")]
        branch: Option<EntityId>,
        personal: bool,
        terms: RoomTerms,
    },
}

fn required_branch<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<EntityId>, D::Error> {
    Option::deserialize(deserializer)
}

impl StoredReadContext {
    /// Capture the bound handle, after its host-origin proof has been applied.
    /// No resolved lane, audience or live room ceiling is stored.
    pub(crate) fn of(memory: &Memory<'_>) -> Self {
        let identity = match (&memory.host_action, &memory.read_proof) {
            (Some(action), _) => {
                ReadIdentity::HostAction(action.guard().durable_identity(memory.vault))
            }
            (None, Some(proof)) => ReadIdentity::Credential(StoredReadProof::of(proof)),
            (None, None) => ReadIdentity::Actor,
        };
        Self {
            actor: memory.actor,
            actor_class: memory.actor_class as u8,
            identity,
            locality: memory.locality,
            destination: StoredReadDestination::of(&memory.destination),
            room: match &memory.room_turn {
                Some(turn) => StoredRoom::Bound {
                    room: turn.room,
                    branch: turn.branch,
                    personal: turn.personal,
                    terms: turn.terms.get(),
                },
                None => StoredRoom::Unbound,
            },
        }
    }

    /// Rebuild only this source reader. Its first and every later read still
    /// resolves the actor key and the live room in the normal read lane.
    pub(crate) fn restore<'v>(&self, vault: &'v Vault) -> MemoryResult<Memory<'v>> {
        let class = EdgeActorClass::try_from_u8(self.actor_class)
            .ok_or(Error::CorruptedIndex("stored source reader actor class"))?;
        let mut memory = vault
            .memory(self.actor, class)
            .at(self.locality)
            .for_destination(&self.destination.restore());
        match &self.identity {
            ReadIdentity::Actor => {}
            ReadIdentity::Credential(proof) => {
                memory = memory.with_read_proof(&proof.restore());
            }
            ReadIdentity::HostAction(identity) => {
                let action = {
                    let txn = vault.store.env.read_txn().map_err(Error::from)?;
                    HostActionAuthority::from_recorded_in_txn(vault, &txn, identity)?
                };
                memory = memory.with_host_action_authority(&action)?;
            }
        }
        if let StoredRoom::Bound {
            room,
            branch,
            personal,
            terms,
        } = &self.room
        {
            let mut now = match branch {
                Some(thread) => memory.thread_ceiling(*room, *thread)?,
                None => memory.room_ceiling(*room)?,
            };
            let held = TurnTerms::new(terms.clone());
            held.meet(&now.terms.get());
            now.terms = held;
            now.personal = *personal;
            memory.room_turn = Some(now);
        }
        Ok(memory)
    }
}
