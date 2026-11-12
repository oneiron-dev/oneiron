//! Moved from `crates/oneiron/src/workspace_roster/rooms/participation.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::workspace_roster::rooms::hosting;
use crate::workspace_roster::rooms::offers;
use oneiron_base::edge::EdgeActorClass;
use oneiron_base::error::ClaimError;
use oneiron_base::error::Error;
use oneiron_base::error::RecordError;
use oneiron_base::error::Result;
use oneiron_base::registry::ENTITY_TYPE_AGENT_DEF;
use oneiron_base::registry::ENTITY_TYPE_PERSON;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::room_join::JoinSubject;
use oneiron_contracts::room_join::RoomJoinHold;
use oneiron_store::side_table::key::SideKey;
use oneiron_store::write_envelope::WriteActor;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// Why a participant takes part in a room or thread.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum JoinCause {
    /// A person wrote there; `turn` is its first turn.
    Wrote { turn: EntityId },
    /// An agent was named on `turn` and stood on a Ready receipt, when named
    /// or when its claim on that turn passed.
    Addressed { turn: EntityId },
    /// An agent holds `task`, an open TASK bound to the thread.
    Task { task: EntityId },
    /// The participant accepted an offer to join (OF-530).
    Offer { offer_id: String },
}

impl JoinCause {
    pub const fn kind(&self) -> u8 {
        match self {
            Self::Wrote { .. } => 1,
            Self::Addressed { .. } => 2,
            Self::Task { .. } => 3,
            Self::Offer { .. } => 4,
        }
    }

    /// The cause's id in a key: its turn or task, or an offer id's digest.
    pub fn key_id(&self) -> [u8; 16] {
        match self {
            Self::Wrote { turn } | Self::Addressed { turn } => *turn.as_bytes(),
            Self::Task { task } => *task.as_bytes(),
            Self::Offer { offer_id } => {
                let mut hasher = blake3::Hasher::new();
                hasher.update(b"oneiron.rooms.participation.offer.v1");
                hasher.update(offer_id.as_bytes());
                let mut id = [0; 16];
                id.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
                id
            }
        }
    }

    /// A first join is recorded once per subject and place: a later turn
    /// or naming adds no row. Each TASK and offer is its own fact.
    const fn first_only(&self) -> bool {
        matches!(self, Self::Wrote { .. } | Self::Addressed { .. })
    }
}
