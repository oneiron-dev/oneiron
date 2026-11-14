//! Moved from `crates/oneiron/src/session_lifecycle/speakers.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use heed::RwTxn;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// One participant bound to a sitting, with the display name it had then.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionParticipant {
    pub actor: EntityId,
    pub display_name: String,
}

/// A sitting's speaker bindings (FIX 2015).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSpeakers {
    /// Every agent bound as the sitting's answerer, in bind order.
    #[serde(default)]
    pub agents: Vec<EntityId>,
    /// Every distinct actor and name pair bound, in bind order: an actor
    /// whose name changed in the sitting keeps both.
    #[serde(default)]
    pub participants: Vec<SessionParticipant>,
    /// How many bindings an actor's erase took out.
    #[serde(default)]
    pub erased: u32,
}

impl SessionSpeakers {
    /// Binds `agent` as an answerer; true when it is new.
    fn bind_agent(&mut self, agent: EntityId) -> bool {
        if self.agents.contains(&agent) {
            return false;
        }
        self.agents.push(agent);
        true
    }

    /// Binds `actor` under `display_name`; true when the pair is new.
    fn bind_participant(&mut self, actor: EntityId, display_name: String) -> bool {
        if self
            .participants
            .iter()
            .any(|held| held.actor == actor && held.display_name == display_name)
        {
            return false;
        }
        self.participants.push(SessionParticipant {
            actor,
            display_name,
        });
        true
    }

    /// Takes `actor`'s bindings out, counting them; true when it held any.
    fn forget(&mut self, actor: EntityId) -> bool {
        let held = self.agents.len() + self.participants.len();
        self.agents.retain(|agent| *agent != actor);
        self.participants
            .retain(|participant| participant.actor != actor);
        let gone = held - (self.agents.len() + self.participants.len());
        self.erased = self
            .erased
            .saturating_add(u32::try_from(gone).unwrap_or(u32::MAX));
        gone > 0
    }
}
