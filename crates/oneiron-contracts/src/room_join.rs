//! The consent vocabulary of a room join (OF-531): who asks, which consents a
//! join collects, and the party each missing one waits on. The decision that
//! reads the vault stays in `oneiron::workspace_roster`; these are its typed
//! parts, here so a refusal can carry them.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;

/// Who asks to take part. Resolved from stored bindings, never from labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum JoinSubject {
    /// A PERSON: a human, or a companion, who is a person everywhere.
    Person(EntityId),
    /// An AGENT_DEF. An agent never takes a room seat.
    Agent(EntityId),
}

impl JoinSubject {
    #[must_use]
    pub const fn id(&self) -> EntityId {
        match self {
            Self::Person(id) | Self::Agent(id) => *id,
        }
    }
}

/// The consents a join collects, one from each party.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConsentPart {
    Subject,
    Spend,
    Membership,
    Admission,
}

/// The party a missing consent waits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequiredParty {
    /// The subject itself, or its principal: an invitation waits on its own
    /// yes, given through the consent door.
    Subject(JoinSubject),
    /// The PERSON who funds the named scope; only they say yes for it.
    Payer(EntityId),
    /// No scope with a payer's consent is named yet: whoever will pay opens
    /// one and says yes. Never the room host's or the vault owner's funds.
    PayerUnknown,
    /// The vault's Owner or Admin, through the membership doors (add a
    /// member, grant guest access). `vault` is the shared vault's id; 0 is a
    /// personal vault, whose owner alone stands in it.
    VaultAdmin { vault: u64 },
    /// The room's owner or a delegated host.
    RoomHost { room: EntityId },
}

/// One consent a join still waits on, and the party who gives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentNeed {
    pub part: ConsentPart,
    pub party: RequiredParty,
}

/// A person's first write in a room whose join holds: the consents still
/// missing, and the key `vault.rooms.join` files that join under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoomJoinHold {
    pub room: EntityId,
    pub person: EntityId,
    /// `vault.rooms.join` with this key files the held join for its parties.
    pub intent_key: String,
    /// Every party still missing, never only the first.
    pub needs: Vec<ConsentNeed>,
}

impl fmt::Display for RoomJoinHold {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let needs = serde_json::to_string(&self.needs).unwrap_or_default();
        write!(
            f,
            "the write waits on its room join, which holds on {needs}; vault.rooms.join with \
             intent_key {} files it for those parties",
            self.intent_key
        )
    }
}
