//! Conversation body vocabulary and strict body codecs.

use oneiron_base::error::Error;
use oneiron_base::error::{RecordError, Result};
use oneiron_contracts::entity_id::EntityId;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversationKind {
    #[default]
    Direct,
    Agent,
    Group,
    Channel,
    Mirror,
}
impl ConversationKind {
    /// Whether a room of this kind shares its past with a newcomer when it
    /// sets no rule of its own. None does (ILDF2 P5, "the default is from
    /// now"); a room that shares its past says so in `history_visible`.
    pub const fn history_default(self) -> bool {
        match self {
            Self::Direct | Self::Agent | Self::Group | Self::Channel | Self::Mirror => false,
        }
    }
}

/// A room role is authority, not an actor class: agent PERSON records can hold it.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoomRole {
    Owner,
    Admin,
    #[default]
    Member,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ConversationBody {
    pub v: Option<u8>,
    pub kind: ConversationKind,
    pub member_ids: Vec<EntityId>,
    /// Explicit role overrides keyed by PERSON id (hex); vault owner is implicit.
    pub roles: BTreeMap<String, RoomRole>,
    pub external_id: Option<String>,
    pub title: Option<String>,
    pub status: Option<String>,
    pub history_visible: Option<bool>,
    pub relationship: Option<EntityId>,
    pub is_default: Option<bool>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, rmpv::Value>,
}
impl ConversationBody {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // A live header-only legacy room has no pinned fields. It is distinct
        // from a deleted shell (checked by the owning read door).
        if bytes.is_empty() {
            return Ok(Self::default());
        }
        let mut cursor = std::io::Cursor::new(bytes);
        let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid("body decode"))?;
        let rmpv::Value::Map(entries) = value else {
            return Err(invalid("body must be a map"));
        };
        if cursor.position() != bytes.len() as u64 {
            return Err(invalid("trailing body bytes"));
        }
        let mut seen = BTreeSet::new();
        for (key, _) in entries {
            let key = key
                .as_str()
                .ok_or(invalid("body keys must be strings"))?
                .to_owned();
            if !seen.insert(key) {
                return Err(invalid("duplicate body key"));
            }
        }
        let body: Self = decode(bytes)?;
        body.validate()?;
        Ok(body)
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        encode(self)
    }
    /// The room's history rule: its own `history_visible` when the owner set
    /// one, else its kind's default, which is from now.
    pub fn shares_history(&self) -> bool {
        self.history_visible.unwrap_or(self.kind.history_default())
    }
    fn validate(&self) -> Result<()> {
        for person in self.roles.keys() {
            let id = EntityId::from_hex(person).map_err(|_| invalid("invalid role PERSON id"))?;
            if id.to_hex() != *person || !self.member_ids.contains(&id) {
                return Err(invalid("roles require current members"));
            }
        }
        if self.v.is_some_and(|v| v != 1) {
            return Err(invalid("unsupported version"));
        }
        if self.kind == ConversationKind::Mirror
            && self
                .external_id
                .as_ref()
                .is_none_or(|s| s.trim().is_empty())
        {
            return Err(invalid("mirror requires external_id"));
        }
        if self
            .member_ids
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .len()
            != self.member_ids.len()
        {
            return Err(invalid("duplicate member"));
        }
        Ok(())
    }
}

pub fn invalid(reason: &'static str) -> Error {
    Error::Record(RecordError::InvalidConversationBody(reason))
}

pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(value).map_err(|_| invalid("body encode"))
}

pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    rmp_serde::from_slice(bytes).map_err(|_| invalid("body decode"))
}

/// The door-owned TURN body key a thread binding rides under.
pub const ROOM_THREAD_KEY: &str = "room_thread";

/// A thread TURN's birth binding: its thread's root, the room whose
/// membership it reads under, the trunk turn the thread hangs off and, on
/// the root alone, the audience the thread names (`None`: it reads as its
/// room does). The room is the canonical one, never a session's shell, and
/// every turn of a thread repeats its root's room and anchor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreadBinding {
    pub root: EntityId,
    pub room: EntityId,
    pub anchor: Option<EntityId>,
    pub audience: Option<BTreeSet<EntityId>>,
}

/// The door-owned TURN body key an audience edit rides under.
pub const ROOM_THREAD_AUDIENCE_KEY: &str = "room_thread_audience";

/// The producer a private thread's notices are recorded under; a read
/// admits such a notice to its recipient and the thread's readers alone
/// (FIX 6473).
pub const THREAD_NOTICE_PRODUCER: &str = "rooms.private_thread";

/// The bound a plain delete or unlink of a kept edit meets.
pub const AUDIENCE_EDIT_BOUND: &str = "a thread audience edit stays while its thread's root lives; erase the thread or its people instead";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectRoom {
    pub schema_version: u8,
    pub kind: String,
    pub project_id: String,
    #[serde(rename = "memberIds")]
    pub member_ids: Vec<String>,
    /// Membership never grants additional memory scope.
    pub claims_scope_ref: String,
    /// Absent on an ordinary room, so its body and API shape stay unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<RoomOriginCard>,
}
/// A reference to the original thread, not a second copy of its messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoomOriginCard {
    pub room: String,
    pub thread: String,
    pub message: String,
    pub at: u64,
}

/// `vault.rooms.thread_join.requests`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ThreadJoinRequestsRequest {
    /// The private thread's root TURN, 32-hex.
    pub thread_ref: String,
}
