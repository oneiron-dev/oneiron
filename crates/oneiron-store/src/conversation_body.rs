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
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
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
    /// The room's shared pins, one record per target; only the room pin
    /// doors write them. Absent from the bytes while empty.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pins: Vec<RoomPin>,
    /// Who may change `pins`; only the room pin-policy door writes it.
    /// Absent from the bytes while it is the default.
    #[serde(skip_serializing_if = "RoomPinPolicy::is_members")]
    pub pin_policy: RoomPinPolicy,
    #[serde(flatten)]
    pub extra: BTreeMap<String, rmpv::Value>,
}

/// One shared pin of a room (ROOM-SCOPED-PINS, owner 12 Nov 00:04): the
/// target, the PERSON who pinned it, the AGENT_DEF that acted for that
/// PERSON (`None` when the PERSON acted), and the engine time of the pin in
/// Unix seconds. A pin moves its target into the PINNED tier of the boards
/// that work in the room; every reader still reads the target as itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomPin {
    pub target: EntityId,
    pub pinned_by: EntityId,
    pub acting_agent: Option<EntityId>,
    pub pinned_at: u64,
}

/// Who may change a room's shared pins: every current member (the default),
/// or only the room's managers.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum RoomPinPolicy {
    #[default]
    Members,
    Managers,
}
impl RoomPinPolicy {
    /// Whether this is the default policy, which a body leaves unwritten.
    pub fn is_members(&self) -> bool {
        *self == Self::Members
    }
}

/// Refuses a pin list that names one target twice.
pub fn validate_room_pins(pins: &[RoomPin]) -> Result<()> {
    let mut targets = BTreeSet::new();
    if pins.iter().all(|pin| targets.insert(pin.target)) {
        Ok(())
    } else {
        Err(invalid("duplicate pin target"))
    }
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
    /// The project that groups this room as an extra room, from its door-owned `project_group`
    /// key: absent reads as unlinked; a canonical 32-hex id reads as linked; any other value is
    /// refused, so a malformed key never encodes or decodes.
    pub fn project_group(&self) -> Result<Option<EntityId>> {
        let Some(value) = self.extra.get(ROOM_PROJECT_GROUP_KEY) else {
            return Ok(None);
        };
        let Some(id) = value.as_str() else {
            return Err(invalid("invalid project_group"));
        };
        let project = EntityId::from_hex(id).map_err(|_| invalid("invalid project_group"))?;
        if project.to_hex() != id {
            return Err(invalid("invalid project_group"));
        }
        Ok(Some(project))
    }
    fn validate(&self) -> Result<()> {
        self.project_group()?;
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
        validate_room_pins(&self.pins)?;
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

/// The door-owned CONVERSATION body key naming the project that groups this ordinary room as an
/// extra room; only vault.projects.rooms.link and .unlink stamp it.
pub const ROOM_PROJECT_GROUP_KEY: &str = "project_group";

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
    /// The home room's shared pins, as on [`ConversationBody::pins`]; the
    /// project projector carries them forward unchanged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pins: Vec<RoomPin>,
    /// As [`ConversationBody::pin_policy`].
    #[serde(default, skip_serializing_if = "RoomPinPolicy::is_members")]
    pub pin_policy: RoomPinPolicy,
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
