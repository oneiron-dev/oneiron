use std::io::Cursor;

#[cfg(test)]
use rmpv::Value;

use crate::entity_id::EntityId;

pub(crate) const TASK_BODY_ROLE_KEY: &str = "role";

/// Pinned TASK role byte for the productivity pack.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaskRole {
    Task = 1,
    Goal = 2,
    Milestone = 3,
    Habit = 4,
    HabitCheckin = 5,
}

impl TaskRole {
    pub const ALL: [Self; 5] = [
        Self::Task,
        Self::Goal,
        Self::Milestone,
        Self::Habit,
        Self::HabitCheckin,
    ];

    #[must_use]
    pub const fn role_byte(self) -> u8 {
        match self {
            Self::Task => 1,
            Self::Goal => 2,
            Self::Milestone => 3,
            Self::Habit => 4,
            Self::HabitCheckin => 5,
        }
    }

    #[must_use]
    pub const fn from_role_byte(role: u8) -> Option<Self> {
        match role {
            1 => Some(Self::Task),
            2 => Some(Self::Goal),
            3 => Some(Self::Milestone),
            4 => Some(Self::Habit),
            5 => Some(Self::HabitCheckin),
            _ => None,
        }
    }
}

#[cfg(test)]
pub(crate) fn task_body_for_test(role: TaskRole) -> Vec<u8> {
    let value = Value::Map(vec![(
        Value::from(TASK_BODY_ROLE_KEY),
        Value::from(role.role_byte()),
    )]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &value)
        .expect("writing MessagePack TASK body to Vec cannot fail");
    bytes
}

pub(crate) fn task_role_from_body_bytes(bytes: &[u8]) -> crate::error::Result<TaskRole> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| crate::error::Error::InvalidTaskBody("body is not valid MessagePack"))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(crate::error::Error::InvalidTaskBody(
            "trailing bytes after body map",
        ));
    }
    let entries = value.as_map().ok_or(crate::error::Error::InvalidTaskBody(
        "body must be a MessagePack map",
    ))?;
    let mut role = None;
    for (key, value) in entries {
        let key = key.as_str().ok_or(crate::error::Error::InvalidTaskBody(
            "body keys must be strings",
        ))?;
        if key != TASK_BODY_ROLE_KEY {
            continue;
        }
        if role.is_some() {
            return Err(crate::error::Error::InvalidTaskBody(
                "duplicate task role key",
            ));
        }
        let role_byte = value
            .as_u64()
            .and_then(|raw| u8::try_from(raw).ok())
            .ok_or(crate::error::Error::InvalidTaskBody(
                "task role must be a byte",
            ))?;
        role = Some(
            TaskRole::from_role_byte(role_byte)
                .ok_or(crate::error::Error::InvalidTaskBody("unknown task role"))?,
        );
    }
    role.ok_or(crate::error::Error::InvalidTaskBody("missing task role"))
}

/// Stable deletion reason surfaced by short-id hydrate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HydratedShortIdDeletionReason {
    UserDelete,
    UserHardDelete,
    GdprDelete,
    PolicyDelete,
}

/// Where hydrate found deletion evidence for a short-id row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HydratedShortIdDeletionSource {
    Tombstone,
    PendingTombstone,
    DanglingShortId,
}

/// Deletion metadata returned when a short-id row resolves to deleted state.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HydratedShortIdDeletion {
    pub source: HydratedShortIdDeletionSource,
    pub reason: Option<HydratedShortIdDeletionReason>,
    pub deleted_at: Option<u64>,
    pub request_id: Option<String>,
    pub hard: bool,
}

/// Renderer-facing lifecycle state for one record in a memory timeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryTimelineRecordState {
    /// The record exists and is not closed by the supersession graph.
    Live,
    /// The record exists and has been superseded by at least one newer record.
    Superseded,
    /// The record exists as explicitly retracted claim history.
    Retracted,
    /// The record exists only as a deletion shell with tombstone metadata.
    Deleted,
    /// The graph still references an entity id whose record is absent locally.
    Missing,
}

/// One node in a bitemporal supersession timeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryTimelineRecord {
    pub id: EntityId,
    pub state: MemoryTimelineRecordState,
    pub entity_type: Option<u8>,
    pub occurred_start: Option<u64>,
    pub occurred_end: Option<u64>,
    pub learned_at: Option<u64>,
    pub body_bytes: Option<usize>,
    pub deletion: Option<HydratedShortIdDeletion>,
    pub supersedes: Vec<EntityId>,
    pub superseded_by: Vec<EntityId>,
}

/// Stable, ordered supersession-chain data for one anchor entity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryTimeline {
    pub anchor: EntityId,
    pub records: Vec<MemoryTimelineRecord>,
}

/// Human-readable memory verbs exposed by API surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamedMemoryVerb {
    Remember,
    Supersede,
    Retract,
    Delete,
    HardDelete,
}

impl NamedMemoryVerb {
    /// Parses a public route verb, accepting stable aliases while resolving to
    /// one canonical typed operation family.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().replace('-', "_").as_str() {
            "remember" | "put" | "put_entity" => Some(Self::Remember),
            "supersede" | "replace" | "revise" | "supersede_claim" => Some(Self::Supersede),
            "retract" | "withdraw" | "retract_claim" => Some(Self::Retract),
            "delete" | "forget" | "soft_delete" | "user_delete" => Some(Self::Delete),
            "hard_delete" | "erase" | "purge" | "user_hard_delete" => Some(Self::HardDelete),
            _ => None,
        }
    }

    pub const fn canonical_name(self) -> &'static str {
        match self {
            Self::Remember => "remember",
            Self::Supersede => "supersede",
            Self::Retract => "retract",
            Self::Delete => "delete",
            Self::HardDelete => "hard_delete",
        }
    }

    pub const fn operation_kind(self) -> MemoryOperationKind {
        match self {
            Self::Remember => MemoryOperationKind::PutEntity,
            Self::Supersede => MemoryOperationKind::SupersedeClaim,
            Self::Retract => MemoryOperationKind::RetractClaim,
            Self::Delete | Self::HardDelete => MemoryOperationKind::DeleteEntity,
        }
    }
}

/// Typed operation family selected by a named memory verb.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryOperationKind {
    PutEntity,
    SupersedeClaim,
    RetractClaim,
    DeleteEntity,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_role_from_body_bytes_rejects_malformed_bodies() {
        fn encode(value: &Value) -> Vec<u8> {
            let mut bytes = Vec::new();
            rmpv::encode::write_value(&mut bytes, value).expect("encode msgpack test body");
            bytes
        }

        let role_byte = TaskRole::Task.role_byte();

        // A map carrying two "role" entries: decoders that resolve first-vs-last
        // key differently must not silently disagree; this is rejected outright.
        let duplicate_role = encode(&Value::Map(vec![
            (Value::from(TASK_BODY_ROLE_KEY), Value::from(role_byte)),
            (Value::from(TASK_BODY_ROLE_KEY), Value::from(role_byte)),
        ]));
        match task_role_from_body_bytes(&duplicate_role) {
            Err(crate::error::Error::InvalidTaskBody(msg)) => {
                assert_eq!(msg, "duplicate task role key");
            }
            other => panic!("expected duplicate-role-key rejection, got {other:?}"),
        }

        let non_map = encode(&Value::from(role_byte));
        match task_role_from_body_bytes(&non_map) {
            Err(crate::error::Error::InvalidTaskBody(msg)) => {
                assert_eq!(msg, "body must be a MessagePack map");
            }
            other => panic!("expected non-map rejection, got {other:?}"),
        }

        let non_string_key = encode(&Value::Map(vec![(
            Value::from(1_u64),
            Value::from(role_byte),
        )]));
        match task_role_from_body_bytes(&non_string_key) {
            Err(crate::error::Error::InvalidTaskBody(msg)) => {
                assert_eq!(msg, "body keys must be strings");
            }
            other => panic!("expected non-string-key rejection, got {other:?}"),
        }
    }
}
