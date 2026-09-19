//! Backend-independent values carried across storage ports.
use crate::{EntityId, TimeRange};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq)]
pub struct EntityRecord {
    pub entity_type: u8,
    pub occurred: TimeRange,
    pub learned_at: u64,
    pub body: Vec<u8>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdgeDirection {
    In,
    Out,
    Both,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangeOp {
    Create,
    Update,
    Delete,
    Redact,
    Forget,
    Merge,
    Supersede,
    TierTransition,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeLogRecord {
    pub id: [u8; 16],
    #[serde(with = "crate::entity_id::serde_hex")]
    pub entity: EntityId,
    pub op: ChangeOp,
    #[serde(with = "crate::entity_id::serde_hex")]
    pub actor_principal: EntityId,
    #[serde(with = "crate::entity_id::serde_hex::optional")]
    pub actor_person: Option<EntityId>,
    pub occurred_at: u64,
    pub recorded_at: u64,
    pub input_hash: [u8; 32],
    pub patch: Option<Vec<u8>>,
    pub reason: Option<String>,
}
/// Source version identity. A non-CRDT source uses its learned-at revision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SourceSpan {
    pub document: EntityId,
    pub frontier: u64,
}
