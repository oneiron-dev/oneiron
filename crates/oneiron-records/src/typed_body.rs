//! Moved from `crates/oneiron/src/typed_body.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
pub use oneiron_store::typed_body::body_actor::BodyActor;
pub use oneiron_store::typed_body::live_pin;
use serde::Deserialize;
use serde::Serialize;

/// One entity's typed body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypedBodyHead {
    pub entity: EntityId,
    /// The owning module's shape tag, e.g. `office.docx.v1`.
    pub schema: String,
    /// The body as born: an owner's base for what changed since.
    pub birth: Vec<u8>,
    pub frontier: Vec<u8>,
    /// Commits on the body, a merged fork's included.
    pub commits: u64,
    /// When a fork's commits last landed on the body. They keep the times
    /// they were made at, so a quiet clock runs from here too (FIX 11983).
    #[serde(default)]
    pub landed_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TypedForkState {
    Open,
    Merged {
        by: BodyActor,
        at: u64,
        head: Vec<u8>,
    },
    Discarded {
        by: BodyActor,
        at: u64,
    },
}

/// Work on a body away from its head: opened at a head frontier, written only
/// by its opener, landed by someone else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypedBodyFork {
    pub entity: EntityId,
    pub fork: EntityId,
    pub opener: BodyActor,
    pub base: Vec<u8>,
    pub commits: u64,
    pub opened_at: u64,
    pub state: TypedForkState,
    /// The fork document's version vector at its latest authored state,
    /// encoded (`oplog_vv().encode()`), and kept once the fork is merged or
    /// discarded: what orders two machines' copies of the fork, since a
    /// version vector compares without the other machine's operations (FIX
    /// 12470). Empty for a fork stored before it was recorded, which keeps
    /// the spelling it was stored in.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub version: Vec<u8>,
}
pub mod body_actor;
#[cfg(feature = "sync")]
pub mod carried_fork;
