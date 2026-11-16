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
#[cfg(feature = "sync")]
pub mod carried_fork;
