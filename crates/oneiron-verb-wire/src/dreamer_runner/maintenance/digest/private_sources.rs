//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/digest/private_sources.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// One private thread turn a proposal's words were drawn from when its
/// digest was assembled (FIX 6411).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct DigestPrivateSource {
    /// The thread's root TURN.
    #[serde(with = "oneiron_contracts::serialize::entity_ref")]
    #[schemars(with = "String")]
    pub root: EntityId,
    /// The turn the words were read from.
    #[serde(with = "oneiron_contracts::serialize::entity_ref")]
    #[schemars(with = "String")]
    pub turn: EntityId,
}
