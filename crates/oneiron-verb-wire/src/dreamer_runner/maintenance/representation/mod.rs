//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/representation/mod.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use rmpv::Value;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepresentationSourceRef {
    #[serde(with = "oneiron_contracts::serialize::entity_ref")]
    #[schemars(with = "String")]
    pub claim: EntityId,
}
