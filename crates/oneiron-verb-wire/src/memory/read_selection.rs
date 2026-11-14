//! Moved from `crates/oneiron/src/memory/read_selection.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecallWorlds {
    All,
    Base,
    World {
        world_ref: String,
        include_base: bool,
    },
    Worlds {
        world_refs: Vec<String>,
        include_base: bool,
    },
}
