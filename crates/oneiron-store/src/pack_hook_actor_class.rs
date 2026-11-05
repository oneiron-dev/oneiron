//! The actor classes a pack hook's selector may name. Pack hooks
//! (`skill_hub::pack_catalog`) declare and bind them; the store-layer verb
//! hook callers (compaction) name the class they run under.
use serde::{Deserialize, Serialize};

/// The closed actor classes a selector may name (ARCH-0067 §4).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum HookActorClass {
    Human,
    Agent,
    System,
}
