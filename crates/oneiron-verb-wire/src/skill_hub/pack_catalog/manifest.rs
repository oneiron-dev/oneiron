//! Moved from `crates/oneiron/src/skill_hub/pack_catalog/manifest.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PackKind {
    Capability,
    Connector,
    Agent,
    /// A seasonal model pack (FIX 5365): data only, its roles, variants,
    /// changelog and bench evidence in `knowledge/model-pack.json`.
    Model,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PackAdapter {
    Builtin(String),
    Script(String),
}
