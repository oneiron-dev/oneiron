//! Moved from `crates/oneiron/src/vault_shape/member.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

/// The ARCH-0043 preset a shared vault's defaults came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ShapePreset {
    Personal,
    Family,
    Team,
    Org,
    Community,
}
