//! Moved from `crates/oneiron/src/origin/residence.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use rmpv::Value;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum OriginResidence {
    LocalVault,
    CloudVault,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OriginAuthority {
    pub epoch: u64,
    pub residence: OriginResidence,
    /// The one host/vault principal that can obtain an epoch-bound publication permit.
    pub writer: String,
    /// Mirrored repositories are read-only, including main and deletions.
    pub mirror: bool,
}
