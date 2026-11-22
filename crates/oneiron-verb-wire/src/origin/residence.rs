//! Moved from `crates/oneiron/src/origin/residence.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

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
    /// The git door base of the host that writes this epoch
    /// (`https://host.example/git`), as the owner's cutover named it: where
    /// this copy, when it is a mirror or a former origin, redirects a push
    /// (RA7). Absent when the cutover named none; a row without it encodes
    /// as before the field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writer_door: Option<String>,
}
