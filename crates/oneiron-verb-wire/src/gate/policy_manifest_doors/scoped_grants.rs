//! Moved from `crates/oneiron/src/gate/policy_manifest_doors/scoped_grants.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyGrantExtension {
    pub tag: i8,
    pub data: Vec<u8>,
}
