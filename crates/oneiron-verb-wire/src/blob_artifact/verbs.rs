//! Moved from `crates/oneiron/src/blob_artifact/verbs.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use base64::Engine as _;
use serde::Deserialize;
use serde::Serialize;

/// One file of a folder ask and the result row its answer fills.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FolderItemInput {
    pub artifact_ref: String,
    pub row: u32,
}
