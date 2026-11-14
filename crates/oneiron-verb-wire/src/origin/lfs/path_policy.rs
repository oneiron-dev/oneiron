//! Moved from `crates/oneiron/src/origin/lfs/path_policy.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The paths one rule names, in the canonical text of Git path bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OriginLfsPathMatch {
    /// This one repository-relative path.
    Exact(String),
    /// Every path under this directory, at a `/` boundary: `vendor` matches
    /// `vendor/lib.bin`, not `vendor` itself or `vendor-other/lib.bin`. No
    /// trailing `/`.
    Prefix(String),
}
