//! Moved from `crates/oneiron/src/memory/foreign_code.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ForeignCodeRunRequest {
    /// Plain JavaScript for the foreign interpreter, not native code or a host path.
    pub source: String,
    /// Named records to freeze through this credential's scoped read.
    /// Entry N is frozen as JSON at /mnt/workspace/record-N.json.
    /// The answer repeats the reference-to-path mapping.
    #[serde(default)]
    pub reads: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ForeignCodeRead {
    pub reference: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ForeignCodeOutput {
    pub path: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ForeignCodeTier {
    Foreign,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ForeignCodeApproval {
    Proposed,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ForeignCodeSource {
    Generated,
}

/// The public part of the backend's own proof. The complete manifest is
/// retained by the sandbox receipt, not asserted by the calling program.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ForeignCodeIsolation {
    pub backend: String,
    pub runtime: String,
    pub image: String,
    pub argv_digest: String,
    pub network: String,
    pub generation: String,
    pub fence_proven: bool,
}
