//! Moved from `crates/oneiron/src/blob_artifact/create.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use base64::Engine as _;
use serde::Deserialize;
use serde::Serialize;

/// A new artifact and the bytes of its first version.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactCreateRequest {
    pub name: String,
    pub media_type: String,
    /// The first version's bytes, standard base64.
    pub content_base64: String,
    /// The run that made the bytes; an agent's version names it.
    #[serde(default)]
    pub run_ref: Option<String>,
    /// The first version's made_by input; the authenticated writer owns its
    /// process identity/class, and a supplied process actor stays as input
    /// provenance (FIX 9618). The writer's own envelope when absent.
    #[serde(default)]
    pub made_by: Option<serde_json::Value>,
}
