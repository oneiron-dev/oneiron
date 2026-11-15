//! Moved from `crates/oneiron/src/edit_settle/stranded.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::edit_roundtrip::manifest::EditManifest;
use oneiron_base::error::Result;
use serde::Deserialize;
use serde::Serialize;

/// Recovery payload. The original manifest is not replayed on the newer head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrandedEditProposal {
    pub artifact_ref: String,
    pub proposal_ref: String,
    pub base_version: Option<u64>,
    pub base_content_hash: [u8; 32],
    pub head_version: u64,
    pub head_content_hash: [u8; 32],
    pub new_bytes: Vec<u8>,
    pub manifest_bytes: Vec<u8>,
    pub actor_ref: String,
    pub actor_class: u8,
    pub retained_at: u64,
}

impl StrandedEditProposal {
    pub fn manifest(&self) -> Result<EditManifest> {
        EditManifest::from_msgpack(&self.manifest_bytes)
    }
}
