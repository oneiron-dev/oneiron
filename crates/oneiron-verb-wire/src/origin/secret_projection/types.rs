//! Moved from `crates/oneiron/src/origin/secret_projection/types.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::bytes_to_hex_lower;
use oneiron_store::git_wire::ids::GitOid;
use serde::Deserialize;
use serde::Serialize;

/// What reads a projected file's stored bytes: one fixed line, naming no
/// key, handle, finding or count.
pub const REPO_PROJECTION_WAY_OUT: &str = "An Owner reads this file's stored bytes; an agent reads them through a real-byte file \
     reveal the owner grants.";

/// How the bytes a reply returns differ from the stored blob they stand in
/// for. Present only when they differ: an unmarked file's reply has none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RepoFileProjectionView {
    pub kind: RepoFileProjectionKind,
    /// The Git OID of the stored blob, 40 lower-hex characters: the source
    /// the copy stands in for, never the copy's own.
    pub source_blob: String,
    /// The BLAKE3 of exactly the returned bytes, 64 lower-hex characters.
    pub copy_blake3: String,
    /// The length of exactly the returned bytes.
    pub copy_size_bytes: u64,
    /// What reads the stored bytes.
    pub way_out: String,
}

/// A projected file's kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RepoFileProjectionKind {
    /// Each marked key's span overwritten in place, the rest as stored.
    Masked,
    /// The sealed-file placeholder, [`REPO_OPAQUE_FILE_BYTES`].
    Opaque,
}

impl RepoFileProjectionView {
    pub fn of(kind: RepoFileProjectionKind, source_blob: &GitOid, copy: &[u8]) -> Self {
        Self {
            kind,
            source_blob: source_blob.as_str().to_owned(),
            copy_blake3: bytes_to_hex_lower(blake3::hash(copy).as_bytes()),
            copy_size_bytes: copy.len() as u64,
            way_out: REPO_PROJECTION_WAY_OUT.to_owned(),
        }
    }
}
