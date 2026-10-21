//! The value-free shapes a projected repo read carries (FIX 7608 slice 2a,
//! CALL P1): the opaque placeholder's bytes, the reply descriptor beside a
//! projected file, and the proof a real-byte file reveal would carry.

use serde::{Deserialize, Serialize};

use crate::entity_id::bytes_to_hex_lower;
use crate::git_wire::GitOid;

/// The bytes a masked reader reads in place of a file whose marks hold
/// residue no span isolates (CALL P1, `RepoOpaqueRepresentation::SealedFile`):
/// never a raw prefix, an empty file or a rewritten original.
pub(crate) const REPO_OPAQUE_FILE_BYTES: &[u8] = b"[sealed file: reveal required]\n";

/// What reads a projected file's stored bytes: one fixed line, naming no
/// key, handle, finding or count.
const REPO_PROJECTION_WAY_OUT: &str = "An Owner reads this file's stored bytes; an agent reads them through a real-byte file \
     reveal the owner grants.";

/// An opaque file as a masked reader gets it: the placeholder, standing in
/// for the stored blob named here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepoOpaqueFile {
    pub(crate) source_blob: GitOid,
}

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
    pub(crate) fn of(kind: RepoFileProjectionKind, source_blob: &GitOid, copy: &[u8]) -> Self {
        Self {
            kind,
            source_blob: source_blob.as_str().to_owned(),
            copy_blake3: bytes_to_hex_lower(blake3::hash(copy).as_bytes()),
            copy_size_bytes: copy.len() as u64,
            way_out: REPO_PROJECTION_WAY_OUT.to_owned(),
        }
    }
}

/// A real-byte read of one marked file, committed by the shipped file reveal
/// (ConsentGrant ApproveOnce or a standing disclosure grant) with its
/// reason logged before any byte is released. Only that reveal's adapter
/// mints one; no request field, owner token or `SecretSight` value does.
#[allow(
    dead_code,
    reason = "FIX 7608 slice 2a: no repo reader takes a why yet, so none asks for a file reveal"
)]
#[derive(Debug)]
pub(crate) struct RepoGrantedFileProof {
    raw_blake3: [u8; 32],
}
