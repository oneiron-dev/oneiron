//! Moved from `crates/oneiron/src/sync/chunks.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::sync::chunks::read::ChunkMark;
pub use crate::sync::chunks::read::ChunkRead;
use oneiron_contracts::entity_id::EntityId;

/// A manifest request, or the hashes the receiver still wants after its have pass.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChunkSyncRequest {
    /// The receiver's id for the transfer this request belongs to, echoed on
    /// its reply, so a late reply never reaches another transfer.
    pub request: u64,
    /// SHA-256 pointer that scopes this exchange to one object.
    pub oid: [u8; 32],
    /// Existing grant-backed selector codec bytes.
    pub selector: Vec<u8>,
    /// Already-held ids in this bounded negotiation page.
    pub have: Vec<[u8; 32]>,
    /// None requests a manifest; Some requests only these missing hashes.
    pub want: Option<Vec<[u8; 32]>>,
    /// Where this request goes on from: the `next` its last reply named, or
    /// `None` for the first page.
    pub cursor: Option<ChunkPageCursor>,
    /// What the reader asks of a lift-marked object's read (FIX 2897).
    pub read: Option<ChunkRead>,
}

/// Where the next page of an exchange starts: the manifest every page reads,
/// and an offset into its canonical bytes or into the WANT. A position, never
/// authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChunkPageCursor {
    /// BLAKE3 of the canonical manifest.
    pub manifest: [u8; 32],
    /// The canonical manifest byte, or the WANT's hash, the page starts at.
    pub offset: u64,
}

/// One page of a manifest's canonical bytes.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ManifestPage {
    /// The request id it answers.
    pub request: u64,
    /// BLAKE3 of the whole canonical manifest.
    pub manifest: [u8; 32],
    /// Where these bytes start in it.
    pub offset: u64,
    /// Its whole length.
    pub total: u64,
    /// The page's bytes.
    pub bytes: Vec<u8>,
    /// Where the next page starts; `None` on the last.
    pub next: Option<ChunkPageCursor>,
    /// The granted read the host admitted (FIX 2897), which the read's later
    /// requests name.
    pub read: Option<EntityId>,
    /// The lift mark on the object, sent with its real bytes, so an owner's
    /// device that installs it keeps it marked (FIX 2897).
    pub mark: Option<ChunkMark>,
}

/// The requested chunks from one index of the WANT on, in its order.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChunkPage {
    /// The request id it answers.
    pub request: u64,
    /// The WANT's index of the first chunk here.
    pub offset: u64,
    /// Each chunk's hash and body.
    pub chunks: Vec<([u8; 32], Vec<u8>)>,
    /// Where the rest of the WANT goes on; `None` once every hash was sent.
    pub next: Option<ChunkPageCursor>,
    /// The granted read the host admitted (FIX 2897).
    pub read: Option<EntityId>,
}
pub mod read;
