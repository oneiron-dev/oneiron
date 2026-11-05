//! A real-byte read of one marked repo file through the shipped file reveal
//! (FIX 7608 slice 2b-ii-A, GAP-B / FIX 8960; ASK 1 addition).
//!
//! The door pins and admits the ORIGINAL file first and hands its bytes'
//! reader here. A read with no why (CALL 3), or from a recipient the host
//! did not prove, is today's masked or opaque read: no ask, no refusal.
//! A read that says why, from a proven recipient, runs the one file check
//! ([`Vault::repo_file_sight`]) outside any read snapshot: its receipts
//! commit before anything is released, the door re-admits its pins, and
//! the stored bytes go out only under the committed proof, checked against
//! the very blob read. A text door whose granted bytes are not text keeps
//! its masked reply and names the byte route instead (CALL 4): nothing is
//! asked, spent or logged as delivered that the door could not return.

#![allow(
    dead_code,
    reason = "FIX 7608 2b-ii-A: inert until 2b-ii-B wires the per-file why readers"
)]

use crate::secret_record::write_records::RepoFileKeys;
use crate::secret_record::write_records::RepoFileOriginal;
use oneiron_base::error::Result;

/// CALL 4: what a text door names when the bytes a grant would open are not
/// text. The byte-valued doors deliver granted bytes with their receipts.
pub const REPO_FILE_BYTE_ROUTE: &str = "This file's stored bytes are not text: read them through the snapshot's byte view \
     or an artifact export, which deliver granted bytes with their receipts.";

/// What kind of reply a repo read's door returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoReadDoor {
    /// A door whose reply holds text only.
    Text,
    /// A door whose reply carries bytes.
    Bytes,
}

/// How a door can return a file's stored bytes (CALL 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoFileReadRepresentation {
    /// The door returns them as they are.
    Deliverable,
    /// A text door and bytes that are not text: the door keeps its masked
    /// reply and names [`REPO_FILE_BYTE_ROUTE`]; no grant is spent.
    KeepMasked,
}

/// CALL 4, one hook: whether `door` can return `stored` as granted bytes.
pub fn repo_file_read_representation(
    door: RepoReadDoor,
    stored: &[u8],
) -> RepoFileReadRepresentation {
    match door {
        RepoReadDoor::Text if std::str::from_utf8(stored).is_err() => {
            RepoFileReadRepresentation::KeepMasked
        }
        RepoReadDoor::Text | RepoReadDoor::Bytes => RepoFileReadRepresentation::Deliverable,
    }
}
