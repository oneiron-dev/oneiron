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

use super::{
    RepoBodyProjection, RepoGrantedFileProof, RepoSecretAudience, project_repo_blob,
    project_repo_bytes_in_txn,
};
use crate::Vault;
use crate::error::Result;
use crate::origin::secret_marks::RepoBlobMarks;
use crate::secret_custody::{
    RepoFileKeys, RepoFileOriginal, RepoFileReadDisclosure, RepoFileRevealTarget, RepoFileSight,
};

/// CALL 4: what a text door names when the bytes a grant would open are not
/// text. The byte-valued doors deliver granted bytes with their receipts.
pub(crate) const REPO_FILE_BYTE_ROUTE: &str = "This file's stored bytes are not text: read them through the snapshot's byte view \
     or an artifact export, which deliver granted bytes with their receipts.";

/// What kind of reply a repo read's door returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RepoReadDoor {
    /// A door whose reply holds text only.
    Text,
    /// A door whose reply carries bytes.
    Bytes,
}

/// How a door can return a file's stored bytes (CALL 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RepoFileReadRepresentation {
    /// The door returns them as they are.
    Deliverable,
    /// A text door and bytes that are not text: the door keeps its masked
    /// reply and names [`REPO_FILE_BYTE_ROUTE`]; no grant is spent.
    KeepMasked,
}

/// CALL 4, one hook: whether `door` can return `stored` as granted bytes.
pub(crate) fn repo_file_read_representation(
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

/// What one per-file repo read returns.
#[derive(Debug)]
pub(crate) struct RepoFileRevealRead {
    /// The bytes the reply carries, as the reader's audience reads them.
    pub(crate) projection: RepoBodyProjection,
    /// The committed delivery's proof, when the stored bytes went out.
    pub(crate) proof: Option<RepoGrantedFileProof>,
    /// CALL 4: the byte route a text door names in place of granted bytes.
    pub(crate) byte_route: Option<&'static str>,
}

impl RepoFileRevealRead {
    const fn projected(projection: RepoBodyProjection) -> Self {
        Self {
            projection,
            proof: None,
            byte_route: None,
        }
    }
}

/// One per-file read of the ORIGINAL `original`, whose readable marks are
/// `marks`, by a masked reader under `disclosure`, through `door`.
/// `read_exact` reads the stored bytes; `readmit` re-admits the door's pins
/// after the reveal's receipts commit and before a byte is released.
///
/// # Errors
/// `read_exact`'s and `readmit`'s own, the file check's, or a store failure.
pub(crate) fn read_repo_file_with_reveal<F, R>(
    vault: &Vault,
    original: &RepoFileOriginal,
    marks: &RepoBlobMarks,
    disclosure: RepoFileReadDisclosure,
    door: RepoReadDoor,
    read_exact: F,
    readmit: R,
) -> Result<RepoFileRevealRead>
where
    F: FnOnce() -> Result<Vec<u8>>,
    R: FnOnce() -> Result<()>,
{
    let RepoFileReadDisclosure::Ask { asker, why } = disclosure else {
        return project_repo_blob(vault, marks, &RepoSecretAudience::Masked, read_exact)
            .map(RepoFileRevealRead::projected);
    };
    if marks.is_empty() {
        return read_exact()
            .map(|bytes| RepoFileRevealRead::projected(RepoBodyProjection::Exact(bytes)));
    }
    let bytes = read_exact()?;
    let masked = |bytes: Vec<u8>| -> Result<RepoBodyProjection> {
        let txn = vault.store.env.read_txn()?;
        project_repo_bytes_in_txn(vault, &txn, marks, bytes)
    };
    let raw_blake3 = *blake3::hash(&bytes).as_bytes();
    // Bytes the marks were not kept under are no file this check names.
    if marks.raw_blake3() != Some(raw_blake3) {
        return masked(bytes).map(RepoFileRevealRead::projected);
    }
    if repo_file_read_representation(door, &bytes) == RepoFileReadRepresentation::KeepMasked {
        let mut read = RepoFileRevealRead::projected(masked(bytes)?);
        read.byte_route = Some(REPO_FILE_BYTE_ROUTE);
        return Ok(read);
    }
    let target = RepoFileRevealTarget::new(original, &asker);
    let keys = RepoFileKeys {
        custody: marks.custody(),
        opaque: marks.opaque(),
    };
    let delivery = match vault.repo_file_sight(&asker, &target, &raw_blake3, &keys, &why)? {
        RepoFileSight::Delivered(delivery) => delivery,
        RepoFileSight::Masked => return masked(bytes).map(RepoFileRevealRead::projected),
    };
    // The receipts are committed: the door's pins stand again before a
    // byte goes out, and the proof must name the very blob read.
    readmit()?;
    let proof = RepoGrantedFileProof::from_delivery(&delivery)?;
    let projection = project_repo_blob(
        vault,
        marks,
        &RepoSecretAudience::GrantedFile(&proof),
        || Ok(bytes),
    )?;
    Ok(RepoFileRevealRead {
        projection,
        proof: Some(proof),
        byte_route: None,
    })
}
