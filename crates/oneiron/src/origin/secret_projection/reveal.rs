//! Core half of `origin::secret_projection::reveal`: its store-layer items live in `oneiron_store::origin::secret_projection::reveal` and are
//! re-exported here; the items below stay in the engine.

#![allow(
    dead_code,
    reason = "FIX 7608 2b-ii-A: inert until 2b-ii-B wires the per-file why readers"
)]

pub(crate) use oneiron_store::origin::secret_projection::reveal::*;

use super::{
    RepoBodyProjection, RepoGrantedFileProof, RepoSecretAudience, project_repo_blob,
    project_repo_bytes_in_txn,
};
use crate::Vault;
use crate::error::Result;
use crate::origin::secret_marks::RepoBlobMarks;
use crate::secret_custody::{RepoFileReadDisclosure, RepoFileRevealTarget, RepoFileSight};
use crate::secret_record::{RepoFileKeys, RepoFileOriginal};

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
