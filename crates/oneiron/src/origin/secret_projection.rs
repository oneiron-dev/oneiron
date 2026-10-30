//! Who reads a marked repo blob's real bytes (FIX 7608 slice 2a, owner
//! ruling SECRETS-IN-REPOS = A, ASK 1).
//!
//! History stays exact: the stored blob never changes. A reader is served
//! by its audience, which only a door's own admission chooses, never a
//! request field: the owner's own doors, a committed real-byte file reveal
//! and a proved original-source export read the stored bytes; every reader
//! the host knows to be a run, an agent, a model or an MCP tool reads the
//! projection. A blob with no readable mark is the stored bytes for every
//! audience, with no detector, container read, reveal, disk write or reply
//! field added: before the receive flip no vault holds a mark, so every
//! read here is today's.
//!
//! A marked blob's projection is found before a byte of it is read: opaque
//! residue wins and gives [`REPO_OPAQUE_FILE_BYTES`] in its place. Span
//! marks give the blob with each marked span overwritten in place, rebuilt
//! through its containers by the retained repository read and read again by
//! the rules that placed them; a copy that does not rebuild or still reads
//! as secret is opaque, never a raw fallback and never a refusal. The marks
//! are found once per request (CALL 8033 option d) and kept no longer.

use std::collections::BTreeMap;

use heed::RoTxn;

pub(crate) mod checkout;
pub(crate) mod checkout_recipient;
pub(crate) mod claims;
pub(crate) mod clearance;
pub(crate) mod copy_id;
pub(crate) mod disposal;
pub(crate) mod edit;
pub(crate) mod git;
pub(crate) mod graph_objects;
pub(crate) mod index;
pub(crate) mod recipient;
pub(crate) mod reveal;
pub(crate) mod types;

pub(crate) use self::git::ExactSourceExportProof;
pub(crate) use self::recipient::{RepoRevealRecipient, RepoToolRecipient};
pub(crate) use self::types::{
    REPO_OPAQUE_FILE_BYTES, RepoFileProjectionKind, RepoFileProjectionView, RepoGrantedFileProof,
    RepoOpaqueFile,
};

use super::export_preview::{
    CodeExportBlockingSource, CodeExportPreviewBlockReason, CodeExportPreviewBlocker,
    CodeExportSide, PinnedLeaf,
};
use super::lfs::lfs_repo_id;
use super::secret_marks::{
    RepoBlobAddress, RepoBlobMarks, RepoMarkFacts, RepoSecretMarkLookup, add_place,
};
use crate::Vault;
use crate::batch::secret_scan::project_marked_retained_repo_blob;
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::git_wire::GitOid;
use crate::secret_custody::masked_file_in_txn;

/// Who a repo read serves, as the door that admitted it binds it. Every
/// arm but [`Self::Masked`] holds a proof its door already judged; none is
/// built from caller input.
#[allow(
    dead_code,
    reason = "each exact arm carries its proof as a witness; GrantedFile and ExactSource are \
              FIX 7608 slice 2a vocabulary, wired by later slices"
)]
pub(crate) enum RepoSecretAudience<'a> {
    /// The owner at the owner's own door: the stored bytes.
    HumanOwner(&'a AuthenticatedOwner),
    /// A run, an agent, a model or an MCP tool: the projection.
    Masked,
    /// A committed real-byte file reveal: the stored bytes.
    GrantedFile(&'a RepoGrantedFileProof),
    /// A proved export back to the original source: the stored bytes.
    ExactSource(&'a ExactSourceExportProof),
}

impl RepoSecretAudience<'_> {
    /// Whether this audience reads stored bytes, with no mark looked up.
    pub(crate) const fn reads_exact(&self) -> bool {
        !matches!(self, Self::Masked)
    }
}

/// What one read of one repo blob returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RepoBodyProjection {
    /// The stored bytes: no mark, or an exact audience.
    Exact(Vec<u8>),
    /// The stored blob `source_blob` with each marked span overwritten.
    Masked { bytes: Vec<u8>, source_blob: GitOid },
    /// The placeholder, for residue no span isolates.
    Opaque(RepoOpaqueFile),
}

impl RepoBodyProjection {
    /// The reply descriptor of a projected read; `None` for stored bytes,
    /// whose reply is today's.
    pub(crate) fn view(&self) -> Option<RepoFileProjectionView> {
        match self {
            Self::Exact(_) => None,
            Self::Masked { bytes, source_blob } => Some(RepoFileProjectionView::of(
                RepoFileProjectionKind::Masked,
                source_blob,
                bytes,
            )),
            Self::Opaque(file) => Some(RepoFileProjectionView::of(
                RepoFileProjectionKind::Opaque,
                &file.source_blob,
                REPO_OPAQUE_FILE_BYTES,
            )),
        }
    }

    /// The returned bytes.
    pub(crate) fn into_bytes(self) -> Vec<u8> {
        match self {
            Self::Exact(bytes) | Self::Masked { bytes, .. } => bytes,
            Self::Opaque(_) => REPO_OPAQUE_FILE_BYTES.to_vec(),
        }
    }
}

/// The blob `marks` names, as `audience` reads it. An exact audience, and
/// any audience of an unmarked blob, reads `read_exact()` as it is; a masked
/// reader of opaque residue gets the placeholder before anything is read.
///
/// # Errors
/// `read_exact`'s own, or a store failure.
pub(crate) fn project_repo_blob<F: FnOnce() -> Result<Vec<u8>>>(
    vault: &Vault,
    marks: &RepoBlobMarks,
    audience: &RepoSecretAudience<'_>,
    read_exact: F,
) -> Result<RepoBodyProjection> {
    // A granted file proof opens only the ORIGINAL it was committed for:
    // any other blob reads as a masked reader's (FIX 7608 2b-ii).
    let exact = match audience {
        RepoSecretAudience::GrantedFile(proof) => {
            proof.covers(marks.source_blob(), marks.raw_blake3())
        }
        _ => audience.reads_exact(),
    };
    if exact || marks.is_empty() {
        return read_exact().map(RepoBodyProjection::Exact);
    }
    if let (true, Some(source_blob)) = (marks.opaque(), marks.source_blob()) {
        return Ok(RepoBodyProjection::Opaque(RepoOpaqueFile {
            source_blob: source_blob.clone(),
        }));
    }
    let bytes = read_exact()?;
    let txn = vault.store.env.read_txn()?;
    project_repo_bytes_in_txn(vault, &txn, marks, bytes)
}

/// `bytes`, read whole from the blob `marks` names, as a masked reader
/// reads them in `txn`: the stored bytes when nothing marks them, the
/// masked copy when every span rebuilds clean, the placeholder otherwise.
/// Bytes that are not the marked blob's own (its BLAKE3) are opaque.
///
/// # Errors
/// A store failure.
pub(crate) fn project_repo_bytes_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    marks: &RepoBlobMarks,
    bytes: Vec<u8>,
) -> Result<RepoBodyProjection> {
    let Some(source_blob) = marks.source_blob().cloned() else {
        return Ok(RepoBodyProjection::Exact(bytes));
    };
    let hash = *blake3::hash(&bytes).as_bytes();
    let copy = if marks.opaque() || marks.raw_blake3() != Some(hash) {
        None
    } else {
        // The marks' spans, and any the stored blob's mask row holds beside
        // them (a value custody came to know later, FIX 2781).
        let mut places = marks.places();
        if let Some(row) = masked_file_in_txn(&vault.store, txn, &hash)? {
            for (member, spans) in row.places() {
                for span in spans {
                    add_place(&mut places, &member, span);
                }
            }
        }
        project_marked_retained_repo_blob(&bytes, &places)
    };
    Ok(match copy {
        Some(bytes) => RepoBodyProjection::Masked { bytes, source_blob },
        None => RepoBodyProjection::Opaque(RepoOpaqueFile { source_blob }),
    })
}

/// A tree's files as one audience reads them, path by path.
#[derive(Debug)]
pub(crate) struct RepoMaterializedCopy {
    files: BTreeMap<String, RepoBodyProjection>,
}

impl RepoMaterializedCopy {
    /// How each projected path's bytes differ from its stored blob (FIX
    /// 8965); a path holding its stored bytes has none.
    pub(crate) fn projections(&self) -> BTreeMap<String, RepoFileProjectionView> {
        self.files
            .iter()
            .filter_map(|(path, body)| Some((path.clone(), body.view()?)))
            .collect()
    }

    /// Each path's returned bytes: what a materializer copies and hashes.
    pub(crate) fn into_contents(self) -> BTreeMap<String, Vec<u8>> {
        self.files
            .into_iter()
            .map(|(path, body)| (path, body.into_bytes()))
            .collect()
    }
}

/// `files`, a tree's already selected paths with their stored bytes, as
/// `audience` reads them: the marks are found in one walk for the whole
/// tree, each file joined to them by its bytes' BLAKE3. An exact audience,
/// or a tree nothing marks, keeps every file's stored bytes.
///
/// # Errors
/// A store failure, or a mark that does not decode.
pub(crate) fn materialize_masked_repo(
    vault: &Vault,
    files: BTreeMap<String, Vec<u8>>,
    audience: &RepoSecretAudience<'_>,
) -> Result<RepoMaterializedCopy> {
    let exact = |files: BTreeMap<String, Vec<u8>>| RepoMaterializedCopy {
        files: files
            .into_iter()
            .map(|(path, bytes)| (path, RepoBodyProjection::Exact(bytes)))
            .collect(),
    };
    if audience.reads_exact() {
        return Ok(exact(files));
    }
    let txn = vault.store.env.read_txn()?;
    let facts = RepoMarkFacts::read_in_txn(vault, &txn, RepoSecretMarkLookup::ReadableClaims)?;
    if facts.is_empty() {
        return Ok(exact(files));
    }
    let mut out = BTreeMap::new();
    for (path, bytes) in files {
        let marks = facts.for_hash(blake3::hash(&bytes).as_bytes());
        out.insert(path, project_repo_bytes_in_txn(vault, &txn, &marks, bytes)?);
    }
    Ok(RepoMaterializedCopy { files: out })
}

/// The hold lines a Granted agent's export preview gets for marked blobs
/// (CALL N, G4 tie-in): one per leaf of either pinned tree whose blob a
/// readable mark names, in the served store `store_identity` or under the
/// same bytes, opaque residue included. Nothing of a leaf is read here and
/// nothing is masked: the preview stays exact or held. The owner's arm
/// never calls this.
///
/// # Errors
/// A store failure, or a mark that does not decode.
pub(crate) fn repo_mark_preview_blockers_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    store_identity: &str,
    before: &BTreeMap<String, PinnedLeaf>,
    after: &BTreeMap<String, PinnedLeaf>,
) -> Result<Vec<CodeExportPreviewBlocker>> {
    let facts = RepoMarkFacts::read_in_txn(vault, txn, RepoSecretMarkLookup::ReadableClaims)?;
    if facts.is_empty() {
        return Ok(Vec::new());
    }
    let store = lfs_repo_id(store_identity)?;
    let mut blockers = Vec::new();
    for (side, leaves) in [
        (CodeExportSide::Before, before),
        (CodeExportSide::After, after),
    ] {
        for (path, leaf) in leaves {
            let addressed = GitOid::parse_hex(leaf.blob.git_oid.clone())
                .is_ok_and(|blob| !facts.for_blob(&RepoBlobAddress { store, blob }).is_empty());
            if addressed || !facts.for_hash(&leaf.blob.content_hash).is_empty() {
                blockers.push(CodeExportPreviewBlocker::new(
                    CodeExportBlockingSource::File {
                        side,
                        path: path.clone(),
                        entity: None,
                    },
                    CodeExportPreviewBlockReason::Masked,
                    "your credential reads a masked copy of this file, not its exact bytes",
                    "Have an Owner read this preview, or obtain a secret read grant covering this \
                     file's keys; a masked copy is never released as exact.",
                ));
            }
        }
    }
    Ok(blockers)
}
