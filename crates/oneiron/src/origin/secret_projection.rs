//! Who reads a marked repo blob's real bytes (FIX 7608 slice 2a, owner
//! ruling SECRETS-IN-REPOS = A, ASK 1).
//!
//! History stays exact: the stored blob never changes. A reader is served
//! by its audience, which only a door's own admission chooses, never a
//! request field: the owner's own doors, a committed real-byte file reveal
//! and a proved original-source export read the stored bytes; every reader
//! the host knows to be a run, an agent, a model or an MCP tool reads the
//! projection. A blob no mark names, whose mask row holds nothing and in
//! which no value custody knows now appears, is the stored bytes for every
//! audience, with no reveal, disk write or reply field added. A read that
//! owns its snapshot checks the blob against the values custody knows now
//! (FIX 8966), so a value learned after the blob was stored is masked even
//! in a Git-only blob no sweep walks.
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
pub(crate) use oneiron_store::origin::secret_projection::copy_id;
pub(crate) mod disposal;
pub(crate) mod edit;
pub(crate) mod git;
pub(crate) mod graph_objects;
pub(crate) mod index;
pub(crate) mod recipient;
pub(crate) mod reveal;
pub(crate) mod selector_release;
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
use crate::batch::secret_scan::{
    RepoKnownCheck, project_marked_retained_repo_blob, retained_repo_known_places,
};
use crate::code_document::CodeDocumentFrontier;
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::git_wire::GitOid;
use crate::secret_record::RepoFileKeys;
use crate::store::file_key_masks::masked_file_in_txn;
use crate::store::known_value_index::KnownValues;

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

/// The blob `marks` names, as `audience` reads it. An exact audience reads
/// `read_exact()` as it is; a masked reader of opaque residue gets the
/// placeholder before anything is read. Any other masked reader reads the
/// bytes as [`project_repo_bytes_in_txn`] projects them against the values
/// custody knows now (FIX 8966), so a blob no mark names is checked too.
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
    if exact {
        return read_exact().map(RepoBodyProjection::Exact);
    }
    if let (true, Some(source_blob)) = (marks.opaque(), marks.source_blob()) {
        return Ok(RepoBodyProjection::Opaque(RepoOpaqueFile {
            source_blob: source_blob.clone(),
        }));
    }
    let bytes = read_exact()?;
    vault.with_known_snapshot(|known, txn| {
        project_repo_bytes_in_txn(vault, txn, marks, bytes, known)
    })
}

/// `bytes`, read whole from the blob `marks` names, as a masked reader
/// reads them in `txn`: the stored bytes when nothing marks them, the
/// masked copy when every span rebuilds clean, the placeholder otherwise.
/// Bytes that are not the marked blob's own (its BLAKE3) are opaque.
///
/// The spans are the marks', any the stored blob's mask row holds beside
/// them (a value custody came to know later, FIX 2781), and, with `known`,
/// each value custody knows now in the blob's own bytes or any member
/// (FIX 8966): a blob no mark names, such as a Git-only blob the lift sweep
/// never walks, is masked by what custody knows all the same, under the
/// Git id of its own bytes. `known` is the matcher of a pass the caller
/// holds ([`Vault::with_known_values`]); `None` checks the stored spans
/// alone.
///
/// # Errors
/// A store failure.
pub(crate) fn project_repo_bytes_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    marks: &RepoBlobMarks,
    bytes: Vec<u8>,
    known: Option<&KnownValues>,
) -> Result<RepoBodyProjection> {
    let hash = *blake3::hash(&bytes).as_bytes();
    if let Some(source_blob) = marks.source_blob()
        && (marks.opaque() || marks.raw_blake3() != Some(hash))
    {
        return Ok(RepoBodyProjection::Opaque(RepoOpaqueFile {
            source_blob: source_blob.clone(),
        }));
    }
    let mut places = marks.places();
    if let Some(row) = masked_file_in_txn(&vault.store, txn, &hash)? {
        for (member, spans) in row.places() {
            for span in spans {
                add_place(&mut places, &member, span);
            }
        }
    }
    let check = match known {
        Some(known) => Some(RepoKnownCheck::for_blob_in_txn(vault, txn, known, &hash)?),
        None => None,
    };
    if let Some(check) = &check {
        places = retained_repo_known_places(&bytes, check, &places)?;
    }
    // A known value no place covers (a container's own bytes, such as a ZIP
    // entry's name) leaves no copy to make: the blob is opaque.
    let unplaced = match &check {
        Some(check) if places.is_empty() => check.reads_known(&bytes)?,
        _ => false,
    };
    if places.is_empty() && !unplaced {
        return Ok(RepoBodyProjection::Exact(bytes));
    }
    let source_blob = match marks.source_blob() {
        Some(source_blob) => source_blob.clone(),
        None => git_blob_oid(&bytes)?,
    };
    if unplaced {
        return Ok(RepoBodyProjection::Opaque(RepoOpaqueFile { source_blob }));
    }
    Ok(
        match project_marked_retained_repo_blob(&bytes, &places, check.as_ref()) {
            Some(bytes) => RepoBodyProjection::Masked { bytes, source_blob },
            None => RepoBodyProjection::Opaque(RepoOpaqueFile { source_blob }),
        },
    )
}

/// The keys a release of `bytes`, the stored bytes of the marked repo file
/// `marks` names, shows (FIX 8966): its marks' custody and residue, and,
/// with `known`, each custody record past them whose value custody knows
/// reads in `bytes`, its own and every member's. Value-free: a grant must
/// cover every class among them before the stored bytes go out, so a value
/// learned after a grant leaves the file masked.
///
/// # Errors
/// A store failure, or a walk failure.
pub(crate) fn repo_file_keys_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    marks: &RepoBlobMarks,
    bytes: &[u8],
    known: Option<&KnownValues>,
) -> Result<RepoFileKeys> {
    let mut custody = marks.custody();
    if let Some(known) = known {
        let hash = *blake3::hash(bytes).as_bytes();
        let check = RepoKnownCheck::for_blob_in_txn(vault, txn, known, &hash)?;
        for holder in check.holders(bytes)? {
            if !custody.contains(&holder) {
                custody.push(holder);
            }
        }
    }
    Ok(RepoFileKeys {
        custody,
        opaque: marks.opaque(),
    })
}

/// The Git blob id of `bytes`: SHA-1 over the blob header and the bytes,
/// what a masked copy of a blob no mark names is described by (FIX 8966).
fn git_blob_oid(bytes: &[u8]) -> Result<GitOid> {
    let mut hasher = gix::hash::hasher(gix::hash::Kind::Sha1);
    hasher.update(format!("blob {}\0", bytes.len()).as_bytes());
    hasher.update(bytes);
    let oid = hasher
        .try_finalize()
        .map_err(|_| crate::error::Error::CorruptedIndex("masked repo blob hash"))?;
    Ok(GitOid::parse_hex(oid.to_string())?)
}

/// The placeholder a masked reader reads for `bytes`, a code document
/// state's text, when that text grew from a marked repo blob it no longer is
/// (FIX 8967): an edit of a marked file, or any later state of it. A mark
/// is placed on the marked blob's own bytes and cannot be mapped onto edited
/// text, so the text is opaque, never raw and never refused. `None` when
/// `bytes` read by their own marks as before: they are a marked blob's, a
/// stored repo blob's (its snapshot ASSET is held, so the receive read
/// judged it), or grew from nothing marked. `sources` gives the BLAKE3 of
/// each text the state grew from, proved from its own history; it is read
/// only when the rest does not decide.
///
/// # Errors
/// A store failure, or `sources`' own.
pub(crate) fn sourced_opaque_in_txn<F>(
    vault: &Vault,
    txn: &RoTxn<'_>,
    facts: &RepoMarkFacts,
    bytes: &[u8],
    sources: F,
) -> Result<Option<RepoOpaqueFile>>
where
    F: FnOnce() -> Result<Vec<[u8; 32]>>,
{
    let hash = *blake3::hash(bytes).as_bytes();
    if facts.is_empty() || !facts.for_hash(&hash).is_empty() {
        return Ok(None);
    }
    let asset = crate::codebase::snapshot_asset_entity_id(&hash)?;
    if vault.get_entity_type_in_txn(txn, &asset)? == Some(crate::registry::ENTITY_TYPE_ASSET) {
        return Ok(None);
    }
    for source in sources()? {
        if let Some(source_blob) = facts.for_hash(&source).source_blob() {
            return Ok(Some(RepoOpaqueFile {
                source_blob: source_blob.clone(),
            }));
        }
    }
    Ok(None)
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
/// tree, each file joined to them by its bytes' BLAKE3 and checked against
/// the values custody knows now (FIX 8966). An exact audience keeps every
/// file's stored bytes, and so does a file nothing marks or holds.
///
/// # Errors
/// A store failure, or a mark that does not decode.
pub(crate) fn materialize_masked_repo(
    vault: &Vault,
    files: BTreeMap<String, Vec<u8>>,
    audience: &RepoSecretAudience<'_>,
) -> Result<RepoMaterializedCopy> {
    materialize_masked_repo_sourced(vault, files, &BTreeMap::new(), audience)
}

/// [`materialize_masked_repo`] for a tree some of whose files are code
/// document states (FIX 8967): a path `documents` names reads as
/// [`sourced_opaque_in_txn`] reads it, by the history of that state, before
/// its own bytes are joined to the marks.
///
/// # Errors
/// As [`materialize_masked_repo`], or a stored document state that does
/// not check.
pub(crate) fn materialize_masked_repo_sourced(
    vault: &Vault,
    files: BTreeMap<String, Vec<u8>>,
    documents: &BTreeMap<String, CodeDocumentFrontier>,
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
    // One known-value pass for the whole tree (FIX 8966): a file no mark
    // names, such as a blob `work.open` captured from Git that no sweep
    // walks, is checked against the values custody knows now all the same.
    vault.with_known_snapshot(|known, txn| {
        let facts = RepoMarkFacts::read_in_txn(vault, txn, RepoSecretMarkLookup::ReadableClaims)?;
        let mut out = BTreeMap::new();
        for (path, bytes) in files {
            let sourced = match documents.get(&path) {
                Some(tested) => sourced_opaque_in_txn(vault, txn, &facts, &bytes, || {
                    vault.code_document_source_hashes_in_txn(txn, tested)
                })?,
                None => None,
            };
            let body = match sourced {
                Some(opaque) => RepoBodyProjection::Opaque(opaque),
                None => {
                    let marks = facts.for_hash(blake3::hash(&bytes).as_bytes());
                    project_repo_bytes_in_txn(vault, txn, &marks, bytes, known)?
                }
            };
            out.insert(path, body);
        }
        Ok(RepoMaterializedCopy { files: out })
    })
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
