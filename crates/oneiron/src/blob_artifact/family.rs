//! The artifact family contract (ARCH-0078): every deliverable is an
//! artifact, and every kind gives the same verbs. A blob artifact's versions,
//! their made_by receipts, born-from, export and serving read the same way for
//! a document, a sheet, a deck or an image; bodies and fidelity rules stay per
//! kind. This module names the kinds and reads the contract's common views.

use heed::RoTxn;
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::blob_artifact::office_address::OfficeFormat;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_BLOB_ARTIFACT, ENTITY_TYPE_CLAIM, ENTITY_TYPE_CODE_ARTIFACT};
use crate::store::record_ref::RecordRef;
use crate::write_envelope::provenance::made_by::MadeBy;

use super::born_from::BornFromSource;
use super::store_keys::BLOB_ARTIFACT_CONTENT_HASH_LEN;
use super::versions::BlobArtifactVersion;

/// One kind of the artifact family. A kind is a body plus its fidelity rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    /// docx and friends.
    Document,
    /// xlsx and xlsm.
    Sheet,
    /// pptx.
    Deck,
    /// A code tree (CODE_ARTIFACT); git is its export.
    Code,
    /// A design canvas.
    Canvas,
    /// A static image (the image organ's kind).
    Image,
    /// Any other exported file, kept as versions with no kind-specific body.
    File,
}

impl ArtifactKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Document => "document",
            Self::Sheet => "sheet",
            Self::Deck => "deck",
            Self::Code => "code",
            Self::Canvas => "canvas",
            Self::Image => "image",
            Self::File => "file",
        }
    }

    /// The kind a blob artifact's export media type names.
    #[must_use]
    pub fn of_media_type(media_type: &str) -> Self {
        match OfficeFormat::from_media_type(media_type) {
            Ok(OfficeFormat::Docx) => Self::Document,
            Ok(OfficeFormat::Xlsx) => Self::Sheet,
            Ok(OfficeFormat::Pptx) => Self::Deck,
            Err(_) => match media_type {
                "image/png" | "image/jpeg" | "image/webp" => Self::Image,
                _ => Self::File,
            },
        }
    }
}

/// One version as the family contract shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactVersionView {
    pub version: u64,
    pub content_hash: String,
    pub parent_version: Option<u64>,
    pub fork_of_version: Option<u64>,
    pub provenance: String,
    pub run_ref: Option<String>,
    pub created_at: u64,
    pub export_name: String,
    pub export_media_type: String,
    pub made_by: MadeBy,
    pub born_from: Vec<BornFromSource>,
    /// The version's `blob.version` LEDGER claim as a typed record ref
    /// (OF-063), built from its id with no read.
    pub claim: RecordRef,
}

impl From<&BlobArtifactVersion> for ArtifactVersionView {
    fn from(version: &BlobArtifactVersion) -> Self {
        Self {
            version: version.version,
            content_hash: hash_hex(&version.content_hash),
            parent_version: version.parent_version,
            fork_of_version: version.fork_of_version,
            provenance: version.provenance.as_str().to_owned(),
            run_ref: version.provenance.run_ref().map(str::to_owned),
            created_at: version.created_at,
            export_name: version.export_name.clone(),
            export_media_type: version.export_media_type.clone(),
            made_by: version.made_by.clone(),
            born_from: BornFromSource::of_version(version),
            claim: RecordRef::from_id(ENTITY_TYPE_CLAIM, &version.claim_id, None),
        }
    }
}

/// A version that landed while the artifact's head was a version it was not
/// made from (FIX 2700): it forked from the version it was made against,
/// and the head it replaced stays as its own version beside it, readable
/// and exportable as any other. Nothing of either is merged or lost.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionReconciliation {
    /// The version it was made against: its fork parent.
    pub base_version: u64,
    /// The head it replaced, kept beside it.
    pub kept_head: ArtifactVersionView,
}

impl VersionReconciliation {
    /// The reconciliation of a version forked from `base` over `head`, the
    /// head it replaced; none when it did not fork.
    #[must_use]
    pub fn of(base: Option<u64>, head: Option<&BlobArtifactVersion>) -> Option<Self> {
        Some(Self {
            base_version: base?,
            kept_head: ArtifactVersionView::from(head?),
        })
    }
}

/// Projects stored versions to the vault's current erase state after their
/// raw chain and claim bindings have been checked (FIX 9619).
fn artifact_version_views_erased(
    vault: &Vault,
    txn: &RoTxn<'_>,
    versions: &[BlobArtifactVersion],
) -> Result<Vec<ArtifactVersionView>> {
    versions
        .iter()
        .map(|version| {
            let projected = super::project_version_erased_in_txn(vault, txn, version)?;
            Ok(ArtifactVersionView::from(&projected))
        })
        .collect()
}

/// One blob artifact as the family contract shows it: its kind, its body's
/// name and type, its head, and its whole version tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactView {
    pub artifact_id: EntityId,
    /// The artifact as a typed record ref (OF-063, FIX 9340), built from its
    /// id with no read.
    pub artifact: RecordRef,
    pub kind: ArtifactKind,
    pub name: String,
    pub media_type: String,
    pub head: Option<u64>,
    pub versions: Vec<ArtifactVersionView>,
}

/// One version's export file (ARCH-0078 "Export"): the bytes a person takes
/// away, with the name and type pinned when the version was appended. The
/// export is a version, never the base.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactExport {
    pub artifact_id: EntityId,
    pub version: u64,
    pub kind: ArtifactKind,
    pub name: String,
    pub media_type: String,
    pub content_hash: [u8; BLOB_ARTIFACT_CONTENT_HASH_LEN],
    pub made_by: MadeBy,
    pub bytes: Vec<u8>,
}

impl Vault {
    /// The family kind of one artifact entity: `Code` for a code artifact, the
    /// export media type's kind for a blob artifact, `None` for any other row.
    pub fn artifact_kind(&self, id: &EntityId) -> Result<Option<ArtifactKind>> {
        match self.get_entity_type(id)? {
            Some(ENTITY_TYPE_CODE_ARTIFACT) => Ok(Some(ArtifactKind::Code)),
            Some(ENTITY_TYPE_BLOB_ARTIFACT) => Ok(self
                .get_blob_artifact(id)?
                .map(|body| ArtifactKind::of_media_type(&body.media_type))),
            _ => Ok(None),
        }
    }

    /// The family view of one blob artifact, or `None` when it does not exist.
    pub fn blob_artifact_view(&self, id: &EntityId) -> Result<Option<ArtifactView>> {
        let Some(body) = self.get_blob_artifact(id)? else {
            return Ok(None);
        };
        let versions = self.blob_artifact_versions(id)?;
        let txn = self.store.env.read_txn()?;
        Ok(Some(ArtifactView {
            artifact_id: *id,
            artifact: RecordRef::from_id(ENTITY_TYPE_BLOB_ARTIFACT, id, None),
            kind: ArtifactKind::of_media_type(&body.media_type),
            name: body.name,
            media_type: body.media_type,
            head: versions.last().map(|version| version.version),
            versions: artifact_version_views_erased(self, &txn, &versions)?,
        }))
    }

    /// [`Vault::blob_artifact_view`] for a reader held to the rows it may
    /// read (FIX 7645): `admit` is handed the artifact and every row its
    /// version tree shows, each version's CLAIM and its content's ASSET,
    /// before any of the view is read or projected, from the very records the
    /// view is then made of. A tree it does not admit whole reads as absent,
    /// as a missing artifact does.
    pub fn blob_artifact_view_admitted(
        &self,
        id: &EntityId,
        admit: impl FnOnce(&[EntityId]) -> Result<bool>,
    ) -> Result<Option<ArtifactView>> {
        let versions = self.blob_artifact_versions(id)?;
        if !admit(&super::version_rows::blob_tree_rows(id, &versions)?)? {
            return Ok(None);
        }
        let Some(body) = self.get_blob_artifact(id)? else {
            return Ok(None);
        };
        let txn = self.store.env.read_txn()?;
        Ok(Some(ArtifactView {
            artifact_id: *id,
            artifact: RecordRef::from_id(ENTITY_TYPE_BLOB_ARTIFACT, id, None),
            kind: ArtifactKind::of_media_type(&body.media_type),
            name: body.name,
            media_type: body.media_type,
            head: versions.last().map(|version| version.version),
            versions: artifact_version_views_erased(self, &txn, &versions)?,
        }))
    }

    /// Exports one version as a file: `version` or the head when `None`. The
    /// record is bound to its ledger claim and the bytes to its content hash.
    /// A DOCX copy shows its default author (FIX 4513), so `content_hash`
    /// names the copy, not the stored version (FIX 5491): a reader checking
    /// the bytes it got against it finds them.
    pub fn export_blob_artifact(
        &self,
        id: &EntityId,
        version: Option<u64>,
    ) -> Result<Option<ArtifactExport>> {
        let Some(mut file) = self.export_blob_artifact_raw(id, version)? else {
            return Ok(None);
        };
        file.bytes = self.resolve_docx_authors(std::mem::take(&mut file.bytes))?;
        file.content_hash = *blake3::hash(&file.bytes).as_bytes();
        Ok(Some(file))
    }

    /// [`Vault::export_blob_artifact`] with the stored bytes as they are, for
    /// a door that reads them before it serves a copy.
    pub(crate) fn export_blob_artifact_raw(
        &self,
        id: &EntityId,
        version: Option<u64>,
    ) -> Result<Option<ArtifactExport>> {
        let txn = self.store.env.read_txn()?;
        self.export_blob_artifact_read_in_txn(&txn, id, version, |record| {
            let bytes = self
                .read_blob_artifact_version_in_txn(&txn, id, record.version)?
                .ok_or(Error::EntityNotFound)?;
            if blake3::hash(&bytes).as_bytes() != &record.content_hash {
                return Err(Error::CorruptedIndex("blob content hash"));
            }
            Ok(bytes)
        })
    }

    /// One version's export in `txn`, its bytes as `read` reads them from the
    /// version's record (FIX 6507): `version`, or the head when `None`, its
    /// record bound to its ledger claim. A serving door's reader masks a body
    /// kept in its file as it reads it, so the stored bytes are never held
    /// whole beside the copy; the export's `content_hash` still names the
    /// stored version. `None` when the artifact has no such version.
    pub(crate) fn export_blob_artifact_read_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        version: Option<u64>,
        read: impl FnOnce(&BlobArtifactVersion) -> Result<Vec<u8>>,
    ) -> Result<Option<ArtifactExport>> {
        let version = match version {
            Some(version) => version,
            None => match super::read_blob_artifact_head_in_txn(&self.store, txn, id)? {
                Some(head) => head.version,
                None => return Ok(None),
            },
        };
        let Some(record) = self.blob_artifact_version_metadata_in_txn(txn, id, version)? else {
            return Ok(None);
        };
        let bytes = read(&record)?;
        let record = super::project_version_erased_in_txn(self, txn, &record)?;
        Ok(Some(ArtifactExport {
            artifact_id: *id,
            version,
            kind: ArtifactKind::of_media_type(&record.export_media_type),
            name: record.export_name,
            media_type: record.export_media_type,
            content_hash: record.content_hash,
            made_by: record.made_by,
            bytes,
        }))
    }

    /// The family view of one blob artifact for a reader (FIX 7227): the
    /// same view [`Vault::blob_artifact_view`] shows, fenced only when a
    /// retained version is a queue-check version. With `Some(lane)` the view
    /// is read under the lane's `read_projected` snapshot (body pins plus
    /// grant clock) and its `.value` is returned; with `None` it is read
    /// under a native read transaction. A protected artifact with no owner
    /// proof or no lane reads as absent, as a missing artifact does.
    pub fn blob_artifact_view_for_reader(
        &self,
        id: &EntityId,
        owner: Option<&crate::consent::AuthenticatedOwner>,
        lane: Option<&crate::claim::ScopedRead<'_>>,
    ) -> Result<Option<ArtifactView>> {
        if let Some(lane) = lane {
            Ok(lane
                .read_projected(&[], None, |txn, _| {
                    self.blob_artifact_view_for_reader_in_txn(txn, id, owner, Some(lane), false)
                })?
                .value)
        } else {
            let txn = self.store.env.read_txn()?;
            self.blob_artifact_view_for_reader_in_txn(&txn, id, owner, None, false)
        }
    }

    /// The public reader view with the existing whole-tree record-caveat
    /// admission, checked before projection in the same snapshot.
    pub fn blob_artifact_view_admitted_for_reader(
        &self,
        id: &EntityId,
        owner: Option<&crate::consent::AuthenticatedOwner>,
        lane: &crate::claim::ScopedRead<'_>,
    ) -> Result<Option<ArtifactView>> {
        Ok(lane
            .read_projected(&[], None, |txn, _| {
                self.blob_artifact_view_for_reader_in_txn(txn, id, owner, Some(lane), true)
            })?
            .value)
    }

    /// [`Vault::blob_artifact_view_for_reader`] in the caller's snapshot:
    /// the real body first, then the real versions, then the same
    /// [`ArtifactView`] the trusted view builds, with no copied ledger and
    /// no extra transaction. Any retained
    /// [`BlobVersionProvenance::QueueCheck`](crate::blob_artifact::BlobVersionProvenance::QueueCheck)
    /// version protects the whole tree: its owner proof is revalidated in
    /// this same snapshot and its artifact id must read under the lane's
    /// original frozen artifact scope, with no shared-hash ASSET narrowing.
    /// An ordinary artifact ignores the proof and scope gates.
    fn blob_artifact_view_for_reader_in_txn(
        &self,
        txn: &RoTxn<'_>,
        id: &EntityId,
        owner: Option<&crate::consent::AuthenticatedOwner>,
        lane: Option<&crate::claim::ScopedRead<'_>>,
        admit_version_rows: bool,
    ) -> Result<Option<ArtifactView>> {
        let Some(body) = self.get_blob_artifact_in_txn(txn, id)? else {
            return Ok(None);
        };
        let versions = self.blob_artifact_versions_in_txn(txn, id)?;
        let protected = versions.iter().any(|version| {
            matches!(
                version.provenance,
                crate::blob_artifact::BlobVersionProvenance::QueueCheck { .. }
            )
        });
        if protected {
            let (Some(owner), Some(lane)) = (owner, lane) else {
                return Ok(None);
            };
            owner.revalidate_in_txn(self, txn)?;
            let readable = lane.entities_readable_in_txn(txn, &[*id])?;
            if !readable.iter().all(|admitted| *admitted) {
                return Ok(None);
            }
        }
        if admit_version_rows {
            let Some(lane) = lane else {
                return Ok(None);
            };
            let rows = super::version_rows::blob_tree_rows(id, &versions)?;
            let readable = match lane.entities_readable_in_txn(txn, &rows) {
                Err(error) if error.kind() == crate::ErrorKind::InvalidSecretCustodyBody => {
                    return Ok(None);
                }
                readable => readable?,
            };
            if !readable.into_iter().all(|readable| readable) {
                return Ok(None);
            }
        }
        Ok(Some(ArtifactView {
            artifact_id: *id,
            artifact: RecordRef::from_id(ENTITY_TYPE_BLOB_ARTIFACT, id, None),
            kind: ArtifactKind::of_media_type(&body.media_type),
            name: body.name,
            media_type: body.media_type,
            head: versions.last().map(|version| version.version),
            versions: artifact_version_views_erased(self, txn, &versions)?,
        }))
    }

    /// Whether exactly `version` of `id` is a queue-check version (FIX 7227),
    /// from its metadata and native claim binding in its own snapshot. This
    /// is only the immutable version precheck for the actual sighted
    /// consumer; it is not the authority check, which
    /// [`Vault::export_blob_artifact_for_reader`] revalidates with the
    /// actual version and owner inside the actual read transaction. A
    /// missing version reads as not a queue-check version.
    pub(crate) fn blob_artifact_version_is_queue_check(
        &self,
        id: &EntityId,
        version: u64,
    ) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        let Some(record) = self.blob_artifact_version_metadata_in_txn(&txn, id, version)? else {
            return Ok(false);
        };
        Ok(matches!(
            record.provenance,
            crate::blob_artifact::BlobVersionProvenance::QueueCheck { .. }
        ))
    }

    /// [`Vault::export_blob_artifact`] for a reader (FIX 7227): one version's
    /// bytes as `sight` reads them, `version` or the head read once when
    /// `None`. With `Some(lane)` the export is read under the lane's
    /// `read_projected` snapshot and its `.value` is returned; with `None`
    /// it is read under a native read transaction. Exactly a queue-check
    /// version needs the same owner proof plus artifact-scope gate as the
    /// reader view; an ordinary version needs no extra gate. The DOCX author
    /// is resolved after the transaction, as the sighted export does, and
    /// `content_hash` still names the stored version.
    pub fn export_blob_artifact_for_reader(
        &self,
        id: &EntityId,
        version: Option<u64>,
        sight: crate::file_secret_marks::SecretSight,
        owner: Option<&crate::consent::AuthenticatedOwner>,
        lane: Option<&crate::claim::ScopedRead<'_>>,
    ) -> Result<Option<ArtifactExport>> {
        let file = if let Some(lane) = lane {
            lane.read_projected(&[], None, |txn, _| {
                self.export_blob_artifact_for_reader_in_txn(
                    txn,
                    id,
                    version,
                    sight,
                    owner,
                    Some(lane),
                )
            })?
            .value
        } else {
            let txn = self.store.env.read_txn()?;
            self.export_blob_artifact_for_reader_in_txn(&txn, id, version, sight, owner, None)?
        };
        let Some(mut file) = file else {
            return Ok(None);
        };
        file.bytes = self.resolve_docx_authors(std::mem::take(&mut file.bytes))?;
        Ok(Some(file))
    }

    /// [`Vault::export_blob_artifact_for_reader`] in the caller's snapshot:
    /// the head read once when `version` is `None`, then the exact version's
    /// metadata, then its owner plus artifact-scope gate when that version
    /// is a queue-check version, then the existing
    /// [`Vault::export_blob_artifact_read_in_txn`] read with the existing
    /// sighted-bytes closure. The metadata read inside that existing call is
    /// the same snapshot's second read of the same record, not a new version
    /// algorithm. Bytes, sight, deletion, compaction, hash and erase behave
    /// as the existing export does.
    fn export_blob_artifact_for_reader_in_txn(
        &self,
        txn: &RoTxn<'_>,
        id: &EntityId,
        version: Option<u64>,
        sight: crate::file_secret_marks::SecretSight,
        owner: Option<&crate::consent::AuthenticatedOwner>,
        lane: Option<&crate::claim::ScopedRead<'_>>,
    ) -> Result<Option<ArtifactExport>> {
        let pinned = match version {
            Some(version) => version,
            None => match super::read_blob_artifact_head_in_txn(&self.store, txn, id)? {
                Some(head) => head.version,
                None => return Ok(None),
            },
        };
        let Some(record) = self.blob_artifact_version_metadata_in_txn(txn, id, pinned)? else {
            return Ok(None);
        };
        let protected = matches!(
            record.provenance,
            crate::blob_artifact::BlobVersionProvenance::QueueCheck { .. }
        );
        if protected {
            let (Some(owner), Some(lane)) = (owner, lane) else {
                return Ok(None);
            };
            owner.revalidate_in_txn(self, txn)?;
            let readable = lane.entities_readable_in_txn(txn, &[*id])?;
            if !readable.iter().all(|admitted| *admitted) {
                return Ok(None);
            }
        }
        self.export_blob_artifact_read_in_txn(txn, id, Some(pinned), |record| {
            self.read_blob_artifact_version_sighted_in_txn(txn, id, record.version, sight)?
                .ok_or(Error::EntityNotFound)
        })
    }

    /// Keeps the travel receipt `vault.artifacts.export` keeps (OF-491) for
    /// a copy a download door served: the copy, its digest and who took it.
    /// The digest names the copy as served (FIX 5491): a sighted copy's
    /// bytes may have been masked or had their DOCX author resolved after
    /// the stored version's hash was taken.
    /// No born-with text leaves a download, so it is never gated on this.
    ///
    /// # Errors
    /// Never for a lost receipt: one with nothing travelling only warns.
    pub fn record_blob_artifact_download(
        &self,
        file: &ArtifactExport,
        by: &EntityId,
    ) -> Result<()> {
        self.record_export_travel(
            file.artifact_id.to_hex(),
            file.version,
            hash_hex(blake3::hash(&file.bytes).as_bytes()),
            by,
            &oneiron_authority::share_travel::BornWith::new(),
        )
    }
}

pub(crate) fn hash_hex(hash: &[u8; 32]) -> String {
    blake3::Hash::from_bytes(*hash).to_hex().to_string()
}
