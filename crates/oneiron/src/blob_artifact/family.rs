//! The artifact family contract (ARCH-0078): every deliverable is an
//! artifact, and every kind gives the same verbs. A blob artifact's versions,
//! their made_by receipts, born-from, export and serving read the same way for
//! a document, a sheet, a deck or an image; bodies and fidelity rules stay per
//! kind. This module names the kinds and reads the contract's common views.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::edit_roundtrip::OfficeFormat;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::provenance::made_by::MadeBy;
use crate::registry::{ENTITY_TYPE_BLOB_ARTIFACT, ENTITY_TYPE_CODE_ARTIFACT};

use super::born_from::BornFromSource;
use super::store_keys::BLOB_ARTIFACT_CONTENT_HASH_LEN;
use super::versions::BlobArtifactVersion;

/// One kind of the artifact family. A kind is a body plus its fidelity rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
        }
    }
}

/// One blob artifact as the family contract shows it: its kind, its body's
/// name and type, its head, and its whole version tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactView {
    pub artifact_id: EntityId,
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
        Ok(Some(ArtifactView {
            artifact_id: *id,
            kind: ArtifactKind::of_media_type(&body.media_type),
            name: body.name,
            media_type: body.media_type,
            head: versions.last().map(|version| version.version),
            versions: versions.iter().map(ArtifactVersionView::from).collect(),
        }))
    }

    /// Exports one version as a file: `version` or the head when `None`. The
    /// record is bound to its ledger claim and the bytes to its content hash.
    pub fn export_blob_artifact(
        &self,
        id: &EntityId,
        version: Option<u64>,
    ) -> Result<Option<ArtifactExport>> {
        let version = match version {
            Some(version) => version,
            None => match self.blob_artifact_head(id)? {
                Some(head) => head.version,
                None => return Ok(None),
            },
        };
        let Some(record) = self.blob_artifact_version_metadata(id, version)? else {
            return Ok(None);
        };
        let bytes = self
            .read_blob_artifact_version(id, version)?
            .ok_or(Error::EntityNotFound)?;
        if blake3::hash(&bytes).as_bytes() != &record.content_hash {
            return Err(Error::CorruptedIndex("blob content hash"));
        }
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

    /// Keeps the travel receipt `vault.artifacts.export` keeps (OF-491) for
    /// a copy a download door served: the copy, its digest and who took it.
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
            hash_hex(&file.content_hash),
            by,
            &crate::share_travel::BornWith::new(),
        )
    }
}

pub(crate) fn hash_hex(hash: &[u8; 32]) -> String {
    blake3::Hash::from_bytes(*hash).to_hex().to_string()
}
