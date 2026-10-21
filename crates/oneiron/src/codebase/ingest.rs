//! Local-git ingest helpers: blob walk, hosted-media gate, custody scan, and validators.

use super::snapshot::{
    CODEBASE_CONTENT_HASH_LEN, CODEBASE_FILE_PATH_MAX_BYTES, CODEBASE_PROJECT_ID_MAX_BYTES,
    CodebaseSnapshot, validate_bounded_text,
};
use super::store::codebase_asset_entity_id;
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, secret_scan};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{CodeError, Error, Result};
use crate::registry::ENTITY_TYPE_ASSET;
use crate::secret_custody::SecretSight;
use gix::bstr::ByteSlice;
use gix::object::tree::EntryKind;
use std::fmt;
use std::io::Read;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RepoIngestConfig {
    pub repo_path: PathBuf,
    pub editable_whitelist: Vec<String>,
}

impl RepoIngestConfig {
    pub fn new(
        repo_path: impl Into<PathBuf>,
        editable_whitelist: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self> {
        let editable_whitelist = editable_whitelist
            .into_iter()
            .map(Into::into)
            .map(|path| {
                validate_manifest_path(&path)?;
                Ok(path)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            repo_path: repo_path.into(),
            editable_whitelist,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RepoIngestResult {
    pub code_artifact_id: EntityId,
    pub snapshot: CodebaseSnapshot,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct HostedMediaHashMatchInput<'a> {
    pub project_id: &'a str,
    pub path: &'a str,
    pub media_type: &'static str,
    pub content_hash: [u8; CODEBASE_CONTENT_HASH_LEN],
    pub size_bytes: u64,
    pub bytes: &'a [u8],
}

impl fmt::Debug for HostedMediaHashMatchInput<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostedMediaHashMatchInput")
            .field("project_id", &self.project_id)
            .field("path", &self.path)
            .field("media_type", &self.media_type)
            .field("content_hash", &bytes_to_hex_lower(&self.content_hash))
            .field("size_bytes", &self.size_bytes)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HostedMediaHashMatchDecision {
    NoMatch,
    KnownMatch { provider: String, reference: String },
}

pub trait HostedMediaHashMatchProvider {
    fn check_hosted_media(
        &self,
        input: HostedMediaHashMatchInput<'_>,
    ) -> Result<HostedMediaHashMatchDecision>;
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoopHostedMediaHashMatchProvider;

impl HostedMediaHashMatchProvider for NoopHostedMediaHashMatchProvider {
    fn check_hosted_media(
        &self,
        _input: HostedMediaHashMatchInput<'_>,
    ) -> Result<HostedMediaHashMatchDecision> {
        Ok(HostedMediaHashMatchDecision::NoMatch)
    }
}

pub(super) struct RepoIngestBlob {
    pub(super) path: String,
    pub(super) content_hash: [u8; CODEBASE_CONTENT_HASH_LEN],
    pub(super) size_bytes: u64,
    pub(super) data: Vec<u8>,
    /// The entry's exact Git mode; a link is its target text, never read
    /// through (FIX 6869).
    pub(super) mode: u32,
}

pub(super) fn check_hosted_media_hash_matches(
    project_id: &str,
    blobs: &[RepoIngestBlob],
    provider: &(impl HostedMediaHashMatchProvider + ?Sized),
) -> Result<()> {
    for blob in blobs {
        let Some(media_type) = hosted_media_type_for_blob(&blob.path, &blob.data) else {
            continue;
        };
        let decision = provider.check_hosted_media(HostedMediaHashMatchInput {
            project_id,
            path: &blob.path,
            media_type,
            content_hash: blob.content_hash,
            size_bytes: blob.size_bytes,
            bytes: &blob.data,
        })?;
        match decision {
            HostedMediaHashMatchDecision::NoMatch => {}
            HostedMediaHashMatchDecision::KnownMatch {
                provider,
                reference,
            } => {
                return Err(Error::Code(CodeError::HostedMediaHashMatchKnownMatch {
                    provider: provider.into_boxed_str(),
                    reference: reference.into_boxed_str(),
                    path: blob.path.clone().into_boxed_str(),
                    content_hash: Box::new(blob.content_hash),
                }));
            }
        }
    }
    Ok(())
}

pub(super) fn hosted_media_type_for_blob(path: &str, bytes: &[u8]) -> Option<&'static str> {
    sniff_hosted_media_type(bytes).or_else(|| hosted_media_type_for_path(path))
}

fn hosted_media_type_for_path(path: &str) -> Option<&'static str> {
    let (_, extension) = path.rsplit_once('.')?;
    if extension.eq_ignore_ascii_case("png") {
        Some("image/png")
    } else if extension.eq_ignore_ascii_case("jpg") || extension.eq_ignore_ascii_case("jpeg") {
        Some("image/jpeg")
    } else if extension.eq_ignore_ascii_case("gif") {
        Some("image/gif")
    } else if extension.eq_ignore_ascii_case("webp") {
        Some("image/webp")
    } else if extension.eq_ignore_ascii_case("avif") {
        Some("image/avif")
    } else if extension.eq_ignore_ascii_case("heic") {
        Some("image/heic")
    } else if extension.eq_ignore_ascii_case("heif") {
        Some("image/heif")
    } else if extension.eq_ignore_ascii_case("mp4") || extension.eq_ignore_ascii_case("m4v") {
        Some("video/mp4")
    } else if extension.eq_ignore_ascii_case("mov") {
        Some("video/quicktime")
    } else if extension.eq_ignore_ascii_case("webm") {
        Some("video/webm")
    } else {
        None
    }
}

fn sniff_hosted_media_type(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if bytes.len() >= 3 && bytes[0..3] == [0xff, 0xd8, 0xff] {
        Some("image/jpeg")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
        Some("image/webp")
    } else if let Some(media_type) = sniff_iso_bmff_media_type(bytes) {
        Some(media_type)
    } else if bytes.starts_with(b"\x1a\x45\xdf\xa3")
        && bytes[..bytes.len().min(64)]
            .windows(4)
            .any(|w| w == b"webm")
    {
        Some("video/webm")
    } else {
        None
    }
}

fn sniff_iso_bmff_media_type(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() < 12 || &bytes[4..8] != b"ftyp" {
        return None;
    }
    let box_len = u32::from_be_bytes(bytes[0..4].try_into().ok()?) as usize;
    if box_len < 12 {
        return None;
    }
    let scan_len = box_len.min(bytes.len()).min(128);
    let brands = bytes[8..scan_len].chunks_exact(4);
    let mut fallback_video = false;
    for brand in brands {
        match brand {
            b"avif" | b"avis" => return Some("image/avif"),
            b"heic" | b"heix" | b"hevc" | b"hevx" => return Some("image/heic"),
            b"heif" | b"mif1" | b"msf1" => return Some("image/heif"),
            b"qt  " => return Some("video/quicktime"),
            b"isom" | b"iso2" | b"mp41" | b"mp42" | b"m4v " | b"M4V " | b"avc1" | b"dash" => {
                fallback_video = true;
            }
            _ => {}
        }
    }
    fallback_video.then_some("video/mp4")
}

pub(super) fn collect_repo_blobs(
    tree: &gix::Tree<'_>,
    prefix: &str,
    out: &mut Vec<RepoIngestBlob>,
) -> Result<()> {
    for entry in tree.iter() {
        let entry = entry.map_err(|_| {
            Error::Code(CodeError::InvalidCodebaseSnapshotBody(
                "Git tree entry could not be decoded",
            ))
        })?;
        let filename = entry.filename().to_str().map_err(|_| {
            Error::Code(CodeError::InvalidCodebaseSnapshotBody(
                "Git tree path must be UTF-8",
            ))
        })?;
        let path = if prefix.is_empty() {
            filename.to_owned()
        } else {
            format!("{prefix}/{filename}")
        };
        match entry.kind() {
            EntryKind::Tree => {
                validate_manifest_path(&path)?;
                let subtree_object = entry.object().map_err(|_| {
                    Error::Code(CodeError::InvalidCodebaseSnapshotBody(
                        "Git subtree object could not be read",
                    ))
                })?;
                let subtree = subtree_object.try_into_tree().map_err(|_| {
                    Error::Code(CodeError::InvalidCodebaseSnapshotBody(
                        "Git subtree object could not be read",
                    ))
                })?;
                collect_repo_blobs(&subtree, &path, out)?;
            }
            kind @ (EntryKind::Blob | EntryKind::BlobExecutable | EntryKind::Link) => {
                validate_manifest_path(&path)?;
                let mode = match kind {
                    EntryKind::BlobExecutable => 0o100_755,
                    EntryKind::Link => 0o120_000,
                    _ => super::DEFAULT_CODE_FILE_MODE,
                };
                let blob_object = entry.object().map_err(|_| {
                    Error::Code(CodeError::InvalidCodebaseSnapshotBody(
                        "Git blob object could not be read",
                    ))
                })?;
                let mut blob = blob_object.try_into_blob().map_err(|_| {
                    Error::Code(CodeError::InvalidCodebaseSnapshotBody(
                        "Git blob object could not be read",
                    ))
                })?;
                let data = blob.take_data();
                let content_hash = *blake3::hash(&data).as_bytes();
                let size_bytes = u64::try_from(data.len())
                    .map_err(|_| Error::ArithmeticOverflow("codebase blob length overflow"))?;
                out.push(RepoIngestBlob {
                    path,
                    content_hash,
                    size_bytes,
                    data,
                    mode,
                });
            }
            EntryKind::Commit => {}
        }
    }
    Ok(())
}

pub(super) fn read_asset_blob(
    vault: &Vault,
    content_hash: &[u8; CODEBASE_CONTENT_HASH_LEN],
) -> Result<Vec<u8>> {
    // A file holding these bytes is named by their hash: pinned before the
    // snapshot that finds its row opens (FIX 5399).
    let _body = vault.pin_result_body(*content_hash);
    let txn = vault.store.env.read_txn()?;
    read_asset_blob_in_txn(vault, &txn, content_hash)
}

/// The stored bytes of the snapshot ASSET named `content_hash`, checked
/// against it: [`with_asset_blob_reader_in_txn`] read whole, for a reader
/// that holds a file's bytes (FIX 5399). A body kept in its ASSET's file is
/// read once through the checked reader, which verifies its length and
/// BLAKE3, against the hash the manifest names (FIX 6557); an inline body is
/// its row's, as before.
pub(crate) fn read_asset_blob_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    content_hash: &[u8; CODEBASE_CONTENT_HASH_LEN],
) -> Result<Vec<u8>> {
    with_asset_blob_reader_in_txn(vault, txn, content_hash, |body| {
        let mut bytes = Vec::new();
        body.read_to_end(&mut bytes)?;
        Ok(bytes)
    })
}

/// The stored bytes of the snapshot ASSET named `content_hash` as they
/// stream, for a reader that must not hold a large file whole (FIX 5399):
/// `read` runs over them, unmasked. A body kept in its ASSET's file is read
/// through the checked reader once its manifest names `content_hash`, and
/// whatever `read` leaves is read too, so its length and BLAKE3 are checked
/// whether or not `read` reaches its end; an inline body is checked against
/// `content_hash` before `read` sees it. The file is pinned while it is
/// read; a caller that found the snapshot in a transaction it opened
/// earlier pins the body before it opened.
///
/// # Errors
///
/// [`Error::EntityNotFound`] for no ASSET, [`Error::CorruptedIndex`] for
/// bytes of another hash, [`CodeError::InvalidCodebaseSnapshotBody`] for a
/// row of another type, `read`'s errors and the checked reader's.
pub(crate) fn with_asset_blob_reader_in_txn<T>(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    content_hash: &[u8; CODEBASE_CONTENT_HASH_LEN],
    read: impl FnOnce(&mut dyn Read) -> Result<T>,
) -> Result<T> {
    let asset_id = codebase_asset_entity_id(content_hash)?;
    let mut read = Some(read);
    // The stored bytes: the sight that reads them unmasked.
    if let Some(row) =
        crate::ports::EntityStoreRead::port_entity_record(&vault.store, txn, &asset_id)?
        && row.entity_type == ENTITY_TYPE_ASSET
        && let Some(manifest) =
            crate::store::asset_file_in_txn(&vault.store, txn, &asset_id, &row.body)?
    {
        if manifest.facts.blake3 != *content_hash {
            return Err(Error::CorruptedIndex("blob content hash"));
        }
        let streamed =
            vault.with_asset_body_reader_in_txn(txn, &asset_id, |body| match read.take() {
                Some(read) => read(body),
                None => Err(read_twice()),
            })?;
        if let Some(value) = streamed {
            return Ok(value);
        }
    }
    let bytes = inline_asset_blob_in_txn(vault, txn, &asset_id, content_hash)?;
    let read = read.take().ok_or_else(read_twice)?;
    read(&mut bytes.as_slice())
}

fn read_twice() -> Error {
    Error::InvariantViolation("an asset blob reader ran twice")
}

/// [`read_asset_blob_in_txn`] as `sight` reads it, as the hosted door reads
/// a snapshot file (FIX 6557): a body kept in its ASSET's file is masked as
/// it passes the checked reader, never held whole beside its copy; an inline
/// body is read whole, checked and masked by its mark.
pub(crate) fn read_asset_blob_sighted_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    content_hash: &[u8; CODEBASE_CONTENT_HASH_LEN],
    sight: SecretSight,
) -> Result<Vec<u8>> {
    let asset_id = codebase_asset_entity_id(content_hash)?;
    if let Some(bytes) = vault.sighted_body_file_in_txn(txn, &asset_id, content_hash, sight)? {
        return Ok(bytes);
    }
    let bytes = inline_asset_blob_in_txn(vault, txn, &asset_id, content_hash)?;
    crate::secret_custody::sighted_bytes_in_txn(&vault.store, txn, bytes, sight)
}

/// The body ASSET `asset_id`'s row holds, checked against `content_hash`.
fn inline_asset_blob_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    asset_id: &EntityId,
    content_hash: &[u8; CODEBASE_CONTENT_HASH_LEN],
) -> Result<Vec<u8>> {
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, asset_id)?
    else {
        return Err(Error::EntityNotFound);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_ASSET {
        return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
            "manifest content hash did not resolve to an ASSET",
        )));
    }
    let body = raw[ENTITY_METADATA_HEADER_LEN..].to_vec();
    if blake3::hash(&body).as_bytes() != content_hash {
        return Err(Error::CorruptedIndex("codebase asset content hash"));
    }
    Ok(body)
}

pub(super) fn scan_codebase_snapshot_metadata(snapshot: &CodebaseSnapshot) -> Result<()> {
    secret_scan::scan_metadata_field(&snapshot.project_id)?;
    let repo_ref = snapshot.repo_ref.canonical();
    secret_scan::scan_metadata_field(&repo_ref)?;
    if let Some(commit_hash) = &snapshot.commit_hash {
        secret_scan::scan_metadata_field(commit_hash)?;
    }
    for entry in &snapshot.files {
        secret_scan::scan_metadata_field(&entry.path)?;
    }
    Ok(())
}

pub(crate) fn validate_project_id(project_id: &str) -> Result<()> {
    validate_bounded_text(
        project_id,
        CODEBASE_PROJECT_ID_MAX_BYTES,
        "project_id must be non-empty and at most 256 bytes",
    )?;
    if project_id.trim() != project_id {
        return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
            "project_id must not have leading or trailing whitespace",
        )));
    }
    Ok(())
}

pub(super) fn validate_manifest_path(path: &str) -> Result<()> {
    validate_bounded_text(
        path,
        CODEBASE_FILE_PATH_MAX_BYTES,
        "file path must be non-empty and at most 4096 bytes",
    )?;
    if path.starts_with('/') || path.contains('\\') {
        return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
            "file path must be repository-relative",
        )));
    }
    if path
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
            "file path must be normalized and cannot contain . or .. segments",
        )));
    }
    Ok(())
}
