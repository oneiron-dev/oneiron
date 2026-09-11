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
use gix::bstr::ByteSlice;
use gix::object::tree::EntryKind;
use std::fmt;
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
            EntryKind::Blob | EntryKind::BlobExecutable | EntryKind::Link => {
                validate_manifest_path(&path)?;
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
    let asset_id = codebase_asset_entity_id(content_hash)?;
    let Some(raw) = vault.get_raw(&asset_id)? else {
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

pub(super) fn validate_project_id(project_id: &str) -> Result<()> {
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
