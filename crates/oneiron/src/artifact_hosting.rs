//! Local artifact hosting over pinned code snapshots and blob exports.
//!
//! The serving surface is intentionally pointer-shaped: `published` and
//! `preview` point at immutable fork hashes. Removing a pointer kills the
//! channel URL, while direct fork-hash mounts remain read-only and replayable.

mod provenance;
#[cfg(feature = "sync")]
pub(crate) use provenance::artifact_birth_dependency_pending;
pub(crate) use provenance::guard_artifact_put;
pub use provenance::{
    ArtifactBirthBody, ArtifactBirthEnvelope, ArtifactBirthProjection, ArtifactPurpose,
    ArtifactTrigger,
};

mod version;
pub use version::ArtifactPinnedVersion;

use crate::Vault;
use crate::code_artifact::CodeArtifactClass;
use crate::codebase::{
    CODEBASE_FILE_PATH_MAX_BYTES, CODEBASE_FORK_HASH_LEN, CODEBASE_PROJECT_ID_MAX_BYTES,
    CodebaseFileEntry, CodebaseForkHash, CodebaseSnapshot,
};
use crate::entity_id::EntityId;
use crate::error::{CodeError, Error, Result, SecretError};
use crate::secret_rotation::{
    ArtifactTaintState, allow_stale_publish_in_txn, exhaust_taint_refs_in_txn,
    taint_state_for_refs_in_txn,
};

pub const ARTIFACT_POINTER_CHANNELS: [&str; 2] = ["published", "preview"];
pub const ARTIFACT_PUBLISH_VERB_FEATURE: &str = "artifact-publish-verb";

const ARTIFACT_POINTER_KEY_PREFIX: &[u8] = b"artifact:pointer:v1:";
const ARTIFACT_CHANNEL_PUBLISHED: u8 = 0;
const ARTIFACT_CHANNEL_PREVIEW: u8 = 1;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArtifactPointerChannel {
    #[default]
    Published,
    Preview,
}

impl ArtifactPointerChannel {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Published => ARTIFACT_POINTER_CHANNELS[0],
            Self::Preview => ARTIFACT_POINTER_CHANNELS[1],
        }
    }

    #[must_use]
    pub const fn key_byte(self) -> u8 {
        match self {
            Self::Published => ARTIFACT_CHANNEL_PUBLISHED,
            Self::Preview => ARTIFACT_CHANNEL_PREVIEW,
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "published" => Ok(Self::Published),
            "preview" => Ok(Self::Preview),
            _ => Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
                "artifact pointer channel must be published or preview",
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArtifactSnapshotSelector {
    Channel(ArtifactPointerChannel),
    ForkHash(CodebaseForkHash),
    BlobVersion { artifact_id: EntityId, version: u64 },
}

impl Default for ArtifactSnapshotSelector {
    fn default() -> Self {
        Self::Channel(ArtifactPointerChannel::Published)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ArtifactPointer {
    pub artifact: String,
    pub channel: ArtifactPointerChannel,
    pub version: ArtifactPinnedVersion,
    pub artifact_id: EntityId,
    /// Whether this pointer was published over a `TaintedStale` refusal
    /// through the `secret.taint.allow_stale_publish` dial (SECRET-04).
    ///
    /// Read back off the row, not remembered in process: an override is a
    /// durable fact about how this pointer came to exist, and someone
    /// auditing the channel later deserves to see it.
    pub stale_taint_override: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ArtifactSnapshotRef {
    pub artifact: String,
    pub fork_hash: CodebaseForkHash,
    pub code_artifact_id: EntityId,
    pub snapshot: CodebaseSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ArtifactServedFile {
    pub artifact: String,
    pub selector: ArtifactSnapshotSelector,
    pub version: ArtifactPinnedVersion,
    pub artifact_id: EntityId,
    pub path: String,
    pub content_hash: [u8; 32],
    pub size_bytes: u64,
    pub bytes: Vec<u8>,
}

mod publish;
mod publish_receipt;
pub use publish::{
    ArtifactPublishVerbOutcome, ArtifactPublishVerbRequest, ArtifactPublishVerbStatus,
};
pub(crate) use publish_receipt::artifact_publish_receipts;

impl Vault {
    /// Publishes a channel pointer at a resolved snapshot.
    ///
    /// SECRET-04 (ONE-1922) adds the taint gate, and only the gate: the
    /// artifact's stored taint refs are compared against the custody
    /// records' CURRENT generations right here, at the check — read-time
    /// invalidation (ARCH-0069 S7, amended 2026-08-05). An artifact whose
    /// secrets have rotated or been revoked reads `TaintedStale` and the
    /// publish refuses with [`SecretError::TaintedArtifactStale`](crate::error::SecretError::TaintedArtifactStale).
    ///
    /// It is a DIAL, not a wall. When the resolved policy key
    /// `secret.taint.allow_stale_publish` is on, the publish proceeds and
    /// the pointer row is STAMPED, so the override is durable evidence
    /// rather than an unrecorded decision. `TaintedLive` publishes
    /// unstamped and ungated: live tainted exhaust is not stale exhaust.
    ///
    /// The dial is resolved and the state derived inside the SAME write
    /// transaction that puts the row, so a rotation landing mid-publish
    /// cannot slip a stale pointer past a check taken against an older
    /// reading. No receipt plane is minted here — the publish gate is the
    /// whole of this ticket's business in this module.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn publish_artifact_pointer(
        &self,
        artifact: &str,
        channel: ArtifactPointerChannel,
        fork_hash: &CodebaseForkHash,
    ) -> Result<ArtifactPointer> {
        self.publish_pinned_artifact(artifact, channel, ArtifactPinnedVersion::Code(*fork_hash))
    }

    #[cfg(any(test, feature = "test-hooks"))]
    fn publish_pinned_artifact(
        &self,
        artifact: &str,
        channel: ArtifactPointerChannel,
        version: ArtifactPinnedVersion,
    ) -> Result<ArtifactPointer> {
        let artifact_id = self
            .resolve_pinned_artifact(artifact, version)?
            .ok_or(Error::EntityNotFound)?;
        self.with_write_txn(|wtxn| {
            self.publish_pointer_in_txn(wtxn, artifact, channel, version, artifact_id)
        })
    }

    fn publish_pointer_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        artifact: &str,
        channel: ArtifactPointerChannel,
        version: ArtifactPinnedVersion,
        artifact_id: EntityId,
    ) -> Result<ArtifactPointer> {
        let refs = exhaust_taint_refs_in_txn(&self.store, wtxn, &artifact_id)?;
        let stale_taint_override = match taint_state_for_refs_in_txn(&self.store, wtxn, &refs)? {
            ArtifactTaintState::Clean | ArtifactTaintState::TaintedLive => false,
            ArtifactTaintState::TaintedStale => {
                if !allow_stale_publish_in_txn(&self.store, wtxn)? {
                    return Err(Error::Secret(SecretError::TaintedArtifactStale {
                        artifact: artifact.to_owned(),
                    }));
                }
                true
            }
        };
        let bytes = version.encode(stale_taint_override);
        self.store
            .vault_meta
            .put(wtxn, &artifact_pointer_key(artifact, channel)?, &bytes)?;
        Ok(ArtifactPointer {
            artifact: artifact.to_owned(),
            channel,
            version,
            artifact_id,
            stale_taint_override,
        })
    }

    pub fn unpublish_artifact_pointer(
        &self,
        artifact: &str,
        channel: ArtifactPointerChannel,
    ) -> Result<bool> {
        validate_artifact_id(artifact)?;
        let mut wtxn = self.store.env.write_txn()?;
        let removed = self
            .store
            .vault_meta
            .delete(&mut wtxn, &artifact_pointer_key(artifact, channel)?)?;
        wtxn.commit()?;
        Ok(removed)
    }

    pub fn artifact_pointer(
        &self,
        artifact: &str,
        channel: ArtifactPointerChannel,
    ) -> Result<Option<ArtifactPointer>> {
        validate_artifact_id(artifact)?;
        let raw = {
            let rtxn = self.store.env.read_txn()?;
            self.store
                .vault_meta
                .get(&rtxn, &artifact_pointer_key(artifact, channel)?)?
                .map(|value| value.to_vec())
        };
        let Some(raw) = raw else {
            return Ok(None);
        };
        let (version, stale_taint_override) = ArtifactPinnedVersion::decode(&raw)?;
        let Some(artifact_id) = self.resolve_pinned_artifact(artifact, version)? else {
            return Ok(None);
        };
        Ok(Some(ArtifactPointer {
            artifact: artifact.to_owned(),
            channel,
            version,
            artifact_id,
            stale_taint_override,
        }))
    }

    fn resolve_pinned_artifact(
        &self,
        artifact: &str,
        version: ArtifactPinnedVersion,
    ) -> Result<Option<EntityId>> {
        validate_artifact_id(artifact)?;
        match version {
            ArtifactPinnedVersion::Code(hash) => Ok(self
                .resolve_artifact_snapshot_by_fork(artifact, &hash)?
                .map(|s| s.code_artifact_id)),
            ArtifactPinnedVersion::Blob {
                artifact_id,
                version,
            } => {
                if version == 0 {
                    return Err(Error::InvalidConfig(
                        "Artifact versions start at one".into(),
                    ));
                }
                if self
                    .get_entity_type(&artifact_id)?
                    .and_then(crate::registry::artifact_family_kind)
                    != Some(crate::registry::ArtifactFamilyKind::Blob)
                {
                    return Ok(None);
                }
                Ok(self
                    .blob_artifact_version_metadata(&artifact_id, version)?
                    .map(|_| artifact_id))
            }
        }
    }

    pub fn resolve_artifact_snapshot_by_fork(
        &self,
        artifact: &str,
        fork_hash: &CodebaseForkHash,
    ) -> Result<Option<ArtifactSnapshotRef>> {
        validate_artifact_id(artifact)?;
        for code_artifact_id in self.codebase_snapshots_by_fork_hash(fork_hash)? {
            if self
                .get_entity_type(&code_artifact_id)?
                .and_then(crate::registry::artifact_family_kind)
                != Some(crate::registry::ArtifactFamilyKind::Code)
            {
                continue;
            }
            let Some(snapshot) = self.get_codebase_snapshot(&code_artifact_id)? else {
                continue;
            };
            if snapshot.project_id != artifact {
                continue;
            }
            let Some(body) = self.get_code_artifact(&code_artifact_id)? else {
                continue;
            };
            if body.class != CodeArtifactClass::Artifact {
                continue;
            }
            return Ok(Some(ArtifactSnapshotRef {
                artifact: artifact.to_owned(),
                fork_hash: *fork_hash,
                code_artifact_id,
                snapshot,
            }));
        }
        Ok(None)
    }

    pub fn resolve_artifact_file(
        &self,
        artifact: &str,
        selector: ArtifactSnapshotSelector,
        path: &str,
    ) -> Result<Option<ArtifactServedFile>> {
        validate_artifact_id(artifact)?;
        validate_artifact_path(path)?;
        let version = match selector {
            ArtifactSnapshotSelector::Channel(channel) => {
                let Some(pointer) = self.artifact_pointer(artifact, channel)? else {
                    return Ok(None);
                };
                pointer.version
            }
            ArtifactSnapshotSelector::ForkHash(hash) => ArtifactPinnedVersion::Code(hash),
            ArtifactSnapshotSelector::BlobVersion {
                artifact_id,
                version,
            } => ArtifactPinnedVersion::Blob {
                artifact_id,
                version,
            },
        };
        let Some(artifact_id) = self.resolve_pinned_artifact(artifact, version)? else {
            return Ok(None);
        };
        let (path, bytes) = match version {
            ArtifactPinnedVersion::Code(hash) => {
                let snapshot = self
                    .resolve_artifact_snapshot_by_fork(artifact, &hash)?
                    .ok_or(Error::EntityNotFound)?;
                if snapshot_file_entry(&snapshot.snapshot, path).is_none() {
                    return Ok(None);
                }
                let mount = self
                    .mount_codebase_snapshot(&artifact_id)?
                    .ok_or(Error::EntityNotFound)?;
                let bytes = mount.read_file(path)?.ok_or(Error::EntityNotFound)?;
                (path.to_owned(), bytes)
            }
            ArtifactPinnedVersion::Blob { version, .. } => {
                let body = self
                    .get_blob_artifact(&artifact_id)?
                    .ok_or(Error::EntityNotFound)?;
                if path != "index.html" && path != body.name {
                    return Ok(None);
                }
                let bytes = self
                    .read_blob_artifact_version(&artifact_id, version)?
                    .ok_or(Error::EntityNotFound)?;
                (body.name, bytes)
            }
        };
        Ok(Some(ArtifactServedFile {
            artifact: artifact.to_owned(),
            selector,
            version,
            artifact_id,
            path,
            content_hash: *blake3::hash(&bytes).as_bytes(),
            size_bytes: bytes.len() as u64,
            bytes,
        }))
    }
}

pub fn parse_codebase_fork_hash_hex(value: &str) -> Result<CodebaseForkHash> {
    if value.len() != CODEBASE_FORK_HASH_LEN * 2 {
        return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
            "forkHash must be 64 lowercase or uppercase hex characters",
        )));
    }
    let mut out = [0_u8; CODEBASE_FORK_HASH_LEN];
    let bytes = value.as_bytes();
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0]).ok_or(Error::Code(
            CodeError::InvalidCodebaseSnapshotBody("forkHash must be hexadecimal"),
        ))?;
        let low = hex_nibble(pair[1]).ok_or(Error::Code(
            CodeError::InvalidCodebaseSnapshotBody("forkHash must be hexadecimal"),
        ))?;
        out[index] = (high << 4) | low;
    }
    Ok(out)
}

#[must_use]
pub fn artifact_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn artifact_pointer_key(artifact: &str, channel: ArtifactPointerChannel) -> Result<Vec<u8>> {
    validate_artifact_id(artifact)?;
    let len = u16::try_from(artifact.len())
        .map_err(|_| Error::ArithmeticOverflow("artifact id length overflow"))?;
    let mut key = Vec::with_capacity(ARTIFACT_POINTER_KEY_PREFIX.len() + 1 + 2 + artifact.len());
    key.extend_from_slice(ARTIFACT_POINTER_KEY_PREFIX);
    key.push(channel.key_byte());
    key.extend_from_slice(&len.to_be_bytes());
    key.extend_from_slice(artifact.as_bytes());
    Ok(key)
}

fn snapshot_file_entry<'a>(
    snapshot: &'a CodebaseSnapshot,
    path: &str,
) -> Option<&'a CodebaseFileEntry> {
    let Ok(index) = snapshot
        .files
        .binary_search_by(|entry| entry.path.as_str().cmp(path))
    else {
        return None;
    };
    snapshot.files.get(index)
}

fn validate_artifact_id(artifact: &str) -> Result<()> {
    validate_bounded_text(
        artifact,
        CODEBASE_PROJECT_ID_MAX_BYTES,
        "artifact id must be non-empty and at most 256 bytes",
    )?;
    if artifact.trim() != artifact {
        return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
            "artifact id must not have leading or trailing whitespace",
        )));
    }
    Ok(())
}

fn validate_artifact_path(path: &str) -> Result<()> {
    validate_bounded_text(
        path,
        CODEBASE_FILE_PATH_MAX_BYTES,
        "artifact path must be non-empty and at most 4096 bytes",
    )?;
    if path.starts_with('/') || path.contains('\\') {
        return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
            "artifact path must be bundle-relative",
        )));
    }
    if path
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
            "artifact path must be normalized and cannot contain . or .. segments",
        )));
    }
    Ok(())
}

fn validate_bounded_text(text: &str, max_bytes: usize, context: &'static str) -> Result<()> {
    if text.is_empty() || text.len() > max_bytes {
        return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(context)));
    }
    if text.chars().any(char::is_control) {
        return Err(Error::Code(CodeError::InvalidCodebaseSnapshotBody(
            "artifact text fields must not contain control characters",
        )));
    }
    Ok(())
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
