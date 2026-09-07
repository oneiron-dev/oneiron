//! Local artifact hosting over pinned CODE_ARTIFACT snapshots.
//!
//! The serving surface is intentionally pointer-shaped: `published` and
//! `preview` point at immutable fork hashes. Removing a pointer kills the
//! channel URL, while direct fork-hash mounts remain read-only and replayable.

use heed::RwTxn;

use crate::Vault;
use crate::code_artifact::CodeArtifactClass;
use crate::codebase::{
    CODEBASE_FILE_PATH_MAX_BYTES, CODEBASE_FORK_HASH_LEN, CODEBASE_PROJECT_ID_MAX_BYTES,
    CodebaseFileEntry, CodebaseForkHash, CodebaseSnapshot,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::secret_rotation::{
    ArtifactTaintState, allow_stale_publish_in_txn, exhaust_taint_refs_in_txn,
    taint_state_for_refs_in_txn,
};

pub const ARTIFACT_POINTER_CHANNELS: [&str; 2] = ["published", "preview"];
pub const ARTIFACT_PUBLISH_VERB_FEATURE: &str = "artifact-publish-verb";

const ARTIFACT_POINTER_KEY_PREFIX: &[u8] = b"artifact:pointer:v1:";
const ARTIFACT_CHANNEL_PUBLISHED: u8 = 0;
const ARTIFACT_CHANNEL_PREVIEW: u8 = 1;

/// The pointer row's value framing.
///
/// A pointer row was, and by default still is, EXACTLY the 32-byte fork
/// hash. SECRET-04 (ONE-1922) needs one more fact on the row — that this
/// publish went through the stale-taint override — and the row has no
/// framing slack, so the stamp is a single trailing byte and both read paths
/// accept both lengths. An ordinary publish writes 32 bytes and is
/// byte-identical to every pointer written before this change; only an
/// overridden publish writes 33.
const ARTIFACT_POINTER_STALE_OVERRIDE_STAMP: u8 = 0x01;

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
            _ => Err(Error::InvalidCodebaseSnapshotBody(
                "artifact pointer channel must be published or preview",
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArtifactSnapshotSelector {
    Channel(ArtifactPointerChannel),
    ForkHash(CodebaseForkHash),
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
    pub fork_hash: CodebaseForkHash,
    pub code_artifact_id: EntityId,
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
    pub fork_hash: CodebaseForkHash,
    pub code_artifact_id: EntityId,
    pub path: String,
    pub content_hash: [u8; 32],
    pub size_bytes: u64,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ArtifactPublishVerbRequest {
    pub artifact: String,
    pub channel: ArtifactPointerChannel,
    pub fork_hash: CodebaseForkHash,
    pub standing_grant: bool,
}

impl ArtifactPublishVerbRequest {
    #[must_use]
    pub fn new(
        artifact: impl Into<String>,
        channel: ArtifactPointerChannel,
        fork_hash: CodebaseForkHash,
        standing_grant: bool,
    ) -> Self {
        Self {
            artifact: artifact.into(),
            channel,
            fork_hash,
            standing_grant,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArtifactPublishVerbStatus {
    Proposed,
    Published,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ArtifactPublishVerbOutcome {
    pub status: ArtifactPublishVerbStatus,
    pub pointer: Option<ArtifactPointer>,
    pub dispatcher_feature_enabled: bool,
    pub reason: &'static str,
}

impl Vault {
    /// Publishes a channel pointer at a resolved snapshot.
    ///
    /// SECRET-04 (ONE-1922) adds the taint gate, and only the gate: the
    /// artifact's stored taint refs are compared against the custody
    /// records' CURRENT generations right here, at the check — read-time
    /// invalidation (ARCH-0069 S7, amended 2026-08-05). An artifact whose
    /// secrets have rotated or been revoked reads `TaintedStale` and the
    /// publish refuses with [`Error::TaintedArtifactStale`].
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
    pub fn publish_artifact_pointer(
        &self,
        artifact: &str,
        channel: ArtifactPointerChannel,
        fork_hash: &CodebaseForkHash,
    ) -> Result<ArtifactPointer> {
        let snapshot_ref = self
            .resolve_artifact_snapshot_by_fork(artifact, fork_hash)?
            .ok_or(Error::EntityNotFound)?;
        let mut wtxn = self.store.env.write_txn()?;
        let refs = exhaust_taint_refs_in_txn(&self.store, &wtxn, &snapshot_ref.code_artifact_id)?;
        let stale_taint_override = match taint_state_for_refs_in_txn(&self.store, &wtxn, &refs)? {
            ArtifactTaintState::Clean | ArtifactTaintState::TaintedLive => false,
            ArtifactTaintState::TaintedStale => {
                if !allow_stale_publish_in_txn(&self.store, &wtxn)? {
                    return Err(Error::TaintedArtifactStale {
                        artifact: artifact.to_owned(),
                    });
                }
                true
            }
        };
        put_artifact_pointer_in_txn(
            &self.store,
            &mut wtxn,
            artifact,
            channel,
            fork_hash,
            stale_taint_override,
        )?;
        wtxn.commit()?;
        Ok(ArtifactPointer {
            artifact: artifact.to_owned(),
            channel,
            fork_hash: *fork_hash,
            code_artifact_id: snapshot_ref.code_artifact_id,
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
        let (fork_hash, stale_taint_override) = decode_artifact_pointer_row(&raw)?;
        let Some(snapshot_ref) = self.resolve_artifact_snapshot_by_fork(artifact, &fork_hash)?
        else {
            return Ok(None);
        };
        Ok(Some(ArtifactPointer {
            artifact: artifact.to_owned(),
            channel,
            fork_hash,
            code_artifact_id: snapshot_ref.code_artifact_id,
            stale_taint_override,
        }))
    }

    pub fn resolve_artifact_snapshot_by_fork(
        &self,
        artifact: &str,
        fork_hash: &CodebaseForkHash,
    ) -> Result<Option<ArtifactSnapshotRef>> {
        validate_artifact_id(artifact)?;
        for code_artifact_id in self.codebase_snapshots_by_fork_hash(fork_hash)? {
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
        validate_artifact_path(path)?;
        let fork_hash = match selector {
            ArtifactSnapshotSelector::Channel(channel) => {
                let Some(pointer) = self.artifact_pointer(artifact, channel)? else {
                    return Ok(None);
                };
                pointer.fork_hash
            }
            ArtifactSnapshotSelector::ForkHash(fork_hash) => fork_hash,
        };
        let Some(snapshot_ref) = self.resolve_artifact_snapshot_by_fork(artifact, &fork_hash)?
        else {
            return Ok(None);
        };
        let Some(entry) = snapshot_file_entry(&snapshot_ref.snapshot, path) else {
            return Ok(None);
        };
        let content_hash = entry.content_hash;
        let size_bytes = entry.size_bytes;
        let mount = self
            .mount_codebase_snapshot(&snapshot_ref.code_artifact_id)?
            .ok_or(Error::EntityNotFound)?;
        let bytes = mount.read_file(path)?.ok_or(Error::EntityNotFound)?;
        Ok(Some(ArtifactServedFile {
            artifact: artifact.to_owned(),
            selector,
            fork_hash,
            code_artifact_id: snapshot_ref.code_artifact_id,
            path: path.to_owned(),
            content_hash,
            size_bytes,
            bytes,
        }))
    }

    pub fn request_artifact_publish(
        &self,
        request: &ArtifactPublishVerbRequest,
    ) -> Result<ArtifactPublishVerbOutcome> {
        validate_artifact_id(&request.artifact)?;
        self.resolve_artifact_snapshot_by_fork(&request.artifact, &request.fork_hash)?
            .ok_or(Error::EntityNotFound)?;
        if request.standing_grant && cfg!(feature = "artifact-publish-verb") {
            let pointer = self.publish_artifact_pointer(
                &request.artifact,
                request.channel,
                &request.fork_hash,
            )?;
            return Ok(ArtifactPublishVerbOutcome {
                status: ArtifactPublishVerbStatus::Published,
                pointer: Some(pointer),
                dispatcher_feature_enabled: true,
                reason: "standing grant accepted under artifact-publish-verb; artifact pointer published locally",
            });
        }
        let reason = if request.standing_grant {
            "standing grant present, but artifact-publish-verb is disabled; publish verb parks as Proposed"
        } else {
            "standing grant required; OF-327 outbound dispatcher is not landed; publish verb parks as Proposed"
        };
        Ok(ArtifactPublishVerbOutcome {
            status: ArtifactPublishVerbStatus::Proposed,
            pointer: None,
            dispatcher_feature_enabled: cfg!(feature = "artifact-publish-verb"),
            reason,
        })
    }
}

pub fn parse_codebase_fork_hash_hex(value: &str) -> Result<CodebaseForkHash> {
    if value.len() != CODEBASE_FORK_HASH_LEN * 2 {
        return Err(Error::InvalidCodebaseSnapshotBody(
            "forkHash must be 64 lowercase or uppercase hex characters",
        ));
    }
    let mut out = [0_u8; CODEBASE_FORK_HASH_LEN];
    let bytes = value.as_bytes();
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0]).ok_or(Error::InvalidCodebaseSnapshotBody(
            "forkHash must be hexadecimal",
        ))?;
        let low = hex_nibble(pair[1]).ok_or(Error::InvalidCodebaseSnapshotBody(
            "forkHash must be hexadecimal",
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

fn put_artifact_pointer_in_txn(
    store: &crate::store::Store,
    wtxn: &mut RwTxn<'_>,
    artifact: &str,
    channel: ArtifactPointerChannel,
    fork_hash: &CodebaseForkHash,
    stale_taint_override: bool,
) -> Result<()> {
    validate_artifact_id(artifact)?;
    let key = artifact_pointer_key(artifact, channel)?;
    if stale_taint_override {
        let mut value = Vec::with_capacity(CODEBASE_FORK_HASH_LEN + 1);
        value.extend_from_slice(fork_hash);
        value.push(ARTIFACT_POINTER_STALE_OVERRIDE_STAMP);
        store.vault_meta.put(wtxn, &key, &value)?;
    } else {
        // Byte-identical to every pointer row written before SECRET-04.
        store.vault_meta.put(wtxn, &key, fork_hash)?;
    }
    Ok(())
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

/// Reads one pointer row into its fork hash and its stale-taint override,
/// branching ONCE on the framing the row length declares.
///
/// The bare 32-byte row is every pointer written before SECRET-04 and
/// carries no override; a 33-byte row must carry the one defined stamp byte,
/// because a pointer row asserting an override nobody minted is corruption,
/// not a default. Any other length is a corrupted row.
fn decode_artifact_pointer_row(raw: &[u8]) -> Result<(CodebaseForkHash, bool)> {
    let stale_taint_override = match raw.len() {
        CODEBASE_FORK_HASH_LEN => false,
        len if len == CODEBASE_FORK_HASH_LEN + 1 => {
            if raw[CODEBASE_FORK_HASH_LEN] != ARTIFACT_POINTER_STALE_OVERRIDE_STAMP {
                return Err(Error::CorruptedIndex("artifact pointer taint stamp"));
            }
            true
        }
        _ => return Err(Error::CorruptedIndex("artifact pointer fork hash")),
    };
    let fork_hash = raw[..CODEBASE_FORK_HASH_LEN]
        .try_into()
        .map_err(|_| Error::CorruptedIndex("artifact pointer fork hash"))?;
    Ok((fork_hash, stale_taint_override))
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
        return Err(Error::InvalidCodebaseSnapshotBody(
            "artifact id must not have leading or trailing whitespace",
        ));
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
        return Err(Error::InvalidCodebaseSnapshotBody(
            "artifact path must be bundle-relative",
        ));
    }
    if path
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(Error::InvalidCodebaseSnapshotBody(
            "artifact path must be normalized and cannot contain . or .. segments",
        ));
    }
    Ok(())
}

fn validate_bounded_text(text: &str, max_bytes: usize, context: &'static str) -> Result<()> {
    if text.is_empty() || text.len() > max_bytes {
        return Err(Error::InvalidCodebaseSnapshotBody(context));
    }
    if text.chars().any(char::is_control) {
        return Err(Error::InvalidCodebaseSnapshotBody(
            "artifact text fields must not contain control characters",
        ));
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
