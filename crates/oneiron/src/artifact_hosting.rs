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
use crate::error::{CodeError, Error, Result, SecretError};
use crate::secret_rotation::{
    ArtifactTaintState, allow_stale_publish_in_txn, exhaust_taint_refs_in_txn,
    taint_state_for_refs_in_txn,
};
use crate::side_table::{self, CodecError, Raw, RawValue, SideKey, SideTable};

pub const ARTIFACT_POINTER_CHANNELS: [&str; 2] = ["published", "preview"];
pub const ARTIFACT_PUBLISH_VERB_FEATURE: &str = "artifact-publish-verb";

const ARTIFACT_CHANNEL_PUBLISHED: u8 = 0;
const ARTIFACT_CHANNEL_PREVIEW: u8 = 1;

/// One channel pointer, keyed by `channel(1) ++ artifact_len(u16 be) ++ artifact`
/// exactly as `artifact_pointer_key` used to spell it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ArtifactPointerRowKey {
    channel: ArtifactPointerChannel,
    artifact: String,
}

impl SideKey for ArtifactPointerRowKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(self.channel.key_byte());
        out.extend_from_slice(&(self.artifact.len() as u16).to_be_bytes());
        out.extend_from_slice(self.artifact.as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (&channel_byte, rest) = bytes.split_first()?;
        let channel = ArtifactPointerChannel::from_key_byte(channel_byte)?;
        let (len_bytes, rest) = rest.split_at_checked(2)?;
        let len = u16::from_be_bytes(len_bytes.try_into().ok()?) as usize;
        if rest.len() != len {
            return None;
        }
        Some(Self {
            channel,
            artifact: String::from_utf8(rest.to_vec()).ok()?,
        })
    }
}

/// One pointer row's value: a bare 32-byte fork hash (every pointer written
/// before SECRET-04) or 33 bytes when the publish rode a stale-taint override.
struct ArtifactPointerRow {
    fork_hash: CodebaseForkHash,
    stale_taint_override: bool,
}

impl RawValue for ArtifactPointerRow {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let mut value = self.fork_hash.to_vec();
        if self.stale_taint_override {
            value.push(ARTIFACT_POINTER_STALE_OVERRIDE_STAMP);
        }
        Ok(value)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let (fork_hash, stale_taint_override) = decode_artifact_pointer_row(bytes)?;
        Ok(Self {
            fork_hash,
            stale_taint_override,
        })
    }
}

const ARTIFACT_POINTERS: SideTable<ArtifactPointerRowKey, ArtifactPointerRow, Raw> =
    SideTable::new(&side_table::ARTIFACT_POINTER);

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

    #[must_use]
    const fn from_key_byte(byte: u8) -> Option<Self> {
        match byte {
            ARTIFACT_CHANNEL_PUBLISHED => Some(Self::Published),
            ARTIFACT_CHANNEL_PREVIEW => Some(Self::Preview),
            _ => None,
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
                    return Err(Error::Secret(SecretError::TaintedArtifactStale {
                        artifact: artifact.to_owned(),
                    }));
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
        let key = ArtifactPointerRowKey {
            channel,
            artifact: artifact.to_owned(),
        };
        let removed = ARTIFACT_POINTERS.delete(&self.store, &mut wtxn, &key)?;
        wtxn.commit()?;
        Ok(removed)
    }

    pub fn artifact_pointer(
        &self,
        artifact: &str,
        channel: ArtifactPointerChannel,
    ) -> Result<Option<ArtifactPointer>> {
        validate_artifact_id(artifact)?;
        let row = {
            let rtxn = self.store.env.read_txn()?;
            let key = ArtifactPointerRowKey {
                channel,
                artifact: artifact.to_owned(),
            };
            ARTIFACT_POINTERS.get(&self.store, &rtxn, &key)?
        };
        let Some(row) = row else {
            return Ok(None);
        };
        let (fork_hash, stale_taint_override) = (row.fork_hash, row.stale_taint_override);
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

fn put_artifact_pointer_in_txn(
    store: &crate::store::Store,
    wtxn: &mut RwTxn<'_>,
    artifact: &str,
    channel: ArtifactPointerChannel,
    fork_hash: &CodebaseForkHash,
    stale_taint_override: bool,
) -> Result<()> {
    validate_artifact_id(artifact)?;
    let key = ArtifactPointerRowKey {
        channel,
        artifact: artifact.to_owned(),
    };
    let row = ArtifactPointerRow {
        fork_hash: *fork_hash,
        stale_taint_override,
    };
    ARTIFACT_POINTERS.put(store, wtxn, &key, &row)?;
    Ok(())
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
