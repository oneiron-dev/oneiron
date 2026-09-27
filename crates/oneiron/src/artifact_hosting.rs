//! Local artifact hosting over pinned code snapshots and blob exports.
//!
//! The serving surface is intentionally pointer-shaped: `published` and
//! `preview` point at immutable fork hashes or blob versions. Removing a pointer
//! kills the channel URL; direct version mounts remain read-only.

use heed::RwTxn;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::Vault;
use crate::code_artifact::CodeArtifactClass;
use crate::codebase::{
    CODEBASE_FILE_PATH_MAX_BYTES, CODEBASE_FORK_HASH_LEN, CODEBASE_PROJECT_ID_MAX_BYTES,
    CodebaseFileEntry, CodebaseForkHash, CodebaseSnapshot,
};
use crate::entity_id::EntityId;
use crate::error::{CodeError, Error, Result, SecretError};
use crate::gate::{
    self, ExternalEffectGateInput, ExternalEffectPolicyRisk, GateActor, GateOutcome,
    GateProvenanceHandles,
};
use crate::outbound::OutboundDispatchPipeline;
use crate::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};
use crate::registry::{ArtifactFamilyKindId, artifact_family_kind_of};
use crate::secret_rotation::{
    ArtifactTaintState, allow_stale_publish_in_txn, exhaust_taint_refs_in_txn,
    taint_state_for_refs_in_txn,
};
use crate::store::GateDecisionId;
use crate::write_envelope::WriteActor;

pub const ARTIFACT_POINTER_CHANNELS: [&str; 2] = ["published", "preview"];

const ARTIFACT_POINTER_KEY_PREFIX: &[u8] = b"artifact:pointer:v1:";
const ARTIFACT_PUBLISH_ADMISSION_PREFIX: &[u8] = b"artifact:publish:admission:v1:";
const ARTIFACT_CHANNEL_PUBLISHED: u8 = 0;
const ARTIFACT_CHANNEL_PREVIEW: u8 = 1;

/// The pointer row's value framing.
///
/// Code pointers remain 32-byte fork hashes (33 with SECRET-04 override).
/// Blob pointers use a disjoint tagged frame (25 bytes, or 26 with override).
/// The trailing stamp records a stale-taint publish override on either kind.
const ARTIFACT_POINTER_STALE_OVERRIDE_STAMP: u8 = 0x01;
const ARTIFACT_POINTER_BLOB_TAG: u8 = 0x02;

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
    BlobVersion(u64),
}

impl Default for ArtifactSnapshotSelector {
    fn default() -> Self {
        Self::Channel(ArtifactPointerChannel::Published)
    }
}

/// Exactly one immutable export, owned by the artifact in the route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ArtifactExportRef {
    ForkHash(CodebaseForkHash),
    BlobVersion { artifact_id: EntityId, version: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ArtifactPointer {
    pub artifact: String,
    pub channel: ArtifactPointerChannel,
    pub export: ArtifactExportRef,
    /// Durable evidence of an explicit stale-taint publish override.
    pub stale_taint_override: bool,
    /// The serve tier of this live pointer.
    pub serve_tier: ArtifactServeTier,
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
    pub serve_tier: ArtifactServeTier,
    pub selector: ArtifactSnapshotSelector,
    pub export: ArtifactExportRef,
    pub path: String,
    pub media_type: Option<String>,
    pub content_hash: [u8; 32],
    pub size_bytes: u64,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ArtifactPublishVerbRequest {
    pub artifact: String,
    /// A publish defaults closed; public disclosure must be explicit.
    pub serve_tier: ArtifactServeTier,
    pub channel: ArtifactPointerChannel,
    pub export: ArtifactExportRef,
    pub actor: WriteActor,
    /// Stable identity for retrying this exact publish action.
    pub publish_id: EntityId,
    pub occurred_at: u64,
}

impl ArtifactPublishVerbRequest {
    #[must_use]
    pub fn new(
        artifact: impl Into<String>,
        channel: ArtifactPointerChannel,
        fork_hash: CodebaseForkHash,
        actor: WriteActor,
        publish_id: EntityId,
        occurred_at: u64,
    ) -> Self {
        Self {
            artifact: artifact.into(),
            serve_tier: ArtifactServeTier::Private,
            channel,
            export: ArtifactExportRef::ForkHash(fork_hash),
            actor,
            publish_id,
            occurred_at,
        }
    }

    #[must_use]
    pub fn new_blob(
        artifact_id: EntityId,
        channel: ArtifactPointerChannel,
        version: u64,
        actor: WriteActor,
        publish_id: EntityId,
        occurred_at: u64,
    ) -> Self {
        Self {
            artifact: artifact_id.to_hex(),
            serve_tier: ArtifactServeTier::Private,
            channel,
            export: ArtifactExportRef::BlobVersion {
                artifact_id,
                version,
            },
            actor,
            publish_id,
            occurred_at,
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
    /// Only an admitted publish has a share-style, replayable receipt.
    pub receipt: Option<ReceiptRecord>,
    pub gate_decision_ref: String,
}

/// Immutable admission for a publish. The pointer can be repointed or removed,
/// but the receipt of the earlier public effect must survive both actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ArtifactPublishAdmission {
    artifact: String,
    channel: u8,
    export: ArtifactExportRef,
    export_entity_id: EntityId,
    actor: EntityId,
    actor_class: String,
    gate_id: GateDecisionId,
    occurred_at: u64,
    stale_taint_override: bool,
    #[serde(default)]
    serve_tier: ArtifactServeTier,
}

impl Vault {
    /// Test-only direct pointer setup. Production publishes through the
    /// outbound dispatcher's Gate and receipts the public effect.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn publish_artifact_pointer(
        &self,
        artifact: &str,
        channel: ArtifactPointerChannel,
        fork_hash: &CodebaseForkHash,
    ) -> Result<ArtifactPointer> {
        let snapshot = self
            .resolve_artifact_snapshot_by_fork(artifact, fork_hash)?
            .ok_or(Error::EntityNotFound)?;
        let mut wtxn = self.store.env.write_txn()?;
        let pointer = publish_artifact_pointer_in_txn(
            self,
            &mut wtxn,
            &snapshot,
            channel,
            ArtifactServeTier::Private,
        )?;
        wtxn.commit()?;
        Ok(pointer)
    }

    /// Test-only direct blob pointer setup; production uses the Gate dispatch.
    /// The route identity is the blob entity's canonical hex id.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn publish_blob_artifact_pointer(
        &self,
        artifact_id: &EntityId,
        channel: ArtifactPointerChannel,
        version: u64,
    ) -> Result<ArtifactPointer> {
        self.publish_export_pointer(
            &artifact_id.to_hex(),
            channel,
            ArtifactExportRef::BlobVersion {
                artifact_id: *artifact_id,
                version,
            },
            ArtifactServeTier::Private,
        )
    }

    /// Test-only setup of an explicit tier without the outbound Gate.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn publish_artifact_pointer_with_tier(
        &self,
        artifact: &str,
        channel: ArtifactPointerChannel,
        fork_hash: &CodebaseForkHash,
        tier: ArtifactServeTier,
    ) -> Result<ArtifactPointer> {
        self.publish_export_pointer(
            artifact,
            channel,
            ArtifactExportRef::ForkHash(*fork_hash),
            tier,
        )
    }

    /// Test-only setup of a blob pointer's explicit tier.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn publish_blob_artifact_pointer_with_tier(
        &self,
        artifact_id: &EntityId,
        channel: ArtifactPointerChannel,
        version: u64,
        tier: ArtifactServeTier,
    ) -> Result<ArtifactPointer> {
        self.publish_export_pointer(
            &artifact_id.to_hex(),
            channel,
            ArtifactExportRef::BlobVersion {
                artifact_id: *artifact_id,
                version,
            },
            tier,
        )
    }

    #[cfg(any(test, feature = "test-hooks"))]
    fn publish_export_pointer(
        &self,
        artifact: &str,
        channel: ArtifactPointerChannel,
        export: ArtifactExportRef,
        tier: ArtifactServeTier,
    ) -> Result<ArtifactPointer> {
        let mut wtxn = self.store.env.write_txn()?;
        let pointer =
            self.publish_export_pointer_in_txn(&mut wtxn, artifact, channel, export, tier)?;
        wtxn.commit()?;
        Ok(pointer)
    }

    fn publish_export_pointer_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        artifact: &str,
        channel: ArtifactPointerChannel,
        export: ArtifactExportRef,
        serve_tier: ArtifactServeTier,
    ) -> Result<ArtifactPointer> {
        let entity_id = self
            .resolve_export_owner_in_txn(wtxn, artifact, export)?
            .ok_or(Error::EntityNotFound)?;
        let refs = exhaust_taint_refs_in_txn(&self.store, wtxn, &entity_id)?;
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
        put_artifact_pointer_in_txn(
            &self.store,
            wtxn,
            artifact,
            channel,
            export,
            stale_taint_override,
            serve_tier,
        )?;
        Ok(ArtifactPointer {
            artifact: artifact.to_owned(),
            channel,
            export,
            stale_taint_override,
            serve_tier,
        })
    }

    fn resolve_export_owner(
        &self,
        artifact: &str,
        export: ArtifactExportRef,
    ) -> Result<Option<EntityId>> {
        validate_artifact_id(artifact)?;
        match export {
            ArtifactExportRef::ForkHash(fork_hash) => Ok(self
                .resolve_artifact_snapshot_by_fork(artifact, &fork_hash)?
                .map(|r| r.code_artifact_id)),
            ArtifactExportRef::BlobVersion {
                artifact_id,
                version,
            } => {
                if artifact != artifact_id.to_hex()
                    || version == 0
                    || self.get_blob_artifact(&artifact_id)?.is_none()
                {
                    return Ok(None);
                }
                Ok(self
                    .blob_artifact_version_metadata(&artifact_id, version)?
                    .map(|_| artifact_id))
            }
        }
    }

    /// Publish admission runs behind the writer. No concurrent delete may
    /// remove a blob between validating its version and inserting its pointer.
    fn resolve_export_owner_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        artifact: &str,
        export: ArtifactExportRef,
    ) -> Result<Option<EntityId>> {
        validate_artifact_id(artifact)?;
        match export {
            ArtifactExportRef::ForkHash(_) => self.resolve_export_owner(artifact, export),
            ArtifactExportRef::BlobVersion {
                artifact_id,
                version,
            } => {
                if artifact != artifact_id.to_hex()
                    || version == 0
                    || self.get_blob_artifact_in_txn(rtxn, &artifact_id)?.is_none()
                {
                    return Ok(None);
                }
                Ok(self
                    .blob_artifact_version_metadata_in_txn(rtxn, &artifact_id, version)?
                    .map(|_| artifact_id))
            }
        }
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

    pub fn unpublish_blob_artifact_pointer(
        &self,
        artifact_id: &EntityId,
        channel: ArtifactPointerChannel,
    ) -> Result<bool> {
        self.unpublish_artifact_pointer(&artifact_id.to_hex(), channel)
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
        let (export, stale_taint_override, serve_tier) = decode_artifact_pointer_row(&raw)?;
        if self.resolve_export_owner(artifact, export)?.is_none() {
            return Ok(None);
        }
        Ok(Some(ArtifactPointer {
            artifact: artifact.to_owned(),
            channel,
            export,
            stale_taint_override,
            serve_tier,
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
            // This serving adapter mounts code trees only. The semantic family
            // match keeps other registered kinds out without treating their
            // different export bodies as code snapshots.
            if self
                .get_entity_type(&code_artifact_id)?
                .and_then(artifact_family_kind_of)
                != Some(ArtifactFamilyKindId::Code)
            {
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
        let export = match selector {
            ArtifactSnapshotSelector::Channel(channel) => {
                let Some(pointer) = self.artifact_pointer(artifact, channel)? else {
                    return Ok(None);
                };
                pointer.export
            }
            ArtifactSnapshotSelector::ForkHash(hash) => ArtifactExportRef::ForkHash(hash),
            ArtifactSnapshotSelector::BlobVersion(version) => {
                let Ok(artifact_id) = EntityId::from_hex(artifact) else {
                    return Ok(None);
                };
                ArtifactExportRef::BlobVersion {
                    artifact_id,
                    version,
                }
            }
        };
        match export {
            ArtifactExportRef::ForkHash(fork_hash) => {
                let Some(snapshot_ref) =
                    self.resolve_artifact_snapshot_by_fork(artifact, &fork_hash)?
                else {
                    return Ok(None);
                };
                let Some(entry) = snapshot_file_entry(&snapshot_ref.snapshot, path) else {
                    return Ok(None);
                };
                let mount = self
                    .mount_codebase_snapshot(&snapshot_ref.code_artifact_id)?
                    .ok_or(Error::EntityNotFound)?;
                let bytes = mount.read_file(path)?.ok_or(Error::EntityNotFound)?;
                Ok(Some(ArtifactServedFile {
                    artifact: artifact.to_owned(),
                    selector,
                    serve_tier: ArtifactServeTier::Private,
                    export,
                    path: path.to_owned(),
                    media_type: None,
                    content_hash: entry.content_hash,
                    size_bytes: entry.size_bytes,
                    bytes,
                }))
            }
            ArtifactExportRef::BlobVersion {
                artifact_id,
                version,
            } => {
                if artifact != artifact_id.to_hex() || version == 0 {
                    return Ok(None);
                }
                let rtxn = self.store.env.read_txn()?;
                if self
                    .get_blob_artifact_in_txn(&rtxn, &artifact_id)?
                    .is_none()
                {
                    return Ok(None);
                }
                let Some(record) =
                    self.blob_artifact_version_metadata_in_txn(&rtxn, &artifact_id, version)?
                else {
                    return Ok(None);
                };
                // Pin the export presentation with the version. Later body
                // edits cannot rename or retype an already-published route.
                if path != "export" && path != "index.html" && path != record.export_name {
                    return Ok(None);
                }
                let bytes = self
                    .read_blob_artifact_version_in_txn(&rtxn, &artifact_id, version)?
                    .ok_or(Error::EntityNotFound)?;
                if *blake3::hash(&bytes).as_bytes() != record.content_hash {
                    return Err(Error::CorruptedIndex("blob export content hash"));
                }
                let size_bytes = u64::try_from(bytes.len())
                    .map_err(|_| Error::ArithmeticOverflow("blob export length"))?;
                Ok(Some(ArtifactServedFile {
                    artifact: artifact.to_owned(),
                    selector,
                    serve_tier: ArtifactServeTier::Private,
                    export,
                    path: path.to_owned(),
                    media_type: Some(record.export_media_type),
                    content_hash: record.content_hash,
                    size_bytes,
                    bytes,
                }))
            }
        }
    }

    pub fn request_artifact_publish(
        &self,
        request: &ArtifactPublishVerbRequest,
    ) -> Result<ArtifactPublishVerbOutcome> {
        OutboundDispatchPipeline.dispatch_artifact_publish(self, request)
    }

    /// Exact, engine-computed approval key for an owner to approve one publish.
    /// This key is not authority until an authenticated `approve_once` records it.
    pub fn artifact_publish_approval_digest(
        &self,
        request: &ArtifactPublishVerbRequest,
    ) -> Result<crate::consent::EffectDigest> {
        publish::artifact_publish_approval_digest(self, request)
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
    export: ArtifactExportRef,
    stale_taint_override: bool,
    serve_tier: ArtifactServeTier,
) -> Result<()> {
    let key = artifact_pointer_key(artifact, channel)?;
    let mut value = match export {
        ArtifactExportRef::ForkHash(hash) => hash.to_vec(),
        ArtifactExportRef::BlobVersion {
            artifact_id,
            version,
        } => {
            let mut value = Vec::with_capacity(26);
            value.push(ARTIFACT_POINTER_BLOB_TAG);
            value.extend_from_slice(artifact_id.as_bytes());
            value.extend_from_slice(&version.to_be_bytes());
            value
        }
    };
    if stale_taint_override || serve_tier != ArtifactServeTier::Private {
        value.push(u8::from(stale_taint_override));
        match serve_tier {
            ArtifactServeTier::Private => {}
            ArtifactServeTier::Public => value.push(1),
            ArtifactServeTier::LinkToken(capability) => {
                value.push(2);
                value.extend_from_slice(&capability.0);
            }
            ArtifactServeTier::WorldMembers(world_id) => {
                if world_id == 0 {
                    return Err(Error::InvalidConfig(
                        "artifact world id cannot be zero".into(),
                    ));
                }
                value.push(3);
                value.extend_from_slice(&world_id.to_be_bytes());
            }
        }
    }
    store.vault_meta.put(wtxn, &key, &value)?;
    Ok(())
}

/// A deleted blob must not leave a channel that can spring back to life if
/// the caller later creates another version chain under the same entity id.
pub(crate) fn remove_blob_pointers_in_txn(
    store: &crate::store::Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let artifact = id.to_hex();
    for channel in [
        ArtifactPointerChannel::Published,
        ArtifactPointerChannel::Preview,
    ] {
        let key = artifact_pointer_key(&artifact, channel)?;
        if let Some(raw) = store.vault_meta.get(wtxn, &key)?
            && matches!(decode_artifact_pointer_row(&raw)?.0,
                ArtifactExportRef::BlobVersion { artifact_id, .. } if artifact_id == *id)
        {
            store.vault_meta.delete(wtxn, &key)?;
        }
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

/// Legacy 32/33-byte fork rows remain byte-identical. A blob row has a
/// disjoint 25/26-byte tagged frame: tag, entity id, big-endian version,
/// and the optional stale-taint override stamp.
fn decode_artifact_pointer_row(raw: &[u8]) -> Result<(ArtifactExportRef, bool, ArtifactServeTier)> {
    // Fork and blob base frames are disjoint lengths even with the tier suffix.
    let base_len = match raw.len() {
        32 | 33 | 34 | 42 | 66 => 32,
        25 | 26 | 27 | 35 | 59 => 25,
        _ => return Err(Error::CorruptedIndex("artifact pointer frame")),
    };
    let export = if base_len == 32 {
        ArtifactExportRef::ForkHash(
            raw[..32]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("artifact pointer fork hash"))?,
        )
    } else {
        if raw[0] != ARTIFACT_POINTER_BLOB_TAG {
            return Err(Error::CorruptedIndex("artifact pointer blob tag"));
        }
        let id = raw[1..17]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("artifact pointer blob id"))?;
        let artifact_id = EntityId::from_bytes(id)
            .map_err(|_| Error::CorruptedIndex("artifact pointer blob id"))?;
        let version = u64::from_be_bytes(
            raw[17..25]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("artifact pointer blob version"))?,
        );
        if version == 0 {
            return Err(Error::CorruptedIndex("artifact pointer blob version"));
        }
        ArtifactExportRef::BlobVersion {
            artifact_id,
            version,
        }
    };
    let (stale, tier) = match &raw[base_len..] {
        [] => (false, ArtifactServeTier::Private),
        [ARTIFACT_POINTER_STALE_OVERRIDE_STAMP] => (true, ArtifactServeTier::Private),
        [stamp @ (0 | 1), 1] => (*stamp == 1, ArtifactServeTier::Public),
        [stamp @ (0 | 1), 2, digest @ ..] if digest.len() == 32 => (
            *stamp == 1,
            ArtifactServeTier::LinkToken(ArtifactLinkCapability(
                digest
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("artifact token digest"))?,
            )),
        ),
        [stamp @ (0 | 1), 3, world @ ..] if world.len() == 8 => {
            let world_id = u64::from_be_bytes(
                world
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("artifact world id"))?,
            );
            if world_id == 0 {
                return Err(Error::CorruptedIndex("artifact world id"));
            }
            (*stamp == 1, ArtifactServeTier::WorldMembers(world_id))
        }
        _ => return Err(Error::CorruptedIndex("artifact pointer tier")),
    };
    Ok((export, stale, tier))
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

pub(crate) fn validate_artifact_id(artifact: &str) -> Result<()> {
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

#[path = "artifact_hosting/access.rs"]
mod access;
pub use self::access::{ArtifactLinkCapability, ArtifactServeTier};

#[path = "artifact_hosting/publish.rs"]
mod publish;
pub(crate) use self::publish::artifact_publish_receipts;
#[cfg(any(test, feature = "test-hooks"))]
use self::publish::publish_artifact_pointer_in_txn;

#[cfg(test)]
mod tests;
