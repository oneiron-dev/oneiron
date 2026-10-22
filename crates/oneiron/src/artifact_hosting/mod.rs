//! Local artifact hosting over pinned code snapshots and blob exports.
//!
//! The serving surface is intentionally pointer-shaped: `published` and
//! `preview` point at immutable fork hashes or blob versions. Removing a pointer
//! kills the channel URL; direct version mounts remain read-only.

use heed::RwTxn;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::Vault;
use crate::code_artifact::{CodeArtifactClass, decode_code_artifact_body};
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
use crate::ports::EntityStoreRead;
use crate::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};
use crate::registry::{ArtifactFamilyKindId, artifact_family_kind_of};
use crate::secret_rotation::{
    ArtifactTaintState, allow_stale_publish_in_txn, exhaust_taint_refs_in_txn,
    taint_state_for_refs_in_txn,
};
use crate::side_table::{self, CodecError, Raw, RawValue, SideKey, SideTable};
use crate::store::GateDecisionId;
use crate::write_envelope::WriteActor;

/// Typed requests and replies for publication and live-preview host doors.
pub mod door_types;
mod pointer_rows;
/// Lease-bound live process previews, separate from pinned artifact pointers.
pub mod preview;
mod publication_sync;
mod serving;
// The serving descriptor of a published blob version (FIX 1195).
mod serving_blob;
mod vocabulary;
use self::pointer_rows::{
    decode_artifact_pointer_row, hex_nibble, put_artifact_pointer_in_txn, snapshot_file_entry,
    validate_artifact_path,
};
pub(crate) use self::pointer_rows::{remove_blob_pointers_in_txn, validate_artifact_id};
pub use self::publication_sync::ArtifactPublicationOutcome;
use self::publication_sync::mark_publication_in_txn;
pub(crate) use self::publication_sync::{
    ArtifactPublicationCursor, ArtifactPublicationPart, ArtifactPublicationStep,
};
pub use self::vocabulary::{
    ARTIFACT_POINTER_CHANNELS, ArtifactExportRef, ArtifactPointer, ArtifactPointerChannel,
    ArtifactPublishVerbOutcome, ArtifactPublishVerbRequest, ArtifactPublishVerbStatus,
    ArtifactServedFile, ArtifactSnapshotRef, ArtifactSnapshotSelector,
};

/// One exact publish identity, even after its pointer changes or disappears.
const ARTIFACT_ADMISSIONS: SideTable<
    EntityId,
    ArtifactPublishAdmission,
    crate::side_table::LegacyJson,
> = SideTable::new(&side_table::ARTIFACT_PUBLISH_ADMISSION);

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

/// One pointer row's value: the export frame, then an optional suffix. A
/// private pointer keeps the pre-tier frame: a bare 32-byte fork hash (every
/// pointer written before SECRET-04) or 33 bytes when the publish rode a
/// stale-taint override. Any other tier appends the stale flag (0 or 1), a
/// tier tag and the tier body; `decode_artifact_pointer_row` reads it back.
struct ArtifactPointerRow {
    export: ArtifactExportRef,
    stale_taint_override: bool,
    serve_tier: ArtifactServeTier,
}

impl RawValue for ArtifactPointerRow {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let mut value = match self.export {
            ArtifactExportRef::ForkHash(hash) => hash.to_vec(),
            ArtifactExportRef::BlobVersion {
                artifact_id,
                version,
            } => {
                let mut bytes = Vec::with_capacity(26);
                bytes.push(ARTIFACT_POINTER_BLOB_TAG);
                bytes.extend_from_slice(artifact_id.as_bytes());
                bytes.extend_from_slice(&version.to_be_bytes());
                bytes
            }
        };
        if self.stale_taint_override || self.serve_tier != ArtifactServeTier::Private {
            // A private override is the bare SECRET-04 stamp (0x01).
            value.push(u8::from(self.stale_taint_override));
            match self.serve_tier {
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
                        )
                        .into());
                    }
                    value.push(3);
                    value.extend_from_slice(&world_id.to_be_bytes());
                }
            }
        }
        Ok(value)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let (export, stale_taint_override, serve_tier) = decode_artifact_pointer_row(bytes)?;
        Ok(Self {
            export,
            stale_taint_override,
            serve_tier,
        })
    }
}

const ARTIFACT_POINTERS: SideTable<ArtifactPointerRowKey, ArtifactPointerRow, Raw> =
    SideTable::new(&side_table::ARTIFACT_POINTER);

/// The pointer row's value framing.
///
/// Code pointers remain 32-byte fork hashes (33 with SECRET-04 override).
/// Blob pointers use a disjoint tagged frame (25 bytes, or 26 with override).
/// The trailing stamp records a stale-taint publish override on either kind.
const ARTIFACT_POINTER_STALE_OVERRIDE_STAMP: u8 = 0x01;
const ARTIFACT_POINTER_BLOB_TAG: u8 = 0x02;

impl ArtifactPointerChannel {
    #[must_use]
    const fn from_key_byte(byte: u8) -> Option<Self> {
        match byte {
            ARTIFACT_CHANNEL_PUBLISHED => Some(Self::Published),
            ARTIFACT_CHANNEL_PREVIEW => Some(Self::Preview),
            _ => None,
        }
    }
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
        if removed {
            mark_publication_in_txn(&self.store, &mut wtxn, channel, artifact)?;
        }
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

mod access;
pub use self::access::{ArtifactLinkCapability, ArtifactServeTier};

mod publish;
#[cfg(any(test, feature = "test-hooks"))]
use self::publish::publish_artifact_pointer_in_txn;
pub(crate) use self::publish::{artifact_publish_gate_refs_in_txn, artifact_publish_receipts};

#[cfg(test)]
mod tests;
