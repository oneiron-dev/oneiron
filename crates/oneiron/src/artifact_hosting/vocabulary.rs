//! Core half of `artifact_hosting::vocabulary`: its store-layer items live in `oneiron_store::artifact_hosting::vocabulary` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::artifact_hosting::vocabulary::*;

use super::{
    ARTIFACT_CHANNEL_PREVIEW, ARTIFACT_CHANNEL_PUBLISHED, ArtifactServeTier, CodeError,
    CodebaseForkHash, CodebaseSnapshot, EntityId, Error, ReceiptRecord, Result, WriteActor,
};
use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub use oneiron_verb_wire::artifact_hosting::vocabulary::ArtifactPointerChannel;

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ArtifactPublishVerbOutcome {
    pub status: ArtifactPublishVerbStatus,
    pub pointer: Option<ArtifactPointer>,
    /// Only an admitted publish has a share-style, replayable receipt.
    pub receipt: Option<ReceiptRecord>,
    pub gate_decision_ref: String,
}
