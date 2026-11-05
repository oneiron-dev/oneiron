//! Value types for artifact pointers, immutable exports, and publication.
//! Keeps the existing public type and constructor paths through the parent.
//! Row codecs, the private channel decoder, and publication state stay there.

use crate::code_snapshot::snapshot::CodebaseForkHash;
use crate::code_snapshot::snapshot::CodebaseSnapshot;
use crate::write_envelope::WriteActor;
use oneiron_base::error::CodeError;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use serde::{Deserialize, Serialize};

pub const ARTIFACT_POINTER_CHANNELS: [&str; 2] = ["published", "preview"];

/// Exactly one immutable export, owned by the artifact in the route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum ArtifactExportRef {
    ForkHash(CodebaseForkHash),
    BlobVersion { artifact_id: EntityId, version: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactSnapshotRef {
    pub artifact: String,
    pub fork_hash: CodebaseForkHash,
    pub code_artifact_id: EntityId,
    pub snapshot: CodebaseSnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactPublishVerbStatus {
    Proposed,
    Published,
    /// A full count-bound budget window paces the publish (FIX 12156):
    /// nothing was recorded, charged or published. Bring it back at
    /// `retry_at`, Unix seconds on the engine's clock.
    Paced {
        retry_at: u64,
    },
}
