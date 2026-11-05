//! Wire shapes over the existing publication Gate and private preview lease.

use serde::{Deserialize, Serialize};

use crate::artifact_hosting::vocabulary::ArtifactExportRef;
use crate::artifact_hosting::vocabulary::ArtifactPublishVerbStatus;
use oneiron_contracts::entity_id::EntityId;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ArtifactPublishApproval {
    /// Engine-computed key for the existing owner approve-once door. Merely
    /// reading this key grants nothing; it binds the entire publish request.
    pub effect_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ArtifactUnpublished {
    pub removed: bool,
}

/// The declared process is resolved only by the serving session runtime.
/// This is not a caller-supplied OS pid, destination address or public port.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactPreviewPort {
    pub process_ref: String,
    pub port: u16,
}

/// The owner's lease declaration. The authenticated owner supplies owner_ref
/// at the host, and the whole manifest must match the runtime's declaration.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactPreviewRegisterRequest {
    pub session_ref: String,
    pub lease_ref: String,
    pub expires_at: u64,
    pub preview: ArtifactPreviewPort,
}

impl ArtifactPreviewRegisterRequest {
    pub fn into_manifest(
        self,
        owner_ref: String,
    ) -> crate::artifact_hosting::preview::PreviewSessionManifest {
        crate::artifact_hosting::preview::PreviewSessionManifest {
            session_ref: self.session_ref,
            lease_ref: self.lease_ref,
            owner_ref,
            expires_at: self.expires_at,
            preview: crate::artifact_hosting::preview::PreviewPortDeclaration {
                process_ref: self.preview.process_ref,
                port: self.preview.port,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactPreviewRequest {
    pub session_ref: String,
    pub lease_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactPreviewInviteRequest {
    pub session_ref: String,
    pub lease_ref: String,
    pub principal_ref: EntityId,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactPreviewStage {
    Draft,
}

/// A displayable endpoint plus this caller's preview-only bootstrap URL.
/// The URL is never an owner API credential and cannot publish an artifact.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ArtifactPreviewView {
    pub session_ref: String,
    pub lease_ref: String,
    pub local_url: String,
    pub stage: ArtifactPreviewStage,
    /// Never a public audience; only owner, named invitees or a sharing URL.
    pub private: bool,
    pub expires_at: u64,
    pub access_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ArtifactPreviewClosed {
    pub closed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ArtifactPreviewInvitation {
    pub principal_ref: EntityId,
    pub invited: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ArtifactPreviewShare {
    /// None after revocation. A new sharing URL replaces the earlier one.
    pub access_url: Option<String>,
}
