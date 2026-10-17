//! `vault.artifacts.create` (OF-181): one artifact with its first version,
//! the composite `POST /v1/core/artifacts` makes. The REST route and the
//! row run this one door as their bound actor.

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use super::{ArtifactView, BlobArtifactBody, BlobVersionProvenance};
use crate::edge::EdgeActorClass;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::provenance::made_by::MadeBy;
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;

/// A new artifact and the bytes of its first version.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactCreateRequest {
    pub name: String,
    pub media_type: String,
    /// The first version's bytes, standard base64.
    pub content_base64: String,
    /// The run that made the bytes; an agent's version names it.
    #[serde(default)]
    pub run_ref: Option<String>,
    /// The first version's made_by envelope; the writer's own when absent.
    #[serde(default)]
    pub made_by: Option<serde_json::Value>,
}

impl Memory<'_> {
    /// `vault.artifacts.create`: registers an artifact and appends its first
    /// version as the bound actor. A person's upload is theirs; an agent's
    /// version names the run that made it. The two writes are sequential: a
    /// refused version leaves the registration.
    /// # Errors
    /// Bytes that are not base64, a made_by that is no envelope, an agent
    /// with no run, or the vault's refusal.
    pub fn artifacts_create(
        &self,
        input: &ArtifactCreateRequest,
    ) -> MemoryResult<Option<ArtifactView>> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&input.content_base64)
            .map_err(|_| MemoryError::bad_request("content must be base64"))?;
        let made_by = input
            .made_by
            .clone()
            .map(serde_json::from_value::<MadeBy>)
            .transpose()
            .map_err(|_| MemoryError::bad_request("made_by is not a made_by envelope"))?;
        let actor = WriteActor::new(self.actor(), self.actor_class());
        let provenance = match &input.run_ref {
            Some(run_ref) => BlobVersionProvenance::AgentRun {
                run_ref: run_ref.clone(),
            },
            None if actor.actor_class() == EdgeActorClass::Human => {
                BlobVersionProvenance::UserUpload
            }
            None => {
                return Err(MemoryError::bad_request(
                    "an agent's version names its run_ref",
                ));
            }
        };
        let vault = self.vault();
        let now = vault.now_recorded_at();
        let occurred = TimeRange {
            start: now,
            end: now,
        };
        let id = vault.new_entity_id()?;
        vault.put_blob_artifact(
            &id,
            &BlobArtifactBody::new(input.name.clone(), input.media_type.clone()),
            occurred,
            now,
        )?;
        match &made_by {
            Some(made_by) => vault.append_blob_artifact_version_made_by(
                &id,
                None,
                &bytes,
                &provenance,
                made_by,
                actor,
                occurred,
                now,
            )?,
            None => vault.append_blob_artifact_version(
                &id,
                &bytes,
                &provenance,
                actor,
                occurred,
                now,
            )?,
        };
        Ok(vault.blob_artifact_view(&id)?)
    }
}
