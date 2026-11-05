//! Core half of `blob_artifact::create`: its store-layer items live in `oneiron_store::blob_artifact::create` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::blob_artifact::create::*;

use super::{ArtifactView, BlobArtifactBody, BlobVersionProvenance};
use crate::edge::EdgeActorClass;
use crate::memory::Memory;
use crate::temporal::TimeRange;
use crate::write_envelope::provenance::made_by::MadeBy;
use base64::Engine as _;
use oneiron_contracts::memory::{MemoryError, MemoryResult};
use serde::{Deserialize, Serialize};

impl Memory<'_> {
    /// `vault.artifacts.create`: registers an artifact and appends its first
    /// version as the bound actor. A person's upload is theirs; an agent's
    /// version names the run that made it. A supplied made_by keeps its
    /// attribution as input, never as native producer authority (FIX 9618).
    /// The two writes are sequential: a refused version leaves the registration.
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
        let actor = self.write_actor();
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
