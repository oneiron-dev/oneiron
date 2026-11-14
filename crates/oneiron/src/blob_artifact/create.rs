//! `vault.artifacts.create` (OF-181): one artifact with its first version,
//! the composite `POST /v1/core/artifacts` makes. The REST route and the
//! row run this one door as their bound actor.

use base64::Engine as _;

use super::{ArtifactView, BlobArtifactBody, BlobBodyFile, BlobVersionProvenance};
use crate::edge::EdgeActorClass;
use crate::memory::Memory;
use crate::temporal::TimeRange;
use crate::write_envelope::provenance::made_by::MadeBy;
use oneiron_contracts::memory::{MemoryError, MemoryResult};

#[doc(hidden)]
pub use oneiron_verb_wire::blob_artifact::create::ArtifactCreateRequest;

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
        self.create_artifact(input, FirstVersion::Bytes(&bytes))
    }

    /// [`Self::artifacts_create`] of a first version an ingress door decoded
    /// into `body` before any writer opened (FIX 22074): `input` names the
    /// artifact and holds no content of its own. A body no longer than the
    /// asset plane's inline size is read once; a longer one is staged from
    /// the file inside the version's writer, never held whole.
    /// # Errors
    /// [`Self::artifacts_create`]'s errors, an `input` that holds content,
    /// and the file's read errors.
    pub fn artifacts_create_file(
        &self,
        input: &ArtifactCreateRequest,
        body: &BlobBodyFile<'_>,
    ) -> MemoryResult<Option<ArtifactView>> {
        if !input.content_base64.is_empty() {
            return Err(MemoryError::bad_request(
                "content arrives in the body file, not in the request",
            ));
        }
        self.create_artifact(input, FirstVersion::File(body))
    }

    fn create_artifact(
        &self,
        input: &ArtifactCreateRequest,
        first: FirstVersion<'_>,
    ) -> MemoryResult<Option<ArtifactView>> {
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
        match (first, &made_by) {
            (FirstVersion::Bytes(bytes), Some(made_by)) => vault
                .append_blob_artifact_version_made_by(
                    &id,
                    None,
                    bytes,
                    &provenance,
                    made_by,
                    actor,
                    occurred,
                    now,
                )?,
            (FirstVersion::Bytes(bytes), None) => {
                vault.append_blob_artifact_version(&id, bytes, &provenance, actor, occurred, now)?
            }
            (FirstVersion::File(body), made_by) => vault.append_blob_artifact_version_file(
                &id,
                body,
                &provenance,
                made_by.as_ref(),
                actor,
                occurred,
                now,
            )?,
        };
        Ok(vault.blob_artifact_view(&id)?)
    }
}

/// Where a created artifact's first version comes from: decoded bytes, or a
/// body file an ingress door decoded (FIX 22074).
#[derive(Clone, Copy)]
enum FirstVersion<'a> {
    Bytes(&'a [u8]),
    File(&'a BlobBodyFile<'a>),
}
