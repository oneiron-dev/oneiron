//! Secret sight for artifact and typed-body reads by a bound memory caller.
use crate::EntityId;
use crate::claim::ClaimReadStatus;
use crate::edge::EdgeActorClass;
use crate::error::Error;
use crate::memory::{
    MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult, verify_actor_binding,
};
use crate::secret_custody::{RevealAsker, SecretSight};
use crate::task_verb::task_create_origin_in_txn;
use crate::typed_body::LiftedSources;

impl Memory<'_> {
    /// The request's real Owner proof for queue-check exhaust, when the host
    /// bound the owner's own direct request (`with_owner_authorship`).
    /// Borrowed from the existing field; never a new field or factory.
    pub(crate) fn queue_check_request_owner(&self) -> Option<&crate::consent::AuthenticatedOwner> {
        self.owner_authorship.as_ref()
    }

    /// One artifact version's export, its bytes as this caller reads them: a
    /// file stored with keys in it reads whole for the owner, and for an
    /// agent that says `why` once a grant covers its keys (OF-560, granted
    /// file sight); every other read, masked.
    pub(crate) fn export_blob_artifact_sighted(
        &self,
        artifact: &EntityId,
        version: Option<u64>,
        why: Option<&str>,
    ) -> MemoryResult<Option<crate::blob_artifact::ArtifactExport>> {
        self.export_blob_artifact_sighted_with_owner(artifact, version, why, None)
    }

    pub(crate) fn export_blob_artifact_sighted_as_owner(
        &self,
        artifact: &EntityId,
        version: Option<u64>,
        why: Option<&str>,
        owner: &crate::consent::AuthenticatedOwner,
    ) -> MemoryResult<Option<crate::blob_artifact::ArtifactExport>> {
        self.export_blob_artifact_sighted_with_owner(artifact, version, why, Some(owner))
    }

    fn export_blob_artifact_sighted_with_owner(
        &self,
        artifact: &EntityId,
        version: Option<u64>,
        why: Option<&str>,
        owner: Option<&crate::consent::AuthenticatedOwner>,
    ) -> MemoryResult<Option<crate::blob_artifact::ArtifactExport>> {
        let vault = self.vault();
        // FIX 4997: pin the exact version once, then judge a wording
        // version's source through the caller's own lane; no sight bypasses
        // the check. An unmarked version keeps its behavior below with the
        // pinned version threaded through (no head re-resolution, so no race
        // from an unmarked head into a protected new head).
        let Some((pinned, _)) = vault.blob_artifact_version_rows(artifact, version)? else {
            return Ok(None);
        };
        if vault.blob_artifact_version_is_queue_check(artifact, pinned)? {
            let Some(owner) = owner else {
                return Ok(None);
            };
            self.artifact_owner_matches(owner)?;
            let lane = self.queue_check_owner_read_lane(owner, ClaimReadStatus::Recorded)?;
            return Ok(vault.export_blob_artifact_for_reader(
                artifact,
                Some(pinned),
                self.secret_sight()?,
                Some(owner),
                Some(&lane),
            )?);
        }
        if vault.commitment_reminder_wording_protected(artifact, pinned)?
            && !self
                .read_lane(ClaimReadStatus::Recorded)?
                .commitment_reminder_wording_source_readable(artifact, pinned)?
        {
            return Ok(None);
        }
        let version = Some(pinned);
        // A repo-marked version reads as a repo file before the owner-key
        // sight below: a tool or a run on the owner's key gets the masked
        // copy, or the file reveal with a why (FIX 7608, FIX 8960).
        if self.repo_reads_masked()?
            && let Some(export) = self.export_repo_marked_artifact(artifact, version, why)?
        {
            return Ok(export);
        }
        let sight = self.secret_sight()?;
        let Some(why) = why.filter(|_| {
            sight == SecretSight::Masked && self.actor_class() == EdgeActorClass::Agent
        }) else {
            return Ok(vault.export_blob_artifact_as(artifact, version, sight)?);
        };
        // A marked file kept in its body file is judged by its stored digest,
        // then read masked or whole as it streams, never held whole beside
        // its copy (FIX 6507).
        if let Some((pinned, hash)) = vault.marked_blob_version_file(artifact, version)? {
            let asker = self.reveal_asker()?;
            if let Some(sight) = vault.marked_file_sight(&asker, artifact, &hash, why)? {
                return Ok(vault.export_blob_artifact_as(artifact, Some(pinned), sight)?);
            }
        }
        let Some(mut file) = vault.export_blob_artifact_raw(artifact, version)? else {
            return Ok(None);
        };
        let asker = self.reveal_asker()?;
        let sight = vault.file_sight(&asker, &file.artifact_id, &file.bytes, why)?;
        file.bytes = vault.sighted_asset_bytes_with_digest(
            std::mem::take(&mut file.bytes),
            &file.content_hash,
            sight,
        )?;
        // FIX 4513: once, after custody read the stored bytes.
        file.bytes = vault.resolve_docx_authors(std::mem::take(&mut file.bytes))?;
        Ok(Some(file))
    }

    /// How this caller reads one projection of `artifact`'s typed body (a
    /// deck's export, a body's view) that `projection_fingerprint` names,
    /// whose lifted texts name `lifted`, read in the projection's snapshot
    /// ([`crate::Vault::typed_body_lifted_sources_in_txn`]) (OF-067, FIX
    /// 2941). The owner, a body whose texts name no key, and a reader that is
    /// no agent or says no `why` read as [`Memory::secret_sight`] says. An
    /// agent that says `why` reads it whole once a grant covers its keys and
    /// this read's receipts are written, and masked otherwise, its ask filed
    /// ([`crate::Vault::typed_body_sight`]). The sight is this read's alone:
    /// [`Memory::secret_sight`] and [`Memory::reads_lifted_keys_masked`] do
    /// not change.
    pub(crate) fn typed_body_read_sight(
        &self,
        artifact: &EntityId,
        projection_fingerprint: &[u8; 32],
        lifted: &LiftedSources,
        why: Option<&str>,
    ) -> MemoryResult<SecretSight> {
        let sight = self.secret_sight()?;
        let Some(why) = why.filter(|_| {
            sight == SecretSight::Masked
                && !lifted.is_empty()
                && self.actor_class() == EdgeActorClass::Agent
        }) else {
            return Ok(sight);
        };
        let asker = self.reveal_asker()?;
        Ok(self
            .vault()
            .typed_body_sight(&asker, artifact, projection_fingerprint, lifted, why)?)
    }

    /// The asker of a reveal: the calling agent, and the project and run its
    /// host bound. Only an agent reveals to a model; a reveal writes a
    /// receipt, so an anonymous off-record session cannot make one.
    pub(crate) fn reveal_asker(&self) -> MemoryResult<RevealAsker> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        if self.actor_class() != EdgeActorClass::Agent {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "only an agent reveals a secret to its model",
                &["The owner reads a value at POST /v1/owner/secrets/reveal, with a reason."],
            ));
        }
        if self.keeps_no_record() {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "a reveal writes its receipt, and an anonymous off-record session keeps none",
                &["Reveal outside the anonymous session."],
            ));
        }
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        let origin = task_create_origin_in_txn(self, &txn, self.task_host())?;
        // The leased try is the run a run-bound secret's record names
        // (FIX 8028); its task ref is the task a task's grant names
        // (FIX 2354).
        let attempt = origin.as_ref().and_then(|origin| origin.parent_attempt());
        let task = match attempt {
            Some(attempt) => crate::AttemptQueue::new(self.vault())
                .get_in_txn(&txn, attempt)?
                .and_then(|record| record.task_ref),
            None => None,
        };
        drop(txn);
        // The provider is the host's: the one its ladder served this
        // program's turn from, never a field the agent sends.
        Ok(RevealAsker::new(
            self.actor(),
            origin.as_ref().and_then(|origin| origin.project_ref()),
            origin.and_then(|origin| origin.run_id()),
        )
        .with_provider(self.model_provider())
        .with_reader(self.read_key()?)
        .with_attempt(attempt)
        .with_task(task)
        .with_step(self.host_step())
        .with_exec_run(self.bound_code_run()))
    }
}
