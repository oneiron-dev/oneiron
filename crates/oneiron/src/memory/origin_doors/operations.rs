//! Origin doors: authority get and set, checkout door binding, code export and publications.
//! `Memory::origin_authority_get_as` is its call surface.
//! `memory::origin_doors::types` defines the records these take and return.

use super::*;
use crate::checkout::lease::CheckoutRepoOps;
use crate::git_wire::{GitOid, GitRefName, GitWireRepo};
use crate::origin::export::EngineCommitExport;
use crate::origin::publication::{OriginPublicationRecord, OriginPublicationStatus};
use crate::origin::residence::{
    ORIGIN_WRITER_ERASED_REFUSAL, OriginAuthorityLease, OriginHostAuthority,
};
use crate::origin::smart_http::push_queue_key;

impl Memory<'_> {
    /// `vault.code.origin.authority.get`: one served repository authority row
    /// and this install machine, as `/v1/owner/origin-authority` reads them.
    pub fn origin_authority_get_as(
        &self,
        owner: &AuthenticatedOwner,
        input: OriginRepoRequest,
    ) -> MemoryResult<OriginAuthorityView> {
        self.origin_owner(owner)?;
        let authority = self.vault.served_origin_authority(&input.repo)?;
        let host = self
            .vault
            .local_machine()?
            .map(|machine| machine.id.to_hex());
        Ok(OriginAuthorityView {
            repo: input.repo,
            host,
            authority,
        })
    }

    /// `vault.code.origin.authority.set`: the owner cutover of an existing
    /// served repository, through the unchanged engine CAS. An epoch that
    /// moved refuses; nothing retries, fails over or creates a repository.
    pub fn origin_authority_set_as(
        &self,
        owner: &AuthenticatedOwner,
        input: OriginAuthoritySetRequest,
    ) -> MemoryResult<OriginAuthorityView> {
        self.origin_owner(owner)?;
        let host = self.vault.local_machine()?.map(|machine| machine.id);
        let writer = origin_authority_writer(input.writer.as_deref(), host)?;
        let authority = self.vault.set_served_origin_authority(
            &input.repo,
            input.expected_epoch,
            input.residence,
            writer,
            input.mirror,
        )?;
        Ok(OriginAuthorityView {
            repo: input.repo,
            host: host.map(|host| host.to_hex()),
            authority: Some(authority),
        })
    }

    /// `vault.code.checkout.bind`: materializes the owner live checkout and
    /// points its remote at the door, through the unchanged GitWire port. No
    /// lease is minted and no upstream credential is copied.
    pub fn checkout_door_bind_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CheckoutDoorBindRequest,
    ) -> MemoryResult<CheckoutDoorBinding> {
        self.origin_owner(owner)?;
        let lease = self.origin_checkout_lease(owner, &input.repo, &input.checkout, input.epoch)?;
        let wire = self.origin_door_wire(&input.endpoint)?;
        wire.materialize(&lease).map_err(checkout_refusal)?;
        let path = wire
            .checkout_worktree_path(&lease)
            .map_err(checkout_refusal)?;
        let checkout = lease.checkout_id.to_string();
        let remote_url = format!(
            "{}/lease/{checkout}.{}/{}.git",
            input.endpoint, lease.epoch, input.repo
        );
        Ok(CheckoutDoorBinding {
            repo: input.repo,
            checkout,
            epoch: lease.epoch,
            checkout_path: path.to_string_lossy().into_owned(),
            remote_url,
        })
    }

    /// `vault.code.export`: one finalized, promoted CodeRevision exported
    /// through the unchanged engine export and origin publication protocol.
    /// The engine regenerates every byte; no tree, commit, actor or result is
    /// taken from the request.
    pub fn code_export_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeExportRequest,
    ) -> MemoryResult<CodeExportResult> {
        self.origin_owner(owner)?;
        let wire = self.origin_door_wire(&input.endpoint)?;
        let repo = self.origin_export_source(owner, &wire, &input)?;
        let request = origin_export_target(&input)?;
        let revision = self
            .vault
            .get_code_revision(&request.revision_id)?
            .ok_or_else(|| MemoryError::not_found("code revision not found"))?;
        self.origin_readable(revision.revision_id)?;
        self.origin_readable(revision.session_id)?;
        let author = revision
            .commit_metadata
            .as_ref()
            .map(|metadata| metadata.author);
        self.origin_listed(revision.provenance_claim_id.into_iter().chain(author))?;
        let authority = self.origin_export_authority(&input.repo)?;
        let receipt =
            self.vault
                .export_engine_commit(&wire, &repo, &request, authority.as_ref())?;
        let publication = self.origin_publication_view(&receipt.record)?;
        Ok(CodeExportResult {
            revision: request.revision_id,
            git_commit: receipt.record.new_oid.as_str().to_owned(),
            remote_url: format!("{}/{}.git", input.endpoint, input.repo),
            receipt: receipt.record.publication_id,
            publication,
            ref_was_already_applied: receipt.ref_was_already_applied,
            wire_replayed: receipt.wire_replayed(),
            wire_rejected: receipt.wire_rejection().is_some(),
        })
    }

    /// `vault.code.origin.publications`: every durable publication of one
    /// served ref to one commit, in every status, ordered by publication id.
    /// A read only: no reconcile, retry or row cap, and no synthesized push
    /// acknowledgement.
    pub fn origin_publications_as(
        &self,
        owner: &AuthenticatedOwner,
        input: OriginPublicationsRequest,
    ) -> MemoryResult<OriginPublicationsView> {
        self.origin_owner(owner)?;
        let ref_name = GitRefName::parse_full(input.ref_name)?;
        let commit = GitOid::parse_hex(input.git_commit)?;
        let repo_dir = origin_repo_dir(self.vault, &input.repo)?;
        let identity = GitWire::new(self.vault)?.repository_identity(&repo_dir)?;
        let repo_id = crate::origin::lfs::lfs_repo_id(&identity.as_hex())?;
        let mut publications = Vec::new();
        for record in self.origin_matching_publications(repo_id, &ref_name, &commit)? {
            publications.push(self.origin_publication_view(&record)?);
        }
        Ok(OriginPublicationsView {
            repo: input.repo,
            publications,
        })
    }

    /// The CALL behind the publication lookup: exact repository, ref and
    /// commit, every matching history in every status, ordered by id.
    pub(super) fn origin_matching_publications(
        &self,
        repo_id: EntityId,
        ref_name: &GitRefName,
        commit: &GitOid,
    ) -> MemoryResult<Vec<OriginPublicationRecord>> {
        let mut ids = self.vault.origin_publication_ids(Some(repo_id))?;
        ids.sort_unstable();
        let mut records = Vec::new();
        for id in ids {
            let Some(record) = self.vault.origin_publication(id)? else {
                continue;
            };
            if record.ref_name == *ref_name && record.new_oid == *commit {
                records.push(record);
            }
        }
        Ok(records)
    }

    /// The CALL behind the export source: the live checkout the owner holds,
    /// already materialized, whose object store is the served repository.
    /// A different clone or a caller path cannot stand in for it.
    pub(super) fn origin_export_source(
        &self,
        owner: &AuthenticatedOwner,
        wire: &GitWire<'_>,
        input: &CodeExportRequest,
    ) -> MemoryResult<GitWireRepo> {
        let lease = self.origin_checkout_lease(owner, &input.repo, &input.checkout, input.epoch)?;
        let tree = wire
            .checkout_worktree_path(&lease)
            .map_err(checkout_refusal)?;
        if !tree.is_dir() {
            return Err(MemoryError::new(
                MEMORY_CODE_INVALID_STATE,
                "the checkout is not materialized",
                &["Bind it first with vault.code.checkout.bind."],
            ));
        }
        let repo = wire.open_repo(lease.repo_ref.clone(), &tree)?;
        if repo.common_dir() != push_queue_key(self.vault, &input.repo)?.as_path() {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "the checkout does not share the served repository's object store",
                &[],
            ));
        }
        Ok(repo)
    }

    /// The host authority an export publishes under, read positively: a held
    /// epoch passes its lease, an unconfigured origin passes none, a mirror or
    /// another writer refuses, and an erased writer names the owner's cutover.
    /// A read failure is an error, never unconfigured.
    pub(super) fn origin_export_authority(
        &self,
        repo: &str,
    ) -> MemoryResult<Option<OriginAuthorityLease>> {
        match self.vault.origin_host_authority(repo)? {
            OriginHostAuthority::Unconfigured => Ok(None),
            OriginHostAuthority::Held(lease) => Ok(Some(lease)),
            OriginHostAuthority::Mirror(_) | OriginHostAuthority::Elsewhere(_) => {
                Err(MemoryError::new(
                    MEMORY_CODE_FORBIDDEN,
                    "this host does not hold the served repository's origin authority",
                    &["Read vault.code.origin.authority.get, then export from the writer host."],
                ))
            }
            OriginHostAuthority::WriterErased(_) => Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                ORIGIN_WRITER_ERASED_REFUSAL,
                &[
                    "The owner cuts over with vault.code.origin.authority.set; export from the writer it names.",
                ],
            )),
        }
    }

    /// The CALL behind every publication field: the record's own source claim,
    /// its `repo.publication` claim and its actor stay three distinct fields,
    /// and an erased actor is `None`. Each row that still exists is listed.
    fn origin_publication_view(
        &self,
        record: &OriginPublicationRecord,
    ) -> MemoryResult<OriginPublicationView> {
        let actor = record.actor_id.id();
        self.origin_listed(
            [
                Some(record.provenance_claim_id),
                record.publication_claim_id,
                actor,
            ]
            .into_iter()
            .flatten(),
        )?;
        Ok(OriginPublicationView {
            receipt: record.publication_id,
            repo_id: record.repo_id,
            ref_name: record.ref_name.as_str().to_owned(),
            git_commit: record.new_oid.as_str().to_owned(),
            provenance_receipt: record.provenance_claim_id,
            publication_claim: record.publication_claim_id,
            actor,
            status: match record.status {
                OriginPublicationStatus::Prepared => OriginPublicationState::Prepared,
                OriginPublicationStatus::Published => OriginPublicationState::Published,
                OriginPublicationStatus::Failed => OriginPublicationState::Failed,
                OriginPublicationStatus::Conflicted => OriginPublicationState::Conflicted,
            },
            failure: record.failure.clone(),
            created_at: record.created_at,
            finished_at: record.finished_at,
        })
    }
}

/// The CALL behind the cutover writer: the machine the owner names, or this
/// install's own machine, never the caller. No machine id yet is an error.
fn origin_authority_writer(named: Option<&str>, host: Option<EntityId>) -> MemoryResult<EntityId> {
    match named {
        Some(writer) => EntityId::from_hex(writer)
            .map_err(|_| MemoryError::bad_request("writer must be a machine id")),
        None => host.ok_or_else(|| {
            MemoryError::new(
                MEMORY_CODE_INVALID_STATE,
                "this install has no machine id yet; name the writer",
                &[],
            )
        }),
    }
}

/// The CALL behind the export target: an explicit full ref and the value it
/// is decided against, `None` meaning the ref must not exist. No branch is
/// defaulted and no expectation is discovered or retried.
fn origin_export_target(input: &CodeExportRequest) -> MemoryResult<EngineCommitExport> {
    Ok(EngineCommitExport {
        revision_id: input.revision,
        ref_name: GitRefName::parse_full(input.ref_name.clone())?,
        expected_old_oid: input
            .expected_old_oid
            .clone()
            .map(GitOid::parse_hex)
            .transpose()?,
    })
}
