//! The outside import doors (FIX 6871, G7 PR1): `vault.code.imports.create`
//! and `vault.code.imports.get`.
//!
//! Two callers, as the exact publish doors admit them: the owner's own
//! live proof, or this handle's own actor, which the engine admits by the
//! SAME receive decision any push meets (a `git_push` Grant on the repo, or
//! a checkout whose run's Grant covers it). No principal class decides, no
//! owner proof is lent to a member, and no request field names a caller.
//! Create needs the per-call transport its host lends this handle
//! ([`Memory::with_external_git_source_host`]); an unhosted create is
//! unavailable, never an owner fallback. Get is a read: it rechecks the
//! caller's standing and its credential's record reads, and fetches,
//! pushes, matches, enqueues or repairs nothing.

use std::sync::Arc;

use super::workbench::ServedCodeRepo;
use super::workbench_types::CodePushIngressView;
use super::{MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};
use crate::EntityId;
use crate::consent::AuthenticatedOwner;
use crate::memory::merge_queue_doors::{MergeQueueCheckWorkView, check_work_view};
use crate::repo_mutation::external_import::{
    EXTERNAL_IMPORT_STATUS_ROUTE, ExternalGitSourceHost, ExternalImportLookup,
    ExternalImportReceipt, ExternalImportRequest, ExternalImportStatus, ExternalStatusRoute,
};

/// Who calls an import door, as its host bound it.
#[derive(Debug, Clone)]
pub enum ExternalImportProof {
    /// The owner's live proof, naming this handle's own human actor.
    Owner(AuthenticatedOwner),
    /// This handle's own actor, admitted by its standing on the repo.
    Member,
}

fn host_unavailable() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        "external_import_host_unavailable: an outside import needs its serving host's \
         authenticated Git transport",
        &["Call vault.code.imports.create through the server's facade, SDK or MCP door."],
    )
}

impl Memory<'_> {
    /// An embedded handle's import caller: the vault owner's proof when the
    /// handle is the embedded owner's, else the handle's own actor.
    pub fn external_import_proof(&self, verb: &str) -> ExternalImportProof {
        self.embedded_owner(verb)
            .map_or(ExternalImportProof::Member, ExternalImportProof::Owner)
    }

    /// Lends this handle the authenticated Git transport of ONE call. A
    /// handle built for another call or turn starts without one.
    #[must_use]
    pub fn with_external_git_source_host(mut self, host: Arc<dyn ExternalGitSourceHost>) -> Self {
        self.external_git_source_host = Some(host);
        self
    }

    /// `vault.code.imports.create`: one exact outside source, fetched and
    /// sent through the authenticated door, answered as its immutable
    /// receipt. Progress is `vault.code.imports.get`'s.
    pub fn code_external_import_create_as(
        &self,
        proof: &ExternalImportProof,
        input: ExternalImportRequest,
    ) -> MemoryResult<ExternalImportReceipt> {
        self.import_owner(proof)?;
        let host = self
            .external_git_source_host
            .clone()
            .ok_or_else(host_unavailable)?;
        self.import_host_bound(host.as_ref())?;
        if !self.workbench_readable(input.code_repo)?
            || !self.workbench_readable(input.base_revision)?
        {
            return Err(MemoryError::not_found(
                "the served repository or its base revision is absent or withheld",
            ));
        }
        let receipt = self.vault.import_external_change(host.as_ref(), &input)?;
        self.import_owner(proof)?;
        host.revalidate()?;
        self.produced_from([receipt.import]);
        Ok(receipt)
    }

    /// `vault.code.imports.get`: one import's receipt, its derived phase,
    /// the received head update with its aggregate candidate, and the
    /// candidate's linked checker work. Local only (CALL U).
    pub fn code_external_import_get_as(
        &self,
        proof: &ExternalImportProof,
        input: ExternalImportLookup,
    ) -> MemoryResult<Option<ExternalImportStatus>> {
        match EXTERNAL_IMPORT_STATUS_ROUTE {
            ExternalStatusRoute::Local => {}
        }
        self.import_owner(proof)?;
        let host = self.external_git_source_host.clone();
        match (&host, proof) {
            (Some(host), _) => {
                self.import_host_bound(host.as_ref())?;
                self.vault
                    .admit_external_import(host.caller(), &input.repo, &input.door)?;
            }
            (None, ExternalImportProof::Owner(_)) => {}
            (None, ExternalImportProof::Member) => return Err(host_unavailable()),
        }
        if !self.workbench_readable(input.import)? {
            return Ok(None);
        }
        let Some(served) = self.workbench_repo(input.code_repo)? else {
            return Ok(None);
        };
        let Some(projection) = self.vault.external_import_status(
            &served.store,
            &input.repo,
            input.code_repo,
            input.import,
        )?
        else {
            return Ok(None);
        };
        let ingress = match projection.head {
            Some(head) => {
                self.import_ingress(&served, head.provenance, &projection.receipt.imported_ref)?
            }
            None => None,
        };
        let checks = match &ingress {
            Some(view) => self.import_checks(&served, view)?,
            None => Vec::new(),
        };
        self.import_owner(proof)?;
        if let Some(host) = &host {
            host.revalidate()?;
        }
        Ok(Some(ExternalImportStatus {
            receipt: projection.receipt,
            phase: projection.phase,
            reason: projection.reason,
            ingress,
            checks,
        }))
    }

    /// The owner's proof, judged live and naming this handle's own actor;
    /// a member's call proves nothing here.
    fn import_owner(&self, proof: &ExternalImportProof) -> MemoryResult<()> {
        if let ExternalImportProof::Owner(owner) = proof {
            self.origin_owner(owner)?;
        }
        Ok(())
    }

    /// The lent transport authenticated this handle's own actor.
    fn import_host_bound(&self, host: &dyn ExternalGitSourceHost) -> MemoryResult<()> {
        if host.caller().principal() != self.actor {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "an import's transport authenticated another principal than this caller",
                &["Call the import door with the credential whose transport it lends."],
            ));
        }
        Ok(())
    }

    /// The received head update's view, composed from the candidate
    /// matcher's own pure reads, as the owner's ingress read composes them.
    fn import_ingress(
        &self,
        served: &ServedCodeRepo,
        provenance: EntityId,
        ref_name: &str,
    ) -> MemoryResult<Option<CodePushIngressView>> {
        if !self.workbench_readable(provenance)? {
            return Ok(None);
        }
        let row = {
            let txn = self
                .vault
                .store
                .env
                .read_txn()
                .map_err(crate::Error::from)?;
            self.vault
                .received_code_ingress_in_txn(&txn, provenance, ref_name)?
        };
        let Some(row) = row.filter(|row| row.source.object_store == served.store) else {
            return Ok(None);
        };
        let publication = self.vault.received_ref_publication(provenance, &row)?;
        let mut candidate = self.vault.received_candidate_view(&row)?;
        if let Some(view) = &mut candidate {
            let sealed = self.workbench_sealed_with(served, view.candidate)?;
            if !sealed.is_empty() {
                view.state = crate::origin::CodePushCandidateState::Sealed;
            }
            view.revision_refs = sealed;
            view.proposal_refs
                .retain(|id| self.workbench_readable(*id).unwrap_or(false));
        }
        Ok(Some(CodePushIngressView {
            repo: served.repo,
            provenance,
            ref_name: row.source.ref_name,
            old_oid: row.source.old_oid,
            new_oid: row.source.new_oid,
            received_at: row.received_at,
            published: publication.is_some_and(|(_, published)| published),
            publication: publication.map(|(id, _)| id),
            operations: row.operations,
            candidate,
        }))
    }

    /// The candidate's own linked checker work, each work once, in saved
    /// order: the stored rows as the check status read projects them. No
    /// work, no checks; nothing is invented or refreshed.
    fn import_checks(
        &self,
        served: &ServedCodeRepo,
        ingress: &CodePushIngressView,
    ) -> MemoryResult<Vec<MergeQueueCheckWorkView>> {
        let Some(candidate) = &ingress.candidate else {
            return Ok(Vec::new());
        };
        if candidate.check_work_refs.is_empty() {
            return Ok(Vec::new());
        }
        // Read by the served store, never through its null-pinned folder
        // (FIX 6869).
        let config = self.vault.queue_check_configuration_of(&served.store)?;
        let mut seen = std::collections::BTreeSet::new();
        let mut checks = Vec::new();
        for work_ref in &candidate.check_work_refs {
            if !seen.insert(work_ref.as_str()) {
                continue;
            }
            if let Some(work) = self.vault.queue_check_work_of(&served.store, work_ref)? {
                checks.push(check_work_view(config.clone(), work));
            }
        }
        Ok(checks)
    }
}
