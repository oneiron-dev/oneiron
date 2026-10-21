//! The owner's workbench reads (FIX 6869, G4 PR2): `vault.code.repos.get`,
//! `vault.code.forks.get` and `vault.code.ingress.get`.
//!
//! Each authenticates the owner before any id resolves, judges the owner
//! again in its read snapshot, and answers only stored links the caller's
//! credential reads: an unreadable optional link is left out, an
//! unreadable required record answers `None`. No read matches a push,
//! reviews, initializes a queue, refreshes a check or exports. Lists are
//! deduplicated and sorted by stable id; documents by path.
use std::collections::BTreeSet;

use super::workbench_types::{
    CodeForkDocumentView, CodeForkGetRequest, CodeForkView, CodeIngressRef,
    CodePushIngressGetRequest, CodePushIngressView, CodeRepoGetRequest, CodeRepoImportLink,
    CodeRepoView, CodeRunWorkFile, CodeRunWorkLink,
};
use super::{Memory, MemoryResult};
use crate::EntityId;
use crate::code_revision::{CodeImportManifest, CodeRevision};
use crate::codebase::RepoRef;
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeKind;
use crate::entity_id::bytes_to_hex_lower;
use crate::git_wire::GitWire;
use crate::memory::merge_queue_doors::MergeQueuePointersView;
use crate::merge_queue::MergeQueue;
use crate::ports::{EdgeDirection, EdgeStore};
use crate::registry::ENTITY_TYPE_CODE_ARTIFACT;

/// A served repository as the reads resolve it: its anchor, its stored
/// local folder and the object store that folder proves.
struct ServedCodeRepo {
    repo: EntityId,
    repo_ref: RepoRef,
    folder: String,
    store: String,
}

impl Memory<'_> {
    /// Whether the caller's credential reads the record `id`; listed as
    /// read either way.
    fn workbench_readable(&self, id: EntityId) -> MemoryResult<bool> {
        self.produced_from([id]);
        Ok(self.get_entity(&id.to_hex())?.value.is_some())
    }

    /// The selected served repository, once readable: a CODE_ARTIFACT whose
    /// stored pointer is a local folder of a proven object store.
    fn workbench_repo(&self, repo: EntityId) -> MemoryResult<Option<ServedCodeRepo>> {
        if self.vault.get_entity_type(&repo)? != Some(ENTITY_TYPE_CODE_ARTIFACT)
            || !self.workbench_readable(repo)?
        {
            return Ok(None);
        }
        let Some(artifact) = self.vault.get_code_artifact(&repo)? else {
            return Ok(None);
        };
        let repo_ref = RepoRef::parse(&artifact.repo_ref)?;
        let RepoRef::LocalFolder { path, .. } = &repo_ref else {
            return Ok(None);
        };
        let Ok(store) = GitWire::new(self.vault)?.repository_identity(std::path::Path::new(path))
        else {
            return Ok(None);
        };
        Ok(Some(ServedCodeRepo {
            repo,
            folder: path.clone(),
            store: store.as_hex(),
            repo_ref,
        }))
    }

    /// `vault.code.repos.get`: the selected served repository, its
    /// immutable imports, queue pointers and exact green seal, and its
    /// stored batch, check, fork, ingress and run-work links.
    pub fn code_repo_get_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeRepoGetRequest,
    ) -> MemoryResult<Option<CodeRepoView>> {
        self.origin_owner(owner)?;
        let Some(served) = self.workbench_repo(input.repo)? else {
            return Ok(None);
        };
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        self.origin_owner_in_txn(owner, &txn)?;
        let mut projects: Vec<EntityId> = EdgeStore::port_edge_neighbors(
            self.vault,
            &txn,
            &served.repo,
            EdgeDirection::Out,
            Some(EdgeKind::BelongsTo),
            crate::vault::MAX_EDGE_QUERY_RESULTS,
        )?
        .into_iter()
        .map(|edge| edge.target)
        .collect();
        projects.sort();
        let mut project = None;
        for candidate in projects {
            if crate::workspace_roster::is_project_entity(&self.vault.store, &txn, candidate)? {
                project = Some(candidate);
                break;
            }
        }
        let Some(project) = project else {
            return Ok(None);
        };
        let mut imports = Vec::new();
        for id in self.vault.claims_for_subject_in_txn(&txn, &served.repo)? {
            let Some(body) = self.vault.get_claim_in_txn(&txn, &id)? else {
                continue;
            };
            if body.predicate != "repo.import_manifest" || !self.workbench_readable(id)? {
                continue;
            }
            if let Ok(manifest) = CodeImportManifest::from_claim(&body) {
                imports.push(CodeRepoImportLink {
                    manifest: id,
                    anchor: manifest.anchor,
                });
            }
        }
        imports.sort_by_key(|link| link.manifest);
        let mut run_works = Vec::new();
        let mut task_refs = BTreeSet::new();
        for receipt in crate::code_view::repo_view_receipts_in_txn(self.vault, &txn, served.repo)? {
            let Some(stamp) = receipt.run else {
                continue;
            };
            if !self.workbench_readable(stamp.task)?
                || !self.workbench_readable(stamp.executor_run)?
            {
                continue;
            }
            task_refs.insert(stamp.task);
            run_works.push(CodeRunWorkLink {
                work: stamp.work,
                task: stamp.task,
                executor_run: stamp.executor_run,
                ref_name: stamp.git_ref,
                base_green: stamp.base_green,
                base_snapshot: bytes_to_hex_lower(&stamp.base_snapshot),
                fork_hash: bytes_to_hex_lower(&receipt.fork_hash),
                files: receipt
                    .files
                    .into_iter()
                    .map(|(path, hash)| CodeRunWorkFile {
                        path,
                        content_hash_blake3: bytes_to_hex_lower(&hash),
                    })
                    .collect(),
            });
        }
        drop(txn);
        run_works.sort_by_key(|work| work.work);
        let (queue, green_revision, batch_refs, check_work_refs) =
            match MergeQueue::open(self.vault, served.repo_ref.clone()) {
                Ok(queue) => {
                    let pointers = queue
                        .pointers()
                        .ok()
                        .map(|pointers| MergeQueuePointersView {
                            repo: served.repo,
                            head_commit: pointers.head,
                            green_commit: pointers.green,
                            pending_slow_batch_refs: pointers.pending_slow,
                        });
                    let green = queue
                        .green_revision()
                        .ok()
                        .and_then(Result::ok)
                        .map(|green| green.revision_id());
                    let (batches, works) = queue.workbench_refs()?;
                    (pointers, green, batches, works)
                }
                Err(_) => (None, None, Vec::new(), Vec::new()),
            };
        let mut ingress = BTreeSet::new();
        let mut fork_sessions = BTreeSet::new();
        for (provenance, row) in self.vault.received_code_ingress_rows(&served.store)? {
            if !self.workbench_readable(provenance)? {
                continue;
            }
            if let Some(resolved) = row.candidate.as_ref().and_then(|c| c.resolved.as_ref()) {
                fork_sessions.insert(resolved.fork_session);
            }
            ingress.insert(CodeIngressRef {
                provenance,
                ref_name: row.source.ref_name,
            });
        }
        Ok(Some(CodeRepoView {
            repo: served.repo,
            project,
            served_repo: served_name(&served.folder),
            imports,
            queue,
            green_revision,
            batch_refs,
            check_work_refs,
            task_refs: task_refs.into_iter().collect(),
            fork_sessions: fork_sessions.into_iter().collect(),
            ingress: ingress.into_iter().collect(),
            run_works,
        }))
    }

    /// `vault.code.forks.get`: one durable revision fork whose base is a
    /// tested revision of this repository's object store, with the
    /// documents its received candidate names, if any.
    pub fn code_fork_get_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeForkGetRequest,
    ) -> MemoryResult<Option<CodeForkView>> {
        self.origin_owner(owner)?;
        let Some(served) = self.workbench_repo(input.repo)? else {
            return Ok(None);
        };
        if !self.workbench_readable(input.fork_session)? {
            return Ok(None);
        }
        let Some(fork) = self.vault.get_code_revision_fork(&input.fork_session)? else {
            return Ok(None);
        };
        let Some(base) = self.vault.get_code_revision(&fork.base_revision_id)? else {
            return Ok(None);
        };
        if !base
            .tested_queue
            .as_ref()
            .is_some_and(|tested| tested.store == served.store && tested.repo == served.repo)
        {
            return Ok(None);
        }
        let mut view = CodeForkView {
            repo: served.repo,
            fork_session: fork.fork_session_id,
            parent_session: fork.parent_session_id,
            base_revision: fork.base_revision_id,
            forked_at: fork.forked_at,
            documents: Vec::new(),
            proposal_refs: Vec::new(),
            revision_refs: Vec::new(),
            task_refs: Vec::new(),
            ingress: None,
        };
        for (provenance, row) in self.vault.received_code_ingress_rows(&served.store)? {
            let Some(candidate) = &row.candidate else {
                continue;
            };
            let Some(resolved) = candidate
                .resolved
                .as_ref()
                .filter(|resolved| resolved.fork_session == fork.fork_session_id)
            else {
                continue;
            };
            if self.workbench_readable(provenance)? {
                view.ingress = Some(CodeIngressRef {
                    provenance,
                    ref_name: row.source.ref_name.clone(),
                });
            }
            if self.workbench_readable(resolved.proposal_id)? {
                view.proposal_refs.push(resolved.proposal_id);
            }
            for file in &resolved.files {
                let landed = match file.document_operation {
                    Some(operation) => self
                        .vault
                        .code_file_edit_receipt(operation)?
                        .filter(|receipt| receipt.session_id == fork.fork_session_id)
                        .map(|receipt| receipt.after),
                    None => None,
                };
                let document_id = landed
                    .as_ref()
                    .or(file.base_frontier.as_ref())
                    .map(|frontier| bytes_to_hex_lower(&frontier.document_id));
                view.documents.push(CodeForkDocumentView {
                    document_id,
                    path: file.path.clone(),
                    base: file.base_frontier.clone(),
                    landed,
                    target: file.after.clone(),
                    metadata_edit: Some(file.metadata_edit.clone()),
                    proposal_ref: Some(resolved.proposal_id),
                });
            }
            view.revision_refs = self.workbench_sealed_with(&served, candidate.candidate)?;
        }
        view.documents.sort_by(|left, right| {
            (&left.path, &left.document_id).cmp(&(&right.path, &right.document_id))
        });
        Ok(Some(view))
    }

    /// `vault.code.ingress.get`: one authenticated received ref of this
    /// repository's object store, its recorded operations, its admitting
    /// publication and its candidate's saved progress.
    pub fn code_push_ingress_get_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodePushIngressGetRequest,
    ) -> MemoryResult<Option<CodePushIngressView>> {
        self.origin_owner(owner)?;
        let Some(served) = self.workbench_repo(input.repo)? else {
            return Ok(None);
        };
        if !self.workbench_readable(input.provenance)? {
            return Ok(None);
        }
        let row = {
            let txn = self
                .vault
                .store
                .env
                .read_txn()
                .map_err(crate::Error::from)?;
            self.origin_owner_in_txn(owner, &txn)?;
            self.vault
                .received_code_ingress_in_txn(&txn, input.provenance, &input.ref_name)?
        };
        let Some(row) = row.filter(|row| row.source.object_store == served.store) else {
            return Ok(None);
        };
        let publication = self
            .vault
            .received_ref_publication(input.provenance, &row)?;
        let mut candidate = self.vault.received_candidate_view(&row)?;
        if let Some(view) = &mut candidate {
            let sealed = self.workbench_sealed_with(&served, view.candidate)?;
            if !sealed.is_empty() {
                view.state = crate::origin::CodePushCandidateState::Sealed;
            }
            view.revision_refs = sealed;
            view.proposal_refs
                .retain(|id| self.workbench_readable(*id).unwrap_or(false));
        }
        Ok(Some(CodePushIngressView {
            repo: served.repo,
            provenance: input.provenance,
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

    /// The tested revisions of this repository's queue chain whose
    /// complete-push links name `candidate`, newest first: the seals it
    /// earned. Walks the stored chain from the exact green seal only.
    fn workbench_sealed_with(
        &self,
        served: &ServedCodeRepo,
        candidate: EntityId,
    ) -> MemoryResult<Vec<EntityId>> {
        let Ok(queue) = MergeQueue::open(self.vault, served.repo_ref.clone()) else {
            return Ok(Vec::new());
        };
        let mut next: Option<CodeRevision> = queue
            .green_revision()
            .ok()
            .and_then(Result::ok)
            .and_then(|green| {
                self.vault
                    .get_code_revision(&green.revision_id())
                    .ok()
                    .flatten()
            });
        let mut sealed = Vec::new();
        for _ in 0..crate::limits::MAX_ANCESTOR_DEPTH {
            let Some(revision) = next else {
                break;
            };
            if revision.tested_queue.as_ref().is_some_and(|tested| {
                tested
                    .received_pushes
                    .iter()
                    .any(|link| link.candidate == candidate)
            }) && self.workbench_readable(revision.revision_id)?
            {
                sealed.push(revision.revision_id);
            }
            next = match revision.parent_revision_id {
                Some(parent) => self.vault.get_code_revision(&parent)?,
                None => None,
            };
        }
        Ok(sealed)
    }
}

/// The served name of a served repository's stored folder, with no `.git`
/// suffix.
fn served_name(folder: &str) -> String {
    let name = std::path::Path::new(folder)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    name.strip_suffix(".git").unwrap_or(name).to_owned()
}
