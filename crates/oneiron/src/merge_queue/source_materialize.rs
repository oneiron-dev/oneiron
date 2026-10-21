//! The served queue source's materialization (FIX 6869): the one place its
//! engine-owned detached worktree is made, put back or pinned.
//!
//! An owner's explicit checked init selects and authenticates the import,
//! then makes ONE detached linked worktree of the served object store at
//! its exact commit through the journaled `GitWire::add_worktree`, pinned
//! with a protected keep-ref (CALL 3). It is no anchor, clone, store, lease
//! or owner path, and no shared ref names its HEAD. The checker's drain and
//! the owner's recover only put back a MISSING projection, at the recorded
//! queue head with its recorded tree; an open landing or rollback intent,
//! an unproved head, an occupied path or changed bytes hold by name with
//! the work kept (CALL 6). Nothing is reset, deleted to make room, timed
//! out or followed to the published tip, and no approval is revived.
use std::path::Path;

use super::MergeQueue;
use super::check_inputs::{QueueCheckHold, QueueCheckHoldReason};
use super::check_store::{CHECK_WORK, QueueCheckRequest, QueueCheckWork};
use super::source::{BoundQueueSource, NO_SOURCE, queue_source_root, served_store_folder};
use super::source_types::{PreparedQueueInit, ServedQueueSource};
use super::types::QueueRecord;
use crate::code_revision::CodeImportManifest;
use crate::codebase::RepoRef;
use crate::consent::AuthenticatedOwner;
use crate::contract_oracle::invalid;
use crate::error::{Error, Result};
use crate::git_wire::{GitOid, GitWire, GitWireRepo, lock_repository};
use crate::{EntityId, Vault};

/// A queue source path that holds something other than its worktree.
const OCCUPIED: &str = "the queue source path is occupied by something that is not its \
     store's registered worktree; nothing is deleted";

impl Vault {
    /// The queue an owner's checked init at `baseline_commit` requests on
    /// for the CODE_ARTIFACT `repo` whose stored pointer is `repo_ref`. A
    /// native repository opens its own root, unchanged. A served anchor,
    /// under its store's writer and the owner judged again, reuses its
    /// bound source, else the import this exact request froze, else the
    /// one `select_queue_import` names, authenticated, and materializes it.
    ///
    /// # Errors
    /// An owner refusal, an unimported, ambiguous or unadmitted source, a
    /// native queue in the store, a held materialization by name, or a
    /// store or object store failure.
    pub(crate) fn prepare_queue_initialization(
        &self,
        owner: &AuthenticatedOwner,
        repo: EntityId,
        repo_ref: &RepoRef,
        baseline_commit: &str,
        contract_baseline_ref: Option<&str>,
    ) -> Result<PreparedQueueInit<'_>> {
        let Some(folder) = served_store_folder(repo_ref) else {
            return Ok(PreparedQueueInit {
                queue: MergeQueue::open(self, repo_ref.clone())?,
                source: None,
            });
        };
        let commit = GitOid::parse_hex(baseline_commit)?;
        let git = GitWire::new(self)?;
        let served = git.open_repo(
            RepoRef::LocalFolder {
                path: folder.to_owned(),
                commit: commit.as_str().to_owned(),
            },
            Path::new(folder),
        )?;
        let store = served.identity().as_hex();
        let _guard = lock_repository(served.common_dir())?;
        owner.revalidate(self)?;
        if let Some(bound) = self.require_existing_queue_source(&store, repo)? {
            let queue = self
                .ensure_served_queue_source(&bound)?
                .map_err(Error::Refused)?;
            return Ok(PreparedQueueInit {
                queue,
                source: Some(bound.source),
            });
        }
        let request = QueueCheckRequest::Initialize {
            baseline_commit: commit.as_str().to_owned(),
            contract_baseline_ref: contract_baseline_ref.map(str::to_owned),
        };
        let frozen = {
            let txn = self.store.env.read_txn()?;
            CHECK_WORK.get(&self.store, &txn, &format!("{store}:{}", request.digest()?))?
        }
        .filter(|work| work.repo == repo)
        .and_then(|work| work.source);
        let manifest_ref = match frozen {
            Some(source) => source.manifest,
            None => self.select_queue_import(repo, &store, commit.as_str())?,
        };
        let manifest = self.require_served_queue_source(&git, &served, repo, manifest_ref)?;
        let queue = self
            .materialize_queue_source(&git, &served, &manifest)?
            .map_err(Error::Refused)?;
        Ok(PreparedQueueInit {
            queue,
            source: Some(ServedQueueSource {
                manifest: manifest_ref,
            }),
        })
    }

    /// The queue the owner's explicit recover reconciles: a native one's
    /// own root, or a served anchor's bound source, its missing projection
    /// put back first.
    ///
    /// # Errors
    /// No bound source, a held materialization by name, or a store failure.
    pub(crate) fn open_queue_for_recovery(
        &self,
        repo: EntityId,
        repo_ref: &RepoRef,
    ) -> Result<MergeQueue<'_>> {
        let Some(folder) = served_store_folder(repo_ref) else {
            return MergeQueue::open(self, repo_ref.clone());
        };
        let store = GitWire::new(self)?
            .repository_identity(Path::new(folder))?
            .as_hex();
        let bound = self
            .require_existing_queue_source(&store, repo)?
            .ok_or_else(|| Error::Refused(NO_SOURCE.to_owned()))?;
        self.ensure_served_queue_source(&bound)?
            .map_err(Error::Refused)
    }

    /// The queue checker `work` runs on: an init joined to its own
    /// descriptor, any other work to its store's bound source, each put
    /// back if missing; a native work's own stored root, as before.
    /// `Ok(Err(_))` holds the work with what is missing.
    ///
    /// # Errors
    /// A binding that does not prove, the native open's refusal, or a
    /// store failure.
    pub(super) fn open_queue_check_source(
        &self,
        work: &QueueCheckWork,
    ) -> Result<std::result::Result<MergeQueue<'_>, QueueCheckHold>> {
        let bound = match &work.request {
            QueueCheckRequest::Initialize { .. } => self.init_work_source(work)?,
            _ => self.store_queue_source(&work.store)?,
        };
        let Some(bound) = bound else {
            return Ok(Ok(MergeQueue::open(self, RepoRef::parse(&work.repo_ref)?)?));
        };
        if bound.anchor != work.repo || bound.repo_ref.canonical() != work.repo_ref {
            return Ok(Err(QueueCheckHold::new(
                QueueCheckHoldReason::Refused,
                "this work names another queue source than its store's",
            )));
        }
        Ok(self
            .ensure_served_queue_source(&bound)?
            .map_err(|detail| QueueCheckHold::new(QueueCheckHoldReason::TreeUnavailable, detail)))
    }

    /// CALL 3/6 "materialization time" and "missing or changed source":
    /// the bound source opened, a MISSING projection first put back at the
    /// recorded queue head under the store's writer. A present root opens
    /// as it stands; the queue's own gates judge its HEAD. `Ok(Err(_))`
    /// names what holds; nothing is reset or deleted.
    ///
    /// # Errors
    /// A served anchor that no longer names its store, or a store or object
    /// store failure.
    pub(super) fn ensure_served_queue_source(
        &self,
        bound: &BoundQueueSource,
    ) -> Result<std::result::Result<MergeQueue<'_>, String>> {
        let git = GitWire::new(self)?;
        let served = self.bound_served_store(&git, bound)?;
        let _guard = lock_repository(served.common_dir())?;
        if bound.root.symlink_metadata().is_ok() {
            return self.open_bound_queue_source(bound);
        }
        let (head, tree) = match self.recorded_source_head(&git, &served, bound)? {
            Ok(found) => found,
            Err(held) => return Ok(Err(held)),
        };
        // A missing root registered at the engine-derived path is this
        // store's own registration: pruned, then added again.
        if git.worktree_registered(&served, &bound.root)? {
            git.prune_worktrees(&served)?;
        }
        if let Some(parent) = bound.root.parent() {
            std::fs::create_dir_all(parent)?;
        }
        git.add_worktree(&served, &bound.root, &head, 0)?;
        let queue = match self.open_bound_queue_source(bound)? {
            Ok(queue) => queue,
            Err(held) => return Ok(Err(held)),
        };
        if !queue.source_projection_holds(head.as_str(), &tree, bound.anchor)? {
            return Ok(Err(
                "the queue source put back is not its recorded head and tree, clean and \
                 detached; it is kept as it is"
                    .to_owned(),
            ));
        }
        Ok(Ok(queue))
    }

    /// The bound source's served object store, opened again from its
    /// anchor's stored pointer at the bound baseline: the artifact must
    /// still locate that store.
    fn bound_served_store(
        &self,
        git: &GitWire<'_>,
        bound: &BoundQueueSource,
    ) -> Result<GitWireRepo> {
        let artifact = self
            .get_code_artifact(&bound.anchor)?
            .ok_or(Error::EntityNotFound)?;
        let repo_ref = RepoRef::parse(&artifact.repo_ref)?;
        let Some(folder) = served_store_folder(&repo_ref) else {
            return Err(Error::ConcurrentWrite(
                "the served anchor no longer locates its object store",
            ));
        };
        let served = git.open_repo(
            RepoRef::LocalFolder {
                path: folder.to_owned(),
                commit: bound.baseline_commit.clone(),
            },
            Path::new(folder),
        )?;
        if served.identity().as_hex() != bound.store {
            return Err(Error::ConcurrentWrite(
                "the code artifact no longer names the checked object store",
            ));
        }
        Ok(served)
    }

    /// The head a missing projection is put back at, with its recorded
    /// tree: the import's commit before the queue exists; else the saved
    /// queue head, whose tree is its import's (the baseline) or its landed
    /// batch's, and its sealed green's when it is the green. Never the
    /// published tip. An open intent, an unbound queue, or a head with no
    /// recorded tree or kept object holds by name.
    fn recorded_source_head(
        &self,
        git: &GitWire<'_>,
        served: &GitWireRepo,
        bound: &BoundQueueSource,
    ) -> Result<std::result::Result<(GitOid, String), String>> {
        let rows = MergeQueue::of_repo(self, served.clone());
        let Some(queue) = rows.read_queue()? else {
            let commit = GitOid::parse_hex(bound.baseline_commit.clone())?;
            return Ok(Ok((commit, bound.manifest.anchor.source_tree.clone())));
        };
        if queue.source_init_work.as_deref() != Some(bound.init_work.as_str()) {
            return Ok(Err(
                "this store's queue is not bound to this source; nothing is put back".to_owned(),
            ));
        }
        if queue.intent.is_some() {
            return Ok(Err(
                "held_recovery: a landing or rollback intent is open and its applied prefix \
                 cannot be proved without the queue source; nothing is guessed or reset"
                    .to_owned(),
            ));
        }
        let head = queue.pointers.head.clone();
        let tree = if head == bound.baseline_commit {
            bound.manifest.anchor.source_tree.clone()
        } else {
            let batches = {
                let txn = self.store.env.read_txn()?;
                rows.repo_batches_in_txn(&txn)?
            };
            let Some(batch) = batches
                .iter()
                .find(|batch| batch.landed_head.as_deref() == Some(head.as_str()))
            else {
                return Ok(Err(format!(
                    "the queue head {head} names no landed batch, so its tree is unproved; \
                     nothing is reset"
                )));
            };
            rows.landed_path(batch)?.tree.clone()
        };
        if head == queue.pointers.green
            && let Ok(Ok(green)) = rows.green_revision()
            && green
                .revision()
                .tested_queue
                .as_ref()
                .is_some_and(|tested| tested.tree != tree)
        {
            return Ok(Err(
                "the queue's sealed green names another tree than its head; nothing is reset"
                    .to_owned(),
            ));
        }
        let commit = GitOid::parse_hex(head.clone())?;
        let named = git
            .commit_trees(served, std::slice::from_ref(&commit))
            .ok()
            .and_then(|trees| trees.get(&commit).map(|named| named.as_str().to_owned()));
        if named.as_deref() != Some(tree.as_str()) {
            return Ok(Err(format!(
                "the recorded queue head {head} is not kept with its tree in the store; nothing \
                 is guessed"
            )));
        }
        Ok(Ok((commit, tree)))
    }

    /// The import `manifest`'s source made at its exact commit, at the
    /// owner's explicit init alone: a present clean projection at that
    /// commit is reused; a clean pre-init one of an earlier requested
    /// import (no queue or configuration stands on it) moves through the
    /// journaled remove and add; anything else holds with nothing deleted.
    /// The commit is pinned before any work names it.
    fn materialize_queue_source(
        &self,
        git: &GitWire<'_>,
        served: &GitWireRepo,
        manifest: &CodeImportManifest,
    ) -> Result<std::result::Result<MergeQueue<'_>, String>> {
        let store = served.identity().as_hex();
        let root = queue_source_root(self, &store)?;
        let commit = GitOid::parse_hex(manifest.anchor.source_commit.clone())?;
        let source = RepoRef::LocalFolder {
            path: root
                .to_str()
                .ok_or_else(|| invalid("the queue source path must be UTF-8"))?
                .to_owned(),
            commit: commit.as_str().to_owned(),
        };
        let (tree, anchor) = (manifest.anchor.source_tree.as_str(), manifest.anchor.repo);
        if root.symlink_metadata().is_ok() {
            let Ok(present) = self.open_queue_source_root(&source, &root, &store)? else {
                return Ok(Err(OCCUPIED.to_owned()));
            };
            if present.source_projection_holds(commit.as_str(), tree, anchor)? {
                pin_source_commit(git, served, &commit)?;
                return Ok(Ok(present));
            }
            if present.require_clean(&root).is_err() || present.attached_target(anchor)?.is_some() {
                return Ok(Err(
                    "an earlier init's queue source holds changes or a branch; nothing is deleted"
                        .to_owned(),
                ));
            }
            git.remove_worktree(served, &root, 0)?;
        } else if git.worktree_registered(served, &root)? {
            git.prune_worktrees(served)?;
        }
        if let Some(parent) = root.parent() {
            std::fs::create_dir_all(parent)?;
        }
        git.add_worktree(served, &root, &commit, 0)?;
        pin_source_commit(git, served, &commit)?;
        let queue = match self.open_queue_source_root(&source, &root, &store)? {
            Ok(queue) => queue,
            Err(held) => return Ok(Err(held)),
        };
        if !queue.source_projection_holds(commit.as_str(), tree, anchor)? {
            return Ok(Err(
                "the new queue source is not its import's exact commit and tree, clean and \
                 detached; it is kept as it is"
                    .to_owned(),
            ));
        }
        Ok(Ok(queue))
    }
}

impl MergeQueue<'_> {
    /// Keeps a served source queue's new head with a protected keep-ref
    /// before the pointer naming it is saved (FIX 6869). A native queue
    /// keeps none here, as before.
    ///
    /// # Errors
    /// A keep-ref that is not Applied, or a Git failure.
    pub(super) fn pin_served_queue_head(&self, queue: &QueueRecord, head: &str) -> Result<()> {
        if queue.source_init_work.is_none() {
            return Ok(());
        }
        pin_source_commit(
            &GitWire::new(self.vault)?,
            &self.repo,
            &GitOid::parse_hex(head)?,
        )
    }

    /// Whether this source root is exactly `head` with `tree`, detached and
    /// clean.
    fn source_projection_holds(&self, head: &str, tree: &str, anchor: EntityId) -> Result<bool> {
        Ok(self.head()? == head
            && self.tree()? == tree
            && self.attached_target(anchor)?.is_none()
            && self.require_clean(self.repo.repo_root()).is_ok())
    }
}

/// Pins `commit` with the existing protected keep-ref; only an Applied
/// outcome keeps it.
fn pin_source_commit(git: &GitWire<'_>, repo: &GitWireRepo, commit: &GitOid) -> Result<()> {
    if !git.write_keep_ref(repo, commit, 0)?.is_applied() {
        return Err(Error::ConcurrentWrite(
            "the queue source commit could not be kept",
        ));
    }
    Ok(())
}
