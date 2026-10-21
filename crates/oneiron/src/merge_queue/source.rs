//! The served queue source's one resolver (FIX 6869): which root a queue
//! opens at the owner's doors, the driver and the workbench joins.
//!
//! A native repository's queue opens its own stored folder, exactly as
//! before. A served anchor's pointer locates its bare object store with no
//! commit selected; its queue opens the engine-owned detached worktree its
//! checked init bound, found by the store's configuration (or queue) and
//! the exact init work it names. Every lookup proves the work's store,
//! anchor, baseline and import manifest, and the root by engine derivation,
//! never by a stored path alone. These reads create no path, renew no
//! approval and materialize nothing: `source_materialize` does that, at an
//! explicit init or recover and in the checker's own drain.
use std::path::{Path, PathBuf};

use super::check_store::{CHECK_CONFIGS, CHECK_WORK, QueueCheckConfiguration, QueueCheckWork};
use super::source_types::{QUEUE_SOURCE_DIR, QUEUE_SOURCE_LEAF, ServedQueueSource};
use super::storage::{BATCHES, QUEUE_STATE};
use super::{MergeQueue, QueueCheckRequest, QueueDriverTarget};
use crate::code_revision::{
    CodeImportManifest, CodeTreeInventory, IMPORT_MANIFEST_PREDICATE,
    import_snapshot_custody_in_txn, manifest_digest, manifest_id,
};
use crate::codebase::RepoRef;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::git_wire::{GitRefName, GitWire, GitWireRepo};
use crate::{EntityId, Vault};

/// The refusal of a served repository's queue door before any init bound
/// its source.
pub(super) const NO_SOURCE: &str = "this served repository's queue has no source yet: request \
     vault.code.merge_queue.init at a commit vault.code.import imported";

/// A served queue source as its init work binds it, every part proved.
pub(super) struct BoundQueueSource {
    /// The object store's hex identity.
    pub(super) store: String,
    /// The served anchor (CODE_ARTIFACT) the queue describes.
    pub(super) anchor: EntityId,
    /// The binding init work's full key.
    pub(super) init_work: String,
    pub(super) baseline_commit: String,
    /// The internal pointer: the source root at the baseline commit.
    pub(super) repo_ref: RepoRef,
    /// The engine-derived root.
    pub(super) root: PathBuf,
    pub(super) source: ServedQueueSource,
    pub(super) manifest: CodeImportManifest,
}

/// The folder a served anchor's stored pointer locates: a local folder with
/// no commit selected. Any other pointer is a native queue's own root.
pub(super) fn served_store_folder(repo_ref: &RepoRef) -> Option<&str> {
    match repo_ref {
        RepoRef::LocalFolder { path, commit }
            if commit.len() == 40 && commit.bytes().all(|byte| byte == b'0') =>
        {
            Some(path.as_str())
        }
        _ => None,
    }
}

/// The engine-derived root of `store`'s queue source (CALL 1). Creates
/// nothing; a store name that is not a hex identity has no root.
///
/// # Errors
/// A vault environment path that does not resolve, or a malformed store.
pub(super) fn queue_source_root(vault: &Vault, store: &str) -> Result<PathBuf> {
    if store.is_empty() || !store.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::CorruptedIndex(
            "a queue source store is not a hex identity",
        ));
    }
    Ok(vault
        .store
        .env
        .path()
        .canonicalize()?
        .join(QUEUE_SOURCE_DIR)
        .join(store)
        .join(QUEUE_SOURCE_LEAF))
}

impl Vault {
    /// Object store `store`'s checked configuration, read by its key: no
    /// root opens, so an init's need stays readable before its source.
    ///
    /// # Errors
    /// A store failure.
    pub(crate) fn queue_check_configuration_of(
        &self,
        store: &str,
    ) -> Result<Option<QueueCheckConfiguration>> {
        let txn = self.store.env.read_txn()?;
        CHECK_CONFIGS.get(&self.store, &txn, &store.to_owned())
    }

    /// One work row of object store `store` by its public reference, read
    /// by its key alone.
    ///
    /// # Errors
    /// A reference that is no digest, or a store failure.
    pub(crate) fn queue_check_work_of(
        &self,
        store: &str,
        work_ref: &str,
    ) -> Result<Option<QueueCheckWork>> {
        if work_ref.len() != 64 || !work_ref.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(crate::contract_oracle::invalid("work_ref must be a digest"));
        }
        let txn = self.store.env.read_txn()?;
        CHECK_WORK.get(&self.store, &txn, &format!("{store}:{work_ref}"))
    }

    /// Object store `store`'s batch refs and checker work refs, ids only,
    /// in key order: the owner's workbench links (G4 PR2), read by store
    /// even before its init completes. A pure read.
    ///
    /// # Errors
    /// A store failure.
    pub(crate) fn queue_workbench_refs_of(
        &self,
        store: &str,
    ) -> Result<(Vec<String>, Vec<String>)> {
        let txn = self.store.env.read_txn()?;
        let prefix = format!("{store}:");
        let batches = BATCHES
            .scan_from(&self.store, &txn, prefix.as_bytes())?
            .into_iter()
            .map(|(_, batch)| batch.id)
            .collect();
        let works = CHECK_WORK
            .scan_from(&self.store, &txn, prefix.as_bytes())?
            .into_iter()
            .map(|(_, work)| work.work_ref().to_owned())
            .collect();
        Ok((batches, works))
    }

    /// The queue the owner's doors and the workbench open for the
    /// CODE_ARTIFACT `repo` whose stored pointer is `repo_ref`: a native
    /// one's own folder, unchanged, or a served anchor's bound source as it
    /// stands. Never creates or puts back a root.
    ///
    /// # Errors
    /// A served repository with no bound source, a source bound to another
    /// anchor, a missing or changed root (each naming its way out), or the
    /// native open's own refusal.
    pub(crate) fn open_queue_for_artifact(
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
        self.open_bound_queue_source(&bound)?
            .map_err(Error::Refused)
    }

    /// The bound source's root opened as it stands (see
    /// [`Self::open_queue_source_root`]).
    ///
    /// # Errors
    /// A store failure.
    pub(super) fn open_bound_queue_source(
        &self,
        bound: &BoundQueueSource,
    ) -> Result<std::result::Result<MergeQueue<'_>, String>> {
        self.open_queue_source_root(&bound.repo_ref, &bound.root, &bound.store)
    }

    /// The queue source `root` opened through its internal pointer
    /// `repo_ref` as it stands: present, a registered worktree of object
    /// store `store`, at no corrected HEAD. `Ok(Err(_))` names what is
    /// missing or changed; the queue holds and nothing is deleted.
    ///
    /// # Errors
    /// A store failure.
    pub(super) fn open_queue_source_root(
        &self,
        repo_ref: &RepoRef,
        root: &Path,
        store: &str,
    ) -> Result<std::result::Result<MergeQueue<'_>, String>> {
        if root.symlink_metadata().is_err() {
            return Ok(Err(
                "the queue source is missing: vault.code.merge_queue.recover, or the checker's \
                 drain, puts back its recorded head"
                    .to_owned(),
            ));
        }
        let git = GitWire::new(self)?;
        let repo = match git.open_repo(repo_ref.clone(), root) {
            Ok(repo) => repo,
            Err(error) => {
                return Ok(Err(format!(
                    "the queue source does not open as its store's worktree: {error}"
                )));
            }
        };
        if repo.identity().as_hex() != store || !git.worktree_registered(&repo, root)? {
            return Ok(Err(
                "the queue source path is not a registered worktree of its served store; nothing \
                 is deleted"
                    .to_owned(),
            ));
        }
        Ok(Ok(MergeQueue::of_repo(self, repo)))
    }

    /// The served source object store `store`'s queue is bound to: the
    /// init work its checked configuration names, else the one its queue
    /// saved (a configuration a historical restore did not bring back).
    /// `None` for a native or unbound store.
    ///
    /// # Errors
    /// A binding that disagrees with itself or does not prove, or a store
    /// failure.
    pub(super) fn store_queue_source(&self, store: &str) -> Result<Option<BoundQueueSource>> {
        let key = store.to_owned();
        let (config, queued, init) = {
            let txn = self.store.env.read_txn()?;
            let config = CHECK_CONFIGS.get(&self.store, &txn, &key)?;
            let queued = QUEUE_STATE
                .get(&self.store, &txn, &key)?
                .and_then(|queue| queue.source_init_work);
            let init_key = config
                .as_ref()
                .map(|config| config.init_work.clone())
                .or_else(|| queued.clone());
            let init = match &init_key {
                Some(init_key) => CHECK_WORK.get(&self.store, &txn, init_key)?,
                None => None,
            };
            (config, queued, init)
        };
        let bound = match &init {
            Some(work) => self.init_work_source(work)?,
            None if config.is_none() && queued.is_some() => {
                return Err(Error::Refused(
                    "the queue's source init work is gone; its queue holds with its work kept"
                        .to_owned(),
                ));
            }
            None => None,
        };
        let agrees = match (&bound, &queued) {
            (Some(bound), Some(queued)) => *queued == bound.init_work,
            (None, Some(_)) => false,
            (_, None) => true,
        };
        if !agrees {
            return Err(Error::Refused(
                "this store's queue and its checked configuration name different sources; its \
                 queue holds with its work kept"
                    .to_owned(),
            ));
        }
        Ok(bound)
    }

    /// The served source init work `work` binds, every part proved: its
    /// manifest, and its stored root against the engine's derivation for
    /// its store. `None` for a native init or any other work.
    ///
    /// # Errors
    /// A binding that does not prove, or a store failure.
    pub(super) fn init_work_source(
        &self,
        work: &QueueCheckWork,
    ) -> Result<Option<BoundQueueSource>> {
        let Some(source) = work.source.clone() else {
            return Ok(None);
        };
        let QueueCheckRequest::Initialize {
            baseline_commit, ..
        } = &work.request
        else {
            return Err(Error::CorruptedIndex(
                "a served queue source rides an init work only",
            ));
        };
        let manifest =
            self.queue_import_manifest(source.manifest, work.repo, &work.store, baseline_commit)?;
        let repo_ref = RepoRef::parse(&work.repo_ref)?;
        let root = queue_source_root(self, &work.store)?;
        let derived = matches!(
            &repo_ref,
            RepoRef::LocalFolder { path, commit }
                if commit == baseline_commit && Path::new(path) == root.as_path()
        );
        if !derived || work.key.split_once(':').map(|(store, _)| store) != Some(work.store.as_str())
        {
            return Err(Error::Refused(
                "the queue source's stored root is not the engine's own for its store; its queue \
                 holds with its work kept"
                    .to_owned(),
            ));
        }
        Ok(Some(BoundQueueSource {
            store: work.store.clone(),
            anchor: work.repo,
            init_work: work.key.clone(),
            baseline_commit: baseline_commit.clone(),
            repo_ref,
            root,
            source,
            manifest,
        }))
    }

    /// CALL 5 "existing queue": the source object store `store` is bound
    /// to, which must be `anchor`'s. A store that already holds a native or
    /// raw queue is never adopted, converted or given a second queue.
    /// `None` when nothing stands yet.
    ///
    /// # Errors
    /// Another anchor's source, a native queue, or a binding that does not
    /// prove.
    pub(super) fn require_existing_queue_source(
        &self,
        store: &str,
        anchor: EntityId,
    ) -> Result<Option<BoundQueueSource>> {
        if let Some(bound) = self.store_queue_source(store)? {
            if bound.anchor != anchor {
                return Err(Error::Refused(
                    "this object store's queue source is bound to another served anchor; use that \
                     anchor's doors"
                        .to_owned(),
                ));
            }
            return Ok(Some(bound));
        }
        let key = store.to_owned();
        let txn = self.store.env.read_txn()?;
        if CHECK_CONFIGS.get(&self.store, &txn, &key)?.is_some()
            || QUEUE_STATE.get(&self.store, &txn, &key)?.is_some()
        {
            return Err(Error::Refused(
                "this object store already holds a native queue, which a served source never \
                 adopts, converts or resets; its own repository's doors keep working"
                    .to_owned(),
            ));
        }
        Ok(None)
    }

    /// The import manifest `manifest_ref` names, proved to be `anchor`'s
    /// import of `commit` in object store `store`.
    ///
    /// # Errors
    /// A manifest that is gone or names anything else, or a store failure.
    pub(super) fn queue_import_manifest(
        &self,
        manifest_ref: EntityId,
        anchor: EntityId,
        store: &str,
        commit: &str,
    ) -> Result<CodeImportManifest> {
        let body = {
            let txn = self.store.env.read_txn()?;
            self.get_claim_in_txn(&txn, &manifest_ref)?
        };
        let manifest = body
            .map(|body| CodeImportManifest::from_claim(&body))
            .transpose()?
            .ok_or_else(|| {
                Error::Refused(
                    "the queue source's import manifest is gone; its queue holds with its work \
                     kept"
                        .to_owned(),
                )
            })?;
        if manifest_id(&manifest.digest)? != manifest_ref
            || manifest.anchor.repo != anchor
            || manifest.anchor.object_store != store
            || manifest.anchor.source_commit != commit
        {
            return Err(Error::Refused(
                "the queue source's import manifest does not name this anchor, store and baseline \
                 commit; its queue holds with its work kept"
                    .to_owned(),
            ));
        }
        Ok(manifest)
    }

    /// CALL 2 "first selection": the import of exactly `anchor` at
    /// `commit` in `store`. Identical imports (one source ref, tree and
    /// inventory) answer the smallest manifest id, which the init work then
    /// freezes; imports that disagree refuse by name before anything is
    /// scheduled. No default, branch or latest import is guessed.
    ///
    /// # Errors
    /// No such import, an ambiguous one, or a store failure.
    pub(super) fn select_queue_import(
        &self,
        anchor: EntityId,
        store: &str,
        commit: &str,
    ) -> Result<EntityId> {
        let mut found: Vec<(EntityId, CodeImportManifest)> = Vec::new();
        {
            let txn = self.store.env.read_txn()?;
            for id in self.claims_for_subject_in_txn(&txn, &anchor)? {
                let Some(body) = self.get_claim_in_txn(&txn, &id)? else {
                    continue;
                };
                if body.predicate != IMPORT_MANIFEST_PREDICATE {
                    continue;
                }
                let Ok(manifest) = CodeImportManifest::from_claim(&body) else {
                    continue;
                };
                if manifest_id(&manifest.digest).ok() == Some(id)
                    && manifest.anchor.repo == anchor
                    && manifest.anchor.object_store == store
                    && manifest.anchor.source_commit == commit
                {
                    found.push((id, manifest));
                }
            }
        }
        found.sort_by_key(|(id, _)| *id);
        let Some((first, chosen)) = found.first() else {
            return Err(Error::Refused(format!(
                "no import of this served repository names commit {commit}: import it with \
                 vault.code.import, or initialize at a commit it imported"
            )));
        };
        let ambiguous = found.iter().any(|(_, other)| {
            other.anchor.source_ref != chosen.anchor.source_ref
                || other.anchor.source_tree != chosen.anchor.source_tree
                || other.inventory_digest != chosen.inventory_digest
        });
        if ambiguous {
            let mut refs: Vec<&str> = found
                .iter()
                .map(|(_, manifest)| manifest.anchor.source_ref.as_str())
                .collect();
            refs.sort_unstable();
            refs.dedup();
            return Err(Error::Refused(format!(
                "the queue source is ambiguous: the imports of commit {commit} disagree (source \
                 refs {}); initialize at a commit whose imports name one ref and one tree",
                refs.join(", ")
            )));
        }
        Ok(*first)
    }

    /// The import `manifest_ref` authenticated before its source is made:
    /// its identity, its Published receive-pack admission revalidated, the
    /// pinned commit's complete tree and inventory digest, and the imported
    /// snapshot's custody. Approval is not required: it needs the checked
    /// Baseline this init produces.
    ///
    /// # Errors
    /// What does not prove, by name, or a store or object store failure.
    pub(super) fn require_served_queue_source(
        &self,
        git: &GitWire<'_>,
        served: &GitWireRepo,
        anchor: EntityId,
        manifest_ref: EntityId,
    ) -> Result<CodeImportManifest> {
        let commit = served.pinned_commit()?;
        let store = served.identity().as_hex();
        let manifest = self.queue_import_manifest(manifest_ref, anchor, &store, commit.as_str())?;
        let source_ref = GitRefName::parse_full(manifest.anchor.source_ref.clone())?;
        let (_, tree) = self.require_admitted_push(
            git,
            served,
            manifest.anchor.admission_receipt,
            &source_ref,
            &commit,
        )?;
        if tree.as_str() != manifest.anchor.source_tree {
            return Err(Error::Refused(
                "the imported commit no longer names its manifest's tree".to_owned(),
            ));
        }
        let inventory = CodeTreeInventory::capture_pinned(self, git, served, &commit, &tree)?;
        if manifest_digest(&manifest.anchor, inventory.blobs()) != manifest.digest
            || bytes_to_hex_lower(&CodeTreeInventory::blob_digest(inventory.blobs()))
                != manifest.inventory_digest
        {
            return Err(Error::Refused(
                "the imported tree's inventory is not its manifest's".to_owned(),
            ));
        }
        let txn = self.store.env.read_txn()?;
        import_snapshot_custody_in_txn(self, &txn, &manifest)?.map_err(Error::Refused)?;
        Ok(manifest)
    }
}

impl MergeQueue<'_> {
    /// CALL 4 "logical branch": the branch a checked init enrolls for
    /// automatic driving. A served source's is its frozen import's full
    /// `refs/heads/*` ref with the served anchor as subject; a tag import
    /// enrolls none. A native queue's is its attached HEAD, as before.
    ///
    /// # Errors
    /// A binding that does not prove, or a Git read failure.
    pub(super) fn queue_source_driver_target(
        &self,
        work: &QueueCheckWork,
        subject: EntityId,
    ) -> Result<Option<QueueDriverTarget>> {
        let Some(bound) = self.vault.init_work_source(work)? else {
            return self.attached_target(subject);
        };
        let full_ref = bound.manifest.anchor.source_ref;
        let Some(branch) = full_ref.strip_prefix("refs/heads/").map(str::to_owned) else {
            return Ok(None);
        };
        Ok(Some(QueueDriverTarget {
            full_ref,
            branch,
            branch_subject: subject,
        }))
    }
}
