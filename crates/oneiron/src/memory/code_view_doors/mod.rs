//! Owner-credential working views and account-local build/verify reuse.
//! No account-vault path, foreign account lookup, secret value, or caller result is admitted.
mod execution;
mod types;
pub use types::*;

use super::{MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};
use crate::build_cache::{
    BuildAction, BuildCache, BuildCacheError, BuildInputRoot, BuildPlatform, CachedActionResult,
    DeclaredOutputPath, ExtraInputDigest, FrozenBuildCommand,
};
use crate::code_revision::{CodeRevision, read_code_revision_blobs};
use crate::code_view::{CodeViewSet, ViewReceipt};
use crate::codebase::{CodebaseFileEntry, CodebaseSnapshot, RepoRef};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::Error;
use crate::git_wire::GitWire;
use crate::memory::repo_secret_reads::project_repo_file;
use crate::origin::secret_projection::{RepoSecretAudience, materialize_masked_repo};
use crate::{EdgeActorClass, EntityId};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

impl Memory<'_> {
    fn view_owner(&self, owner: &AuthenticatedOwner, account: EntityId) -> MemoryResult<()> {
        if owner.revalidate(self.vault)? != self.actor
            || self.actor_class != EdgeActorClass::Human
            || account != self.actor
        {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "working views and cache act only within the authenticated owner's account",
                &[],
            ));
        }
        Ok(())
    }

    fn view_readable(&self, id: EntityId) -> MemoryResult<()> {
        self.produced_from([id]);
        if self.get_entity(&id.to_hex())?.value.is_none() {
            return Err(MemoryError::not_found(
                "working-view source is absent or withheld",
            ));
        }
        Ok(())
    }

    fn view_source(
        &self,
        repo: EntityId,
        tested: EntityId,
    ) -> MemoryResult<(CodebaseSnapshot, BTreeMap<String, Vec<u8>>)> {
        self.view_readable(repo)?;
        self.view_readable(tested)?;
        let body = self
            .vault
            .get_code_artifact(&repo)?
            .ok_or_else(|| MemoryError::not_found("repository not found"))?;
        let repo_ref = RepoRef::parse(&body.repo_ref)?;
        let revision = self
            .vault
            .get_code_revision(&tested)?
            .ok_or_else(|| MemoryError::not_found("finalized tested revision not found"))?;
        self.view_readable(revision.session_id)?;
        let mut contents = BTreeMap::new();
        for frontier in revision.file_frontiers.values() {
            if frontier.repo != repo_ref.canonical() {
                return Err(MemoryError::bad_request(
                    "tested file belongs to another repository",
                ));
            }
            let bytes = self.vault.code_document_at(frontier)?.into_bytes();
            if contents.insert(frontier.path.clone(), bytes).is_some() {
                return Err(MemoryError::bad_request("duplicate tested path"));
            }
        }
        // A tested queue revision's untouched paths are files of its tree too (FIX 9940).
        if !revision.blob_frontiers.is_empty() {
            for (path, bytes) in self.tested_blobs(repo, &repo_ref, &revision)? {
                if contents.insert(path, bytes).is_some() {
                    return Err(MemoryError::bad_request("duplicate tested path"));
                }
            }
        }
        if contents.is_empty() {
            return Err(MemoryError::bad_request("tested revision holds no files"));
        }
        let entries = contents
            .iter()
            .map(|(path, bytes)| {
                CodebaseFileEntry::new(
                    path.clone(),
                    *blake3::hash(bytes).as_bytes(),
                    bytes.len() as u64,
                )
            })
            .collect();
        let snapshot = CodebaseSnapshot::new(repo.to_hex(), repo_ref, None, entries)?;
        Ok((snapshot, contents))
    }

    /// The untouched blobs of tested queue revision `revision` of `repo`,
    /// read from the repository's own object store.
    fn tested_blobs(
        &self,
        repo: EntityId,
        repo_ref: &RepoRef,
        revision: &CodeRevision,
    ) -> MemoryResult<BTreeMap<String, Vec<u8>>> {
        if revision
            .tested_queue
            .as_ref()
            .is_some_and(|tested| tested.repo != repo)
        {
            return Err(MemoryError::bad_request(
                "tested file belongs to another repository",
            ));
        }
        let RepoRef::LocalFolder { path, .. } = repo_ref else {
            return Err(MemoryError::bad_request(
                "a tested tree's untouched files read from a local repository",
            ));
        };
        let wire = GitWire::new(self.vault)?;
        let store = wire.open_repo(repo_ref.clone(), std::path::Path::new(path))?;
        Ok(read_code_revision_blobs(
            self.vault, &wire, &store, revision,
        )?)
    }

    pub fn code_view_materialize_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeViewMaterializeRequest,
    ) -> MemoryResult<CodeWorkingView> {
        self.view_materialize(owner, input, &RepoSecretAudience::HumanOwner(owner))
    }

    /// [`Self::code_view_materialize_as`] for a caller the host knows is a
    /// tool or a run (FIX 7608, ASK 1): the same admission and receipt, the
    /// view holding the masked copy of each file a repo mark covers.
    pub fn code_view_materialize_projected_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeViewMaterializeRequest,
    ) -> MemoryResult<CodeWorkingView> {
        self.view_materialize(owner, input, &RepoSecretAudience::Masked)
    }

    /// The one materializer of both: the selected files as `audience`
    /// reads them; stored bytes for the owner.
    fn view_materialize(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeViewMaterializeRequest,
        audience: &RepoSecretAudience<'_>,
    ) -> MemoryResult<CodeWorkingView> {
        self.view_owner(owner, input.account)?;
        let (snapshot, contents) = self.view_source(input.repo, input.tested)?;
        let mut selected = BTreeMap::new();
        // Validate the policy even if it selects no files.
        if input.policy.version != 1 {
            return Err(MemoryError::bad_request(
                "unknown visible-file policy version",
            ));
        }
        for (path, bytes) in contents {
            if input.policy.selects(&path)? {
                selected.insert(path, bytes);
            }
        }
        let selected = materialize_masked_repo(self.vault, selected, audience)?.into_contents();
        BuildCache::bind_owner_account(self.vault, owner, &input.account.to_hex())
            .map_err(cache_error)?;
        let set = CodeViewSet::open(self.vault)?;
        let revision = self
            .vault
            .get_code_revision(&input.tested)?
            .ok_or(Error::EntityNotFound)?;
        let receipt = set.materialize_tree(
            self.actor,
            snapshot.fork_hash,
            Some((input.repo, input.tested)),
            &selected,
            |txn| {
                owner.revalidate_in_txn(self.vault, txn)?;
                if self
                    .vault
                    .get_code_revision_in_txn(txn, &input.tested)?
                    .as_ref()
                    != Some(&revision)
                {
                    return Err(Error::ConcurrentWrite(
                        "tested revision changed during materialization",
                    ));
                }
                Ok(())
            },
        )?;
        working_view(
            self.vault,
            &set,
            receipt,
            input.repo,
            input.tested,
            input.account,
        )
    }

    fn admitted_view<'a>(
        &'a self,
        owner: &AuthenticatedOwner,
        input: &CodeViewRequest,
    ) -> MemoryResult<(CodeViewSet<'a>, ViewReceipt, CodebaseSnapshot)> {
        self.view_owner(owner, input.account)?;
        BuildCache::for_owner(self.vault, owner, &input.account.to_hex()).map_err(cache_error)?;
        let (snapshot, _) = self.view_source(input.repo, input.tested)?;
        let set = CodeViewSet::open(self.vault)?;
        let receipt = set
            .receipt(input.view)?
            .ok_or_else(|| MemoryError::not_found("view not found"))?;
        if receipt.actor != self.actor
            || receipt.fork_hash != snapshot.fork_hash
            || receipt.base != Some((input.repo, input.tested))
        {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "view base or account mismatch",
                &[],
            ));
        }
        Ok((set, receipt, snapshot))
    }

    pub fn code_view_get_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeViewRequest,
    ) -> MemoryResult<CodeWorkingView> {
        let (set, receipt, _) = self.admitted_view(owner, &input)?;
        working_view(
            self.vault,
            &set,
            receipt,
            input.repo,
            input.tested,
            input.account,
        )
    }

    pub fn code_view_read_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeViewReadRequest,
    ) -> MemoryResult<CodeViewFileBytes> {
        let (set, receipt, _) = self.admitted_view(owner, &input.view)?;
        if !receipt.files.contains_key(&input.path) {
            return Err(MemoryError::not_found("path is not an input of this view"));
        }
        let bytes =
            crate::code_view::read_view_file(&set.view_path(input.view.view)?, &input.path)?;
        Ok(CodeViewFileBytes {
            path: input.path,
            sha256: bytes_to_hex_lower(&Sha256::digest(&bytes)),
            bytes,
            projection: None,
        })
    }

    /// [`Self::code_view_read_as`] for a caller the host knows is a tool or
    /// a run (FIX 7608, ASK 1): the same admission; bytes a repo mark covers
    /// read as their projection, with the copy's own SHA-256.
    pub fn code_view_read_projected_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeViewReadRequest,
    ) -> MemoryResult<CodeViewFileBytes> {
        if let Some(why) = input.why.clone() {
            return self.code_view_read_with_why(owner, input, &why);
        }
        let file = self.code_view_read_as(owner, input)?;
        let projected = project_repo_file(self.vault, file.bytes)?;
        let projection = projected.view();
        let bytes = projected.into_bytes();
        Ok(CodeViewFileBytes {
            path: file.path,
            sha256: bytes_to_hex_lower(&Sha256::digest(&bytes)),
            bytes,
            projection,
        })
    }

    /// [`Self::code_view_read_projected_as`] for a read that says `why`
    /// (FIX 8960): the view's file read as the marked blob it holds through
    /// the file reveal, its stored bytes only under a committed delivery,
    /// else its masked copy; the view is admitted again before release.
    fn code_view_read_with_why(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeViewReadRequest,
        why: &str,
    ) -> MemoryResult<CodeViewFileBytes> {
        let view = input.view.clone();
        let file = self.code_view_read_as(owner, input)?;
        let readmit = || -> crate::error::Result<()> {
            self.admitted_view(owner, &view)
                .map(|_| ())
                .map_err(|_| crate::Error::ConcurrentWrite("the view read's admission changed"))
        };
        let read = self.view_file_read_with_why(
            view.repo,
            Some(view.tested),
            &file.path,
            file.bytes,
            Some(why),
            readmit,
        )?;
        let projection = read.projection.view();
        let bytes = read.projection.into_bytes();
        Ok(CodeViewFileBytes {
            path: file.path,
            sha256: bytes_to_hex_lower(&Sha256::digest(&bytes)),
            bytes,
            projection,
        })
    }

    pub fn code_view_action_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeViewActionRequest,
    ) -> MemoryResult<CodeViewAction> {
        let (set, _, snapshot) = self.admitted_view(owner, &input.view)?;
        let action = build_action(&snapshot, &input.spec)?;
        let action = set
            .build_action(input.view.view, &action)
            .map_err(cache_error)?;
        Ok(CodeViewAction {
            action_digest: digest(action.reapi_digest().map_err(cache_error)?),
            command_bytes: action.reapi_command_bytes(),
            input_root_digest: digest(action.reapi_input_root_digest()),
        })
    }

    pub fn code_cache_get_as(
        &self,
        owner: &AuthenticatedOwner,
        input: CodeCacheReadRequest,
    ) -> MemoryResult<CodeCacheOutcome> {
        self.view_owner(owner, self.actor)?;
        let cache = match BuildCache::for_owner(self.vault, owner, &input.account.to_hex()) {
            Ok(cache) => cache,
            Err(BuildCacheError::AccountMismatch) => {
                return Ok(outcome(CodeCacheState::Denied, None));
            }
            Err(error) => return Err(cache_error(error)),
        };
        let key =
            crate::build_cache::ActionKey::parse(&input.action_digest.hash).map_err(cache_error)?;
        match cache.get(&key) {
            Ok(Some(cached)) if cached.action_size_bytes != input.action_digest.size_bytes => {
                Ok(outcome(CodeCacheState::Denied, None))
            }
            Ok(Some(cached)) => Ok(outcome(
                CodeCacheState::Hit,
                Some(self.build_entry(&cached, input.account, true)?),
            )),
            Ok(None) => Ok(outcome(CodeCacheState::Miss, None)),
            Err(
                BuildCacheError::TaintedResult { .. } | BuildCacheError::ArtifactUnavailable { .. },
            ) => Ok(outcome(CodeCacheState::Denied, None)),
            Err(error) => Err(cache_error(error)),
        }
    }

    fn build_entry(
        &self,
        cached: &CachedActionResult,
        account: EntityId,
        reusable: bool,
    ) -> MemoryResult<CodeBuildEntry> {
        let mut outputs = BTreeMap::new();
        let mut refs = BTreeMap::<String, u32>::new();
        for reference in cached.result.artifact_refs() {
            self.view_readable(*reference.artifact_id())?;
            for taint in self.vault.artifact_taint_refs(reference.artifact_id())? {
                refs.entry(taint.secret_ref)
                    .and_modify(|g| *g = (*g).min(taint.generation))
                    .or_insert(taint.generation);
            }
        }
        for (path, reference) in &cached.result.outputs {
            let bytes = self
                .vault
                .read_blob_artifact_version(reference.artifact_id(), reference.version())?
                .ok_or(Error::EntityNotFound)?;
            outputs.insert(
                path.as_str().to_owned(),
                CodeBuildOutput {
                    artifact_ref: reference.to_result_ref(),
                    output_sha256: bytes_to_hex_lower(&Sha256::digest(&bytes)),
                },
            );
        }
        Ok(CodeBuildEntry {
            action_digest: CodeActionDigest {
                hash: cached.action_key.to_hex(),
                size_bytes: cached.action_size_bytes,
            },
            account,
            exit_code: cached.result.exit_code,
            outputs,
            stdout_ref: cached.result.stdout_ref.as_ref().map(|r| r.to_result_ref()),
            stderr_ref: cached.result.stderr_ref.as_ref().map(|r| r.to_result_ref()),
            secret_taint_refs: refs
                .into_iter()
                .map(|(secret_ref, generation)| CodeSecretTaintRef {
                    secret_ref,
                    rotation_generation: generation,
                })
                .collect(),
            reusable,
            receipt: cached.result.producer_ref.clone(),
        })
    }
}

fn build_action(snapshot: &CodebaseSnapshot, spec: &CodeBuildSpec) -> MemoryResult<BuildAction> {
    crate::secret_rotation::validate_taint_refs(&spec.engine_taint_refs())?;
    if spec
        .argv
        .first()
        .is_none_or(|program| !std::path::Path::new(program).is_absolute())
    {
        return Err(MemoryError::bad_request(
            "argv must name an absolute native build executable",
        ));
    }
    for value in spec
        .argv
        .iter()
        .chain(spec.env_allowlist.values())
        .chain(spec.platform.values())
    {
        crate::batch::secret_scan::scan_metadata_field(value)?;
    }
    for path in &spec.declared_outputs {
        crate::code_view::relative(path)?;
    }
    let mut taint = spec.secret_taint_refs.clone();
    taint.sort_by(|a, b| a.secret_ref.cmp(&b.secret_ref));
    let identity = rmp_serde::to_vec(&(taint, &spec.class))
        .map_err(|_| MemoryError::bad_request("build inputs could not encode"))?;
    BuildAction::new(
        FrozenBuildCommand::new(spec.argv.clone(), spec.env_allowlist.clone())
            .map_err(cache_error)?,
        BuildInputRoot {
            repo_ref: snapshot.repo_ref.clone(),
            fork_hash: snapshot.fork_hash,
            extra_inputs: vec![ExtraInputDigest::new(Sha256::digest(identity).into())],
        },
        BuildPlatform::new(spec.platform.clone()).map_err(cache_error)?,
        spec.declared_outputs
            .iter()
            .map(|p| DeclaredOutputPath::parse(p.clone()))
            .collect::<Result<_, _>>()
            .map_err(cache_error)?,
    )
    .map_err(cache_error)
}
fn working_view(
    vault: &crate::Vault,
    set: &CodeViewSet<'_>,
    receipt: ViewReceipt,
    repo: EntityId,
    tested: EntityId,
    account: EntityId,
) -> MemoryResult<CodeWorkingView> {
    let revision = vault
        .get_code_revision(&tested)?
        .ok_or(Error::EntityNotFound)?;
    let mut files = Vec::new();
    for (path, hash) in receipt.files {
        let content_hash_blake3 = bytes_to_hex_lower(&hash);
        // An untouched blob keeps its Git object, never a fabricated frontier (FIX 9940).
        let Some(frontier) = revision
            .file_frontiers
            .values()
            .find(|file| file.path == path)
        else {
            let blob = revision
                .blob_frontiers
                .get(&path)
                .ok_or(Error::CorruptedIndex("view file has no tested frontier"))?;
            files.push(CodeViewFile {
                git_oid: Some(blob.git_oid.clone()),
                path,
                content_hash_blake3,
                frontier: None,
                text_sha256: None,
            });
            continue;
        };
        let text = vault.code_document_at(frontier)?;
        files.push(CodeViewFile {
            path,
            content_hash_blake3,
            frontier: Some(frontier.clone()),
            text_sha256: Some(bytes_to_hex_lower(&Sha256::digest(text.as_bytes()))),
            git_oid: None,
        });
    }
    Ok(CodeWorkingView {
        view: receipt.view_id,
        repo,
        base: tested,
        account,
        fork_hash: bytes_to_hex_lower(&receipt.fork_hash),
        files,
        receipt: receipt.view_id,
        host_path: set
            .view_path(receipt.view_id)?
            .to_string_lossy()
            .into_owned(),
    })
}
fn digest(digest: crate::build_cache::ReapiDigest) -> CodeActionDigest {
    CodeActionDigest {
        hash: bytes_to_hex_lower(&digest.hash),
        size_bytes: digest.size_bytes,
    }
}
fn outcome(state: CodeCacheState, entry: Option<CodeBuildEntry>) -> CodeCacheOutcome {
    CodeCacheOutcome {
        state,
        receipt: entry.as_ref().map(|e| e.receipt.clone()),
        entry,
    }
}
fn cache_error(error: BuildCacheError) -> MemoryError {
    match error {
        BuildCacheError::Store(error) => error.into(),
        error => MemoryError::new(MEMORY_CODE_INVALID_STATE, error.to_string(), &[]),
    }
}
