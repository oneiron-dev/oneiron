//! The run repo doors' reads: snapshots and their files and definitions at
//! the commit the run's full ref names now, the run's own work and its
//! files, and the queue its work is pinned under. Lists and bytes are the
//! paths the Grant reads now; nothing else of the snapshot, the work or the
//! queue is shown.

use sha2::{Digest, Sha256};

use super::work::{
    RepoOwnWork, repo_ref_pin, resolve_repo_queue_target, same_folder, snapshot_file, work_view,
};
use super::{
    NO_PATHS, RepoMergeQueueObserveInput, RepoMergeQueueObserveOutput, RepoRunAdmitted,
    RepoRunAnswer, RepoRunBinding, RepoSnapshotView, RepoSnapshotsGetInput, RepoSnapshotsGetOutput,
    RepoSnapshotsReadInput, RepoSnapshotsReadOutput, RepoSymbolsDefinitionsInput,
    RepoSymbolsDefinitionsOutput, RepoViewsGetInput, RepoViewsGetOutput, RepoViewsReadInput,
    RepoViewsReadOutput, refusal_error, repo_target,
};
use crate::EntityId;
use crate::code_view::CodeViewSet;
use crate::codebase::{CodebaseSnapshotMount, snapshot_asset_entity_id};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::Error;
use crate::federation::{RepoAccessIntent, RepoAccessRefusal};
use crate::memory::codebase_doors::CodeSnapshotDefinition;
use crate::memory::{MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};

impl Memory<'_> {
    /// `self.code.snapshots.get` for a run: the manifest of the named
    /// snapshot of the admitted repo at its ref's current commit, the paths
    /// the Grant reads only.
    pub fn repo_snapshots_get_for_run(
        &self,
        binding: &RepoRunBinding,
        input: RepoSnapshotsGetInput,
    ) -> MemoryResult<RepoRunAnswer<RepoSnapshotsGetOutput>> {
        let target = repo_target(input.repo, &input.git_ref, NO_PATHS);
        let admitted = self.repo_run_admit(binding, &target, RepoAccessIntent::Read)?;
        let (mount, commit) =
            self.repo_pinned_snapshot(binding, &admitted, &input.git_ref, &input.snapshot)?;
        let bounds = &admitted.membership.bounds;
        let files = mount
            .snapshot()
            .files
            .iter()
            .filter(|entry| bounds.admits_path(RepoAccessIntent::Read, &entry.path))
            .map(snapshot_file)
            .collect();
        Ok(RepoRunAnswer {
            rows: vec![input.repo, mount.code_artifact_id()],
            output: RepoSnapshotView {
                repo: input.repo,
                git_ref: input.git_ref,
                commit,
                snapshot: input.snapshot,
                artifact: mount.code_artifact_id(),
                files,
            },
        })
    }

    /// `self.code.snapshots.read` for a run: one file of such a snapshot,
    /// read from its stored blob, which the run's lane must read. A path the
    /// Grant does not read is refused before the snapshot resolves.
    pub fn repo_snapshots_read_for_run(
        &self,
        binding: &RepoRunBinding,
        input: RepoSnapshotsReadInput,
    ) -> MemoryResult<RepoRunAnswer<RepoSnapshotsReadOutput>> {
        let target = repo_target(input.repo, &input.git_ref, [input.path.as_str()]);
        let admitted = self.repo_run_admit(binding, &target, RepoAccessIntent::Read)?;
        let (mount, _) =
            self.repo_pinned_snapshot(binding, &admitted, &input.git_ref, &input.snapshot)?;
        let absent = || MemoryError::not_found("the file is absent or withheld in this snapshot");
        let bytes = mount.read_file(&input.path)?.ok_or_else(absent)?;
        let entry = mount
            .snapshot()
            .files
            .iter()
            .find(|entry| entry.path == input.path)
            .ok_or_else(absent)?;
        let asset = snapshot_asset_entity_id(&entry.content_hash)?;
        self.repo_lane_reads(binding, &[asset])
            .map_err(|_| absent())?;
        let text_sha256 = bytes_to_hex_lower(&Sha256::digest(&bytes));
        let content = String::from_utf8(bytes)
            .map_err(|_| MemoryError::bad_request("the pinned file is not UTF-8 text"))?;
        Ok(RepoRunAnswer {
            rows: vec![input.repo, mount.code_artifact_id(), asset],
            output: RepoSnapshotsReadOutput {
                repo: input.repo,
                git_ref: input.git_ref,
                snapshot: input.snapshot,
                file: snapshot_file(entry),
                content,
                text_sha256,
            },
        })
    }

    /// `self.code.symbols.definitions` for a run: the exact-name Rust
    /// definitions such a snapshot's symbol manifest records, in its order,
    /// on the paths the Grant reads only.
    pub fn repo_symbols_definitions_for_run(
        &self,
        binding: &RepoRunBinding,
        input: RepoSymbolsDefinitionsInput,
    ) -> MemoryResult<RepoRunAnswer<RepoSymbolsDefinitionsOutput>> {
        let target = repo_target(input.repo, &input.git_ref, NO_PATHS);
        let admitted = self.repo_run_admit(binding, &target, RepoAccessIntent::Read)?;
        let (mount, _) =
            self.repo_pinned_snapshot(binding, &admitted, &input.git_ref, &input.snapshot)?;
        let artifact = mount.code_artifact_id();
        if let Some(manifest) = self.vault.get_code_symbol_manifest(&artifact)? {
            let pinned = mount.snapshot();
            if manifest.repo_ref != pinned.repo_ref || manifest.commit_hash != pinned.commit_hash {
                return Err(MemoryError::new(
                    MEMORY_CODE_INVALID_STATE,
                    "the symbol manifest is not of the pinned snapshot",
                    &[],
                ));
            }
        }
        let bounds = &admitted.membership.bounds;
        let definitions: Vec<_> = self
            .vault
            .code_symbol_definitions(&artifact, &input.name)?
            .into_iter()
            .filter(|definition| bounds.admits_path(RepoAccessIntent::Read, &definition.path))
            .collect();
        let mut rows = vec![input.repo, artifact];
        rows.extend(definitions.iter().map(|definition| definition.entity_id));
        Ok(RepoRunAnswer {
            rows,
            output: RepoSymbolsDefinitionsOutput {
                repo: input.repo,
                git_ref: input.git_ref,
                snapshot: input.snapshot,
                definitions: definitions
                    .into_iter()
                    .map(|definition| CodeSnapshotDefinition {
                        symbol: definition.entity_id,
                        path: definition.path,
                        name: definition.name,
                        kind: definition.kind,
                        fingerprint: bytes_to_hex_lower(&definition.fingerprint),
                        start_line: definition.start_line,
                        end_line: definition.end_line,
                    })
                    .collect(),
            },
        })
    }

    /// `self.code.views.get` for a run: its own work, the files it holds
    /// that the Grant still reads.
    pub fn repo_views_get_for_run(
        &self,
        binding: &RepoRunBinding,
        input: RepoViewsGetInput,
    ) -> MemoryResult<RepoRunAnswer<RepoViewsGetOutput>> {
        let own = self.repo_own_work(binding, input.work, NO_PATHS, RepoAccessIntent::Read)?;
        let bounds = &own.admitted.membership.bounds;
        let mut output = work_view(&own.receipt, &own.stamp);
        output
            .files
            .retain(|file| bounds.admits_path(RepoAccessIntent::Read, &file.path));
        Ok(RepoRunAnswer {
            rows: vec![own.stamp.repo],
            output,
        })
    }

    /// `self.code.views.read` for a run: one file of its own work, as the
    /// work holds it. Bytes that no longer match the work's receipt are
    /// refused, never shown.
    pub fn repo_views_read_for_run(
        &self,
        binding: &RepoRunBinding,
        input: RepoViewsReadInput,
    ) -> MemoryResult<RepoRunAnswer<RepoViewsReadOutput>> {
        let own = self.repo_own_work(
            binding,
            input.work,
            [input.path.as_str()],
            RepoAccessIntent::Read,
        )?;
        let Some(expected) = own.receipt.files.get(&input.path) else {
            return Err(MemoryError::not_found(
                "the path is not a file of this work",
            ));
        };
        let set = CodeViewSet::open(self.vault)?;
        let bytes = crate::code_view::read_view_file(&set.view_path(input.work)?, &input.path)?;
        if blake3::hash(&bytes).as_bytes() != expected {
            return Err(Error::CorruptedIndex("work file was modified").into());
        }
        Ok(RepoRunAnswer {
            rows: vec![own.stamp.repo],
            output: RepoViewsReadOutput {
                work: input.work,
                path: input.path,
                sha256: bytes_to_hex_lower(&Sha256::digest(&bytes)),
                bytes,
            },
        })
    }

    /// `self.code.merge_queue.observe` for a run: the queue its own work is
    /// pinned under, its head and green, whether green moved past the work's
    /// pin, and the entries accepted from this work with what each waits
    /// behind now.
    pub fn repo_merge_queue_observe_for_run(
        &self,
        binding: &RepoRunBinding,
        input: RepoMergeQueueObserveInput,
    ) -> MemoryResult<RepoRunAnswer<RepoMergeQueueObserveOutput>> {
        let own = self.repo_own_work(binding, input.work, NO_PATHS, RepoAccessIntent::Read)?;
        let queue = resolve_repo_queue_target(
            self.vault,
            &own.admitted.membership.repo_ref,
            &own.stamp.git_ref,
        )?
        .map_err(refusal_error)?;
        let (entries, blockers) =
            self.repo_queue_entries(binding, &own.admitted.membership.repo_ref, input.work)?;
        let mut rows = vec![own.stamp.repo];
        rows.extend(blockers);
        Ok(RepoRunAnswer {
            rows,
            output: RepoMergeQueueObserveOutput {
                work: input.work,
                repo: own.stamp.repo,
                entries,
                green_moved: queue.green != own.stamp.base_green,
                git_ref: own.stamp.git_ref,
                base_green: own.stamp.base_green,
                head_commit: queue.head,
                green_commit: queue.green,
            },
        })
    }

    /// The run's own work `work`, admitted for `intent` on `paths` (none: its
    /// ref alone), with the run's lane reading its repo.
    pub(super) fn repo_own_work<S: AsRef<str>>(
        &self,
        binding: &RepoRunBinding,
        work: EntityId,
        paths: impl IntoIterator<Item = S>,
        intent: RepoAccessIntent,
    ) -> MemoryResult<RepoOwnWork> {
        let own = {
            let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
            self.vault
                .admitted_repo_work_in_txn(&txn, binding, work, paths, intent)?
                .map_err(refusal_error)?
        };
        self.repo_lane_reads(binding, &[own.stamp.repo])?;
        Ok(own)
    }

    /// The snapshot `snapshot` names of the admitted repo, at the commit the
    /// run's full ref names now, with that commit (CALLS "FIX 6867 run-only
    /// ref contract"): no snapshot of another commit or another repo is
    /// served under an admitted ref. The run's lane must read the repo and
    /// the snapshot's artifact.
    fn repo_pinned_snapshot(
        &self,
        binding: &RepoRunBinding,
        admitted: &RepoRunAdmitted,
        git_ref: &str,
        snapshot: &str,
    ) -> MemoryResult<(CodebaseSnapshotMount<'_>, String)> {
        let fork_hash = parse_fork_hash(snapshot)?;
        let membership = &admitted.membership;
        let Some(commit) = repo_ref_pin(self.vault, &membership.repo_ref, git_ref) else {
            return Err(refusal_error(RepoAccessRefusal::WrongRef));
        };
        let mut pinned = None;
        for artifact in self.vault.codebase_snapshots_by_fork_hash(&fork_hash)? {
            let Some(mount) = self.vault.mount_codebase_snapshot(&artifact)? else {
                continue;
            };
            let held = mount.snapshot();
            if held.commit_hash.as_deref() == Some(commit.as_str())
                && same_folder(&held.repo_ref, &membership.repo_ref)
            {
                pinned = Some(mount);
                break;
            }
        }
        let Some(mount) = pinned else {
            return Err(refusal_error(RepoAccessRefusal::WrongRef));
        };
        self.repo_lane_reads(binding, &[membership.bounds.repo, mount.code_artifact_id()])?;
        Ok((mount, commit.as_str().to_owned()))
    }
}

/// A snapshot selector: its fork hash in 64 lower-hex characters.
fn parse_fork_hash(snapshot: &str) -> MemoryResult<[u8; 32]> {
    let invalid =
        || MemoryError::bad_request("snapshot must be the fork hash, 64 lower-hex characters");
    if snapshot.len() != 64
        || !snapshot
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid());
    }
    let mut hash = [0_u8; 32];
    for (index, slot) in hash.iter_mut().enumerate() {
        *slot =
            u8::from_str_radix(&snapshot[index * 2..index * 2 + 2], 16).map_err(|_| invalid())?;
    }
    Ok(hash)
}
