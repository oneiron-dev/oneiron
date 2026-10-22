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
use crate::EdgeActorClass;
use crate::code_view::CodeViewSet;
use crate::codebase::{CodebaseSnapshotMount, snapshot_asset_entity_id};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::Error;
use crate::federation::{RepoAccessIntent, RepoAccessRefusal};
use crate::memory::codebase_doors::CodeSnapshotDefinition;
use crate::memory::{MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};
use crate::origin::secret_projection::RepoRevealRecipient;
use crate::origin::secret_projection::reveal::RepoReadDoor;

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
        // A run reads repo bytes masked (FIX 7608): each marked file names
        // the copy its read returns.
        let mut views =
            mount.projected_file_views(|path| bounds.admits_path(RepoAccessIntent::Read, path))?;
        let files = mount
            .snapshot()
            .files
            .iter()
            .filter(|entry| bounds.admits_path(RepoAccessIntent::Read, &entry.path))
            .map(|entry| {
                let mut file = snapshot_file(entry);
                file.projection = views.remove(&entry.path);
                file
            })
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
        // A run reads repo bytes masked (FIX 7608): a marked file's
        // projection, its opaque residue found before a byte is read. A read
        // that says why asks only after its lane admits the file (FIX 8960).
        let early = match input.why {
            None => Some(mount.read_file_projected(&input.path)?.ok_or_else(absent)?),
            Some(_) => None,
        };
        let entry = mount
            .snapshot()
            .files
            .iter()
            .find(|entry| entry.path == input.path)
            .ok_or_else(absent)?;
        let asset = snapshot_asset_entity_id(&entry.content_hash)?;
        self.repo_lane_reads(binding, &[asset])
            .map_err(|_| absent())?;
        let (read, byte_route) = match early {
            Some(read) => (read, None),
            None => {
                let changed = || Error::ConcurrentWrite("the run's repo read admission changed");
                let artifact = mount.code_artifact_id();
                let readmit = || -> crate::error::Result<()> {
                    let txn = self.vault.store.env.read_txn()?;
                    let again = self.vault.admit_repo_run_in_txn(
                        &txn,
                        binding,
                        &target,
                        RepoAccessIntent::Read,
                    )?;
                    drop(txn);
                    let again = again
                        .ok()
                        .filter(|again| again.same_lease(&admitted))
                        .ok_or_else(changed)?;
                    let (pinned, _) = self
                        .repo_pinned_snapshot(binding, &again, &input.git_ref, &input.snapshot)
                        .map_err(|_| changed())?;
                    if pinned.code_artifact_id() != artifact {
                        return Err(changed());
                    }
                    self.repo_lane_reads(binding, &[asset])
                        .map_err(|_| changed())
                };
                let read = run_reveal_reader(self, binding, &admitted)
                    .snapshot_file_read_with_why(
                        &mount,
                        input.repo,
                        &input.path,
                        input.why.as_deref(),
                        RepoReadDoor::Text,
                        readmit,
                    )?
                    .ok_or_else(absent)?;
                (read.projection, read.byte_route)
            }
        };
        let mut file = snapshot_file(entry);
        file.projection = read.view();
        // CALL 4: granted bytes that are not text keep the masked reply,
        // which names the byte route.
        if let (Some(route), Some(view)) = (byte_route, file.projection.as_mut()) {
            route.clone_into(&mut view.way_out);
        }
        let bytes = read.into_bytes();
        let text_sha256 = bytes_to_hex_lower(&Sha256::digest(&bytes));
        let content = String::from_utf8(bytes)
            .map_err(|_| MemoryError::bad_request("the pinned file is not UTF-8 text"))?;
        Ok(RepoRunAnswer {
            rows: vec![input.repo, mount.code_artifact_id(), asset],
            output: RepoSnapshotsReadOutput {
                repo: input.repo,
                git_ref: input.git_ref,
                snapshot: input.snapshot,
                file,
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
        let mut bytes =
            crate::code_view::read_view_file(&set.view_path(input.work)?, &input.path)?;
        if blake3::hash(&bytes).as_bytes() != expected {
            return Err(Error::CorruptedIndex("work file was modified").into());
        }
        // A read that says why may get the base file's stored bytes, while
        // the work still holds that file's masked copy (FIX 8960).
        if let Some(why) = input.why.as_deref() {
            if let Some(revealed) = self.repo_view_base_reveal(binding, &own, &input.path, &bytes, why)? {
                bytes = revealed;
            }
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

    /// The stored bytes of the work's base file `path`, for a read that
    /// says `why`, when the work still holds exactly that file's masked copy
    /// and the file reveal delivered them (FIX 8960); `None` otherwise, and
    /// the work's bytes are read as they are. A base the run's ref no longer
    /// pins, or a file the run changed, asks nothing.
    fn repo_view_base_reveal(
        &self,
        binding: &RepoRunBinding,
        own: &RepoOwnWork,
        path: &str,
        held: &[u8],
        why: &str,
    ) -> MemoryResult<Option<Vec<u8>>> {
        let snapshot = bytes_to_hex_lower(&own.stamp.base_snapshot);
        let Ok((mount, _)) =
            self.repo_pinned_snapshot(binding, &own.admitted, &own.stamp.git_ref, &snapshot)
        else {
            return Ok(None);
        };
        let Some(masked) = mount.read_file_projected(path)? else {
            return Ok(None);
        };
        if masked.view().is_none() || masked.into_bytes() != held {
            return Ok(None);
        }
        let changed = || Error::ConcurrentWrite("the run's work admission changed");
        let work = own.stamp.work;
        let readmit = || -> crate::error::Result<()> {
            let txn = self.vault.store.env.read_txn()?;
            let again = self.vault.admitted_repo_work_in_txn(
                &txn,
                binding,
                work,
                [path],
                RepoAccessIntent::Read,
            )?;
            drop(txn);
            match again {
                Ok(again)
                    if again.stamp == own.stamp && again.admitted.same_lease(&own.admitted) =>
                {
                    Ok(())
                }
                _ => Err(changed()),
            }
        };
        let read = run_reveal_reader(self, binding, &own.admitted).snapshot_file_read_with_why(
            &mount,
            own.stamp.repo,
            path,
            Some(why),
            RepoReadDoor::Bytes,
            readmit,
        )?;
        Ok(read
            .filter(|read| read.proof.is_some())
            .map(|read| read.projection.into_bytes()))
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

/// A run's handle for a per-file read that may ask for real bytes (FIX
/// 8960): masked whatever credential rides it, and bound to the run's own
/// agent when the run's actor is one; never the owner standing in for one.
fn run_reveal_reader<'v>(
    memory: &Memory<'v>,
    binding: &RepoRunBinding,
    admitted: &RepoRunAdmitted,
) -> Memory<'v> {
    let reader = memory.clone().for_repo_tool_recipient();
    if binding.actor.actor_class() != EdgeActorClass::Agent {
        return reader;
    }
    reader.for_repo_reveal_recipient(
        RepoRevealRecipient::proven_agent(binding.actor.entity_ref())
            .in_project(Some(admitted.membership.bounds.project))
            .for_run(Some(binding.executor_run.to_hex())),
    )
}
