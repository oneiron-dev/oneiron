//! The run repo doors' one read join (FIX 4300, CODE-CUSTODY-01): the
//! admitted CODE anchor, the snapshot its full ref selects now, the requested
//! path, and the ASSET or symbol revisions under it, judged in one read
//! snapshot before the door shows anything.
//!
//! - Authority is the run's L02 admission
//!   ([`Vault::admit_repo_run_with_portable_in_txn`]), read again in the
//!   join's own snapshot under the same lease and repository. A read that
//!   names a portable repo id is admitted on the anchor the id selects, and
//!   the join refuses a selection that changed meanwhile. The ref contract
//!   is the run's: the commit the admitted full ref names now, never a
//!   historical pin.
//! - The snapshot belongs to the anchor: it names that anchor, or names none
//!   as an unregistered capture of the same folder. A capture of another
//!   registration is not served under this anchor.
//! - Every row the answer stands on is read through the run's own ScopedRead
//!   key in that snapshot. The snapshot's repository scope then filters
//!   them. Scope membership is a filter, never a Grant.
//! - A symbol's span and fingerprint are the selected manifest's, never a
//!   newer symbol row's.
//!
//! A refusal before authority stands is the typed [`RepoAccessRefusal`]. A
//! repo or snapshot row the run's lane does not read is
//! [`super::REPO_LANE_UNREADABLE`]. A file or symbol the lane or the scope
//! leaves out reads as absent, with no count.

use super::work::{repo_ref_pin, same_folder};
use super::{RepoRunAdmitted, RepoRunBinding, refusal_error, repo_lane_unreadable};
use crate::Vault;
use crate::claim::{ClaimReadStatus, PointRead, ScopedRead};
use crate::code_symbol::{CodeSymbolDefinition, code_symbol_definitions_in_txn};
use crate::codebase::{
    CodebaseFileEntry, CodebaseSnapshotMount, codebase_candidate_matches_scope_key,
    snapshot_asset_entity_id,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::memory::{MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};
use crate::origin::RepoPortableId;
use oneiron_authority::federation::{RepoAccessIntent, RepoAccessRefusal, RepoTarget};

/// What a run's read selects under the snapshot its pin selected (FIX 4300).
pub(super) trait RepoReadMember {
    /// The selection, as the join keeps it.
    type Joined;

    /// The selection under `mount`, read in `txn` under `admitted`, and the
    /// member rows it stands on, in order.
    fn select(
        self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        mount: &CodebaseSnapshotMount<'_>,
        admitted: &RepoRunAdmitted,
    ) -> MemoryResult<(Self::Joined, Vec<EntityId>)>;

    /// The part of `joined` whose rows the run's lane reads and the scope
    /// holds: `kept` answers for each member row, in order.
    fn keep(joined: Self::Joined, kept: &[bool]) -> MemoryResult<Self::Joined>;
}

/// The snapshot alone: its anchor and its CODE.
pub(super) struct SnapshotRows;

impl RepoReadMember for SnapshotRows {
    type Joined = ();

    fn select(
        self,
        _: &Vault,
        _: &heed::RoTxn<'_>,
        _: &CodebaseSnapshotMount<'_>,
        _: &RepoRunAdmitted,
    ) -> MemoryResult<((), Vec<EntityId>)> {
        Ok(((), Vec::new()))
    }

    fn keep(joined: (), _: &[bool]) -> MemoryResult<()> {
        Ok(joined)
    }
}

/// One file of the snapshot, by path, and the ASSET its bytes are stored as.
pub(super) struct FileRow<'a>(pub(super) &'a str);

/// The file a [`FileRow`] joined.
pub(super) struct JoinedFile {
    pub(super) entry: CodebaseFileEntry,
    pub(super) asset: EntityId,
}

impl RepoReadMember for FileRow<'_> {
    type Joined = JoinedFile;

    fn select(
        self,
        _: &Vault,
        _: &heed::RoTxn<'_>,
        mount: &CodebaseSnapshotMount<'_>,
        _: &RepoRunAdmitted,
    ) -> MemoryResult<(JoinedFile, Vec<EntityId>)> {
        let path = self.0;
        if mount.is_withheld(path) {
            return Err(file_absent());
        }
        let entry = mount
            .snapshot()
            .files
            .iter()
            .find(|entry| entry.path == path)
            .cloned()
            .ok_or_else(file_absent)?;
        let asset = snapshot_asset_entity_id(&entry.content_hash)?;
        Ok((JoinedFile { entry, asset }, vec![asset]))
    }

    fn keep(joined: JoinedFile, kept: &[bool]) -> MemoryResult<JoinedFile> {
        if kept.first() == Some(&true) {
            Ok(joined)
        } else {
            Err(file_absent())
        }
    }
}

/// The definitions of one exact name in the snapshot's own symbol manifest,
/// on the paths the Grant reads and the snapshot does not withhold.
pub(super) struct DefinitionRows<'a>(pub(super) &'a str);

impl RepoReadMember for DefinitionRows<'_> {
    type Joined = Vec<CodeSymbolDefinition>;

    fn select(
        self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        mount: &CodebaseSnapshotMount<'_>,
        admitted: &RepoRunAdmitted,
    ) -> MemoryResult<(Vec<CodeSymbolDefinition>, Vec<EntityId>)> {
        let artifact = mount.code_artifact_id();
        let Some((manifest, definitions)) =
            code_symbol_definitions_in_txn(&vault.store, txn, &artifact, self.0)?
        else {
            return Ok((Vec::new(), Vec::new()));
        };
        let pinned = mount.snapshot();
        if manifest.repo_ref != pinned.repo_ref || manifest.commit_hash != pinned.commit_hash {
            return Err(MemoryError::new(
                MEMORY_CODE_INVALID_STATE,
                "the symbol manifest is not of the pinned snapshot",
                &[],
            ));
        }
        let bounds = &admitted.membership.bounds;
        let definitions: Vec<_> = definitions
            .into_iter()
            .filter(|definition| {
                bounds.admits_path(RepoAccessIntent::Read, &definition.path)
                    && !mount.is_withheld(&definition.path)
            })
            .collect();
        let rows = definitions
            .iter()
            .map(|definition| definition.entity_id)
            .collect();
        Ok((definitions, rows))
    }

    fn keep(
        joined: Vec<CodeSymbolDefinition>,
        kept: &[bool],
    ) -> MemoryResult<Vec<CodeSymbolDefinition>> {
        Ok(joined
            .into_iter()
            .zip(kept)
            .filter_map(|(definition, kept)| kept.then_some(definition))
            .collect())
    }
}

/// What one read join stands on (FIX 4300).
pub(super) struct RepoReadJoin<'v, J> {
    /// The run's admission, as the join's snapshot read it.
    pub(super) admitted: RepoRunAdmitted,
    /// The snapshot the pin selected.
    pub(super) mount: CodebaseSnapshotMount<'v>,
    /// The commit the admitted full ref names now.
    pub(super) commit: String,
    /// The member, as the lane and the scope kept it.
    pub(super) joined: J,
    /// The rows the answer stands on: the anchor, the snapshot CODE, then
    /// each member row kept, for the run's replay and its send-time release.
    pub(super) rows: Vec<EntityId>,
    /// The CODE the read selected: the portable id's anchor, else the
    /// requested repo.
    pub(super) selected: EntityId,
    /// Whether the read's portable id resolved.
    pub(super) portable_hit: bool,
}

impl<J> RepoReadJoin<'_, J> {
    /// This join's selection of `requested` and `portable`, to join the
    /// same read again.
    pub(super) fn selection<'a>(
        &self,
        requested: &'a RepoTarget,
        portable: Option<&'a RepoPortableId>,
    ) -> RepoReadSelection<'a> {
        RepoReadSelection {
            requested,
            portable,
            selected: self.selected,
            portable_hit: self.portable_hit,
        }
    }
}

/// The repo a run's read names and the one its admission selected: the
/// requested act, the portable id that may select another anchor, and the
/// CODE it resolved to. A join under it refuses a selection that changed.
#[derive(Clone, Copy)]
pub(super) struct RepoReadSelection<'a> {
    requested: &'a RepoTarget,
    portable: Option<&'a RepoPortableId>,
    selected: EntityId,
    portable_hit: bool,
}

impl<'a> RepoReadSelection<'a> {
    /// A read of `target`'s own repo, with no portable id.
    pub(super) fn plain(target: &'a RepoTarget) -> Self {
        Self {
            requested: target,
            portable: None,
            selected: target.repo,
            portable_hit: false,
        }
    }
}

/// What a read join pins outside the store, before its snapshot opens: the
/// act the run was admitted for, the fork its read selects and the commit
/// the act's full ref names now (FIX 4300).
pub(super) struct RepoReadPin<'a> {
    selection: RepoReadSelection<'a>,
    fork_hash: [u8; 32],
    commit: String,
}

/// A file the snapshot does not hold, withholds, or the run may not read.
pub(super) fn file_absent() -> MemoryError {
    MemoryError::not_found("the file is absent or withheld in this snapshot")
}

impl Memory<'_> {
    /// The read join for a run (FIX 4300): admits the run to `target` for a
    /// read, on the anchor `portable` selects when it names a known repo,
    /// then joins `member` under the snapshot `snapshot` names.
    pub(super) fn repo_read_join_for_run<M: RepoReadMember>(
        &self,
        binding: &RepoRunBinding,
        target: &RepoTarget,
        portable: Option<&RepoPortableId>,
        snapshot: &str,
        member: M,
    ) -> MemoryResult<RepoReadJoin<'_, M::Joined>> {
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        let (selected, portable_hit, admission) = self.vault.admit_repo_run_with_portable_in_txn(
            &txn,
            binding,
            target.repo,
            portable,
            &target.git_ref,
            &target.paths,
            RepoAccessIntent::Read,
        )?;
        drop(txn);
        let admitted = admission.map_err(refusal_error)?;
        let selection = RepoReadSelection {
            requested: target,
            portable,
            selected,
            portable_hit,
        };
        self.repo_read_join_under(binding, &admitted, &selection, snapshot, member)
    }

    /// The read join under `admitted`, an admission the caller holds, in a
    /// read snapshot of its own: the pin first, then the run's lane, its
    /// grant clock and its body pins, then the snapshot.
    pub(super) fn repo_read_join_under<M: RepoReadMember>(
        &self,
        binding: &RepoRunBinding,
        admitted: &RepoRunAdmitted,
        selection: &RepoReadSelection<'_>,
        snapshot: &str,
        member: M,
    ) -> MemoryResult<RepoReadJoin<'_, M::Joined>> {
        let pin = self.repo_read_pin(admitted, *selection, snapshot)?;
        let lane = self
            .vault
            .scoped_read(binding.reader.clone())
            .with_claim_status(ClaimReadStatus::Recorded);
        lane.persist_grant_clock()?;
        let _bodies = crate::store::ASSET_FILE_PLANE.then(|| self.vault.pin_all_result_bodies());
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        self.repo_read_join_in_txn(&lane, &txn, binding, admitted, &pin, member)
    }

    /// The fork `snapshot` selects and the commit the admitted repo's full
    /// ref in `selection` names now, read from the repo's own store. No
    /// historical pin: a ref the repo does not name is `WrongRef`.
    pub(super) fn repo_read_pin<'a>(
        &self,
        admitted: &RepoRunAdmitted,
        selection: RepoReadSelection<'a>,
        snapshot: &str,
    ) -> MemoryResult<RepoReadPin<'a>> {
        let fork_hash = parse_fork_hash(snapshot)?;
        let git_ref = &selection.requested.git_ref;
        let Some(commit) = repo_ref_pin(self.vault, &admitted.membership.repo_ref, git_ref) else {
            return Err(refusal_error(RepoAccessRefusal::WrongRef));
        };
        Ok(RepoReadPin {
            selection,
            fork_hash,
            commit: commit.as_str().to_owned(),
        })
    }

    /// The read join in the caller's read snapshot `txn` (FIX 4300). It
    /// admits the run to `pin`'s act again, on the same selected anchor and
    /// under the same lease and repository as `admitted`, selects the
    /// snapshot of the pinned commit
    /// and folder and `member` under it, and reads every row through `lane`,
    /// the run's own read lane, the scope filter last. Prepare `lane`'s
    /// grant clock and the body pins before `txn` opens.
    pub(super) fn repo_read_join_in_txn<M: RepoReadMember>(
        &self,
        lane: &ScopedRead<'_>,
        txn: &heed::RoTxn<'_>,
        binding: &RepoRunBinding,
        admitted: &RepoRunAdmitted,
        pin: &RepoReadPin<'_>,
        member: M,
    ) -> MemoryResult<RepoReadJoin<'_, M::Joined>> {
        let selection = &pin.selection;
        let (selected, portable_hit, admission) = self.vault.admit_repo_run_with_portable_in_txn(
            txn,
            binding,
            selection.requested.repo,
            selection.portable,
            &selection.requested.git_ref,
            &selection.requested.paths,
            RepoAccessIntent::Read,
        )?;
        if selected != selection.selected || portable_hit != selection.portable_hit {
            return Err(Error::ConcurrentWrite("the run's repo read selection changed").into());
        }
        let again = admission.map_err(refusal_error)?;
        if !again.same_lease(admitted) || again.membership.repo_ref != admitted.membership.repo_ref
        {
            return Err(Error::ConcurrentWrite("the run's repo read admission changed").into());
        }
        let Some(mount) = self.pinned_mount_in_txn(txn, &again, &pin.fork_hash, &pin.commit)?
        else {
            return Err(refusal_error(RepoAccessRefusal::WrongRef));
        };
        // The anchor and the snapshot first: the run's lane reads both, and
        // the snapshot's scope holds both, before any member resolves.
        let anchor = again.membership.bounds.repo;
        let artifact = mount.code_artifact_id();
        if !lane_reads_in_txn(lane, txn, &[anchor, artifact])?
            .iter()
            .all(|read| *read)
        {
            return Err(repo_lane_unreadable());
        }
        let pinned = mount.snapshot();
        let in_scope = |id: &EntityId| -> Result<bool> {
            codebase_candidate_matches_scope_key(&self.vault.store, txn, id, &pinned.scope_key)
        };
        if !in_scope(&artifact)? || (pinned.repository == Some(anchor) && !in_scope(&anchor)?) {
            return Err(MemoryError::new(
                MEMORY_CODE_INVALID_STATE,
                "the pinned snapshot is not a member of its repository scope",
                &[],
            ));
        }
        // Then the member: each of its rows the lane reads and the scope
        // holds, in this same snapshot.
        let (joined, members) = member.select(self.vault, txn, &mount, &again)?;
        let read = lane_reads_in_txn(lane, txn, &members)?;
        let kept = members
            .iter()
            .zip(&read)
            .map(|(id, read)| -> Result<bool> { Ok(*read && in_scope(id)?) })
            .collect::<Result<Vec<bool>>>()?;
        let joined = M::keep(joined, &kept)?;
        let mut rows = vec![anchor, artifact];
        rows.extend(
            members
                .iter()
                .zip(&kept)
                .filter_map(|(id, kept)| kept.then_some(*id)),
        );
        Ok(RepoReadJoin {
            admitted: again,
            mount,
            commit: pin.commit.clone(),
            joined,
            rows,
            selected,
            portable_hit,
        })
    }

    /// The snapshot of the fork `fork_hash` at `commit`, of the admitted
    /// folder, that belongs to the admitted anchor or to no anchor, read in
    /// `txn`; `None` when there is none.
    fn pinned_mount_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        admitted: &RepoRunAdmitted,
        fork_hash: &[u8; 32],
        commit: &str,
    ) -> Result<Option<CodebaseSnapshotMount<'_>>> {
        let membership = &admitted.membership;
        for artifact in self
            .vault
            .codebase_snapshots_by_fork_hash_in_txn(txn, fork_hash)?
        {
            let Some(mount) = self.vault.mount_codebase_snapshot_in_txn(txn, &artifact)? else {
                continue;
            };
            let held = mount.snapshot();
            if held.commit_hash.as_deref() == Some(commit)
                && same_folder(&held.repo_ref, &membership.repo_ref)
                && held
                    .repository
                    .is_none_or(|anchor| anchor == membership.bounds.repo)
            {
                return Ok(Some(mount));
            }
        }
        Ok(None)
    }
}

/// Whether `lane` reads each of `ids`, body included, in `txn`, in order.
fn lane_reads_in_txn(
    lane: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    ids: &[EntityId],
) -> Result<Vec<bool>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let points: Vec<_> = ids.iter().copied().map(PointRead::id).collect();
    Ok(lane
        .read_projected_in_txn(txn, &points, None, |_, rows| Ok::<_, Error>(rows))?
        .value
        .iter()
        .map(|row| row.as_ref().is_some_and(|row| row.body.is_some()))
        .collect())
}

/// A snapshot selector: its fork hash in 64 lower-hex characters.
pub(super) fn parse_fork_hash(snapshot: &str) -> MemoryResult<[u8; 32]> {
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
