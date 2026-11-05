//! Core half of `origin::mirror`: its store-layer items live in `oneiron_store::origin::mirror` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::origin::mirror::*;

use super::mirror_auto::OriginMirrorAutomation;
use super::mirror_census::LfsCensus;
use super::mirror_run::{MirrorPass, MirrorTrigger};
use super::mirror_strategy::{
    OriginMirrorSyncStrategy, PublishRequestRequired, configured_strategy,
};
use super::publication::OriginPublicationStatus;
use super::residence::OriginHostAuthority;
use super::secret_publication::{
    RepoDestinationAudience, RepoDestinationVisibility, configured_audience,
};
use super::smart_http::origin_repo_dir;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::{GitOid, GitRefName, GitWire, GitWireRepo};
use crate::side_table::{self, Named, SideTable};
use crate::store::code_snapshot::RepoRef;
use serde::{Deserialize, Serialize};

/// One repository's mirror. Key: repo id.
pub(super) const TARGETS: SideTable<EntityId, OriginMirrorTarget, Named> =
    SideTable::new(&side_table::ORIGIN_MIRROR_TARGET);

impl Vault {
    /// Sets the mirror of a served repository. The token must already be in
    /// custody, bound to [`ORIGIN_MIRROR_PUSH_EFFECTOR`]: the door is asked
    /// now, so a target it would refuse is refused here. A new URL starts
    /// with nothing pushed; the same URL keeps its history.
    pub fn set_served_origin_mirror(
        &self,
        repo_name: &str,
        input: OriginMirrorTargetInput,
    ) -> Result<OriginMirrorTarget> {
        let mut txn = self.store.env.write_txn()?;
        let row = self.set_served_origin_mirror_in_txn(&mut txn, repo_name, input)?;
        txn.commit()?;
        self.wake_origin_mirrors();
        Ok(row)
    }

    /// [`Self::set_served_origin_mirror`] as the caller's owner proof,
    /// revalidated in the transaction that installs the target (FIX 8214).
    pub fn set_served_origin_mirror_as_owner(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        repo_name: &str,
        input: OriginMirrorTargetInput,
    ) -> Result<OriginMirrorTarget> {
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let row = self.set_served_origin_mirror_in_txn(&mut txn, repo_name, input)?;
        txn.commit()?;
        self.wake_origin_mirrors();
        Ok(row)
    }

    /// The shared setter, checked in the transaction that installs the target.
    pub(crate) fn set_served_origin_mirror_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        repo_name: &str,
        input: OriginMirrorTargetInput,
    ) -> Result<OriginMirrorTarget> {
        let user = input
            .user
            .unwrap_or_else(|| ORIGIN_MIRROR_DEFAULT_USER.to_owned());
        validate_mirror_url(&input.url)?;
        if user.is_empty()
            || user.len() > MAX_USER_BYTES
            || user.contains(':')
            || user.chars().any(char::is_control)
        {
            return Err(invalid("mirror user must be a short name with no ':'"));
        }
        if input.every_secs < ORIGIN_MIRROR_MIN_EVERY_SECS {
            return Err(invalid("mirror cadence is shorter than one minute"));
        }
        self.check_secret_at_door_in_txn(txn, &input.secret_ref, ORIGIN_MIRROR_PUSH_EFFECTOR)?;
        let repo_id = self.served_mirror_repo_id(repo_name)?;
        let previous = TARGETS.get(&self.store, txn, &repo_id)?;
        let configured = configured_strategy(
            previous.as_ref(),
            repo_name,
            (&input.url, &user, &input.secret_ref),
            input.sync_strategy,
        );
        let moved = previous.as_ref().is_some_and(|row| {
            row.strategy_revision != configured.revision
                || row.target_generation != configured.generation
        });
        let audience = configured_audience(input.visibility, previous.as_ref(), &input.url);
        let (last, pushed, automation) = match previous {
            Some(row) if row.url == input.url => (row.last, row.pushed, row.automation),
            _ => (None, Vec::new(), None),
        };
        let row = OriginMirrorTarget {
            repo: repo_name.to_owned(),
            url: input.url,
            secret_ref: input.secret_ref,
            user,
            every_secs: input.every_secs,
            last,
            pushed,
            sync_strategy: configured.strategy,
            strategy_revision: configured.revision,
            target_generation: configured.generation,
            automation,
            audience,
        };
        TARGETS.put(&self.store, txn, &repo_id, &row)?;
        if moved {
            self.pause_mirror_work_on_change_in_txn(txn, repo_id, false);
        }
        Ok(row)
    }

    /// The mirror of a served repository, if the owner set one.
    pub fn served_origin_mirror(&self, repo_name: &str) -> Result<Option<OriginMirrorTarget>> {
        let repo_id = self.served_mirror_repo_id(repo_name)?;
        let txn = self.store.env.read_txn()?;
        TARGETS.get(&self.store, &txn, &repo_id)
    }

    /// Stops mirroring a served repository. The mirror keeps what it has.
    /// `true` when a target was set.
    pub fn clear_served_origin_mirror(&self, repo_name: &str) -> Result<bool> {
        let mut txn = self.store.env.write_txn()?;
        let removed = self.clear_served_origin_mirror_in_txn(&mut txn, repo_name)?;
        txn.commit()?;
        Ok(removed)
    }

    /// [`Self::clear_served_origin_mirror`] as the caller's owner proof,
    /// revalidated in the transaction that removes the target (FIX 8214).
    pub fn clear_served_origin_mirror_as_owner(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        repo_name: &str,
    ) -> Result<bool> {
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let removed = self.clear_served_origin_mirror_in_txn(&mut txn, repo_name)?;
        txn.commit()?;
        Ok(removed)
    }

    pub(crate) fn clear_served_origin_mirror_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        repo_name: &str,
    ) -> Result<bool> {
        let repo_id = self.served_mirror_repo_id(repo_name)?;
        self.clear_mirror_lfs_census_in_txn(txn, &repo_id)?;
        self.pause_mirror_work_on_change_in_txn(txn, repo_id, true);
        TARGETS.delete(&self.store, txn, &repo_id)
    }

    /// Pushes a served repository to its mirror now, due or not, as the
    /// owner asked. Returns the run it recorded.
    pub fn push_served_origin_mirror(&self, repo_name: &str) -> Result<OriginMirrorRun> {
        let repo_id = self.served_mirror_repo_id(repo_name)?;
        let target = {
            let txn = self.store.env.read_txn()?;
            TARGETS.get(&self.store, &txn, &repo_id)?
        }
        .ok_or(Error::EntityNotFound)?;
        require_whole_ref_strategy(repo_name, &target)?;
        self.require_mirror_pusher(repo_name)?;
        self.run_mirror_target(repo_id, &target, MirrorTrigger::PushNow(None))
            .ok_or(Error::ConcurrentWrite("the mirror changed before its push"))
    }

    /// Pushes now as the caller's owner proof, rechecked when its run is written.
    pub fn push_served_origin_mirror_as_owner(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        repo_name: &str,
    ) -> Result<OriginMirrorRun> {
        let repo_id = self.served_mirror_repo_id(repo_name)?;
        let (actor, target) = {
            let txn = self.store.env.read_txn()?;
            let actor = owner.revalidate_in_txn(self, &txn)?;
            (actor, TARGETS.get(&self.store, &txn, &repo_id)?)
        };
        let target = target.ok_or(Error::EntityNotFound)?;
        require_whole_ref_strategy(repo_name, &target)?;
        self.require_mirror_pusher(repo_name)?;
        let run = self
            .attempt_mirror_target(repo_id, &target, MirrorTrigger::PushNow(Some(actor)))
            .ok_or(Error::ConcurrentWrite("the mirror changed before its push"))?;
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        self.record_mirror_run_in_txn(&mut txn, repo_id, &target.url, &run)?;
        txn.commit()?;
        Ok(run)
    }

    /// One pass over every mirror target: each `schedule` mirror that is
    /// due, each `full_auto` mirror and each open plan, of a repository this
    /// host is the origin of. An `ask_me` mirror is never due; one switched
    /// with a plan open only settles it. `admit` takes the
    /// host's hold for one push, or returns `None` when it has none to give;
    /// `stop` asks the pass to start no further push.
    pub fn push_due_origin_mirrors(
        &self,
        admit: impl FnMut() -> Option<Box<dyn Send>>,
        stop: impl Fn() -> bool,
    ) -> Result<OriginMirrorPushes> {
        self.push_origin_mirrors(MirrorPass::Tick, admit, stop)
    }

    /// The pass a wake starts (FIX 6866): each `full_auto` mirror and each
    /// open plan, at once; no cadence is read and no other job runs.
    pub fn push_woken_origin_mirrors(
        &self,
        admit: impl FnMut() -> Option<Box<dyn Send>>,
        stop: impl Fn() -> bool,
    ) -> Result<OriginMirrorPushes> {
        self.push_origin_mirrors(MirrorPass::Wake, admit, stop)
    }

    /// Refuses unless this host is the repository's origin: no authority row
    /// (this vault alone serves it) or this host's held epoch.
    pub(super) fn require_mirror_pusher(&self, repo_name: &str) -> Result<()> {
        match self.origin_host_authority(repo_name)? {
            OriginHostAuthority::Unconfigured | OriginHostAuthority::Held(_) => Ok(()),
            OriginHostAuthority::Mirror(_)
            | OriginHostAuthority::Elsewhere(_)
            | OriginHostAuthority::WriterErased(_) => Err(Error::ConcurrentWrite(
                "only the repository's origin pushes its mirror",
            )),
        }
    }

    pub(super) fn served_mirror_repo_id(&self, repo_name: &str) -> Result<EntityId> {
        let repo_root = origin_repo_dir(self, repo_name)?;
        let identity = GitWire::new(self)?.repository_identity(&repo_root)?;
        super::lfs::lfs_repo_id(&identity.as_hex())
    }

    /// Runs one target and records the run on its row. A failure is the
    /// row's to carry, never the caller's: the next pass tries again.
    /// `None` when the run had nothing to record (module `mirror_run`). The
    /// names the mirror holds went on the row under the run's hold already.
    pub(super) fn run_mirror_target(
        &self,
        repo_id: EntityId,
        target: &OriginMirrorTarget,
        trigger: MirrorTrigger,
    ) -> Option<OriginMirrorRun> {
        let run = self.attempt_mirror_target(repo_id, target, trigger)?;
        if let Err(error) = self.record_mirror_run(repo_id, &target.url, &run) {
            tracing::warn!(kind = ?error.kind(), "mirror push run was not recorded");
        }
        Some(run)
    }

    fn attempt_mirror_target(
        &self,
        repo_id: EntityId,
        target: &OriginMirrorTarget,
        trigger: MirrorTrigger,
    ) -> Option<OriginMirrorRun> {
        let attempt = self.push_mirror_once(repo_id, target, trigger);
        let at = self.now_recorded_at();
        Some(match attempt {
            Ok(None) => return None,
            Ok(Some((refs, deleted, readiness))) => OriginMirrorRun {
                at,
                refs,
                deleted,
                failure: None,
                readiness: Some(readiness),
            },
            Err(error) => OriginMirrorRun {
                at,
                refs: 0,
                deleted: 0,
                failure: Some(error.to_string()),
                readiness: None,
            },
        })
    }

    /// The push itself: `(refs, deleted, its readiness)`, through a reviewed
    /// plan (`mirror_run`); `None` when the run had nothing to record.
    fn push_mirror_once(
        &self,
        repo_id: EntityId,
        target: &OriginMirrorTarget,
        trigger: MirrorTrigger,
    ) -> Result<Option<(u64, u64, OriginMirrorReadiness)>> {
        let repo_root = origin_repo_dir(self, &target.repo)?;
        let wire = GitWire::new(self)?;
        let Some(handle) = self.mirror_handle(&wire, repo_id, &repo_root)? else {
            if !trigger.records_idle(target.sync_strategy) {
                return Ok(None);
            }
            // No commit to pin a handle to, not even a deleted tip: the
            // mirror has nothing to take, and keeps what it holds until there
            // is one. Nothing walked what it holds, so only a mirror holding
            // none is ready.
            let readiness = LfsCensus::default().readiness(target.pushed.is_empty());
            return Ok(Some((0, 0, readiness)));
        };
        let Some(done) = self.run_mirror_whole_refs(&wire, &handle, repo_id, target, trigger)?
        else {
            return Ok(None);
        };
        let readiness = self.mirror_lfs_readiness(&wire, &handle, target, repo_id, &done.census);
        Ok(Some((done.refs, done.deleted, readiness)))
    }

    /// What a whole-ref plan starts from, read under the mirror's push hold
    /// (`mirror_run`): every published ref but the imported ones, and the
    /// deletions the names the mirror row says it took call for. `None`
    /// when the row is gone: nothing is planned for a cleared mirror.
    pub(super) fn mirror_published_basis(
        &self,
        wire: &GitWire<'_>,
        handle: &GitWireRepo,
        repo_id: EntityId,
    ) -> Result<Option<(Vec<(GitRefName, GitOid)>, Vec<GitRefName>)>> {
        let target = {
            let txn = self.store.env.read_txn()?;
            TARGETS.get(&self.store, &txn, &repo_id)?
        };
        let Some(target) = target else {
            return Ok(None);
        };
        let refs: Vec<(GitRefName, GitOid)> = self
            .published_origin_refs_without_waiting(wire, repo_id, handle)?
            .into_iter()
            .filter(|(name, _)| !name.as_str().starts_with(ORIGIN_MIRROR_IMPORTED_PREFIX))
            .collect();
        let deletions = target
            .pushed
            .iter()
            .filter(|old| !refs.iter().any(|(name, _)| name.as_str() == old.as_str()))
            .map(|old| GitRefName::parse_full(old.clone()))
            .collect::<Result<Vec<_>>>()?;
        Ok(Some((refs, deletions)))
    }

    /// A proven handle on the served repository, pinned to a commit one of
    /// its publications names: a published tip, else, once every ref was
    /// deleted, the tip a deletion moved from while the store still holds
    /// it, so the deletions reach the mirror with no later publication (FIX
    /// 920). `None` while it has neither.
    pub(super) fn mirror_handle(
        &self,
        wire: &GitWire<'_>,
        repo_id: EntityId,
        repo_root: &std::path::Path,
    ) -> Result<Option<GitWireRepo>> {
        let open = |commit: &GitOid| {
            let repo_ref = RepoRef::LocalFolder {
                path: repo_root.to_string_lossy().into_owned(),
                commit: commit.as_str().to_owned(),
            };
            wire.open_repo(repo_ref, repo_root).ok()
        };
        let mut moved_from = Vec::new();
        for publication_id in self.origin_visible_ref_rows(&repo_id)? {
            let Some(record) = self.origin_publication(publication_id)? else {
                continue;
            };
            if record.repo_id != repo_id || record.status != OriginPublicationStatus::Published {
                continue;
            }
            // A deleted ref's slot or an annotated tag pins no commit; the
            // next publication may.
            if let Some(handle) = open(&record.new_oid) {
                return Ok(Some(handle));
            }
            moved_from.extend(record.expected_old_oid);
        }
        Ok(moved_from.iter().find_map(open))
    }

    /// Writes a run onto its target. A target the owner re-pointed or cleared
    /// meanwhile keeps the owner's row.
    fn record_mirror_run(&self, repo_id: EntityId, url: &str, run: &OriginMirrorRun) -> Result<()> {
        let mut txn = self.store.env.write_txn()?;
        self.record_mirror_run_in_txn(&mut txn, repo_id, url, run)?;
        txn.commit()?;
        Ok(())
    }

    fn record_mirror_run_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        repo_id: EntityId,
        url: &str,
        run: &OriginMirrorRun,
    ) -> Result<()> {
        let Some(mut row) = TARGETS.get(&self.store, txn, &repo_id)? else {
            return Ok(());
        };
        if row.url != url {
            return Ok(());
        }
        row.last = Some(run.clone());
        TARGETS.put(&self.store, txn, &repo_id, &row)?;
        Ok(())
    }
}
