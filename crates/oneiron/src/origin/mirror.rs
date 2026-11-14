//! Outbound mirror pushing (ARCH-0068 RA8).
//!
//! The owner names one https mirror per served repository: its URL, the
//! custody record holding its push token and a cadence. The repository's
//! origin pushes its published refs, and only those, to the mirror on that
//! cadence, forced, and deletes there the refs it pushed before that are no
//! longer published. The cadence is the repository's real RPO. A host that
//! is not the repository's origin (a mirror, or another host's epoch) never
//! pushes.
//!
//! The token leaves custody only through [`Vault::inject_secret_at_door`]
//! bound to [`ORIGIN_MIRROR_PUSH_EFFECTOR`]. On a served host the ref reads
//! and pushes hand it only to the credential broker, which installs it on
//! each exchange of the host's mirror relay (`git_transport`, FIX 19083), so
//! no Git child holds it; on an embedded vault it reaches git only as the
//! push's `Authorization` header, never config or disk. The Git-LFS upload
//! after a push hands it, on a served host, only to the broker too, which
//! installs it on each LFS batch call (FIX 19876); on an embedded vault the
//! daemon's own LFS client sends it (`publish::mirror_lfs`). Each run that
//! sends LFS objects records which way they went
//! ([`OriginMirrorLfsTransfer`]), apart from any plan batch's isolation.
//!
//! Mirror-main stays read-only. Mirror-side work comes back inbound through
//! the door as `refs/imported/<source>/<branch>`, which the change index
//! stamps `mirror_import`; merges happen at origin and push outward. Imported
//! refs are never pushed back out.
//!
//! Refs pushed are not readiness. A mirror clone must build without this
//! vault (ARCH-0068), and the push sends no Git-LFS bytes, so each run that
//! lands records an [`OriginMirrorReadiness`]: `Ready` only when the pushed
//! refs' whole history names no LFS object, else `NotReady`, naming the
//! objects nothing has verified at the mirror. The census behind it
//! (`mirror_census`) reads histories of any size in pages and never fails or
//! holds back the push.
//!
//! Each mirror carries a sync strategy (FIX 6866, `mirror_strategy`): a
//! `schedule` mirror is pushed on its cadence or by a push-now; a
//! `full_auto` mirror as soon as its published refs move, green heads only
//! (`mirror_auto`). An `ask_me` mirror, the default, sends nothing whole:
//! its push-now refuses with `publish_request_required`, and exact reviewed
//! commits go out through `origin::publish` instead. Every automatic push
//! freezes a reviewed plan before egress, leases each ref on the tip it
//! read and reconciles before any resend (`mirror_run`, `origin::publish`).
//! A mirror whose audience is public or unstated never takes history that
//! holds a marked live key (FIX 7608 slice 9, `secret_publication`).

use super::mirror_census::LfsCensus;
use super::mirror_run::{MirrorPass, MirrorTrigger};
use super::mirror_strategy::{
    OriginMirrorSyncStrategy, PublishRequestRequired, configured_strategy,
};
use super::publication::OriginPublicationStatus;
use super::residence::OriginHostAuthority;
use super::secret_publication::{RepoDestinationVisibility, configured_audience};
use super::smart_http::origin_repo_dir;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::{GitOid, GitRefName, GitWire, GitWireRepo};
use crate::side_table::{self, Named, SideTable};
use crate::store::code_snapshot::RepoRef;

/// The effector a mirror's push token is bound to in custody.
pub const ORIGIN_MIRROR_PUSH_EFFECTOR: &str = "origin:mirror-push";

/// The shortest cadence the owner may set, in seconds: the lifecycle tick.
pub const ORIGIN_MIRROR_MIN_EVERY_SECS: u64 = 60;

/// The basic-auth user a token goes with when the owner names none.
pub const ORIGIN_MIRROR_DEFAULT_USER: &str = "x-access-token";

/// Refs that came in from a mirror; they never go back out.
pub const ORIGIN_MIRROR_IMPORTED_PREFIX: &str = "refs/imported/";

/// The Git-LFS objects a not-ready run names; the census counts the rest and
/// still reads every one.
pub const ORIGIN_MIRROR_NAMED_LFS_OBJECTS: usize = 8;

/// The door that pushes a served repository to its mirror now.
const MIRROR_PUSH_VERB: &str = "vault.code.origin.mirror.push";
const MAX_URL_BYTES: usize = 2048;
const MAX_USER_BYTES: usize = 128;

/// One repository's mirror. Key: repo id.
pub(super) const TARGETS: SideTable<EntityId, OriginMirrorTarget, Named> =
    SideTable::new(&side_table::ORIGIN_MIRROR_TARGET);

#[doc(hidden)]
pub use oneiron_verb_wire::origin::mirror::{
    OriginMirrorLfsObject, OriginMirrorLfsRoute, OriginMirrorLfsTransfer,
    OriginMirrorNotReadyReason, OriginMirrorReadiness, OriginMirrorRun, OriginMirrorTarget,
};

/// What the owner sets.
#[derive(Debug, Clone)]
pub struct OriginMirrorTargetInput {
    /// The mirror's https URL.
    pub url: String,
    /// The custody record of the push token, bound to
    /// [`ORIGIN_MIRROR_PUSH_EFFECTOR`].
    pub secret_ref: String,
    /// [`ORIGIN_MIRROR_DEFAULT_USER`] when absent.
    pub user: Option<String>,
    /// Seconds between pushes, at least [`ORIGIN_MIRROR_MIN_EVERY_SECS`].
    pub every_secs: u64,
    /// The strategy; when absent the same URL keeps its own and a new one
    /// starts at `ask_me`.
    pub sync_strategy: Option<OriginMirrorSyncStrategy>,
    /// Who can read the mirror, as the owner states it; when absent the
    /// same URL keeps its own and a new one is `unknown`, held as public.
    pub visibility: Option<RepoDestinationVisibility>,
}

/// What one scheduled pass over the mirror targets did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct OriginMirrorPushes {
    /// Targets configured.
    pub targets: u64,
    /// Pushes that landed.
    pub pushed: u64,
    /// Targets not due, not this host's to push, or left for the next pass.
    pub skipped: u64,
    /// Pushes that failed; each target's row names its cause.
    pub failed: u64,
}

/// What a push that landed records on its run.
struct MirrorRunLanded {
    refs: u64,
    deleted: u64,
    readiness: OriginMirrorReadiness,
    lfs_transfer: Option<OriginMirrorLfsTransfer>,
}

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

    /// Pushes now as the caller's owner proof, rechecked when its run is written.
    ///
    /// The push checks in first (2k9b; P25-SHAPE Q1 = A): it goes on the
    /// Owner's own proof, and with `check_in_ref` the Owner applies an
    /// asker's approved check-in for this repository's push
    /// ([`crate::check_in::origin_mirror_push_effect_digest`]). The ask is
    /// spent in a writer of its own on the Owner's live proof before anything
    /// leaves, as the custody doors spend theirs (2k3): a push that then
    /// fails, or finds the mirror changed, leaves it spent, and the Owner
    /// pushes again on their own proof. The run answers the decision; the
    /// run the target keeps does not carry it.
    ///
    /// # Errors
    ///
    /// No such repository or mirror; an `ask_me` mirror; a host that is not
    /// the repository's origin; the Owner's proof no longer holds; a
    /// check-in that does not apply; the mirror changed before its push.
    pub fn push_served_origin_mirror_as_owner(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        repo_name: &str,
        check_in_ref: Option<&EntityId>,
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
        let applied = check_in_ref.map(|id| crate::check_in::AppliedCheckIn {
            id: *id,
            verb: MIRROR_PUSH_VERB,
            effect_digest: crate::check_in::origin_mirror_push_effect_digest(repo_name),
        });
        let decision = crate::check_in::owner_act_decision_in_own_writer(
            self,
            owner,
            crate::check_in::ActClass::OutboundSend,
            applied.as_ref(),
        )?;
        let run = self
            .attempt_mirror_target(repo_id, &target, MirrorTrigger::PushNow(Some(actor)))
            .ok_or(Error::ConcurrentWrite("the mirror changed before its push"))?;
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        self.record_mirror_run_in_txn(&mut txn, repo_id, &target.url, &run)?;
        txn.commit()?;
        Ok(OriginMirrorRun {
            check_in: Some(decision),
            ..run
        })
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
            Ok(Some(landed)) => OriginMirrorRun {
                at,
                refs: landed.refs,
                deleted: landed.deleted,
                failure: None,
                readiness: Some(landed.readiness),
                lfs_transfer: landed.lfs_transfer,
                check_in: None,
            },
            Err(error) => OriginMirrorRun {
                at,
                refs: 0,
                deleted: 0,
                failure: Some(error.to_string()),
                readiness: None,
                lfs_transfer: None,
                check_in: None,
            },
        })
    }

    /// The push itself, through a reviewed plan (`mirror_run`); `None` when
    /// the run had nothing to record.
    fn push_mirror_once(
        &self,
        repo_id: EntityId,
        target: &OriginMirrorTarget,
        trigger: MirrorTrigger,
    ) -> Result<Option<MirrorRunLanded>> {
        require_plain_mirror_url(&target.url)?;
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
            return Ok(Some(MirrorRunLanded {
                refs: 0,
                deleted: 0,
                readiness,
                lfs_transfer: None,
            }));
        };
        let Some(done) = self.run_mirror_whole_refs(&wire, &handle, repo_id, target, trigger)?
        else {
            return Ok(None);
        };
        let (readiness, lfs_transfer) =
            self.mirror_lfs_readiness(&wire, &handle, target, repo_id, &done.census);
        Ok(Some(MirrorRunLanded {
            refs: done.refs,
            deleted: done.deleted,
            readiness,
            lfs_transfer,
        }))
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

/// Refuses a whole-ref push of a mirror whose strategy asks first.
fn require_whole_ref_strategy(repo_name: &str, target: &OriginMirrorTarget) -> Result<()> {
    if target.sync_strategy.pushes_whole_refs() {
        return Ok(());
    }
    Err(PublishRequestRequired {
        repo: repo_name.to_owned(),
        strategy: target.sync_strategy,
    }
    .into())
}

/// An https URL with a host, and no credential, query, fragment, space or
/// control byte, whose path is plain segments ([`require_plain_mirror_url`]).
fn validate_mirror_url(url: &str) -> Result<()> {
    let Some(rest) = url.strip_prefix("https://") else {
        return Err(invalid("mirror URL must be https"));
    };
    let host = rest.split('/').next().unwrap_or("");
    if url.len() > MAX_URL_BYTES
        || host.is_empty()
        || host.contains('@')
        || rest.len() == host.len()
        || url
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '?' | '#' | '\\'))
    {
        return Err(invalid(
            "mirror URL must name a host and a path, with no credential, query or fragment",
        ));
    }
    require_plain_mirror_url(url)
}

/// The code a mirror URL the credential broker sends to no repository at is
/// refused under: at setup, and on every run or publish of a mirror set up
/// before the rule (FIX 20091). A served host's mirror relay names the same
/// code.
pub const MIRROR_URL_MALFORMED: &str = "mirror_url_malformed";

/// Refuses a mirror URL the credential broker sends to no repository at: one
/// [`broker_repository`] does not read as plain, such as a path that is `/`
/// alone or that holds an empty, `.` or `..` segment once the URL parser has
/// normalized it (`/%2e` included). A served host's mirror git goes only
/// through the broker, so one URL rule holds on every host: such a mirror is
/// refused at setup, and one already set up reports misconfigured under
/// [`MIRROR_URL_MALFORMED`] on each run and publish, served or embedded,
/// before any request goes out (FIX 20091).
///
/// # Errors
/// [`Error::Refused`] naming [`MIRROR_URL_MALFORMED`].
pub(crate) fn require_plain_mirror_url(url: &str) -> Result<()> {
    if broker_repository(url) {
        return Ok(());
    }
    Err(Error::Refused(format!(
        "{MIRROR_URL_MALFORMED}: a mirror URL must be a plain https repository: a host with no \
         credential, no query or fragment, and a path of segments that are neither empty, '.' \
         nor '..' once normalized, and not '/' alone"
    )))
}

/// Whether the credential broker reads `url` as a repository, by its own
/// rule (oneiron-broker `GitRepository::parse` and `check`), read the same
/// way here: an `https` origin with a host and no credential that serializes
/// back to itself, no query or fragment, and a path, as the URL parser
/// normalizes it and with its trailing slashes trimmed, of non-empty
/// segments, none `.` or `..`, that joins back onto the origin unchanged.
fn broker_repository(url: &str) -> bool {
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return false;
    };
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.host().is_none()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return false;
    }
    let origin = parsed.origin().ascii_serialization();
    let Ok(base) = reqwest::Url::parse(&origin) else {
        return false;
    };
    if base.scheme() != "https"
        || !base.username().is_empty()
        || base.password().is_some()
        || base.host().is_none()
        || base.origin().ascii_serialization() != origin
    {
        return false;
    }
    let path = parsed.path().trim_end_matches('/');
    let plain = !path.contains(['?', '#'])
        && path.strip_prefix('/').is_some_and(|segments| {
            segments
                .split('/')
                .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
        });
    // The broker joins the path back onto its origin and takes it only when
    // both come back unchanged.
    plain
        && reqwest::Url::parse(&format!("{origin}{path}"))
            .is_ok_and(|joined| joined.origin() == base.origin() && joined.path() == path)
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}
