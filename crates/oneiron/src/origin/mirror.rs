//! Outbound mirror pushing (ARCH-0068 RA8).
//!
//! The owner names one https mirror per served repository: its URL, the
//! custody record holding its push token and a cadence. That choice is the
//! catalogue key `origin.mirror` at the repository's scope (DESIGN
//! 15-setting-primitive stage 4); what the mirror has done since (its served
//! name, last run, pushed refs, strategy revision, target generation and
//! automation) is the state row beside it. The repository's
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

use super::mirror_auto::OriginMirrorAutomation;
use super::mirror_census::LfsCensus;
use super::mirror_run::{MirrorPass, MirrorTrigger};
use super::mirror_strategy::{
    OriginMirrorSyncStrategy, PublishRequestRequired, configured_strategy,
};
use super::publication::OriginPublicationStatus;
use super::residence::OriginHostAuthority;
use super::secret_publication::{RepoDestinationAudience, RepoDestinationVisibility};
use super::setting_keys::MIRROR;
use super::smart_http::{ORIGIN_REPO_DIR_SUFFIX, origin_repo_dir, origin_serving_root};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::{GitOid, GitRefName, GitWire, GitWireRepo};
use crate::side_table::{self, Named, SideTable};
use crate::store::code_snapshot::RepoRef;
use serde::{Deserialize, Serialize};

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

const MAX_URL_BYTES: usize = 2048;
const MAX_USER_BYTES: usize = 128;

/// What one repository's mirror has done. Key: repo id. A row stands while
/// the owner's `origin.mirror` names a setup at the repository's scope: the
/// key's hook writes it and removes it.
pub(super) const STATES: SideTable<EntityId, OriginMirrorState, Named> =
    SideTable::new(&side_table::ORIGIN_MIRROR_STATE);

#[doc(hidden)]
pub use oneiron_verb_wire::origin::mirror::{
    OriginMirrorLfsObject, OriginMirrorLfsRoute, OriginMirrorLfsTransfer,
    OriginMirrorNotReadyReason, OriginMirrorReadiness, OriginMirrorRun, OriginMirrorTarget,
};

/// The owner's choice of one served repository's outbound mirror: the value
/// of the catalogue key `origin.mirror` at the repository's scope. The token
/// stays in custody, bound to [`ORIGIN_MIRROR_PUSH_EFFECTOR`]; the setting
/// holds only its custody name, which the key's hook checks in the write that
/// sets it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OriginMirrorSetup {
    /// The mirror's https URL, with no credential, query or fragment.
    pub url: String,
    /// The custody record of the push token.
    pub secret_ref: String,
    /// The basic-auth user the token goes with; [`ORIGIN_MIRROR_DEFAULT_USER`]
    /// when absent.
    #[serde(default = "default_mirror_user")]
    pub user: String,
    /// Seconds between pushes, at least [`ORIGIN_MIRROR_MIN_EVERY_SECS`]: the
    /// repository's real RPO.
    pub every_secs: u64,
    /// How the mirror sends what this vault publishes; `ask_me` when absent.
    #[serde(default)]
    pub sync_strategy: OriginMirrorSyncStrategy,
    /// Who can read the mirror, as the owner states it; `unknown` when
    /// absent, held as public. A public or unknown mirror never takes history
    /// that holds a marked live key.
    #[serde(default = "unknown_visibility")]
    pub visibility: RepoDestinationVisibility,
}

impl crate::setting::SettingValue for OriginMirrorSetup {
    fn check(self) -> Result<Self> {
        validate_mirror_url(&self.url)?;
        if self.user.is_empty()
            || self.user.len() > MAX_USER_BYTES
            || self.user.contains(':')
            || self.user.chars().any(char::is_control)
        {
            return Err(invalid("mirror user must be a short name with no ':'"));
        }
        if self.every_secs < ORIGIN_MIRROR_MIN_EVERY_SECS {
            return Err(invalid("mirror cadence is shorter than one minute"));
        }
        if self.secret_ref.is_empty() || self.secret_ref.chars().any(char::is_control) {
            return Err(invalid("mirror secret_ref must name a custody record"));
        }
        Ok(self)
    }
}

fn default_mirror_user() -> String {
    ORIGIN_MIRROR_DEFAULT_USER.to_owned()
}

const fn unknown_visibility() -> RepoDestinationVisibility {
    RepoDestinationVisibility::Unknown
}

/// What one repository's mirror has done, apart from the owner's setup: the
/// served name it was set under, its last run, the refs it took, its
/// strategy's revision, its target's generation and the automatic pushes'
/// status ([`OriginMirrorTarget`] documents each).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OriginMirrorState {
    pub(super) repo: String,
    pub(super) last: Option<OriginMirrorRun>,
    pub(super) pushed: Vec<String>,
    pub(super) strategy_revision: u64,
    pub(super) target_generation: Option<EntityId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) automation: Option<OriginMirrorAutomation>,
}

/// The mirror as its readers see it: the owner's setup with its state.
fn joined_target(setup: OriginMirrorSetup, state: OriginMirrorState) -> OriginMirrorTarget {
    OriginMirrorTarget {
        repo: state.repo,
        url: setup.url,
        secret_ref: setup.secret_ref,
        user: setup.user,
        every_secs: setup.every_secs,
        last: state.last,
        pushed: state.pushed,
        sync_strategy: setup.sync_strategy,
        strategy_revision: state.strategy_revision,
        target_generation: state.target_generation,
        automation: state.automation,
        audience: RepoDestinationAudience::mirror(setup.visibility),
    }
}

/// Writes the state half of `target`, read through
/// [`Vault::mirror_target_in_txn`] and changed, back to its row.
pub(super) fn put_mirror_state_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    repo_id: EntityId,
    target: &OriginMirrorTarget,
) -> Result<()> {
    let state = OriginMirrorState {
        repo: target.repo.clone(),
        last: target.last.clone(),
        pushed: target.pushed.clone(),
        strategy_revision: target.strategy_revision,
        target_generation: target.target_generation,
        automation: target.automation.clone(),
    };
    STATES.put(&vault.store, txn, &repo_id, &state)
}

/// The hook of `origin.mirror`, in the write that changes it: what the old
/// setter did beside the row. A setup's custody record must already be bound
/// to [`ORIGIN_MIRROR_PUSH_EFFECTOR`], or the write fails. The state row takes
/// the served name, a fresh generation when the URL, user, custody record or
/// served name moves, the strategy's revision moved by one when the strategy
/// does, and the history only for the same URL; moved work pauses. A clear
/// drops the state row and the LFS census and stops the work. A row at any
/// scope but a repository's is refused: a mirror is per repository.
///
/// # Errors
/// That refusal, the custody refusal, a repository id no served repository
/// has, or a store failure.
pub(crate) fn mirror_setup_changed_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    change: &crate::setting::SettingChange,
) -> Result<()> {
    let crate::setting::SettingScope::Repo(repo_id) = change.scope else {
        return Err(invalid(
            "origin.mirror is set per served repository: name the repository's scope",
        ));
    };
    let decode = |value: Option<&crate::setting::EncodedValue>| {
        value
            .and_then(crate::setting::Kind::<Option<OriginMirrorSetup>>::decode)
            .flatten()
    };
    let Some(setup) = decode(change.value.as_ref()) else {
        vault.clear_mirror_lfs_census_in_txn(txn, &repo_id)?;
        vault.pause_mirror_work_on_change_in_txn(txn, repo_id, true);
        STATES.delete(&vault.store, txn, &repo_id)?;
        return Ok(());
    };
    vault.check_secret_at_door_in_txn(txn, &setup.secret_ref, ORIGIN_MIRROR_PUSH_EFFECTOR)?;
    let repo = vault.served_origin_name(repo_id)?;
    let prior = decode(change.prior.as_ref());
    let state = STATES.get(&vault.store, txn, &repo_id)?;
    let configured = configured_strategy(prior.as_ref().zip(state.as_ref()), &repo, &setup);
    let moved = state.as_ref().is_some_and(|row| {
        row.strategy_revision != configured.revision
            || row.target_generation != configured.generation
    });
    let (last, pushed, automation) = match (prior, state) {
        (Some(prior), Some(row)) if prior.url == setup.url => {
            (row.last, row.pushed, row.automation)
        }
        _ => (None, Vec::new(), None),
    };
    let row = OriginMirrorState {
        repo,
        last,
        pushed,
        strategy_revision: configured.revision,
        target_generation: configured.generation,
        automation,
    };
    STATES.put(&vault.store, txn, &repo_id, &row)?;
    if moved {
        vault.pause_mirror_work_on_change_in_txn(txn, repo_id, false);
    }
    // A full-auto mirror plans its published state at once; a wake before
    // this write commits finds it on the next pass.
    vault.wake_origin_mirrors();
    Ok(())
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
    /// The mirror of `repo_id` as its readers see it: the owner's setup at
    /// the repository's scope with its state row; `None` when no setup
    /// stands.
    ///
    /// # Errors
    /// A row that does not decode, or a store failure.
    pub(super) fn mirror_target_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        repo_id: EntityId,
    ) -> Result<Option<OriginMirrorTarget>> {
        let Some(state) = STATES.get(&self.store, txn, &repo_id)? else {
            return Ok(None);
        };
        let setup = MIRROR
            .read_in_txn(
                self,
                txn,
                &[crate::setting::SettingScope::Repo(repo_id)],
                None,
            )?
            .value;
        Ok(setup.map(|setup| joined_target(setup, state)))
    }

    /// Every repository's mirror that has a setup, by repo id.
    ///
    /// # Errors
    /// A row that does not decode, or a store failure.
    pub(super) fn mirror_targets_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Vec<(EntityId, OriginMirrorTarget)>> {
        let mut targets = Vec::new();
        for (repo_id, state) in STATES.scan(&self.store, txn)? {
            let setup = MIRROR
                .read_in_txn(
                    self,
                    txn,
                    &[crate::setting::SettingScope::Repo(repo_id)],
                    None,
                )?
                .value;
            if let Some(setup) = setup {
                targets.push((repo_id, joined_target(setup, state)));
            }
        }
        Ok(targets)
    }

    /// The served name of the repository whose id is `repo_id`.
    ///
    /// # Errors
    /// `EntityNotFound` when no served repository has it; a serving root or
    /// repository that cannot be read.
    fn served_origin_name(&self, repo_id: EntityId) -> Result<String> {
        for entry in std::fs::read_dir(origin_serving_root(self)?)? {
            let file_name = entry?.file_name();
            let Some(name) = file_name
                .to_str()
                .and_then(|name| name.strip_suffix(ORIGIN_REPO_DIR_SUFFIX))
            else {
                continue;
            };
            if self.served_mirror_repo_id(name).ok() == Some(repo_id) {
                return Ok(name.to_owned());
            }
        }
        Err(Error::EntityNotFound)
    }

    /// The mirror of a served repository, if the owner set one.
    pub fn served_origin_mirror(&self, repo_name: &str) -> Result<Option<OriginMirrorTarget>> {
        let repo_id = self.served_mirror_repo_id(repo_name)?;
        let txn = self.store.env.read_txn()?;
        self.mirror_target_in_txn(&txn, repo_id)
    }

    /// Pushes a served repository to its mirror now, due or not, as the
    /// owner asked. Returns the run it recorded.
    pub fn push_served_origin_mirror(&self, repo_name: &str) -> Result<OriginMirrorRun> {
        let repo_id = self.served_mirror_repo_id(repo_name)?;
        let target = {
            let txn = self.store.env.read_txn()?;
            self.mirror_target_in_txn(&txn, repo_id)?
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
            (actor, self.mirror_target_in_txn(&txn, repo_id)?)
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
            Ok(Some(landed)) => OriginMirrorRun {
                at,
                refs: landed.refs,
                deleted: landed.deleted,
                failure: None,
                readiness: Some(landed.readiness),
                lfs_transfer: landed.lfs_transfer,
            },
            Err(error) => OriginMirrorRun {
                at,
                refs: 0,
                deleted: 0,
                failure: Some(error.to_string()),
                readiness: None,
                lfs_transfer: None,
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
            self.mirror_target_in_txn(&txn, repo_id)?
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
        let Some(mut row) = self.mirror_target_in_txn(txn, repo_id)? else {
            return Ok(());
        };
        if row.url != url {
            return Ok(());
        }
        row.last = Some(run.clone());
        put_mirror_state_in_txn(self, txn, repo_id, &row)?;
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
