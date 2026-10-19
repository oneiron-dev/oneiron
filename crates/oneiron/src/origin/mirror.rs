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
//! bound to [`ORIGIN_MIRROR_PUSH_EFFECTOR`], and reaches git only as this
//! push's `Authorization` header, never config or disk.
//!
//! Mirror-main stays read-only. Mirror-side work comes back inbound through
//! the door as `refs/imported/<source>/<branch>`, which the change index
//! stamps `mirror_import`; merges happen at origin and push outward. Imported
//! refs are never pushed back out.

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use super::publication::OriginPublicationStatus;
use super::residence::OriginHostAuthority;
use super::smart_http::origin_repo_dir;
use crate::Vault;
use crate::codebase::RepoRef;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::{GitOid, GitRefName, GitWire, GitWireRepo};
use crate::side_table::{self, Named, SideTable};

/// The effector a mirror's push token is bound to in custody.
pub const ORIGIN_MIRROR_PUSH_EFFECTOR: &str = "origin:mirror-push";

/// The shortest cadence the owner may set, in seconds: the lifecycle tick.
pub const ORIGIN_MIRROR_MIN_EVERY_SECS: u64 = 60;

/// The basic-auth user a token goes with when the owner names none.
pub const ORIGIN_MIRROR_DEFAULT_USER: &str = "x-access-token";

/// Refs that came in from a mirror; they never go back out.
pub const ORIGIN_MIRROR_IMPORTED_PREFIX: &str = "refs/imported/";

const MAX_URL_BYTES: usize = 2048;
const MAX_USER_BYTES: usize = 128;

/// One repository's mirror. Key: repo id.
const TARGETS: SideTable<EntityId, OriginMirrorTarget, Named> =
    SideTable::new(&side_table::ORIGIN_MIRROR_TARGET);

/// The owner's outbound mirror of one served repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OriginMirrorTarget {
    /// The served name the owner configured it under.
    pub repo: String,
    /// The mirror's https URL. It carries no credential, query or fragment.
    pub url: String,
    /// The custody record whose value is the mirror's push token.
    pub secret_ref: String,
    /// The basic-auth user the token goes with.
    pub user: String,
    /// Seconds between pushes: the repository's real RPO.
    pub every_secs: u64,
    /// The last push, whatever its outcome.
    pub last: Option<OriginMirrorRun>,
    /// The refs the mirror took from this vault's last successful push. A
    /// ref that leaves the published set is deleted there on the next push.
    pub pushed: Vec<String>,
}

/// One push to a mirror.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OriginMirrorRun {
    /// Seconds, on the vault clock.
    pub at: u64,
    /// Refs pushed.
    pub refs: u64,
    /// Refs deleted at the mirror.
    pub deleted: u64,
    /// `None` when the push landed; its redacted cause otherwise.
    pub failure: Option<String>,
}

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
        let (last, pushed) = match previous {
            Some(row) if row.url == input.url => (row.last, row.pushed),
            _ => (None, Vec::new()),
        };
        let row = OriginMirrorTarget {
            repo: repo_name.to_owned(),
            url: input.url,
            secret_ref: input.secret_ref,
            user,
            every_secs: input.every_secs,
            last,
            pushed,
        };
        TARGETS.put(&self.store, txn, &repo_id, &row)?;
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

    pub(crate) fn clear_served_origin_mirror_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        repo_name: &str,
    ) -> Result<bool> {
        let repo_id = self.served_mirror_repo_id(repo_name)?;
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
        self.require_mirror_pusher(repo_name)?;
        Ok(self.push_mirror_target(repo_id, &target))
    }

    /// Pushes now as the caller's owner proof, rechecked when its run is written.
    pub fn push_served_origin_mirror_as_owner(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        repo_name: &str,
    ) -> Result<OriginMirrorRun> {
        let repo_id = self.served_mirror_repo_id(repo_name)?;
        let target = {
            let txn = self.store.env.read_txn()?;
            owner.revalidate_in_txn(self, &txn)?;
            TARGETS.get(&self.store, &txn, &repo_id)?
        }
        .ok_or(Error::EntityNotFound)?;
        self.require_mirror_pusher(repo_name)?;
        let (run, pushed) = self.attempt_mirror_target(repo_id, &target);
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        self.record_mirror_run_in_txn(&mut txn, repo_id, &target.url, &run, pushed)?;
        txn.commit()?;
        Ok(run)
    }

    /// One pass over every mirror target: each that is due, and whose
    /// repository this host is the origin of, is pushed. `admit` takes the
    /// host's hold for one push, or returns `None` when it has none to give;
    /// `stop` asks the pass to start no further push.
    pub fn push_due_origin_mirrors(
        &self,
        mut admit: impl FnMut() -> Option<Box<dyn Send>>,
        stop: impl Fn() -> bool,
    ) -> Result<OriginMirrorPushes> {
        let targets = {
            let txn = self.store.env.read_txn()?;
            TARGETS.scan(&self.store, &txn)?
        };
        let mut report = OriginMirrorPushes {
            targets: u64::try_from(targets.len()).unwrap_or(u64::MAX),
            ..OriginMirrorPushes::default()
        };
        let now = self.now_recorded_at();
        for (repo_id, target) in targets {
            let due = target
                .last
                .as_ref()
                .is_none_or(|run| now.saturating_sub(run.at) >= target.every_secs);
            if !due || stop() || self.require_mirror_pusher(&target.repo).is_err() {
                report.skipped += 1;
                continue;
            }
            // The repository was renamed or recreated: its id moved, so this
            // row names a repository no longer served.
            if self.served_mirror_repo_id(&target.repo).ok() != Some(repo_id) {
                report.skipped += 1;
                continue;
            }
            let Some(_hold) = admit() else {
                report.skipped += 1;
                continue;
            };
            if self.push_mirror_target(repo_id, &target).failure.is_some() {
                report.failed += 1;
            } else {
                report.pushed += 1;
            }
        }
        Ok(report)
    }

    /// Refuses unless this host is the repository's origin: no authority row
    /// (this vault alone serves it) or this host's held epoch.
    fn require_mirror_pusher(&self, repo_name: &str) -> Result<()> {
        match self.origin_host_authority(repo_name)? {
            OriginHostAuthority::Unconfigured | OriginHostAuthority::Held(_) => Ok(()),
            OriginHostAuthority::Mirror(_) | OriginHostAuthority::Elsewhere(_) => Err(
                Error::ConcurrentWrite("only the repository's origin pushes its mirror"),
            ),
        }
    }

    fn served_mirror_repo_id(&self, repo_name: &str) -> Result<EntityId> {
        let repo_root = origin_repo_dir(self, repo_name)?;
        let identity = GitWire::new(self)?.repository_identity(&repo_root)?;
        super::lfs::lfs_repo_id(&identity.as_hex())
    }

    /// Pushes one target and records the run on its row. A failure is the
    /// row's to carry, never the caller's: the next pass tries again.
    fn push_mirror_target(
        &self,
        repo_id: EntityId,
        target: &OriginMirrorTarget,
    ) -> OriginMirrorRun {
        let (run, pushed) = self.attempt_mirror_target(repo_id, target);
        if let Err(error) = self.record_mirror_run(repo_id, &target.url, &run, pushed) {
            tracing::warn!(kind = ?error.kind(), "mirror push run was not recorded");
        }
        run
    }

    fn attempt_mirror_target(
        &self,
        repo_id: EntityId,
        target: &OriginMirrorTarget,
    ) -> (OriginMirrorRun, Option<Vec<String>>) {
        let attempt = self.push_mirror_once(repo_id, target);
        let at = self.now_recorded_at();
        let (run, pushed) = match attempt {
            Ok((refs, deleted, pushed)) => (
                OriginMirrorRun {
                    at,
                    refs,
                    deleted,
                    failure: None,
                },
                Some(pushed),
            ),
            Err(error) => (
                OriginMirrorRun {
                    at,
                    refs: 0,
                    deleted: 0,
                    failure: Some(error.to_string()),
                },
                None,
            ),
        };
        (run, pushed)
    }

    /// The push itself: `(refs, deleted, the refs the mirror now holds)`.
    fn push_mirror_once(
        &self,
        repo_id: EntityId,
        target: &OriginMirrorTarget,
    ) -> Result<(u64, u64, Vec<String>)> {
        let repo_root = origin_repo_dir(self, &target.repo)?;
        let wire = GitWire::new(self)?;
        let Some(handle) = self.mirror_handle(&wire, repo_id, &repo_root)? else {
            // No published commit to pin a handle to: the mirror has nothing
            // to take, and keeps what it holds until there is one.
            return Ok((0, 0, target.pushed.clone()));
        };
        let refs: Vec<(GitRefName, GitOid)> = self
            .published_origin_refs_without_waiting(&wire, repo_id, &handle)?
            .into_iter()
            .filter(|(name, _)| !name.as_str().starts_with(ORIGIN_MIRROR_IMPORTED_PREFIX))
            .collect();
        let deletions = target
            .pushed
            .iter()
            .filter(|old| !refs.iter().any(|(name, _)| name.as_str() == old.as_str()))
            .map(|old| GitRefName::parse_full(old.clone()))
            .collect::<Result<Vec<_>>>()?;
        let user = target.user.clone();
        let mut pushed = Err(Error::InvariantViolation("mirror push door never ran"));
        self.inject_secret_at_door(
            &target.secret_ref,
            ORIGIN_MIRROR_PUSH_EFFECTOR,
            &mut |token: &[u8]| {
                let mut credential =
                    zeroize::Zeroizing::new(Vec::with_capacity(user.len() + 1 + token.len()));
                credential.extend_from_slice(user.as_bytes());
                credential.push(b':');
                credential.extend_from_slice(token);
                let header = zeroize::Zeroizing::new(format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD.encode(credential.as_slice())
                ));
                pushed = wire.push_mirror(&handle, &target.url, &refs, &deletions, &header);
                Ok(())
            },
        )?;
        pushed?;
        let count = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
        let names = refs
            .iter()
            .map(|(name, _)| name.as_str().to_owned())
            .collect();
        Ok((count(refs.len()), count(deletions.len()), names))
    }

    /// A proven handle on the served repository, pinned to a commit one of
    /// its publications names. `None` while it has no published commit.
    fn mirror_handle(
        &self,
        wire: &GitWire<'_>,
        repo_id: EntityId,
        repo_root: &std::path::Path,
    ) -> Result<Option<GitWireRepo>> {
        for publication_id in self.origin_visible_ref_rows(&repo_id)? {
            let Some(record) = self.origin_publication(publication_id)? else {
                continue;
            };
            if record.repo_id != repo_id || record.status != OriginPublicationStatus::Published {
                continue;
            }
            let repo_ref = RepoRef::LocalFolder {
                path: repo_root.to_string_lossy().into_owned(),
                commit: record.new_oid.as_str().to_owned(),
            };
            // A deleted ref's slot or an annotated tag pins no commit; the
            // next publication may.
            if let Ok(handle) = wire.open_repo(repo_ref, repo_root) {
                return Ok(Some(handle));
            }
        }
        Ok(None)
    }

    /// Writes a run onto its target. A target the owner re-pointed or cleared
    /// meanwhile keeps the owner's row.
    fn record_mirror_run(
        &self,
        repo_id: EntityId,
        url: &str,
        run: &OriginMirrorRun,
        pushed: Option<Vec<String>>,
    ) -> Result<()> {
        let mut txn = self.store.env.write_txn()?;
        self.record_mirror_run_in_txn(&mut txn, repo_id, url, run, pushed)?;
        txn.commit()?;
        Ok(())
    }

    fn record_mirror_run_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        repo_id: EntityId,
        url: &str,
        run: &OriginMirrorRun,
        pushed: Option<Vec<String>>,
    ) -> Result<()> {
        let Some(mut row) = TARGETS.get(&self.store, txn, &repo_id)? else {
            return Ok(());
        };
        if row.url != url {
            return Ok(());
        }
        row.last = Some(run.clone());
        if let Some(pushed) = pushed {
            row.pushed = pushed;
        }
        TARGETS.put(&self.store, txn, &repo_id, &row)?;
        Ok(())
    }
}

/// An https URL with a host, and no credential, query, fragment, space or
/// control byte.
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
    Ok(())
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}
