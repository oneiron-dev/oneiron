//! Scheduled backups for a running `serve`.
//!
//! Each tick asks one question: is the newest backup older than the interval?
//! If so it takes one and prunes beyond `keep`. The newest file on disk is the
//! schedule's only state, so a restart, a manual backup or a deleted file all
//! do the right thing without a ledger.
//!
//! Whether the schedule runs, its interval and `keep` are the policy in force
//! when a backup holds the lock: the owner's backup setting in the vault, else
//! the deployment's `[backup]` section (FIX 5621). A setting stored while a
//! backup is being written applies from the next one.
//!
//! A managed vault's host also carries the managed backup duty (`managed`):
//! on a tick where the owner's schedule takes nothing, the same pass backs
//! the vault up hourly when it changed, or prunes what its node's supervisor
//! acked.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, AtomicU64};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use oneiron::settings::backup::BackupPolicy;

use super::backup::{self, BackupOutcome, BackupPlan, BackupRecord, Rehearsal, write_budget};
use super::location::{self, Location};
use super::stamp::now_unix_ms;
use super::{OwnerError, OwnerResult};
use crate::server::{HousekeepingAdmission, SyncServer, admit_every_pass};

/// The managed backup duty: hourly when changed, before an idle reap, and
/// the prune-only pass.
mod managed;

pub(crate) use self::managed::{MANAGED_BACKUP_EVERY, PreIdleAttempt, PreIdleBackup};

/// How often a running server checks whether a backup is due.
pub(crate) const SCHEDULE_TICK: Duration = Duration::from_secs(60);

/// How often a scheduled backup pass that has not finished says so (FIX
/// 6769): a pass held on the backup lock or in a long backup shows in the
/// log, not only by its silence.
const PASS_STILL_RUNNING_EVERY: Duration = Duration::from_secs(60);

/// What a server knows about its vault's place on disk and its backups.
pub(crate) struct OwnerHost {
    pub(crate) vault_path: PathBuf,
    pub(crate) vault_config: oneiron::VaultConfig,
    /// Where backups go and how they are written. Each backup takes a copy
    /// carrying the `keep` in force (`effective_plan`).
    pub(crate) backups: BackupPlan,
    /// The deployment's `[backup]` schedule, which decides while the owner
    /// has stored no backup setting (FIX 5621).
    pub(crate) fallback: BackupPolicy,
    /// One backup at a time, whether the schedule or the owner asked.
    pub(crate) backup_lock: Mutex<()>,
    /// Where rehearsals make their scratch copy: a managed vault's private
    /// directory beside its data, or a test's own. `None` is the vault's own
    /// directory, the disk its floor measures (FIX 5612).
    pub(crate) rehearse_temp: Option<PathBuf>,
    /// How often the managed backup duty backs a changed vault up: a
    /// managed vault's host carries it (`managed`); `None` elsewhere.
    managed_every: Option<Duration>,
    /// The backup jobs in flight: the resident pass and a backup before an
    /// idle reap, which a reap preparation tells from other writes.
    backup_jobs: AtomicU64,
    /// The managed pass's last decision said that took no backup, `0` for
    /// none (`managed`).
    managed_said: AtomicU8,
}

impl OwnerHost {
    /// `vault_config` is the one `serve` opened the vault with, dictionary
    /// paths resolved, so a rehearsal opens its copy the same way.
    pub(crate) fn from_config(
        config: &crate::config::ServeConfig,
        vault_config: oneiron::VaultConfig,
    ) -> Self {
        let backup = &config.backup;
        Self {
            vault_path: config.vault_path.clone(),
            vault_config,
            backups: BackupPlan::new(
                &config.vault_path,
                backup.dir_for(&config.vault_path),
                backup.keep,
            ),
            // The deployment's `[backup]` policy, on every posture, while the
            // owner's own setting is unset.
            fallback: backup.policy(),
            backup_lock: Mutex::new(()),
            rehearse_temp: None,
            managed_every: None,
            backup_jobs: AtomicU64::new(0),
            managed_said: AtomicU8::new(0),
        }
    }

    /// Makes rehearsals' scratch copies under `dir`, a private directory on
    /// the vault's own storage, instead of the vault's directory.
    pub(crate) fn with_rehearsal_dir(mut self, dir: PathBuf) -> Self {
        self.rehearse_temp = Some(dir);
        self
    }

    /// Binds each backup's vault id to `registry`, the registry's id for this
    /// vault (FIX 5826): a managed vault's name.
    pub(crate) fn registered_as(mut self, registry: String) -> Self {
        self.backups.registry = Some(registry);
        self
    }

    fn one_at_a_time(&self) -> std::sync::MutexGuard<'_, ()> {
        self.backup_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The policy in force over the owner's `stored` setting: it whole, else
    /// this host's `[backup]` schedule. An explicit off is a stored choice.
    pub(crate) fn effective(&self, stored: Option<BackupPolicy>) -> BackupPolicy {
        stored.unwrap_or(self.fallback)
    }

    /// The policy in force now, read from the vault, and this host's plan
    /// with its `keep`; the plan keeps its floor and custody anchor.
    fn effective_plan(
        &self,
        vault: &oneiron::Vault,
    ) -> oneiron::Result<(BackupPlan, BackupPolicy)> {
        let policy = self.effective(vault.backup_policy()?);
        let mut plan = self.backups.clone();
        plan.keep = policy.keep;
        Ok((plan, policy))
    }

    /// The data-location section of the owner's status: the backups as the
    /// policy in force has them, their hours `None` while the schedule is off.
    pub(crate) fn locate(&self, vault: &oneiron::Vault) -> anyhow::Result<Location> {
        let (plan, policy) = self.effective_plan(vault)?;
        location::locate(
            &self.vault_path,
            Some(vault),
            &plan,
            policy.enabled.then_some(policy.every_hours),
        )
    }

    /// Takes a backup now, serialized with every other backup of this vault.
    /// On an owner's request, `owner` is rechecked once the lock is held, in
    /// the snapshot itself: a request queued behind a revocation or an
    /// ownership change takes and prunes nothing. A backup stopped at the
    /// disk's floor is logged and answered as capacity (FIX 5479). It prunes
    /// to the `keep` in force, and is taken whether the schedule is on or not.
    pub(crate) fn take(
        &self,
        vault: &oneiron::Vault,
        owner: Option<&oneiron::consent::AuthenticatedOwner>,
    ) -> OwnerResult<BackupOutcome> {
        let _one_at_a_time = self.one_at_a_time();
        let (plan, _) = self.effective_plan(vault)?;
        backup::take_as(vault, &plan, owner).map_err(|error| {
            if let Some(capacity) = write_budget::Capacity::of_host(&error) {
                tracing::warn!(
                    reason = "capacity",
                    cause = capacity.cause(),
                    refusal = capacity.refusal(),
                    "backup not taken: no room on the disk it writes to"
                );
            }
            match error.downcast::<oneiron::Error>() {
                Ok(engine) => OwnerError::from(engine),
                Err(error) => OwnerError::Host(error),
            }
        })
    }

    /// Rehearses one of this vault's backups by its listed file name, the
    /// newest by default; never a caller-built path. The backup lock is held
    /// from choosing the file until the rehearsal has read it, so retention
    /// cannot prune it in between. `vault` is the open vault the backup is
    /// of; the rehearsal reads only its key-custody state. The copy's writes
    /// claim their room on the floor this host was lent, and on the disk
    /// they land on, and one stopped there or by a full disk says capacity
    /// (FIX 5479, FIX 5612, FIX 5615).
    pub(crate) fn rehearse(
        &self,
        vault: &oneiron::Vault,
        file: Option<&str>,
    ) -> OwnerResult<Rehearsal> {
        self.with_chosen(file, |chosen| {
            write_budget::rehearse_claiming(
                &self.rehearse_temp(vault),
                &chosen.path,
                self.vault_config.clone(),
                &vault.side_restore_source()?,
                &self.backups,
            )
            .map_err(write_budget::rehearsal_error)
        })
    }

    /// The directory a rehearsal's scratch copy is made in and removed from:
    /// [`Self::rehearsal_parent`], else the system temp directory.
    fn rehearse_temp(&self, vault: &oneiron::Vault) -> PathBuf {
        self.rehearsal_parent(vault)
            .unwrap_or_else(std::env::temp_dir)
    }

    /// This host's own rehearsal directory, which rehearsals make their
    /// scratch in and the start-up sweep clears: the one this host was given,
    /// else the vault's own, as it opened, so the copy lands on the disk the
    /// floor measures (FIX 5612). `None` for a vault directory another user
    /// could move entries in, where no scratch is made: a rehearsal keeps the
    /// system temp directory as before, which is never swept.
    fn rehearsal_parent(&self, vault: &oneiron::Vault) -> Option<PathBuf> {
        if let Some(dir) = &self.rehearse_temp {
            return Some(dir.clone());
        }
        let dir = vault.lfs_storage_dir();
        #[cfg(unix)]
        let shared = !matches!(oneiron::store::shared_path(dir), Ok(None));
        #[cfg(not(unix))]
        let shared = false;
        (!shared).then(|| dir.to_path_buf())
    }

    /// Removes the scratch copies a stopped process's rehearsals left in this
    /// host's rehearsal directory (FIX 5677), called at start before any
    /// rehearsal of this process can begin. Only a marked copy no rehearsal
    /// holds goes ([`backup::sweep_rehearsals`]); a kept `--scratch` copy is
    /// never marked, and nothing outside that directory is looked at. A sweep
    /// that fails is logged, and start goes on.
    pub(crate) fn sweep_rehearsals(&self, vault: &oneiron::Vault) {
        #[cfg(unix)]
        if let Some(parent) = self.rehearsal_parent(vault) {
            match backup::sweep_rehearsals(&parent) {
                Ok(0) => {}
                Ok(removed) => tracing::info!(
                    removed,
                    dir = %parent.display(),
                    "removed the scratch copies of rehearsals a stopped process left"
                ),
                Err(error) => tracing::warn!(
                    reason = "rehearsal_sweep_failed",
                    dir = %parent.display(),
                    error = %format!("{error:#}"),
                    "could not sweep the scratch copies of rehearsals a stopped process left; \
                     start goes on"
                ),
            }
        }
        #[cfg(not(unix))]
        let _ = vault;
    }

    fn with_chosen<T>(
        &self,
        file: Option<&str>,
        rehearse: impl FnOnce(&BackupRecord) -> OwnerResult<T>,
    ) -> OwnerResult<T> {
        let _one_at_a_time = self.one_at_a_time();
        let backups = backup::list(&self.backups)?;
        let chosen = match file {
            Some(file) => backups.into_iter().find(|record| record.file == file),
            None => backups.into_iter().last(),
        }
        .ok_or_else(|| OwnerError::Invalid("no such backup for this vault".into()))?;
        rehearse(&chosen)
    }

    /// Takes a backup when the policy in force has the schedule on and the
    /// newest backup is older than its interval. The policy is read once the
    /// lock is held, so a backup already being written finishes under the
    /// one it began with. When it takes none, a managed vault's duty decides
    /// in the same pass: an hourly backup of a changed vault, else a prune
    /// alone (`managed`).
    pub(crate) fn take_if_due(
        &self,
        vault: &oneiron::Vault,
    ) -> anyhow::Result<Option<BackupOutcome>> {
        let _one_at_a_time = self.one_at_a_time();
        let (plan, policy) = self.effective_plan(vault)?;
        if policy.enabled {
            let every_ms = policy
                .every_hours
                .saturating_mul(3_600)
                .saturating_mul(1_000);
            let due = backup::list(&plan)?
                .last()
                .is_none_or(|newest| now_unix_ms().saturating_sub(newest.taken_ms) >= every_ms);
            if due {
                return backup::take(vault, &plan).map(Some);
            }
        }
        self.managed_pass(vault, &plan)
    }
}

impl SyncServer {
    /// Starts the backup schedule when this server has its vault's backup
    /// storage. It ticks while the policy in force is off too, so a setting
    /// that turns it on is served from the next tick, with no restart.
    pub(crate) fn spawn_backup_schedule(
        self: &Arc<Self>,
        tick: Duration,
    ) -> Option<tokio::task::JoinHandle<()>> {
        self.spawn_backup_schedule_admitted(tick, admit_every_pass())
    }

    /// Starts the backup schedule on a host with a write freeze: each tick is
    /// admitted through `admit` and holds that admission on its blocking
    /// thread through the due check, the backup and its pruning, counted as
    /// a backup job meanwhile. A refused tick takes nothing and waits for the
    /// next.
    pub(crate) fn spawn_backup_schedule_admitted(
        self: &Arc<Self>,
        tick: Duration,
        admit: HousekeepingAdmission,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let Some(host) = self.owner_host.as_ref().map(Arc::clone) else {
            tracing::info!("no backup schedule: this server keeps no backups");
            return None;
        };
        let server = Arc::clone(self);
        tracing::info!(
            tick_secs = tick.as_secs(),
            managed_every_secs = ?host.managed_every.map(|every| every.as_secs()),
            "backup schedule started"
        );
        Some(tokio::spawn(async move {
            let mut interval = tokio::time::interval(tick);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut refused = false;
            loop {
                interval.tick().await;
                let Some(admission) = admit() else {
                    // Said once a run of refused ticks, as the pause is.
                    if !std::mem::replace(&mut refused, true) {
                        tracing::info!(
                            "scheduled backup tick refused: the vault is paused; the next \
                             admitted tick decides"
                        );
                    }
                    continue;
                };
                refused = false;
                let (host, server) = (Arc::clone(&host), Arc::clone(&server));
                let mut pass = tokio::task::spawn_blocking(move || {
                    let _admission = admission;
                    let _job = host.backup_job();
                    host.take_if_due(server.vault())
                });
                let started = tokio::time::Instant::now();
                let outcome = loop {
                    match tokio::time::timeout(PASS_STILL_RUNNING_EVERY, &mut pass).await {
                        Ok(outcome) => break outcome,
                        Err(_) => tracing::info!(
                            running_secs = started.elapsed().as_secs(),
                            "scheduled backup pass still running"
                        ),
                    }
                };
                match outcome {
                    Ok(Ok(Some(taken))) => tracing::info!(
                        backup = %taken.backup.path.display(),
                        pruned = taken.pruned.len(),
                        "scheduled backup taken"
                    ),
                    Ok(Ok(None)) => {}
                    Ok(Err(error)) => match write_budget::Capacity::of_host(&error) {
                        // Still due, so a later tick with room takes it (FIX
                        // 5479), after a full disk too (FIX 5615).
                        Some(capacity) => tracing::warn!(
                            reason = "capacity",
                            cause = capacity.cause(),
                            refusal = capacity.refusal(),
                            "scheduled backup not taken: no room on the disk it writes to; a \
                             later tick with room takes it"
                        ),
                        None => tracing::warn!(
                            kind = ?crate::logging::engine_kind(&error),
                            "scheduled backup failed"
                        ),
                    },
                    Err(error) => {
                        tracing::warn!(panicked = error.is_panic(), "scheduled backup task failed");
                    }
                }
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SyncServerConfig;

    fn scheduled_server(
        every: Duration,
        keep: usize,
    ) -> (tempfile::TempDir, tempfile::TempDir, Arc<SyncServer>) {
        let dir = oneiron::test_support::restore_tempdir();
        let backups = oneiron::test_support::restore_tempdir();
        let vault =
            Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
        let host = OwnerHost {
            vault_path: dir.path().to_path_buf(),
            vault_config: oneiron::VaultConfig::device(),
            backups: BackupPlan::new(dir.path(), backups.path().to_path_buf(), keep),
            every: Some(every),
            backup_lock: Mutex::new(()),
            rehearse_temp: dir.path().parent().map(std::path::Path::to_path_buf),
        };
        let server = SyncServer::new(vault, SyncServerConfig::default())
            .unwrap()
            .with_owner_host(host);
        (dir, backups, Arc::new(server))
    }

    #[test]
    fn a_backup_is_due_only_once_the_newest_is_older_than_the_interval() {
        let (_dir, _backups, server) = scheduled_server(Duration::from_secs(3_600), 3);
        let host = server.owner_host.as_ref().unwrap();
        assert!(host.take_if_due(server.vault()).unwrap().is_some());
        assert!(host.take_if_due(server.vault()).unwrap().is_none());
        assert_eq!(backup::list(&host.backups).unwrap().len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_schedule_backs_up_on_its_own_and_prunes_to_keep() {
        let (_dir, _backups, server) = scheduled_server(Duration::from_millis(40), 2);
        let host = Arc::clone(server.owner_host.as_ref().unwrap());
        let handle = server
            .spawn_backup_schedule(Duration::from_millis(10))
            .expect("a schedule is configured");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let first = loop {
            if let Some(first) = backup::list(&host.backups).unwrap().first().cloned() {
                break first;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "no scheduled backup"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        // Retention: the first backup is pruned once two newer ones exist.
        loop {
            let listed = backup::list(&host.backups).unwrap();
            if listed.len() == 2 && listed.iter().all(|record| record.file != first.file) {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "first backup never pruned"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        handle.abort();
    }

    #[test]
    fn a_backup_waits_for_the_rehearsal_of_the_file_it_would_prune() {
        let (_dir, backups, server) = scheduled_server(Duration::from_secs(3_600), 1);
        let host = Arc::clone(server.owner_host.as_ref().unwrap());
        let only = host.take(server.vault(), None).unwrap().backup;
        let rehearsal = host
            .with_chosen(None, |chosen| {
                assert_eq!(chosen.file, only.file);
                // A backup asked for now, with keep = 1, would prune the file
                // being rehearsed; it waits until the rehearsal is done.
                let racing = {
                    let (host, server) = (Arc::clone(&host), Arc::clone(&server));
                    std::thread::spawn(move || host.take(server.vault(), None).unwrap())
                };
                std::thread::sleep(Duration::from_millis(500));
                assert!(!racing.is_finished(), "the backup waited");
                let source = server.vault().side_restore_source()?;
                let rehearsal = backup::rehearse_in(
                    backups.path(),
                    &chosen.path,
                    host.vault_config.clone(),
                    None,
                    &source,
                );
                Ok((rehearsal?, racing))
            })
            .unwrap();
        let (rehearsal, racing) = rehearsal;
        assert!(rehearsal.verified);
        assert_eq!(racing.join().unwrap().pruned, vec![only.file]);
    }

    #[test]
    fn the_schedule_is_opt_in_and_never_on_a_hosted_node() {
        let mut config = crate::config::ServeConfig::default();
        let host = |config: &crate::config::ServeConfig| {
            OwnerHost::from_config(config, config.vault_config())
        };
        assert!(host(&config).every.is_none(), "the schedule is opt-in");
        config.backup.enabled = true;
        assert_eq!(host(&config).every, Some(Duration::from_secs(24 * 3_600)));
        config.privacy_posture = oneiron::HostingPrivacyPosture::Hosted;
        assert!(host(&config).every.is_none());
    }
}
