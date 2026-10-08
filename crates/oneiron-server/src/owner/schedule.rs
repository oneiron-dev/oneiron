//! Scheduled backups for a running `serve`.
//!
//! Each tick asks one question: is the newest backup older than the interval?
//! If so it takes one and prunes beyond `keep`. The newest file on disk is the
//! schedule's only state, so a restart, a manual backup or a deleted file all
//! do the right thing without a ledger.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::backup::{self, BackupOutcome, BackupPlan};
use super::stamp::now_unix_ms;
use crate::server::SyncServer;

/// How often a running server checks whether a backup is due.
pub(crate) const SCHEDULE_TICK: Duration = Duration::from_secs(60);

/// What a server knows about its vault's place on disk and its backups.
pub(crate) struct OwnerHost {
    pub(crate) vault_path: PathBuf,
    pub(crate) vault_config: oneiron::VaultConfig,
    pub(crate) backups: BackupPlan,
    /// Interval between scheduled backups; `None` turns the schedule off.
    pub(crate) every: Option<Duration>,
    /// One backup at a time, whether the schedule or the owner asked.
    pub(crate) backup_lock: Mutex<()>,
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
            // A hosted or relay node backs up through its host, not beside
            // each vault.
            every: (backup.enabled
                && config.privacy_posture == oneiron::HostingPrivacyPosture::SelfHostLocal)
                .then(|| Duration::from_secs(backup.every_hours.saturating_mul(3_600))),
            backup_lock: Mutex::new(()),
        }
    }

    /// Takes a backup now, serialized with every other backup of this vault.
    pub(crate) fn take(&self, vault: &oneiron::Vault) -> anyhow::Result<BackupOutcome> {
        let _one_at_a_time = self
            .backup_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        backup::take(vault, &self.backups)
    }

    /// Takes a backup when the newest one is older than the interval.
    pub(crate) fn take_if_due(
        &self,
        vault: &oneiron::Vault,
    ) -> anyhow::Result<Option<BackupOutcome>> {
        let Some(every) = self.every else {
            return Ok(None);
        };
        let _one_at_a_time = self
            .backup_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let every_ms = u64::try_from(every.as_millis()).unwrap_or(u64::MAX);
        let due = backup::list(&self.backups)?
            .last()
            .is_none_or(|newest| now_unix_ms().saturating_sub(newest.taken_ms) >= every_ms);
        if !due {
            return Ok(None);
        }
        backup::take(vault, &self.backups).map(Some)
    }
}

impl SyncServer {
    /// Starts the backup schedule when this server has one.
    pub(crate) fn spawn_backup_schedule(
        self: &Arc<Self>,
        tick: Duration,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let host = Arc::clone(self.owner_host.as_ref()?);
        // No interval, no schedule.
        host.every?;
        let server = Arc::clone(self);
        Some(tokio::spawn(async move {
            let mut interval = tokio::time::interval(tick);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let (host, server) = (Arc::clone(&host), Arc::clone(&server));
                let outcome =
                    tokio::task::spawn_blocking(move || host.take_if_due(server.vault())).await;
                match outcome {
                    Ok(Ok(Some(taken))) => tracing::info!(
                        backup = %taken.backup.path.display(),
                        pruned = taken.pruned.len(),
                        "scheduled backup taken"
                    ),
                    Ok(Ok(None)) => {}
                    Ok(Err(error)) => tracing::warn!(error = %error, "scheduled backup failed"),
                    Err(error) => tracing::warn!(error = %error, "scheduled backup task failed"),
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
        let dir = tempfile::tempdir().unwrap();
        let backups = tempfile::tempdir().unwrap();
        let vault =
            Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
        let host = OwnerHost {
            vault_path: dir.path().to_path_buf(),
            vault_config: oneiron::VaultConfig::device(),
            backups: BackupPlan::new(dir.path(), backups.path().to_path_buf(), keep),
            every: Some(every),
            backup_lock: Mutex::new(()),
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
    fn the_schedule_is_opt_in_and_never_on_a_hosted_node() {
        let mut config = crate::config::ServeConfig::default();
        let host = |config: &crate::config::ServeConfig| {
            OwnerHost::from_config(config, config.vault_config())
        };
        assert!(host(&config).every.is_none(), "the schedule is opt-in");
        config.backup.enabled = true;
        assert_eq!(
            host(&config).every,
            Some(Duration::from_secs(24 * 3_600))
        );
        config.privacy_posture = oneiron::HostingPrivacyPosture::Hosted;
        assert!(host(&config).every.is_none());
    }
}
