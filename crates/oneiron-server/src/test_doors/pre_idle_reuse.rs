//! Door for `tests/pre_idle_held_verdict.rs` ([HELD-WHOLE-READ-OFF-PRE-IDLE]):
//! a managed vault's owner host over a test's vault and backup directory,
//! its scheduled pass, the background verify of its accepted backup run to
//! its end on the caller's thread (a tick runs it on a thread of its own),
//! and one backup before an idle reap for an attempt that stands throughout.
//! Compiled only under `--cfg oneiron_test_support`; never API.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use crate::owner::backup::finalize;
use crate::owner::schedule::{OwnerHost, PreIdleAttempt, PreIdleBackup};

/// A managed vault and its host's backups.
pub struct ManagedBackups {
    host: OwnerHost,
    vault: Arc<oneiron::Vault>,
}

/// The vault at `vault_dir`, opened with a memory keystore, and its host
/// with the managed backup duty, writing its backups to `backups`; the
/// owner's own schedule off, so each pass is the managed duty's.
pub fn managed_backups(vault_dir: &Path, backups: &Path) -> ManagedBackups {
    let vault = Arc::new(
        oneiron::Vault::open(vault_dir, oneiron::VaultConfig::device()).expect("the vault opens"),
    );
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let mut config = crate::config::ServeConfig::default();
    config.vault_path = vault_dir.to_path_buf();
    config.backup.enabled = false;
    config.backup.keep = 3;
    config.backup.dir = Some(backups.to_path_buf());
    let rehearsals = vault_dir
        .parent()
        .map_or_else(|| vault_dir.to_path_buf(), Path::to_path_buf);
    let host = OwnerHost::from_config(&config, oneiron::VaultConfig::device())
        .with_rehearsal_dir(rehearsals)
        .managed_hourly();
    ManagedBackups { host, vault }
}

/// An attempt that stands from its lock to its settling, and keeps whether
/// the backup it settled on was the last accepted one.
#[derive(Default)]
struct StandingAttempt {
    reused: Mutex<Option<bool>>,
}

impl PreIdleAttempt for StandingAttempt {
    fn id(&self) -> &str {
        "pre-idle-reuse-door"
    }

    fn locked(&self) -> bool {
        true
    }

    fn standing(&self) -> bool {
        true
    }

    fn settle(&self, done: &PreIdleBackup) -> bool {
        *self.reused.lock().unwrap_or_else(PoisonError::into_inner) = Some(done.reused);
        true
    }
}

impl ManagedBackups {
    /// The vault.
    pub fn vault(&self) -> &oneiron::Vault {
        &self.vault
    }

    /// One scheduled pass, as a tick runs it: whether it took a backup.
    pub fn pass(&self) -> anyhow::Result<bool> {
        self.host
            .take_if_due(&self.vault)
            .map(|taken| taken.is_some())
    }

    /// The background verify the last pass noted, run to its end on this
    /// thread: whether the backup read held; `None` with nothing noted. This
    /// base has no background verify, so nothing is ever noted.
    pub fn verify_noted(&self) -> Option<bool> {
        None
    }

    /// The accepted backup's file, as its marker names it.
    pub fn accepted_file(&self) -> Option<PathBuf> {
        finalize::accepted_marker(&self.host.backups)
            .map(|marker| self.host.backups.dir.join(marker.file()))
    }

    /// One backup before an idle reap: whether it reused the last accepted
    /// backup (`None` when it settled nothing), or its failure's closed
    /// reason.
    pub fn before_idle(&self) -> Result<Option<bool>, &'static str> {
        let attempt = StandingAttempt::default();
        self.host
            .back_up_before_idle(&self.vault, &attempt)
            .map_err(|failure| failure.as_str())?;
        Ok(*attempt
            .reused
            .lock()
            .unwrap_or_else(PoisonError::into_inner))
    }
}
