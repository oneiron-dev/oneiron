//! The `[backup]` section: where local backups go, whether `serve` takes them
//! on its own, how often, and how many it keeps.
//!
//! The schedule is opt-in (`enabled = true`): one a day, the newest seven
//! kept, in a directory beside the vault, and nothing leaves the machine. It
//! stays off by default until erasure reaches backup files (ARCH-0038 orders
//! the exterior erasure ledger before snapshot storage). `oneiron backup`
//! works either way. A running server follows the owner's backup setting in
//! the vault over this section's `enabled`, `every_hours` and `keep` (FIX
//! 5621); this section decides while he has stored none, and `dir` is this
//! section's alone.

use std::path::{Path, PathBuf};

use oneiron::settings::backup::BackupPolicy;
use serde::Deserialize;

use super::lookup::{lookup_bool, lookup_parse, lookup_path};

/// Resolved backup settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupConfig {
    /// Whether `serve` takes backups on its own. Off unless set.
    pub enabled: bool,
    /// Backup directory. `None` means `<vault>.backups` beside the vault.
    pub dir: Option<PathBuf>,
    /// Hours between scheduled backups.
    pub every_hours: u64,
    /// Newest backups kept; older ones are deleted after each new backup.
    pub keep: usize,
    /// CALLS CUSTODY_ANCHOR_ROOT (KS-4, Engine 10-20): the owner-selected
    /// directory holding this vault's custody anchor, outside the vault and
    /// its key custody, on storage that outlives this host (`ONEIRON_CUSTODY_
    /// ANCHOR_ROOT`). Unset by default: custody heads still publish beside
    /// the backups, the anchor step stays pending by name on the owner's
    /// status read, and a restore on a new host uses the head it finds and
    /// says rollback is not proven. Never a backup or save refusal.
    pub custody_anchor_root: Option<PathBuf>,
}

impl Default for BackupConfig {
    fn default() -> Self {
        let policy = BackupPolicy::default();
        Self {
            enabled: policy.enabled,
            dir: None,
            every_hours: policy.every_hours,
            keep: policy.keep,
            custody_anchor_root: None,
        }
    }
}

impl BackupConfig {
    /// The directory backups for `vault_path` live in.
    pub fn dir_for(&self, vault_path: &Path) -> PathBuf {
        self.dir
            .clone()
            .unwrap_or_else(|| default_backup_dir(vault_path))
    }

    /// This section's schedule as one policy: what a running server follows
    /// while the owner has stored no backup setting (FIX 5621).
    pub fn policy(&self) -> BackupPolicy {
        BackupPolicy {
            enabled: self.enabled,
            every_hours: self.every_hours,
            keep: self.keep,
        }
    }

    pub(super) fn apply_override(&mut self, over: BackupConfigOverride) {
        if let Some(value) = over.enabled {
            self.enabled = value;
        }
        if let Some(value) = over.dir {
            self.dir = Some(super::lookup::expand_home(value));
        }
        if let Some(value) = over.every_hours {
            self.every_hours = value;
        }
        if let Some(value) = over.keep {
            self.keep = value;
        }
        if let Some(value) = over.custody_anchor_root {
            self.custody_anchor_root = Some(super::lookup::expand_home(value));
        }
    }

    /// The rules the owner's setting is held to as well (FIX 5621).
    pub(super) fn validate(&self) -> anyhow::Result<()> {
        match self.policy().problem() {
            Some(problem) => anyhow::bail!("backup.{problem}"),
            None => Ok(()),
        }
    }
}

/// `<parent>/<vault-name>.backups`.
pub fn default_backup_dir(vault_path: &Path) -> PathBuf {
    let name = vault_path.file_name().map_or_else(
        || "vault".into(),
        |name| name.to_string_lossy().into_owned(),
    );
    vault_path.with_file_name(format!("{name}.backups"))
}

/// One layer's `[backup]` keys.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct BackupConfigOverride {
    pub enabled: Option<bool>,
    pub dir: Option<PathBuf>,
    pub every_hours: Option<u64>,
    pub keep: Option<usize>,
    pub custody_anchor_root: Option<PathBuf>,
}

pub(super) fn lookup_backup_override(
    lookup: &mut impl FnMut(&str) -> Option<String>,
) -> anyhow::Result<Option<BackupConfigOverride>> {
    let over = BackupConfigOverride {
        enabled: lookup_bool(lookup, "ONEIRON_BACKUP_ENABLED")?,
        dir: lookup_path(lookup, "ONEIRON_BACKUP_DIR"),
        every_hours: lookup_parse(lookup, "ONEIRON_BACKUP_EVERY_HOURS")?,
        keep: lookup_parse(lookup, "ONEIRON_BACKUP_KEEP")?,
        custody_anchor_root: lookup_path(lookup, "ONEIRON_CUSTODY_ANCHOR_ROOT"),
    };
    Ok((over != BackupConfigOverride::default()).then_some(over))
}
