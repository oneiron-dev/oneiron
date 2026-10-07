//! The `[backup]` section: where local backups go, how often `serve` takes one,
//! and how many it keeps.
//!
//! Backups are on by default for a self-hosted `serve`: one a day, the newest
//! seven kept, in a directory beside the vault. Nothing leaves the machine.
//! `enabled = false` stops the schedule; `oneiron backup` still works by hand.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::lookup::{lookup_bool, lookup_parse, lookup_path};

const DEFAULT_EVERY_HOURS: u64 = 24;
const DEFAULT_KEEP: usize = 7;

/// Resolved backup settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupConfig {
    /// Whether `serve` takes backups on its own.
    pub enabled: bool,
    /// Backup directory. `None` means `<vault>.backups` beside the vault.
    pub dir: Option<PathBuf>,
    /// Hours between scheduled backups.
    pub every_hours: u64,
    /// Newest backups kept; older ones are deleted after each new backup.
    pub keep: usize,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            dir: None,
            every_hours: DEFAULT_EVERY_HOURS,
            keep: DEFAULT_KEEP,
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
    }

    pub(super) fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.every_hours > 0,
            "backup.every_hours must be greater than zero"
        );
        anyhow::ensure!(
            self.keep > 0,
            "backup.keep must be greater than zero; set backup.enabled = false to stop scheduled backups"
        );
        Ok(())
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
}

pub(super) fn lookup_backup_override(
    lookup: &mut impl FnMut(&str) -> Option<String>,
) -> anyhow::Result<Option<BackupConfigOverride>> {
    let over = BackupConfigOverride {
        enabled: lookup_bool(lookup, "ONEIRON_BACKUP_ENABLED")?,
        dir: lookup_path(lookup, "ONEIRON_BACKUP_DIR"),
        every_hours: lookup_parse(lookup, "ONEIRON_BACKUP_EVERY_HOURS")?,
        keep: lookup_parse(lookup, "ONEIRON_BACKUP_KEEP")?,
    };
    Ok((over != BackupConfigOverride::default()).then_some(over))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_dir_sits_beside_the_vault() {
        assert_eq!(
            default_backup_dir(Path::new("/data/notes")),
            PathBuf::from("/data/notes.backups")
        );
    }

    #[test]
    fn env_keys_override_and_zero_keep_is_refused() {
        let env = [("ONEIRON_BACKUP_KEEP", "3"), ("ONEIRON_BACKUP_DIR", "/b")];
        let over = lookup_backup_override(&mut |key| {
            env.iter()
                .find(|(name, _)| *name == key)
                .map(|(_, value)| (*value).to_owned())
        })
        .unwrap()
        .unwrap();
        let mut config = BackupConfig::default();
        config.apply_override(over);
        assert_eq!(config.keep, 3);
        assert_eq!(config.dir_for(Path::new("/v")), PathBuf::from("/b"));
        config.keep = 0;
        assert!(config.validate().is_err());
    }
}
