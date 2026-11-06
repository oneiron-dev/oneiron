//! The owner's backup setting (FIX 5621): whether a running server takes
//! backups on its own, how many hours apart, and how many it keeps. It is
//! owner policy kept in the vault, one row for the whole choice. A server's
//! schedule follows it over the deployment's `[backup]` section, which
//! decides while the owner has stored none; where backups go stays the
//! deployment's alone. A checkpoint keeps the row, and a restore keeps the
//! live vault's.

use serde::{Deserialize, Serialize};

use oneiron_base::error::Error;
use oneiron_base::error::Result;

/// Hours between scheduled backups when nothing sets them.
pub const DEFAULT_EVERY_HOURS: u64 = 24;
/// Newest backups kept when nothing sets it.
pub const DEFAULT_KEEP: usize = 7;

/// One backup policy: the owner's choice, or the deployment's `[backup]`
/// section read as one.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupPolicy {
    /// Whether a running server takes backups on its own. A backup asked
    /// for now is taken either way.
    pub enabled: bool,
    /// Hours between scheduled backups.
    pub every_hours: u64,
    /// Newest backups kept; older ones are deleted after each new backup.
    pub keep: usize,
}

impl Default for BackupPolicy {
    /// Off, one a day, the newest seven kept.
    fn default() -> Self {
        Self {
            enabled: false,
            every_hours: DEFAULT_EVERY_HOURS,
            keep: DEFAULT_KEEP,
        }
    }
}

impl BackupPolicy {
    /// The rule this policy breaks, naming its field, or `None`: `every_hours`
    /// and `keep` are each greater than zero, with the schedule on or off.
    /// These are the `[backup]` section's own rules; nothing else bounds them.
    #[must_use]
    pub const fn problem(&self) -> Option<&'static str> {
        if self.every_hours == 0 {
            Some("every_hours must be greater than zero")
        } else if self.keep == 0 {
            Some("keep must be greater than zero; set enabled to false to stop scheduled backups")
        } else {
            None
        }
    }
}
