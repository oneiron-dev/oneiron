//! The setting keys `vault_cleanup` declares (Setting stage 1): the crate's build script lists
//! each row in the setting catalogue.

use super::CleanupPosture;
use crate::setting::Kind;

const fn ninety_days() -> u32 {
    90
}

const fn propose_first() -> CleanupPosture {
    CleanupPosture::ProposeFirst
}

crate::setting::setting_keys! {
    /// Whether the cleanup job proposes its archives (the owner accepts each) or archives
    /// directly and says so once per run. Automatic from birth unless the owner sets
    /// propose-first (owner 2026-10-18, ARCH-0073; DEC-0006); either posture is the owner's
    /// choice, and the ARCH-0066 teeth ride each automatic run's digest as a badge. A row that
    /// does not decode reads propose-first.
    pub(crate) POSTURE: CleanupPosture = "cleanup.posture" {
        kind: Kind::new(CleanupPosture::default).strictest(propose_first),
    };
    /// How many days a completed TASK's queue record stays before cleanup may archive it; 0
    /// turns this arm off. 90 days unless the owner sets it. Archiving never erases task bytes.
    pub(crate) TASK_RETENTION_DAYS: u32 = "cleanup.task_retention_days" {
        kind: Kind::new(ninety_days),
    };
}
