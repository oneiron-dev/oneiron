//! The setting keys `vault_cleanup` declares (DESIGN 15-setting-primitive): the crate's build
//! script lists each row in the setting catalogue.

use super::CleanupPosture;
use crate::setting::{Kind, higher_is_tighter};

/// On: only the owner, or for an attempt delete a live vault Admin, acts.
const fn owner_acts_alone() -> bool {
    true
}

const fn ninety_days() -> u32 {
    90
}

const fn propose_first() -> CleanupPosture {
    CleanupPosture::ProposeFirst
}

crate::setting::setting_keys! {
    /// Whether only the owner or a live vault Admin may preview and delete a cleanup-archived
    /// completed attempt. On by default: every agent is refused. Off, an agent whose live owner
    /// Grant names `vault.archive.attempt.delete.confirm` previews and deletes one too, and the
    /// receipt names the agent and that Grant. A member keeps the Admin rule. Off is the looser
    /// value, so only the owner turns it off; a row that does not decode reads on.
    pub(crate) ATTEMPT_DELETE_OWNER_OR_ADMIN_ONLY: bool =
        "vault_cleanup.attempt_delete.owner_or_admin_only" {
        kind: Kind::new(owner_acts_alone)
            .strictest(owner_acts_alone)
            .tighter(higher_is_tighter::<bool>),
    };
    /// Whether only the owner decides an open cleanup proposal (`vault.cleanup.decide`). On by
    /// default. Off, an agent whose live owner Grant names `vault.cleanup.decide` decides one
    /// too: the same complete verdict, bound to the revision it names, with the same digest,
    /// and what it archives the owner brings back by a restore or a run revert. A member never
    /// decides, because a verdict acts on other persons' records. Off is the looser value, so
    /// only the owner turns it off; a row that does not decode reads on.
    pub(crate) DECIDE_OWNER_ONLY: bool = "vault_cleanup.decide.owner_only" {
        kind: Kind::new(owner_acts_alone)
            .strictest(owner_acts_alone)
            .tighter(higher_is_tighter::<bool>),
    };
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
