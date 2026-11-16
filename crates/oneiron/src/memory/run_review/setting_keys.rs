//! Run review's owner Setting keys (DESIGN 15-setting-primitive): rows the setting catalogue
//! reads from this file.

use crate::setting::{Kind, lower_is_tighter};

/// Off: run review is read through the owner's own credential alone.
fn read_by_owner_alone() -> bool {
    false
}

crate::setting::setting_keys! {
    /// Let agents read run reviews. Off by default: a run's review, its settlement and its
    /// changes (`vault.runs.review`, `vault.runs.settlement`, `vault.runs.changes.get`) are read
    /// only through the owner's own credential. On, an agent whose live grant names the read's
    /// verb reads them as well, checked at each read. A restore group stays the owner's read.
    /// Settling, reverting and restoring a run stay the owner's acts either way: an agent never
    /// settles a run, and so never approves its own (substrate behind grants, owner 9 Nov 22:47).
    /// On is the looser value, so only the owner turns it on; an agent's change waits on the
    /// owner's answer.
    pub(crate) RUN_REVIEW_AGENT_MAY_READ: bool = "memory.run_review.agent_may_read" {
        kind: Kind::new(read_by_owner_alone)
            .strictest(read_by_owner_alone)
            .tighter(lower_is_tighter::<bool>),
    };
}
