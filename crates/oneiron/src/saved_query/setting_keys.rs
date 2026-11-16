//! Memory watches' owner Setting keys (DESIGN 15-setting-primitive): rows the setting
//! catalogue reads from this file.

use crate::setting::{Kind, lower_is_tighter};

/// Off: only the vault owner sets, clears and reads a per-claim watch.
fn owner_watches_alone() -> bool {
    false
}

crate::setting::setting_keys! {
    /// Let an agent keep its own per-claim memory watch. Off by default: only the vault owner
    /// sets, clears and reads a per-claim watch. On, an agent sets, clears and reads its own
    /// watch on a claim it can read, on its own live credential; each wake reads through the
    /// agent's live grants, and the owner's live feed stays the owner's. While it is off an
    /// agent's watches do not wake. On is the looser value, so only the owner turns it on; an
    /// agent's change waits on the owner's answer.
    pub(crate) MEMORY_WATCH_AGENT_MAY_WATCH: bool = "memory.watch.agent_may_watch" {
        kind: Kind::new(owner_watches_alone)
            .strictest(owner_watches_alone)
            .tighter(lower_is_tighter::<bool>),
    };
}
