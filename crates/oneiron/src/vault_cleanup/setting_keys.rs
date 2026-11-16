//! The setting keys `vault_cleanup` declares (DESIGN 15-setting-primitive): the crate's build
//! script lists each row in the setting catalogue.

use crate::setting::{Kind, higher_is_tighter};

/// On: only the owner, or for an attempt delete a live vault Admin, acts.
const fn owner_acts_alone() -> bool {
    true
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
}
