//! The setting keys `deletion` declares (DESIGN 15-setting-primitive): the crate's build script
//! lists each row in the setting catalogue.

use crate::setting::Kind;

/// On: a delete under a live brief share goes through the confirmed door.
const fn brief_share_delete_confirmed() -> bool {
    true
}

/// Seven days: how long an undelivered courtesy-delete leg retried before this key.
const fn courtesy_delete_give_up_default() -> u64 {
    super::COOP_DELETION_GIVE_UP_SECS
}

const fn remat_dependency_hold_default() -> u64 {
    86_400
}

const fn remat_dependency_hold_strictest() -> u64 {
    0
}

crate::setting::setting_keys! {
    /// How long, in seconds, an undelivered courtesy-delete leg keeps retrying before it is
    /// `unreachable`. Seven days unless set. The wait between tries stays one minute to six
    /// hours, growing with the leg's age; 0 makes the first failed try final. A shorter time is
    /// the looser value, since a leg that gives up sooner leaves more copies of the owner's data
    /// in place: an agent may only lengthen it, and a shorter one, 0 included, waits on the
    /// owner's check-in. A row that does not decode reads seven days.
    pub(crate) COOP_DELIVERY_GIVE_UP_SECS: u64 = "deletion.coop_delivery.give_up_secs" {
        kind: Kind::new(courtesy_delete_give_up_default)
            .strictest(courtesy_delete_give_up_default)
            .higher(),
    };
    /// How long, in seconds, the forward pass may report a WARN for a window whose replay markers
    /// all wait for a project, or the message a project was born from, that this replica does not
    /// hold yet, before raising the GDPR breach ERROR.
    /// One day unless set. Only the owner changes it: an agent's change waits on the owner's
    /// answer to that change, and the owner's standing approval does not cover it.
    /// A row that does not decode reads 0, with no grace period beyond the start second.
    pub(crate) REMAT_DEPENDENCY_HOLD_MAX_SECS: u64 = "sync.remat.dependency_hold_max_secs" {
        kind: Kind::new(remat_dependency_hold_default).strictest(remat_dependency_hold_strictest),
        standing_approval: false,
    };
    /// Whether the owner's delete of a record under a live brief share must go through the
    /// confirmed door, which shows what the delete retracts before it runs. On by default: the
    /// plain delete refuses. Off, the owner's own plain delete revokes the record's live shares
    /// first and goes on as any plain delete does. An agent's delete keeps the confirmed door
    /// (it may stop only a share it issued), and so does a proof-free delete. Off is the looser
    /// value, so only the owner turns it off; a row that does not decode reads on.
    pub(crate) BRIEF_SHARE_REQUIRES_CONFIRMED: bool = "deletion.brief_share.require_confirmed" {
        kind: Kind::new(brief_share_delete_confirmed)
            .strictest(brief_share_delete_confirmed)
            .higher(),
    };
}
