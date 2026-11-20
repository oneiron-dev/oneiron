//! The setting keys `deletion` declares (DESIGN 15-setting-primitive): the crate's build script
//! lists each row in the setting catalogue.

use crate::setting::{Kind, higher_is_tighter, lower_is_tighter};

/// On: a delete under a live brief share goes through the confirmed door.
const fn brief_share_delete_confirmed() -> bool {
    true
}

/// Seven days: how long an undelivered courtesy-delete leg retried before this key.
const fn courtesy_delete_give_up_default() -> u64 {
    super::COOP_DELETION_GIVE_UP_SECS
}

crate::setting::setting_keys! {
    /// How long, in seconds, an undelivered courtesy-delete leg keeps retrying before it is
    /// `unreachable`. Seven days unless the owner sets it. The wait between tries stays one
    /// minute to six hours, growing with the leg's age; 0 makes the first failed try final. A
    /// longer time is the looser value, so only the owner raises it; a row that does not decode
    /// reads seven days.
    pub(crate) COOP_DELIVERY_GIVE_UP_SECS: u64 = "deletion.coop_delivery.give_up_secs" {
        kind: Kind::new(courtesy_delete_give_up_default)
            .strictest(courtesy_delete_give_up_default)
            .tighter(lower_is_tighter::<u64>),
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
            .tighter(higher_is_tighter::<bool>),
    };
}
