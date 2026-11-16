//! The setting keys `commitment_wake` declares (Setting stage 1): the crate's build script lists
//! each row in the setting catalogue.

use super::reminder::CommitmentReminderRoute;
use crate::setting::Kind;

fn no_route() -> Option<CommitmentReminderRoute> {
    None
}

crate::setting::setting_keys! {
    /// Where the owner's own commitment reminders go, and the owner's civil clock for their
    /// delivery windows (OF-187). Unset until the owner sets it: canon picks no default channel
    /// (ARCH-0046), so an owner's promise with no route proposes no reminder. Setting it approves
    /// no reminder and changes none already approved.
    pub(crate) REMINDER_ROUTE: Option<CommitmentReminderRoute> = "commitments.reminder_route" {
        kind: Kind::new(no_route),
    };
}
