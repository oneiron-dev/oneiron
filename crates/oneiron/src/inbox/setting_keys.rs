//! The setting keys `inbox` declares (Setting stage 1): the crate's build script lists each row
//! in the setting catalogue.

use super::InboxReviewDial;
use crate::setting::Kind;

crate::setting::setting_keys! {
    /// Which inbox rows surface for the owner's review: only the exceptions (a checker hedge, a
    /// manifest-critical row, a supersede of what the owner stated, a conflict), every open
    /// member, or none beyond the manifest-critical rows, which no position waives
    /// (OF-234). Exceptions only unless the owner sets it.
    pub(crate) REVIEW_DIAL: InboxReviewDial = "inbox.review_dial" {
        kind: Kind::new(InboxReviewDial::default),
    };
}
