//! The idle fold's catalogue keys (L2-37 PR-4; RULING L2-37-RULE-D-SETTING = A).

use crate::setting::Kind;

/// The stated default: thirty idle minutes (RULING L2-37-COLD-START = B).
fn half_an_hour() -> u64 {
    1_800
}

/// What an unreadable row reads as: no Keep.
fn no_keep() -> u64 {
    0
}

crate::setting::setting_keys! {
    /// The cold-start keep window, in seconds. When a parked wait's return cell is too thin to
    /// read, the idle call keeps the cached prompt warm through this long from the answer that
    /// cached it, then folds the run's kind marks at the next timer, or lets the prompt expire
    /// when it holds none. 0 keeps nothing.
    pub(crate) COLD_START_KEEP_THROUGH_SECS: u64 = "idle_fold.cold_start_keep_through_secs" {
        kind: Kind::new(half_an_hour).strictest(no_keep),
    };
}
