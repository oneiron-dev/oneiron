//! Doors for `tests/root_appointment_verdict.rs` (OWNER-ANCHOR-ROOT-RECOVERY
//! parts (a) and (b1)): the reference fold of a vault's own log under a pin,
//! which the appointment judge reads, and the stored-log fold whole and
//! resumed from a base.

use crate::authority::{AuthorityFold, AuthorityLogEntry, PinnedRoot, fold_own_authority_log};

/// The fold of `entries` as a self-hosted install that pins `pin` folds its
/// own log, with no seen-times.
#[must_use]
pub fn fold_under_pin(entries: &[AuthorityLogEntry], pin: Option<&PinnedRoot>) -> AuthorityFold {
    fold_own_authority_log(entries, crate::HostingPrivacyPosture::SelfHostLocal, pin)
}

/// The stored-log fold of `entries` as a self-hosted install that pins `pin`
/// folds it, every row first seen at second 1 and the fold at second 2 under
/// a stale-roster window of `window_secs`: whole, and resumed from the base
/// the fold of the first `base_len` rows keeps (None where the resumed fold
/// declines the rest and the install folds the whole log).
///
/// # Panics
///
/// When `base_len` passes the end of `entries`.
#[must_use]
pub fn whole_and_resumed_folds(
    entries: &[AuthorityLogEntry],
    base_len: usize,
    pin: Option<&PinnedRoot>,
    window_secs: u64,
) -> (AuthorityFold, Option<AuthorityFold>) {
    crate::authority::whole_and_resumed_folds_for_test(entries, base_len, pin, window_secs)
}
