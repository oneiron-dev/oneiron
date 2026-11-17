//! Doors for `tests/root_appointment_verdict.rs` (OWNER-ANCHOR-ROOT-RECOVERY
//! part (a)): the reference fold of a vault's own log under a pin, which the
//! appointment judge reads.

use crate::authority::{AuthorityFold, AuthorityLogEntry, PinnedRoot, fold_own_authority_log};

/// The fold of `entries` as a self-hosted install that pins `pin` folds its
/// own log, with no seen-times.
#[must_use]
pub fn fold_under_pin(entries: &[AuthorityLogEntry], pin: Option<&PinnedRoot>) -> AuthorityFold {
    fold_own_authority_log(entries, crate::HostingPrivacyPosture::SelfHostLocal, pin)
}
