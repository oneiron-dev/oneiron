//! Doors for `tests/root_appointment_verdict.rs` (OWNER-ANCHOR-ROOT-RECOVERY
//! parts (a) and (b1)): the reference fold of a vault's own log under a pin,
//! which the appointment judge reads, and the stored-log fold whole and
//! resumed from a base, and whether a fold holds a key in the host's custody
//! (PLAN v3 test 16). For `tests/owner_anchor_appointment.rs` (part (b2)):
//! the appointment door with a step run between its read-only check and its
//! writer.

use crate::Vault;
use crate::authority::{
    AuthorityFold, AuthorityKey, AuthorityLogEntry, PinnedRoot, RootAppointmentReceipt,
    fold_own_authority_log,
};
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::world_keys::{KitConfirmation, RecoveryRootSeed};

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

/// Whether `fold` holds `key` in the host's custody: a key the roster marks
/// as the host's, or one such a key admitted, directly or through others.
#[must_use]
pub fn in_host_custody(fold: &AuthorityFold, key: &AuthorityKey) -> bool {
    fold.in_host_custody(key)
}

/// [`Vault::appoint_owner_root`] with `between` run after the door's
/// read-only check and before its writer, where another run of the door can
/// commit first.
///
/// # Errors
///
/// As [`Vault::appoint_owner_root`].
pub fn appoint_owner_root_between(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    seed: &RecoveryRootSeed,
    confirm: Option<KitConfirmation>,
    between: impl FnOnce(),
) -> Result<RootAppointmentReceipt> {
    vault.appoint_owner_root_between(owner, seed, confirm, between)
}
