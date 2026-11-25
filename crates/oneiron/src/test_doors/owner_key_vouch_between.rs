//! Door for `tests/owner_key_vouch.rs` (FIX
//! APPOINTMENT-PIN-STEP-AND-VOUCH-ENTRY-FOLD-NO-TEST): the vouch door with a
//! step run between its read, which picks the vouching owner key, and the
//! enrollment's writer, which asks that key for its signature.

use crate::Vault;
use crate::authority::{ActAuthority, OwnerKeyEnrollmentReceipt, OwnerKeyVouchRequest};
use crate::error::Result;

/// [`Vault::enrol_vouched_owner_signing_key`] with `between` run after the
/// door's read picked the vouching key and before the enrollment's writer,
/// where another writer can commit first.
///
/// # Errors
///
/// As [`Vault::enrol_vouched_owner_signing_key`].
pub fn enrol_vouched_owner_signing_key_between(
    vault: &Vault,
    authority: &ActAuthority,
    request: &OwnerKeyVouchRequest,
    between: impl FnOnce(),
) -> Result<OwnerKeyEnrollmentReceipt> {
    vault.enrol_vouched_owner_signing_key_between(authority, request, between)
}
