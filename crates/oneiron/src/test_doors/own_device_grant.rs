//! Door for `tests/opened_device_admits_owner_slip.rs` (FIX 23747): an
//! owner's own-device grants retired, as a membership change that ends the
//! member's Owner standing retires them (FIX 3294).

use crate::error::Result;
use crate::{EntityId, Vault};

/// Retires `member`'s live own-device grants in one writer, as a role change
/// that ends their Owner standing does, and returns the grants' ids.
pub fn retire_own_device_grants(vault: &Vault, member: EntityId) -> Result<Vec<EntityId>> {
    vault.with_write_txn(|wtxn| vault.retire_own_device_grants_in_txn(wtxn, member))
}
