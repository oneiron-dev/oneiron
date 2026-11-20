//! Door for the read behind the fragile-genesis flag
//! (`Vault::genesis_fragile_now`; FIX GENESIS-FRAGILE-START-SCANS-AUTHORITY-LOG):
//! whether a vault keeps a valid enrolment of a live owner key, and how much
//! of its stored authority log the search read. For
//! `tests/owner_key_enrolment_read.rs`. Compiled only under
//! `--cfg oneiron_test_support`; never API.

use crate::authority::AuthorityEntryHash;
use crate::{Result, Vault};

/// What the search for a live owner key enrolment answered, and what it
/// read.
pub struct LiveOwnerKeyEnrolmentRead {
    /// Whether the vault keeps a valid enrolment of an owner key that is
    /// live on its roster now.
    pub enrolled: bool,
    /// The stored authority log rows the search read before it answered.
    pub rows_read: usize,
    /// The hash of every stored authority log row, in the order the search
    /// reads them.
    pub stored: Vec<AuthorityEntryHash>,
}

/// Runs the search on `vault` as it stands now.
///
/// # Errors
///
/// Storage and fold faults.
pub fn live_owner_key_enrolment_read(vault: &Vault) -> Result<LiveOwnerKeyEnrolmentRead> {
    let (enrolled, rows_read, stored) = vault.live_owner_key_enrolment_read_for_test()?;
    Ok(LiveOwnerKeyEnrolmentRead {
        enrolled,
        rows_read,
        stored,
    })
}
