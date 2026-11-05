//! Owner-only retained held-edit evidence from the sync quarantine.

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::memory::MemoryResult;
use crate::sync::QuarantineRecord;

use super::EmptyRequest;

/// Lists retained hash-only evidence, not live pending work or settlement.
pub fn sync_quarantine_held_edits_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    _input: EmptyRequest,
) -> MemoryResult<Vec<(u64, QuarantineRecord)>> {
    Ok(vault.held_edits_as_owner(owner)?)
}
