//! Resident ownership storage and loaded-skill erasure.

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::skill_resident::LOADED_SKILL;

pub(crate) use crate::store::skill_resident::{
    RESIDENT_PROVENANCE_KEY, bind_receipt_in_txn, bind_skill_in_txn, check_owner_marker_in_txn,
    receipt_loaded_skill, receipt_resident, receipt_resident_in_txn, require_resident_in_txn,
    resident_of, validate_owner_put_in_txn,
};

/// Deletes every loaded-skill marker of erased skill `entity` (FIX 8988):
/// a pending load mark whose authority ended with the skill. A row that no
/// longer decodes is deleted and counted.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_resident_loaded_skill_in_txn(
    vault: &crate::Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    for (key, _) in crate::skill_attribution::erase_scan_in_txn(vault, wtxn, LOADED_SKILL)? {
        if key.skill == *entity {
            LOADED_SKILL.delete(&vault.store, wtxn, &key)?;
        }
    }
    Ok(())
}
