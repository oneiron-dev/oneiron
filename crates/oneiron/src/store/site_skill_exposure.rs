//! Core half of `store::site_skill_exposure`: its store-layer items live in `oneiron_store::site_skill_exposure` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::site_skill_exposure::*;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use serde::{Deserialize, Serialize};

const SITE_EXPOSURES: SideTable<SiteExposureKey, SiteSkillExposure, Named> =
    SideTable::new(&side_table::SKILL_ATTRIBUTION_SITE_EXPOSURE);

/// Records `rows` in one write of its own; an empty slice writes nothing.
pub fn record_site_exposures(vault: &Vault, rows: &[SiteSkillExposure]) -> Result<()> {
    if rows.is_empty() {
        return Ok(());
    }
    vault.with_write_txn(|wtxn| {
        for row in rows {
            SITE_EXPOSURES.put(&vault.store, wtxn, &row.key(), row)?;
        }
        Ok(())
    })
}

/// Whether any row shows `skill`'s site knowledge to `run`, read in a read
/// transaction of its own.
pub fn site_exposed(vault: &Vault, run: EntityId, skill: EntityId) -> Result<bool> {
    let rtxn = vault.store.env.read_txn()?;
    let mut prefix = Vec::with_capacity(32);
    prefix.extend_from_slice(run.as_bytes());
    prefix.extend_from_slice(skill.as_bytes());
    let found = SITE_EXPOSURES
        .iter_raw_from(&vault.store, &rtxn, &prefix)?
        .next()
        .transpose()?
        .is_some();
    Ok(found)
}

/// Deletes every row whose run or skill is erased `entity`.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_site_exposure_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    for (key, row) in
        crate::store::side_table_erase_scan::erase_scan_in_txn(vault, wtxn, SITE_EXPOSURES)?
    {
        if row.run == *entity || row.skill == *entity {
            SITE_EXPOSURES.delete(&vault.store, wtxn, &key)?;
        }
    }
    Ok(())
}
