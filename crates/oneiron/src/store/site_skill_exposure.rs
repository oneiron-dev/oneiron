//! Site-skill exposures (FIX 11436): the site knowledge a run's browser was shown.
//!
//! Site knowledge delivered on an observation is not a `TaskExposure` byte
//! span, so a contribution check that finds no span for its target reads
//! here instead. One row per skill per observation; a run's rows for one
//! skill share a key prefix. Skill attribution (`skill_attribution`) records
//! and reads them through its re-exports; the row's side-table declaration
//! names its erase hook.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};

#[doc(hidden)]
use oneiron_records::store::site_skill_exposure::SiteExposureKey;
#[doc(hidden)]
pub use oneiron_records::store::site_skill_exposure::SiteSkillExposure;

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
