//! Site-skill exposures (FIX 11436): the site knowledge a run's browser was shown.
//!
//! Site knowledge delivered on an observation is not a `TaskExposure` byte
//! span, so a contribution check that finds no span for its target reads
//! here instead. One row per skill per observation; a run's rows for one
//! skill share a key prefix.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};

/// `(run, skill, rest)`: the run that was shown the knowledge, the skill it
/// came from, and `be64(seq)` plus the first 8 bytes of `blake3(scope)`.
type SiteExposureKey = ([u8; 16], [u8; 16], Vec<u8>);

const SITE_EXPOSURES: SideTable<SiteExposureKey, SiteSkillExposure, Named> =
    SideTable::new(&side_table::SKILL_ATTRIBUTION_SITE_EXPOSURE);

/// One skill's site knowledge a run's browser was shown on observation
/// `seq` of `scope`; it has no byte span in the run's task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteSkillExposure {
    pub run: EntityId,
    pub scope: String,
    pub seq: u64,
    pub skill: EntityId,
    pub revision: String,
    pub content_hash: [u8; 32],
    pub at: u64,
}

impl SiteSkillExposure {
    /// The exposure of `knowledge` shown to `run` on observation `seq` of
    /// `scope`; `None` when `skill_id` names no skill id.
    #[must_use]
    pub fn delivered(
        run: EntityId,
        scope: &str,
        seq: u64,
        skill_id: &str,
        revision: &str,
        knowledge: &str,
        at: u64,
    ) -> Option<Self> {
        let skill = EntityId::from_hex(skill_id).ok()?;
        Some(Self {
            run,
            scope: scope.to_owned(),
            seq,
            skill,
            revision: revision.to_owned(),
            content_hash: *blake3::hash(knowledge.as_bytes()).as_bytes(),
            at,
        })
    }

    fn key(&self) -> SiteExposureKey {
        let mut rest = self.seq.to_be_bytes().to_vec();
        rest.extend_from_slice(&blake3::hash(self.scope.as_bytes()).as_bytes()[..8]);
        (*self.run.as_bytes(), *self.skill.as_bytes(), rest)
    }
}

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
    for (key, row) in super::skill_erase::erase_scan_in_txn(vault, wtxn, SITE_EXPOSURES)? {
        if row.run == *entity || row.skill == *entity {
            SITE_EXPOSURES.delete(&vault.store, wtxn, &key)?;
        }
    }
    Ok(())
}
