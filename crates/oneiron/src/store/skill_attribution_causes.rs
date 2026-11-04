//! The ledger of the labels the attribution judge settled on each attempt's
//! terminal outcome (`SKILL_ATTRIBUTION_CAUSE` rows), and the erase that
//! forgets an erased actor or skill on them. Skill attribution
//! (`skill_attribution::causes`) writes and reads the ledger; the row's
//! side-table declaration names its erase hook.
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};

/// One settled label. Key: blake3 of the terminal pack receipt id, then the
/// evidence sequence.
pub(crate) const CAUSES: SideTable<([u8; 32], u64), CauseRow, Named> =
    SideTable::new(&side_table::SKILL_ATTRIBUTION_CAUSE);

/// [`CAUSES`]'s stored row. The label is the judge's stable wire token.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CauseRow {
    pub(crate) source: EntityId,
    pub(crate) sequence: u64,
    pub(crate) receipt: String,
    /// `None` once the actor is erased: the label stays with its receipt.
    pub(crate) actor: Option<EntityId>,
    /// `None` once the skill is erased (FIX 8265), as the actor's slot.
    pub(crate) skill: Option<EntityId>,
    pub(crate) label: String,
    pub(crate) share: f32,
    pub(crate) judge_revision: Option<String>,
    pub(crate) at: u64,
}

/// Forgets erased `entity` on every cause row that names it, in the erase's
/// own write: an actor it executed or a skill it loaded (FIX 8265), each slot
/// nil, and the label stays with its receipt, as a call receipt keeps its row
/// and drops its identity. A later projection keeps the row's identity slots
/// as they are held (`skill_attribution::causes::put_attribution_cause_in_txn`),
/// so it never names either again.
///
/// # Errors
///
/// Storage and codec errors.
pub(crate) fn erase_attribution_cause_entity_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    let mut erased = Vec::new();
    for row in CAUSES.iter_from(&vault.store, wtxn, &[])? {
        let (key, row) = row?;
        if row.actor == Some(*entity) || row.skill == Some(*entity) {
            erased.push((key, row));
        }
    }
    for (key, mut row) in erased {
        if row.actor == Some(*entity) {
            row.actor = None;
        }
        if row.skill == Some(*entity) {
            row.skill = None;
        }
        CAUSES.put(&vault.store, wtxn, &key, &row)?;
    }
    Ok(())
}
