//! The skill-attribution outcome-evidence rows (`SKILL_ATTRIBUTION_EVIDENCE`,
//! FIX 8265), keyed by sequence, and the erase that forgets an erased skill
//! or actor in them (FIX 8988). The attribution ledger
//! (`skill_attribution::{codec, projector, positive}`) encodes, writes and
//! reads them; the side-table declaration's erase hook calls the erase.
use oneiron_skill_attribution::types::OutcomeEvidence;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Raw, SideTable};
use crate::store::side_table_erase_scan::erase_scan_in_txn;

/// One recorded outcome-evidence row, keyed by sequence. The sequence is
/// stored redundantly inside the MessagePack map as well as in the key
/// (`encode_evidence` takes it as a separate argument), so the value type
/// carries it too — that IS the row's existing byte layout.
pub(crate) struct EvidenceRow {
    pub(crate) sequence: u64,
    pub(crate) evidence: OutcomeEvidence,
}

/// One recorded outcome-evidence row awaiting attribution routing. Key: u64be sequence.
pub(crate) const EVIDENCE: SideTable<u64, EvidenceRow, Raw> =
    SideTable::new(&side_table::SKILL_ATTRIBUTION_EVIDENCE);

/// Forgets erased `entity` as the skill or the actor of every evidence row
/// that names it.
///
/// # Errors
///
/// Storage and codec errors.
pub(crate) fn erase_attribution_evidence_skill_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    for (sequence, mut row) in erase_scan_in_txn(vault, wtxn, EVIDENCE)? {
        let skill = row.evidence.skill == Some(*entity);
        let actor = row.evidence.actor == Some(*entity);
        if !skill && !actor {
            continue;
        }
        if skill {
            row.evidence.skill = None;
        }
        if actor {
            row.evidence.actor = None;
        }
        EVIDENCE.put(&vault.store, wtxn, &sequence, &row)?;
    }
    Ok(())
}
