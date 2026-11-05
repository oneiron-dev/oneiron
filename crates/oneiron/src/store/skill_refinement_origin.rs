//! Core half of `store::skill_refinement_origin`: its store-layer items live in `oneiron_store::skill_refinement_origin` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::skill_refinement_origin::*;

use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;
use crate::store::skill_package::codec::invalid;
use crate::{EntityId, error::Result};

// Permanent candidate origin, keyed only by entity ID. The value is the hash
// of the first native Proposed bytes, never the body or an approval receipt.
pub(crate) const CLAIM_ORIGIN: SideTable<EntityId, [u8; 32], Raw> =
    SideTable::new(&side_table::SKILL_HUB_REFINEMENT_CLAIM_ORIGIN);

pub(crate) const SKILL_ORIGIN: SideTable<EntityId, [u8; 32], Raw> =
    SideTable::new(&side_table::SKILL_HUB_REFINEMENT_SKILL_ORIGIN);

/// The ordinary put chokepoint stages the first native Candidate/Proposed
/// origin after validation, for local and replicated writes alike. Delete
/// never removes these content-free facts.
pub(crate) fn stage_refinement_origin(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    claim: Option<&crate::write_envelope::claim_body::ClaimBody>,
    skill: Option<&crate::write_envelope::skill_record::SkillRecord>,
    data: &[u8],
) -> Result<()> {
    let table = if claim.is_some_and(|body| {
        body.approval == oneiron_contracts::claim::ClaimApprovalStatus::Proposed
            && declares_refinement(body)
    }) {
        CLAIM_ORIGIN
    } else if skill.is_some_and(|record| {
        record.lifecycle_status == crate::write_envelope::skill_record::SkillLifecycle::Candidate
            && declares_skill_refinement(record)
    }) {
        SKILL_ORIGIN
    } else {
        return Ok(());
    };
    let digest = blake3::hash(data);
    if let Some(prior) = table.get(store, txn, id)? {
        if prior != *digest.as_bytes() {
            return Err(invalid("refinement origin changed"));
        }
    } else {
        table.put(store, txn, id, digest.as_bytes())?;
    }
    Ok(())
}
