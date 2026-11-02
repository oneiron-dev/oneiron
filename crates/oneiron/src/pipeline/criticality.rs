//! Narrow-only manifest criticality selection at candidate admission, and the
//! critical claims a pack's selection takes first (FIX 9760).
use std::collections::HashSet;

use crate::EntityId;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::StoreRead;
use heed::RoTxn;

pub(super) fn candidate_matches_criticality(
    store: &StoreRead<'_>,
    txn: &RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    selection: Option<bool>,
) -> Result<bool> {
    let Some(selected) = selection else {
        return Ok(true);
    };
    if entity_type != ENTITY_TYPE_CLAIM {
        return Ok(true);
    }
    let Some(raw) = store.port_entity_record(txn, id)?.map(|row| row.encode()) else {
        return Ok(false);
    };
    let Some(body) = raw
        .get(ENTITY_METADATA_HEADER_LEN..)
        .and_then(|bytes| crate::claim::decode_claim_body(bytes, true).ok())
    else {
        return Ok(false);
    };
    let policy = crate::gate::resolve_policy_manifest(store.base(), txn)?;
    Ok((policy.criticality_for_predicate(&body.predicate)
        == crate::gate::PolicyCriticality::Critical)
        == selected)
}

/// The critical claims among `scores`, the admitted candidates of a pack run
/// before any cut: each judged on the body the claim status gate admitted,
/// under the vault's manifest. Other rows, and claims the gate refused, are
/// never critical.
pub(super) fn critical_candidate_ids(
    scores: &[super::types::ScoredEntity],
    claim_gate: &super::types::ClaimStatusGateCache,
    store: &StoreRead<'_>,
    txn: &RoTxn<'_>,
) -> Result<HashSet<EntityId>> {
    let mut critical = HashSet::new();
    if scores.is_empty() {
        return Ok(critical);
    }
    let policy = crate::gate::resolve_policy_manifest(store.base(), txn)?;
    for row in scores {
        if let Some(Some(body)) = claim_gate.decisions.get(&row.id)
            && policy.criticality_for_predicate(&body.predicate)
                == crate::gate::PolicyCriticality::Critical
        {
            critical.insert(row.id);
        }
    }
    Ok(critical)
}
