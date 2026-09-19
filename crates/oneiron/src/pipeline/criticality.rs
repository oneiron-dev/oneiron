//! Narrow-only manifest criticality selection at candidate admission.
use crate::EntityId;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::Store;
use heed::RoTxn;

pub(super) fn candidate_matches_criticality(
    store: &Store,
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
    let Some(raw) = store.port_entity_record(txn, &id)?.map(|row| row.encode()) else {
        return Ok(false);
    };
    let Some(body) = raw
        .get(ENTITY_METADATA_HEADER_LEN..)
        .and_then(|bytes| crate::claim::decode_claim_body(bytes, true).ok())
    else {
        return Ok(false);
    };
    let policy = crate::gate::resolve_policy_manifest(store, txn)?;
    Ok((policy.criticality_for_predicate(&body.predicate)
        == crate::gate::PolicyCriticality::Critical)
        == selected)
}
