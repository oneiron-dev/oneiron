//! Canonical contact head collection with deferred fold errors.

use super::{ContactClaimValue, contact_claim_value, duplicate_contact_head_error};
use crate::Vault;
use crate::counterparty_contact::types::COUNTERPARTY_CONTACT_CLAIM_PREDICATES;
use crate::entity_id::EntityId;
use crate::write_envelope::claim_body::{ClaimBodyReadError, ClaimScopeReadMemory};

pub(super) fn contact_claim_values_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    contact_id: &EntityId,
    memory: Option<ClaimScopeReadMemory<'_>>,
) -> std::result::Result<Vec<ContactClaimValue>, ClaimBodyReadError> {
    let mut bodies = Vec::new();
    let mut seen = [false; COUNTERPARTY_CONTACT_CLAIM_PREDICATES.len()];
    let mut duplicate = false;
    let mut retained_value_bytes = 0u64;
    // Keep the first duplicate for the fold, but read every claim so later
    // read errors still take precedence over the duplicate-head error.
    for claim_id in vault.claims_for_subject_in_txn(rtxn, contact_id)? {
        let memory = memory.map(|memory| memory.with_additional_pinned(retained_value_bytes));
        if let Some(body) =
            vault.get_claim_value_head_with_memory_in_txn(rtxn, &claim_id, memory)?
        {
            if duplicate {
                continue;
            }
            let Some(value) = contact_claim_value(body) else {
                continue;
            };
            duplicate = std::mem::replace(&mut seen[value.predicate_index], true);
            if duplicate {
                drop(value);
                drop(std::mem::take(&mut bodies));
                retained_value_bytes = 0;
                continue;
            }
            retained_value_bytes =
                retained_value_bytes.saturating_add(value.value.retained_bytes());
            bodies.push(value);
        }
    }
    if duplicate {
        return Err(duplicate_contact_head_error().into());
    }
    Ok(bodies)
}
