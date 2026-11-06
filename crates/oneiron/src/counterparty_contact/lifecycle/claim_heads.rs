//! Canonical contact head collection with deferred fold errors.

use super::{
    ContactClaimValue, contact_claim_value, duplicate_contact_head_error,
    missing_contact_head_error,
};
use crate::Vault;
use crate::counterparty_contact::codec::{
    CounterpartyContactScalarHeads, counterparty_contact_body_key, validate_contact_notes_value,
};
use crate::counterparty_contact::read_memory::{
    CounterpartyContactLabelRead, CounterpartyContactRead,
};
use crate::counterparty_contact::storage::contact_deleted_in_txn;
use crate::counterparty_contact::types::{COUNTERPARTY_CONTACT_CLAIM_PREDICATES, KEY_NOTES};
use crate::entity_id::EntityId;
use crate::write_envelope::claim_body::{ClaimBodyReadError, ClaimScopeReadMemory};

pub(super) struct ContactClaimHeads {
    bodies: Vec<ContactClaimValue>,
    scalars: CounterpartyContactScalarHeads,
    seen: [bool; COUNTERPARTY_CONTACT_CLAIM_PREDICATES.len()],
    notes_validation: Option<crate::Result<()>>,
}

impl ContactClaimHeads {
    pub(super) fn is_empty(&self) -> bool {
        !self.seen.iter().any(|seen| *seen)
    }

    pub(super) fn into_label_read(self) -> crate::Result<CounterpartyContactLabelRead> {
        if self.seen.iter().any(|seen| !seen) {
            return Err(missing_contact_head_error());
        }
        let counterparty = self
            .bodies
            .into_iter()
            .next()
            .expect("complete contact label head");
        CounterpartyContactLabelRead::from_staged_head(
            counterparty.value,
            self.scalars,
            self.notes_validation
                .expect("complete contact notes validation"),
        )
    }

    pub(super) fn into_read(self) -> crate::Result<CounterpartyContactRead> {
        if self.seen.iter().any(|seen| !seen) {
            return Err(missing_contact_head_error());
        }
        let mut heads = std::array::from_fn(|_| None);
        for body in self.bodies {
            heads[body.predicate_index] = Some(body.value);
        }
        CounterpartyContactRead::from_staged_heads(heads, self.scalars)
    }
}

pub(in crate::counterparty_contact) fn counterparty_contact_label_with_memory_in_claims_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    contact_id: &EntityId,
    memory: Option<ClaimScopeReadMemory<'_>>,
) -> std::result::Result<Option<CounterpartyContactLabelRead>, ClaimBodyReadError> {
    if contact_deleted_in_txn(&vault.store, rtxn, contact_id)? {
        return Ok(None);
    }
    let bodies = contact_claim_values_in_txn(vault, rtxn, contact_id, memory, false)?;
    if bodies.is_empty() {
        return Ok(None);
    }
    let mut record = bodies.into_label_read()?;
    let (counterparty, state) = record.fold_fields();
    vault
        .store
        .record_hooks
        .fold_party_opt_out_heads_in_txn(vault, rtxn, counterparty, state)?;
    Ok(Some(record))
}

pub(super) fn contact_claim_values_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    contact_id: &EntityId,
    memory: Option<ClaimScopeReadMemory<'_>>,
    retain_notes: bool,
) -> std::result::Result<ContactClaimHeads, ClaimBodyReadError> {
    let mut bodies = Vec::new();
    let mut scalars = CounterpartyContactScalarHeads::default();
    let mut seen = [false; COUNTERPARTY_CONTACT_CLAIM_PREDICATES.len()];
    let mut duplicate = false;
    let mut retained_value_bytes = 0u64;
    let mut notes_validation = None;
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
                scalars = CounterpartyContactScalarHeads::default();
                retained_value_bytes = 0;
                notes_validation = None;
                continue;
            }
            let key = counterparty_contact_body_key(
                COUNTERPARTY_CONTACT_CLAIM_PREDICATES[value.predicate_index],
            );
            if scalars.stage(key, &value.value) {
                drop(value);
                continue;
            }
            if !retain_notes && key == KEY_NOTES {
                notes_validation = Some(validate_contact_notes_value(&value.value));
                drop(value);
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
    Ok(ContactClaimHeads {
        bodies,
        scalars,
        seen,
        notes_validation,
    })
}
