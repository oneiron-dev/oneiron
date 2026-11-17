//! Whether a PERSON is an agent, for the readers that let only a human's
//! words wake a resident or count as a person's (FIX
//! RESIDENT-HUMANMESSAGES-ADMITS-AGENTS).

use std::collections::BTreeSet;

use super::{PersonSubstrate, person_substrate_in_txn};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_PERSON;

/// Whether the live PERSON `person_ref` is an agent at caller time `at`, in
/// the caller's snapshot: a PERSON of model substrate (each AGENT_DEF's own
/// person, a brought companion), or the principal PERSON of a named agent
/// (`Vault::ensure_agent_principal`), which carries no substrate claim. A
/// merge makes one identity of both sides, so a PERSON merged with a named
/// agent's principal is that agent whichever side survived: the check reads
/// the one canonical PERSON the ref resolves to and every shell merged into
/// it (REVIEW-9173 rounds 1 and 2), as the substrate read does. Any other
/// PERSON is no agent. `Err` when its identity or substrate does not read:
/// an ambiguous identity, a split shell of a named agent that names more
/// people than this one, or a malformed claim. Every agent is a PERSON, so
/// the substrate, not the entity type, tells a human.
pub(crate) fn person_is_agent_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    person_ref: &EntityId,
    at: u64,
) -> Result<bool> {
    // An ambiguous identity names no one canonical PERSON here; the
    // substrate read below refuses it.
    let resolved = vault.resolve_entity_in_txn(txn, person_ref)?;
    if let [canonical] = resolved.as_slice()
        && is_named_agent_identity_in_txn(vault, txn, canonical)?
    {
        return Ok(true);
    }
    Ok(person_substrate_in_txn(vault, txn, person_ref, at)? == Some(PersonSubstrate::Model))
}

/// Whether `canonical` (a resolved head) or a shell merged into it is a named
/// agent's principal PERSON. A split shell that also names other people
/// cannot make this one an agent, and cannot be ruled out either: `Err`.
fn is_named_agent_identity_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    canonical: &EntityId,
) -> Result<bool> {
    let mut subjects = crate::identity_redirect::inbound_redirect_shells_in_txn(
        &vault.store,
        txn,
        &BTreeSet::from([*canonical]),
    )?;
    subjects.insert(*canonical);
    for subject in subjects {
        let crate::vault::LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_PERSON,
            body,
        } = crate::vault::live_entity_row_in_txn(&vault.store, txn, &subject)?
        else {
            continue;
        };
        if !crate::vault::is_named_agent_principal_body(&subject, &body) {
            continue;
        }
        let heads = vault.resolve_entity_in_txn(txn, &subject)?;
        if heads.as_slice() == [*canonical] {
            return Ok(true);
        }
        if heads.contains(canonical) {
            return Err(Error::InvalidClaimBody(
                "a named agent's split shell names more than one PERSON",
            ));
        }
    }
    Ok(false)
}
