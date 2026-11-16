//! Whether a PERSON is an agent, for the readers that let only a human's
//! words wake a resident or count as a person's (FIX
//! RESIDENT-HUMANMESSAGES-ADMITS-AGENTS).

use super::{PersonSubstrate, person_substrate_in_txn};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_PERSON;

/// Whether the live PERSON `person_ref` is an agent at caller time `at`, in
/// the caller's snapshot: a PERSON of model substrate (each AGENT_DEF's own
/// person, a brought companion), or the principal PERSON of a named agent
/// (`Vault::ensure_agent_principal`), which carries no substrate claim. A
/// PERSON merged into either is that agent: both checks read the one
/// canonical PERSON the ref resolves to (REVIEW-9173 P1). Any other PERSON is
/// no agent. `Err` when its substrate does not read: an ambiguous identity or
/// a malformed claim. Every agent is a PERSON, so the substrate, not the
/// entity type, tells a human.
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
        && let crate::vault::LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_PERSON,
            body,
        } = crate::vault::live_entity_row_in_txn(&vault.store, txn, canonical)?
        && crate::vault::is_named_agent_principal_body(canonical, &body)
    {
        return Ok(true);
    }
    Ok(person_substrate_in_txn(vault, txn, person_ref, at)? == Some(PersonSubstrate::Model))
}
