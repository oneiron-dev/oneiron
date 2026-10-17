//! Who is one of this vault's own agents (the Engine lane's ruling,
//! 2026-10-11): an active `agent` binding in this vault's rooted authority
//! fold, or one of its live AGENT_DEF rows. An agent that a contact is About
//! acts for that contact's person, so it is someone else's agent, never the
//! vault's own.

use crate::Vault;
use crate::authority::AuthorityFold;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_AGENT_DEF;
use crate::vault::LiveEntityRow;

/// Whether `member` is one of the vault's own agents as `txn` and its
/// authority `fold` read it.
pub(crate) fn is_vault_agent_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    member: &EntityId,
) -> Result<bool> {
    // A contact's party is no vault agent; contacts are read from their
    // claims (OF-272).
    let contacts = vault.counterparty_contact_ids_for_identity_in_txn(txn, member)?;
    if !contacts.is_empty() {
        return Ok(false);
    }
    if fold.vault_id.is_some() && crate::authority::actor_binding_is_active(fold, member, "agent") {
        return Ok(true);
    }
    Ok(matches!(
        crate::vault::live_entity_row_in_txn(&vault.store, txn, member)?,
        LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_AGENT_DEF,
            ..
        }
    ))
}
