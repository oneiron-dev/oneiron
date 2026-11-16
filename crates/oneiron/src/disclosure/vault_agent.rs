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

impl Vault {
    /// Whether a credential held by `holder` as `actor_class` reads as one of
    /// the vault's own agents reading on its own, as `txn` reads it (RULING
    /// L5-02-UNNAMED-HOME = A): an `agent` holder that is one of the vault's
    /// own agents ([`is_vault_agent_in`]), on a credential not `transferred`
    /// to it. A transferred slip is another holder's, acting on the agent's
    /// word, so it is not the agent reading on its own.
    pub(crate) fn own_agent_credential_in(
        &self,
        txn: &heed::RoTxn<'_>,
        holder: &EntityId,
        actor_class: Option<&str>,
        transferred: bool,
    ) -> Result<bool> {
        if actor_class != Some("agent") || transferred {
            return Ok(false);
        }
        let fold = self.authority_fold_readonly_in_txn(txn)?;
        is_vault_agent_in(self, txn, &fold, holder)
    }

    /// Whether `member` is one of this vault's own agents, read in one
    /// snapshot ([`is_vault_agent_in`]). A route that has only a principal id
    /// asks this, as the conversation-home default does (RULING
    /// L5-02-UNNAMED-HOME = A: the vault's own agents read as homed here).
    pub fn is_vault_agent(&self, member: &EntityId) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_fold_readonly_in_txn(&txn)?;
        is_vault_agent_in(self, &txn, &fold, member)
    }
}
