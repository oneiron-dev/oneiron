//! The Gmail seats on a vault (FIX 1168): every delegated `email` row, each
//! with the adapter its own row describes. A delegated mailbox's custody is
//! `connector:gmail`-bound by the grant schema, so every such row is a Gmail
//! seat. Entry: [`active_gmail_seats`]. Defines its own items.

use super::*;
use crate::channel_identity_provider::member_mail::member_mail_identity_in_txn;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_CHANNEL_IDENTITY;

impl GmailDelegatedAdapter {
    /// The adapter the delegated `email` row at `identity_id` describes: its
    /// mailbox, its custody record and its granted scopes, reading under the
    /// default placement policy. `None` when the id names no delegated
    /// `email` row. The row's state is the doors' own question.
    ///
    /// # Errors
    ///
    /// Store failure, or a stored mailbox or custody name the config refuses.
    pub fn for_delegated_identity(vault: &Vault, identity_id: EntityId) -> Result<Option<Self>> {
        let txn = vault.store.env.read_txn()?;
        let Some(row) = member_mail_identity_in_txn(&vault.store, &txn, identity_id)? else {
            return Ok(None);
        };
        let Some(grant) = row.custody.grant() else {
            return Ok(None);
        };
        let mut config = GmailDelegatedAdapterConfig::new(
            row.facts.address_or_handle.as_str(),
            grant.custody_record_ref.as_str(),
        )?;
        config.scopes.clone_from(&grant.scopes);
        Ok(Some(Self::new(config)))
    }
}

/// Every Gmail seat on `vault` whose row is ACTIVE now, in id order.
///
/// # Errors
///
/// Store failure or an undecodable identity row.
pub fn active_gmail_seats(vault: &Vault) -> Result<Vec<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    let mut active = Vec::new();
    for entry in vault
        .store
        .port_entity_ids_by_type(&txn, ENTITY_TYPE_CHANNEL_IDENTITY, None)?
    {
        let identity = entry?;
        if member_mail_identity_in_txn(&vault.store, &txn, identity)?
            .is_some_and(|row| row.facts.state == ChannelIdentityState::Active)
        {
            active.push(identity);
        }
    }
    Ok(active)
}
