//! Damage one stored share entity row and one stored sharedInvitation row in
//! place, past every write door, so a slip test reads how the slip liveness
//! doors report store damage (RATCHET-9413 review round 2): a share-bound
//! slip over an undecodable share header, and an invitation-bound slip over
//! an undecodable stored invitation, are the vault failing to answer (a
//! store fault), never the slip's refusal. A missing invitation row stays a
//! refusal.

use crate::ports::EntityStoreRead;
use crate::side_table::{self, Raw, SideTable};
use crate::{EntityId, Error, Result, Vault};

const INVITATIONS: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::SHARED_VAULT_INVITATION);

/// Truncates the stored entity row `share` names to three bytes, past every
/// write door, so its entity header no longer decodes. Only the entity row
/// is touched; the share admission row stays as it was.
///
/// # Errors
///
/// No row is stored under `share`, or the store refuses the write.
pub fn truncate_share_entity(vault: &Vault, share: EntityId) -> Result<()> {
    vault.with_write_txn(|txn| {
        let raw = vault
            .store
            .port_entity_record(txn, &share)?
            .map(|row| row.encode())
            .ok_or(Error::InvariantViolation(
                "no stored entity row for the share",
            ))?;
        let end = raw.len().min(3);
        vault
            .store
            .entities
            .put(txn, share.as_bytes(), &raw[..end])?;
        Ok(())
    })
}

/// Overwrites `invitee`'s stored invitation `invitation_id` row with `bytes`,
/// past every write door, so it no longer decodes as an invitation.
///
/// # Errors
///
/// A malformed invitation id, or the store refuses the write.
pub fn overwrite_invitation_row(
    vault: &Vault,
    invitee: EntityId,
    invitation_id: &str,
    bytes: &[u8],
) -> Result<()> {
    let key = format!(
        "{}:{}",
        invitee.to_hex(),
        EntityId::from_hex(invitation_id)?.to_hex()
    );
    vault.with_write_txn(|txn| {
        INVITATIONS.put(&vault.store, txn, &key, &bytes.to_vec())?;
        Ok(())
    })
}

/// Deletes `invitee`'s stored invitation `invitation_id` row, past every
/// write door.
///
/// # Errors
///
/// A malformed invitation id, or the store refuses the write.
pub fn delete_invitation_row(vault: &Vault, invitee: EntityId, invitation_id: &str) -> Result<()> {
    let key = format!(
        "{}:{}",
        invitee.to_hex(),
        EntityId::from_hex(invitation_id)?.to_hex()
    );
    vault.with_write_txn(|txn| {
        INVITATIONS.delete(&vault.store, txn, &key)?;
        Ok(())
    })
}
