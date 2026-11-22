//! The shared-vault invitation rows, for the invitation actor-erase test:
//! the invitation and invitation-key rows that hold a person's id, and the
//! key row an invitee binds, which the test writes in the form an owner's
//! invitation pairing code leaves (`Vault::redeem_invitation_link_in_txn`: a
//! key with no source slip).

use crate::side_table::{self, Raw, SideTable};
use crate::{EntityId, Result, Vault};

const INVITATIONS: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::SHARED_VAULT_INVITATION);
const INVITATION_KEYS: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::SHARED_VAULT_INVITATION_KEY);

/// `table:key` of each invitation or invitation-key row whose key or stored
/// bytes hold `person`'s hex.
///
/// # Errors
/// The scan's.
#[doc(hidden)]
pub fn rows_naming(vault: &Vault, person: EntityId) -> Result<Vec<String>> {
    let hex = person.to_hex();
    let txn = vault.store.env.read_txn()?;
    let mut found = Vec::new();
    for (name, table) in [
        ("invitation", INVITATIONS),
        ("invitation_key", INVITATION_KEYS),
    ] {
        for (key, row) in table.scan(&vault.store, &txn)? {
            if key.contains(&hex) || row.windows(hex.len()).any(|bytes| bytes == hex.as_bytes()) {
                found.push(format!("{name}:{key}"));
            }
        }
    }
    Ok(found)
}

/// Binds `invitee`'s invitation `invitation_id` to `holder_key`, with no
/// source slip, as a redeemed invitation pairing code binds it.
///
/// # Errors
/// A malformed invitation id, or the write's.
#[doc(hidden)]
pub fn bind_invitation_key(
    vault: &Vault,
    invitee: EntityId,
    invitation_id: &str,
    holder_key: [u8; 32],
) -> Result<()> {
    let key = format!(
        "{}:{}",
        invitee.to_hex(),
        EntityId::from_hex(invitation_id)?.to_hex()
    );
    let mut txn = vault.store.env.write_txn()?;
    INVITATION_KEYS.put(&vault.store, &mut txn, &key, &holder_key.to_vec())?;
    txn.commit()?;
    Ok(())
}
