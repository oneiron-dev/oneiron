//! The fold's grant lines and the Grant standing read (Fable pass 28 R1): what the counted
//! acts say of a FEDERATION_GRANT row, and whether the row stands on them.

use crate::authority::GrantFamily;
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Result, Vault};

/// The counted act the owner's agent Grant row `grant` stands on at `now`
/// (`Vault::standing_grant_in_txn`); `None` when the row does not stand as his agent Grant.
///
/// # Errors
///
/// A store or authority-fold read failure.
pub fn standing_grant_act(vault: &Vault, grant: EntityId, now: u64) -> Result<Option<[u8; 32]>> {
    standing_act_in_family(vault, grant, GrantFamily::OwnerAgent, now)
}

/// The counted act the shared vault member row `grant` stands on at `now`; `None` when the
/// row does not stand as a member's Grant.
///
/// # Errors
///
/// A store or authority-fold read failure.
pub fn standing_member_grant_act(
    vault: &Vault,
    grant: EntityId,
    now: u64,
) -> Result<Option<[u8; 32]>> {
    standing_act_in_family(vault, grant, GrantFamily::SharedMember, now)
}

fn standing_act_in_family(
    vault: &Vault,
    grant: EntityId,
    family: GrantFamily,
    now: u64,
) -> Result<Option<[u8; 32]>> {
    let txn = vault.store.env.read_txn()?;
    Ok(vault
        .standing_grant_in_txn(&txn, grant, family, now)?
        .map(|standing| *standing.act()))
}

/// What the fold says of `grant` on this install: the act of the one giving that counts here,
/// if any, and whether a counted act ended it. `None` when no counted act names it.
///
/// # Errors
///
/// A store or authority-fold read failure.
pub fn grant_line(vault: &Vault, grant: EntityId) -> Result<Option<(Option<[u8; 32]>, bool)>> {
    let txn = vault.store.env.read_txn()?;
    let fold = vault.authority_view_readonly_in_txn(&txn)?;
    Ok(fold
        .grant_line(grant)
        .map(|line| (line.giving.as_ref().map(|(act, _)| *act), line.ended)))
}

/// The live FEDERATION_GRANT body at `id`; `None` when no live Grant row is there.
///
/// # Errors
///
/// A store read failure.
pub fn grant_row(vault: &Vault, id: EntityId) -> Result<Option<Vec<u8>>> {
    let txn = vault.store.env.read_txn()?;
    Ok(match live_entity_row_in_txn(&vault.store, &txn, &id)? {
        LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_FEDERATION_GRANT,
            body,
        } => Some(body),
        _ => None,
    })
}
