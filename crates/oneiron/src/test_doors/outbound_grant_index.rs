//! Doors for `tests/outbound_grant_index.rs` (census L3-28A): the by-id and
//! by-principal reads of standing outbound grants as the indexes answer them
//! and as the full scan answers them, a mint of many grants in one write
//! transaction, and the indexes' drop and completeness flag.

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::genui::GrantMintIntentScope;
use crate::outbound_grant::{StandingOutboundGrant, StandingOutboundGrantScope};

/// The grants `principal_ref` holds as the principal index answers: `None`
/// when the read would fall back to the full scan.
pub fn indexed_grants_for_principal(
    vault: &Vault,
    principal_ref: &str,
) -> Result<Option<Vec<StandingOutboundGrant>>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(crate::outbound_grant::indexed_grants_for_principal_in_txn(
        &vault.store,
        &rtxn,
        principal_ref,
    ))
}

/// The grants `principal_ref` holds by the full scan of every Grant row.
pub fn scanned_grants_for_principal(
    vault: &Vault,
    principal_ref: &str,
) -> Result<Vec<StandingOutboundGrant>> {
    let rtxn = vault.store.env.read_txn()?;
    crate::outbound_grant::scanned_standing_outbound_grants_for_principal_in_txn(
        &vault.store,
        &rtxn,
        principal_ref,
    )
}

/// The rows of grant `id` as the id index answers: `None` when the read
/// would fall back to the full scan.
pub fn indexed_grants_with_id(
    vault: &Vault,
    id: &EntityId,
) -> Result<Option<Vec<StandingOutboundGrant>>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(crate::outbound_grant::indexed_grants_with_id_in_txn(
        &vault.store,
        &rtxn,
        id,
    ))
}

/// Grant `id` (its live row, else the row it was revoked as) by the full
/// scan of every Grant row.
pub fn scanned_grant(vault: &Vault, id: &EntityId) -> Result<Option<StandingOutboundGrant>> {
    let rtxn = vault.store.env.read_txn()?;
    crate::outbound_grant::scanned_standing_outbound_grant_in_txn(&vault.store, &rtxn, id)
}

/// Mints one standing outbound grant per `(id, principal, scope)`, all in one
/// write transaction, as the owner's mint door mints each.
pub fn mint_standing_outbound_grants(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    grants: &[(EntityId, String, GrantMintIntentScope)],
) -> Result<Vec<StandingOutboundGrant>> {
    let mut scoped = Vec::with_capacity(grants.len());
    for (id, principal_ref, scope) in grants {
        scoped.push((
            *id,
            principal_ref.as_str(),
            StandingOutboundGrantScope::from_grant_mint_scope(scope)?,
        ));
    }
    vault.with_write_txn_grouped(|wtxn| {
        scoped
            .into_iter()
            .map(|(id, principal_ref, scope)| {
                vault.mint_standing_outbound_grant_in_txn(wtxn, owner, id, principal_ref, scope)
            })
            .collect()
    })
}

/// Drops both outbound grant indexes and their completeness flag, as a vault
/// older than the indexes holds them.
pub fn drop_index(vault: &Vault) -> Result<()> {
    crate::outbound_grant::drop_standing_outbound_grant_index(vault)
}

/// Whether both outbound grant indexes are complete.
pub fn index_complete(vault: &Vault) -> Result<bool> {
    crate::outbound_grant::standing_outbound_grant_index_complete(vault)
}
