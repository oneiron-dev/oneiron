//! The house link's bind-interval read (HOUSE-BIND = A, S3) for the test
//! that reads it on both sides of an unbind, and the own-device read of a
//! house's grant.
use crate::error::Error;
use crate::{EntityId, Result, Vault};

/// The org `house` ran at `at`, by its bind and unbind receipts alone.
///
/// # Errors
///
/// The store's.
pub fn house_org_at(vault: &Vault, house: EntityId, at: u64) -> Result<Option<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    crate::workspace_roster::house_org_at_in_txn(vault, &txn, house, at)
}

/// Whether the live FEDERATION_GRANT `grant` reads as an own-device grant
/// (`federation::is_own_device_grant`). A grant with no live row is
/// `EntityNotFound`.
///
/// # Errors
///
/// The store's, and the grant body's decode.
pub fn is_own_device_grant(vault: &Vault, grant: EntityId) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    let crate::vault::LiveEntityRow::Live {
        entity_type: crate::registry::ENTITY_TYPE_FEDERATION_GRANT,
        body,
    } = crate::vault::live_entity_row_in_txn(&vault.store, &txn, &grant)?
    else {
        return Err(Error::EntityNotFound);
    };
    let grant = crate::federation::decode_federation_grant_body(&body)?;
    Ok(crate::federation::is_own_device_grant(&grant))
}

/// Puts `body` as CLAIM `id` through the raw claim door, then stamps
/// `made_by` as its stated birth, so the claim reads as made by
/// `made_by.process.actor` at `made_by.at`: the byline read of
/// `tests/claim_view_for_org.rs` (FIX SPEAKER-BYLINE-FOR-ORG-CLAIMS).
///
/// # Errors
///
/// The claim door's refusal, the birth's shape refusal, or the store's.
pub fn put_claim_made_by(
    vault: &Vault,
    id: EntityId,
    body: &crate::claim::ClaimBody,
    made_by: crate::provenance::made_by::MadeBy,
) -> Result<()> {
    let at = made_by.at;
    vault.put_claim(&id, body, crate::TimeRange { start: at, end: at }, at)?;
    let mut txn = vault.store.env.write_txn()?;
    crate::store::birth_record::stamp_row_birth_in_txn(
        &vault.store,
        &mut txn,
        &id,
        &crate::store::row_birth::RowBirth::stated(made_by),
    )?;
    txn.commit()?;
    Ok(())
}
