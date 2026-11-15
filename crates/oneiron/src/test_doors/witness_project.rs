//! The PROJECT a witness row is stamped under, for integration tests.

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::vault::Vault;

/// The PROJECT of the TURN or MESSAGE `id`, as the Dreamer reads it (FIX
/// WITNESS-TURN-NO-PROJECT-POSITION): its record position's audience. The
/// vault default where the row carries no position; `None` where the
/// audience is not exactly one project.
///
/// # Errors
///
/// Storage failures, a missing row, or a row whose header does not parse.
pub fn stamped_project(vault: &Vault, id: EntityId) -> Result<Option<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    let raw = vault
        .store
        .port_entity_raw(&txn, &id)?
        .ok_or(Error::EntityNotFound)?;
    let header =
        EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("witness row header"))?;
    let body = &raw[ENTITY_METADATA_HEADER_LEN..];
    crate::dreamer_consolidation::resources::stored_project(
        &vault.store,
        &txn,
        id,
        header.entity_type,
        body,
    )
}
