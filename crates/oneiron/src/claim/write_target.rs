//! Stored-target checks for generic writes of engine-owned claims.

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::Store;

use super::{decode_claim_body, validate_predicate};

/// An incoming public predicate cannot disguise an overwrite of an owned id.
/// The same reserved predicate gate applies to both the old and new body.
pub(crate) fn validate_claim_write_target_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    allow_reserved: bool,
) -> Result<()> {
    if allow_reserved {
        return Ok(());
    }
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(());
    };
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("claim write target header"))?;
    // A parsed header-only row is an erased shell, not a MessagePack body.
    // The caller checks durable publication slot ownership before this helper.
    // Nonempty CLAIM bodies still decode and validate fail-closed.
    if header.entity_type == ENTITY_TYPE_CLAIM && raw.len() > ENTITY_METADATA_HEADER_LEN {
        let body = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        validate_predicate(&body.predicate, false)?;
    }
    Ok(())
}
