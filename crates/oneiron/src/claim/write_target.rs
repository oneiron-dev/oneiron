//! Stored-target checks for generic writes of engine-owned claims.

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
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
    // A staged self.refine claim is source on its session branch, not an
    // ordinary claim ID. Raw writes, batch writes and replay all refuse it;
    // only its consented merge transaction can release the marker temporarily.
    if crate::skill_hub::claim_refinement_pending_in_txn(store, txn, id)? {
        return Err(Error::InvalidClaimBody(
            "claim refinement requires merge-back admission",
        ));
    }
    if allow_reserved {
        return Ok(());
    }
    let Some(raw) = store.port_entity_record(txn, id)?.map(|row| row.encode()) else {
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

impl crate::Vault {
    /// Code-run claim writes cannot create or replace actor-owned keyed revisions.
    /// The incoming predicate and stored target are checked in the mutation's txn.
    pub(crate) fn validate_code_run_claim_target_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        predicate: Option<&str>,
    ) -> Result<()> {
        let owned_door = || Error::Claim(crate::error::ClaimError::KeyValueWriteRequiresOwnedDoor);
        if predicate == Some(super::KEY_VALUE_PREDICATE) {
            return Err(owned_door());
        }
        if self.local_hard_delete_marker_exists_in_txn(txn, id)? {
            return Err(Error::InvalidClaimBody(
                "code-run cannot reuse an erased claim id",
            ));
        }
        let Some(raw) = self.store.entities.get(txn, id.as_bytes())? else {
            return Ok(());
        };
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("code-run claim target header"))?;
        if header.entity_type == ENTITY_TYPE_CLAIM {
            // Erased shells no longer identify their predicate. Do not remint them.
            if raw.len() == ENTITY_METADATA_HEADER_LEN {
                return Err(Error::InvalidClaimBody(
                    "code-run cannot reuse an erased claim id",
                ));
            }
            let body = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
            if !super::claim_generic_readable(&body) {
                return Err(owned_door());
            }
        }
        Ok(())
    }
}
