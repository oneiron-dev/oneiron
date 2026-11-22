//! [SCAN-CANDIDATES-UNDECODABLE-CLAIM-TEST]: damage one stored CLAIM row's
//! body in place, past every write door, so a test reads how a scoped text
//! scan treats a live CLAIM whose body does not decode.

use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::{EntityId, Error, Result, Vault};

/// Overwrites the body of the stored CLAIM row `id` with bytes of the same
/// length that decode as no claim body. The row keeps its header, its text
/// postings and every index row that names it, so it stays a live CLAIM to
/// every read that does not decode its body.
///
/// # Errors
///
/// `id` names no stored CLAIM row, or the store refuses the write.
pub fn damage_stored_claim_body(vault: &Vault, id: EntityId) -> Result<()> {
    vault.with_write_txn(|txn| {
        let row = vault
            .store
            .port_entity_record(txn, &id)?
            .ok_or(Error::InvariantViolation("no stored row has this id"))?;
        if row.entity_type != ENTITY_TYPE_CLAIM {
            return Err(Error::InvariantViolation("the stored row is no CLAIM"));
        }
        let mut raw = row.encode();
        // 0xc1 is the one byte MessagePack never uses.
        raw[ENTITY_METADATA_HEADER_LEN..].fill(0xc1);
        vault.store.entities.put(txn, id.as_bytes(), &raw)?;
        Ok(())
    })
}
