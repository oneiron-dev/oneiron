//! Doors for `tests/direct_answer_proof_store_error.rs`
//! (DIRECT-ANSWER-PROOF-STORE-ERROR): truncate the embedded owner's PERSON
//! row in place, past every write door, so a test reads how the
//! direct-request proof builders report store damage. Compiled only under
//! `--cfg oneiron_test_support`; never API.

use crate::ports::EntityStoreRead;
use crate::vault::Vault;
use crate::{EntityId, Error, Result};

/// The truncated row's length: below the 33-byte entity metadata header, so
/// the header no longer parses.
const TRUNCATED_LEN: usize = 4;

/// Truncates the embedded owner's stored PERSON row to [`TRUNCATED_LEN`]
/// bytes, past every write door, and answers the owner's id. The row keeps
/// its key and its type-index entry; only its bytes shorten, so it is still
/// found but its record no longer decodes, and readers of it fail with a
/// store error. Returns the damaged row's id.
///
/// # Errors
///
/// The vault stores no PERSON row for the embedded owner, or the store
/// refuses the write.
#[doc(hidden)]
pub fn truncate_embedded_owner_person_row(vault: &Vault) -> Result<EntityId> {
    let owner = crate::vault::embedded_owner_actor_id()?;
    vault.with_write_txn(|txn| {
        let raw = vault
            .store
            .port_entity_raw(txn, &owner)?
            .ok_or(Error::InvariantViolation(
                "the vault stores no embedded-owner row",
            ))?;
        vault.store.entities.put(txn, owner.as_bytes(), &raw[..TRUNCATED_LEN])?;
        Ok(owner)
    })
}
