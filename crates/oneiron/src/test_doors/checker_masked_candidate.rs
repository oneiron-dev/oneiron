//! Doors for `tests/checker_masked_candidate.rs`
//! (CHECKER-PREVIEW-READS-UNMASKED-CANDIDATE): a stored claim as the gate's
//! consent binding reads it. Compiled only under `--cfg oneiron_test_support`;
//! never API.

use crate::Result;
use crate::claim::ClaimBody;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::ports::EntityStoreRead;
use crate::vault::Vault;

/// The claim `id` as stored, and the diff handle the gate's consent binding
/// names for that body (`gate::claim_consent_binding_parts`): the handle an
/// owner's answer to the claim's pending review is judged against.
///
/// # Errors
/// [`Error::EntityNotFound`] when no row is stored for `id`; else the store's.
#[doc(hidden)]
pub fn stored_claim_with_consent_diff(
    vault: &Vault,
    id: &EntityId,
) -> Result<(ClaimBody, Vec<u8>)> {
    let txn = vault.store.env.read_txn()?;
    let record = vault
        .store
        .port_entity_record(&txn, id)?
        .ok_or(Error::EntityNotFound)?;
    let body = crate::write_envelope::claim_body::decode_claim_body(&record.body, true)?;
    let (diff_handle, _) = crate::gate::claim_consent_binding_parts(&vault.store, &txn, &body)?;
    Ok((body, diff_handle))
}
