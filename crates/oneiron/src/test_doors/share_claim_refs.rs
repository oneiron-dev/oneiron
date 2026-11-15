//! A stored CLAIM row past the claim write doors, for
//! `tests/share_claim_refs_skip_row_conjuncts.rs`: a share brief can name a
//! claim a write door would refuse today (a `core.coreference.status`
//! claim one of whose ends no row stores, as an endpoint deleted after the
//! claim landed or a row that arrived replicated), and the share's
//! resolution reads stored rows. Compiled only under
//! `--cfg oneiron_test_support` (`test_doors`); hidden, never API.

use crate::claim::{ClaimBody, encode_claim_body};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::temporal::TimeRange;
use crate::{EntityId, Result, Vault};

/// Stores `body` as the CLAIM row `id`, past every claim write door, as a
/// row a vault already holds stands: the entity record the share tests'
/// raw claim fixture writes, occurred and learned at 1.
///
/// # Errors
///
/// The body does not encode, or the store refuses the write.
#[doc(hidden)]
pub fn put_stored_claim(vault: &Vault, id: &EntityId, body: &ClaimBody) -> Result<()> {
    let bytes = encode_claim_body(body)?;
    vault.with_write_txn(|txn| {
        let raw = crate::test_fixtures::entity_record(
            ENTITY_TYPE_CLAIM,
            TimeRange { start: 1, end: 1 },
            1,
            0,
            &bytes,
        );
        vault.store.entities.put(txn, id.as_bytes(), &raw)?;
        Ok(())
    })
}
