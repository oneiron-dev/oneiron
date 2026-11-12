//! Door for `tests/esign_commitments.rs`: the evidence a commitment's current
//! status carries, read at the head of its status chain, which is
//! crate-private.

use rmpv::Value;

use crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY;
use crate::{EntityId, Result, Vault};

/// The writer's evidence on the claim at the head of `commitment`'s status
/// chain: `None` when no claim stands there or its writer named none.
///
/// # Errors
///
/// The store's.
pub fn commitment_status_evidence(vault: &Vault, commitment: &EntityId) -> Result<Option<Value>> {
    let txn = vault.store.env.read_txn()?;
    let head = vault.commitment_head_in_txn(&txn, commitment)?;
    let Some(Value::Map(entries)) = vault
        .get_claim_in_txn(&txn, &head)?
        .and_then(|body| body.evidence)
    else {
        return Ok(None);
    };
    Ok(entries
        .into_iter()
        .find(|(key, _)| key.as_str() == Some(WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY))
        .map(|(_, value)| value))
}
