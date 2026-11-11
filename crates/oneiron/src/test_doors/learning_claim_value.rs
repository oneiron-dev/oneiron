//! Doors for `tests/learning_claim_value.rs` (FIX
//! LEARNING-CELL-POSITIONAL-DECODE): the learning claim value codec, the
//! positional spelling written before named fields, and the active heads of
//! a cell.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::learning::project::{StoredEstimateClaim, active_heads_in_txn};
use crate::learning::{Estimate, LearningCell};
use crate::temporal::TimeRange;

/// The claim value of `cell` and `estimate` as positional MessagePack bytes:
/// `rmpv::ext::to_value` over the claim, the encoder every learning claim
/// was written with before named fields.
///
/// # Errors
///
/// [`Error::InvariantViolation`] when the claim does not encode.
pub fn positional_claim_bytes(cell: &LearningCell, estimate: &Estimate) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &positional_value(&claim(cell, estimate))?)
        .map_err(|_| Error::InvariantViolation("positional learning claim bytes"))?;
    Ok(bytes)
}

/// Decodes stored claim value bytes as every reader does and returns the
/// claim's cell and estimate.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] when the bytes are not a learning claim value.
pub fn decode_claim_bytes(bytes: &[u8]) -> Result<(LearningCell, Estimate)> {
    let value = rmpv::decode::read_value(&mut &bytes[..])
        .map_err(|_| Error::InvalidClaimBody("learning claim value bytes"))?;
    let stored = StoredEstimateClaim::from_value(&value)?;
    Ok((stored.cell, stored.estimate))
}

/// Replaces the one active head of `cell` with its positional twin: a new
/// claim with the head's estimate, evidence and source, spelled positionally,
/// supersedes the head at `now`. Returns the twin's id.
///
/// # Errors
///
/// [`Error::InvariantViolation`] when the cell has no single active head;
/// storage and claim write errors.
pub fn respell_head_positional(vault: &Vault, cell: &LearningCell, now: u64) -> Result<EntityId> {
    vault.with_write_txn_grouped(|wtxn| {
        let heads = active_heads_in_txn(vault, wtxn, cell)?;
        let [(head_id, body, head_start)] = heads.as_slice() else {
            return Err(Error::InvariantViolation(
                "a positional respell takes a cell with one active head",
            ));
        };
        let mut twin = body.clone();
        twin.value = positional_value(&StoredEstimateClaim::from_value(&body.value)?)?;
        let twin_id = vault.store.clock.entity_id()?;
        vault.put_reserved_claim_in_txn(
            wtxn,
            &twin_id,
            &twin,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )?;
        vault.supersede_reserved_claim_in_txn(wtxn, &twin_id, head_id, now.max(*head_start))?;
        Ok(twin_id)
    })
}

/// The ids of the active heads of `cell`, as the projector selects them.
///
/// # Errors
///
/// Storage errors.
pub fn active_head_ids(vault: &Vault, cell: &LearningCell) -> Result<Vec<EntityId>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(active_heads_in_txn(vault, &rtxn, cell)?
        .into_iter()
        .map(|(id, _, _)| id)
        .collect())
}

fn positional_value(claim: &StoredEstimateClaim) -> Result<rmpv::Value> {
    rmpv::ext::to_value(claim)
        .map_err(|_| Error::InvariantViolation("positional learning claim encode"))
}

fn claim(cell: &LearningCell, estimate: &Estimate) -> StoredEstimateClaim {
    StoredEstimateClaim {
        kind: "estimate".to_owned(),
        form: estimate.form(),
        cell: cell.clone(),
        estimate: estimate.clone(),
        untested: estimate.untested(),
        donor_tally: None,
        frozen: None,
    }
}
