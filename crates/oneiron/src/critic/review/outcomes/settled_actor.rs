//! The actor a settlement no owner decided writes a critique's outcome under
//! (FIX 12188): the review's own actor as it asked for the review, with the
//! run attempt and authority frontier it carried. Today's actor, the
//! principal at its stored class with neither, writes it instead only when
//! the gate refuses or holds the write because of them.
use super::*;

/// How the gate landed one trial write of an outcome claim.
enum Landing {
    /// It stands now, and its savepoint is kept.
    Standing,
    /// The gate held it; its savepoint is dropped.
    Held,
    /// The gate refused it; its savepoint is dropped.
    Refused(Error),
}

/// Writes the outcome claim `id` with `body` as `stored`, the review's actor,
/// and gives back the actor it landed under. A stored actor with no run
/// attempt and no authority frontier writes as before. Otherwise, a write
/// the gate refuses or holds under `stored` but lands standing under today's
/// actor was stopped only by that attempt or frontier: it lands under
/// today's actor, with a warning. When today's actor cannot land it standing
/// either, a held write stands as `stored` gives it, and a refused one is
/// written once more as today's actor, as before, with a warning.
pub(super) fn write_settled_outcome_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
    stored: WriteActor,
    at: u64,
) -> Result<WriteActor> {
    let today = WriteActor::new(stored.entity_ref(), stored.actor_class());
    if stored.run_attempt().is_none() && stored.authority_frontier().is_none() {
        write_claim(vault, txn, id, body, stored, at)?;
        return Ok(stored);
    }
    let refused = match land_in_savepoint(vault, txn, id, body, stored, at)? {
        Landing::Standing => return Ok(stored),
        Landing::Held => None,
        Landing::Refused(error) => Some(error),
    };
    let today_stands = matches!(
        land_in_savepoint(vault, txn, id, body, today, at)?,
        Landing::Standing
    );
    if !today_stands && refused.is_none() {
        write_claim(vault, txn, id, body, stored, at)?;
        return Ok(stored);
    }
    match &refused {
        Some(error) => tracing::warn!(
            kind = ?error.kind(),
            "a critique's outcome was refused under its review's run and frontier; it is written as the review's principal"
        ),
        None => tracing::warn!(
            "a critique's outcome was held under its review's run and frontier; it is written as the review's principal"
        ),
    }
    if !today_stands {
        write_claim(vault, txn, id, body, today, at)?;
    }
    Ok(today)
}

/// Writes `id` as `actor` in a savepoint of `txn`, kept only when the claim
/// stands: neither refused nor held by the gate.
fn land_in_savepoint(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
    actor: WriteActor,
    at: u64,
) -> Result<Landing> {
    let mut savepoint = vault.store.env.nested_write_txn(txn)?;
    if let Err(error) = write_claim(vault, &mut savepoint, id, body, actor, at) {
        return Ok(Landing::Refused(error));
    }
    let standing = vault
        .get_claim_in_txn(&savepoint, id)?
        .is_some_and(|landed| landed.approval != ClaimApprovalStatus::Proposed)
        && crate::gate::claim_consolidation_eligible_in_txn(
            &vault.store,
            &savepoint,
            id,
            crate::gate::ConsolidationReader::CriticOutcome,
        )?;
    if !standing {
        return Ok(Landing::Held);
    }
    savepoint.commit()?;
    Ok(Landing::Standing)
}
