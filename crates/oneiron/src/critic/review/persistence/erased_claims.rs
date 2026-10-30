//! The review claims an erase takes (FIX 12073). A verdict about the erased
//! entity, an outcome about it (its session), and the automatic outcomes and
//! outcomes of a verdict that goes are about what the user erased, so they go
//! with it, torn the way a cascade tears a row: no claim is re-keyed to a new
//! subject. The calibration evidence those outcomes gave goes too, and so do
//! a torn verdict's stored review, its pointer and the trust stamps.

use super::*;

/// Tears, in the erase's own transaction, every review claim the erase of
/// `entity` takes: each `review.verdict` about `entity`, each
/// `review.automatic_outcome` about `entity` or one of those verdicts, and
/// each `review.outcome` about `entity` or keyed to one of those verdicts.
/// When `entity` is itself a verdict or an outcome, its own row is left to
/// its erase, and what it carries goes as for a torn one. A claim a legal
/// hold keeps stays, as every tear keeps it. The evidence each outcome gave
/// its critic's cell is withdrawn and the cell is projected again; a fact a
/// critique's kept dissent settled is not the outcome's, and stays.
pub(super) fn erase_review_claims_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    let about = ClaimSubject::Entity(*entity);
    let mut verdicts = BTreeSet::new();
    vault.for_each_claim_with_predicate_in_txn(wtxn, "review.verdict", |id, body| {
        if id == *entity || body.subject == about {
            verdicts.insert(id);
        }
        Ok(())
    })?;
    let mut torn = Vec::new();
    vault.for_each_claim_with_predicate_in_txn(wtxn, "review.automatic_outcome", |id, body| {
        let ClaimSubject::Entity(of) = body.subject else {
            return Ok(());
        };
        if of == *entity || verdicts.contains(&of) {
            torn.push(id);
        }
        Ok(())
    })?;
    let mut receipts = BTreeSet::new();
    vault.for_each_claim_with_predicate_in_txn(wtxn, "review.outcome", |id, body| {
        let key = candidate_evidence(&body)
            .and_then(Value::as_str)
            .and_then(|key| key.split_once(':'))
            .and_then(|(verdict, artifact)| {
                Some((EntityId::from_hex(verdict).ok()?, artifact))
            });
        if id == *entity
            || body.subject == about
            || key.is_some_and(|(verdict, _)| verdicts.contains(&verdict))
        {
            if let Some((verdict, artifact)) = key {
                receipts.insert(super::super::outcomes::calibration_receipt(
                    &verdict, artifact,
                ));
            }
            torn.push(id);
        }
        Ok(())
    })?;
    withdraw_outcome_evidence_in_txn(vault, wtxn, &receipts)?;
    for verdict in verdicts {
        if verdict == *entity || tear_review_claim_in_txn(vault, wtxn, &verdict)? {
            drop_stored_review_in_txn(vault, wtxn, &verdict)?;
        }
    }
    for id in torn.iter().filter(|id| *id != entity) {
        tear_review_claim_in_txn(vault, wtxn, id)?;
    }
    CLAIM_TRUST.delete(&vault.store, wtxn, entity)?;
    Ok(())
}

/// Withdraws every calibration evidence row under one of `receipts` that a
/// critique's outcome gave, and projects each cell it leaves again. A
/// world-outcome row is the settled fact's, and stays.
fn withdraw_outcome_evidence_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    receipts: &BTreeSet<String>,
) -> Result<()> {
    if receipts.is_empty() {
        return Ok(());
    }
    let table = crate::learning::evidence::EVIDENCE;
    let mut cells = BTreeSet::new();
    for ((digest, receipt), row) in crate::skill_attribution::erase_scan_in_txn(vault, wtxn, table)?
    {
        if row.anchor == crate::learning::Anchor::WorldOutcome || !receipts.contains(&receipt) {
            continue;
        }
        table.delete(&vault.store, wtxn, &(digest, receipt))?;
        cells.insert(digest);
    }
    let now = vault.store.clock.now_recorded_at();
    for digest in cells {
        crate::learning::project::project_cell_in_txn(vault, wtxn, &digest, now)?;
    }
    Ok(())
}

/// Tears the review claim `id` as a cascade tears a row: its provenance,
/// indexes, edges and trust stamp go, and its replicas get its tombstone.
/// Gives back false for a claim a legal hold keeps, which stays whole.
fn tear_review_claim_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    if crate::store::legal_hold::held_in_txn(&vault.store, wtxn, id.as_bytes())? {
        return Ok(false);
    }
    CLAIM_TRUST.delete(&vault.store, wtxn, id)?;
    crate::provenance::erase_row_provenance_in_txn(&vault.store, wtxn, id, true)?;
    let (existed, vector, graph, neighbors) =
        crate::batch::deindex_entity_with_machine_history(&vault.store, wtxn, id)?;
    if !existed {
        return Ok(true);
    }
    crate::batch::stage_cascade_tombstone_in_txn(&vault.store, wtxn, id)?;
    crate::ppr::invalidate_ppr_for_delete(&vault.store, wtxn, id, &neighbors)?;
    if graph {
        crate::ppr::increment_graph_version(&vault.store, wtxn)?;
    }
    if vector {
        crate::hnsw::increment_vector_version(&vault.store, wtxn)?;
    }
    Ok(true)
}

/// Deletes the stored review of the torn `verdict` and its pointer, so no
/// reader of stored reviews meets a verdict that is gone.
fn drop_stored_review_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    verdict: &EntityId,
) -> Result<()> {
    let Some(pointer) = RESULT_ID.get(&vault.store, wtxn, verdict)? else {
        return Ok(());
    };
    let hash: Option<[u8; 32]> = pointer
        .strip_prefix(RESULT.decl().prefix)
        .and_then(|hash| hash.try_into().ok());
    if let Some(hash) = hash {
        RESULT.delete(&vault.store, wtxn, &hash)?;
    }
    RESULT_ID.delete(&vault.store, wtxn, verdict)?;
    Ok(())
}
