//! The landing half of one promotion: the prior read, the claim's write
//! and everything `promote_one_answering` does inside its write
//! transaction, on the transaction of the caller that opened it.

use super::*;

/// Reads the claim's bytes before the write, into the prepared value's
/// prior slot.
pub(super) fn read_prior_in_txn(
    vault: &Vault,
    prepared: &PreparedPromotion<'_>,
    txn: &heed::RoTxn<'_>,
) -> crate::Result<()> {
    *prepared.prior.borrow_mut() =
        crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &prepared.claim_id)?;
    Ok(())
}

/// The whole of `promote_one_answering`'s `finish_promotion`: document
/// evidence check, fence, supersession, approval rules, own-rate count,
/// finding notification, birth, MESSAGE dependencies and strength, and
/// the owned attempt sink's output recording.
pub(super) fn finish_promotion_in_txn(
    vault: &Vault,
    run: &DreamerRunContext,
    prepared: &PreparedPromotion<'_>,
    fence: Option<&crate::dreamer_consolidation::resources::ConsolidationFence>,
    record_output: bool,
    wtxn: &mut heed::RwTxn<'_>,
) -> crate::Result<()> {
    crate::entity_doc::verify_promotion_evidence_in_txn(vault, wtxn, &prepared.public_refs)?;
    if let Some(fence) = fence {
        fence.validate_in_txn(vault, wtxn)?;
    }
    if let Some(old_id) = prepared.supersedes.as_ref() {
        vault.stage_claim_supersession_in_txn(
            wtxn,
            &prepared.claim_id,
            old_id,
            &prepared.envelope,
            run.now_ms,
        )?;
    }
    // Failed apply or stage rolls back the claim, binding and gate receipt.
    // Checker refusals never reach this callback: preflight commits only
    // the rejection receipt, with no claim or pending-consent row.
    // The already-stored answer TURN never shared this transaction.
    let landed =
        vault
            .get_claim_in_txn(&*wtxn, &prepared.claim_id)?
            .ok_or(Error::InvalidClaimBody(
                "consolidation claim is missing inside its own write transaction",
            ))?;
    // Never Auto, and never Proposed where no review holds it.
    if prepared.imported
        && (landed.approval == ClaimApprovalStatus::Auto
            || store_pending_group(vault, wtxn, &prepared.claim_id)?.is_none())
    {
        return Err(Error::InvalidClaimBody(
            "a claim from imported evidence lands only in an owner review",
        ));
    }
    if landed.approval != ClaimApprovalStatus::Auto
        && prepared.supersedes.is_none()
        && !prepared.is_conflict_marker
        && !prepared.imported
    {
        return Err(Error::InvalidClaimBody(
            "consolidation write was not granted Auto; no approval queue is created",
        ));
    }
    // An Auto write counts on the agent's own-rate window. Its first
    // crossing leaves a typed check; the write itself stays Auto.
    let replayed = match prepared.prior.borrow().as_deref() {
        Some(before) => {
            crate::ports::EntityStoreRead::port_entity_raw(&vault.store, wtxn, &prepared.claim_id)?
                .as_deref()
                == Some(before)
        }
        None => false,
    };
    if landed.approval == ClaimApprovalStatus::Auto && !replayed {
        crate::own_rate::count_in_txn(
            &vault.store,
            wtxn,
            crate::store::own_rate_record::OwnRateKind::AutoWrite,
            run.agent_actor.entity_ref(),
            vault.store.clock.now_recorded_at(),
            prepared.auto_write_rate,
        )?;
        #[cfg(test)]
        crate::own_rate::counted_auto_write(crate::own_rate::AutoWriteDoor::Promotion);
        // A landed finding reaches its owner's inbox in the same
        // transaction; a pended or refused one never does.
        if let crate::claim::ClaimSubject::Entity(subject) = landed.subject {
            vault.record_finding_notification_in_txn(
                wtxn,
                prepared.claim_id,
                subject,
                run.now_ms,
            )?;
        }
    }
    // Both write paths reach here; a replayed attempt keeps the claim's
    // first birth.
    if let Some(birth) = &prepared.birth {
        crate::provenance::birth::stamp_birth_if_absent_in_txn(
            &vault.store,
            wtxn,
            &prepared.claim_id,
            birth,
        )?;
    }
    // The MESSAGE words the evidence names become this claim's
    // dependencies in the claim's own transaction.
    match prepared.verified {
        Some(evidence) => {
            evidence.record_message_dependencies_in_txn(vault, wtxn, &prepared.claim_id)?;
            crate::dreamer_consolidation::strength::record_verified_in_txn(
                vault,
                wtxn,
                prepared.claim_id,
                evidence,
                run.now_ms,
            )
        }
        None => crate::mail_pack::claim_recheck::owe_claim_recheck_for_cited_in_txn(
            vault,
            wtxn,
            &prepared.unverified_cited,
        ),
    }?;
    if record_output {
        let approval = verify_landed_body(&landed, &prepared.predicate, prepared.source)
            .map_err(Error::InvalidClaimBody)?;
        if matches!(
            approval,
            ClaimApprovalStatus::Auto | ClaimApprovalStatus::Proposed
        ) {
            crate::dreamer_consolidation::nightly_merge::record_outputs_in_txn(
                vault,
                wtxn,
                run.attempt_id,
                &[prepared.claim_id],
            )?;
        }
    }
    Ok(())
}

/// The body of `promote_one_answering`'s no-checker arm without its
/// `WriterHold`: the prior read, the claim and its text, then the whole
/// of `finish_promotion`. The caller that opened the transaction holds
/// it.
pub(crate) fn land_prepared_promotion_in_txn(
    vault: &Vault,
    run: &DreamerRunContext,
    prepared: &PreparedPromotion<'_>,
    claim_candidate: crate::ClaimCandidate,
    fence: Option<&crate::dreamer_consolidation::resources::ConsolidationFence>,
    record_output: bool,
    txn: &mut heed::RwTxn<'_>,
) -> crate::Result<()> {
    // 4. ONE wtxn: the proposed claim and its deferred closure binding
    // commit or roll back together; the prior stays active until later grant.
    // GATE-007 (Generated over UserStated) is rechecked on closure.
    read_prior_in_txn(vault, prepared, txn)?;
    let hints: Vec<&str> = prepared.hints.iter().map(String::as_str).collect();
    vault
        .batch_in()
        .claim_candidate_with_lexical_hints(
            &prepared.claim_id,
            claim_candidate,
            &prepared.envelope,
            prepared.occurred,
            prepared.learned_at,
            &hints,
        )
        .text(&prepared.claim_id, &[("val", prepared.birth_text.as_str())])
        .apply_recording_gate_decisions(txn)?;
    finish_promotion_in_txn(vault, run, prepared, fence, record_output, txn)
}
