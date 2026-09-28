//! Persisted-head convergence through the existing promotion, claim Gate,
//! semantic-edge and provenance doors. A head is never re-authored to attach
//! evidence: its value, approval, source and original attribution stay intact.
use super::*;
use crate::dreamer_consolidation::evidence::VerifiedEvidenceSet;
use crate::dreamer_consolidation::resources::{ConsolidationFence, ScopedConsolidationWrite};
use crate::edge::EdgeKind;
use crate::ports::EdgeStoreRead;
use crate::provenance::{EdgeProvenanceClaimBody, EdgeRef, SupersessionStatus};

/// Consumes a sealed executor handoff. This is the persistence door for custom
/// consolidation sinks; merely inspecting candidates does not consume its pins.
pub fn promote_scoped_consolidation(
    vault: &Vault,
    run: &DreamerRunContext,
    write: ScopedConsolidationWrite,
    checker: Option<&BoundedAutoChecker>,
) -> Result<PromotionOutcome> {
    write.fence.validate_run(run)?;
    if run.agent_actor != vault.dreamer_actor_for_attempt(run.attempt_id)? {
        return Err(Error::InvalidClaimBody("scoped promotion actor mismatch"));
    }
    let mut outcome = PromotionOutcome::default();
    for (head, candidate, evidence) in write.attachments {
        match attach_evidence(
            vault,
            run,
            &write.fence,
            head,
            &candidate,
            &evidence,
            checker,
        ) {
            Ok(()) => outcome.landed.push(head),
            Err(error) => outcome.rejected.push((head, error.to_string())),
        }
    }
    for (mut candidate, evidence) in write.candidates.into_iter().zip(write.candidate_evidence) {
        candidate.evidence_meet = evidence.meet();
        let id = candidate.claim_id;
        match promote_one(
            vault,
            run,
            candidate,
            checker,
            Some(&write.fence),
            Some(&evidence),
        ) {
            Ok(ClaimApprovalStatus::Auto) => outcome.landed.push(id),
            Ok(ClaimApprovalStatus::Proposed) => outcome.pended.push(id),
            Ok(_) => outcome
                .rejected
                .push((id, "scoped promotion was not Auto".into())),
            Err(reason) => outcome.rejected.push((id, reason)),
        }
    }
    Ok(outcome)
}

fn attach_evidence(
    vault: &Vault,
    run: &DreamerRunContext,
    fence: &ConsolidationFence,
    head: EntityId,
    candidate: &PromotionCandidate,
    evidence: &VerifiedEvidenceSet,
    checker: Option<&BoundedAutoChecker>,
) -> Result<()> {
    let source = evidence.meet();
    let envelope = WriteEnvelope::with_lineage(
        run.agent_actor,
        source,
        WriteProvenance::new(promotion_provenance(run, &candidate.provenance_chain))?,
        ClaimApprovalStatus::Auto,
        SourceLineage::of(ClaimSource::Generated).with(source),
    );
    let refs: std::collections::BTreeSet<_> =
        candidate.evidence_turn_refs.iter().copied().collect();
    vault.with_write_txn(|txn| {
        fence.validate_in_txn(vault, txn)?;
        let original = vault
            .get_claim_in_txn(txn, &head)?
            .ok_or(Error::EntityNotFound)?;
        // Gate the evidence assertion, not an overwrite of the approved head.
        // Copy the head's complete scope so sensitivity/persona policy cannot be
        // lowered by a minimally scoped extraction. Keep the normal Dreamer
        // validity, source/lineage, isolation, checker and receipt machinery.
        let gate_candidate = candidate
            .candidate
            .clone()
            .with_scope(scope_with_taint(original.scope.clone(), source))
            .with_evidence(evidence.envelope(Vec::new()));
        let gate_body = gate_candidate.into_claim_body(&envelope, vault.default_facet_in_txn(txn)?)?;
        let policy = crate::gate::resolve_policy_manifest(&vault.store, txn)?;
        crate::gate::check_claim_policy_for_write(
            &vault.store,
            txn,
            &head,
            crate::gate::ClaimGateWrite {
                body: &gate_body,
                envelope: Some(&envelope),
                auto_checker: checker,
                defer_metrics_until_commit: false,
                transition: None,
            },
            &policy,
            crate::gate::GateWriteMode {
                record_decision: true,
                persist_pending_consent: false,
                resolve_pending: false,
                can_resolve_pending_consent: false,
                include_source_in_gate_input: true,
            },
            false,
        )?;
        // The gate is not an authority-granting preflight: all materialization
        // below and its receipt share this transaction, including live pins.
        for source_id in &refs {
            let cited = evidence.for_source(*source_id);
            attach_ref(vault, txn, run, head, *source_id, &cited)?;
        }
        if vault.get_claim_in_txn(txn, &head)?.as_ref() != Some(&original) {
            return Err(Error::InvalidClaimBody(
                "evidence attachment altered its head",
            ));
        }
        Ok(())
    })
}

fn attach_ref(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    run: &DreamerRunContext,
    head: EntityId,
    source: EntityId,
    evidence: &VerifiedEvidenceSet,
) -> Result<()> {
    let evidence_meet = evidence.meet();
    let locators = evidence.verified_locators();
    if locators.is_empty()
        || locators
            .iter()
            .any(|(locator, _)| locator.source_id != source)
    {
        return Err(Error::InvalidClaimBody(
            "attachment locator source mismatch",
        ));
    }
    let head_raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &head)?
        .ok_or(Error::EntityNotFound)?;
    let source_raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &source)?
        .ok_or(Error::EntityNotFound)?;
    let head_hash = blake3::hash(&head_raw);
    let source_hash = blake3::hash(&source_raw);
    let mut hash = blake3::Hasher::new();
    hash.update(b"oneiron:dreamer-evidence-attachment:v1");
    hash.update(head.as_bytes());
    hash.update(source.as_bytes());
    hash.update(head_hash.as_bytes());
    hash.update(source_hash.as_bytes());
    hash.update(evidence_meet.as_str().as_bytes());
    for (locator, digest) in locators {
        hash.update(&[u8::from(locator.claim_id.is_some())]);
        if let Some(claim) = locator.claim_id {
            hash.update(claim.as_bytes());
        }
        hash.update(&[u8::from(locator.byte_range.is_some())]);
        if let Some((start, end)) = locator.byte_range {
            hash.update(&(start as u64).to_be_bytes());
            hash.update(&(end as u64).to_be_bytes());
        }
        hash.update(&digest);
    }
    let mut id = [0_u8; 16];
    id.copy_from_slice(&hash.finalize().as_bytes()[..16]);
    let id =
        EntityId::from_bytes(id).map_err(|_| Error::InvalidClaimBody("reserved attachment id"))?;
    let edge = EdgeRef {
        source,
        kind: EdgeKind::Supports,
        target: head,
    };
    let mut record = EdgeProvenanceClaimBody::new(
        run.agent_actor.entity_ref(),
        1.0,
        SupersessionStatus::Confirmed,
    );
    record.source_revision_ref = Some(
        source_hash.as_bytes()[..16]
            .try_into()
            .expect("hash prefix"),
    );
    record.body_snapshot_ref = Some(head_hash.as_bytes()[..16].try_into().expect("hash prefix"));
    record.actor_class = Some(run.agent_actor.actor_class());
    let derived_evidence = evidence.envelope(Vec::new());
    if let Some(existing) = vault.get_claim_in_txn(txn, &id)? {
        let expected_scope = Value::Map(vec![
            (
                Value::from(crate::claim::CLAIM_SCOPE_EVIDENCE_TAINT_KEY),
                Value::from(evidence_meet.as_str()),
            ),
            (Value::from("derived_evidence"), derived_evidence),
        ]);
        let edge_consistent =
            vault
                .store
                .port_edge_consistent(txn, &source, EdgeKind::Supports, &head)?;
        let forward = vault
            .store
            .port_edge_get(txn, &source, EdgeKind::Supports, &head)
            .map_err(|error| match error {
                Error::CorruptedIndex(_) => {
                    Error::InvalidClaimBody("attachment replay binding changed")
                }
                error => error,
            })?;
        if existing.scope.as_ref() != Some(&expected_scope)
            || existing.approval != ClaimApprovalStatus::Auto
            || !edge_consistent
            || forward.as_ref().is_none_or(|edge| {
                edge.provenance
                    != Some(crate::edge::EdgeProvenanceFlags {
                        confirmation_status: crate::edge::EdgeConfirmationStatus::Confirmed,
                        actor_class: run.agent_actor.actor_class(),
                    })
            })
            || existing.source != Some(evidence_meet)
            || existing.predicate != crate::provenance::PREDICATE_EDGE_PROVENANCE
            || existing.subject != crate::ClaimSubject::from(edge)
            || existing.lifecycle != crate::ClaimLifecycleStatus::Active
            || crate::provenance::decode_edge_provenance_body(&existing.value)? != record
        {
            return Err(Error::InvalidClaimBody("attachment replay binding changed"));
        }
        let policy = crate::gate::resolve_policy_manifest(&vault.store, txn)?;
        crate::gate::check_edge_provenance_claim_policy(
            &vault.store,
            txn,
            &existing,
            &record,
            run.agent_actor.actor_class(),
            &policy,
        )?;
        return Ok(());
    }
    if vault
        .store
        .port_edge_get(txn, &source, EdgeKind::Supports, &head)?
        .is_none()
    {
        // Never a raw ungated edge: the caller completed the head-predicate
        // Gate above; provenance policy and both edge indexes co-commit below.
        vault
            .batch_in()
            .edge_with_created_at(&source, EdgeKind::Supports, &head, 1.0, run.now_ms)
            .apply(txn)?;
    }
    vault.write_edge_provenance_in_txn(
        txn,
        crate::provenance::EdgeProvenanceWrite {
            claim_id: &id,
            subject: &edge,
            body: &record,
            actor_class: run.agent_actor.actor_class(),
            learned_at: run.now_ms,
            explicit_prior: None,
            imported_evidence: None,
            generated_evidence: Some(derived_evidence),
        },
    )
}
