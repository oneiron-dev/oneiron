//! Persisted-head convergence through the existing promotion, claim Gate,
//! semantic-edge and provenance doors. A head is never re-authored to attach
//! evidence: its value, approval, source and original attribution stay intact.
use super::*;
use crate::dreamer_consolidation::resources::{ConsolidationFence, ScopedConsolidationWrite};
use crate::edge::EdgeKind;
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
    for (head, candidate) in write.attachments {
        match attach_evidence(vault, run, &write.fence, head, &candidate, checker) {
            Ok(()) => outcome.landed.push(head),
            Err(error) => outcome.rejected.push((head, error.to_string())),
        }
    }
    for mut candidate in write.candidates {
        candidate.evidence_meet = write.fence.evidence_source(&candidate)?;
        let id = candidate.claim_id;
        match promote_one(vault, run, candidate, checker, Some(&write.fence)) {
            Ok(ClaimApprovalStatus::Auto) => outcome.landed.push(id),
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
    checker: Option<&BoundedAutoChecker>,
) -> Result<()> {
    let source = fence.evidence_source(candidate)?;
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
            .with_evidence(encode_consolidation_evidence(
                &ConsolidationEvidenceEnvelope {
                    refs: refs.iter().copied().collect(),
                    chain: Vec::new(),
                    source_meet: source,
                },
            ));
        let gate_body = gate_candidate.into_claim_body(&envelope);
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
            attach_ref(vault, txn, run, head, *source_id)?;
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
) -> Result<()> {
    let head_raw = vault
        .store
        .entities
        .get(txn, head.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let source_raw = vault
        .store
        .entities
        .get(txn, source.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let head_hash = blake3::hash(&head_raw);
    let source_hash = blake3::hash(&source_raw);
    let mut hash = blake3::Hasher::new();
    hash.update(b"oneiron:dreamer-evidence-attachment:v1");
    hash.update(head.as_bytes());
    hash.update(source.as_bytes());
    hash.update(head_hash.as_bytes());
    hash.update(source_hash.as_bytes());
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
    let derived_evidence = encode_consolidation_evidence(&ConsolidationEvidenceEnvelope {
        refs: vec![source],
        chain: Vec::new(),
        source_meet: ClaimSource::Generated,
    });
    let edge_key = crate::store::Store::encode_edge_key(&source, EdgeKind::Supports, &head);
    if let Some(existing) = vault.get_claim_in_txn(txn, &id)? {
        let expected_scope = Value::Map(vec![
            (
                Value::from(crate::claim::CLAIM_SCOPE_EVIDENCE_TAINT_KEY),
                Value::from(ClaimSource::Generated.as_str()),
            ),
            (Value::from("derived_evidence"), derived_evidence.clone()),
        ]);
        let forward = vault.store.edges_out.get(txn, &edge_key)?;
        let reverse_key = crate::store::Store::encode_edge_key(&head, EdgeKind::Supports, &source);
        let reverse = vault.store.edges_in.get(txn, &reverse_key)?;
        if existing.scope.as_ref() != Some(&expected_scope)
            || existing.approval != ClaimApprovalStatus::Auto
            || forward.as_deref() != reverse.as_deref()
            || forward.as_ref().is_none_or(|raw| {
                crate::vault::parse_edge_record(&edge_key, raw).map_or(true, |edge| {
                    edge.provenance
                        != Some(crate::edge::EdgeProvenanceFlags {
                            confirmation_status: crate::edge::EdgeConfirmationStatus::Confirmed,
                            actor_class: run.agent_actor.actor_class(),
                        })
                })
            })
            || existing.source != Some(ClaimSource::Generated)
            || existing.predicate != crate::provenance::PREDICATE_EDGE_PROVENANCE
            || existing.subject != crate::ClaimSubject::from(edge)
            || existing.lifecycle != crate::ClaimLifecycleStatus::Active
            || crate::provenance::decode_edge_provenance_body(&existing.value)? != record
            || vault.store.edges_out.get(txn, &edge_key)?.is_none()
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
    if vault.store.edges_out.get(txn, &edge_key)?.is_none() {
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
