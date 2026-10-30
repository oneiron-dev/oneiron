//! Persisted-head convergence through the existing promotion, claim Gate,
//! semantic-edge and provenance doors. A head is never re-authored to attach
//! evidence: its value, approval, source and original attribution stay intact.
use std::collections::{BTreeMap, BTreeSet};

use super::writer::{GateCodes, PromotionRejection};
use super::*;
use super::{corrections, resolved_outputs};
use crate::dreamer_consolidation::evidence::{ResolvedConflictOutput, VerifiedEvidenceSet};
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
    // One deadline for the whole sealed write (FIX 8701): every candidate's
    // checker turn and consult spend the wake pass's, never a fresh one each.
    let checker = checker.map(|checker| match write.checker_deadline {
        Some(deadline) => checker.with_deadline(deadline),
        None => checker.clone(),
    });
    let checker = checker.as_ref();
    let landing = write.landing;
    let mut outcome = PromotionOutcome::default();
    // The open markers this write's outputs answer (FIX 7325), and each head
    // the write landed or met again with the evidence its candidate cited.
    let mut answers = write.answers;
    let mut stood: BTreeMap<EntityId, Vec<EntityId>> = BTreeMap::new();
    // Each head and candidate this write met but held, pended or rejected
    // (FIX 7380): an answer that needs one of them stays open.
    let mut unmet: BTreeSet<EntityId> = BTreeSet::new();
    for (index, (head, candidate, evidence)) in write.attachments.into_iter().enumerate() {
        // This attempt's own output, met again by a replay after it landed (a
        // kill before the attempt completed): it already carries these words.
        // What its grant left to close still closes, once.
        if head == candidate.claim_id {
            if let Some(prior) = corrections::superseded_prior(vault, head)? {
                corrections::close_conflicts_naming(
                    vault,
                    run,
                    &write.fence,
                    head,
                    prior,
                    &candidate.evidence_turn_refs,
                )?;
            }
            // What it answered still closes, from its own provenance.
            answers.extend(resolved_outputs::stored_answers(vault, head));
            stood.insert(head, candidate.evidence_turn_refs);
            outcome.landed.push(head);
            continue;
        }
        // Imported material reaches the vault only through the owner's import
        // review (ARCH-0027), and an attachment is no claim that review could
        // hold: a head imported words restate keeps its own evidence.
        if evidence.meet() == ClaimSource::Imported {
            outcome.held.push(head);
            continue;
        }
        // The answers this head gives ride on its support assertion (FIX
        // 7381); a replay that meets the assertion again reads them back.
        let bound: Vec<_> = answers
            .iter()
            .filter(|answer| answer.outputs.contains(&head))
            .cloned()
            .collect();
        match attach_evidence(
            vault,
            run,
            &write.fence,
            head,
            &candidate,
            &evidence,
            checker,
            &bound,
        ) {
            Ok(stored) => {
                answers.extend(stored);
                stood.insert(head, candidate.evidence_turn_refs);
                outcome.landed.push(head);
            }
            Err(error) => {
                let rejection = PromotionRejection::engine(error);
                log_rejected(
                    run,
                    index,
                    "attach_evidence",
                    rejection.kind,
                    rejection.gate.as_ref(),
                );
                rejection.record(head, &mut outcome);
            }
        }
    }
    let candidates = write.candidates.into_iter().zip(write.candidate_evidence);
    for (index, (mut candidate, evidence)) in candidates.enumerate() {
        candidate.evidence_meet = evidence.meet();
        let id = candidate.claim_id;
        // The owner declined this claim from these same imported words; a
        // message landing later in their TURN re-reads them and the Dreamer
        // finds it again. It is not proposed again.
        if let Some(declined) = crate::dreamer_consolidation::reviewed::declined_from_same_words(
            vault,
            &candidate,
            &evidence.cited_messages(),
        )? {
            // The declined candidate itself stands nowhere in this write.
            unmet.insert(id);
            outcome.held.push(declined);
            continue;
        }
        let evidence_refs = candidate.evidence_turn_refs.clone();
        // This attempt's own correction, granted before a kill: what its
        // grant left to close still closes, once.
        if let Some(prior) = corrections::granted_correction(vault, &candidate)? {
            corrections::close_conflicts_naming(
                vault,
                run,
                &write.fence,
                id,
                prior,
                &evidence_refs,
            )?;
            answers.extend(resolved_outputs::stored_answers(vault, id));
            stood.insert(id, evidence_refs);
            outcome.landed.push(id);
            continue;
        }
        let bound: Vec<_> = answers
            .iter()
            .filter(|answer| answer.outputs.contains(&id))
            .collect();
        match super::writer::promote_one_answering(
            vault,
            run,
            candidate,
            checker,
            Some(&write.fence),
            Some(&evidence),
            &bound,
        ) {
            Ok(ClaimApprovalStatus::Auto) => {
                stood.insert(id, evidence_refs);
                outcome.landed.push(id);
            }
            Ok(ClaimApprovalStatus::Proposed) => {
                match corrections::grant_allowed_replacement(vault, run, &write.fence, id, checker)
                {
                    Some(prior) => {
                        corrections::close_conflicts_naming(
                            vault,
                            run,
                            &write.fence,
                            id,
                            prior,
                            &evidence_refs,
                        )?;
                        stood.insert(id, evidence_refs);
                        outcome.landed.push(id);
                    }
                    None => outcome.pended.push(id),
                }
            }
            Ok(_) => {
                log_rejected(run, index, "promote_not_auto", None, None);
                outcome
                    .rejected
                    .push((id, "scoped promotion was not Auto".into()));
            }
            // The promotion door's refusal keeps its text for the outcome
            // and its kind beside it (FIX 9429); the log takes the kind of
            // the engine error behind it, when one refused it (FIX 7271),
            // and the gate's codes when the gate refused it (FIX 10355),
            // and never the text.
            Err(rejection) => {
                log_rejected(
                    run,
                    index,
                    "promote",
                    rejection.kind,
                    rejection.gate.as_ref(),
                );
                rejection.record(id, &mut outcome);
            }
        }
    }
    // Once one output an answer needs stood here, none of the rest was held,
    // pended or rejected here, and every one stands, its marker closes.
    unmet.extend(outcome.held.iter().copied());
    unmet.extend(outcome.pended.iter().copied());
    unmet.extend(outcome.rejected.iter().map(|(id, _)| *id));
    answers.sort();
    answers.dedup();
    resolved_outputs::close_resolved_outputs(vault, run, &write.fence, &answers, &stood, &unmet);
    if let Some(landing) = landing {
        landing.record(&outcome.landed, outcome.rejected.len());
    }
    Ok(outcome)
}

/// Logs one candidate of `run`'s sealed write the door rejected, before the
/// rejections fold into the write's one error (FIX 7271): its index in its
/// list, a static code for where it was rejected, its error's kind when
/// the rejection carries one, and the gate's outcome and reason codes when
/// the gate refused it (FIX 10355). Never the rejection's text.
fn log_rejected(
    run: &DreamerRunContext,
    index: usize,
    stage: &'static str,
    kind: Option<crate::error::ErrorKind>,
    gate: Option<&GateCodes>,
) {
    let attempt_id = crate::entity_id::bytes_to_hex_lower(run.attempt_id.as_bytes());
    let (gate_outcome, reason_codes) = gate.map_or(("", &[][..]), |(outcome, codes)| {
        (*outcome, codes.as_slice())
    });
    match kind {
        Some(kind) => tracing::warn!(
            attempt_id = %attempt_id,
            candidate = index,
            stage,
            error_kind = ?kind,
            gate_outcome,
            reason_codes = ?reason_codes,
            "a scoped consolidation candidate was rejected"
        ),
        None => tracing::warn!(
            attempt_id = %attempt_id,
            candidate = index,
            stage,
            "a scoped consolidation candidate was rejected"
        ),
    }
}

/// The row an attachment's carried reference refusal is receipted under (FIX
/// 11439): the Dreamer's evidence-attachment door, which no verb-table row
/// reaches, so the sealed consolidation write names it itself.
const ATTACHMENT_REFUSAL_ROW: &str = "dreamer.attach_evidence";

/// The support assertion's scope key its derived evidence sits under.
const DERIVED_EVIDENCE_KEY: &str = "derived_evidence";

/// Attaches `evidence` to `head`, each support assertion carrying the
/// `answers` the head gives. Returns the answers a support assertion this
/// attempt already wrote keeps, for a replay that meets it again.
#[expect(
    clippy::too_many_arguments,
    reason = "one sealed attachment: its run, fence, head, candidate, evidence, checker and answers"
)]
fn attach_evidence(
    vault: &Vault,
    run: &DreamerRunContext,
    fence: &ConsolidationFence,
    head: EntityId,
    candidate: &PromotionCandidate,
    evidence: &VerifiedEvidenceSet,
    checker: Option<&BoundedAutoChecker>,
    answers: &[ResolvedConflictOutput],
) -> Result<Vec<ResolvedConflictOutput>> {
    let source = evidence.meet();
    let envelope = WriteEnvelope::with_lineage(
        run.agent_actor,
        source,
        WriteProvenance::new(promotion_provenance(
            run,
            &candidate.provenance_chain,
            None,
            &candidate.decisions,
        )?)?,
        ClaimApprovalStatus::Auto,
        SourceLineage::of(ClaimSource::Generated).with(source),
    );
    let refs: std::collections::BTreeSet<_> =
        candidate.evidence_turn_refs.iter().copied().collect();
    // Read on this thread: a grouped commit may run the closure elsewhere.
    let auto_write_rate = crate::own_rate::auto_write_rate();
    // The Dreamer's own read, the one the fence holds every pin to: each
    // record the gated body names must resolve under it in the writer below
    // (OF-063, FIX 1218).
    let reader = fence.reader(vault)?;
    // The checker's turn, waited for here, before the write opens (FIX 8751).
    let checker = checker
        .map(|checker| checker.admit_for_writes(&vault.store, run.agent_actor.entity_ref()))
        .transpose()?;
    // A reference Deny rolls back with the write it refuses, so the denied
    // slot's pointer is carried out of it and receipted after, outside it
    // (FIX 11439).
    let mut carried: Option<String> = None;
    let outcome = vault.with_write_txn_grouped(|txn| {
        // Source grants are judged at this writer's own clock.
        crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        fence.validate_in_txn(vault, txn)?;
        let original = vault
            .get_claim_in_txn(txn, &head)?
            .ok_or(Error::EntityNotFound)?;
        // Gate the evidence assertion, not an overwrite of the approved head.
        // Copy the head's complete scope so sensitivity/persona policy cannot be
        // lowered by a minimally scoped extraction, and its own facet and
        // project stamps so the decision and its receipt sit where the head
        // does. Keep the normal Dreamer validity, source/lineage, isolation,
        // checker and receipt machinery.
        let gate_candidate = candidate
            .candidate
            .clone()
            .with_scope(scope_with_taint(original.scope.clone(), source))
            .with_scope_stamps(original.scope_facet, original.scope_project)
            .with_evidence(evidence.envelope(Vec::new()));
        let gate_body =
            gate_candidate.into_claim_body(&envelope, vault.default_facet_in_txn(txn)?)?;
        let policy = crate::gate::resolve_policy_manifest(&vault.store, txn)?;
        crate::gate::check_claim_policy_for_write_with_record_with_reader_carrying_refusal(
            &vault.store,
            txn,
            &head,
            crate::gate::ClaimGateWrite {
                body: &gate_body,
                envelope: Some(&envelope),
                auto_checker: checker.as_ref(),
                defer_metrics_until_commit: false,
                transition: None,
                owner_authored: None,
            },
            &policy,
            crate::gate::GateWriteMode {
                record_decision: true,
                persist_pending_consent: false,
                resolve_pending: false,
                can_resolve_pending_consent: false,
                include_source_in_gate_input: true,
            },
            &mut None,
            &reader,
            &mut carried,
        )?;
        // The gate is not an authority-granting preflight: all materialization
        // below and its receipt share this transaction, including live pins.
        let mut stored = Vec::new();
        for source_id in &refs {
            let cited = evidence.for_source(*source_id);
            stored.extend(attach_ref(
                vault,
                txn,
                run,
                (head, *source_id),
                &cited,
                answers,
                auto_write_rate,
            )?);
        }
        crate::dreamer_consolidation::strength::record_verified_in_txn(
            vault, txn, head, evidence, run.now_ms,
        )?;
        if vault.get_claim_in_txn(txn, &head)?.as_ref() != Some(&original) {
            return Err(Error::InvalidClaimBody(
                "evidence attachment altered its head",
            ));
        }
        Ok(stored)
    });
    match outcome {
        Err(error) => {
            // The refused write has rolled back; its carried refusal keeps
            // its receipt on a small write of its own, and the caller still
            // hears the refusal the transaction returned.
            if let Some(field) = carried {
                crate::gate::receipt_carried_reference_refusal(
                    vault,
                    run.agent_actor,
                    ATTACHMENT_REFUSAL_ROW,
                    field,
                );
            }
            Err(error)
        }
        Ok(stored) => Ok(stored),
    }
}

/// One support assertion of `source` for `head`, carrying the `answers` the
/// head gives (FIX 7381). Returns the answers the assertion already keeps
/// when this attempt wrote it before: a replay compares everything else
/// exactly, and reads its binding back.
fn attach_ref(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    run: &DreamerRunContext,
    (head, source): (EntityId, EntityId),
    evidence: &VerifiedEvidenceSet,
    answers: &[ResolvedConflictOutput],
    auto_write_rate: crate::own_rate::OwnRate,
) -> Result<Vec<ResolvedConflictOutput>> {
    let evidence_meet = evidence.meet();
    let locators = evidence.verified_locators();
    if locators.is_empty()
        || locators
            .iter()
            .any(|(locator, _, _)| locator.source_id != source)
    {
        return Err(Error::InvalidClaimBody(
            "attachment locator source mismatch",
        ));
    }
    let head_raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &head)?
        .ok_or(Error::EntityNotFound)?;
    let source_raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &source)?
        .ok_or(Error::EntityNotFound)?;
    let edge = EdgeRef {
        source,
        kind: EdgeKind::Supports,
        target: head,
    };
    // The provenance row lands in the one project its source and head share;
    // a support across projects is refused before its edge is written, and a
    // replay binds the stored row to that same project.
    let project = crate::provenance::support_project(vault, txn, &edge, &source_raw, &head_raw)?;
    let head_hash = blake3::hash(&head_raw);
    let source_hash = blake3::hash(&source_raw);
    let mut hash = blake3::Hasher::new();
    hash.update(b"oneiron:dreamer-evidence-attachment:v1");
    hash.update(head.as_bytes());
    hash.update(source.as_bytes());
    hash.update(head_hash.as_bytes());
    hash.update(source_hash.as_bytes());
    hash.update(evidence_meet.as_str().as_bytes());
    // A witnessed TURN's revision is its row plus the MESSAGE revisions the
    // citation names; any other source keeps its row hash exactly.
    let mut revision = blake3::Hasher::new();
    revision.update(b"oneiron:dreamer-evidence-source-revision:v1");
    revision.update(source_hash.as_bytes());
    let mut named = false;
    for (locator, digest, messages) in &locators {
        hash.update(&[u8::from(locator.claim_id.is_some())]);
        if let Some(claim) = locator.claim_id {
            hash.update(claim.as_bytes());
        }
        hash.update(&[u8::from(locator.byte_range.is_some())]);
        if let Some((start, end)) = locator.byte_range {
            hash.update(&(start as u64).to_be_bytes());
            hash.update(&(end as u64).to_be_bytes());
        }
        hash.update(digest);
        for message in messages {
            message.hash_into(&mut hash);
            message.hash_into(&mut revision);
            named = true;
        }
    }
    let source_revision = if named {
        revision.finalize()
    } else {
        source_hash
    };
    let mut id = [0_u8; 16];
    id.copy_from_slice(&hash.finalize().as_bytes()[..16]);
    let id =
        EntityId::from_bytes(id).map_err(|_| Error::InvalidClaimBody("reserved attachment id"))?;
    let mut record = EdgeProvenanceClaimBody::new(
        run.agent_actor.entity_ref(),
        1.0,
        SupersessionStatus::Confirmed,
    );
    record.source_revision_ref = Some(
        source_revision.as_bytes()[..16]
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
            (Value::from(DERIVED_EVIDENCE_KEY), derived_evidence),
        ]);
        // The answers binding is compared apart: a replay may carry more or
        // fewer answers than the try that wrote it, and reads back the rest.
        let (stored_scope, stored_answers) = match existing.scope.as_ref() {
            Some(scope) => {
                let (scope, named) =
                    super::resolved_outputs::split_attachment_answers(scope, DERIVED_EVIDENCE_KEY);
                (Some(scope), named)
            }
            None => (None, Vec::new()),
        };
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
        if stored_scope.as_ref() != Some(&expected_scope)
            || existing.scope_project != project
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
        return Ok(stored_answers);
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
            generated_evidence: Some(super::resolved_outputs::with_answers(
                derived_evidence,
                &answers.iter().collect::<Vec<_>>(),
            )),
        },
    )?;
    // The new evidence assertion is an Auto write by the Dreamer actor, so it
    // counts on that actor's own-rate window, as a promoted claim does; the
    // replay above returned before this and counts nothing.
    crate::own_rate::count_in_txn(
        &vault.store,
        txn,
        crate::own_rate::OwnRateKind::AutoWrite,
        run.agent_actor.entity_ref(),
        vault.store.clock.now_recorded_at(),
        auto_write_rate,
    )?;
    #[cfg(test)]
    crate::own_rate::counted_auto_write(crate::own_rate::AutoWriteDoor::Attachment);
    evidence.record_message_dependencies_in_txn(vault, txn, &id)?;
    Ok(Vec::new())
}
