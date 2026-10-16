use super::*;

use crate::Vault;
use crate::gate::ConsolidationReader;
use std::collections::BTreeSet;

mod history;
mod identity;
mod questions;
mod reserved;
mod skill;

fn reader_body() -> ClaimBody {
    public_stamped(source_trust_claim(ClaimSource::UserStated))
}

fn check_transition(
    vault: &Vault,
    id: EntityId,
    reader: ConsolidationReader,
    mut consumes: impl FnMut(&Vault, &EntityId) -> Result<bool>,
) -> Result<()> {
    let before = stored_claim_body(vault, &id)?;
    let pending = critical_confirm_pending(id, 0x70, crate::unix_seconds_now());
    vault.with_write_txn(|txn| vault.store.put_pending_gate_consent_in_txn(txn, &pending))?;
    let consumed = consumes(vault, &id)
        .unwrap_or_else(|error| panic!("FAILBEFORE H244 invariant: {reader:?}: {error:?}"));
    assert!(
        !consumed,
        "FAILBEFORE H244 invariant: {reader:?} consumed a claim awaiting its critical confirm"
    );
    assert_eq!(
        stored_claim_body(vault, &id)?,
        before,
        "{reader:?}: held claim changed"
    );
    // The owner's Clear answers the item and lets the claim go.
    vault.with_write_txn(|txn| {
        let removal = crate::gate::owner_answer::close_owner_answer_obligation_in_txn(
            &vault.store,
            txn,
            &id,
            &pending.diff_handle,
            crate::gate::owner_answer::OwnerAnswer::authority_log(),
        )?;
        vault
            .store
            .remove_pending_gate_consent_in_txn(txn, &id, removal)?;
        Ok(())
    })?;
    let consumed = consumes(vault, &id)
        .unwrap_or_else(|error| panic!("{reader:?}: settled reader failed: {error:?}"));
    assert!(
        consumed,
        "{reader:?}: the same claim was not consumed after settlement"
    );
    Ok(())
}

fn accepted<T>(result: Result<T>) -> Result<bool> {
    match result {
        Ok(_) => Ok(true),
        Err(Error::InvalidClaimBody(_)) => Ok(false),
        Err(error) => Err(error),
    }
}

/// A settled `coping.outcome` prior about `subject` whose strategy turn is
/// `turn`.
fn coping_prior_body(subject: EntityId, turn: EntityId) -> Result<ClaimBody> {
    use crate::affect::VadDelta;
    use crate::affect::coping::{
        COPING_OUTCOME_PREDICATE, CopingOutcomeValue, CopingStrategy, coping_outcome_value,
    };
    let delta = VadDelta::new(0.2, -0.1, 0.1)?;
    let value = CopingOutcomeValue::new(subject, turn, CopingStrategy::CogChg, delta, 0.8, 1)?;
    let mut body = reader_body();
    body.predicate = COPING_OUTCOME_PREDICATE.to_owned();
    body.value = coping_outcome_value(&value);
    body.confidence = 0.8;
    body.valid_from = Some(1);
    Ok(body)
}

/// A standing question about `subject` and its one answer: the question's id
/// and the answer's claim.
fn seed_question_answer(
    vault: &Vault,
    principal: EntityId,
    subject: EntityId,
    reader: ConsolidationReader,
) -> Result<(EntityId, EntityId)> {
    use crate::llm::decision::questions::{
        AnswerProposal, OutcomeBinding, OutcomeSource, RefreshTrigger, refresh_question,
    };
    use crate::llm::decision::{DecisionAnswer, DecisionRung, ProviderPin};
    // A question reads its unit through its principal's scoped read: both
    // rows land through the entity door, as a host writes them.
    for id in [principal, subject] {
        vault.put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"source",
        )?;
    }
    crate::test_util::authorize_readers(vault, &[&principal.to_hex()]);
    let binding = Some(OutcomeBinding {
        source: OutcomeSource::Claim {
            predicate: "profile.name".into(),
        },
        horizon: 100,
        mapping: std::collections::BTreeMap::from([("Ada".to_owned(), true)]),
        noise_weight: 1.0,
        linked_by: None,
    });
    let question = fixture_question(vault, principal, vec![subject], binding)?;
    let answers = refresh_question(
        vault,
        WriteActor::new(principal, EdgeActorClass::Human),
        principal,
        question,
        RefreshTrigger::Manual,
        1,
        |_, _, _| {
            Ok(AnswerProposal {
                answer: DecisionAnswer::Noul(true),
                probability: Some(0.8),
                providers: vec![ProviderPin {
                    rung: DecisionRung::Rule,
                    model: "fixture".into(),
                    version: "one".into(),
                }],
                paired: Vec::new(),
            })
        },
    )?;
    assert_eq!(answers.len(), 1, "{reader:?}: answer fixture");
    assert_eq!(answers[0].unit, subject, "{reader:?}: answer unit");
    Ok((question, answers[0].claim))
}

/// A standing graph question of `principal` over `units`; it learns from
/// `binding` when one is given.
fn fixture_question(
    vault: &Vault,
    principal: EntityId,
    units: Vec<EntityId>,
    binding: Option<crate::llm::decision::questions::OutcomeBinding>,
) -> Result<EntityId> {
    use crate::llm::decision::questions::{
        QuestionActivation, QuestionDefinition, RefreshPolicy, create_question,
    };
    use crate::llm::decision::{
        AnswerContract, DecisionBand, DecisionClass, DecisionDial, DecisionQuestion, DecisionRung,
    };
    let record = create_question(
        vault,
        principal,
        QuestionDefinition {
            question: DecisionQuestion {
                id: EntityId::now(),
                version: 1,
                text: "fixture question".into(),
                class: DecisionClass::Judgment,
                contract: AnswerContract::Noul,
                accept_type: false,
            },
            adapter: "graph".into(),
            units,
            recipe: "unit".into(),
            profile: "fixture".into(),
            dial: DecisionDial {
                first: DecisionRung::Rule,
                ceiling: DecisionRung::Big,
                band: DecisionBand::default(),
            },
            activation: QuestionActivation::Standing,
            refresh: RefreshPolicy {
                on_arrival: true,
                every_seconds: None,
            },
            delivery: "now".into(),
            learning: binding.is_some(),
            binding,
        },
        1,
    )?;
    Ok(record.definition.question.id)
}

/// The change-log rows the claim door writes beside a body, which the wake
/// count discovers claims by. The table seeds bodies raw.
fn log_claim_mutations(vault: &Vault, ids: &[EntityId]) -> Result<()> {
    vault.with_write_txn(|txn| {
        for id in ids {
            crate::ports::audit_mutation_in_txn(
                &vault.store,
                txn,
                crate::ports::MutationAudit {
                    entity: *id,
                    op: crate::ports::ChangeOp::Create,
                    actor_principal: None,
                    occurred_at: 1,
                    input: id.as_bytes(),
                    reason: None,
                },
            )?;
        }
        Ok(())
    })
}

fn project_one(vault: &Vault, id: EntityId) -> Result<usize> {
    vault.with_write_txn(|txn| {
        crate::llm::decision::questions::project_arrivals_in_txn(
            &vault.store,
            txn,
            &BTreeSet::from([id]),
        )
    })
}

#[test]
fn every_consolidation_reader_holds_a_claim_awaiting_its_critical_confirm() -> Result<()> {
    for reader in ConsolidationReader::ALL {
        let (_dir, vault) = temp_vault();
        let subject = test_id(0x21);
        let claim = test_id(0x40);
        let control = test_id(0x41);
        let head = test_id(0x48);
        let principal = test_id(0x43);
        put_raw_entity_row(&vault, &subject, ENTITY_TYPE_PERSON, b"subject")?;
        put_raw_entity_row(&vault, &principal, ENTITY_TYPE_PERSON, b"reader")?;
        for id in [claim, control, head] {
            put_claim_body(&vault, &id, &reader_body())?;
        }
        match reader {
            ConsolidationReader::ClaimVad => {
                use crate::affect::{Vad, VadAnnotation, VadAnnotationSource};
                let turn = test_id(0x44);
                put_raw_entity_row(&vault, &turn, ENTITY_TYPE_TURN, b"observation")?;
                let vad = Vad {
                    valence: 0.5,
                    arousal: 0.5,
                    dominance: 0.5,
                };
                vault.annotate_turn_vad(
                    &turn,
                    VadAnnotation {
                        vad,
                        source: VadAnnotationSource::UserSelfReport,
                        annotated_at: 2,
                    },
                )?;
                let mut body = reader_body();
                body.evidence = Some(Value::Array(vec![Value::Binary(turn.as_bytes().to_vec())]));
                put_claim_body(&vault, &claim, &body)?;
                check_transition(&vault, claim, reader, |v, id| {
                    match v.consolidate_claim_vad_now(id, 10) {
                        Ok(result) => {
                            assert_eq!(result.claim_id, *id, "{reader:?}: reader output");
                            assert_eq!(result.vad, Some(vad), "{reader:?}: reader output");
                            assert_eq!(result.evidence_turns.len(), 1, "{reader:?}: turn evidence");
                            assert_eq!(
                                result.evidence_turns[0].turn_id, turn,
                                "{reader:?}: turn evidence",
                            );
                            let derived = result
                                .reappraisal
                                .active_claim_id
                                .unwrap_or_else(|| panic!("{reader:?}: no VAD state landed"));
                            let landed = stored_claim_body(v, &derived)?;
                            assert_eq!(
                                landed.predicate, "affect.claim_vad",
                                "{reader:?}: VAD state"
                            );
                            assert_eq!(
                                landed.subject,
                                ClaimSubject::Entity(*id),
                                "{reader:?}: VAD state subject",
                            );
                            Ok(true)
                        }
                        Err(Error::InvalidClaimBody(_)) => Ok(false),
                        Err(error) => Err(error),
                    }
                })?;
            }
            ConsolidationReader::VadAnnotation => {
                use crate::affect::{Vad, VadAnnotation, VadAnnotationSource};
                // The consolidated claim is settled; only its turn's
                // annotation, itself a claim, waits for its confirm.
                let turn = test_id(0x44);
                put_raw_entity_row(&vault, &turn, ENTITY_TYPE_TURN, b"observation")?;
                let vad = Vad {
                    valence: 0.5,
                    arousal: 0.5,
                    dominance: 0.5,
                };
                vault.annotate_turn_vad(
                    &turn,
                    VadAnnotation {
                        vad,
                        source: VadAnnotationSource::UserSelfReport,
                        annotated_at: 2,
                    },
                )?;
                let annotation = crate::affect::vad_annotation_claim_id(ENTITY_TYPE_TURN, &turn)?;
                let mut body = reader_body();
                body.evidence = Some(Value::Array(vec![Value::Binary(turn.as_bytes().to_vec())]));
                put_claim_body(&vault, &claim, &body)?;
                check_transition(&vault, annotation, reader, |v, _| {
                    match v.consolidate_claim_vad_now(&claim, 10) {
                        Ok(result) => Ok(result.vad == Some(vad)),
                        Err(Error::InvalidClaimBody(_)) => Ok(false),
                        Err(error) => Err(error),
                    }
                })?;
                // Coping folds two turns' annotations into a settled prior;
                // only the later turn's annotation waits for its confirm.
                let baseline = test_id(0x45);
                let later = test_id(0x46);
                for (turn, valence) in [(baseline, 0.1), (later, 0.6)] {
                    put_raw_entity_row(&vault, &turn, ENTITY_TYPE_TURN, b"observation")?;
                    vault.annotate_turn_vad(
                        &turn,
                        VadAnnotation {
                            vad: Vad {
                                valence,
                                arousal: 0.5,
                                dominance: 0.5,
                            },
                            source: VadAnnotationSource::UserSelfReport,
                            annotated_at: 2,
                        },
                    )?;
                }
                put_claim_body(&vault, &control, &coping_prior_body(subject, baseline)?)?;
                let held = crate::affect::vad_annotation_claim_id(ENTITY_TYPE_TURN, &later)?;
                check_transition(&vault, held, reader, |v, _| {
                    accepted(
                        v.update_coping_outcome_from_turn_vad(&control, &baseline, &later, 0.8, 10),
                    )
                })?;
            }
            ConsolidationReader::CopingOutcome => {
                use crate::affect::VadDelta;
                let turn = test_id(0x44);
                put_raw_entity_row(&vault, &turn, ENTITY_TYPE_TURN, b"observation")?;
                let delta = VadDelta::new(0.2, -0.1, 0.1)?;
                put_claim_body(&vault, &claim, &coping_prior_body(subject, turn)?)?;
                check_transition(&vault, claim, reader, |v, id| {
                    match v.update_coping_outcome_from_turn_vad_delta(id, turn, delta, 0.8, 10) {
                        Ok(update) => {
                            assert_eq!(update.prior_claim_id, *id, "{reader:?}: reader output");
                            assert_ne!(update.active_claim_id, *id, "{reader:?}: reader output");
                            assert_eq!(
                                update.superseded_claim_ids,
                                vec![*id],
                                "{reader:?}: reader output",
                            );
                            assert_eq!(update.value.observed_n(), 2, "{reader:?}: reader output");
                            assert_eq!(
                                stored_claim_body(v, id)?.lifecycle,
                                ClaimLifecycleStatus::Superseded,
                                "{reader:?}: reader output",
                            );
                            assert_eq!(
                                stored_claim_body(v, &update.active_claim_id)?.lifecycle,
                                ClaimLifecycleStatus::Active,
                                "{reader:?}: reader output",
                            );
                            Ok(true)
                        }
                        Err(Error::InvalidClaimBody(_)) => Ok(false),
                        Err(error) => Err(error),
                    }
                })?;
            }
            ConsolidationReader::NewestClaims => {
                crate::test_util::authorize_readers(&vault, &[&principal.to_hex()]);
                for id in [claim, control, head] {
                    vault.put_edge(&id, EdgeKind::ClaimOf, &subject, 1.0)?;
                }
                check_transition(&vault, claim, reader, |v, id| {
                    let listed = v.newest_claim_ids_for_test(principal, subject)?;
                    assert!(
                        listed.contains(&control),
                        "{reader:?}: settled control missing"
                    );
                    assert!(listed.contains(&head), "{reader:?}: settled head missing");
                    Ok(listed.contains(id))
                })?;
            }
            ConsolidationReader::GraphSignal => {
                // The Dreamer reads its branch under the shipped policy's
                // Dreamer read row.
                put_policy_manifest_bytes(
                    &vault,
                    crate::gate::default_policy_manifest_id()?,
                    &crate::gate::default_policy_manifest()?,
                )?;
                // The Dreamer opens the branch, as a consolidation pass does.
                let conversation = test_id(0x49);
                vault.put_entity(
                    &conversation,
                    crate::registry::ENTITY_TYPE_SESSION,
                    test_time(1),
                    1,
                    b"session",
                )?;
                vault.put_edge(&claim, EdgeKind::ClaimOf, &subject, 1.0)?;
                let actor = vault.dreamer_authority()?;
                check_transition(&vault, claim, reader, |v, id| {
                    v.graph_source_in_slice_for_test(actor, conversation, id)
                })?;
            }
            ConsolidationReader::ExplicitPrior => {
                // The Dreamer reads its branch under the shipped policy's
                // Dreamer read row.
                put_policy_manifest_bytes(
                    &vault,
                    crate::gate::default_policy_manifest_id()?,
                    &crate::gate::default_policy_manifest()?,
                )?;
                let conversation = test_id(0x49);
                vault.put_entity(
                    &conversation,
                    crate::registry::ENTITY_TYPE_SESSION,
                    test_time(1),
                    1,
                    b"session",
                )?;
                let actor = vault.dreamer_authority()?;
                check_transition(&vault, claim, reader, |v, id| {
                    Ok(v.explicit_prior_ids_for_test(actor, conversation, *id)?
                        .contains(id))
                })?;
            }
            ConsolidationReader::FenceSource => {
                use crate::dreamer_consolidation::resources::ConsolidationFence;
                crate::test_util::authorize_readers(&vault, &[&principal.to_hex()]);
                let actor = WriteActor::new(principal, EdgeActorClass::Human);
                let fence = {
                    let txn = vault.store.env.read_txn()?;
                    ConsolidationFence::for_reader_test(&vault, &txn, actor, Some(claim))?
                };
                check_transition(&vault, claim, reader, |v, _| {
                    let txn = v.store.env.read_txn()?;
                    accepted(fence.validate_in_txn(v, &txn))
                })?;
            }
            ConsolidationReader::FenceReplacement => {
                use crate::dreamer_consolidation::resources::{ConsolidationFence, RowRevision};
                crate::test_util::authorize_readers(&vault, &[&principal.to_hex()]);
                let actor = WriteActor::new(principal, EdgeActorClass::Human);
                let fence = {
                    let txn = vault.store.env.read_txn()?;
                    let fence = ConsolidationFence::for_reader_test(&vault, &txn, actor, None)?;
                    let revision =
                        RowRevision::read_in(&vault, &txn, &claim)?.ok_or(Error::EntityNotFound)?;
                    fence.relies_on(claim, revision);
                    fence
                };
                check_transition(&vault, claim, reader, |v, _| {
                    let txn = v.store.env.read_txn()?;
                    accepted(fence.validate_in_txn(v, &txn))
                })?;
            }
            ConsolidationReader::PromotionEvidence => {
                assert!(
                    crate::dreamer_promotion::evidence_ref_admissible_for_test(&vault, &control,)?,
                    "{reader:?}: reader output"
                );
                check_transition(&vault, claim, reader, |v, id| {
                    crate::dreamer_promotion::evidence_ref_admissible_for_test(v, id)
                })?;
            }
            ConsolidationReader::PrecommitEvidence => {
                let candidate = precommit_body(
                    Value::from("Ada Lovelace"),
                    Some(Value::Map(vec![(
                        Value::from(crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY),
                        precommit_evidence(vec![claim]),
                    )])),
                );
                check_transition(&vault, claim, reader, |v, _| {
                    match v.dreamer_precommit_denial_for_test(&candidate)? {
                        Some(GateReasonCode::DenyDreamerNoEvidence) => Ok(false),
                        None => Ok(true),
                        other => panic!("{reader:?}: unexpected precommit refusal: {other:?}"),
                    }
                })?;
            }
            ConsolidationReader::ResolutionWaterfall => {
                use crate::ingest::{
                    EntityResolutionCandidate, evaluate_entity_resolution_waterfall,
                };
                let mut body = reader_body();
                body.predicate = "provider.enrichment".to_owned();
                body.value = Value::Map(vec![(Value::from("provider"), Value::from("fixture"))]);
                put_claim_body(&vault, &claim, &body)?;
                check_transition(&vault, claim, reader, |v, id| {
                    let result = evaluate_entity_resolution_waterfall(
                        v,
                        &[EntityResolutionCandidate {
                            subject,
                            confidence_claim_ref: *id,
                        }],
                        false,
                    )?;
                    if result.ranked.is_empty() {
                        assert_eq!(result.claims_suppressed, 1, "{reader:?}: reader output");
                        assert_eq!(result.selected, None, "{reader:?}: reader output");
                        Ok(false)
                    } else {
                        assert_eq!(result.claims_suppressed, 0, "{reader:?}: reader output");
                        assert_eq!(result.ranked.len(), 1, "{reader:?}: reader output");
                        assert_eq!(
                            result.ranked[0].candidate.confidence_claim_ref, *id,
                            "{reader:?}: reader output",
                        );
                        assert_eq!(result.selected, Some(subject), "{reader:?}: reader output");
                        Ok(true)
                    }
                })?;
            }
            ConsolidationReader::ArrivalFact => {
                use crate::llm::decision::questions::calibration_pairs;
                let (question, _) = seed_question_answer(&vault, principal, subject, reader)?;
                // The arrival road: a held fact projects no label.
                check_transition(&vault, claim, reader, |v, id| {
                    let count = project_one(v, *id)?;
                    let pairs = calibration_pairs(
                        v,
                        principal,
                        question,
                        crate::claim::CallerLocality::OnDevice,
                    )?;
                    assert_eq!(count, pairs.len(), "{reader:?}: reader output");
                    match count {
                        0 => Ok(false),
                        1 => {
                            assert_eq!(pairs[0].outcome.fact, *id, "{reader:?}: reader output");
                            Ok(true)
                        }
                        other => panic!("{reader:?}: unexpected projected labels: {other}"),
                    }
                })?;
                // The read road: a label already projected reads back only
                // while its fact is settled.
                let initial = calibration_pairs(
                    &vault,
                    principal,
                    question,
                    crate::claim::CallerLocality::OnDevice,
                )?;
                assert_eq!(initial.len(), 1, "{reader:?}: reader output");
                assert_eq!(initial[0].outcome.fact, claim, "{reader:?}: reader output");
                check_transition(&vault, claim, reader, |v, id| {
                    let pairs = calibration_pairs(
                        v,
                        principal,
                        question,
                        crate::claim::CallerLocality::OnDevice,
                    )?;
                    if pairs.is_empty() {
                        Ok(false)
                    } else {
                        assert_eq!(pairs, initial, "{reader:?}: reader output");
                        assert_eq!(pairs[0].outcome.fact, *id, "{reader:?}: reader output");
                        Ok(true)
                    }
                })?;
            }
            ConsolidationReader::StateIndexSignal => {
                use crate::affect::state_index::{ENGAGEMENT, GOAL_VELOCITY, StateIndexEvidence};
                use crate::affect::{Vad, VadAnnotation, VadAnnotationSource};
                let turn = test_id(0x44);
                put_raw_entity_row(&vault, &turn, ENTITY_TYPE_TURN, b"observation")?;
                vault.annotate_turn_vad(
                    &turn,
                    VadAnnotation {
                        vad: Vad {
                            valence: 0.5,
                            arousal: 0.5,
                            dominance: 0.5,
                        },
                        source: VadAnnotationSource::UserSelfReport,
                        annotated_at: 2,
                    },
                )?;
                for (id, predicate) in [(claim, GOAL_VELOCITY), (control, ENGAGEMENT)] {
                    let mut body = reader_body();
                    body.subject = ClaimSubject::Entity(subject);
                    body.predicate = predicate.to_owned();
                    body.value = Value::F32(0.5);
                    put_claim_body(&vault, &id, &body)?;
                }
                let evidence = StateIndexEvidence {
                    vad_turns: vec![turn],
                    goal_velocity: claim,
                    engagement: control,
                };
                check_transition(&vault, claim, reader, |v, _| {
                    accepted(v.derive_state_index(&subject, &evidence, 10))
                })?;
            }
            ConsolidationReader::AnswerPrediction => {
                questions::answer_prediction(&vault, [principal, subject, claim], reader)?;
            }
            ConsolidationReader::WakeCount => {
                log_claim_mutations(&vault, &[claim, control])?;
                check_transition(&vault, claim, reader, |v, id| {
                    let pending = v.wake_pending_records_for_test()?;
                    assert!(
                        pending.contains(&control.to_hex()),
                        "{reader:?}: settled control missing"
                    );
                    Ok(pending.contains(&id.to_hex()))
                })?;
            }
            ConsolidationReader::DerivedSupport => {
                use crate::dreamer_consolidation::{
                    ConsolidationEvidenceEnvelope, encode_consolidation_evidence,
                    swarm_evidence_content_hash,
                };
                let edge = EdgeRef::new(claim, EdgeKind::Supports, head);
                let bytes = crate::claim::encode_claim_body(&stored_claim_body(&vault, &claim)?)?;
                let hash = swarm_evidence_content_hash(&bytes);
                let mut evidence = encode_consolidation_evidence(&ConsolidationEvidenceEnvelope {
                    refs: vec![claim],
                    chain: Vec::new(),
                    source_meet: ClaimSource::Generated,
                });
                let Value::Map(fields) = &mut evidence else {
                    panic!("{reader:?}: evidence fixture is not a map");
                };
                fields.push((
                    Value::from("locators"),
                    Value::Array(vec![Value::Map(vec![
                        (
                            Value::from("source_id"),
                            Value::Binary(claim.as_bytes().to_vec()),
                        ),
                        (
                            Value::from("claim_id"),
                            Value::Binary(claim.as_bytes().to_vec()),
                        ),
                        (Value::from("content_hash"), Value::Binary(hash.to_vec())),
                    ])]),
                ));
                let actor = WriteActor::new(principal, EdgeActorClass::Human);
                check_transition(&vault, claim, reader, |v, _| {
                    match v.verify_derived_support_for_test(&edge, &evidence, actor) {
                        Ok((source, project)) => {
                            assert_eq!(source, ClaimSource::Generated, "{reader:?}: evidence meet",);
                            assert_eq!(
                                project,
                                stored_claim_body(v, &head)?.scope_project,
                                "{reader:?}: support project",
                            );
                            Ok(true)
                        }
                        Err(Error::InvalidClaimBody(_)) => Ok(false),
                        Err(error) => Err(error),
                    }
                })?;
            }
            ConsolidationReader::ProviderPrior => reserved::provider_prior(&vault, reader)?,
            ConsolidationReader::CriticOutcome => reserved::critic_outcome(reader)?,
            ConsolidationReader::CriticReliability => reserved::critic_reliability(reader)?,
            ConsolidationReader::ProviderConfidence => {
                reserved::provider_confidence(&vault, claim, reader)?;
            }
            ConsolidationReader::PprCommunity => {
                reserved::ppr_community(&vault, claim, control, reader)?;
            }
            ConsolidationReader::SkillReliabilityProjection => {
                skill::reliability_projection(&vault, reader)?;
            }
            ConsolidationReader::SkillReliabilityPosterior => {
                skill::reliability_posterior(&vault, reader)?;
            }
            ConsolidationReader::SkillHubPrior => skill::hub_prior(&vault, reader)?,
            ConsolidationReader::SkillScanPrior => skill::scan_prior(&vault, reader)?,
            ConsolidationReader::SkillOptimizeHubVouch => {
                skill::optimize_hub_vouch(&vault, reader)?;
            }
            ConsolidationReader::SkillOptimizeCitations => {
                skill::optimize_citations(&vault, reader)?;
            }
            ConsolidationReader::HubDefaultPresence => skill::hub_default_presence(&vault, reader)?,
            ConsolidationReader::ActorSkillFit => {
                identity::actor_skill_fit(&vault, subject, reader)?;
            }
            ConsolidationReader::EditCost => identity::edit_cost(&vault, subject, reader)?,
            ConsolidationReader::PeerBinding => identity::peer_binding(&vault, principal, reader)?,
            ConsolidationReader::ActorSubjectAnchor => {
                identity::actor_subject_anchor(&vault, principal, subject, reader)?;
            }
            ConsolidationReader::DefaultFacet => identity::default_facet(&vault, reader)?,
            ConsolidationReader::EdgeProvenance => identity::edge_provenance(reader)?,
            ConsolidationReader::MachineHistory => history::machine_history(reader)?,
            ConsolidationReader::EsignLedger => history::esign_ledger(reader)?,
            ConsolidationReader::RepresentationSource => {
                identity::representation_source(reader)?;
            }
            ConsolidationReader::GraphAnswer => {
                questions::graph_answer(&vault, [principal, subject, claim, control], reader)?;
            }
            ConsolidationReader::StandingAnswerSource => {
                questions::standing_answer_source(&vault, [principal, subject, claim], reader)?;
            }
            ConsolidationReader::QuestionRefreshSource => {
                questions::question_refresh_source(&vault, [principal, subject, claim], reader)?;
            }
        }
    }
    Ok(())
}
