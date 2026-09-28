//! Real executor -> sealed sink -> durable evidence/provenance fixture.
use super::*;
use crate::dreamer_consolidation::resources::{BranchResources, document_version};
use crate::dreamer_promotion::{DreamerRunContext, PromotionWriterSink};
use crate::llm::Scope;
use std::future::Future;

struct Fixture {
    attempt: crate::dreamer_runner::DreamerAdmittedAttempt,
    turn: EntityId,
    subject: EntityId,
    head: EntityId,
    scope: Scope,
    run: DreamerRunContext,
}

pub(super) fn policy(vault: &Vault, reader: EntityId, auto: bool) -> Result<()> {
    let row = Value::Map(vec![
        ("max_auto_sensitivity".into(), 3_u64.into()),
        ("receipted".into(), true.into()),
        ("warned".into(), true.into()),
    ]);
    let manifest = Value::Map(vec![
        (
            "retry_source_policy".into(),
            Value::Array(vec![Value::Map(vec![
                ("selector".into(), "vault".into()),
                ("max_sources".into(), 1_024_u64.into()),
                ("precedence".into(), "nested_narrowing".into()),
            ])]),
        ),
        (
            "schema_version".into(),
            crate::gate::POLICY_SCHEMA_VERSION.into(),
        ),
        ("pack_id".into(), "prior-head-test".into()),
        ("pack_version".into(), "v1".into()),
        (
            "min_engine_version".into(),
            env!("CARGO_PKG_VERSION").into(),
        ),
        (
            "defaults".into(),
            Value::Map(vec![
                ("criticality".into(), "normal".into()),
                ("sensitivity".into(), "normal".into()),
            ]),
        ),
        ("rules".into(), Value::Array(Vec::new())),
        (
            "actor_ceilings".into(),
            Value::Array(
                ["agent", "human", "first_party"]
                    .map(|actor| {
                        Value::Map(vec![
                            ("actor_class".into(), actor.into()),
                            (
                                "ceiling".into(),
                                if actor == "agent" && !auto {
                                    "proposed"
                                } else {
                                    "auto"
                                }
                                .into(),
                            ),
                        ])
                    })
                    .to_vec(),
            ),
        ),
        (
            "source_trust".into(),
            Value::Map(
                [
                    ClaimSource::Generated,
                    ClaimSource::UserStated,
                    ClaimSource::Observed,
                    ClaimSource::Inferred,
                    ClaimSource::Imported,
                    ClaimSource::ToolOutput,
                ]
                .map(|source| (source.as_str().into(), row.clone()))
                .to_vec(),
            ),
        ),
        (
            "scoped_grants".into(),
            Value::Array(vec![Value::Map(vec![
                ("actor_ref".into(), reader.to_hex().into()),
                ("effector".into(), "core:read".into()),
                (
                    "scope".into(),
                    crate::federation::scope_codec::encode_scope_value(
                        &crate::federation::scope_codec::read_preset(),
                    )?,
                ),
                ("receipt_required".into(), false.into()),
            ])]),
        ),
        (
            "signature".into(),
            Value::Map(vec![
                ("alg".into(), "ed25519".into()),
                ("key_id".into(), "prior-test".into()),
                ("sig".into(), "prior-test-signature".into()),
            ]),
        ),
    ]);
    let bytes = super::super::support::encode_value(&manifest)?;
    crate::test_util::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id()?,
        &bytes,
    )
}

fn fixture(vault: &Vault) -> Result<Fixture> {
    fixture_with_head_source(vault, ClaimSource::UserStated)
}

fn fixture_with_head_source(vault: &Vault, source: ClaimSource) -> Result<Fixture> {
    let actor = vault.dreamer_authority()?;
    policy(vault, actor.entity_ref(), true)?;
    let store = DreamerRunnerStore::new(vault);
    let (attempt, turns, _) =
        admitted_attempt_fixture(vault, &store, 0x58, &[("user", "my name is Oleksii")])?;
    let subject = EntityId::now();
    let owner = EntityId::now();
    for id in [subject, owner] {
        vault.put_entity(&id, ENTITY_TYPE_PERSON, occurred(1), 1, b"person")?;
    }
    let head = EntityId::now();
    let envelope = WriteEnvelope::new(
        WriteActor::new(owner, EdgeActorClass::Human),
        source,
        WriteProvenance::new("owner statement".into())?,
        ClaimApprovalStatus::Approved,
    );
    vault
        .batch()
        .claim_candidate(
            &head,
            ClaimCandidate::new(
                "profile.name",
                ClaimSubject::Entity(subject),
                "Oleksii".into(),
                0.9,
            ),
            &envelope,
            occurred(2),
            2,
        )
        .commit()?;
    let (partition, _, _) = decode_partition_payload(&attempt.status.payload.input)?;
    let branch = BranchResources::open(
        vault,
        actor,
        partition,
        &turns,
        attempt.status.attempt.id,
        None,
    )?;
    let mut scope = branch.scope().clone();
    let pin = document_version(head, &vault.get(&head)?.expect("head body"));
    scope.readable.insert(pin.clone());
    scope.writable.insert(pin);
    // Project semantics remain the exact source/head document slice.
    scope.project = Some(EntityId::now());
    scope
        .writable
        .remove(&super::super::gap::branch_gap_projection(
            &partition,
            branch.scope(),
        ));
    scope
        .writable
        .insert(super::super::gap::branch_gap_projection(&partition, &scope));
    let run = DreamerRunContext {
        run_id: attempt.status.attempt.run_id.clone().expect("queued run"),
        attempt_id: attempt.status.attempt.id,
        agent_actor: actor,
        now_ms: 21_000,
    };
    Ok(Fixture {
        attempt,
        turn: turns[0],
        subject,
        head,
        scope,
        run,
    })
}

fn execute(
    vault: &Vault,
    fx: &Fixture,
    backend: &dyn LlmBackend,
    sink: &mut dyn ConsolidationSink,
    scope: Scope,
) -> Result<DreamerAttemptExecution> {
    execute_at_pin(vault, fx, backend, sink, scope, None)
}

fn execute_at_pin<'a>(
    vault: &'a Vault,
    fx: &Fixture,
    backend: &dyn LlmBackend,
    sink: &mut dyn ConsolidationSink,
    scope: Scope,
    pin: Option<&'a PreparedWake>,
) -> Result<DreamerAttemptExecution> {
    let guard = crate::BudgetGuard::with_reserve_units(
        "wake",
        10_000,
        100,
        BudgetExhaustionPolicy::Suspend,
    );
    let deadline = WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 0));
    let mut executor = ConsolidationExecutor {
        backend,
        guard: &guard,
        strategy: DreamerClaimAuthoringStrategy::SinglePass,
        actor: fx.run.agent_actor,
        model: crate::ModelId::new("test/model@r1").unwrap(),
        sink,
        scope: Some(scope),
    };
    block_on_ready(executor.execute(
        &fx.attempt,
        &mut WakeAttemptContext {
            vault,
            deadline: &deadline,
            budget_id: "wake",
            now_ms: 21_000,
            prepared_wake: pin,
            prepared_attempt: None,
        },
    ))
}

fn extract(fx: &Fixture, value: &str) -> crate::LlmResponse {
    text_response(
        serde_json::json!({"candidates": [{
            "subject": fx.subject.to_hex(), "predicate": "profile.name", "value": value,
            "evidence_refs": [{"source_id":fx.turn.to_hex(), "byte_range":[0,1]}], "confidence": 0.8,
        }]})
        .to_string(),
    )
}

fn names(vault: &Vault, subject: EntityId) -> Result<Vec<EntityId>> {
    vault
        .claims_for_subject(&subject)?
        .into_iter()
        .filter_map(|id| match vault.get_claim(&id) {
            Ok(Some(body)) if body.predicate == "profile.name" => Some(Ok(id)),
            Err(error) => Some(Err(error)),
            _ => None,
        })
        .collect()
}

#[test]
fn parent_classifies_admitted_claim_from_stored_body() -> Result<()> {
    let (_dir, vault) = open_vault();
    let fx = fixture(&vault)?;
    let (partition, turns, _) = decode_partition_payload(&fx.attempt.status.payload.input)?;
    // The head grant is supplied at execution, not in the queued payload.
    // The driver must capture that CLAIM at the SAME wake ledger revision.
    let snapshot = PreparedWake::capture_with_grants(
        &vault,
        DreamerConsolidationScope::Micro,
        Some(&fx.scope),
    )?;
    let resources = BranchResources::open_at_pin(
        &vault,
        fx.run.agent_actor,
        partition,
        &turns,
        fx.run.attempt_id,
        Some(&fx.scope),
        Some(&snapshot),
    )?;
    let claim = SwarmEvidenceRef {
        source_id: fx.head,
        claim_id: Some(fx.head),
        byte_range: None,
    };
    let collapsed = collapse_sibling_evidence(
        &resources,
        &[SwarmChildReturn {
            evidence: vec![claim, claim],
            candidates: Vec::new(),
        }],
    )?;
    assert_eq!(collapsed.independent.len(), 1);
    assert_eq!(collapsed.duplicates_collapsed, 1);
    assert_eq!(
        collapsed.independent[0].trust_class,
        ClaimSource::UserStated
    );
    let unbound = SwarmEvidenceRef {
        source_id: fx.turn,
        claim_id: Some(fx.head),
        byte_range: None,
    };
    assert!(resources.verify_evidence_refs(&[unbound]).is_err());
    Ok(())
}

#[test]
fn pinned_extraction_persists_parent_verified_locators_taint_and_integrity_marker() -> Result<()> {
    let (_dir, vault) = open_vault();
    let mut fx = fixture(&vault)?;
    let text = "my name is Oleksii ☕";
    let body = turn_body("user", text, None);
    let old = document_version(fx.turn, &vault.get(&fx.turn)?.expect("old turn"));
    vault.put_entity(&fx.turn, ENTITY_TYPE_TURN, occurred(10), 10, &body)?;
    fx.scope.readable.remove(&old);
    fx.scope.readable.insert(document_version(fx.turn, &body));
    let range_start = text.find('☕').expect("visible multibyte span");
    let range_end = range_start + "☕".len();
    let store = DreamerRunnerStore::new(&vault);
    let (partition, _, _) = decode_partition_payload(&fx.attempt.status.payload.input)?;
    let plan = ConsolidationPartitionPlan {
        key: partition,
        turns: vec![WorkingSetTurn {
            turn_id: fx.turn,
            role: DreamerTurnRole::User,
            learned_at: 10,
            conversation: Some(partition.conversation_ref),
        }],
        watermark_last_learned_at: 0,
    };
    store.enqueue_consolidation(crate::dreamer_runner::EnqueueDreamerConsolidationAttempt {
        scope: DreamerConsolidationScope::Micro,
        input: plan.scoped_input(&fx.scope)?,
        parent_attempt: None,
        dedupe_key: Some("pinned-locator-test".into()),
        run_id: Some("pinned-locator-test".into()),
        now: 22,
    })?;
    let pin = PreparedWake::capture(&vault, DreamerConsolidationScope::Micro)?;
    let next = match store.admit_next_consolidation(AdmitDreamerConsolidationAttempt {
        scope: DreamerConsolidationScope::Micro,
        local_node_id: crate::identity::load_or_mint_client_id(&vault)?,
        claim_authoring_tier: DreamerClaimAuthoringBatchTier::batch(),
        claim_authoring: DreamerClaimAuthoringAdmission::single_pass(),
        admission: AdmitDreamerAttempt {
            lease_owner: "pinned-worker".into(),
            now: 23,
            budget_id: "wake".into(),
            budget_total_units: 10_000,
            reserve_units: 100,
            started_milestone: None,
        },
    })? {
        DreamerConsolidationAdmissionOutcome::Admission(DreamerAdmissionOutcome::Admitted(
            next,
        )) => next,
        other => panic!("{other:?}"),
    };
    let expected_hash = swarm_evidence_content_hash(&text.as_bytes()[range_start..range_end]);
    let reply = text_response(
        serde_json::json!({"candidates":[{
            "subject": fx.subject.to_hex(), "predicate":"profile.nickname",
            "value":"Lex", "confidence":0.8,
            "evidence_refs":[
                {"source_id":fx.turn.to_hex(),"byte_range":[range_start,range_end]},
                {"source_id":fx.turn.to_hex(),"byte_range":[range_start,range_end]},
                {"source_id":fx.head.to_hex(),"claim_id":fx.head.to_hex()}
            ],
            "evidence_hashes":{
                fx.turn.to_hex():"00".repeat(32),
                fx.head.to_hex():"11".repeat(32)
            }
        }]})
        .to_string(),
    );
    let backend = ScriptedBackend::new(vec![Ok(reply)]);
    let guard = crate::BudgetGuard::with_reserve_units(
        "wake",
        10_000,
        100,
        BudgetExhaustionPolicy::Suspend,
    );
    let deadline = WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 0));
    let run = DreamerRunContext {
        run_id: "pinned-locator-test".into(),
        attempt_id: next.status.attempt.id,
        agent_actor: vault.dreamer_authority()?,
        now_ms: 23_000,
    };
    let mut sink = PromotionWriterSink::new(&vault, run);
    let markers = super::support::IntegrityCapture::default();
    let mut ctx = WakeAttemptContext {
        vault: &vault,
        deadline: &deadline,
        budget_id: "wake",
        now_ms: 23_000,
        prepared_wake: Some(&pin),
        prepared_attempt: None,
    };
    let mut executor = ConsolidationExecutor {
        backend: &backend,
        guard: &guard,
        strategy: DreamerClaimAuthoringStrategy::SinglePass,
        actor: vault.dreamer_authority()?,
        model: crate::ModelId::new("test/model@r1").expect("model"),
        sink: &mut sink,
        scope: None,
    };
    vault.set_consolidation_selection(&selection::SelectionConfig {
        soak_ms: 0,
        evidence_minimum: 3,
        ..Default::default()
    })?;
    assert!(
        matches!(
            markers.with_default(|| block_on_ready(executor.execute(&next, &mut ctx)))?,
            DreamerAttemptExecution::Deferred { .. }
        ),
        "a duplicate citation is not a third signal"
    );
    assert!(
        vault
            .claims_for_subject(&fx.subject)?
            .into_iter()
            .map(|id| vault.get_claim(&id))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .all(|body| body.predicate != "profile.nickname")
    );
    vault.set_consolidation_selection(&selection::SelectionConfig {
        soak_ms: 0,
        evidence_minimum: 2,
        ..Default::default()
    })?;
    assert!(matches!(
        markers.with_default(|| block_on_ready(executor.execute(&next, &mut ctx)))?,
        DreamerAttemptExecution::Completed { .. }
    ));
    drop(executor);
    assert_eq!(
        markers
            .markers()
            .iter()
            .filter(|value| value.contains("evidence_hash_mismatch"))
            .count(),
        4,
        "both TURN and admitted CLAIM mismatches survive both executions"
    );
    let [claim_id] = sink.outcome.landed.as_slice() else {
        panic!("one stored claim")
    };
    let stored = vault.get_claim(claim_id)?.expect("landed claim");
    assert_eq!(stored.source, Some(ClaimSource::Generated));
    assert_eq!(
        crate::claim::claim_evidence_taint(&stored),
        Some(ClaimSource::Generated)
    );
    let Value::Map(evidence) = stored.evidence.as_ref().expect("stored evidence") else {
        panic!("claim evidence map")
    };
    let candidate_evidence = evidence
        .iter()
        .find(|(key, _)| key.as_str() == Some("candidate_evidence"))
        .map(|(_, value)| value)
        .expect("candidate evidence");
    let envelope =
        super::super::decode_consolidation_evidence(candidate_evidence)?.expect("typed evidence");
    assert_eq!(envelope.source_meet, ClaimSource::Generated);
    assert_eq!(
        envelope.refs.into_iter().collect::<BTreeSet<_>>(),
        BTreeSet::from([fx.turn, fx.head])
    );
    let Value::Map(entries) = candidate_evidence else {
        panic!("candidate evidence map")
    };
    let Value::Array(locators) = entries
        .iter()
        .find(|(key, _)| key.as_str() == Some("locators"))
        .map(|(_, value)| value)
        .expect("verified locators")
    else {
        panic!("locator array")
    };
    assert_eq!(locators.len(), 2);
    assert!(locators.iter().any(|locator| {
        let Value::Map(fields) = locator else {
            return false;
        };
        fields.iter().any(|(key, value)| {
            key.as_str() == Some("content_hash") && value == &Value::Binary(expected_hash.to_vec())
        })
    }));
    Ok(())
}

#[test]
fn exact_persisted_head_attaches_evidence_without_judge_or_duplicate_and_survives_reopen()
-> Result<()> {
    let (dir, vault) = open_vault();
    let fx = fixture(&vault)?;
    let before = vault.get_raw(&fx.head)?.expect("head");
    let backend = ScriptedBackend::new(vec![Ok(extract(&fx, "Oleksii"))]);
    let mut sink = PromotionWriterSink::new(&vault, fx.run.clone());
    assert!(matches!(
        execute(&vault, &fx, &backend, &mut sink, fx.scope.clone())?,
        DreamerAttemptExecution::Completed { .. }
    ));
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1); // extraction only
    assert_eq!(sink.outcome.landed, vec![fx.head]);
    assert_eq!(vault.get_raw(&fx.head)?.as_ref(), Some(&before));
    assert_eq!(names(&vault, fx.subject)?, vec![fx.head]);
    assert_eq!(
        vault.sources(&fx.head, EdgeKind::Supports, None)?,
        vec![fx.turn]
    );
    let edges = vault.edges_out(&fx.turn)?;
    let support = edges
        .iter()
        .find(|edge| edge.kind == EdgeKind::Supports && edge.target == fx.head)
        .expect("evidence");
    assert!(support.provenance.is_some());
    assert!(
        vault
            .store
            .gate_decisions(1_000)?
            .iter()
            .any(|receipt| receipt.claim_id == Some(*fx.head.as_bytes())
                && receipt.actor_ref.as_deref()
                    == Some(fx.run.agent_actor.entity_ref().to_hex().as_str())
                && receipt.outcome == "allow")
    );
    // Memoized replay neither calls the model nor creates a duplicate edge.
    assert!(matches!(
        execute(&vault, &fx, &backend, &mut sink, fx.scope.clone())?,
        DreamerAttemptExecution::Completed { .. }
    ));
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    drop(sink);
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    assert_eq!(vault.get_raw(&fx.head)?.as_ref(), Some(&before));
    assert_eq!(names(&vault, fx.subject)?, vec![fx.head]);
    assert_eq!(
        vault.sources(&fx.head, EdgeKind::Supports, None)?,
        vec![fx.turn]
    );
    Ok(())
}

#[test]
fn fast_path_and_judge_merge_share_deferred_closure() -> Result<()> {
    for fast_path in [false, true] {
        let (_dir, vault) = open_vault();
        let fx = fixture_with_head_source(&vault, ClaimSource::Generated)?;
        if fast_path {
            let id = crate::gate::default_policy_manifest_id()?;
            let raw = vault.get_raw(&id)?.expect("manifest");
            let mut cursor = std::io::Cursor::new(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..]);
            let Value::Map(mut entries) = rmpv::decode::read_value(&mut cursor).expect("decode")
            else {
                panic!("manifest map");
            };
            entries.push((
                "single_valued_predicates".into(),
                Value::Array(vec!["profile.name".into()]),
            ));
            let bytes = super::super::support::encode_value(&Value::Map(entries))?;
            crate::test_util::put_policy_manifest_bytes(&vault, id, &bytes)?;
        }
        let mut script = vec![Ok(extract(&fx, "Alex"))];
        if !fast_path {
            script.push(Ok(text_response(
                "{\"resolution\":\"merge\",\"value\":\"Alex\"}".into(),
            )));
        }
        let backend = ScriptedBackend::new(script);
        let mut sink = PromotionWriterSink::new(&vault, fx.run.clone());
        assert!(matches!(
            execute(&vault, &fx, &backend, &mut sink, fx.scope.clone())?,
            DreamerAttemptExecution::Completed { .. }
        ));
        assert_eq!(
            backend.calls.load(Ordering::SeqCst),
            if fast_path { 1 } else { 2 }
        );
        let [new] = sink.outcome.pended.as_slice() else {
            panic!("one proposed replacement");
        };
        assert!(sink.outcome.landed.is_empty());
        assert!(sink.outcome.rejected.is_empty());
        let proposed = vault.get_claim(new)?.expect("persisted proposal");
        assert_eq!(proposed.approval, ClaimApprovalStatus::Proposed);
        assert_eq!(vault.pending_claim_supersession(new)?, Some(fx.head));
        assert_eq!(
            vault.get_claim(&fx.head)?.expect("old").lifecycle,
            crate::ClaimLifecycleStatus::Active
        );
        assert!(
            !vault
                .edges_out(new)?
                .iter()
                .any(|edge| edge.kind == EdgeKind::Supersedes)
        );
        assert!(
            vault
                .supersede_claim(new, &fx.head, fx.run.now_ms + 1)
                .is_err()
        );
        assert_eq!(vault.pending_claim_supersession(new)?, Some(fx.head));
        assert_eq!(
            vault.get_claim(&fx.head)?.expect("old").lifecycle,
            crate::ClaimLifecycleStatus::Active
        );
        assert!(
            !vault
                .edges_out(new)?
                .iter()
                .any(|edge| edge.kind == EdgeKind::Supersedes)
        );
        vault.grant_deferred_claim_auto(new, fx.run.now_ms + 1)?;
        assert_eq!(
            vault.get_claim(&fx.head)?.expect("closed").lifecycle,
            crate::ClaimLifecycleStatus::Superseded
        );
        assert!(
            vault
                .edges_out(new)?
                .iter()
                .any(|edge| edge.kind == EdgeKind::Supersedes && edge.target == fx.head)
        );
    }
    Ok(())
}

#[test]
fn saved_execution_scope_pins_claim_across_retry_wakes() -> Result<()> {
    let (_dir, vault) = open_vault();
    let fx = fixture(&vault)?;
    let store = DreamerRunnerStore::new(&vault);
    vault.set_consolidation_selection(&selection::SelectionConfig {
        soak_ms: 0,
        evidence_minimum: 3,
        ..Default::default()
    })?;
    let response = text_response(
        serde_json::json!({"candidates":[{
            "subject":fx.subject.to_hex(), "predicate":"profile.nickname", "value":"Lex",
            "evidence_refs":[
                {"source_id":fx.turn.to_hex(),"byte_range":[0,1]},
                {"source_id":fx.head.to_hex(),"claim_id":fx.head.to_hex()}
            ]
        }]})
        .to_string(),
    );
    let first_backend = ScriptedBackend::new(vec![Ok(response.clone())]);
    let first_pin = PreparedWake::capture_with_grants(
        &vault,
        DreamerConsolidationScope::Micro,
        Some(&fx.scope),
    )?;
    let mut sink = CapturingSink::default();
    let held = execute_at_pin(
        &vault,
        &fx,
        &first_backend,
        &mut sink,
        fx.scope.clone(),
        Some(&first_pin),
    )?;
    let DreamerAttemptExecution::Deferred {
        completed_units,
        retry_at,
    } = held
    else {
        panic!("first wake must schedule a selection retry")
    };
    store.defer_selection(
        &fx.attempt,
        crate::dreamer_runner::SettleDreamerBudget {
            budget_id: "wake".into(),
            child_attempt: fx.attempt.status.attempt.id,
            actual_units: completed_units,
            now: 21,
        },
        retry_at,
    )?;
    // The exact CLAIM grant exists only in the saved execution scope. A new
    // executor with no host bound must still pin it before retry admission.
    let second_pin = PreparedWake::capture(&vault, DreamerConsolidationScope::Micro)?;
    let next = match store.admit_next_consolidation(AdmitDreamerConsolidationAttempt {
        scope: DreamerConsolidationScope::Micro,
        local_node_id: crate::identity::load_or_mint_client_id(&vault)?,
        claim_authoring_tier: DreamerClaimAuthoringBatchTier::batch(),
        claim_authoring: DreamerClaimAuthoringAdmission::single_pass(),
        admission: AdmitDreamerAttempt {
            lease_owner: "second-wake".into(),
            now: retry_at,
            budget_id: "wake".into(),
            budget_total_units: 10_000,
            reserve_units: 100,
            started_milestone: None,
        },
    })? {
        DreamerConsolidationAdmissionOutcome::Admission(DreamerAdmissionOutcome::Admitted(row)) => {
            row
        }
        other => panic!("{other:?}"),
    };
    vault.set_consolidation_selection(&selection::SelectionConfig {
        soak_ms: 0,
        evidence_minimum: 2,
        ..Default::default()
    })?;
    let second_backend = ScriptedBackend::new(vec![Ok(response)]);
    let guard = crate::BudgetGuard::with_reserve_units(
        "wake",
        10_000,
        100,
        BudgetExhaustionPolicy::Suspend,
    );
    let deadline = WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 0));
    let mut executor = ConsolidationExecutor {
        backend: &second_backend,
        guard: &guard,
        strategy: DreamerClaimAuthoringStrategy::SinglePass,
        actor: vault.dreamer_authority()?,
        model: crate::ModelId::new("test/model@r1").expect("model"),
        sink: &mut sink,
        scope: None,
    };
    let mut ctx = WakeAttemptContext {
        vault: &vault,
        deadline: &deadline,
        budget_id: "wake",
        now_ms: retry_at * 1_000,
        prepared_wake: Some(&second_pin),
        prepared_attempt: None,
    };
    assert!(matches!(
        block_on_ready(executor.execute(&next, &mut ctx))?,
        DreamerAttemptExecution::Completed { .. }
    ));
    drop(executor);
    assert_eq!(sink.accepted.len(), 1);
    assert!(sink.accepted[0].evidence_turn_refs.contains(&fx.head));
    Ok(())
}

#[test]
fn wrapper_first_wake_consumes_explicit_host_claim_scope() -> Result<()> {
    let (_dir, vault) = open_vault();
    let fx = fixture(&vault)?;
    let store = DreamerRunnerStore::new(&vault);
    let (partition, _, watermark) = decode_partition_payload(&fx.attempt.status.payload.input)?;
    let queued =
        store.enqueue_consolidation(crate::dreamer_runner::EnqueueDreamerConsolidationAttempt {
            scope: DreamerConsolidationScope::Micro,
            input: super::super::partition::encode_partition_payload(&ConsolidationPartitionPlan {
                key: partition,
                turns: vec![WorkingSetTurn {
                    turn_id: fx.turn,
                    role: DreamerTurnRole::User,
                    learned_at: 10,
                    conversation: Some(partition.conversation_ref),
                }],
                watermark_last_learned_at: watermark,
            }),
            parent_attempt: None,
            dedupe_key: Some("wrapped-host-claim".into()),
            run_id: Some("wrapped-host-claim".into()),
            now: 22,
        })?;
    let attempt_id = match queued {
        EnqueueDreamerAttemptOutcome::Enqueued(row)
        | EnqueueDreamerAttemptOutcome::Existing(row) => row.attempt.id,
    };
    vault.set_consolidation_selection(&selection::SelectionConfig {
        soak_ms: 0,
        evidence_minimum: 2,
        ..Default::default()
    })?;
    let backend = ScriptedBackend::new(vec![Ok(text_response(
        serde_json::json!({"candidates":[{
            "subject":fx.subject.to_hex(), "predicate":"profile.nickname", "value":"Lex",
            "evidence_refs":[
                {"source_id":fx.turn.to_hex(),"byte_range":[0,1]},
                {"source_id":fx.head.to_hex(),"claim_id":fx.head.to_hex()}
            ]
        }]})
        .to_string(),
    ))]);
    let guard = crate::BudgetGuard::with_reserve_units(
        "wake",
        10_000,
        100,
        BudgetExhaustionPolicy::Suspend,
    );
    let run = DreamerRunContext {
        run_id: "wrapped-host-claim".into(),
        attempt_id,
        agent_actor: vault.dreamer_authority()?,
        now_ms: 23_000,
    };
    let mut sink = PromotionWriterSink::new(&vault, run);
    let inner = ConsolidationExecutor {
        backend: &backend,
        guard: &guard,
        strategy: DreamerClaimAuthoringStrategy::SinglePass,
        actor: vault.dreamer_authority()?,
        model: crate::ModelId::new("test/model@r1").expect("model"),
        sink: &mut sink,
        scope: None,
    };
    let mut wrapper = crate::commitment_wake::CommitmentWakeExecutor::new(
        inner,
        None,
        vault.dreamer_authority()?,
    )?;
    let deadline = WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 0));
    let mut driver = crate::dreamer_wake::DreamerWakeDriver::new(&vault, "wake", deadline);
    let input = crate::dreamer_wake::RunWakePass {
        trigger: crate::dreamer_wake::WakeTrigger::Compaction,
        scope: DreamerConsolidationScope::Micro,
        local_node_id: crate::identity::load_or_mint_client_id(&vault)?,
        lease_owner: "wrapped-worker".into(),
        budget_total_units: 10_000,
        reserve_units: 100,
        now: 23,
        host_scope: Some(fx.scope.clone()),
    };
    let report = {
        let cancellation = crate::dreamer_wake::WakeCancellation::new();
        let mut future = Box::pin(driver.run_wake_pass(input, &mut wrapper, &cancellation));
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        let mut completed = None;
        for _ in 0..128 {
            if let std::task::Poll::Ready(result) = future.as_mut().poll(&mut cx) {
                completed = Some(result?);
                break;
            }
        }
        completed.expect("wake must reach an attempt boundary")
    };
    drop(wrapper);
    assert_eq!(report.completed, 1);
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    let [written] = sink.outcome.landed.as_slice() else {
        panic!("one host-scoped claim")
    };
    let stored = vault.get_claim(written)?.expect("claim");
    let Value::Map(fields) = stored.evidence.expect("claim evidence") else {
        panic!("evidence")
    };
    let verified = fields
        .iter()
        .find(|(key, _)| key.as_str() == Some("candidate_evidence"))
        .map(|(_, value)| value)
        .expect("verified evidence");
    assert!(
        super::super::decode_verified_locators(verified)?
            .iter()
            .any(|(locator, _)| locator.claim_id == Some(fx.head))
    );
    Ok(())
}

fn attachment_wrapper(vault: &Vault, source: EntityId, head: EntityId) -> Result<ClaimBody> {
    let edge = crate::provenance::EdgeRef {
        source,
        kind: EdgeKind::Supports,
        target: head,
    };
    let mut matches = Vec::new();
    for id in vault.entities_by_type(crate::registry::ENTITY_TYPE_CLAIM)? {
        if let Some(body) = vault.get_claim(&id)?
            && body.predicate == crate::provenance::PREDICATE_EDGE_PROVENANCE
            && body.subject == ClaimSubject::from(edge)
        {
            matches.push(body);
        }
    }
    let [wrapper] = matches.as_slice() else {
        panic!("one support provenance wrapper")
    };
    Ok(wrapper.clone())
}

fn attached_evidence(wrapper: &ClaimBody) -> Value {
    let Some(Value::Map(scope)) = &wrapper.scope else {
        panic!("wrapper scope")
    };
    scope
        .iter()
        .find(|(key, _)| key.as_str() == Some("derived_evidence"))
        .map(|(_, value)| value.clone())
        .expect("durable derived evidence")
}

#[test]
fn pinned_exact_head_attachment_retains_visible_range_and_original_head() -> Result<()> {
    let (dir, vault) = open_vault();
    let fx = fixture(&vault)?;
    let raw = vault.get_raw(&fx.head)?.expect("original head");
    let text = "my name is Oleksii";
    let start = text.find("Oleksii").expect("quote");
    let end = start + "Oleksii".len();
    let digest = swarm_evidence_content_hash(&text.as_bytes()[start..end]);
    let pin = PreparedWake::capture_with_grants(
        &vault,
        DreamerConsolidationScope::Micro,
        Some(&fx.scope),
    )?;
    let response = text_response(
        serde_json::json!({"candidates":[{
            "subject":fx.subject.to_hex(), "predicate":"profile.name", "value":"Oleksii",
            "confidence":0.8,
            "evidence_refs":[{"source_id":fx.turn.to_hex(), "byte_range":[start,end]}]
        }]})
        .to_string(),
    );
    let backend = ScriptedBackend::new(vec![Ok(response)]);
    let mut sink = PromotionWriterSink::new(&vault, fx.run.clone());
    assert!(matches!(
        execute_at_pin(
            &vault,
            &fx,
            &backend,
            &mut sink,
            fx.scope.clone(),
            Some(&pin)
        )?,
        DreamerAttemptExecution::Completed { .. }
    ));
    assert_eq!(sink.outcome.landed, vec![fx.head]);
    assert_eq!(vault.get_raw(&fx.head)?.as_ref(), Some(&raw));
    let wrapper = attachment_wrapper(&vault, fx.turn, fx.head)?;
    assert_eq!(wrapper.source, Some(ClaimSource::Generated));
    assert_eq!(
        crate::claim::claim_evidence_taint(&wrapper),
        Some(ClaimSource::Generated)
    );
    let evidence = attached_evidence(&wrapper);
    let locators = super::super::decode_verified_locators(&evidence)?;
    assert_eq!(
        locators,
        vec![(
            SwarmEvidenceRef {
                source_id: fx.turn,
                claim_id: None,
                byte_range: Some((start, end))
            },
            digest
        )]
    );
    // A memoized retry neither duplicates the support edge nor drops its
    // verified locator from the replay-bound provenance row.
    assert!(matches!(
        execute_at_pin(
            &vault,
            &fx,
            &backend,
            &mut sink,
            fx.scope.clone(),
            Some(&pin)
        )?,
        DreamerAttemptExecution::Completed { .. }
    ));
    drop(sink);
    drop(vault);
    let reopened = Vault::open(dir.path(), VaultConfig::device())?;
    assert_eq!(reopened.get_raw(&fx.head)?.as_ref(), Some(&raw));
    assert_eq!(
        super::super::decode_verified_locators(&attached_evidence(&attachment_wrapper(
            &reopened, fx.turn, fx.head
        )?))?,
        locators
    );
    Ok(())
}

#[test]
fn pinned_exact_head_attachment_accepts_other_claim_with_restrictive_meet() -> Result<()> {
    let (dir, vault) = open_vault();
    let fx = fixture(&vault)?;
    let raw = vault.get_raw(&fx.head)?.expect("original head");
    let actor = EntityId::now();
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred(1), 1, b"actor")?;
    let cited = EntityId::now();
    let envelope = WriteEnvelope::new(
        WriteActor::new(actor, EdgeActorClass::Human),
        ClaimSource::Imported,
        WriteProvenance::new("outside citation".into())?,
        ClaimApprovalStatus::Approved,
    );
    vault
        .batch()
        .claim_candidate(
            &cited,
            ClaimCandidate::new(
                "profile.employer",
                ClaimSubject::Entity(fx.subject),
                "Elsewhere".into(),
                0.8,
            ),
            &envelope,
            occurred(2),
            2,
        )
        .commit()?;
    let mut scope = fx.scope.clone();
    scope.readable.insert(document_version(
        cited,
        &vault.get(&cited)?.expect("claim body"),
    ));
    let body = vault.get(&cited)?.expect("claim source body");
    let digest = swarm_evidence_content_hash(&body);
    let pin =
        PreparedWake::capture_with_grants(&vault, DreamerConsolidationScope::Micro, Some(&scope))?;
    let response = text_response(
        serde_json::json!({"candidates":[{
            "subject":fx.subject.to_hex(), "predicate":"profile.name", "value":"Oleksii",
            "confidence":0.8,
            "evidence_refs":[{"source_id":cited.to_hex(),"claim_id":cited.to_hex()}],
            "evidence_hashes":{cited.to_hex():"00".repeat(32)}
        }]})
        .to_string(),
    );
    let backend = ScriptedBackend::new(vec![Ok(response)]);
    let mut sink = PromotionWriterSink::new(&vault, fx.run.clone());
    let markers = super::support::IntegrityCapture::default();
    assert!(matches!(
        markers.with_default(|| execute_at_pin(
            &vault,
            &fx,
            &backend,
            &mut sink,
            scope,
            Some(&pin)
        ))?,
        DreamerAttemptExecution::Completed { .. }
    ));
    assert!(
        sink.outcome.rejected.is_empty(),
        "CLAIM citation must attach"
    );
    assert_eq!(sink.outcome.landed, vec![fx.head]);
    assert!(
        markers
            .markers()
            .iter()
            .any(|marker| marker.contains("evidence_hash_mismatch"))
    );
    assert_eq!(vault.get_raw(&fx.head)?.as_ref(), Some(&raw));
    let wrapper = attachment_wrapper(&vault, cited, fx.head)?;
    assert_eq!(wrapper.source, Some(ClaimSource::Imported));
    assert_eq!(
        crate::claim::claim_evidence_taint(&wrapper),
        Some(ClaimSource::Imported)
    );
    let locators = super::super::decode_verified_locators(&attached_evidence(&wrapper))?;
    assert_eq!(
        locators,
        vec![(
            SwarmEvidenceRef {
                source_id: cited,
                claim_id: Some(cited),
                byte_range: None
            },
            digest
        )]
    );
    drop(sink);
    drop(vault);
    let reopened = Vault::open(dir.path(), VaultConfig::device())?;
    assert_eq!(reopened.get_raw(&fx.head)?.as_ref(), Some(&raw));
    assert_eq!(
        super::super::decode_verified_locators(&attached_evidence(&attachment_wrapper(
            &reopened, cited, fx.head
        )?))?,
        locators
    );
    Ok(())
}

#[test]
fn claim_cited_conflict_meets_taint_and_preserves_gap_and_survivor() -> Result<()> {
    for fatal_judge in [false, true] {
        let (_dir, vault) = open_vault();
        let fx = fixture(&vault)?;
        let cited = EntityId::now();
        let actor = EntityId::now();
        vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred(1), 1, b"owner")?;
        let envelope = WriteEnvelope::new(
            WriteActor::new(actor, EdgeActorClass::Human),
            ClaimSource::Imported,
            WriteProvenance::new("imported citation".into())?,
            ClaimApprovalStatus::Approved,
        );
        vault
            .batch()
            .claim_candidate(
                &cited,
                ClaimCandidate::new(
                    "profile.employer",
                    ClaimSubject::Entity(fx.subject),
                    "Acme".into(),
                    0.8,
                ),
                &envelope,
                occurred(2),
                2,
            )
            .commit()?;
        let bytes = vault.get(&cited)?.expect("stored citation");
        let mut scope = fx.scope.clone();
        scope.readable.insert(document_version(cited, &bytes));
        let digest = swarm_evidence_content_hash(&bytes);
        let pin = PreparedWake::capture_with_grants(
            &vault,
            DreamerConsolidationScope::Micro,
            Some(&scope),
        )?;
        let extraction = text_response(
            serde_json::json!({"candidates":[
                {"subject":fx.subject.to_hex(), "predicate":"profile.name", "value":"Alex",
                 "evidence_refs":[{"source_id":cited.to_hex(), "claim_id":cited.to_hex()}]},
                {"subject":fx.subject.to_hex(), "predicate":"profile.tone", "value":"warm",
                 "evidence_refs":[{"source_id":fx.turn.to_hex(), "byte_range":[0,1]}]}
            ]})
            .to_string(),
        );
        let judge = if fatal_judge {
            Err(crate::LlmError::Fatal(crate::FatalLlmError::Auth))
        } else {
            Ok(text_response(r#"{"resolution":"escalate"}"#.into()))
        };
        let backend = ScriptedBackend::new(vec![Ok(extraction), judge]);
        let mut sink = PromotionWriterSink::new(&vault, fx.run.clone());
        vault.set_consolidation_selection(&selection::SelectionConfig {
            soak_ms: 0,
            evidence_minimum: 1,
            ..Default::default()
        })?;
        let outcome = execute_at_pin(&vault, &fx, &backend, &mut sink, scope, Some(&pin))?;
        assert!(matches!(outcome, DreamerAttemptExecution::Completed { .. }));
        let markers: Vec<_> = vault
            .claims_for_subject(&fx.subject)?
            .into_iter()
            .map(|id| vault.get_claim(&id))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .filter(|body| body.predicate == crate::claim::PREDICATE_CONFLICT_OPEN)
            .collect();
        let [marker] = markers.as_slice() else {
            panic!("one open marker")
        };
        assert_eq!(marker.source, Some(ClaimSource::Imported));
        assert_eq!(
            crate::claim::claim_evidence_taint(marker),
            Some(ClaimSource::Imported)
        );
        let Value::Map(evidence) = marker.evidence.as_ref().expect("marker evidence") else {
            panic!("evidence map")
        };
        let nested = evidence
            .iter()
            .find(|(key, _)| key.as_str() == Some("candidate_evidence"))
            .map(|(_, value)| value)
            .expect("candidate evidence");
        assert_eq!(
            super::super::decode_verified_locators(nested)?,
            vec![(
                SwarmEvidenceRef {
                    source_id: cited,
                    claim_id: Some(cited),
                    byte_range: None
                },
                digest
            )]
        );
        if !fatal_judge {
            assert!(sink.outcome.landed.iter().any(|id| {
                vault
                    .get_claim(id)
                    .is_ok_and(|claim| claim.is_some_and(|body| body.predicate == "profile.tone"))
            }));
            let resource = super::super::gap::branch_gap_projection(
                &decode_partition_payload(&fx.attempt.status.payload.input)?.0,
                &fx.scope,
            );
            let crate::llm::ScopeResource::Projection { key } = resource else {
                panic!("gap key")
            };
            let txn = vault.store.env.read_txn()?;
            let rows = vault
                .store
                .vault_meta
                .prefix_iter(&txn, key.as_bytes())?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let [(_, raw)] = rows.as_slice() else {
                panic!("durable contradiction gap")
            };
            let gap = super::super::gap::decode_gap_row(raw)?;
            assert_eq!(
                gap.evidence_refs,
                vec![SwarmEvidenceRef {
                    source_id: cited,
                    claim_id: Some(cited),
                    byte_range: None,
                }]
            );
            assert_eq!(
                super::super::decode_verified_locators(
                    gap.verified_evidence
                        .as_ref()
                        .expect("parent-verified gap evidence")
                )?,
                vec![(
                    SwarmEvidenceRef {
                        source_id: cited,
                        claim_id: Some(cited),
                        byte_range: None,
                    },
                    digest
                )],
            );
        }
    }
    Ok(())
}

struct JudgeBackend {
    inner: ScriptedBackend,
    requests: Mutex<Vec<LlmRequest>>,
}
impl LlmBackend for JudgeBackend {
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        self.requests.lock().unwrap().push(request.clone());
        self.inner.generate(request, lease)
    }
    fn stream<'a>(&'a self, request: LlmRequest, lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        self.inner.stream(request, lease)
    }
}

#[test]
fn different_value_consults_one_prior_and_outage_leaves_original_and_open_conflict() -> Result<()> {
    for outage in [false, true] {
        let (_dir, vault) = open_vault();
        let fx = fixture(&vault)?;
        let before = vault.get_raw(&fx.head)?.expect("head");
        let judge = if outage {
            Err(crate::LlmError::Fatal(crate::FatalLlmError::InvalidRequest))
        } else {
            Ok(text_response("{\"resolution\":\"accumulate\"}".into()))
        };
        let backend = JudgeBackend {
            inner: ScriptedBackend::new(vec![Ok(extract(&fx, "Alex")), judge]),
            requests: Mutex::new(Vec::new()),
        };
        let mut sink = PromotionWriterSink::new(&vault, fx.run.clone());
        let result = execute(&vault, &fx, &backend, &mut sink, fx.scope.clone())?;
        assert_eq!(backend.inner.calls.load(Ordering::SeqCst), 2);
        let requests = backend.requests.lock().unwrap();
        let user_text: String = requests[1]
            .messages
            .iter()
            .flat_map(|message| &message.content)
            .filter_map(|part| match part {
                ContentPart::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        assert!(user_text.contains(&fx.head.to_hex()));
        assert!(user_text.contains("Oleksii"));
        assert_eq!(vault.get_raw(&fx.head)?.as_ref(), Some(&before));
        if outage {
            // The fatal judge uses the durable escalation fallback. It completes
            // without replacing the original or losing the open question.
            assert!(matches!(result, DreamerAttemptExecution::Completed { .. }));
            assert_eq!(names(&vault, fx.subject)?, vec![fx.head]);
            let markers = vault
                .claims_for_subject(&fx.subject)?
                .into_iter()
                .map(|id| vault.get_claim(&id))
                .collect::<Result<Vec<_>>>()?;
            assert!(
                markers
                    .iter()
                    .flatten()
                    .any(|body| body.predicate == crate::claim::PREDICATE_CONFLICT_OPEN)
            );
        } else {
            assert!(matches!(result, DreamerAttemptExecution::Completed { .. }));
            assert_eq!(names(&vault, fx.subject)?.len(), 2);
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Drift {
    Source(EntityId),
    Head(EntityId),
    ReadGrant,
}

struct DriftSink<'a> {
    inner: PromotionWriterSink<'a>,
    drift: Drift,
}
impl ConsolidationSink for DriftSink<'_> {
    fn accept(&mut self, _candidates: Vec<PromotionCandidate>) -> Result<()> {
        panic!("scoped executor must not call unbounded persistence")
    }
    fn accept_scoped(&mut self, write: ScopedConsolidationWrite) -> Result<()> {
        match self.drift {
            Drift::Source(turn) => self.inner.vault.put_entity(
                &turn,
                ENTITY_TYPE_TURN,
                occurred(10),
                10,
                &turn_body("user", "changed after assembly", None),
            )?,
            Drift::Head(head) => {
                let mut body = self.inner.vault.get_claim(&head)?.expect("head");
                body.value = Value::from("owner corrected value");
                self.inner.vault.put_claim(&head, &body, occurred(2), 2)?;
            }
            Drift::ReadGrant => policy(self.inner.vault, EntityId::now(), true)?,
        }
        self.inner.accept_scoped(write)
    }
}

#[test]
fn missing_head_rights_revoked_actor_and_write_time_source_drift_refuse() -> Result<()> {
    for fault in [
        "read",
        "write",
        "actor",
        "gate",
        "revision",
        "new_revision",
        "head_revision",
        "read_revocation",
    ] {
        let (_dir, vault) = open_vault();
        let fx = fixture(&vault)?;
        let before = vault.get_raw(&fx.head)?.expect("head");
        let pin = document_version(fx.head, &vault.get(&fx.head)?.unwrap());
        let mut scope = fx.scope.clone();
        match fault {
            "read" => {
                scope.readable.remove(&pin);
            }
            "write" => {
                scope.writable.remove(&pin);
            }
            "actor" => policy(&vault, EntityId::now(), true)?,
            "gate" => policy(&vault, fx.run.agent_actor.entity_ref(), false)?,
            _ => {}
        }
        let backend = ScriptedBackend::new(vec![Ok(extract(&fx, "Oleksii"))]);
        let sink = PromotionWriterSink::new(&vault, fx.run.clone());
        let result = if fault.ends_with("revision") || fault == "read_revocation" {
            if fault == "new_revision" {
                // A genuinely new belief must carry the same transactional fence.
                scope.readable.remove(&pin);
                scope.writable.remove(&pin);
            }
            let drift = match fault {
                "head_revision" => Drift::Head(fx.head),
                "read_revocation" => Drift::ReadGrant,
                _ => Drift::Source(fx.turn),
            };
            let mut sink = DriftSink { inner: sink, drift };
            execute(&vault, &fx, &backend, &mut sink, scope)
        } else {
            let mut sink = sink;
            execute(&vault, &fx, &backend, &mut sink, scope)
        };
        assert!(result.is_err(), "{fault}");
        if fault == "head_revision" {
            assert_eq!(
                vault.get_claim(&fx.head)?.unwrap().value,
                Value::from("owner corrected value")
            );
        } else {
            assert_eq!(vault.get_raw(&fx.head)?.as_ref(), Some(&before));
        }
        assert_eq!(names(&vault, fx.subject)?, vec![fx.head]);
        assert!(
            vault
                .sources(&fx.head, EdgeKind::Supports, None)?
                .is_empty()
        );
    }
    Ok(())
}

#[test]
fn multiple_pinned_priors_remain_context_without_arbitrary_supersession() -> Result<()> {
    for resolution in ["merge", "escalate"] {
        let (_dir, vault) = open_vault();
        let mut fx = fixture(&vault)?;
        let second = EntityId::now();
        let mut body = vault.get_claim(&fx.head)?.unwrap();
        body.value = "Alexander".into();
        vault.put_claim(&second, &body, occurred(2), 2)?;
        let pin = document_version(second, &vault.get(&second)?.unwrap());
        fx.scope.readable.insert(pin.clone());
        fx.scope.writable.insert(pin);
        let originals = [vault.get_raw(&fx.head)?, vault.get_raw(&second)?];
        let backend = ScriptedBackend::new(vec![
            Ok(extract(&fx, "Alex")),
            Ok(text_response(
                serde_json::json!({"resolution": resolution, "value": "Alex"}).to_string(),
            )),
        ]);
        let mut sink = PromotionWriterSink::new(&vault, fx.run.clone());
        assert!(matches!(
            execute(&vault, &fx, &backend, &mut sink, fx.scope.clone())?,
            DreamerAttemptExecution::Completed { .. }
        ));
        assert_eq!(
            [vault.get_raw(&fx.head)?, vault.get_raw(&second)?],
            originals
        );
        if resolution == "merge" {
            assert_eq!(sink.outcome.landed.len(), 1, "{:?}", sink.outcome.rejected);
            assert_eq!(
                vault.get_claim(&sink.outcome.landed[0])?.unwrap().value,
                Value::from("Alex")
            );
        } else {
            let markers: Vec<_> = vault
                .claims_for_subject(&fx.subject)?
                .into_iter()
                .filter_map(|id| vault.get_claim(&id).transpose())
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .filter(|body| body.predicate == crate::claim::PREDICATE_CONFLICT_OPEN)
                .collect();
            assert_eq!(markers.len(), 1);
            let ids = markers[0]
                .value
                .as_map()
                .unwrap()
                .iter()
                .find(|(key, _)| key.as_str() == Some("prior_heads"))
                .unwrap()
                .1
                .as_array()
                .unwrap();
            assert!(ids.contains(&Value::Binary(fx.head.as_bytes().to_vec())));
            assert!(ids.contains(&Value::Binary(second.as_bytes().to_vec())));
        }
    }
    Ok(())
}
