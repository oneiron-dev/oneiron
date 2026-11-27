//! Project-partitioned consolidation (P1-SLICE): one conversation, one world,
//! one facet, two stored projects. Every TURN's project is stamped BEFORE the
//! scan, as the leader-chat write doors settle it.
use super::witnessed_turns::RecordingBackend;
use super::*;
use crate::dreamer_promotion::{DreamerRunContext, PromotionWriterSink};
use std::collections::{BTreeMap, BTreeSet};

/// A TURN with one world/facet and a stored project, stamped as a leader-chat
/// turn is. Reuses `scope_enforcement::seed_project_turn`, then adds the axes.
fn seed_axis_turn(
    vault: &Vault,
    conversation: &EntityId,
    text: &str,
    learned_at: u64,
    project: EntityId,
    world: EntityId,
    facet: EntityId,
) -> Result<EntityId> {
    let id = super::scope_enforcement::seed_project_turn(
        vault,
        conversation,
        text,
        learned_at,
        project,
    )?;
    let mut source = super::super::support::decode_value(&turn_body("user", text, Some(&facet)))?;
    let Value::Map(source_entries) = &mut source else {
        panic!("turn map");
    };
    source_entries.push((
        Value::from(TURN_BODY_WORLD_REF_KEY),
        Value::Binary(world.as_bytes().to_vec()),
    ));
    vault.put_entity(
        &id,
        ENTITY_TYPE_TURN,
        occurred(learned_at),
        learned_at,
        &super::super::support::encode_value(&source)?,
    )?;
    vault.with_write_txn_grouped(|txn| {
        crate::federation::record_scope::stamp_leader_project(&vault.store, txn, id, project)
    })?;
    Ok(id)
}

/// Request texts of a recording backend, in call order.
fn request_texts(backend: &RecordingBackend) -> Vec<String> {
    backend
        .requests
        .lock()
        .expect("request log")
        .iter()
        .map(|request| {
            request
                .messages
                .iter()
                .flat_map(|message| &message.content)
                .filter_map(|part| match part {
                    ContentPart::Text { text, .. } => Some(text.as_str()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("")
        })
        .collect()
}

/// Main's partition preimage (the keep test's baseline): domain, "partition",
/// conversation, world, facet, with no project suffix.
fn baseline_partition_hash(
    conversation: EntityId,
    world: Option<EntityId>,
    facet: Option<EntityId>,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron:dreamer-bucket:v1");
    hasher.update(b"partition");
    hasher.update(conversation.as_bytes());
    match world {
        Some(id) => {
            hasher.update(&[1]);
            hasher.update(id.as_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
    match facet {
        Some(id) => {
            hasher.update(&[1]);
            hasher.update(id.as_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
    *hasher.finalize().as_bytes()
}

/// Admits the next queued Micro consolidation attempt.
fn admit_next(
    vault: &Vault,
    store: &DreamerRunnerStore,
    node: u64,
    now: u64,
) -> Result<crate::dreamer_runner::DreamerAdmittedAttempt> {
    match store.admit_next_consolidation(AdmitDreamerConsolidationAttempt {
        scope: DreamerConsolidationScope::Micro,
        local_node_id: node,
        claim_authoring_tier: DreamerClaimAuthoringBatchTier::batch(),
        claim_authoring: DreamerClaimAuthoringAdmission::single_pass(),
        admission: AdmitDreamerAttempt {
            lease_owner: "consolidation-test".to_owned(),
            now,
            budget_id: "wake".to_owned(),
            budget_total_units: 10_000,
            reserve_units: 100,
            started_milestone: None,
        },
    })? {
        DreamerConsolidationAdmissionOutcome::Admission(DreamerAdmissionOutcome::Admitted(
            admitted,
        )) => Ok(*admitted),
        other => panic!("expected admitted consolidation attempt, got {other:?}"),
    }
}

/// Executes one admitted attempt directly, as a resumed lease runs it.
fn execute_one(
    vault: &Vault,
    admitted: &crate::dreamer_runner::DreamerAdmittedAttempt,
    backend: &dyn LlmBackend,
    sink: &mut dyn ConsolidationSink,
) -> Result<DreamerAttemptExecution> {
    let guard = crate::BudgetGuard::with_reserve_units(
        "wake",
        10_000,
        100,
        BudgetExhaustionPolicy::Suspend,
    );
    let deadline = WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 0));
    let mut executor = ConsolidationExecutor {
        roles: Default::default(),
        backend,
        guard: &guard,
        strategy: DreamerClaimAuthoringStrategy::SinglePass,
        actor: vault.dreamer_authority()?,
        model: crate::ModelId::new("test/model@r1").unwrap(),
        sink,
        inference: test_inference_host(),
        scope: None,
        decisions: ConsolidationDecisions::shipped()?,
    };
    block_on_ready(executor.execute(
        admitted,
        &mut WakeAttemptContext {
            vault,
            deadline: &deadline,
            cancel: None,
            device_cancel: None,
            budget_id: "wake",
            now_ms: 21_000,
            prepared_wake: None,
            prepared_attempt: None,
            spend_meter: None,
        },
    ))
}

#[test]
fn a_window_with_two_projects_plans_two_partitions_and_two_calls() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let conversation = seed_session(&vault, 0x5a, 1);
    let world = EntityId::now();
    let facet = EntityId::now();
    let (project_p, project_q) = (EntityId::now(), EntityId::now());
    let turn_p = seed_axis_turn(
        &vault,
        &conversation,
        "call me Owen alpha-p-marker",
        10,
        project_p,
        world,
        facet,
    )?;
    let turn_q = seed_axis_turn(
        &vault,
        &conversation,
        "call me Owen beta-q-marker",
        11,
        project_q,
        world,
        facet,
    )?;
    let subject = EntityId::now();
    let named =
        super::super::support::encode_value(&Value::Map(vec![("name".into(), "Owen".into())]))?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred(1), 1, &named)?;
    let scope = DreamerConsolidationScope::Micro;
    let watermark = read_watermark(&vault, scope)?;
    let dirty = scan_dirty_turns(&vault, scope, &watermark, 10)?;
    let plans = plan_partitions(&vault, scope, &dirty, &watermark)?;
    assert_eq!(plans.len(), 2, "two projects plan two partitions");
    assert_eq!(plans[0].key.conversation_ref, plans[1].key.conversation_ref);
    assert_eq!(plans[0].key.world_ref, plans[1].key.world_ref);
    assert_eq!(plans[0].key.facet_ref, plans[1].key.facet_ref);
    assert_ne!(plans[0].key.project, plans[1].key.project);
    let mut by_project = BTreeMap::new();
    for plan in &plans {
        assert_eq!(plan.turns.len(), 1);
        by_project.insert(plan.key.project, plan.turns[0].turn_id);
    }
    assert_eq!(by_project.get(&Some(project_p)), Some(&turn_p));
    assert_eq!(by_project.get(&Some(project_q)), Some(&turn_q));
    enqueue_partition_attempts(&vault, scope, &dirty, &watermark, "run-1", 20)?;
    let node = crate::identity::load_or_mint_client_id(&vault)?;
    let first = admit_next(&vault, &store, node, 21)?;
    let second = admit_next(&vault, &store, node, 21)?;
    let reply = || {
        text_response(
            serde_json::json!({"candidates": [{
                "subject": "P1", "predicate": "profile.name", "value": "Owen",
                "confidence": 0.8, "evidence_refs": [{"source": "T1", "quote": "Owen"}]
            }]})
            .to_string(),
        )
    };
    let backend = RecordingBackend::new(vec![Ok(reply()), Ok(reply())]);
    let mut sink = CapturingSink::default();
    for admitted in [&first, &second] {
        assert!(matches!(
            execute_one(&vault, admitted, &backend, &mut sink)?,
            DreamerAttemptExecution::Completed { .. }
        ));
    }
    assert_eq!(backend.inner.calls.load(Ordering::SeqCst), 2);
    let texts = request_texts(&backend);
    assert_eq!(texts.len(), 2);
    assert!(
        texts
            .iter()
            .any(|text| text.contains("alpha-p-marker") && !text.contains("beta-q-marker"))
    );
    assert!(
        texts
            .iter()
            .any(|text| text.contains("beta-q-marker") && !text.contains("alpha-p-marker"))
    );
    Ok(())
}

#[test]
fn a_claim_from_one_projects_call_showed_and_cites_only_that_project() -> Result<()> {
    let (_dir, vault) = open_vault();
    super::prior_heads::policy(&vault, vault.dreamer_authority()?.entity_ref(), true)?;
    let store = DreamerRunnerStore::new(&vault);
    let conversation = seed_session(&vault, 0x5a, 1);
    let world = EntityId::now();
    let facet = EntityId::now();
    let (project_p, project_q) = (EntityId::now(), EntityId::now());
    let turn_p = seed_axis_turn(
        &vault,
        &conversation,
        "call me Owen alpha-p-marker",
        10,
        project_p,
        world,
        facet,
    )?;
    let turn_q = seed_axis_turn(
        &vault,
        &conversation,
        "call me Owen beta-q-marker",
        11,
        project_q,
        world,
        facet,
    )?;
    let subject = EntityId::now();
    let named =
        super::super::support::encode_value(&Value::Map(vec![("name".into(), "Owen".into())]))?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred(1), 1, &named)?;
    let scope = DreamerConsolidationScope::Micro;
    let watermark = read_watermark(&vault, scope)?;
    let dirty = scan_dirty_turns(&vault, scope, &watermark, 10)?;
    let plans = plan_partitions(&vault, scope, &dirty, &watermark)?;
    assert_eq!(plans.len(), 2);
    enqueue_partition_attempts(&vault, scope, &dirty, &watermark, "run-1", 20)?;
    let node = crate::identity::load_or_mint_client_id(&vault)?;
    let first = admit_next(&vault, &store, node, 21)?;
    let second = admit_next(&vault, &store, node, 21)?;
    let mut admitted_p = None;
    let mut admitted_q = None;
    for admitted in [&first, &second] {
        let queued = decode_partition_payload(&admitted.status.payload.input)?;
        if queued.project == Some(project_p) {
            admitted_p = Some(admitted);
        } else if queued.project == Some(project_q) {
            admitted_q = Some(admitted);
        }
    }
    let (admitted_p, admitted_q) = (
        admitted_p.expect("P attempt"),
        admitted_q.expect("Q attempt"),
    );
    let reply = || {
        text_response(
            serde_json::json!({"candidates": [{
                "subject": "P1", "predicate": "profile.name", "value": "Owen",
                "confidence": 0.8, "evidence_refs": [{"source": "T1", "quote": "Owen"}]
            }]})
            .to_string(),
        )
    };
    let backend = RecordingBackend::new(vec![Ok(reply()), Ok(reply())]);
    let run_p = DreamerRunContext {
        run_id: admitted_p
            .status
            .attempt
            .run_id
            .clone()
            .unwrap_or_else(|| "run-1".into()),
        attempt_id: admitted_p.status.attempt.id,
        agent_actor: vault.dreamer_authority()?,
        now_ms: 21_000,
    };
    let mut sink_p = PromotionWriterSink::new(&vault, run_p);
    let mut sink_q = CapturingSink::default();
    assert!(matches!(
        execute_one(&vault, admitted_p, &backend, &mut sink_p)?,
        DreamerAttemptExecution::Completed { .. }
    ));
    assert!(matches!(
        execute_one(&vault, admitted_q, &backend, &mut sink_q)?,
        DreamerAttemptExecution::Completed { .. }
    ));
    assert_eq!(backend.inner.calls.load(Ordering::SeqCst), 2);
    let texts = request_texts(&backend);
    assert_eq!(texts.len(), 2);
    assert!(texts[0].contains("alpha-p-marker") && !texts[0].contains("beta-q-marker"));
    assert!(texts[1].contains("beta-q-marker") && !texts[1].contains("alpha-p-marker"));
    let [landed] = sink_p.outcome.landed.as_slice() else {
        panic!("one P claim landed: {:?}", sink_p.outcome);
    };
    let stored = vault.get_claim(landed)?.expect("landed claim");
    assert_eq!(stored.scope_project, project_p);
    let Value::Map(evidence) = stored.evidence.as_ref().expect("stored evidence") else {
        panic!("claim evidence map");
    };
    let candidate_evidence = evidence
        .iter()
        .find(|(key, _)| key.as_str() == Some("candidate_evidence"))
        .map(|(_, value)| value)
        .expect("candidate evidence");
    let envelope =
        super::super::decode_consolidation_evidence(candidate_evidence)?.expect("typed evidence");
    assert_eq!(
        envelope.refs.into_iter().collect::<BTreeSet<_>>(),
        BTreeSet::from([turn_p])
    );
    for (project, readable) in [(project_p, true), (project_q, false)] {
        let read = vault
            .scoped_read(
                crate::claim::ScopedReadActorKey::for_engine_actor(vault.dreamer_authority()?)
                    .expect("Dreamer read key"),
            )
            .with_claim_status(crate::claim::ClaimReadStatus::Recorded)
            .within_session_projects(crate::session_project::SessionProjects::Bound {
                project,
                closure: std::sync::Arc::new(BTreeSet::from([project])),
            })
            .get_entity_parts_with_receipt(landed, None)?
            .value
            .is_some();
        assert_eq!(read, readable, "P-placed reads P, Q-placed does not");
    }
    assert_eq!(sink_q.accepted.len(), 1);
    assert_eq!(sink_q.accepted[0].evidence_turn_refs, vec![turn_q]);
    Ok(())
}

#[test]
fn an_old_form_queued_row_with_two_projects_makes_one_call_per_project() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let conversation = seed_session(&vault, 0x5a, 1);
    let world = EntityId::now();
    let facet = EntityId::now();
    let (project_p, project_q) = (EntityId::now(), EntityId::now());
    let turn_p = seed_axis_turn(
        &vault,
        &conversation,
        "call me Owen alpha-p-marker",
        10,
        project_p,
        world,
        facet,
    )?;
    let turn_q = seed_axis_turn(
        &vault,
        &conversation,
        "call me Owen beta-q-marker",
        11,
        project_q,
        world,
        facet,
    )?;
    let subject = EntityId::now();
    let named =
        super::super::support::encode_value(&Value::Map(vec![("name".into(), "Owen".into())]))?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred(1), 1, &named)?;
    let branch: ConsolidationBranchPlan<EntityId> = ConsolidationBranchPlan {
        world_ref: Some(world),
        facet_ref: Some(facet),
        thing: None,
        parts: vec![ConversationPart {
            conversation_ref: conversation,
            turns: vec![turn_p, turn_q],
            watermark_last_learned_at: 0,
            line: 0,
        }],
        project: Some(crate::claim::default_project_id()),
    };
    let payload = super::super::partition::encode_branch_payload(&branch, None);
    let Value::Map(entries) = &payload else {
        panic!("branch payload map");
    };
    assert!(
        !entries
            .iter()
            .any(|(key, _)| key.as_str() == Some("project")),
        "old-form payload carries no project key"
    );
    store.enqueue_consolidation(crate::dreamer_runner::EnqueueDreamerConsolidationAttempt {
        scope: DreamerConsolidationScope::Micro,
        input: payload,
        parent_attempt: None,
        dedupe_key: Some("old-form-mixed".into()),
        run_id: Some("run-1".into()),
        now: 20,
    })?;
    let node = crate::identity::load_or_mint_client_id(&vault)?;
    let admitted = admit_next(&vault, &store, node, 21)?;
    let reply = || {
        text_response(
            serde_json::json!({"candidates": [{
                "subject": "P1", "predicate": "profile.name", "value": "Owen",
                "confidence": 0.8, "evidence_refs": [{"source": "T1", "quote": "Owen"}]
            }]})
            .to_string(),
        )
    };
    let backend = RecordingBackend::new(vec![Ok(reply()), Ok(reply())]);
    let mut sink = CapturingSink::default();
    assert!(matches!(
        execute_one(&vault, &admitted, &backend, &mut sink)?,
        DreamerAttemptExecution::Completed { .. }
    ));
    assert_eq!(
        backend.inner.calls.load(Ordering::SeqCst),
        2,
        "one call per project"
    );
    let texts = request_texts(&backend);
    assert_eq!(texts.len(), 2);
    assert!(
        texts
            .iter()
            .any(|text| text.contains("alpha-p-marker") && !text.contains("beta-q-marker"))
    );
    assert!(
        texts
            .iter()
            .any(|text| text.contains("beta-q-marker") && !text.contains("alpha-p-marker"))
    );
    Ok(())
}

#[test]
fn a_default_project_key_keeps_main_s_hash() -> Result<()> {
    let conversation = EntityId::now();
    let world = Some(EntityId::now());
    let facet = Some(EntityId::now());
    let default = crate::claim::default_project_id();
    let project_p = EntityId::now();
    assert_ne!(project_p, default);
    let key_default = ConsolidationPartitionKey {
        conversation_ref: conversation,
        world_ref: world,
        facet_ref: facet,
        project: Some(default),
    };
    let key_p = ConsolidationPartitionKey {
        conversation_ref: conversation,
        world_ref: world,
        facet_ref: facet,
        project: Some(project_p),
    };
    let key_none = ConsolidationPartitionKey {
        conversation_ref: conversation,
        world_ref: world,
        facet_ref: facet,
        project: None,
    };
    assert_eq!(
        key_default.partition_hash(),
        baseline_partition_hash(conversation, world, facet),
        "default keeps main's bytes"
    );
    assert_ne!(key_p.partition_hash(), key_default.partition_hash());
    assert_ne!(key_none.partition_hash(), key_default.partition_hash());
    assert_ne!(key_p.partition_hash(), key_none.partition_hash());
    for project in [Some(project_p), None] {
        let branch: ConsolidationBranchPlan<EntityId> = ConsolidationBranchPlan {
            world_ref: world,
            facet_ref: facet,
            thing: None,
            parts: vec![ConversationPart {
                conversation_ref: conversation,
                turns: vec![EntityId::now()],
                watermark_last_learned_at: 0,
                line: 0,
            }],
            project,
        };
        let encoded = super::super::partition::encode_branch_payload(&branch, None);
        let Value::Map(entries) = &encoded else {
            panic!("branch payload map");
        };
        assert!(
            entries
                .iter()
                .any(|(key, _)| key.as_str() == Some("project")),
            "non-default encodes its project"
        );
        let decoded = decode_partition_payload(&encoded)?;
        assert_eq!(decoded.project, project);
        assert_eq!(decoded.world_ref, world);
        assert_eq!(decoded.facet_ref, facet);
    }
    let default_branch: ConsolidationBranchPlan<EntityId> = ConsolidationBranchPlan {
        world_ref: world,
        facet_ref: facet,
        thing: None,
        parts: vec![ConversationPart {
            conversation_ref: conversation,
            turns: vec![EntityId::now()],
            watermark_last_learned_at: 0,
            line: 0,
        }],
        project: Some(default),
    };
    let encoded = super::super::partition::encode_branch_payload(&default_branch, None);
    let Value::Map(entries) = &encoded else {
        panic!("branch payload map");
    };
    assert!(
        !entries
            .iter()
            .any(|(key, _)| key.as_str() == Some("project")),
        "default omits the project key"
    );
    let decoded = decode_partition_payload(&encoded)?;
    assert_eq!(decoded.project, Some(default));
    Ok(())
}

#[test]
fn a_retry_does_not_widen_across_projects() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let node = crate::identity::load_or_mint_client_id(&vault)?;
    let conversation = seed_session(&vault, 0x5b, 1);
    let (world, facet) = (EntityId::now(), EntityId::now());
    let (project_p, project_q) = (EntityId::now(), EntityId::now());
    let turn_p = seed_axis_turn(
        &vault,
        &conversation,
        "call me Owen marker-p",
        10,
        project_p,
        world,
        facet,
    )?;
    let turn_q = seed_axis_turn(
        &vault,
        &conversation,
        "call me Owen marker-q",
        11,
        project_q,
        world,
        facet,
    )?;
    let scope = DreamerConsolidationScope::Micro;
    let watermark = read_watermark(&vault, scope)?;
    let mut dirty = scan_dirty_turns(&vault, scope, &watermark, 10)?;
    assert!(dirty.iter().any(|turn| turn.turn_id == turn_q));
    dirty.retain(|turn| turn.turn_id == turn_p);
    enqueue_partition_attempts(&vault, scope, &dirty, &watermark, "run-1", 20)?;
    let admitted = admit_next(&vault, &store, node, 21)?;
    store.defer_selection(
        &admitted,
        crate::dreamer_runner::SettleDreamerBudget {
            budget_id: "wake".into(),
            child_attempt: admitted.status.attempt.id,
            actual_units: 0,
            now: 21,
        },
        30,
        &[],
    )?;
    let retry = AttemptQueue::new(&vault)
        .list()?
        .into_iter()
        .find(|row| row.retry_of == Some(admitted.status.attempt.id))
        .expect("scheduled selection retry");
    let pinned = PreparedWake::capture(&vault, scope)?;
    let Some(AttemptPreparation::Ready(plan)) = pinned.preparation(retry.id) else {
        panic!("retry prepares");
    };
    assert_eq!(
        plan.turn_ids(),
        &[turn_p],
        "retry excludes the other project's peer"
    );
    Ok(())
}
