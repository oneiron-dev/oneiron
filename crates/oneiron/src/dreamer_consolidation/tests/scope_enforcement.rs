use super::super::resources::BranchResources;
use super::*;
use crate::llm::{Scope, ScopeResource};

#[test]
fn branch_resources_enforce_exact_reads_writes_and_revisions() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let (attempt, turns, conversation) = admitted_attempt_fixture(
        &vault,
        &store,
        0x42,
        &[("user", "a source in this partition")],
    )?;
    let (partition, _, _) = decode_partition_payload(&attempt.status.payload.input)?;
    let branch = BranchResources::open(
        &vault,
        vault.dreamer_authority()?,
        partition,
        &turns,
        attempt.status.attempt.id,
        None,
    )?;
    let scope = branch.scope().clone();
    assert_eq!(
        branch.turn(&scope, &turns[0])?.text.as_deref(),
        Some("a source in this partition")
    );
    let source = vault.get(&turns[0])?.expect("source body");
    assert!(scope.readable.contains(&ScopeResource::DocumentVersion {
        document: turns[0],
        version: format!(
            "blake3:{}",
            bytes_to_hex_lower(&swarm_evidence_content_hash(&source))
        ),
    }));

    let unlisted = seed_turn(&vault, &conversation, "user", "unlisted", 12);
    assert!(matches!(
        branch.turn(&scope, &unlisted),
        Err(Error::InvalidClaimBody(_))
    ));
    let mut no_bucket = scope.clone();
    no_bucket
        .readable
        .retain(|key| !matches!(key, ScopeResource::Bucket { .. }));
    assert!(matches!(
        branch.turn(&no_bucket, &turns[0]),
        Err(Error::InvalidClaimBody(_))
    ));
    assert!(matches!(
        branch.turn(&Scope::default(), &turns[0]),
        Err(Error::InvalidClaimBody(_))
    ));

    let mut output = candidate(conversation, "profile.name", "observed", None);
    output.evidence_turn_refs = turns.clone();
    derive_id(&mut output, attempt.status.attempt.id)?;
    let mut sink = CapturingSink::default();
    branch.accept(&scope, &mut sink, vec![output.clone()])?;
    assert_eq!(sink.accepted, vec![output.clone()]);
    let mut wrong_projection = scope.clone();
    wrong_projection.writable = BTreeSet::from([ScopeResource::Projection {
        key: "unlisted-projection".to_owned(),
    }]);
    assert!(matches!(
        branch.accept(&wrong_projection, &mut sink, vec![output.clone()]),
        Err(Error::InvalidClaimBody(_))
    ));
    assert_eq!(sink.accepted, vec![output]);

    // The stored gap projection is also scoped. A branch must not decay the
    // global maintenance queue as a side effect of its own output.
    let gap = ReflectionGap {
        kind: ReflectionGapKind::ContradictionLeftStanding,
        subject: conversation,
        evidence_turn_refs: turns.clone(),
        first_seen: 0,
        last_seen: 0,
        escalations: 0,
        decayed: false,
    };
    assert_eq!(upsert_gap_queue(&vault, vec![gap.clone()], 0)?.created, 1);
    assert_eq!(branch.upsert_gaps(&scope, vec![gap.clone()], 0)?.created, 1);
    assert!(matches!(
        branch.upsert_gaps(&wrong_projection, vec![gap.clone()], 1),
        Err(Error::InvalidClaimBody(_))
    ));
    let later = DREAMER_GAP_DECAY_MS + 1;
    assert_eq!(branch.upsert_gaps(&scope, Vec::new(), later)?.decayed, 1);
    assert_eq!(upsert_gap_queue(&vault, vec![gap], later)?.refreshed, 1);

    // A body edit retaining the entity id and learned_at is a DIFFERENT version.
    vault.put_entity(
        &turns[0],
        ENTITY_TYPE_TURN,
        occurred(10),
        10,
        &turn_body("user", "changed source", None),
    )?;
    assert!(matches!(
        branch.turn(&scope, &turns[0]),
        Err(Error::InvalidClaimBody(_))
    ));
    Ok(())
}

struct ScopeBackend {
    seen: Mutex<Vec<Scope>>,
    inner: ScriptedBackend,
}
impl LlmBackend for ScopeBackend {
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        self.seen
            .lock()
            .expect("scope capture")
            .push(request.envelope.scope.clone());
        self.inner.generate(request, lease)
    }
    fn stream<'a>(&'a self, request: LlmRequest, lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        self.inner.stream(request, lease)
    }
}

#[test]
fn production_executor_carries_scope_and_refuses_unlisted_evidence_and_output() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let (attempt, turns, conversation) =
        admitted_attempt_fixture(&vault, &store, 0x43, &[("user", "a scoped extraction")])?;
    let subject = EntityId::now();
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred(1), 1, b"person")?;
    let outside = seed_turn(&vault, &conversation, "user", "not in the attempt", 12);
    let backend = ScopeBackend {
        seen: Mutex::new(Vec::new()),
        inner: ScriptedBackend::new(vec![
            Ok(extraction_response(&subject, &turns[0])),
            Ok(extraction_response(&subject, &outside)),
        ]),
    };
    let guard = crate::BudgetGuard::with_reserve_units(
        "wake",
        10_000,
        100,
        BudgetExhaustionPolicy::Suspend,
    );
    let deadline = WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 0));
    let mut sink = CapturingSink::default();
    let mut ctx = WakeAttemptContext {
        vault: &vault,
        deadline: &deadline,
        budget_id: "wake",
        now_ms: 21_000,
    };
    let mut executor = ConsolidationExecutor {
        backend: &backend,
        guard: &guard,
        strategy: DreamerClaimAuthoringStrategy::SinglePass,
        actor: vault.dreamer_authority()?,
        model: crate::ModelId::new("test/model@r1").unwrap(),
        sink: &mut sink,
        scope: None,
    };
    assert!(matches!(
        block_on_ready(executor.execute(&attempt, &mut ctx))?,
        DreamerAttemptExecution::Completed { .. }
    ));
    // A different revision forces a new extraction, not the prior memoized one.
    executor.model = crate::ModelId::new("test/model@r2").unwrap();
    assert!(matches!(
        block_on_ready(executor.execute(&attempt, &mut ctx)),
        Err(Error::InvalidClaimBody(_))
    ));
    drop(executor);
    assert_eq!(sink.accepted.len(), 1);
    assert_eq!(sink.accepted[0].evidence_turn_refs, turns);
    let scope = backend.seen.lock().unwrap()[0].clone();
    assert!(
        scope
            .readable
            .iter()
            .any(|r| matches!(r, ScopeResource::Bucket { .. }))
    );
    assert!(scope.readable.iter().any(|r| matches!(r,
        ScopeResource::DocumentVersion { document, .. } if *document == turns[0])));
    assert_eq!(scope.writable.len(), 2);

    // Missing output permission refuses before a model call or sink write.
    let mut no_signals = scope.clone();
    let (partition, _, _) = decode_partition_payload(&attempt.status.payload.input)?;
    no_signals
        .readable
        .remove(&super::super::resources::signals_projection(
            &partition, &turns,
        ));
    let mut no_output = scope;
    no_output.writable.clear();
    let backend = ScriptedBackend::new(Vec::new());
    let mut executor = ConsolidationExecutor {
        backend: &backend,
        guard: &guard,
        strategy: DreamerClaimAuthoringStrategy::SinglePass,
        actor: vault.dreamer_authority()?,
        model: crate::ModelId::new("test/model@r1").unwrap(),
        sink: &mut sink,
        scope: Some(no_output),
    };
    assert!(matches!(
        block_on_ready(executor.execute(&attempt, &mut ctx)),
        Err(Error::InvalidClaimBody(_))
    ));
    executor.scope = Some(no_signals);
    // The failed no-output call already pinned its attenuation. The same
    // attempt cannot regain those output rights under another caller scope.
    assert!(matches!(
        block_on_ready(executor.execute(&attempt, &mut ctx)),
        Err(Error::InvalidConfig(_))
    ));
    drop(executor);
    assert_eq!(sink.accepted.len(), 1);
    assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

fn derive_id(
    candidate: &mut PromotionCandidate,
    attempt: crate::attempt_queue::AttemptId,
) -> Result<()> {
    let facts = super::super::conflict::candidate_facts(&candidate.candidate)?;
    candidate.claim_id = super::super::conflict::deterministic_claim_id(
        attempt,
        facts.subject,
        &facts.predicate,
        &facts.value,
        facts.world,
        facts.facet,
        facts.rel,
    );
    Ok(())
}

#[test]
fn scoped_signals_preserve_ranking_and_filter_foreign_and_private_refs() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let (attempt, turns, conversation) =
        admitted_attempt_fixture(&vault, &store, 0x44, &[("user", "an admitted source")])?;
    let (partition, _, _) = decode_partition_payload(&attempt.status.payload.input)?;
    let mut candidates = Vec::new();
    for _ in 0..2 {
        let subject = EntityId::now();
        vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred(1), 1, b"subject")?;
        let mut output = candidate(subject, "profile.name", "name", None);
        output.evidence_turn_refs = turns.clone();
        derive_id(&mut output, attempt.status.attempt.id)?;
        candidates.push(output);
    }
    candidates.sort_by_key(|candidate| candidate.claim_id);
    let winner = &candidates[1]; // fan-in must beat the otherwise first id
    let subject = super::super::conflict::candidate_facts(&winner.candidate)?.subject;
    vault.with_write_txn(|txn| {
        vault
            .batch_in()
            .edge_with_created_at(&turns[0], EdgeKind::Mentions, &subject, 1.0, 2_000)
            .apply(txn)
    })?;
    let other_conversation = seed_session(&vault, 0x45, 1);
    let outside = seed_turn(
        &vault,
        &other_conversation,
        "user",
        "foreign conversation",
        10,
    );
    let other_facet = EntityId::now();
    let foreign = seed_turn_with_facet(
        &vault,
        &conversation,
        "user",
        "foreign facet",
        10,
        Some(&other_facet),
    );
    vault.put_edge(&outside, EdgeKind::Mentions, &subject, 1.0)?;
    vault.put_edge(&foreign, EdgeKind::Mentions, &subject, 1.0)?;
    let author = EntityId::now();
    vault.put_entity(
        &author,
        ENTITY_TYPE_PERSON,
        occurred(1),
        1,
        b"private author",
    )?;
    let diary = EntityId::now();
    let diary_body = crate::note::encode_note_body(&crate::note::NoteBody {
        kind: crate::note::NoteKind::Diary,
        author_ref: author,
        markdown: "private graph evidence".to_owned(),
        source_revision_ref: [1; 16],
    })?;
    vault.with_write_txn(|txn| {
        vault
            .batch_in()
            .put_authored_note(&diary, &author, occurred(1), 1, &diary_body)
            .edge(&diary, EdgeKind::AuthoredBy, &author, 1.0)
            .edge(&diary, EdgeKind::About, &subject, 1.0)
            .apply(txn)
    })?;
    let initial = BranchResources::open(
        &vault,
        vault.dreamer_authority()?,
        partition,
        &turns,
        attempt.status.attempt.id,
        None,
    )?;
    let mut scope = initial.scope().clone();
    // Even an explicit document grant cannot override actor-private authority.
    scope
        .readable
        .insert(super::super::resources::document_version(
            diary,
            &diary_body,
        ));
    let branch = BranchResources::open(
        &vault,
        vault.dreamer_authority()?,
        partition,
        &turns,
        attempt.status.attempt.id,
        Some(&scope),
    )?;
    let (fan_in, new_refs, vector) = branch.candidate_signals(branch.scope(), winner)?;
    assert_eq!((fan_in, new_refs), (1, 1));
    assert!(vector.is_none());
    let config = selection::SelectionConfig {
        soak_ms: 0,
        evidence_minimum: 1,
        ..Default::default()
    };
    vault.set_consolidation_selection(&config)?;
    let assembled = super::super::assembly::assemble(&vault, &branch, candidates.clone(), 21_000)?;
    assert_eq!(assembled.candidates[0].claim_id, winner.claim_id);
    assert!(assembled.conflicts.is_empty());
    // Resource loss is a refusal, not a successful neutral-scoring run.
    scope
        .readable
        .remove(&super::super::resources::signals_projection(
            &partition, &turns,
        ));
    assert!(matches!(
        branch.candidate_signals(&scope, winner),
        Err(Error::InvalidClaimBody(_))
    ));
    let mut arbitrary = winner.clone();
    arbitrary.claim_id = diary;
    assert!(matches!(
        branch.candidate_signals(branch.scope(), &arbitrary),
        Err(Error::InvalidClaimBody(_))
    ));
    // Scope does not short-circuit either of the existing eligibility gates.
    vault.set_consolidation_selection(&selection::SelectionConfig {
        evidence_minimum: 2,
        ..config.clone()
    })?;
    let held = super::super::assembly::assemble(&vault, &branch, candidates.clone(), 21_000)?;
    assert!(held.held && held.candidates.is_empty());
    vault.set_consolidation_selection(&selection::SelectionConfig {
        soak_ms: 50_000,
        ..config
    })?;
    let held = super::super::assembly::assemble(&vault, &branch, candidates, 21_000)?;
    assert!(held.held && held.candidates.is_empty());
    Ok(())
}

#[test]
fn production_scoped_embeddings_nominate_only_the_judge() -> Result<()> {
    for resolution in ["accumulate", "merge", "missing", "unlisted"] {
        let (_dir, vault) =
            crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
        grant_fixture_reads(&vault)?;
        let store = DreamerRunnerStore::new(&vault);
        let (attempt, turns, _) =
            admitted_attempt_fixture(&vault, &store, 0x46, &[("user", "two related facts")])?;
        let subject = EntityId::now();
        vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred(1), 1, b"subject")?;
        let mut items = Vec::new();
        let mut selected_id = EntityId::now();
        for predicate in ["profile.name", "profile.alias"] {
            let mut output = candidate(subject, predicate, "same text", None);
            derive_id(&mut output, attempt.status.attempt.id)?;
            if predicate == "profile.alias" {
                selected_id = output.claim_id;
            }
            vault.put_vector(&output.claim_id, &vec![1.0; vault.config.dimensions])?;
            items.push(
                serde_json::json!({"subject": subject.to_hex(), "predicate": predicate,
            "value": "same text", "evidence_turn_refs": [turns[0].to_hex()]}),
            );
        }
        let backend = ScopeBackend {
        seen: Mutex::new(Vec::new()),
        inner: ScriptedBackend::new(vec![
            Ok(text_response(
                serde_json::json!({"candidates": items}).to_string(),
            )),
            Ok(text_response(match resolution {
                "accumulate" => serde_json::json!({"resolution":"accumulate"}),
                "merge" => serde_json::json!({"resolution":"merge", "candidate_ref":selected_id.to_hex(), "value":"selected alias"}),
                "missing" => serde_json::json!({"resolution":"merge", "value":"unbound"}),
                _ => serde_json::json!({"resolution":"merge", "candidate_ref":EntityId::now().to_hex(), "value":"unlisted"}),
            }.to_string())),
        ]),
    };
        let guard = crate::BudgetGuard::with_reserve_units(
            "wake",
            10_000,
            100,
            BudgetExhaustionPolicy::Suspend,
        );
        let deadline = WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 0));
        let mut sink = CapturingSink::default();
        let mut executor = ConsolidationExecutor {
            backend: &backend,
            guard: &guard,
            strategy: DreamerClaimAuthoringStrategy::SinglePass,
            actor: vault.dreamer_authority()?,
            model: crate::ModelId::new("test/model@r1").unwrap(),
            sink: &mut sink,
            scope: None,
        };
        let mut ctx = WakeAttemptContext {
            vault: &vault,
            deadline: &deadline,
            budget_id: "wake",
            now_ms: 21_000,
        };
        let result = block_on_ready(executor.execute(&attempt, &mut ctx));
        if matches!(resolution, "missing" | "unlisted") {
            assert!(result.is_err());
        } else {
            assert!(matches!(result?, DreamerAttemptExecution::Completed { .. }));
        }
        drop(executor);
        // Different predicate keys only reach this judge through stored cosine input.
        assert_eq!(backend.inner.calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            sink.accepted.len(),
            match resolution {
                "accumulate" => 2,
                "merge" => 1,
                _ => 0,
            }
        );
        if resolution == "merge" {
            assert_eq!(
                super::super::conflict::candidate_facts(&sink.accepted[0].candidate)?.predicate,
                "profile.alias"
            );
        }
        let scopes = backend.seen.lock().unwrap();
        assert_eq!(scopes[0], scopes[1]);
    }
    Ok(())
}

#[test]
fn queued_four_axis_scope_is_inherited_and_cannot_be_erased() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let (mut attempt, turns, conversation) = admitted_attempt_fixture(
        &vault,
        &store,
        0x47,
        &[("user", "one project relationship slice")],
    )?;
    let world = EntityId::now();
    let facet = EntityId::now();
    let relationship = EntityId::now();
    let project = EntityId::now();
    let mut source = super::super::support::decode_value(&turn_body(
        "user",
        "one project relationship slice",
        Some(&facet),
    ))?;
    let Value::Map(source_entries) = &mut source else {
        panic!("turn map");
    };
    source_entries.push((
        Value::from(TURN_BODY_WORLD_REF_KEY),
        Value::Binary(world.as_bytes().to_vec()),
    ));
    vault.put_entity(
        &turns[0],
        ENTITY_TYPE_TURN,
        occurred(10),
        10,
        &super::super::support::encode_value(&source)?,
    )?;
    let partition = ConsolidationPartitionKey {
        conversation_ref: conversation,
        world_ref: Some(world),
        facet_ref: Some(facet),
    };
    let initial = BranchResources::open(
        &vault,
        vault.dreamer_authority()?,
        partition,
        &turns,
        attempt.status.attempt.id,
        None,
    )?;
    let mut scope = initial.scope().clone();
    scope.relationship = Some(relationship);
    scope.project = Some(project);
    // Gap storage is sliced too; project does not change partition/claim ids.
    scope
        .writable
        .remove(&super::super::gap::branch_gap_projection(
            &partition,
            initial.scope(),
        ));
    scope
        .writable
        .insert(super::super::gap::branch_gap_projection(&partition, &scope));
    let plan = ConsolidationPartitionPlan {
        key: partition,
        turns: vec![WorkingSetTurn {
            turn_id: turns[0],
            role: DreamerTurnRole::User,
            learned_at: 10,
            conversation: Some(conversation),
        }],
        watermark_last_learned_at: 0,
    };
    assert_eq!(
        plan.output_resource(),
        super::super::resources::output_projection(&partition, &turns)
    );
    assert_eq!(
        plan.signals_resource(),
        super::super::resources::signals_projection(&partition, &turns)
    );
    store.enqueue_consolidation(crate::dreamer_runner::EnqueueDreamerConsolidationAttempt {
        scope: DreamerConsolidationScope::Micro,
        input: plan.scoped_input(&scope)?,
        parent_attempt: None,
        dedupe_key: Some("four-axis-branch".into()),
        run_id: Some("four-axis-branch".into()),
        now: 22,
    })?;
    let before = AttemptQueue::new(&vault).list()?.len();
    let mut other_scope = scope.clone();
    other_scope.project = Some(EntityId::now());
    assert!(matches!(
        store.enqueue_consolidation(crate::dreamer_runner::EnqueueDreamerConsolidationAttempt {
            scope: DreamerConsolidationScope::Micro,
            input: plan.scoped_input(&other_scope)?,
            parent_attempt: None,
            dedupe_key: Some("four-axis-branch".into()),
            run_id: Some("four-axis-branch".into()),
            now: 22,
        }),
        Err(Error::Artifact(
            crate::error::ArtifactError::InvalidAttemptQueueRecord(_)
        ))
    ));
    assert_eq!(AttemptQueue::new(&vault).list()?.len(), before);
    let DreamerConsolidationAdmissionOutcome::Admission(DreamerAdmissionOutcome::Admitted(queued)) =
        store.admit_next_consolidation(AdmitDreamerConsolidationAttempt {
            scope: DreamerConsolidationScope::Micro,
            local_node_id: crate::identity::load_or_mint_client_id(&vault)?,
            claim_authoring_tier: DreamerClaimAuthoringBatchTier::batch(),
            claim_authoring: DreamerClaimAuthoringAdmission::single_pass(),
            admission: AdmitDreamerAttempt {
                lease_owner: "consolidation-test".into(),
                now: 23,
                budget_id: "wake".into(),
                budget_total_units: 10_000,
                reserve_units: 100,
                started_milestone: None,
            },
        })?
    else {
        panic!("expected scoped queued attempt");
    };
    attempt = *queued;
    assert_eq!(
        super::super::branch_scope::decode_branch_scope(&attempt.status.payload.input)?,
        Some(scope.clone())
    );
    assert_eq!(
        super::super::branch_scope::resolve_scope(
            &vault,
            Some(attempt.status.attempt.id),
            None,
            None
        )?,
        Some(scope.clone())
    );
    assert!(
        super::super::branch_scope::resolve_scope(
            &vault,
            Some(attempt.status.attempt.id),
            Some(Scope::default()),
            None
        )
        .is_err()
    );
    let child =
        store.enqueue_consolidation(crate::dreamer_runner::EnqueueDreamerConsolidationAttempt {
            scope: DreamerConsolidationScope::Micro,
            input: super::super::partition::encode_partition_payload(&plan),
            parent_attempt: Some(attempt.status.attempt.id),
            dedupe_key: None,
            run_id: Some("inherited-branch".into()),
            now: 24,
        })?;
    let child_id = match child {
        EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status) => status.attempt.id,
    };
    assert_eq!(
        super::super::branch_scope::resolve_scope(&vault, Some(child_id), None, None)?,
        Some(scope.clone())
    );
    let (decoded_key, _, _) = decode_partition_payload(&attempt.status.payload.input)?;
    assert_eq!(decoded_key, partition);
    let branch = BranchResources::open(
        &vault,
        vault.dreamer_authority()?,
        partition,
        &turns,
        attempt.status.attempt.id,
        Some(&scope),
    )?;
    assert!(
        branch
            .transcript(branch.scope(), &turns)?
            .contains("one project relationship slice")
    );
    let mut no_pin = scope.clone();
    no_pin.readable.retain(
        |r| !matches!(r, ScopeResource::DocumentVersion { document, .. } if *document == turns[0]),
    );
    assert!(
        BranchResources::open(
            &vault,
            vault.dreamer_authority()?,
            partition,
            &turns,
            attempt.status.attempt.id,
            Some(&no_pin)
        )
        .is_err()
    );
    let subject = EntityId::now();
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred(1), 1, b"subject")?;
    let mut absent_rel = candidate(subject, "profile.name", "name", Some(facet));
    absent_rel.candidate = absent_rel.candidate.with_world(world);
    absent_rel.evidence_turn_refs = turns.clone();
    derive_id(&mut absent_rel, attempt.status.attempt.id)?;
    assert!(matches!(
        branch.validate_candidates(&scope, &[absent_rel]),
        Err(Error::InvalidClaimBody(_))
    ));
    let backend = ScopeBackend {
        seen: Mutex::new(Vec::new()),
        inner: ScriptedBackend::new(vec![Ok(extraction_response(&subject, &turns[0]))]),
    };
    let guard = crate::BudgetGuard::with_reserve_units(
        "wake",
        10_000,
        100,
        BudgetExhaustionPolicy::Suspend,
    );
    let deadline = WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 0));
    let mut sink = CapturingSink::default();
    let mut executor = ConsolidationExecutor {
        backend: &backend,
        guard: &guard,
        strategy: DreamerClaimAuthoringStrategy::SinglePass,
        actor: vault.dreamer_authority()?,
        model: crate::ModelId::new("test/model@r1").unwrap(),
        sink: &mut sink,
        scope: None,
    };
    let mut ctx = WakeAttemptContext {
        vault: &vault,
        deadline: &deadline,
        budget_id: "wake",
        now_ms: 21_000,
    };
    assert!(matches!(
        block_on_ready(executor.execute(&attempt, &mut ctx))?,
        DreamerAttemptExecution::Completed { .. }
    ));
    for axis in 0..4 {
        let mut widened = scope.clone();
        match axis {
            0 => widened.world = None,
            1 => widened.facet = None,
            2 => widened.relationship = None,
            _ => widened.project = None,
        }
        executor.scope = Some(widened);
        assert!(matches!(
            block_on_ready(executor.execute(&attempt, &mut ctx)),
            Err(Error::InvalidConfig(_))
        ));
    }
    drop(executor);
    assert_eq!(backend.inner.calls.load(Ordering::SeqCst), 1);
    assert_eq!(backend.seen.lock().unwrap()[0], scope);
    let facts = super::super::conflict::candidate_facts(&sink.accepted[0].candidate)?;
    assert_eq!(
        (facts.world, facts.facet, facts.rel),
        (Some(world), Some(facet), Some(relationship))
    );
    // The durable codec refuses ambiguity rather than silently dropping scope.
    let mut duplicate = attempt.status.payload.input.clone();
    let Value::Map(entries) = &mut duplicate else {
        panic!("partition map");
    };
    entries.push(entries.last().unwrap().clone());
    assert!(decode_partition_payload(&duplicate).is_err());
    Ok(())
}

#[test]
fn graph_signals_enforce_relationship_and_exact_project_slice() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let (attempt, turns, _) = admitted_attempt_fixture(&vault, &store, 0x48, &[("user", "slice")])?;
    let (partition, _, _) = decode_partition_payload(&attempt.status.payload.input)?;
    let relationship = EntityId::now();
    let subject = EntityId::now();
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred(1), 1, b"subject")?;
    let author = EntityId::now();
    vault.put_entity(&author, ENTITY_TYPE_PERSON, occurred(1), 1, b"author")?;
    let envelope = WriteEnvelope::new(
        WriteActor::new(author, EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(Value::from("signals-test"))?,
        ClaimApprovalStatus::Approved,
    );
    let initial = BranchResources::open(
        &vault,
        vault.dreamer_authority()?,
        partition,
        &turns,
        attempt.status.attempt.id,
        None,
    )?;
    let mut scope = initial.scope().clone();
    scope.relationship = Some(relationship);
    scope.project = Some(EntityId::now());
    let mut allowed = None;
    for (rel, pinned) in [
        (Some(relationship), true),
        (None, true),
        (Some(EntityId::now()), true),
        (Some(relationship), false),
    ] {
        let id = EntityId::now();
        let mut reference = ClaimCandidate::new(
            "profile.note",
            ClaimSubject::Entity(subject),
            Value::from("reference"),
            0.9,
        );
        if let Some(rel) = rel {
            reference = reference.with_relationship(rel);
        }
        vault
            .batch()
            .claim_candidate(&id, reference, &envelope, occurred(1), 1)
            .edge(&id, EdgeKind::Mentions, &subject, 1.0)
            .commit()?;
        if pinned {
            scope
                .readable
                .insert(super::super::resources::document_version(
                    id,
                    &vault.get(&id)?.unwrap(),
                ));
            if rel == Some(relationship) {
                allowed = Some(id);
            }
        }
    }
    let branch = BranchResources::open(
        &vault,
        vault.dreamer_authority()?,
        partition,
        &turns,
        attempt.status.attempt.id,
        Some(&scope),
    )?;
    let mut output = candidate(subject, "profile.name", "name", None);
    output.candidate = output.candidate.with_relationship(relationship);
    output.evidence_turn_refs = turns;
    derive_id(&mut output, attempt.status.attempt.id)?;
    let (fan_in, _, _) = branch.candidate_signals(&scope, &output)?;
    let expected = vault
        .edges_in(&subject)?
        .iter()
        .filter(|edge| Some(edge.target) == allowed)
        .count();
    assert!(expected > 0);
    assert_eq!(fan_in, expected as u64);
    Ok(())
}

#[test]
fn production_epoch_timestamps_hold_then_release_and_rank_source_diversity() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let (attempt, turns, _) = admitted_attempt_fixture(
        &vault,
        &store,
        0x69,
        &[("user", "first source"), ("assistant", "second source")],
    )?;
    let epoch = 1_800_000_000_u64;
    for (offset, turn) in turns.iter().enumerate() {
        let bytes = vault.get(turn)?.unwrap();
        vault.put_entity(
            turn,
            ENTITY_TYPE_TURN,
            occurred(epoch + offset as u64),
            epoch + offset as u64,
            &bytes,
        )?;
    }
    let (partition, _, _) = decode_partition_payload(&attempt.status.payload.input)?;
    let branch = BranchResources::open(
        &vault,
        vault.dreamer_authority()?,
        partition,
        &turns,
        attempt.status.attempt.id,
        None,
    )?;
    let mut one = candidate(
        partition.conversation_ref,
        "profile.name",
        "single source",
        None,
    );
    one.evidence_turn_refs = vec![turns[0]];
    derive_id(&mut one, attempt.status.attempt.id)?;
    let mut diverse = candidate(
        partition.conversation_ref,
        "profile.alias",
        "two sources",
        None,
    );
    diverse.evidence_turn_refs = turns.clone();
    derive_id(&mut diverse, attempt.status.attempt.id)?;
    let config = selection::SelectionConfig {
        soak_ms: 50_000,
        evidence_minimum: 1,
        ..Default::default()
    };
    vault.set_consolidation_selection(&config)?;
    let candidates = vec![one.clone(), diverse.clone()];
    let held = super::super::assembly::assemble(
        &vault,
        &branch,
        candidates.clone(),
        epoch * 1_000 + 49_999,
    )?;
    assert!(held.held && held.candidates.is_empty());
    let released = super::super::assembly::assemble(
        &vault,
        &branch,
        candidates.clone(),
        epoch * 1_000 + 50_000,
    )?;
    assert!(!released.held);
    assert_eq!(released.candidates.len(), 2);
    let mut diversity = config;
    diversity.type_priors.clear();
    diversity.weights = selection::StrengthWeights {
        type_prior: 0.8,
        frequency: 0.0,
        recency: 0.0,
        diversity: 0.2,
    };
    vault.set_consolidation_selection(&diversity)?;
    let ranked =
        super::super::assembly::assemble(&vault, &branch, candidates, epoch * 1_000 + 50_000)?;
    assert_eq!(ranked.candidates[0].claim_id, diverse.claim_id);
    let mut recent = one.clone();
    recent.candidate = ClaimCandidate::new(
        "profile.alias",
        ClaimSubject::Entity(partition.conversation_ref),
        Value::from("newer"),
        0.8,
    );
    recent.evidence_turn_refs = vec![turns[1]];
    derive_id(&mut recent, attempt.status.attempt.id)?;
    diversity.soak_ms = 0;
    diversity.weights = selection::StrengthWeights {
        type_prior: 0.8,
        frequency: 0.0,
        recency: 0.2,
        diversity: 0.0,
    };
    vault.set_consolidation_selection(&diversity)?;
    let ranked = super::super::assembly::assemble(
        &vault,
        &branch,
        vec![one, recent.clone()],
        epoch * 1_000 + 1_000,
    )?;
    assert_eq!(ranked.candidates[0].claim_id, recent.claim_id);
    // Extraction timestamps are already milliseconds when no evidence supplies
    // a stored seconds-scale timestamp (possible when the configured minimum is zero).
    recent.evidence_turn_refs.clear();
    recent.learned_at = epoch * 1_000;
    diversity.evidence_minimum = 0;
    diversity.soak_ms = 50_000;
    vault.set_consolidation_selection(&diversity)?;
    assert!(
        super::super::assembly::assemble(
            &vault,
            &branch,
            vec![recent.clone()],
            epoch * 1_000 + 49_999
        )?
        .held
    );
    assert!(
        !super::super::assembly::assemble(&vault, &branch, vec![recent], epoch * 1_000 + 50_000)?
            .held
    );
    Ok(())
}

#[test]
fn scheduled_selection_retry_reextracts_new_admitted_evidence() -> Result<()> {
    for caller_bounded in [false, true] {
        let (_dir, vault) = open_vault();
        let store = DreamerRunnerStore::new(&vault);
        let (attempt, turns, conversation) =
            admitted_attempt_fixture(&vault, &store, 0x6A, &[("user", "initial evidence")])?;
        vault.set_consolidation_selection(&selection::SelectionConfig {
            evidence_minimum: 2,
            soak_ms: 0,
            ..Default::default()
        })?;
        let caller_scope = if caller_bounded {
            let (partition, _, _) = decode_partition_payload(&attempt.status.payload.input)?;
            Some(
                BranchResources::open(
                    &vault,
                    vault.dreamer_authority()?,
                    partition,
                    &turns,
                    attempt.status.attempt.id,
                    None,
                )?
                .scope()
                .clone(),
            )
        } else {
            None
        };
        let subject = conversation;
        let response = |ids: &[EntityId]| {
            text_response(
                serde_json::json!({"candidates":[{
                    "subject":subject.to_hex(),"predicate":"profile.name","value":"supported",
                    "evidence_turn_refs":ids.iter().map(EntityId::to_hex).collect::<Vec<_>>()
                }]})
                .to_string(),
            )
        };
        let backend = ScriptedBackend::new(vec![Ok(response(&turns))]);
        let guard = crate::BudgetGuard::with_reserve_units(
            "wake",
            10_000,
            100,
            BudgetExhaustionPolicy::Suspend,
        );
        let deadline = WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 0));
        let mut sink = CapturingSink::default();
        let mut ctx = WakeAttemptContext {
            vault: &vault,
            deadline: &deadline,
            budget_id: "wake",
            now_ms: 21_000,
        };
        let result = {
            let mut executor = ConsolidationExecutor {
                backend: &backend,
                guard: &guard,
                strategy: DreamerClaimAuthoringStrategy::SinglePass,
                actor: vault.dreamer_authority()?,
                model: crate::ModelId::new("test/model@r1").unwrap(),
                sink: &mut sink,
                scope: caller_scope,
            };
            block_on_ready(executor.execute(&attempt, &mut ctx))?
        };
        let DreamerAttemptExecution::Deferred {
            completed_units,
            retry_at,
        } = result
        else {
            panic!("selection hold must defer");
        };
        assert!(sink.accepted.is_empty());
        store.defer_selection(
            &attempt,
            crate::dreamer_runner::SettleDreamerBudget {
                budget_id: "wake".into(),
                child_attempt: attempt.status.attempt.id,
                actual_units: completed_units,
                now: 21,
            },
            retry_at,
        )?;
        let next_turn = seed_turn(
            &vault,
            &conversation,
            "assistant",
            "independent new evidence",
            22,
        );
        let next = match store.admit_next_consolidation(AdmitDreamerConsolidationAttempt {
            scope: DreamerConsolidationScope::Micro,
            local_node_id: crate::identity::load_or_mint_client_id(&vault)?,
            claim_authoring_tier: DreamerClaimAuthoringBatchTier::batch(),
            claim_authoring: DreamerClaimAuthoringAdmission::single_pass(),
            admission: AdmitDreamerAttempt {
                lease_owner: "worker".into(),
                budget_id: "wake".into(),
                budget_total_units: 10_000,
                reserve_units: 100,
                now: retry_at,
                started_milestone: None,
            },
        })? {
            DreamerConsolidationAdmissionOutcome::Admission(DreamerAdmissionOutcome::Admitted(
                next,
            )) => next,
            other => panic!("{other:?}"),
        };
        let backend = ScriptedBackend::new(vec![Ok(response(&[turns[0], next_turn]))]);
        ctx.now_ms = retry_at * 1_000;
        let mut executor = ConsolidationExecutor {
            backend: &backend,
            guard: &guard,
            strategy: DreamerClaimAuthoringStrategy::SinglePass,
            actor: vault.dreamer_authority()?,
            model: crate::ModelId::new("test/model@r1").unwrap(),
            sink: &mut sink,
            scope: None,
        };
        let outcome = block_on_ready(executor.execute(&next, &mut ctx));
        drop(executor);
        if caller_bounded {
            // A new worker supplies no caller scope, but the prior attenuation is
            // durable. A model cannot import the newly arrived, ungranted turn.
            assert!(outcome.is_err());
            assert!(sink.accepted.is_empty());
        } else {
            assert!(matches!(
                outcome?,
                DreamerAttemptExecution::Completed { .. }
            ));
            assert_eq!(sink.accepted.len(), 1);
            assert!(sink.accepted[0].evidence_turn_refs.contains(&next_turn));
        }
    }
    Ok(())
}

#[test]
fn admitted_branch_does_not_infer_read_authority_from_its_queue() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
    let store = DreamerRunnerStore::new(&vault);
    let (attempt, turns, _) =
        admitted_attempt_fixture(&vault, &store, 0x49, &[("user", "read grant required")])?;
    let (partition, _, _) = decode_partition_payload(&attempt.status.payload.input)?;
    assert!(matches!(
        BranchResources::open(
            &vault,
            vault.dreamer_authority()?,
            partition,
            &turns,
            attempt.status.attempt.id,
            None,
        ),
        Err(Error::InvalidClaimBody(_))
    ));
    grant_fixture_reads(&vault)?;
    let branch = BranchResources::open(
        &vault,
        vault.dreamer_authority()?,
        partition,
        &turns,
        attempt.status.attempt.id,
        None,
    )?;
    assert_eq!(
        branch.turn(branch.scope(), &turns[0])?.text.as_deref(),
        Some("read grant required")
    );
    Ok(())
}
