//! Turns captured through the Memory witness door keep their words on MESSAGE
//! children. The Dreamer reads that projection end to end: transcript,
//! evidence ranges, PERSON names, the live write fence and the attachment door.
use super::super::resources::{BranchResources, document_version};
use super::*;
use crate::attempt_queue::AttemptId;
use crate::dreamer_promotion::{DreamerRunContext, PromotionWriterSink};
use crate::dreamer_wake::{DreamerWakeDriver, RunWakePass, WakeCancellation, WakeTrigger};
use crate::llm::ScopeResource;
use crate::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use crate::vault_cleanup::{CleanupKind, zero_live_members};

const SAID: &str = "call me Oleksii";

struct RecordingBackend {
    inner: ScriptedBackend,
    requests: Mutex<Vec<LlmRequest>>,
}

impl RecordingBackend {
    fn new(script: Vec<LlmResult<crate::LlmResponse>>) -> Self {
        Self {
            inner: ScriptedBackend::new(script),
            requests: Mutex::new(Vec::new()),
        }
    }

    fn request_text(&self, index: usize) -> String {
        self.requests.lock().expect("request log")[index]
            .messages
            .iter()
            .flat_map(|message| &message.content)
            .filter_map(|part| match part {
                ContentPart::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect()
    }
}

impl LlmBackend for RecordingBackend {
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        self.requests
            .lock()
            .expect("request log")
            .push(request.clone());
        self.inner.generate(request, lease)
    }
    fn stream<'a>(&'a self, request: LlmRequest, lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        self.inner.stream(request, lease)
    }
}

/// Deletes one MESSAGE after the executor sealed its write, then promotes.
struct DriftSink<'a> {
    inner: PromotionWriterSink<'a>,
    delete: Option<EntityId>,
}

impl ConsolidationSink for DriftSink<'_> {
    fn accept(&mut self, _: Vec<PromotionCandidate>) -> Result<()> {
        panic!("sealed scoped write required")
    }

    fn accept_scoped(&mut self, write: ScopedConsolidationWrite) -> Result<()> {
        if let Some(id) = self.delete.take() {
            self.inner.vault.delete_room_record_unchecked_for_test(
                &id,
                crate::deletion::DeleteReason::UserDelete,
            )?;
        }
        self.inner.accept_scoped(write)
    }
}

fn message(order: u32, author: WitnessAuthor, content: &str, is_visible: bool) -> WitnessMessage {
    WitnessMessage {
        id: Some(EntityId::now().to_hex()),
        author,
        message_type: "dialogue".to_owned(),
        content: content.to_owned(),
        metadata: None,
        is_visible,
        order,
    }
}

/// One turn witnessed by a PERSON into a fresh conversation: (turn, conversation).
fn witness(vault: &Vault, seed: u8, messages: Vec<WitnessMessage>) -> (EntityId, EntityId) {
    let person = EntityId::from_bytes([seed; 16]).expect("person id");
    vault
        .put_entity(&person, ENTITY_TYPE_PERSON, occurred(1), 1, b"witness")
        .expect("witness person");
    let conversation = EntityId::from_bytes([seed + 1; 16]).expect("conversation id");
    let turn = EntityId::now();
    vault
        .memory(person, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: Some(turn.to_hex()),
            messages,
            occurred_at: 10,
        })
        .expect("witnessed turn");
    (turn, conversation)
}

fn queue_micro(vault: &Vault) -> Result<AttemptId> {
    let scope = DreamerConsolidationScope::Micro;
    let watermark = read_watermark(vault, scope)?;
    let dirty = scan_dirty_turns(vault, scope, &watermark, 10)?;
    let rows = enqueue_partition_attempts(vault, scope, &dirty, &watermark, "run-1", 20)?;
    let [EnqueueDreamerAttemptOutcome::Enqueued(row) | EnqueueDreamerAttemptOutcome::Existing(row)] =
        rows.as_slice()
    else {
        panic!("one queued partition");
    };
    Ok(row.attempt.id)
}

fn admit(vault: &Vault) -> Result<crate::dreamer_runner::DreamerAdmittedAttempt> {
    match DreamerRunnerStore::new(vault).admit_next_consolidation(
        AdmitDreamerConsolidationAttempt {
            scope: DreamerConsolidationScope::Micro,
            local_node_id: crate::identity::load_or_mint_client_id(vault)?,
            claim_authoring_tier: DreamerClaimAuthoringBatchTier::batch(),
            claim_authoring: DreamerClaimAuthoringAdmission::single_pass(),
            admission: AdmitDreamerAttempt {
                lease_owner: "witness-worker".to_owned(),
                now: 21,
                budget_id: "wake".to_owned(),
                budget_total_units: 10_000,
                reserve_units: 100,
                started_milestone: None,
            },
        },
    )? {
        DreamerConsolidationAdmissionOutcome::Admission(DreamerAdmissionOutcome::Admitted(
            admitted,
        )) => Ok(*admitted),
        other => panic!("{other:?}"),
    }
}

fn executor<'a>(
    vault: &Vault,
    backend: &'a dyn LlmBackend,
    guard: &'a crate::BudgetGuard,
    sink: &'a mut dyn ConsolidationSink,
    scope: Option<crate::llm::Scope>,
) -> Result<ConsolidationExecutor<'a>> {
    Ok(ConsolidationExecutor {
        backend,
        guard,
        strategy: DreamerClaimAuthoringStrategy::SinglePass,
        actor: vault.dreamer_authority()?,
        model: crate::ModelId::new("test/model@r1").expect("model"),
        sink,
        inference: test_inference_host(),
        scope,
    })
}

fn guard() -> crate::BudgetGuard {
    crate::BudgetGuard::with_reserve_units("wake", 10_000, 100, BudgetExhaustionPolicy::Suspend)
}

/// Direct executor call: the attempt prepares its own one-revision wake.
fn execute_direct(
    vault: &Vault,
    admitted: &crate::dreamer_runner::DreamerAdmittedAttempt,
    backend: &dyn LlmBackend,
    sink: &mut dyn ConsolidationSink,
    scope: Option<crate::llm::Scope>,
) -> Result<DreamerAttemptExecution> {
    let guard = guard();
    let deadline = WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 0));
    let mut executor = executor(vault, backend, &guard, sink, scope)?;
    block_on_ready(executor.execute(
        admitted,
        &mut WakeAttemptContext {
            vault,
            deadline: &deadline,
            budget_id: "wake",
            now_ms: 21_000,
            prepared_wake: None,
            prepared_attempt: None,
        },
    ))
}

/// The wake driver admits the queued attempt and hands it a prepared wake.
fn execute_by_driver(
    vault: &Vault,
    backend: &dyn LlmBackend,
    sink: &mut dyn ConsolidationSink,
) -> Result<u32> {
    let guard = guard();
    let deadline = WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 0));
    let mut executor = executor(vault, backend, &guard, sink, None)?;
    let mut driver = DreamerWakeDriver::new(vault, "wake", deadline);
    let input = RunWakePass {
        trigger: WakeTrigger::Compaction,
        scope: DreamerConsolidationScope::Micro,
        local_node_id: crate::identity::load_or_mint_client_id(vault)?,
        lease_owner: "witness-worker".to_owned(),
        budget_total_units: 10_000,
        reserve_units: 100,
        now: 23,
        host_scope: None,
    };
    let cancellation = WakeCancellation::new();
    let mut future = Box::pin(driver.run_wake_pass(input, &mut executor, &cancellation));
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    for _ in 0..128 {
        if let std::task::Poll::Ready(report) = future.as_mut().poll(&mut cx) {
            return Ok(report?.completed);
        }
    }
    panic!("wake pass did not reach an attempt boundary")
}

fn name_range() -> (usize, usize) {
    let start = SAID.find("Oleksii").expect("name span");
    (start, start + "Oleksii".len())
}

fn cite(turn: EntityId, (start, end): (usize, usize)) -> serde_json::Value {
    serde_json::json!({"source_id": turn.to_hex(), "byte_range": [start, end]})
}

fn candidate_locators(
    vault: &Vault,
    claim: &EntityId,
) -> Result<Vec<(SwarmEvidenceRef, [u8; 32])>> {
    let stored = vault.get_claim(claim)?.expect("landed claim");
    let Some(Value::Map(fields)) = stored.evidence else {
        panic!("claim evidence map")
    };
    let verified = fields
        .iter()
        .find(|(key, _)| key.as_str() == Some("candidate_evidence"))
        .map(|(_, value)| value)
        .expect("verified evidence");
    super::super::decode_verified_locators(verified)
}

fn claims_with(vault: &Vault, predicate: &str) -> Result<Vec<EntityId>> {
    let mut matched = Vec::new();
    for id in vault.entities_by_type(crate::registry::ENTITY_TYPE_CLAIM)? {
        if vault
            .get_claim(&id)?
            .is_some_and(|body| body.predicate == predicate)
        {
            matched.push(id);
        }
    }
    Ok(matched)
}

#[test]
fn witnessed_user_turn_reaches_extraction_and_lands_its_message_evidence() -> Result<()> {
    for by_driver in [false, true] {
        let (_dir, vault) = open_vault();
        let (turn, _) = witness(
            &vault,
            0x61,
            vec![message(0, WitnessAuthor::User, SAID, true)],
        );
        let actor = vault.dreamer_authority()?;
        super::prior_heads::policy(&vault, actor.entity_ref(), true)?;
        let subject = EntityId::now();
        vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred(1), 1, b"person")?;
        let attempt = queue_micro(&vault)?;
        let backend = RecordingBackend::new(vec![Ok(text_response(
            serde_json::json!({"candidates": [{
                "subject": subject.to_hex(), "predicate": "profile.name", "value": "Oleksii",
                "confidence": 0.8, "evidence_refs": [cite(turn, name_range())],
            }]})
            .to_string(),
        ))]);
        let mut sink = PromotionWriterSink::new(
            &vault,
            DreamerRunContext {
                run_id: "run-1".into(),
                attempt_id: attempt,
                agent_actor: actor,
                now_ms: 21_000,
            },
        );
        if by_driver {
            assert_eq!(execute_by_driver(&vault, &backend, &mut sink)?, 1);
        } else {
            let admitted = admit(&vault)?;
            assert_eq!(admitted.status.attempt.id, attempt);
            assert!(matches!(
                execute_direct(&vault, &admitted, &backend, &mut sink, None)?,
                DreamerAttemptExecution::Completed { .. }
            ));
        }
        assert!(
            backend
                .request_text(0)
                .contains(&format!("[{} user] {SAID}\n", turn.to_hex())),
            "the extraction model reads the witnessed words"
        );
        let [claim] = sink.outcome.landed.as_slice() else {
            panic!("one landed claim (driver: {by_driver})")
        };
        assert_eq!(
            candidate_locators(&vault, claim)?,
            vec![(
                SwarmEvidenceRef {
                    source_id: turn,
                    claim_id: None,
                    byte_range: Some(name_range()),
                },
                swarm_evidence_content_hash(b"Oleksii"),
            )]
        );
    }
    Ok(())
}

#[test]
fn witnessed_text_joins_visible_rows_of_its_bucket_and_slices_exact_utf8() -> Result<()> {
    // The pure rule: (order, id) with an id tie-break, joined by exactly
    // "\n" with empty rows kept; system interleave and hidden rows never
    // enter, and another non-system bucket refuses the turn.
    let body = |author: &str, order: u32, is_visible: bool, content: &str| {
        crate::gate::WitnessMessageEnvelope {
            author,
            message_type: "dialogue",
            content,
            metadata: None,
            is_visible,
            order,
        }
        .encode_body()
        .expect("canonical message body")
    };
    let children = vec![
        (
            EntityId::from_bytes([0x22; 16])?,
            body("user", 1, true, "b"),
        ),
        (EntityId::now(), body("system", 0, true, "tool output")),
        (
            EntityId::from_bytes([0x11; 16])?,
            body("user", 1, true, "a"),
        ),
        (EntityId::now(), body("user", 0, false, "hidden")),
        (EntityId::now(), body("user", 0, true, "")),
    ];
    let project = super::super::turn_text::project;
    assert_eq!(project("user", &children)?.as_deref(), Some("\na\nb"));
    let mut mixed = children;
    mixed.push((
        EntityId::now(),
        body("companion", 2, true, "not the speaker"),
    ));
    assert!(project("user", &mixed).is_err());

    // The real door: a companion turn with a hidden row, read by a branch.
    let (_dir, vault) = open_vault();
    let (turn, conversation) = witness(
        &vault,
        0x63,
        vec![
            message(2, WitnessAuthor::Companion, "and ☕ after", true),
            message(0, WitnessAuthor::Companion, "I met Casey", true),
            message(1, WitnessAuthor::Companion, "Morgan stays private", false),
        ],
    );
    let actor = vault.dreamer_authority()?;
    let partition = ConsolidationPartitionKey {
        conversation_ref: conversation,
        world_ref: None,
        facet_ref: None,
    };
    let branch = BranchResources::open(&vault, actor, partition, &[turn], AttemptId::now(), None)?;
    let text = "I met Casey\nand ☕ after";
    assert_eq!(
        branch.transcript(branch.scope(), &[turn])?,
        format!("[{} assistant] {text}\n", turn.to_hex())
    );
    let cup = text.find('☕').expect("multibyte span");
    let range = |end: usize| SwarmEvidenceRef {
        source_id: turn,
        claim_id: None,
        byte_range: Some((cup, end)),
    };
    assert_eq!(
        branch.verify_evidence_refs(&[range(cup + '☕'.len_utf8())])?[0].content_hash,
        swarm_evidence_content_hash("☕".as_bytes())
    );
    assert!(
        branch.verify_evidence_refs(&[range(cup + 1)]).is_err(),
        "a range may not split UTF-8"
    );
    // A supplied scope is never widened to the MESSAGE rows behind the text.
    let mut narrowed = branch.scope().clone();
    narrowed.readable.retain(|resource| {
        !matches!(resource, ScopeResource::DocumentVersion { document, .. }
            if *document != turn && *document != conversation)
    });
    assert!(
        BranchResources::open(
            &vault,
            actor,
            partition,
            &[turn],
            AttemptId::now(),
            Some(&narrowed)
        )
        .is_err()
    );
    // Inline TURN text wins exactly, even when empty.
    let stored = vault.get(&turn)?.expect("witnessed turn body");
    let Value::Map(mut fields) = rmpv::decode::read_value(&mut stored.as_slice()).expect("map")
    else {
        panic!("turn body map")
    };
    fields.push(("txt".into(), "".into()));
    let mut inline = Vec::new();
    rmpv::encode::write_value(&mut inline, &Value::Map(fields)).expect("inline turn body");
    vault.put_entity(&turn, ENTITY_TYPE_TURN, occurred(10), 10, &inline)?;
    let branch = BranchResources::open(&vault, actor, partition, &[turn], AttemptId::now(), None)?;
    assert_eq!(
        branch.transcript(branch.scope(), &[turn])?,
        format!("[{} assistant] \n", turn.to_hex())
    );
    Ok(())
}

#[test]
fn witnessed_names_mint_people_only_from_visible_text() -> Result<()> {
    let (_dir, vault) = open_vault();
    let (turn, _) = witness(
        &vault,
        0x65,
        vec![
            message(0, WitnessAuthor::Companion, "I met Casey", true),
            message(1, WitnessAuthor::Companion, "Morgan stays private", false),
        ],
    );
    queue_micro(&vault)?;
    let admitted = admit(&vault)?;
    let (casey, morgan) = (EntityId::now(), EntityId::now());
    let person = |id: EntityId, name: &str| serde_json::json!({"id": id.to_hex(), "name": name, "evidence_turn_refs": [turn.to_hex()]});
    let backend = RecordingBackend::new(vec![Ok(text_response(
        serde_json::json!({"candidates": [], "persons": [person(casey, "Casey"), person(morgan, "Morgan")]})
            .to_string(),
    ))]);
    let mut sink = CapturingSink::default();
    assert!(matches!(
        execute_direct(&vault, &admitted, &backend, &mut sink, None)?,
        DreamerAttemptExecution::Completed { .. }
    ));
    let request = backend.request_text(0);
    assert!(request.contains("I met Casey") && !request.contains("Morgan"));
    assert_eq!(
        zero_live_members(&vault, &casey)?,
        Some(CleanupKind::ClaimlessExtractionPerson)
    );
    assert!(
        !vault.entity_exists(&morgan)?,
        "a hidden row is no evidence"
    );
    Ok(())
}

#[test]
fn message_drift_after_preparation_refuses_new_claims_and_attachments() -> Result<()> {
    for drift in [false, true] {
        let (_dir, vault) = open_vault();
        let second = message(1, WitnessAuthor::User, "thanks", true);
        let dropped = EntityId::from_hex(second.id.as_deref().expect("message id"))?;
        let (turn, _) = witness(
            &vault,
            0x67,
            vec![message(0, WitnessAuthor::User, SAID, true), second],
        );
        let actor = vault.dreamer_authority()?;
        super::prior_heads::policy(&vault, actor.entity_ref(), true)?;
        let (subject, owner, head) = (EntityId::now(), EntityId::now(), EntityId::now());
        for id in [subject, owner] {
            vault.put_entity(&id, ENTITY_TYPE_PERSON, occurred(1), 1, b"person")?;
        }
        let envelope = WriteEnvelope::new(
            WriteActor::new(owner, EdgeActorClass::Human),
            ClaimSource::UserStated,
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
        queue_micro(&vault)?;
        let admitted = admit(&vault)?;
        // The host grants the branch's own exact scope plus the stored head.
        let (partition, turns, _) = decode_partition_payload(&admitted.status.payload.input)?;
        assert_eq!(turns, vec![turn]);
        let mut scope = BranchResources::open(
            &vault,
            actor,
            partition,
            &turns,
            admitted.status.attempt.id,
            None,
        )?
        .scope()
        .clone();
        let pin = document_version(head, &vault.get(&head)?.expect("head body"));
        scope.readable.insert(pin.clone());
        scope.writable.insert(pin);
        let row = |predicate: &str| {
            serde_json::json!({
                "subject": subject.to_hex(), "predicate": predicate, "value": "Oleksii",
                "confidence": 0.8, "evidence_refs": [cite(turn, name_range())],
            })
        };
        let backend = ScriptedBackend::new(vec![Ok(text_response(
            serde_json::json!({"candidates": [row("profile.name"), row("profile.nickname")]})
                .to_string(),
        ))]);
        let mut sink = DriftSink {
            inner: PromotionWriterSink::new(
                &vault,
                DreamerRunContext {
                    run_id: "run-1".into(),
                    attempt_id: admitted.status.attempt.id,
                    agent_actor: actor,
                    now_ms: 21_000,
                },
            ),
            delete: drift.then_some(dropped),
        };
        let turn_before = vault.get_raw(&turn)?;
        let head_before = vault.get_raw(&head)?;
        let result = execute_direct(&vault, &admitted, &backend, &mut sink, Some(scope));
        let supports = vault.sources(&head, EdgeKind::Supports, None)?;
        let nicknames = claims_with(&vault, "profile.nickname")?;
        let wrappers = claims_with(&vault, crate::provenance::PREDICATE_EDGE_PROVENANCE)?;
        assert_eq!(vault.get_raw(&head)?, head_before);
        if drift {
            assert!(result.is_err(), "a changed child set refuses the write");
            assert_eq!(
                vault.get_raw(&turn)?,
                turn_before,
                "the TURN itself never moved"
            );
            assert!(sink.inner.outcome.landed.is_empty());
            assert_eq!(sink.inner.outcome.rejected.len(), 2);
            assert!(supports.is_empty() && nicknames.is_empty() && wrappers.is_empty());
        } else {
            assert!(matches!(result?, DreamerAttemptExecution::Completed { .. }));
            assert_eq!(sink.inner.outcome.landed.len(), 2);
            assert!(sink.inner.outcome.landed.contains(&head));
            assert_eq!(supports, vec![turn]);
            assert_eq!((nicknames.len(), wrappers.len()), (1, 1));
        }
    }
    Ok(())
}
