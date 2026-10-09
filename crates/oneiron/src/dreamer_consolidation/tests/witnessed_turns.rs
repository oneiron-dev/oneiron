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

type Change = Box<dyn FnOnce(&Vault) -> Result<()>>;

/// Changes the vault after the executor sealed its write, then promotes.
struct DriftSink<'a> {
    inner: PromotionWriterSink<'a>,
    change: Option<Change>,
}

impl ConsolidationSink for DriftSink<'_> {
    fn accept(&mut self, _: Vec<PromotionCandidate>) -> Result<()> {
        panic!("sealed scoped write required")
    }

    fn accept_scoped(&mut self, write: ScopedConsolidationWrite) -> Result<()> {
        if let Some(change) = self.change.take() {
            change(self.inner.vault)?;
        }
        self.inner.accept_scoped(write)
    }
}

fn delete_message(vault: &Vault, id: EntityId) -> Result<()> {
    vault.delete_room_record_unchecked_for_test(&id, crate::deletion::DeleteReason::UserDelete)?;
    Ok(())
}

/// The fixture vault on an injected clock at 50, so a grant can expire
/// between preparation and a write with nothing else changing.
fn open_clocked_vault() -> (
    tempfile::TempDir,
    Vault,
    std::sync::Arc<crate::ports::ManualClock>,
) {
    let clock = crate::ports::ManualClock::new(50);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let (dir, vault) = crate::test_util::open_test_vault_with(config);
    crate::test_util::provision_engine_machines(&vault);
    authorize_test_inference(&vault).expect("owner-pinned test egress");
    grant_fixture_reads(&vault).expect("explicit consolidation read grant");
    (dir, vault, clock)
}

/// The Dreamer's own `MessagesRead` grant on one relationship space.
fn grant_messages(vault: &Vault, space: EntityId, expires_at: u64) -> Result<EntityId> {
    let grant = EntityId::now();
    vault.create_access_grant(
        &grant,
        &crate::access_grant::AccessGrant {
            principal_ref: vault.dreamer_authority()?.entity_ref(),
            scope: crate::access_grant::AccessGrantScope::Messages { space_ref: space },
            capability: crate::access_grant::AccessGrantCapability::MessagesRead,
            status: crate::access_grant::AccessGrantStatus::Active,
            created_at: 1,
            revoked_at: None,
            expires_at: Some(expires_at),
            authority_scope: crate::federation::scope_codec::read_preset(),
        },
    )?;
    Ok(grant)
}

/// An owner-approved `profile.name = Oleksii` head on `subject`.
fn put_head(vault: &Vault, subject: EntityId) -> Result<EntityId> {
    let (owner, head) = (EntityId::now(), EntityId::now());
    vault.put_entity(&owner, ENTITY_TYPE_PERSON, occurred(1), 1, b"person")?;
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
    Ok(head)
}

/// The admitted branch's own exact scope plus the stored head, as a host
/// grants it.
fn head_scope(
    vault: &Vault,
    admitted: &crate::dreamer_runner::DreamerAdmittedAttempt,
    head: EntityId,
) -> Result<(ConsolidationPartitionKey, Vec<EntityId>, crate::llm::Scope)> {
    let (partition, turns, _) = decode_partition_payload(&admitted.status.payload.input)?;
    let mut scope = BranchResources::open(
        vault,
        vault.dreamer_authority()?,
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
    Ok((partition, turns, scope))
}

fn run_context(
    actor: WriteActor,
    admitted: &crate::dreamer_runner::DreamerAdmittedAttempt,
) -> DreamerRunContext {
    DreamerRunContext {
        run_id: "run-1".into(),
        attempt_id: admitted.status.attempt.id,
        agent_actor: actor,
        now_ms: 21_000,
    }
}

/// The fixture's Dreamer read grant plus the one permit for engine-voice
/// `system` rows: an owner-authored `auto` ceiling bound to `writer`.
fn allow_system_rows(vault: &Vault, writer: EntityId) -> Result<()> {
    let Value::Map(mut entries) =
        rmpv::decode::read_value(&mut crate::gate::default_policy_manifest()?.as_slice())
            .expect("default policy map")
    else {
        panic!("policy manifest map")
    };
    for (key, value) in &mut entries {
        if key.as_str() == Some("actor_ceilings")
            && let Value::Array(rows) = value
        {
            rows.push(Value::Map(vec![
                ("actor_class".into(), "human".into()),
                ("actor_ref".into(), writer.to_hex().into()),
                ("ceiling".into(), "auto".into()),
            ]));
        }
    }
    entries.push((
        "scoped_grants".into(),
        Value::Array(vec![Value::Map(vec![
            (
                "actor_ref".into(),
                vault.dreamer_authority()?.entity_ref().to_hex().into(),
            ),
            ("actor_class".into(), "system".into()),
            ("effector".into(), "core:read".into()),
            (
                "scope".into(),
                crate::federation::scope_codec::encode_scope_value(
                    &crate::federation::scope_codec::read_preset(),
                )?,
            ),
            ("receipt_required".into(), false.into()),
        ])]),
    ));
    crate::test_util::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id()?,
        &super::super::support::encode_value(&Value::Map(entries))?,
    )
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

/// GATE-10 and the evidence contract at the branch door: system interleave
/// and hidden rows never reach the transcript or a citation, rows join in
/// position order, ranges are measured over the displayed UTF-8 text, a
/// supplied scope is never widened to the MESSAGE rows, and inline TURN text
/// wins exactly.
#[test]
fn branch_reads_only_the_turns_visible_words_and_cites_them_exactly() -> Result<()> {
    let (_dir, vault) = open_vault();
    let writer = EntityId::from_bytes([0x63; 16])?;
    allow_system_rows(&vault, writer)?;
    let (turn, conversation) = witness(
        &vault,
        0x63,
        vec![
            message(3, WitnessAuthor::Companion, "and ☕ after", true),
            message(0, WitnessAuthor::Companion, "I met Casey", true),
            message(1, WitnessAuthor::System, "tool output", true),
            message(2, WitnessAuthor::Companion, "Morgan stays private", false),
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

/// The write fence (new claims and existing-head attachments alike) refuses
/// a turn whose MESSAGE dependencies moved after the write was sealed: a
/// deleted uncited row, or only an `AuthoredBy` edge on the cited row, with
/// the words themselves unchanged (its author replaced by another PERSON).
#[test]
fn message_drift_after_preparation_refuses_new_claims_and_attachments() -> Result<()> {
    for drift in ["none", "deleted row", "author edge"] {
        let (_dir, vault) = open_vault();
        let first = message(0, WitnessAuthor::User, SAID, true);
        let second = message(1, WitnessAuthor::User, "thanks", true);
        let cited = EntityId::from_hex(first.id.as_deref().expect("message id"))?;
        let dropped = EntityId::from_hex(second.id.as_deref().expect("message id"))?;
        let (turn, _) = witness(&vault, 0x67, vec![first, second]);
        let writer = EntityId::from_bytes([0x67; 16])?;
        let other = EntityId::now();
        vault.put_entity(&other, ENTITY_TYPE_PERSON, occurred(1), 1, b"person")?;
        let change: Option<Change> = match drift {
            "deleted row" => Some(Box::new(move |vault: &Vault| {
                delete_message(vault, dropped)
            })),
            "author edge" => Some(Box::new(move |vault: &Vault| {
                // Fault injection past the delete door's room guards: a room
                // MESSAGE's author edge moves only through the actor door.
                use crate::ports::EdgeStoreStaging;
                vault.with_write_txn(|txn| {
                    let torn = vault.store.port_remove_edge_rows(
                        txn,
                        &cited,
                        EdgeKind::AuthoredBy,
                        &writer,
                    )?;
                    assert!(torn, "the author edge existed");
                    Ok(())
                })?;
                vault.put_edge(&cited, EdgeKind::AuthoredBy, &other, 1.0)?;
                Ok(())
            })),
            _ => None,
        };
        let actor = vault.dreamer_authority()?;
        super::prior_heads::policy(&vault, actor.entity_ref(), true)?;
        let subject = EntityId::now();
        vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred(1), 1, b"person")?;
        let head = put_head(&vault, subject)?;
        queue_micro(&vault)?;
        let admitted = admit(&vault)?;
        let (_, turns, scope) = head_scope(&vault, &admitted, head)?;
        assert_eq!(turns, vec![turn]);
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
            inner: PromotionWriterSink::new(&vault, run_context(actor, &admitted)),
            change,
        };
        let turn_before = vault.get_raw(&turn)?;
        let cited_before = vault.get_raw(&cited)?;
        let head_before = vault.get_raw(&head)?;
        let result = execute_direct(&vault, &admitted, &backend, &mut sink, Some(scope));
        let supports = vault.sources(&head, EdgeKind::Supports, None)?;
        let nicknames = claims_with(&vault, "profile.nickname")?;
        let wrappers = claims_with(&vault, crate::provenance::PREDICATE_EDGE_PROVENANCE)?;
        assert_eq!(vault.get_raw(&head)?, head_before);
        if drift != "none" {
            assert!(
                result.is_err(),
                "{drift}: the moved dependency refuses the write"
            );
            assert_eq!(
                vault.get_raw(&turn)?,
                turn_before,
                "{drift}: the TURN never moved"
            );
            assert_eq!(
                vault.get_raw(&cited)?,
                cited_before,
                "{drift}: the words never moved"
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

/// MESSAGE privacy is a read gate: a private row, or a relationship row the
/// Dreamer holds no live grant for, refuses its turn. No word reaches the
/// model, and no claim or PERSON lands. A grant revoked, or one that simply
/// expires on the clock, after preparation refuses at the write fence the
/// same way, and so does a whole-TURN attachment sealed under the grant.
#[test]
fn private_or_ungranted_relationship_messages_never_reach_consolidation() -> Result<()> {
    let space = EntityId::now();
    let related = || serde_json::json!({"rel": space.to_hex()});
    for case in ["private", "no grant", "revoked grant", "expired grant"] {
        let (_dir, vault, clock) = open_clocked_vault();
        let metadata = if case == "private" {
            serde_json::json!({"scope": {"private": true}})
        } else {
            related()
        };
        let (turn, _) = witness(
            &vault,
            0x69,
            vec![WitnessMessage {
                metadata: Some(metadata),
                ..message(0, WitnessAuthor::User, SAID, true)
            }],
        );
        let actor = vault.dreamer_authority()?;
        super::prior_heads::policy(&vault, actor.entity_ref(), true)?;
        if case == "revoked grant" {
            let grant = grant_messages(&vault, space, u64::MAX)?;
            vault
                .test_hooks()
                .install_before_dreamer_person_mint(move |vault| {
                    vault.revoke_access_grant(&grant, 2).expect("revoke grant");
                });
        }
        if case == "expired grant" {
            grant_messages(&vault, space, 100)?;
            let clock = std::sync::Arc::clone(&clock);
            vault
                .test_hooks()
                .install_before_dreamer_person_mint(move |_| clock.set(200));
        }
        let (subject, named) = (EntityId::now(), EntityId::now());
        vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred(1), 1, b"person")?;
        queue_micro(&vault)?;
        let admitted = admit(&vault)?;
        let backend = RecordingBackend::new(vec![Ok(text_response(
            serde_json::json!({
                "candidates": [{
                    "subject": subject.to_hex(), "predicate": "profile.name", "value": "Oleksii",
                    "confidence": 0.8, "evidence_refs": [cite(turn, name_range())],
                }],
                "persons": [{"id": named.to_hex(), "name": "Oleksii", "evidence_turn_refs": [turn.to_hex()]}],
            })
            .to_string(),
        ))]);
        let mut sink = PromotionWriterSink::new(&vault, run_context(actor, &admitted));
        let result = execute_direct(&vault, &admitted, &backend, &mut sink, None);
        assert!(result.is_err(), "{case}: the turn is refused");
        // Only a grant that was live at preparation let the words out.
        assert_eq!(
            backend.inner.calls.load(Ordering::SeqCst),
            usize::from(matches!(case, "revoked grant" | "expired grant")),
            "{case}"
        );
        assert!(sink.outcome.landed.is_empty(), "{case}");
        assert!(claims_with(&vault, "profile.name")?.is_empty(), "{case}");
        assert!(!vault.entity_exists(&named)?, "{case}: no PERSON");
    }
    // A whole-TURN (no-range) attachment to an existing head, sealed while
    // the grant was live, commits only if the grant still holds when written.
    for expire in [false, true] {
        let (_dir, vault, clock) = open_clocked_vault();
        let (turn, _) = witness(
            &vault,
            0x6d,
            vec![WitnessMessage {
                metadata: Some(related()),
                ..message(0, WitnessAuthor::User, SAID, true)
            }],
        );
        let actor = vault.dreamer_authority()?;
        super::prior_heads::policy(&vault, actor.entity_ref(), true)?;
        grant_messages(&vault, space, 100)?;
        let subject = EntityId::now();
        vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred(1), 1, b"person")?;
        let head = put_head(&vault, subject)?;
        queue_micro(&vault)?;
        let admitted = admit(&vault)?;
        let (partition, turns, scope) = head_scope(&vault, &admitted, head)?;
        let branch = BranchResources::open(
            &vault,
            actor,
            partition,
            &turns,
            admitted.status.attempt.id,
            Some(&scope),
        )?;
        let mut whole = candidate(subject, "profile.name", "Oleksii", None);
        whole.evidence_turn_refs = vec![turn];
        let facts = super::super::conflict::candidate_facts(&whole.candidate)?;
        whole.claim_id = super::super::conflict::deterministic_claim_id(
            admitted.status.attempt.id,
            facts.subject,
            &facts.predicate,
            &facts.value,
            facts.world,
            facts.facet,
            facts.rel,
            facts.topic.as_deref(),
        )?;
        let change: Option<Change> = expire.then(|| {
            let clock = std::sync::Arc::clone(&clock);
            Box::new(move |_: &Vault| {
                clock.set(200);
                Ok(())
            }) as Change
        });
        let mut sink = DriftSink {
            inner: PromotionWriterSink::new(&vault, run_context(actor, &admitted)),
            change,
        };
        let result = branch.accept(branch.scope(), &mut sink, vec![whole]);
        let supports = vault.sources(&head, EdgeKind::Supports, None)?;
        let wrappers = claims_with(&vault, crate::provenance::PREDICATE_EDGE_PROVENANCE)?;
        if expire {
            assert!(result.is_err(), "an expired grant refuses the attachment");
            assert!(supports.is_empty() && wrappers.is_empty());
        } else {
            result?;
            assert_eq!((supports, wrappers.len()), (vec![turn], 1));
        }
    }
    Ok(())
}

/// A text-dependent reflection gap is written only while the words it was
/// read from still stand. Between the scan and the queue write the user's
/// message is deleted, or the grant it was read under expires on the clock;
/// the write then neither creates the new gap nor refreshes the queued one.
#[test]
fn gap_queue_refuses_a_text_gap_whose_message_changed_after_the_scan() -> Result<()> {
    for case in ["deleted row", "expired grant"] {
        let (_dir, vault, clock) = open_clocked_vault();
        let space = EntityId::now();
        let said = WitnessMessage {
            metadata: (case == "expired grant").then(|| serde_json::json!({"rel": space.to_hex()})),
            ..message(0, WitnessAuthor::User, "I'll call Casey tomorrow", true)
        };
        let words = EntityId::from_hex(said.id.as_deref().expect("message id"))?;
        let (turn, conversation) = witness(&vault, 0x6b, vec![said]);
        if case == "expired grant" {
            grant_messages(&vault, space, 100)?;
        }
        let working_set = [WorkingSetTurn {
            turn_id: turn,
            role: DreamerTurnRole::User,
            learned_at: 10,
            carrier: None,
            conversation: Some(conversation),
        }];
        let (gaps, texts) = super::super::gap::scan_with_texts(&vault, &working_set, 2_000)?;
        let [unresolved, intent] = <[ReflectionGap; 2]>::try_from(gaps.clone()).expect("two gaps");
        assert_eq!(
            (unresolved.kind, intent.kind),
            (
                ReflectionGapKind::UnresolvedThread,
                ReflectionGapKind::StatedIntentWithoutAction
            )
        );
        // The role-only gap is already queued from an earlier round.
        assert_eq!(
            upsert_gap_queue(&vault, vec![unresolved], 1_000)?.created,
            1
        );
        if case == "deleted row" {
            delete_message(&vault, words)?;
        } else {
            clock.set(200);
        }
        assert!(
            super::super::gap::upsert_scanned_gap_queue(&vault, gaps, &texts, 2_000).is_err(),
            "{case}"
        );
        // The intent gap is still new, and the queued gap still carries its
        // first observation, so it decays on that schedule.
        let delta = upsert_gap_queue(&vault, vec![intent], 1_000 + DREAMER_GAP_DECAY_MS)?;
        assert_eq!(
            (delta.created, delta.refreshed, delta.decayed),
            (1, 0, 1),
            "{case}"
        );
    }
    Ok(())
}

fn id_of(message: &WitnessMessage) -> EntityId {
    EntityId::from_hex(message.id.as_deref().expect("message id")).expect("message id hex")
}

fn partition_of(conversation: EntityId) -> ConsolidationPartitionKey {
    ConsolidationPartitionKey {
        conversation_ref: conversation,
        world_ref: None,
        facet_ref: None,
    }
}

fn field<'v>(map: &'v Value, key: &str) -> Option<&'v Value> {
    let Value::Map(entries) = map else {
        return None;
    };
    entries
        .iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .map(|(_, value)| value)
}

/// Whether `id` is still current: the readers that honour recorded source
/// dependencies (current entity reads, active claims, retrieval) return it.
fn current(vault: &Vault, id: &EntityId) -> Result<bool> {
    Ok(vault.get(id)?.is_some())
}

/// The stored evidence envelope of a landed claim, or the generated evidence
/// an attachment's provenance record stores.
fn stored_evidence(vault: &Vault, id: &EntityId) -> Result<Value> {
    let stored = vault.get_claim(id)?.expect("stored claim");
    let (map, key) = if stored.predicate == crate::provenance::PREDICATE_EDGE_PROVENANCE {
        (stored.scope.expect("wrapper scope"), "derived_evidence")
    } else {
        (
            stored.evidence.expect("claim evidence"),
            "candidate_evidence",
        )
    };
    Ok(field(&map, key).expect("stored evidence").clone())
}

/// One MESSAGE slice a stored locator names.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Named {
    message: EntityId,
    span: (u64, u64),
    revision: Vec<u8>,
    frontier: Option<Vec<u8>>,
}

/// What each stored locator names, in stored order: the MESSAGE slices behind
/// a witnessed turn range (none for any other citation).
fn named_messages(envelope: &Value) -> Vec<Vec<Named>> {
    let Some(Value::Array(locators)) = field(envelope, "locators") else {
        panic!("stored locators")
    };
    locators
        .iter()
        .map(|locator| {
            let Some(Value::Array(slices)) = field(locator, "messages") else {
                return Vec::new();
            };
            slices
                .iter()
                .map(|slice| {
                    let Some(Value::Array(span)) = field(slice, "span") else {
                        panic!("slice span")
                    };
                    let bytes = |key| match field(slice, key) {
                        Some(Value::Binary(bytes)) => Some(bytes.clone()),
                        None => None,
                        Some(other) => panic!("slice {key}: {other:?}"),
                    };
                    Named {
                        message: field(slice, "message")
                            .and_then(entity_ref_from_value)
                            .expect("slice message"),
                        span: (
                            span[0].as_u64().expect("span start"),
                            span[1].as_u64().expect("span end"),
                        ),
                        revision: bytes("revision").expect("slice revision"),
                        frontier: bytes("frontier"),
                    }
                })
                .collect()
        })
        .collect()
}

/// The exact revision a reader of `message` sees now.
fn revision(vault: &Vault, message: &EntityId) -> Result<Vec<u8>> {
    Ok(swarm_evidence_content_hash(&vault.get(message)?.expect("message body")).to_vec())
}

/// The words a MESSAGE carries now.
fn content(vault: &Vault, message: &EntityId) -> Result<String> {
    let body = vault.get(message)?.expect("message body");
    let value = rmpv::decode::read_value(&mut body.as_slice()).expect("message map");
    Ok(field(&value, "content")
        .and_then(Value::as_str)
        .expect("message content")
        .to_owned())
}

fn span_of((start, end): (usize, usize)) -> (u64, u64) {
    (start as u64, end as u64)
}

/// Runs the queued micro attempt with `rows` as the model's candidates and
/// returns the promotion outcome.
fn land(
    vault: &Vault,
    rows: Vec<serde_json::Value>,
    scope: impl FnOnce(
        &crate::dreamer_runner::DreamerAdmittedAttempt,
    ) -> Result<Option<crate::llm::Scope>>,
) -> Result<crate::dreamer_promotion::PromotionOutcome> {
    let actor = vault.dreamer_authority()?;
    queue_micro(vault)?;
    let admitted = admit(vault)?;
    let scope = scope(&admitted)?;
    let backend = ScriptedBackend::new(vec![Ok(text_response(
        serde_json::json!({ "candidates": rows }).to_string(),
    ))]);
    let mut sink = PromotionWriterSink::new(vault, run_context(actor, &admitted));
    assert!(matches!(
        execute_direct(vault, &admitted, &backend, &mut sink, scope)?,
        DreamerAttemptExecution::Completed { .. }
    ));
    Ok(sink.outcome)
}

fn nickname(subject: EntityId, turn: EntityId, range: (usize, usize)) -> serde_json::Value {
    serde_json::json!({
        "subject": subject.to_hex(), "predicate": "profile.nickname", "value": "Oleksii",
        "confidence": 0.8, "evidence_refs": [cite(turn, range)],
    })
}

/// A stored citation over a witnessed turn names the MESSAGE words it was
/// taken from (the cited child, its own span, its exact revision) on the new
/// claim and on an existing head's attachment alike. Deleting a prefix
/// sibling after commit moves the turn's projected offsets, never what the
/// citation names; erasing the cited child invalidates both citations through
/// their recorded dependency.
#[test]
fn stored_citation_names_its_message_through_a_prefix_deletion() -> Result<()> {
    let (_dir, vault) = open_vault();
    let prefix = message(0, WitnessAuthor::User, "hi", true);
    let words = message(1, WitnessAuthor::User, SAID, true);
    let (prefix_id, cited) = (id_of(&prefix), id_of(&words));
    let (turn, _) = witness(&vault, 0x71, vec![prefix, words]);
    super::prior_heads::policy(&vault, vault.dreamer_authority()?.entity_ref(), true)?;
    let subject = EntityId::now();
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred(1), 1, b"person")?;
    let head = put_head(&vault, subject)?;
    let (start, end) = name_range();
    let projected = (start + "hi\n".len(), end + "hi\n".len());
    let mut name = nickname(subject, turn, projected);
    name["predicate"] = "profile.name".into();
    let outcome = land(
        &vault,
        vec![name, nickname(subject, turn, projected)],
        |admitted| Ok(Some(head_scope(&vault, admitted, head)?.2)),
    )?;
    assert_eq!(outcome.landed.len(), 2, "{outcome:?}");
    let [claim] = claims_with(&vault, "profile.nickname")?[..] else {
        panic!("one new claim")
    };
    let [wrapper] = claims_with(&vault, crate::provenance::PREDICATE_EDGE_PROVENANCE)?[..] else {
        panic!("one attachment")
    };
    let named = vec![vec![Named {
        message: cited,
        span: span_of(name_range()),
        revision: revision(&vault, &cited)?,
        frontier: None,
    }]];
    for citing in [claim, wrapper] {
        assert_eq!(named_messages(&stored_evidence(&vault, &citing)?), named);
    }
    delete_message(&vault, prefix_id)?;
    assert_eq!(&content(&vault, &cited)?[start..end], "Oleksii");
    assert!(current(&vault, &claim)? && current(&vault, &wrapper)?);
    delete_message(&vault, cited)?;
    assert!(
        !current(&vault, &claim)? && !current(&vault, &wrapper)?,
        "the cited words' erasure invalidates every citation of them"
    );
    Ok(())
}

/// Two siblings carry the same words. The stored citation names the one it
/// was taken from, so erasing that one invalidates the claim even though the
/// turn's text at the saved offsets, and its quote hash, are unchanged.
#[test]
fn stored_citation_of_equal_words_names_the_sibling_it_was_taken_from() -> Result<()> {
    let (_dir, vault) = open_vault();
    let first = message(0, WitnessAuthor::User, "same quote", true);
    let second = message(1, WitnessAuthor::User, "same quote", true);
    let (cited, other) = (id_of(&first), id_of(&second));
    let (turn, _) = witness(&vault, 0x73, vec![first, second]);
    super::prior_heads::policy(&vault, vault.dreamer_authority()?.entity_ref(), true)?;
    let subject = EntityId::now();
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred(1), 1, b"person")?;
    land(&vault, vec![nickname(subject, turn, (0, 10))], |_| Ok(None))?;
    let [claim] = claims_with(&vault, "profile.nickname")?[..] else {
        panic!("one landed claim")
    };
    assert_eq!(
        named_messages(&stored_evidence(&vault, &claim)?),
        vec![vec![Named {
            message: cited,
            span: (0, 10),
            revision: revision(&vault, &cited)?,
            frontier: None,
        }]]
    );
    assert_ne!(cited, other);
    delete_message(&vault, cited)?;
    assert!(
        !current(&vault, &claim)?,
        "the cited sibling's erasure invalidates the claim"
    );
    Ok(())
}

/// One user MESSAGE written through the stream doors into a fresh turn and
/// ended by `ending`: (turn, conversation, message, the stream's input).
fn stream_turn(
    vault: &Vault,
    seed: u8,
    text: &str,
    ending: &str,
) -> Result<(EntityId, EntityId, EntityId, WitnessTurn)> {
    let person = EntityId::from_bytes([seed; 16])?;
    vault.put_entity(
        &person,
        ENTITY_TYPE_PERSON,
        occurred(1),
        1,
        b"stream writer",
    )?;
    // A continuation stream needs its human writer's live owner binding.
    crate::test_util::bind_test_owner(vault, person);
    let conversation = EntityId::from_bytes([seed + 1; 16])?;
    let turn = EntityId::now();
    let input = WitnessTurn {
        conversation_ref: conversation.to_hex(),
        turn_ref: Some(turn.to_hex()),
        messages: vec![message(0, WitnessAuthor::User, "", true)],
        occurred_at: 10,
    };
    end_stream(vault, person, &input, text, ending);
    Ok((turn, conversation, id_of(&input.messages[0]), input))
}

/// Opens a stream on `input`'s MESSAGE as `writer` (a continuation once the
/// MESSAGE exists), appends `text` and ends it by `ending`.
fn end_stream(vault: &Vault, writer: EntityId, input: &WitnessTurn, text: &str, ending: &str) {
    let memory = vault.memory(writer, EdgeActorClass::Human);
    let handle = memory
        .begin_message_stream(input, Some(crate::memory::MessageWriteMode::Atomic))
        .expect("stream begins");
    memory.append_to_stream(handle, text).expect("append");
    match ending {
        "finalize" => {
            memory.finalize_stream(handle).expect("finalize");
        }
        "cancel" => {
            memory
                .cancel_stream(handle, crate::memory::StreamCancelReason::UserInterrupted)
                .expect("cancel");
        }
        "idle timeout" => {
            let pump = vault.pump_message_streams_at(u64::MAX).expect("pump");
            assert_eq!(pump.finalized.len(), 1, "the quiet stream timed out");
        }
        other => panic!("unknown stream ending {other}"),
    }
}

/// Only final words are transcript. A stream that ends by cancellation or by
/// idle timeout keeps its text as audit, never as words the Dreamer reads or
/// cites; an explicit finalize is final.
#[test]
fn only_finalized_stream_text_reaches_the_branch() -> Result<()> {
    for ending in ["finalize", "cancel", "idle timeout"] {
        let (_dir, vault) = open_vault();
        let (turn, conversation, _, _) = stream_turn(&vault, 0x75, SAID, ending)?;
        let branch = BranchResources::open(
            &vault,
            vault.dreamer_authority()?,
            partition_of(conversation),
            &[turn],
            AttemptId::now(),
            None,
        )?;
        let transcript = branch.transcript(branch.scope(), &[turn])?;
        let cited = branch.verify_evidence_refs(&[SwarmEvidenceRef {
            source_id: turn,
            claim_id: None,
            byte_range: Some(name_range()),
        }]);
        if ending == "finalize" {
            assert_eq!(transcript, format!("[{} user] {SAID}\n", turn.to_hex()));
            assert_eq!(
                cited?[0].content_hash,
                swarm_evidence_content_hash(b"Oleksii")
            );
        } else {
            assert_eq!(
                transcript,
                format!("[{} user] \n", turn.to_hex()),
                "{ending}: audit text is not transcript"
            );
            assert!(cited.is_err(), "{ending}: audit text is not evidence");
        }
    }
    Ok(())
}

/// The latest stream decides. A final message whose later continuation was
/// cancelled is audit text, and a branch that read it while it was final
/// refuses once that finality moved, even though the words did not.
#[cfg(feature = "sync")]
#[test]
fn a_cancelled_continuation_turns_its_final_message_into_audit_text() -> Result<()> {
    let (_dir, vault) = open_vault();
    let (turn, conversation, _, input) = stream_turn(&vault, 0x77, SAID, "finalize")?;
    let actor = vault.dreamer_authority()?;
    let open = || {
        BranchResources::open(
            &vault,
            actor,
            partition_of(conversation),
            &[turn],
            AttemptId::now(),
            None,
        )
    };
    let branch = open()?;
    assert!(branch.transcript(branch.scope(), &[turn])?.contains(SAID));
    end_stream(
        &vault,
        EntityId::from_bytes([0x77; 16])?,
        &input,
        "",
        "cancel",
    );
    assert!(
        branch.transcript(branch.scope(), &[turn]).is_err(),
        "the finality the branch read moved under it"
    );
    let reopened = open()?;
    assert_eq!(
        reopened.transcript(reopened.scope(), &[turn])?,
        format!("[{} user] \n", turn.to_hex())
    );
    Ok(())
}

/// The citation names the version it quoted. After commit the cited MESSAGE
/// is edited by a finalized continuation: the stored citation still names
/// that child at the revision and document frontier it was read at, that
/// frontier still reads the quoted words, and an edit is not an erasure, so
/// the claim stays current.
#[cfg(feature = "sync")]
#[test]
fn stored_citation_names_its_message_version_through_a_later_edit() -> Result<()> {
    let (_dir, vault) = open_vault();
    let (turn, _, cited, input) = stream_turn(&vault, 0x79, SAID, "finalize")?;
    let quoted = revision(&vault, &cited)?;
    let read_at = vault.entity_text_anchor(&cited, 0, 0)?.frontier().to_vec();
    super::prior_heads::policy(&vault, vault.dreamer_authority()?.entity_ref(), true)?;
    let subject = EntityId::now();
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred(1), 1, b"person")?;
    land(&vault, vec![nickname(subject, turn, name_range())], |_| {
        Ok(None)
    })?;
    let [claim] = claims_with(&vault, "profile.nickname")?[..] else {
        panic!("one landed claim")
    };
    let named = named_messages(&stored_evidence(&vault, &claim)?);
    assert!(named.len() == 1 && named[0].len() == 1, "{named:?}");
    let slice = &named[0][0];
    assert_eq!(
        (slice.message, slice.span, &slice.revision),
        (cited, span_of(name_range()), &quoted)
    );
    assert!(
        slice
            .frontier
            .as_ref()
            .is_some_and(|stored| stored.ends_with(&read_at)),
        "a document-backed child names the frontier it was read at"
    );
    end_stream(
        &vault,
        EntityId::from_bytes([0x79; 16])?,
        &input,
        ", thanks",
        "finalize",
    );
    assert_ne!(revision(&vault, &cited)?, quoted, "the words were edited");
    assert_eq!(
        vault.entity_text_at(&cited, &read_at)?,
        SAID,
        "the named frontier still reads the quoted words"
    );
    assert!(current(&vault, &claim)?, "an edit is not an erasure");
    Ok(())
}

/// A continuation that finalizes new words on an already consumed turn brings
/// the turn back: the next scan selects it, and its new final text gets a new
/// extraction attempt. A continuation still in flight changes nothing.
#[cfg(feature = "sync")]
#[test]
fn a_finalized_continuation_brings_its_consumed_turn_back() -> Result<()> {
    let (_dir, vault) = open_vault();
    let (turn, conversation, _, input) = stream_turn(&vault, 0x7b, "call me", "finalize")?;
    let scope = DreamerConsolidationScope::Micro;
    let dirty = |vault: &Vault| scan_dirty_turns(vault, scope, &read_watermark(vault, scope)?, 10);
    let first = queue_micro(&vault)?;
    let [consumed] = <[WorkingSetTurn; 1]>::try_from(dirty(&vault)?).expect("one dirty turn");
    advance_watermark_to_turn(&vault, scope, &consumed)?;
    assert!(dirty(&vault)?.is_empty(), "the round consumed the turn");
    let writer = EntityId::from_bytes([0x7b; 16])?;
    let memory = vault.memory(writer, EdgeActorClass::Human);
    let handle = memory
        .begin_message_stream(&input, Some(crate::memory::MessageWriteMode::Atomic))
        .expect("continuation begins");
    memory.append_to_stream(handle, " Oleksii").expect("append");
    assert!(dirty(&vault)?.is_empty(), "words in flight are not final");
    memory.finalize_stream(handle).expect("finalize");
    let again: Vec<_> = dirty(&vault)?.into_iter().map(|t| t.turn_id).collect();
    assert_eq!(again, vec![turn], "the finalized words re-dirty their turn");
    let second = queue_micro(&vault)?;
    assert_ne!(second, first, "the new final words get their own attempt");
    let branch = BranchResources::open(
        &vault,
        vault.dreamer_authority()?,
        partition_of(conversation),
        &[turn],
        second,
        None,
    )?;
    assert_eq!(
        branch.transcript(branch.scope(), &[turn])?,
        format!("[{} user] call me Oleksii\n", turn.to_hex())
    );
    Ok(())
}

/// A conversation that adopted the DAG keeps its TURN rows append-only. A
/// continuation there still finalizes its new words.
#[cfg(feature = "sync")]
#[test]
fn a_continuation_in_a_dag_conversation_still_finalizes() -> Result<()> {
    let (_dir, vault) = open_vault();
    let (_, conversation, message, input) = stream_turn(&vault, 0x81, "call me", "finalize")?;
    assert!(
        vault.migrate_conversation_dag(&conversation)?,
        "the conversation adopts the DAG"
    );
    end_stream(
        &vault,
        EntityId::from_bytes([0x81; 16])?,
        &input,
        " Oleksii",
        "finalize",
    );
    assert_eq!(content(&vault, &message)?, "call me Oleksii");
    Ok(())
}

/// The projection contract over stored rows, at the branch door: rows sort by
/// `(order, id)` with the id breaking an order tie, an empty visible row keeps
/// its line (so later offsets count its newline), system rows stay out, and a
/// non-system row of another bucket refuses the turn. The witness
/// door refuses order collisions and foreign buckets, and sync refuses every
/// replicated MESSAGE, so these rows are seeded through the test-only
/// canonical-envelope door: the reader holds its contract on any stored row.
#[test]
fn stored_rows_join_by_order_then_id_and_a_foreign_bucket_refuses() -> Result<()> {
    let (_dir, vault) = open_vault();
    let later = WitnessMessage {
        id: Some(EntityId::from_bytes([0x22; 16])?.to_hex()),
        ..message(1, WitnessAuthor::User, "b", true)
    };
    let (turn, conversation) = witness(&vault, 0x7d, vec![later]);
    let writer = EntityId::from_bytes([0x7d; 16])?;
    let seed = |id: EntityId, author: &str, order: u32, is_visible: bool, text: &str| {
        let body = crate::gate::WitnessMessageEnvelope {
            author,
            message_type: "dialogue",
            content: text,
            metadata: None,
            is_visible,
            order,
        }
        .encode_body()?;
        let mut batch = vault
            .batch()
            .put_canonical_message_for_test(&id, occurred(10), 10, &body)
            .edge(&id, EdgeKind::PartOf, &turn, 1.0)
            .edge(&id, EdgeKind::BelongsTo, &conversation, 1.0);
        if author != "system" {
            batch = batch.edge(&id, EdgeKind::AuthoredBy, &writer, 1.0);
        }
        batch.commit()
    };
    seed(EntityId::from_bytes([0x11; 16])?, "user", 1, true, "a")?;
    seed(EntityId::now(), "system", 0, true, "tool output")?;
    seed(EntityId::now(), "user", 0, true, "")?;
    let actor = vault.dreamer_authority()?;
    let open = || {
        BranchResources::open(
            &vault,
            actor,
            partition_of(conversation),
            &[turn],
            AttemptId::now(),
            None,
        )
    };
    let branch = open()?;
    assert_eq!(
        branch.transcript(branch.scope(), &[turn])?,
        format!("[{} user] \na\nb\n", turn.to_hex())
    );
    let at = |start, end| SwarmEvidenceRef {
        source_id: turn,
        claim_id: None,
        byte_range: Some((start, end)),
    };
    let cited = branch.verify_evidence_refs(&[at(1, 2), at(3, 4)])?;
    assert_eq!(
        (cited[0].content_hash, cited[1].content_hash),
        (
            swarm_evidence_content_hash(b"a"),
            swarm_evidence_content_hash(b"b")
        )
    );
    seed(EntityId::now(), "companion", 2, true, "not the speaker")?;
    assert!(open().is_err(), "another speaker's words refuse the turn");
    Ok(())
}

fn branch_gap_rows(
    vault: &Vault,
    partition: &ConsolidationPartitionKey,
    scope: &crate::llm::Scope,
) -> Result<usize> {
    let ScopeResource::Projection { key } =
        super::super::gap::branch_gap_projection(partition, scope)
    else {
        panic!("branch gap identity is a projection")
    };
    let txn = vault.store.env.read_txn()?;
    Ok(vault
        .store
        .vault_meta
        .prefix_iter(&txn, key.as_bytes())?
        .count())
}

/// The branch's contradiction-gap write is fenced like its claim writes. A
/// cited MESSAGE erased, or its grant expired on the clock, after the branch
/// verified the evidence refuses the queue write in its own transaction, and
/// nothing is queued.
#[test]
fn branch_gap_write_refuses_evidence_that_moved_after_the_read() -> Result<()> {
    for case in ["none", "deleted row", "expired grant"] {
        let (_dir, vault, clock) = open_clocked_vault();
        let space = EntityId::now();
        let said = WitnessMessage {
            metadata: Some(serde_json::json!({"rel": space.to_hex()})),
            ..message(0, WitnessAuthor::User, SAID, true)
        };
        let words = id_of(&said);
        let (turn, conversation) = witness(&vault, 0x7b, vec![said]);
        grant_messages(&vault, space, 100)?;
        let partition = partition_of(conversation);
        let branch = BranchResources::open(
            &vault,
            vault.dreamer_authority()?,
            partition,
            &[turn],
            AttemptId::now(),
            None,
        )?;
        let (start, end) = name_range();
        let evidence = super::super::evidence::VerifiedEvidenceSet::verify(
            &branch,
            &[super::super::evidence::EvidenceLocator::turn_range(
                turn, start, end,
            )?],
            ClaimSource::UserStated,
        )?;
        let gap = ReflectionGap {
            kind: ReflectionGapKind::ContradictionLeftStanding,
            subject: EntityId::now(),
            evidence_turn_refs: evidence.refs(),
            evidence_refs: evidence.locators(),
            verified_evidence: Some(evidence.envelope(Vec::new())),
            first_seen: 2_000,
            last_seen: 2_000,
            escalations: 0,
            decayed: false,
        };
        let fence = branch.write_fence();
        match case {
            "deleted row" => delete_message(&vault, words)?,
            "expired grant" => clock.set(200),
            _ => {}
        }
        let written = super::super::gap::upsert_branch_gap_queue(
            &vault,
            branch.scope(),
            &partition,
            &fence,
            vec![gap],
            2_000,
        );
        let rows = branch_gap_rows(&vault, &partition, branch.scope())?;
        if case == "none" {
            assert_eq!(written?.created, 1);
            assert_eq!(rows, 1);
        } else {
            assert!(
                written.is_err(),
                "{case}: the moved evidence refuses the write"
            );
            assert_eq!(rows, 0, "{case}: nothing is queued");
        }
    }
    Ok(())
}

mod history;
mod redirty;
mod support;
