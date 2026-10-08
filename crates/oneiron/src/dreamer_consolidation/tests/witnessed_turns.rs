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
                assert!(vault.delete_edge(&cited, EdgeKind::AuthoredBy, &writer)?);
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
