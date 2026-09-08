//! Shared fixtures and helpers for the task_verb tests.

use super::*;

pub(super) fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    (dir, vault)
}

/// Test-side TASK census through the BOUNDED primitive. ONE-1873 removed
/// the unpaged `entities_by_type` call from this file entirely, so nothing
/// here reintroduces the read that hard-fails past 100k rows.
///
/// Authority facts share the TASK type byte (they ARE companion TASK rows, and
/// that is how they replicate), so the census counts TASKS: what these tests
/// ask about is how many tasks a verb minted, never how many rows carry the
/// type. [`task_authority_fact_census`] counts the companions.
pub(super) fn task_entity_census(vault: &Vault) -> usize {
    task_entity_census_by_role(vault, |role| role != Some(TaskRole::AuthorityFact))
}

pub(super) fn task_authority_fact_census(vault: &Vault) -> usize {
    task_entity_census_by_role(vault, |role| role == Some(TaskRole::AuthorityFact))
}

pub(super) fn task_entity_census_by_role(
    vault: &Vault,
    keep: impl Fn(Option<TaskRole>) -> bool,
) -> usize {
    vault
        .entities_by_type_page(ENTITY_TYPE_TASK, None, TASK_PRESENCE_SCAN_CAP)
        .expect("task entities")
        .into_iter()
        .filter(|task_ref| keep(task_entity_role(vault, *task_ref).expect("task role")))
        .count()
}

pub(super) fn put_person(vault: &Vault, id: EntityId) {
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"actor",
        )
        .expect("put actor");
}

pub(super) fn own_agent(vault: &Vault) -> EntityId {
    let actor = EntityId::from_bytes([0xE1; 16]).expect("actor id");
    put_person(vault, actor);
    actor
}

pub(super) fn grant_cancel(vault: &Vault, actor: EntityId, seed: u8) {
    let grant_ref = EntityId::from_bytes([seed; 16]).expect("grant id");
    vault
        .mint_standing_outbound_grant(
            &grant_ref,
            &GrantMintIntent {
                principal_ref: actor.to_hex(),
                origin_component_id: "tasks".to_owned(),
                origin_action_id: "cancel".to_owned(),
                origin_receipt_ref: None,
                scope: GrantMintIntentScope::VerbClass {
                    verb_class: TasksVerb::Cancel.as_str().to_owned(),
                },
            },
            1,
        )
        .expect("mint cancel grant");
}

pub(super) fn spec(now: u64) -> TaskCreateSpec {
    TaskCreateSpec::new(Value::from("unit-task"), None, None, Some(now))
}

pub(super) const CONSULT_NOW: u64 = 1_772_400_000;

pub(super) const CONSULT_DEADLINE: u64 = CONSULT_NOW + 60;

pub(super) fn consult_turn(vault: &Vault, seed: u8) -> ConsultPayloadRef {
    let turn_ref = EntityId::from_bytes([seed; 16]).expect("turn id");
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &Value::Map(vec![(Value::from("role"), Value::from("question"))]),
    )
    .expect("encode turn body");
    vault
        .put_entity(
            &turn_ref,
            ENTITY_TYPE_TURN,
            TimeRange {
                start: CONSULT_NOW,
                end: CONSULT_NOW,
            },
            CONSULT_NOW,
            &body,
        )
        .expect("store durable turn");
    ConsultPayloadRef::parse(vault, &format!("tn_{}", turn_ref.to_hex()))
        .expect("turn parses as a typed consult ref")
}

pub(super) fn consult_peer(vault: &Vault, seed: u8) -> EntityId {
    let actor_ref = EntityId::from_bytes([seed; 16]).expect("peer id");
    put_person(vault, actor_ref);
    actor_ref
}

pub(super) fn consult_spec(
    question: ConsultPayloadRef,
    peer: EntityId,
    deadline_at: u64,
) -> TaskCreateSpec {
    TaskCreateSpec::new(Value::Nil, None, None, Some(CONSULT_NOW))
        .with_kind(TaskKind::Consult)
        .with_consult(ConsultPayload::question(
            question,
            Vec::new(),
            EntityId::now(),
        ))
        .with_assignee(TaskAssignee::Peer { actor_ref: peer })
        .with_ttl(TaskTtl::at(deadline_at))
}

pub(super) fn digest_route() -> ConsultDigestRoute {
    ConsultDigestRoute {
        verb: "send".to_owned(),
        channel: "email".to_owned(),
        target: "owner@example.test".to_owned(),
        on_behalf_of: None,
        recovery: vec![ConsultRecovery::NudgeAssignee],
    }
}

pub(super) fn grant_outbound(vault: &Vault, actor: EntityId, seed: u8) {
    let grant_ref = EntityId::from_bytes([seed; 16]).expect("grant id");
    vault
        .mint_standing_outbound_grant(
            &grant_ref,
            &GrantMintIntent {
                principal_ref: actor.to_hex(),
                origin_component_id: "tasks".to_owned(),
                origin_action_id: "consult.expiry".to_owned(),
                origin_receipt_ref: None,
                scope: GrantMintIntentScope::VerbClass {
                    verb_class: "send".to_owned(),
                },
            },
            CONSULT_NOW,
        )
        .expect("mint outbound grant");
}

/// A consult on its peer's board, ready to answer or expire.
pub(super) fn open_consult(vault: &Vault) -> (EntityId, EntityId, ConsultPayloadRef) {
    let asker = own_agent(vault);
    let peer = consult_peer(vault, 0xE2);
    let question = consult_turn(vault, 0x7A);
    let created = vault
        .memory(asker, EdgeActorClass::Agent)
        .tasks_create(&consult_spec(question, peer, CONSULT_DEADLINE))
        .expect("consult create effects");
    (
        created.task_ref.expect("consult mints one TASK"),
        peer,
        question,
    )
}

pub(super) fn answer_input(
    result_ref: EntityId,
    evidence: ConsultPayloadRef,
) -> ConsultResultInput {
    ConsultResultInput {
        kind: ConsultResultKind::Answer {
            result_ref,
            evidence_refs: vec![evidence],
        },
        completed_at: CONSULT_NOW + 10,
    }
}

pub(super) fn assert_queued_terminal_mix_cancel(
    terminal_state: AttemptState,
    expected_receipt_status: RunTreeStatus,
    expected_board_status: TaskBoardStatus,
) {
    assert!(matches!(
        terminal_state,
        AttemptState::Completed | AttemptState::Failed
    ));
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    grant_cancel(&vault, own, 0xDA);
    let facade = vault.memory(own, EdgeActorClass::Agent);
    let created = facade.tasks_create(&spec(120)).expect("create task");
    let task_ref = created.task_ref.expect("task ref");
    let task_hex = task_ref.to_hex();
    let queue = AttemptQueue::new(&vault);
    let terminal = match queue
        .claim_kind(
            TASK_REALIZE_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: "terminal-mix-worker".to_owned(),
                now: 120,
            },
        )
        .expect("claim terminal realization")
    {
        ClaimOutcome::Claimed(claimed) => claimed,
        ClaimOutcome::Empty => panic!("terminal realization must be claimable"),
    };
    let queued = match queue
        .enqueue_with_task_ref(
            EnqueueAttempt {
                kind: TASK_REALIZE_ATTEMPT_KIND.to_owned(),
                payload: Vec::new(),
                dedupe_key: None,
                run_id: None,
                now: 121,
            },
            Some(task_hex.clone()),
        )
        .expect("enqueue live sibling")
    {
        EnqueueOutcome::Enqueued(queued) => queued,
        EnqueueOutcome::Existing(_) => panic!("live sibling must be fresh"),
    };
    match terminal_state {
        AttemptState::Completed => {
            queue
                .complete(CompleteAttempt {
                    id: terminal.id,
                    lease_owner: "terminal-mix-worker".to_owned(),
                    attempt_count: terminal.attempt_count,
                    now: 122,
                })
                .expect("complete terminal sibling");
        }
        AttemptState::Failed => {
            queue
                .fail(FailAttempt {
                    id: terminal.id,
                    lease_owner: "terminal-mix-worker".to_owned(),
                    attempt_count: terminal.attempt_count,
                    reason: "terminal mix failure".to_owned(),
                    now: 122,
                })
                .expect("fail terminal sibling");
        }
        _ => unreachable!("helper accepts only completed or failed states"),
    }

    let cancel = facade
        .tasks_cancel(TaskCancelTarget::Task(task_ref))
        .expect("cancel live sibling");
    let records = queue.list().expect("list attempts after cancel");
    let terminal_after = queue
        .get(terminal.id)
        .expect("read terminal sibling")
        .expect("terminal sibling exists");
    let queued_after = queue
        .get(queued.id)
        .expect("read cancelled sibling")
        .expect("cancelled sibling exists");
    let section = facade.tasks_check().expect("check mixed task");
    let terminal_hex = attempt_hex(terminal.id);
    let queued_hex = attempt_hex(queued.id);

    assert_eq!(usize::from(cancel.effected), 1);
    assert_eq!(cancel.approval, ClaimApprovalStatus::Auto);
    assert_eq!(usize::from(cancel.proposal_ref.is_some()), 0);
    assert_eq!(cancel.status, Some(expected_receipt_status));
    assert_eq!(terminal_after.state, terminal_state);
    assert_eq!(queued_after.state, AttemptState::Cancelled);
    assert_eq!(
        usize::from(task_is_cancelled(&vault, task_ref).expect("cancel state")),
        0
    );
    assert_eq!(
        records
            .iter()
            .filter(|record| {
                record.task_ref.as_deref() == Some(task_hex.as_str())
                    && record.state == terminal_state
            })
            .count(),
        1
    );
    assert_eq!(
        records
            .iter()
            .filter(|record| {
                record.task_ref.as_deref() == Some(task_hex.as_str())
                    && record.state == AttemptState::Cancelled
            })
            .count(),
        1
    );
    assert_eq!(
        records
            .iter()
            .filter(|record| record.task_ref.as_deref() == Some(task_hex.as_str()))
            .count(),
        2
    );
    assert_eq!(
        section.rows.iter().filter(|row| row.id == task_hex).count(),
        1
    );
    let task_row = section
        .rows
        .iter()
        .find(|row| row.id == task_hex)
        .expect("mixed task row");
    assert_eq!(task_row.status, expected_board_status);
    assert_eq!(task_row.folded_job_count, 1);
    assert_eq!(
        section
            .rows
            .iter()
            .filter(|row| row.id == terminal_hex)
            .count(),
        0
    );
    assert_eq!(
        section
            .rows
            .iter()
            .filter(|row| row.id == queued_hex)
            .count(),
        0
    );
    assert_eq!(section.rows.len(), 1);
}

/// One legal task body, re-stamped with a deadline that had already passed
/// when the row claims to have been learned. Built from a real create so every
/// other field is exactly what the facade writes.
pub(super) fn born_expired_task_body(vault: &Vault, now: u64) -> Vec<u8> {
    let facade = vault.memory(own_agent(vault), EdgeActorClass::Agent);
    let created = facade
        .tasks_create(&spec(now).with_ttl(TaskTtl::at(now + 60)))
        .expect("a future deadline is a task with a TTL");
    let mut body = task_verb_body(vault, created.task_ref.expect("task minted"))
        .expect("decode task")
        .expect("task is typed");
    body.ttl = Some(TaskTtl::at(now - 1));
    encode_task_verb_body(body)
}

/// A terminal record claiming `countered` without naming its counter — the
/// shape the DECODER refuses, built so the admission door can be asked about
/// it.
pub(super) fn incoherent_countered_task_body(vault: &Vault, now: u64) -> Vec<u8> {
    let facade = vault.memory(own_agent(vault), EdgeActorClass::Agent);
    let created = facade.tasks_create(&spec(now)).expect("a plain task mints");
    let mut body = task_verb_body(vault, created.task_ref.expect("task minted"))
        .expect("decode task")
        .expect("task is typed");
    body.state = Some(TaskExecutionState::Terminal(TaskTerminalRecord {
        disposition: TaskTerminalDisposition::Completed,
        result_ref: None,
        summary: None,
        finished_at: now,
        ladder: Some(LadderTerminalDisposition::Countered),
        counter_task_ref: None,
    }));
    encode_task_verb_body(body)
}

/// One OPEN `tasks.create` proposal ABOUT `subject`, produced by `producer` —
/// the shape a generic claim writer or a replicated peer leaves behind on an
/// actor it does not speak for.
pub(super) fn put_foreign_create_proposal(
    vault: &Vault,
    subject: EntityId,
    producer: EntityId,
    spec: &TaskCreateSpec,
    now: u64,
) -> EntityId {
    let claim_ref = ladder_id(0xC8);
    let envelope = WriteEnvelope::new(
        WriteActor::new(producer, EdgeActorClass::Agent),
        ClaimSource::Observed,
        WriteProvenance::new(agent_provenance()).expect("provenance is not nil"),
        ClaimApprovalStatus::Proposed,
    );
    let candidate = EnvelopeClaimCandidate::new(
        TASK_CREATE_PROPOSAL_PREDICATE,
        ClaimSubject::Entity(subject),
        task_create_proposal_value(spec, now),
        1.0,
    );
    vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .claim_candidate(
                    &claim_ref,
                    candidate.clone(),
                    &envelope,
                    TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                )
                .apply(wtxn)
        })
        .expect("the foreign proposal lands");
    claim_ref
}

/// One past the edge-materialization ceiling of inbound `ClaimOf` edges on
/// `subject`. Seeded as raw edge records, the way the neighbors regression
/// seeds a high-degree node: the scan cap is what is under test, not a hundred
/// thousand claim bodies.
pub(super) fn seed_capped_inbound_claim_edges(vault: &Vault, subject: EntityId) {
    let mut value = [0u8; 12];
    value[0..4].copy_from_slice(&0.9_f32.to_le_bytes());
    value[4..12].copy_from_slice(&1_u64.to_le_bytes());
    vault
        .with_write_txn(|wtxn| {
            for index in 0..=crate::vault::MAX_EDGE_QUERY_RESULTS {
                let mut bytes = [0u8; 16];
                bytes[..8].copy_from_slice(&(index as u64 + 1).to_le_bytes());
                bytes[15] = 0xC9;
                let peer = EntityId::from_bytes(bytes).expect("seeded id is never reserved");
                let key = crate::store::Store::encode_edge_key(
                    &subject,
                    crate::edge::EdgeKind::ClaimOf,
                    &peer,
                );
                vault.store.edges_in.put(wtxn, &key, &value)?;
            }
            Ok(())
        })
        .expect("seed a high-degree claim subject");
}

/// Open (`Active` + `Proposed`) `tasks.create` proposal rows parked against
/// one actor.
pub(super) fn open_create_proposal_census(vault: &Vault, actor: EntityId) -> usize {
    vault
        .claims_for_subject(&actor)
        .expect("claims for actor")
        .into_iter()
        .filter(|id| {
            vault
                .get_claim(id)
                .expect("claim body")
                .is_some_and(|body| {
                    body.predicate == TASK_CREATE_PROPOSAL_PREDICATE
                        && body.lifecycle == ClaimLifecycleStatus::Active
                        && body.approval == ClaimApprovalStatus::Proposed
                })
        })
        .count()
}

pub(super) const LADDER_NOW: u64 = CONSULT_NOW;

pub(super) const LADDER_DEADLINE: u64 = CONSULT_NOW + 3_600;

/// The default policy manifest gives `agent` an auto ceiling for exactly
/// one actor ref, and `own_agent` is it — so every acting facade in these
/// tests is that actor and the OWNERSHIP under test varies instead.
pub(super) const OTHER_ACTOR_SEED: u8 = 0xE3;

pub(super) fn ladder_id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("ladder test id")
}

/// A second human actor: the owner of the state an agent wants to change.
pub(super) fn other_actor(vault: &Vault) -> EntityId {
    let actor = ladder_id(OTHER_ACTOR_SEED);
    put_person(vault, actor);
    actor
}

/// Writes one CLAIM through the normal envelope-stamped door so its
/// authoring actor and run surface are recoverable exactly as production
/// writes them.
pub(super) fn put_envelope_claim(
    vault: &Vault,
    claim_ref: EntityId,
    subject: EntityId,
    actor: EntityId,
    actor_class: EdgeActorClass,
    provenance: Value,
) {
    put_envelope_claim_citing(
        vault,
        claim_ref,
        subject,
        actor,
        actor_class,
        provenance,
        None,
    );
}

/// `put_envelope_claim`, optionally citing one already-seeded entity as
/// candidate evidence.
///
/// A write stamped with the Dreamer run surface is Dreamer-AUTHORED whatever
/// its evidence source, so it clears the GATE-12 evidence floor like every
/// other Dreamer write. The magistrate fixtures below mean their
/// Dreamer-surface writes, so they cite real evidence rather than dodging the
/// detector by rewriting their provenance, source or actor class.
pub(super) fn put_envelope_claim_citing(
    vault: &Vault,
    claim_ref: EntityId,
    subject: EntityId,
    actor: EntityId,
    actor_class: EdgeActorClass,
    provenance: Value,
    cited: Option<EntityId>,
) {
    let envelope = WriteEnvelope::new(
        WriteActor::new(actor, actor_class),
        ClaimSource::Observed,
        WriteProvenance::new(provenance).expect("provenance is not nil"),
        ClaimApprovalStatus::Proposed,
    );
    let mut candidate = EnvelopeClaimCandidate::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        Value::from("state"),
        1.0,
    );
    if let Some(cited) = cited {
        candidate = candidate.with_evidence(cited_candidate_evidence(cited));
    }
    vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .claim_candidate(
                    &claim_ref,
                    candidate.clone(),
                    &envelope,
                    TimeRange {
                        start: LADDER_NOW,
                        end: LADDER_NOW,
                    },
                    LADDER_NOW,
                )
                .apply(wtxn)
        })
        .expect("claim write lands");
}

/// The consolidation evidence envelope the GATE-12 floor reads, citing one
/// entity the caller has already seeded.
pub(super) fn cited_candidate_evidence(cited: EntityId) -> Value {
    crate::dreamer_consolidation::encode_consolidation_evidence(
        &crate::dreamer_consolidation::ConsolidationEvidenceEnvelope {
            refs: vec![cited],
            chain: Vec::new(),
            source_meet: ClaimSource::Observed,
        },
    )
}

pub(super) fn dreamer_provenance() -> Value {
    Value::Map(vec![
        (
            Value::from("surface"),
            Value::from(DREAMER_RUNNER_ATTEMPT_KIND),
        ),
        (Value::from("run"), Value::from("run-1")),
    ])
}

pub(super) fn agent_provenance() -> Value {
    Value::Map(vec![
        (Value::from("surface"), Value::from("agent.dispatch")),
        (Value::from("run"), Value::from("run-2")),
    ])
}

/// One CLAIM owned by `owner` — the cross-actor target under test.
pub(super) fn owned_claim(
    vault: &Vault,
    seed: u8,
    owner: EntityId,
    actor_class: EdgeActorClass,
) -> EntityId {
    let claim_ref = ladder_id(seed);
    put_envelope_claim(
        vault,
        claim_ref,
        owner,
        owner,
        actor_class,
        agent_provenance(),
    );
    claim_ref
}

pub(super) fn ladder_shape() -> EntityDeltaShape {
    EntityDeltaShape {
        operation_kind: "claim.replace".to_owned(),
        target_entity_type: ENTITY_TYPE_CLAIM,
        normalized_paths: vec!["profile.note".to_owned()],
    }
}

pub(super) fn ladder_delta(
    target_ref: EntityId,
    delta_ref: EntityId,
    proposer: EntityId,
    owner: EntityId,
) -> EntityDeltaArtifact {
    EntityDeltaArtifact {
        target_ref,
        base_state_ref: None,
        delta_ref,
        shape: ladder_shape(),
        proposer_actor_ref: proposer,
        owning_actor_ref: owner,
        message_thread_ref: None,
    }
}

pub(super) struct AlwaysGraduated;

impl GraduationLookup for AlwaysGraduated {
    fn scope_is_graduated(&self, _scope: &GraduationScope) -> std::result::Result<bool, String> {
        Ok(true)
    }

    fn shape_was_approved(
        &self,
        _scope: &GraduationScope,
        _fingerprint: DeltaShapeFingerprint,
    ) -> std::result::Result<bool, String> {
        Ok(true)
    }
}

pub(super) fn ladder_scope(proposer: EntityId, owner: EntityId) -> GraduationScope {
    GraduationScope {
        proposer_actor_ref: proposer,
        owning_actor_ref: owner,
        operation_kind: "claim.replace".to_owned(),
        target_entity_type: ENTITY_TYPE_CLAIM,
        skill_or_agent_ref: None,
        standing_grant_ref: ladder_id(0xB1),
    }
}

/// The whole cross-actor fixture: the acting agent, the state's owner, the
/// owned CLAIM target, and a durable delta artifact.
pub(super) struct CrossActorFixture {
    pub(super) proposer: EntityId,
    pub(super) owner: EntityId,
    pub(super) target: EntityId,
    pub(super) delta_ref: EntityId,
}

pub(super) fn cross_actor_fixture(vault: &Vault) -> CrossActorFixture {
    let proposer = own_agent(vault);
    let owner = other_actor(vault);
    let target = owned_claim(vault, 0xB4, owner, EdgeActorClass::Human);
    let delta_ref = consult_turn(vault, 0x7B).entity_ref();
    CrossActorFixture {
        proposer,
        owner,
        target,
        delta_ref,
    }
}

/// Seeds one consult's persisted state to the projection of `state` so the
/// CAS has a ladder row to move.
pub(super) fn seed_ladder_state(vault: &Vault, task_ref: EntityId, state: &ConsultLadderState) {
    vault
        .with_write_txn(|wtxn| {
            let mut body = task_verb_body_in(vault, &*wtxn, task_ref)?.expect("consult is typed");
            body.state = Some(project_consult_ladder_state(state));
            let encoded = encode_task_verb_body(body);
            vault
                .batch_in()
                .put(
                    &task_ref,
                    ENTITY_TYPE_TASK,
                    TimeRange {
                        start: LADDER_NOW,
                        end: LADDER_NOW,
                    },
                    LADDER_NOW,
                    &encoded,
                )
                .apply(wtxn)
        })
        .expect("seed the ladder projection");
}

/// Escalates one open consult through the real ladder door, leaving its TASK
/// row live with the settled ladder riding inside the interrupted register.
pub(super) fn escalate_consult(
    vault: &Vault,
    task_ref: EntityId,
    result_ref: EntityId,
    finished_at: u64,
) -> LadderTerminalState {
    let working = ConsultLadderState::Working(WorkingState {
        started_at: LADDER_NOW,
        decision_round: 0,
    });
    seed_ladder_state(vault, task_ref, &working);
    let escalated = LadderTerminalState {
        disposition: LadderTerminalDisposition::Escalated,
        result_ref,
        counter_task_ref: None,
        finished_at,
    };
    vault
        .memory(own_agent(vault), EdgeActorClass::Agent)
        .compare_and_set_consult_ladder(task_ref, &working, LadderTransition::Finish(escalated))
        .expect("a working ladder may escalate");
    escalated
}

pub(super) fn magistrate_case(
    state_ref: EntityId,
    delta_ref: EntityId,
    criticality: CaseCriticality,
) -> MagistrateCase {
    MagistrateCase {
        task_ref: ladder_id(0x91),
        contested_state_ref: state_ref,
        contested_delta_ref: delta_ref,
        criticality,
        policy: vec![PolicyEvidence {
            policy_ref: ladder_id(0x92),
            selected_delta_ref: Some(delta_ref),
        }],
        authority: vec![AuthorityEvidence {
            authoritative_actor_ref: ladder_id(0x93),
            state_ref,
            selected_delta_ref: Some(delta_ref),
        }],
        temporal: Vec::new(),
        candidate_delta_refs: vec![delta_ref],
        dreamer_attempt_ref: None,
        now: LADDER_NOW,
    }
}

pub(super) fn open_conflict_count(vault: &Vault) -> usize {
    vault
        .entities_by_type(ENTITY_TYPE_CLAIM)
        .expect("claim census")
        .into_iter()
        .filter_map(|claim_ref| vault.get_claim(&claim_ref).ok().flatten())
        .filter(|body| body.predicate == PREDICATE_CONFLICT_OPEN)
        .count()
}

pub(super) const ROUTE_NOW: u64 = 1_772_500_000;

/// Every generic ONE-1700 fixture identity routes through the canonical
/// band assertion, so a fixture can never alias a production-pinned system
/// identity (`0xD7` is the default policy manifest — a seed collision there
/// surfaces as a bewildering entity-type error deep inside an unrelated
/// write). `crate::test_util::entity` owns the pinned list; this is the
/// seed-shaped adapter onto the ONE-1699 fixture helpers, not a second copy
/// of the rule.
pub(super) fn route_seed(seed: u8) -> u8 {
    crate::test_util::entity(seed);
    seed
}

pub(super) fn route_peer(vault: &Vault, seed: u8) -> EntityId {
    consult_peer(vault, route_seed(seed))
}

pub(super) fn route_turn(vault: &Vault, seed: u8) -> ConsultPayloadRef {
    consult_turn(vault, route_seed(seed))
}

pub(super) fn route_dangling(seed: u8) -> EntityId {
    crate::test_util::entity(seed)
}

/// A dispatchable AGENT_DEF row: an ordinary fork of a seeded row, which is
/// the only way to get an Active+approved+enabled definition without
/// hand-rolling a body the validator would reject.
pub(super) fn routable_agent_def(vault: &Vault, seed: u8) -> EntityId {
    let def_ref = crate::test_util::entity(seed);
    let (base_id, base) = vault
        .get_seeded_agent_definition_by_logical_id("sys.keeper")
        .expect("resolve seeded keeper")
        .expect("seeded keeper exists");
    let mut fork = base.clone();
    fork.agent_id = format!("route-worker-{seed:02x}");
    fork.version = "1".to_owned();
    fork.forked_from = Some(base_id);
    fork.ceiling = base.ceiling;
    fork.logical_id = None;
    fork.display_name = None;
    fork.source = ClaimSource::UserStated;
    fork.provenance = Value::Map(vec![(Value::from("forkOf"), Value::from(base_id.to_hex()))]);
    vault
        .put_agent_definition(&def_ref, &fork, TimeRange { start: 1, end: 1 }, 1)
        .expect("store routable agent definition");
    def_ref
}

pub(super) fn attempts_for(vault: &Vault, task_ref: EntityId) -> Vec<AttemptRecord> {
    let task_hex = task_ref.to_hex();
    AttemptQueue::new(vault)
        .list()
        .expect("list attempts")
        .into_iter()
        .filter(|record| record.task_ref.as_deref() == Some(task_hex.as_str()))
        .collect()
}

pub(super) fn route_spec(assignee: Option<TaskAssignee>) -> TaskCreateSpec {
    let base = TaskCreateSpec::new(Value::from("routed-task"), None, None, Some(ROUTE_NOW));
    match assignee {
        Some(assignee) => base.with_assignee(assignee),
        None => base,
    }
}

/// A synthetic type-index id. Big-endian bytes order numerically exactly
/// as `EntityId`'s byte order does, so index order IS type-index order.
pub(super) fn synthetic_task_id(index: u128) -> EntityId {
    EntityId::from_bytes(index.to_be_bytes()).expect("synthetic id from 16 bytes")
}

pub(super) fn synthetic_index(id: &EntityId) -> u128 {
    u128::from_be_bytes(*id.as_bytes())
}

/// A pager over `1..=rows` that answers the exclusive `after` cursor the
/// way `Vault::entities_by_type_page` does, without holding the rows.
pub(super) fn synthetic_pager(
    rows: u128,
    fetched: &mut usize,
) -> impl FnMut(Option<&EntityId>, usize) -> Result<Vec<EntityId>> + '_ {
    move |after, limit| {
        let start = after.map_or(1, |id| synthetic_index(id) + 1);
        let page: Vec<EntityId> = (start..=rows).take(limit).map(synthetic_task_id).collect();
        *fetched += page.len();
        Ok(page)
    }
}

pub(super) fn created_task_refs(facade: &Memory<'_>, count: usize) -> Vec<EntityId> {
    let mut refs: Vec<EntityId> = (0..count)
        .map(|index| {
            facade
                .tasks_create(&spec(120 + index as u64))
                .expect("create task")
                .task_ref
                .expect("task ref")
        })
        .collect();
    // Type-index order is EntityId byte order; sorting names the same
    // prefix the bounded scan will walk.
    refs.sort_unstable();
    refs
}

/// Claims the next realizing job of a freshly created TASK.
pub(super) fn claim_realization(
    queue: &AttemptQueue<'_>,
    lease_owner: &str,
    now: u64,
) -> AttemptRecord {
    match queue
        .claim_kind(
            TASK_REALIZE_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: lease_owner.to_owned(),
                now,
            },
        )
        .expect("claim realization")
    {
        ClaimOutcome::Claimed(claimed) => claimed,
        ClaimOutcome::Empty => panic!("a realization must be claimable"),
    }
}

pub(super) fn enqueue_sibling(queue: &AttemptQueue<'_>, task_hex: &str, now: u64) -> AttemptRecord {
    match queue
        .enqueue_with_task_ref(
            EnqueueAttempt {
                kind: TASK_REALIZE_ATTEMPT_KIND.to_owned(),
                payload: Vec::new(),
                dedupe_key: None,
                run_id: None,
                now,
            },
            Some(task_hex.to_owned()),
        )
        .expect("enqueue sibling")
    {
        EnqueueOutcome::Enqueued(record) => record,
        EnqueueOutcome::Existing(_) => panic!("a sibling must be fresh"),
    }
}
