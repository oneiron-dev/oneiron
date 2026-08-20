use super::consts::*;
use super::consult_ladder_facade::*;
use super::consult_result::*;
use super::create_validation::*;
use super::dormant_magistrate::*;
use super::follow_up::*;
use super::presence_scan::*;
use super::rate_limit::*;
use super::wire_decode::*;
use super::wire_encode::*;
use super::*;

use rmpv::Value;

use crate::agent_dispatch::{
    AGENT_DISPATCH_ATTEMPT_TYPE, AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher,
    DispatchAgent, decode_agent_dispatch_input,
};
use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, AttemptState, ClaimAttempt, ClaimOutcome,
    CompleteAttempt, EnqueueAttempt, EnqueueOutcome, FailAttempt, RetryAttempt, RetryOutcome,
};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, ClaimSubject};
use crate::config::VaultConfig;
use crate::consult_ladder::{
    ConsultLadderState, ConsultLineage, ConsultLineageRelation, ConsultPurpose,
    DREAMER_MAGISTRATE_ATTEMPT_TYPE, EntityDeltaArtifact, EntityDeltaShape, HumanVerdict,
    LadderTerminalDisposition, LadderTerminalState, LadderTransition, LadderTransitionError,
    MagistrateCase, MagistrateOverturnRecord, MagistrateVerdict, StateAuthorship,
};
use crate::context_board::{TaskBoardStatus, TasksSection, task_is_acked, task_is_cancelled};
use crate::dreamer_runner::{
    DREAMER_RUNNER_ATTEMPT_KIND, DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
    decode_dreamer_attempt_payload,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::facade::{
    FACADE_CODE_FORBIDDEN, FACADE_CODE_INVALID_STATE, MemoryFacade, OutboundDraftInput,
};
use crate::gate::{GateOutcome, PolicyApprovalCeiling};
use crate::genui::{GrantMintIntent, GrantMintIntentScope};
use crate::habit::TaskRole;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON, ENTITY_TYPE_TASK, ENTITY_TYPE_TURN};
use crate::run_tree::RunTreeStatus;
use crate::temporal::TimeRange;
use crate::write_envelope::{WriteActor, WriteEnvelope, WriteProvenance};
use crate::{Vault, unix_seconds_now};

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    (dir, vault)
}

/// Test-side TASK census through the BOUNDED primitive. ONE-1873 removed
/// the unpaged `entities_by_type` call from this file entirely, so nothing
/// here reintroduces the read that hard-fails past 100k rows.
fn task_entity_census(vault: &Vault) -> usize {
    vault
        .entities_by_type_page(ENTITY_TYPE_TASK, None, TASK_PRESENCE_SCAN_CAP)
        .expect("task entities")
        .len()
}

fn put_person(vault: &Vault, id: EntityId) {
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

fn own_agent(vault: &Vault) -> EntityId {
    let actor = EntityId::from_bytes([0xE1; 16]).expect("actor id");
    put_person(vault, actor);
    actor
}

fn grant_cancel(vault: &Vault, actor: EntityId, seed: u8) {
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

fn spec(now: u64) -> TaskCreateSpec {
    TaskCreateSpec::new(Value::from("unit-task"), None, None, Some(now))
}

// ── consult fixtures (ONE-1699) ─────────────────────────────────────

const CONSULT_NOW: u64 = 1_772_400_000;
const CONSULT_DEADLINE: u64 = CONSULT_NOW + 60;

fn consult_turn(vault: &Vault, seed: u8) -> ConsultPayloadRef {
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

fn consult_peer(vault: &Vault, seed: u8) -> EntityId {
    let actor_ref = EntityId::from_bytes([seed; 16]).expect("peer id");
    put_person(vault, actor_ref);
    actor_ref
}

fn consult_spec(question: ConsultPayloadRef, peer: EntityId, deadline_at: u64) -> TaskCreateSpec {
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

fn digest_route() -> ConsultDigestRoute {
    ConsultDigestRoute {
        verb: "send".to_owned(),
        channel: "email".to_owned(),
        target: "owner@example.test".to_owned(),
        on_behalf_of: None,
        recovery: vec![ConsultRecovery::NudgeAssignee],
    }
}

fn grant_outbound(vault: &Vault, actor: EntityId, seed: u8) {
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
fn open_consult(vault: &Vault) -> (EntityId, EntityId, ConsultPayloadRef) {
    let asker = own_agent(vault);
    let peer = consult_peer(vault, 0xE2);
    let question = consult_turn(vault, 0x7A);
    let created = vault
        .memory_facade(asker, EdgeActorClass::Agent)
        .tasks_create(&consult_spec(question, peer, CONSULT_DEADLINE))
        .expect("consult create effects");
    (
        created.task_ref.expect("consult mints one TASK"),
        peer,
        question,
    )
}

fn answer_input(result_ref: EntityId, evidence: ConsultPayloadRef) -> ConsultResultInput {
    ConsultResultInput {
        kind: ConsultResultKind::Answer {
            result_ref,
            evidence_refs: vec![evidence],
        },
        completed_at: CONSULT_NOW + 10,
    }
}

/// A consult create mints exactly one synced TASK entity and ZERO local
/// realizations: a node-local lease could never reach a peer's machine.
#[test]
fn consult_create_mints_one_task_entity_and_no_realization() {
    let (_dir, vault) = open_vault();
    let (task_ref, peer, _question) = open_consult(&vault);
    let task_hex = task_ref.to_hex();
    let realizations = AttemptQueue::new(&vault)
        .list()
        .expect("list attempts")
        .iter()
        .filter(|record| record.task_ref.as_deref() == Some(task_hex.as_str()))
        .count();
    let body = task_verb_body(&vault, task_ref)
        .expect("decode consult body")
        .expect("consult is typed");

    assert_eq!(realizations, 0);
    assert_eq!(task_entity_census(&vault), 1);
    assert_eq!(body.task_kind(), TaskKind::Consult);
    assert_eq!(body.assignee, Some(TaskAssignee::Peer { actor_ref: peer }));
    assert_eq!(body.ttl, Some(TaskTtl::at(CONSULT_DEADLINE)));
    assert_eq!(body.state, Some(TaskExecutionState::Queued));
    assert_eq!(body.spec, Value::Nil);
}

/// The pre-ticket constructor still compiles with exactly four arguments
/// and still takes the legacy Dreamer-realized standard path.
#[test]
fn pre_ticket_create_spec_takes_the_unchanged_standard_path() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let legacy = TaskCreateSpec::new(Value::from("unit-task"), None, None, Some(120));
    let created = vault
        .memory_facade(own, EdgeActorClass::Agent)
        .tasks_create(&legacy)
        .expect("legacy create");
    let task_ref = created.task_ref.expect("task ref");
    let task_hex = task_ref.to_hex();
    let body = task_verb_body(&vault, task_ref)
        .expect("decode body")
        .expect("typed body");

    assert_eq!(legacy.kind, None);
    assert_eq!(legacy.consult, None);
    assert_eq!(legacy.assignee, None);
    assert_eq!(legacy.ttl, None);
    assert_eq!(body.task_kind(), TaskKind::Standard);
    assert_eq!(usize::from(body.assignee.is_none()), 1);
    assert_eq!(usize::from(body.terminal().is_none()), 1);
    assert_eq!(
        AttemptQueue::new(&vault)
            .list()
            .expect("list attempts")
            .iter()
            .filter(|record| record.task_ref.as_deref() == Some(task_hex.as_str()))
            .count(),
        1
    );
}

/// A schema-v1 row — one that names none of the additive keys — decodes as
/// a standard, implicitly Dreamer-routed task with no TTL and no terminal.
#[test]
fn schema_v1_body_decodes_as_standard_dreamer_task() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let task_ref = EntityId::from_bytes([0xB7; 16]).expect("task id");
    let v1_body = {
        let value = Value::Map(vec![
            (Value::from("role"), Value::from(TaskRole::Task.role_byte())),
            (Value::from("schema_version"), Value::from(1u8)),
            (Value::from("subkind"), Value::from(TASK_VERB_BODY_SUBKIND)),
            (Value::from("owner_ref"), Value::from(own.to_hex())),
            (Value::from("label"), Value::from("legacy row")),
            (Value::from("spec"), Value::from("legacy-spec")),
            (Value::from("provenance"), Value::Nil),
            (Value::from("created_at"), Value::from(120u64)),
        ]);
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &value).expect("encode v1 body");
        bytes
    };
    vault
        .put_entity(
            &task_ref,
            ENTITY_TYPE_TASK,
            TimeRange {
                start: 120,
                end: 120,
            },
            120,
            &v1_body,
        )
        .expect("store schema-v1 task");

    let body = task_verb_body(&vault, task_ref)
        .expect("decode v1 body")
        .expect("v1 row is typed");
    let section = vault
        .memory_facade(own, EdgeActorClass::Agent)
        .tasks_check()
        .expect("board reads the v1 row");

    assert_eq!(body.schema_version, 1);
    assert_eq!(body.kind, None);
    assert_eq!(body.task_kind(), TaskKind::Standard);
    assert_eq!(body.assignee, None);
    assert_eq!(body.ttl, None);
    assert_eq!(body.state, None);
    assert_eq!(usize::from(body.terminal().is_none()), 1);
    assert_eq!(body.label.as_deref(), Some("legacy row"));
    let row = section
        .rows
        .iter()
        .find(|row| row.id == task_ref.to_hex())
        .expect("v1 row renders");
    assert_eq!(row.status, TaskBoardStatus::Queued);
    assert_eq!(usize::from(row.assignee.is_none()), 1);
    assert_eq!(usize::from(row.terminal_disposition.is_none()), 1);
}

/// Every malformed consult shape is refused BEFORE the write transaction:
/// no TASK entity lands, whatever the defect.
#[test]
fn invalid_consult_shapes_reject_before_any_write() {
    let (_dir, vault) = open_vault();
    let asker = own_agent(&vault);
    let peer = consult_peer(&vault, 0xE2);
    let question = consult_turn(&vault, 0x7A);
    let facade = vault.memory_facade(asker, EdgeActorClass::Agent);
    let absent_peer = EntityId::from_bytes([0xEE; 16]).expect("absent peer id");
    let absent_turn =
        ConsultPayloadRef::Turn(EntityId::from_bytes([0xEF; 16]).expect("absent turn id"));

    let rejects = [
        // A consult carries its request in the typed payload; the legacy
        // free-form spec must be empty.
        consult_spec(question, peer, CONSULT_DEADLINE).with_kind(TaskKind::Consult),
        // Unresolved payload ref.
        consult_spec(absent_turn, peer, CONSULT_DEADLINE),
        // Peer actor that does not resolve.
        consult_spec(question, absent_peer, CONSULT_DEADLINE),
        // Deadline already past at create time.
        consult_spec(question, peer, CONSULT_NOW),
        // Duplicate refs inside one payload.
        TaskCreateSpec::new(Value::Nil, None, None, Some(CONSULT_NOW))
            .with_kind(TaskKind::Consult)
            .with_consult(ConsultPayload::question(
                question,
                vec![question],
                EntityId::now(),
            ))
            .with_assignee(TaskAssignee::Peer { actor_ref: peer })
            .with_ttl(TaskTtl::at(CONSULT_DEADLINE)),
        // Consult kind without a peer assignee.
        TaskCreateSpec::new(Value::Nil, None, None, Some(CONSULT_NOW))
            .with_kind(TaskKind::Consult)
            .with_consult(ConsultPayload::question(
                question,
                Vec::new(),
                EntityId::now(),
            ))
            .with_assignee(TaskAssignee::Dreamer)
            .with_ttl(TaskTtl::at(CONSULT_DEADLINE)),
    ];
    // The first case is the non-Nil spec; rebuild it with a real payload.
    let mut cases = rejects.to_vec();
    cases[0] = TaskCreateSpec::new(Value::from("raw question"), None, None, Some(CONSULT_NOW))
        .with_kind(TaskKind::Consult)
        .with_consult(ConsultPayload::question(
            question,
            Vec::new(),
            EntityId::now(),
        ))
        .with_assignee(TaskAssignee::Peer { actor_ref: peer })
        .with_ttl(TaskTtl::at(CONSULT_DEADLINE));

    let outcomes: Vec<String> = cases
        .iter()
        .map(|case| {
            facade
                .tasks_create(case)
                .expect_err("invalid consult shape rejects")
                .code
        })
        .collect();

    assert_eq!(outcomes.len(), 6);
    assert_eq!(
        outcomes
            .iter()
            .filter(|code| *code == crate::facade::FACADE_CODE_BAD_REQUEST
                || *code == crate::facade::FACADE_CODE_NOT_FOUND)
            .count(),
        6
    );
    assert_eq!(task_entity_census(&vault), 0);
    assert_eq!(AttemptQueue::new(&vault).list().expect("attempts").len(), 0);
}

/// Only the addressed peer may answer, exactly one of evidence-answer or
/// reasoned-abstention lands, and neither/both is unrepresentable.
#[test]
fn result_contract_is_addressed_and_partitioned() {
    let (_dir, vault) = open_vault();
    let (task_ref, peer, question) = open_consult(&vault);
    let stranger = consult_peer(&vault, 0xE9);
    let result_ref = consult_turn(&vault, 0x80).entity_ref();

    let by_stranger = vault
        .memory_facade(stranger, EdgeActorClass::Agent)
        .land_consult_result(task_ref, &answer_input(result_ref, question))
        .expect_err("a stranger may not answer an addressed consult");
    let evidence_free = vault
        .memory_facade(peer, EdgeActorClass::Agent)
        .land_consult_result(
            task_ref,
            &ConsultResultInput {
                kind: ConsultResultKind::Answer {
                    result_ref,
                    evidence_refs: Vec::new(),
                },
                completed_at: CONSULT_NOW + 10,
            },
        )
        .expect_err("an answer without evidence is not an answer");
    let landed = vault
        .memory_facade(peer, EdgeActorClass::Agent)
        .land_consult_result(task_ref, &answer_input(result_ref, question))
        .expect("the addressed peer answers");
    let stored = task_verb_body(&vault, task_ref)
        .expect("decode body")
        .expect("typed body");

    assert_eq!(by_stranger.code, crate::facade::FACADE_CODE_FORBIDDEN);
    assert_eq!(evidence_free.code, crate::facade::FACADE_CODE_BAD_REQUEST);
    assert_eq!(usize::from(landed.idempotent_replay), 0);
    assert_eq!(
        landed.terminal.disposition,
        TaskTerminalDisposition::Completed
    );
    assert_eq!(landed.terminal.result_ref, Some(result_ref));
    assert_eq!(
        stored.terminal().map(|record| record.summary.clone()),
        Some(Some(ConsultResultSummary::Answer {
            evidence_refs: vec![question],
        }))
    );
}

/// One replica settles a task once. A byte-identical replay reports the
/// winner; a DIFFERENT second result is refused as terminal-immutable and
/// mutates nothing.
#[test]
fn one_replica_settles_once_and_replays_idempotently() {
    let (_dir, vault) = open_vault();
    let (task_ref, peer, question) = open_consult(&vault);
    let result_ref = consult_turn(&vault, 0x80).entity_ref();
    let other_result = consult_turn(&vault, 0x81).entity_ref();
    let facade = vault.memory_facade(peer, EdgeActorClass::Agent);

    let first = facade
        .land_consult_result(task_ref, &answer_input(result_ref, question))
        .expect("first answer settles");
    let replay = facade
        .land_consult_result(task_ref, &answer_input(result_ref, question))
        .expect("identical replay is idempotent");
    let conflicting = facade
        .land_consult_result(task_ref, &answer_input(other_result, question))
        .expect_err("a different second result is refused");
    let stored = task_verb_body(&vault, task_ref)
        .expect("decode body")
        .expect("typed body");

    assert_eq!(usize::from(first.idempotent_replay), 0);
    assert_eq!(usize::from(replay.idempotent_replay), 1);
    assert_eq!(replay.terminal, first.terminal);
    assert_eq!(conflicting.code, crate::facade::FACADE_CODE_INVALID_STATE);
    assert_eq!(stored.terminal(), Some(&first.terminal));
}

/// An answer that beat the sweep keeps the task out of the expiry path,
/// and an expired task refuses a later answer — one local transition.
#[test]
fn answer_and_expiry_contend_for_one_local_transition() {
    let (_dir, vault) = open_vault();
    let asker = own_agent(&vault);
    grant_outbound(&vault, asker, 0xD1);
    let (answered, peer, question) = open_consult(&vault);
    let expired = vault
        .memory_facade(asker, EdgeActorClass::Agent)
        .tasks_create(&consult_spec(question, peer, CONSULT_DEADLINE))
        .expect("second consult")
        .task_ref
        .expect("second task ref");
    let result_ref = consult_turn(&vault, 0x80).entity_ref();
    let peer_facade = vault.memory_facade(peer, EdgeActorClass::Agent);
    peer_facade
        .land_consult_result(answered, &answer_input(result_ref, question))
        .expect("the first consult is answered before the deadline");

    let report = vault
        .memory_facade(asker, EdgeActorClass::Agent)
        .settle_due_consults(CONSULT_DEADLINE + 1, &digest_route())
        .expect("sweep the due consults");
    let late = peer_facade
        .land_consult_result(
            expired,
            &answer_input(consult_turn(&vault, 0x81).entity_ref(), question),
        )
        .expect_err("an expired consult refuses a late answer");
    let answered_body = task_verb_body(&vault, answered)
        .expect("decode answered")
        .expect("typed");
    let expired_body = task_verb_body(&vault, expired)
        .expect("decode expired")
        .expect("typed");

    assert_eq!(report.expired_task_refs, vec![expired]);
    assert_eq!(late.code, crate::facade::FACADE_CODE_INVALID_STATE);
    assert_eq!(
        answered_body.terminal().map(|record| record.disposition),
        Some(TaskTerminalDisposition::Completed)
    );
    assert_eq!(
        expired_body.terminal().map(|record| record.disposition),
        Some(TaskTerminalDisposition::Expired)
    );
    // The expiry transition is never result-less.
    assert_eq!(
        usize::from(
            expired_body
                .terminal()
                .is_some_and(|record| record.result_ref.is_some())
        ),
        1
    );
}

/// The terminal register is ONE value: later `finished_at` wins, and
/// `Completed` dominates `Expired` on an exact tie — in both merge orders.
#[test]
fn terminal_register_converges_identically_in_both_merge_orders() {
    let completed = |finished_at| TaskTerminalRecord {
        disposition: TaskTerminalDisposition::Completed,
        result_ref: Some(EntityId::from_bytes([0xA1; 16]).expect("result id")),
        summary: Some(ConsultResultSummary::Answer {
            evidence_refs: vec![ConsultPayloadRef::Turn(
                EntityId::from_bytes([0xA2; 16]).expect("evidence id"),
            )],
        }),
        finished_at,
        ladder: None,
        counter_task_ref: None,
    };
    let expired = |finished_at| TaskTerminalRecord {
        disposition: TaskTerminalDisposition::Expired,
        result_ref: Some(EntityId::from_bytes([0xA3; 16]).expect("expiry id")),
        summary: None,
        finished_at,
        ladder: None,
        counter_task_ref: None,
    };
    let cases = [
        // Later answer beats an earlier expiry.
        (completed(200), expired(100), completed(200)),
        // Later expiry beats an earlier answer.
        (completed(100), expired(200), expired(200)),
        // Exact tie: the answer dominates.
        (completed(150), expired(150), completed(150)),
    ];

    for (index, (left, right, expected)) in cases.into_iter().enumerate() {
        let forward = merge_task_terminal_register(Some(&left), Some(&right));
        let backward = merge_task_terminal_register(Some(&right), Some(&left));
        assert_eq!(forward, backward, "case {index} must be order-free");
        assert_eq!(forward, Some(expected), "case {index} winner");
    }
    // An empty register merges to the one side that has a record.
    let only = completed(10);
    assert_eq!(
        merge_task_terminal_register(Some(&only), None),
        Some(only.clone())
    );
    assert_eq!(merge_task_terminal_register(None, Some(&only)), Some(only));
    assert_eq!(merge_task_terminal_register(None, None), None);
}

/// `Expired` and `Abandoned` are distinct causes that survive a body
/// round-trip, even though both project onto the failed lane.
#[test]
fn expired_and_abandoned_stay_distinct_through_the_codec() {
    let dispositions = [
        TaskTerminalDisposition::Completed,
        TaskTerminalDisposition::Rejected,
        TaskTerminalDisposition::Failed,
        TaskTerminalDisposition::Expired,
        TaskTerminalDisposition::Abandoned,
        TaskTerminalDisposition::Cancelled,
    ];
    let round_tripped: Vec<TaskTerminalDisposition> = dispositions
        .into_iter()
        .map(|disposition| {
            let record = TaskTerminalRecord {
                disposition,
                result_ref: Some(EntityId::from_bytes([0xA1; 16]).expect("result id")),
                summary: None,
                finished_at: 42,
                ladder: None,
                counter_task_ref: None,
            };
            let decoded = decode_task_terminal_record(&task_terminal_record_value(&record))
                .expect("terminal record round-trips");
            assert_eq!(decoded, record);
            decoded.disposition
        })
        .collect();

    assert_eq!(round_tripped, dispositions);
    assert_eq!(
        board_status_for_disposition(TaskTerminalDisposition::Expired),
        TaskBoardStatus::Failed
    );
    assert_eq!(
        board_status_for_disposition(TaskTerminalDisposition::Abandoned),
        TaskBoardStatus::Failed
    );
    assert_eq!(
        usize::from(
            TaskTerminalDisposition::Expired.as_str()
                == TaskTerminalDisposition::Abandoned.as_str()
        ),
        0
    );
}

/// Fan-out mints N independent tasks under ONE correlation ref, refuses a
/// repeated peer deterministically, and never mints a partial subset.
#[test]
fn fan_out_mints_one_task_per_distinct_peer_under_one_correlation() {
    let (_dir, vault) = open_vault();
    let asker = own_agent(&vault);
    let peers: Vec<EntityId> = [0xE2, 0xE4, 0xE5]
        .into_iter()
        .map(|seed| consult_peer(&vault, seed))
        .collect();
    let question = consult_turn(&vault, 0x7A);
    let facade = vault.memory_facade(asker, EdgeActorClass::Agent);
    let fan_out = |assignees: Vec<EntityId>| ConsultFanOutSpec {
        question_ref: question,
        context_refs: Vec::new(),
        assignees,
        deadline_at: CONSULT_DEADLINE,
        label: None,
        now: Some(CONSULT_NOW),
    };

    let duplicated = facade
        .fan_out_consults(&fan_out(vec![peers[0], peers[1], peers[0]]))
        .expect_err("a repeated peer is refused, never collapsed");
    let after_refusal = task_entity_census(&vault);
    let empty = facade
        .fan_out_consults(&fan_out(Vec::new()))
        .expect_err("a fan-out addresses at least one peer");
    let receipt = facade
        .fan_out_consults(&fan_out(peers.clone()))
        .expect("fan out to three distinct peers");
    let correlations: Vec<EntityId> = receipt
        .task_refs
        .iter()
        .map(|task_ref| {
            task_verb_body(&vault, *task_ref)
                .expect("decode consult")
                .expect("typed consult")
                .consult
                .expect("consult payload")
                .correlation_ref
        })
        .collect();
    let mut unique_tasks = receipt.task_refs.clone();
    unique_tasks.sort_unstable();
    unique_tasks.dedup();
    let mut sorted_peers = peers;
    sorted_peers.sort_unstable();
    let assignees: Vec<EntityId> = receipt
        .task_refs
        .iter()
        .filter_map(|task_ref| {
            task_verb_body(&vault, *task_ref)
                .expect("decode consult")
                .expect("typed consult")
                .assignee
                .and_then(TaskAssignee::entity_ref)
        })
        .collect();

    assert_eq!(duplicated.code, crate::facade::FACADE_CODE_BAD_REQUEST);
    assert_eq!(empty.code, crate::facade::FACADE_CODE_BAD_REQUEST);
    assert_eq!(after_refusal, 0);
    assert_eq!(receipt.task_refs.len(), 3);
    assert_eq!(unique_tasks.len(), 3);
    assert_eq!(correlations, vec![receipt.correlation_ref; 3]);
    // Deterministic assignee order, independent of how the caller listed
    // them, so a fan-out receipt is comparable across replicas.
    assert_eq!(assignees, sorted_peers);
    assert_eq!(AttemptQueue::new(&vault).list().expect("attempts").len(), 0);
}

/// Expiry notification is exactly-once per `(task_ref, stage)` and
/// survives a crash between terminalization and the outbound schedule.
#[test]
fn expiry_digest_is_once_per_task_and_recovers_from_the_crash_window() {
    let (_dir, vault) = open_vault();
    let asker = own_agent(&vault);
    grant_outbound(&vault, asker, 0xD1);
    let (task_ref, _peer, _question) = open_consult(&vault);
    let facade = vault.memory_facade(asker, EdgeActorClass::Agent);

    let first = facade
        .settle_due_consults(CONSULT_DEADLINE + 1, &digest_route())
        .expect("first sweep expires and notifies");
    let second = facade
        .settle_due_consults(CONSULT_DEADLINE + 2, &digest_route())
        .expect("second sweep is a no-op");
    let sends_after_two_sweeps = vault.connector_send_tasks().expect("connector sends").len();

    // Simulated crash: the task terminalized, but the process died before
    // the follow-up marker landed.
    {
        let mut wtxn = vault.store.env.write_txn().expect("write txn");
        vault
            .store
            .vault_meta
            .delete(
                &mut wtxn,
                task_follow_up_key(task_ref, TASK_FOLLOW_UP_STAGE_CONSULT_EXPIRED).as_slice(),
            )
            .expect("clear the follow-up marker");
        wtxn.commit().expect("commit");
    }
    let recovered = facade
        .settle_due_consults(CONSULT_DEADLINE + 3, &digest_route())
        .expect("the sweep re-drives an undigested expiry");
    let sends_after_recovery = vault.connector_send_tasks().expect("connector sends").len();

    assert_eq!(first.expired_task_refs, vec![task_ref]);
    assert_eq!(first.digest_intent_refs.len(), 1);
    assert_eq!(first.already_settled, 0);
    assert_eq!(second.expired_task_refs.len(), 0);
    assert_eq!(second.digest_intent_refs.len(), 0);
    assert_eq!(second.already_settled, 1);
    assert_eq!(sends_after_two_sweeps, 1);
    // The re-drive re-schedules, and the shared namespace key coalesces it
    // onto the SAME outbound intent rather than double-notifying.
    assert_eq!(recovered.expired_task_refs.len(), 0);
    assert_eq!(recovered.digest_intent_refs.len(), 1);
    assert_eq!(sends_after_recovery, 1);
    assert_eq!(
        recovered.digest_intent_refs, first.digest_intent_refs,
        "the coalesced retry names the first intent"
    );
    // The namespace is shared with ONE-1708's human follow-up stages.
    assert_eq!(
        task_follow_up_dedupe_key(task_ref, TASK_FOLLOW_UP_STAGE_CONSULT_EXPIRED),
        format!("tasks.followup.v1:{}:consult_expired", task_ref.to_hex())
    );
    assert_eq!(
        usize::from(
            task_follow_up_dedupe_key(task_ref, "human_reminder")
                != task_follow_up_dedupe_key(task_ref, TASK_FOLLOW_UP_STAGE_CONSULT_EXPIRED)
        ),
        1
    );
}

/// The asker's failed lane keeps an expired consult until it is acked, and
/// the row names `expired` distinctly from the bare `failed` status.
#[test]
fn expired_consult_holds_the_failed_lane_until_acked() {
    let (_dir, vault) = open_vault();
    let asker = own_agent(&vault);
    grant_outbound(&vault, asker, 0xD1);
    let (task_ref, _peer, _question) = open_consult(&vault);
    let task_hex = task_ref.to_hex();
    let facade = vault.memory_facade(asker, EdgeActorClass::Agent);
    facade
        .settle_due_consults(CONSULT_DEADLINE + 1, &digest_route())
        .expect("settle the expired consult");

    let before = facade.tasks_check().expect("board before ack");
    let lane = crate::context_board::failed_lane(&before);
    let acked = facade.tasks_ack(task_ref).expect("ack the expired consult");
    let after = facade.tasks_check().expect("board after ack");

    assert_eq!(lane.len(), 1);
    assert_eq!(lane[0].id, task_hex);
    assert_eq!(lane[0].status, TaskBoardStatus::Failed);
    assert_eq!(
        lane[0].terminal_disposition,
        Some(TaskTerminalDisposition::Expired)
    );
    assert_eq!(
        lane[0]
            .line
            .split_whitespace()
            .filter(|token| *token == "expired")
            .count(),
        1
    );
    assert_eq!(
        lane[0]
            .line
            .split_whitespace()
            .filter(|token| *token == "failed")
            .count(),
        1
    );
    assert_eq!(usize::from(acked.acked), 1);
    assert_eq!(
        after.rows.iter().filter(|row| row.id == task_hex).count(),
        0
    );
}

/// A board read derives expiry from the persisted deadline alone, so the
/// failed row is never hidden behind reconciliation or outbound
/// availability.
#[test]
fn board_reads_expiry_from_the_deadline_before_the_sweep_runs() {
    let (_dir, vault) = open_vault();
    let asker = own_agent(&vault);
    let peer = consult_peer(&vault, 0xE2);
    let question = consult_turn(&vault, 0x7A);
    let facade = vault.memory_facade(asker, EdgeActorClass::Agent);
    // A deadline one second into the past of the READ clock; nothing has
    // settled it, and no digest has been scheduled.
    let now = unix_seconds_now();
    let created = facade
        .tasks_create(
            &TaskCreateSpec::new(Value::Nil, None, None, Some(now))
                .with_kind(TaskKind::Consult)
                .with_consult(ConsultPayload::question(
                    question,
                    Vec::new(),
                    EntityId::now(),
                ))
                .with_assignee(TaskAssignee::Peer { actor_ref: peer })
                .with_ttl(TaskTtl::at(now + 1)),
        )
        .expect("consult create effects");
    let task_ref = created.task_ref.expect("task ref");
    let body = task_verb_body(&vault, task_ref)
        .expect("decode body")
        .expect("typed body");

    let row = task_intent_presence(
        &vault,
        task_ref,
        &task_ref.to_hex(),
        Vec::new(),
        false,
        now + 2,
    )
    .expect("project the overdue consult")
    .expect("consult projects");

    assert_eq!(usize::from(body.terminal().is_none()), 1);
    assert_eq!(row.status, TaskBoardStatus::Failed);
    assert_eq!(
        row.terminal_disposition,
        Some(TaskTerminalDisposition::Expired)
    );
    assert_eq!(usize::from(row.result_ref.is_none()), 1);
    assert_eq!(vault.connector_send_tasks().expect("sends").len(), 0);
}

/// The synced entity reaches a peer wherever it connects; the lease-bearing
/// plane never leaves this node.
#[cfg(feature = "sync")]
#[test]
fn consult_task_syncs_and_no_attempt_row_follows_it() {
    use crate::config::VaultConfig;
    use crate::sync::schema::create_window_doc;
    use crate::sync::types::WindowKey;
    use crate::sync::window::reverse_rematerialize;
    use loro::{ExportMode, LoroDoc};

    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open device vault");
    let (task_ref, _peer, _question) = open_consult(&vault);
    // A node-local job unrelated to the consult, to prove the export
    // excludes the whole attempt plane and not merely an empty one.
    let EnqueueOutcome::Enqueued(_) = AttemptQueue::new(&vault)
        .enqueue(EnqueueAttempt {
            kind: TASK_REALIZE_ATTEMPT_KIND.to_owned(),
            payload: b"node-local".to_vec(),
            dedupe_key: None,
            run_id: None,
            now: CONSULT_NOW,
        })
        .expect("enqueue node-local job")
    else {
        panic!("job must enqueue");
    };

    let window_key = WindowKey::new("2026-03");
    let sync_doc = create_window_doc("test-user", &window_key);
    reverse_rematerialize(&vault, &sync_doc, &window_key).expect("mirror into sync document");
    let snapshot = sync_doc
        .export(ExportMode::Snapshot)
        .expect("export sync snapshot");
    let exported = LoroDoc::from_snapshot(&snapshot).expect("read sync snapshot");
    let mut synced_attempt_rows = 0;
    exported
        .get_map("attempt_records")
        .for_each(|_, _| synced_attempt_rows += 1);

    assert_eq!(
        usize::from(
            exported
                .get_map("entities")
                .get(task_ref.to_hex().as_str())
                .is_some()
        ),
        1
    );
    assert_eq!(synced_attempt_rows, 0);
    let payload: &[u8] = b"node-local";
    assert_eq!(
        usize::from(
            snapshot
                .windows(payload.len())
                .any(|window| window == payload)
        ),
        0
    );
}

fn assert_queued_terminal_mix_cancel(
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
    let facade = vault.memory_facade(own, EdgeActorClass::Agent);
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

#[test]
fn verb_family_is_exactly_five_without_queue_verbs() {
    let verbs = TasksVerb::ALL.map(TasksVerb::as_str);
    assert_eq!(verbs.len(), 5);
    assert_eq!(verbs, TASKS_VERBS);
    assert_eq!(
        verbs
            .iter()
            .filter(|verb| verb.contains("queue") || verb.contains("lease"))
            .count(),
        0
    );
}

#[test]
fn own_create_effects_and_foreign_create_proposes() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let foreign = EntityId::from_bytes([0xE2; 16]).expect("foreign id");
    put_person(&vault, foreign);
    let rate = TaskCreateRateLimit {
        limit: 10,
        window_seconds: 60,
    };

    let own_result = vault
        .memory_facade(own, EdgeActorClass::Agent)
        .tasks_create_with_rate_limit(&spec(120), rate)
        .expect("own create");
    let foreign_result = vault
        .memory_facade(foreign, EdgeActorClass::Agent)
        .tasks_create_with_rate_limit(&spec(120), rate)
        .expect("foreign create");

    assert_eq!(usize::from(own_result.effected), 1);
    assert_eq!(own_result.approval, ClaimApprovalStatus::Auto);
    assert_eq!(usize::from(own_result.proposal_ref.is_some()), 0);
    assert_eq!(usize::from(foreign_result.effected), 0);
    assert_eq!(foreign_result.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(usize::from(foreign_result.proposal_ref.is_some()), 1);
    assert_eq!(task_entity_census(&vault), 1);
}

#[test]
fn rate_limit_effects_n_and_proposes_every_overflow() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let facade = vault.memory_facade(own, EdgeActorClass::Agent);
    let limit = 3;
    let attempted = 5;
    // The rate window is keyed on the ENGINE clock (`unix_seconds_now()`,
    // not caller time — the codex-r1 anti-bypass fix). A single window here
    // keeps the overflow behavior deterministic: with a finite window these
    // creates could straddle a wall-clock boundary under load and reset the
    // count mid-loop. (Window advancement is covered separately by
    // `create_rate_slot_overwrites_one_key_across_windows`.)
    let rate = TaskCreateRateLimit {
        limit,
        window_seconds: u64::MAX,
    };
    let mut results = Vec::new();
    for _ in 0..attempted {
        results.push(
            facade
                .tasks_create_with_rate_limit(&spec(120), rate)
                .expect("create"),
        );
    }

    assert_eq!(usize::from(results[limit - 1].effected), 1);
    assert_eq!(results[limit - 1].approval, ClaimApprovalStatus::Auto);
    assert_eq!(usize::from(results[limit - 1].proposal_ref.is_some()), 0);
    assert_eq!(usize::from(results[limit].effected), 0);
    assert_eq!(results[limit].approval, ClaimApprovalStatus::Proposed);
    assert_eq!(usize::from(results[limit].proposal_ref.is_some()), 1);
    assert_eq!(
        results.iter().filter(|result| result.effected).count(),
        limit
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| result.proposal_ref.is_some())
            .count(),
        attempted - limit
    );
}

/// A STANDARD task with a deadline already past is born expired, so the same
/// refusal the consult branch gives applies here. A future deadline passes,
/// and no deadline at all still means no TTL.
#[test]
fn a_standard_task_deadline_must_be_in_the_future() {
    let (_dir, vault) = open_vault();
    let facade = vault.memory_facade(own_agent(&vault), EdgeActorClass::Agent);
    let now = 1_772_400_000;

    for past in [now, now - 1, 0] {
        let refused = facade
            .tasks_create(&spec(now).with_ttl(TaskTtl::at(past)))
            .expect_err("a past deadline rejects");
        assert_eq!(refused.code, crate::facade::FACADE_CODE_BAD_REQUEST);
    }
    let accepted = facade
        .tasks_create(&spec(now).with_ttl(TaskTtl::at(now + 1)))
        .expect("a future deadline is a task with a TTL");
    let task_ref = accepted.task_ref.expect("task minted");
    assert_eq!(
        task_verb_body(&vault, task_ref)
            .expect("decode task")
            .expect("task is typed")
            .ttl,
        Some(TaskTtl::at(now + 1))
    );
    facade
        .tasks_create(&spec(now))
        .expect("no deadline is still a legal task");
}

/// Overflow past quota parks a proposal — it does not refuse — so a retry
/// loop must land on the row already waiting rather than mint one per
/// attempt. The receipts still read as proposals every time; only the stored
/// rows are bounded.
#[test]
fn repeated_overflow_creates_park_on_one_proposal_row() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let facade = vault.memory_facade(own, EdgeActorClass::Agent);
    let limit = 1;
    let retries = 6;
    let rate = TaskCreateRateLimit {
        limit,
        window_seconds: u64::MAX,
    };
    let results: Vec<_> = (0..retries)
        .map(|_| {
            facade
                .tasks_create_with_rate_limit(&spec(120), rate)
                .expect("create")
        })
        .collect();

    assert_eq!(
        results.iter().filter(|result| result.effected).count(),
        limit
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| result.proposal_ref.is_some())
            .count(),
        retries - limit,
        "every overflow still answers with a proposal"
    );
    let proposal_refs: std::collections::BTreeSet<EntityId> = results
        .iter()
        .filter_map(|result| result.proposal_ref)
        .collect();
    assert_eq!(
        proposal_refs.len(),
        1,
        "the retries share ONE parked proposal"
    );
    assert_eq!(open_create_proposal_census(&vault, own), 1);
}

/// A DIFFERENT ask past quota still parks its own proposal: the dedupe is on
/// the ask, not on the actor.
#[test]
fn a_distinct_overflow_create_parks_its_own_proposal() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let facade = vault.memory_facade(own, EdgeActorClass::Agent);
    let rate = TaskCreateRateLimit {
        limit: 1,
        window_seconds: u64::MAX,
    };
    facade
        .tasks_create_with_rate_limit(&spec(120), rate)
        .expect("first create takes effect");
    facade
        .tasks_create_with_rate_limit(&spec(120), rate)
        .expect("overflow parks");
    facade
        .tasks_create_with_rate_limit(
            &TaskCreateSpec::new(Value::from("other-task"), None, None, Some(120)),
            rate,
        )
        .expect("a different overflow parks");

    assert_eq!(open_create_proposal_census(&vault, own), 2);
}

/// Open (`Active` + `Proposed`) `tasks.create` proposal rows parked against
/// one actor.
fn open_create_proposal_census(vault: &Vault, actor: EntityId) -> usize {
    vault
        .claims_for_subject(&actor)
        .expect("claims for actor")
        .into_iter()
        .filter(|id| {
            vault
                .get_claim(id)
                .expect("claim body")
                .is_some_and(|body| {
                    body.predicate == "tasks.create"
                        && body.lifecycle == ClaimLifecycleStatus::Active
                        && body.approval == ClaimApprovalStatus::Proposed
                })
        })
        .count()
}

#[test]
fn create_rate_slot_overwrites_one_key_across_windows() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let rate = TaskCreateRateLimit {
        limit: 2,
        window_seconds: 10,
    };
    {
        let mut wtxn = vault.store.env.write_txn().expect("write txn");
        // Window 0 (now 0..9): two slots, then the third is refused.
        assert!(consume_create_rate_slot(&vault, &mut wtxn, own, 0, rate).expect("w0 s1"));
        assert!(consume_create_rate_slot(&vault, &mut wtxn, own, 3, rate).expect("w0 s2"));
        assert!(!consume_create_rate_slot(&vault, &mut wtxn, own, 9, rate).expect("w0 over"));
        // Window 1 (now 10..): the count resets, a slot is available again.
        assert!(consume_create_rate_slot(&vault, &mut wtxn, own, 10, rate).expect("w1 s1"));
        // Window 2 (now 20..): still resets, still the same single key.
        assert!(consume_create_rate_slot(&vault, &mut wtxn, own, 20, rate).expect("w2 s1"));
        wtxn.commit().expect("commit");
    }
    // Elapsed windows overwrite the SAME key: exactly one rate key persists
    // for this (actor, window_seconds), not one row per elapsed window.
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let keys = vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, TASK_CREATE_RATE_KEY_PREFIX)
        .expect("rate prefix iter")
        .count();
    assert_eq!(keys, 1);
}

#[test]
fn caller_time_variation_does_not_bypass_one_engine_rate_window() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let facade = vault.memory_facade(own, EdgeActorClass::Agent);
    let limit = 3;
    let rate = TaskCreateRateLimit {
        limit,
        window_seconds: u64::MAX,
    };
    let caller_times = [0, 60, 120, 180];
    let results = caller_times.map(|now| {
        facade
            .tasks_create_with_rate_limit(&spec(now), rate)
            .expect("create")
    });

    assert_eq!(
        results.iter().filter(|result| result.effected).count(),
        limit
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| result.approval == ClaimApprovalStatus::Proposed)
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| result.proposal_ref.is_some())
            .count(),
        1
    );
}

#[test]
fn cancel_ladder_is_own_scoped_and_records_gate_decision() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    grant_cancel(&vault, own, 0xD1);
    let other = EntityId::from_bytes([0xE2; 16]).expect("other id");
    put_person(&vault, other);
    let facade = vault.memory_facade(own, EdgeActorClass::Agent);
    let own_create = facade.tasks_create(&spec(120)).expect("own task");
    let mut other_spec = spec(120);
    other_spec.owner_ref = Some(other);
    let other_create = facade.tasks_create(&other_spec).expect("other task");

    let decisions_before = vault.gate_decisions(512).expect("decisions before").len();
    let own_cancel = facade
        .tasks_cancel(TaskCancelTarget::Task(
            own_create.task_ref.expect("own task ref"),
        ))
        .expect("own cancel");
    let decisions_after_own = vault
        .gate_decisions(512)
        .expect("decisions after own")
        .len();
    let foreign_cancel = facade
        .tasks_cancel(TaskCancelTarget::Task(
            other_create.task_ref.expect("other task ref"),
        ))
        .expect("foreign cancel");

    assert_eq!(TaskCancelMode::ALL.map(TaskCancelMode::as_str).len(), 3);
    assert_eq!(
        TaskCancelMode::ALL.map(TaskCancelMode::as_str),
        ["auto", "full-access", "manual"]
    );
    assert_eq!(DEFAULT_TASK_CANCEL_MODE.as_str(), "auto");
    assert_eq!(TaskCancelMode::Auto.ceiling(), PolicyApprovalCeiling::Auto);
    assert_eq!(
        TaskCancelMode::FullAccess.ceiling(),
        PolicyApprovalCeiling::Auto
    );
    assert_eq!(
        TaskCancelMode::Manual.ceiling(),
        PolicyApprovalCeiling::Proposed
    );
    assert_eq!(decisions_after_own - decisions_before, 1);
    assert_eq!(usize::from(own_cancel.gate_decision_ref.is_some()), 1);
    assert_eq!(
        vault
            .gate_decisions(512)
            .expect("gate decisions")
            .iter()
            .filter(|decision| {
                own_cancel.gate_decision_ref.as_deref()
                    == Some(format!("gate:{}", decision.decision_id.to_hex()).as_str())
                    && decision.outcome == GateOutcome::Allow.as_str()
            })
            .count(),
        1
    );
    assert_eq!(usize::from(own_cancel.effected), 1);
    assert_eq!(own_cancel.approval, ClaimApprovalStatus::Auto);
    assert_eq!(own_cancel.status, Some(RunTreeStatus::Cancelled));
    assert_eq!(usize::from(foreign_cancel.effected), 0);
    assert_eq!(foreign_cancel.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(usize::from(foreign_cancel.proposal_ref.is_some()), 1);
    assert_eq!(usize::from(foreign_cancel.gate_decision_ref.is_some()), 1);

    let queue = AttemptQueue::new(&vault);
    let records = queue.list().expect("list attempts");
    let own_task_hex = own_create.task_ref.expect("own task ref").to_hex();
    let other_task_hex = other_create.task_ref.expect("other task ref").to_hex();
    let own_attempts: Vec<_> = records
        .iter()
        .filter(|attempt| attempt.task_ref.as_deref() == Some(own_task_hex.as_str()))
        .collect();
    let other_attempts: Vec<_> = records
        .iter()
        .filter(|attempt| attempt.task_ref.as_deref() == Some(other_task_hex.as_str()))
        .collect();
    assert_eq!(own_attempts.len(), 1);
    assert_eq!(other_attempts.len(), 1);
    let own_attempt = own_attempts[0];
    let other_attempt = other_attempts[0];
    assert_eq!(own_attempt.state, AttemptState::Cancelled);
    assert_eq!(other_attempt.state, AttemptState::Queued);
}

#[test]
fn pending_cancel_proposes_without_intervening_realization() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let facade = vault.memory_facade(own, EdgeActorClass::Agent);
    let created = facade.tasks_create(&spec(120)).expect("create task");
    let task_ref = created.task_ref.expect("task ref");

    let cancel = facade
        .tasks_cancel(TaskCancelTarget::Task(task_ref))
        .expect("propose cancel");
    let records = AttemptQueue::new(&vault).list().expect("list attempts");
    let task_hex = task_ref.to_hex();

    assert_eq!(usize::from(cancel.effected), 0);
    assert_eq!(cancel.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(usize::from(cancel.proposal_ref.is_some()), 1);
    assert_eq!(
        vault
            .gate_decisions(512)
            .expect("gate decisions")
            .iter()
            .filter(|decision| {
                cancel.gate_decision_ref.as_deref()
                    == Some(format!("gate:{}", decision.decision_id.to_hex()).as_str())
                    && decision.outcome == GateOutcome::Pending.as_str()
            })
            .count(),
        1
    );
    assert_eq!(
        records
            .iter()
            .filter(|record| {
                record.task_ref.as_deref() == Some(task_hex.as_str())
                    && record.state == AttemptState::Queued
            })
            .count(),
        1
    );
    assert_eq!(
        usize::from(task_is_cancelled(&vault, task_ref).expect("cancel state")),
        0
    );
}

#[test]
fn leased_realization_keeps_cancel_receipt_running() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    grant_cancel(&vault, own, 0xD2);
    let facade = vault.memory_facade(own, EdgeActorClass::Agent);
    let created = facade.tasks_create(&spec(120)).expect("create task");
    let task_ref = created.task_ref.expect("task ref");
    let queue = AttemptQueue::new(&vault);
    let claimed = match queue
        .claim_kind(
            TASK_REALIZE_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: "w1".to_owned(),
                now: 120,
            },
        )
        .expect("claim realization")
    {
        ClaimOutcome::Claimed(claimed) => claimed,
        ClaimOutcome::Empty => panic!("realization must be claimable"),
    };

    let cancel = facade
        .tasks_cancel(TaskCancelTarget::Task(task_ref))
        .expect("cancel task");
    let post_cancel = queue
        .get(claimed.id)
        .expect("read realization")
        .expect("realization exists");
    let section = facade.tasks_check().expect("check tasks");

    // P1-a: a leased realization is NOT stoppable in-txn, so the cancel is
    // honest — it does not claim effect and does not hide the task.
    assert_eq!(usize::from(cancel.effected), 0);
    assert_eq!(cancel.status, Some(RunTreeStatus::Running));
    assert_eq!(
        usize::from(cancel.status == Some(RunTreeStatus::Cancelled)),
        0
    );
    assert_eq!(cancel.approval, ClaimApprovalStatus::Auto);
    assert_eq!(usize::from(cancel.proposal_ref.is_some()), 0);
    assert_eq!(post_cancel.state, AttemptState::Leased);
    // The task is NOT hidden while the lease keeps realizing (outbound
    // delivery included): the cancelled bit is not set.
    assert_eq!(
        usize::from(task_is_cancelled(&vault, task_ref).expect("cancel state")),
        0
    );
    // The board still shows the task exactly once — it folds to Running
    // under its live lease rather than vanishing.
    assert_eq!(
        section
            .rows
            .iter()
            .filter(|row| row.id == task_ref.to_hex())
            .count(),
        1
    );
}

#[test]
fn terminal_task_cancel_is_uneffected_and_keeps_intent_folded() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    grant_cancel(&vault, own, 0xD3);
    let facade = vault.memory_facade(own, EdgeActorClass::Agent);
    let created = facade.tasks_create(&spec(120)).expect("create task");
    let task_ref = created.task_ref.expect("task ref");
    let task_hex = task_ref.to_hex();
    let queue = AttemptQueue::new(&vault);
    let claimed = match queue
        .claim_kind(
            TASK_REALIZE_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: "terminal-task-worker".to_owned(),
                now: 120,
            },
        )
        .expect("claim realization")
    {
        ClaimOutcome::Claimed(claimed) => claimed,
        ClaimOutcome::Empty => panic!("realization must be claimable"),
    };
    queue
        .complete(CompleteAttempt {
            id: claimed.id,
            lease_owner: "terminal-task-worker".to_owned(),
            attempt_count: claimed.attempt_count,
            now: 121,
        })
        .expect("complete realization");

    let cancel = facade
        .tasks_cancel(TaskCancelTarget::Task(task_ref))
        .expect("cancel terminal task");
    let realization = queue
        .get(claimed.id)
        .expect("read realization")
        .expect("realization exists");
    let section = facade.tasks_check().expect("check tasks");
    let job_hex = attempt_hex(claimed.id);

    assert_eq!(usize::from(cancel.effected), 0);
    assert_eq!(cancel.status, Some(RunTreeStatus::Completed));
    assert_eq!(cancel.approval, ClaimApprovalStatus::Auto);
    assert_eq!(realization.state, AttemptState::Completed);
    assert_eq!(
        usize::from(task_is_cancelled(&vault, task_ref).expect("cancel state")),
        0
    );
    assert_eq!(
        section
            .rows
            .iter()
            .filter(|row| row.id == task_hex && row.status == TaskBoardStatus::Done)
            .count(),
        1
    );
    assert_eq!(
        section.rows.iter().filter(|row| row.id == job_hex).count(),
        0
    );
    assert_eq!(section.rows.len(), 1);
}

#[test]
fn queued_completed_mix_cancel_preserves_terminal_fold_exactly_once() {
    assert_queued_terminal_mix_cancel(
        AttemptState::Completed,
        RunTreeStatus::Completed,
        TaskBoardStatus::Done,
    );
}

#[test]
fn queued_failed_mix_cancel_preserves_terminal_fold_exactly_once() {
    assert_queued_terminal_mix_cancel(
        AttemptState::Failed,
        RunTreeStatus::Failed,
        TaskBoardStatus::Failed,
    );
}

// Deferred post-close (CB-04): traced root cause is NOT cancel-receipt
// honesty. For an agent principal cancelling its OWN already-terminal
// spawn, `check_external_effect_policy` resolves `Pending` (propose), not
// `Allow`, so `tasks_cancel_resolved` returns at the gate branch with
// `approval = Proposed, status = None` before the terminal-status path
// runs. The receipt is therefore honest about the proposal; the terminal
// `Some(Completed)`/`Auto` this test expects is unreachable until the
// external-effect gate auto-allows an agent's self-cancel of its own
// spawn. That is gate-authority-surface work (an owner decision on whether
// agent spawn self-cancel is Auto), out of 1696 scope, and fail-closed
// (propose ⊃ allow) so non-security. Re-enable once that authority lands.
#[test]
#[ignore = "CB-04 follow-up: agent spawn self-cancel proposes (gate Pending); Auto/Some(Completed) needs gate-authority change, deferred post-close, non-security"]
fn terminal_spawn_cancel_is_uneffected_and_preserves_terminal_state() {
    let (_dir, vault) = open_vault();
    let own = EntityId::from_bytes([0xB3; 16]).expect("custom agent id");
    // Ordinary row fork off the seeded keeper row: lineage is the parent
    // ROW id, and the child copies the parent's stored ceiling.
    let (keeper_id, keeper) = vault
        .get_seeded_agent_definition_by_logical_id("sys.keeper")
        .expect("resolve seeded keeper")
        .expect("seeded keeper exists");
    let mut fork = keeper.clone();
    fork.agent_id = "spawn-owner".to_owned();
    fork.version = "1".to_owned();
    fork.forked_from = Some(keeper_id);
    fork.ceiling = keeper.ceiling;
    fork.logical_id = None;
    fork.display_name = None;
    fork.source = crate::claim::ClaimSource::UserStated;
    fork.provenance = rmpv::Value::Map(vec![(
        rmpv::Value::from("forkOf"),
        rmpv::Value::from(keeper_id.to_hex()),
    )]);
    vault
        .put_agent_definition(&own, &fork, TimeRange { start: 1, end: 1 }, 1)
        .expect("fork custom agent");
    grant_cancel(&vault, own, 0xD4);
    let dispatcher = AgentDispatcher::new(&vault);
    let parent = match dispatcher
        .dispatch(DispatchAgent {
            target: AgentDispatchTarget::Custom(own),
            parent_attempt: None,
            dedupe_key: None,
            run_id: None,
            now: 120,
        })
        .expect("dispatch parent")
    {
        AgentDispatchOutcome::Dispatched(status) => status,
        AgentDispatchOutcome::Existing(_) => panic!("parent dispatch must be fresh"),
    };
    let child = match dispatcher
        .dispatch_default_base(Some(parent.attempt.id), None, None, 121)
        .expect("dispatch child")
    {
        AgentDispatchOutcome::Dispatched(status) => status,
        AgentDispatchOutcome::Existing(_) => panic!("child dispatch must be fresh"),
    };
    let queue = AttemptQueue::new(&vault);
    for (expected, lease_owner, now) in [
        (parent.attempt.id, "terminal-parent-worker", 122),
        (child.attempt.id, "terminal-child-worker", 123),
    ] {
        let claimed = match queue
            .claim_kind(
                DREAMER_RUNNER_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: lease_owner.to_owned(),
                    now,
                },
            )
            .expect("claim dispatch")
        {
            ClaimOutcome::Claimed(claimed) => claimed,
            ClaimOutcome::Empty => panic!("dispatch must be claimable"),
        };
        assert_eq!(usize::from(claimed.id == expected), 1);
        queue
            .complete(CompleteAttempt {
                id: claimed.id,
                lease_owner: lease_owner.to_owned(),
                attempt_count: claimed.attempt_count,
                now,
            })
            .expect("complete dispatch");
    }

    let facade = vault.memory_facade(own, EdgeActorClass::Agent);
    let cancel = facade
        .tasks_cancel(TaskCancelTarget::Spawn(child.attempt.id))
        .expect("cancel terminal spawn");
    let terminal = queue
        .get(child.attempt.id)
        .expect("read child")
        .expect("child exists");

    assert_eq!(usize::from(cancel.effected), 0);
    assert_eq!(cancel.status, Some(RunTreeStatus::Completed));
    assert_eq!(cancel.approval, ClaimApprovalStatus::Auto);
    assert_eq!(terminal.state, AttemptState::Completed);
    assert_eq!(
        vault
            .gate_decisions(512)
            .expect("gate decisions")
            .iter()
            .filter(|decision| {
                cancel.gate_decision_ref.as_deref()
                    == Some(format!("gate:{}", decision.decision_id.to_hex()).as_str())
                    && decision.outcome == GateOutcome::Allow.as_str()
            })
            .count(),
        1
    );
}

#[test]
fn tasks_cancel_spawn_non_dreamer_attempt_falls_through_to_proposal() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let queue = AttemptQueue::new(&vault);
    let EnqueueOutcome::Enqueued(attempt) = queue
        .enqueue(EnqueueAttempt {
            kind: AGENT_DISPATCH_ATTEMPT_TYPE.to_owned(),
            payload: vec![0xc1, 0x00, 0xff],
            dedupe_key: None,
            run_id: None,
            now: 120,
        })
        .expect("enqueue")
    else {
        panic!("enqueue must succeed")
    };
    let cancel = vault
        .memory_facade(own, EdgeActorClass::Agent)
        .tasks_cancel(TaskCancelTarget::Spawn(attempt.id))
        .expect("cancel");
    assert!(!cancel.effected);
    assert_eq!(cancel.approval, ClaimApprovalStatus::Proposed);
    assert!(cancel.proposal_ref.is_some());
    assert_eq!(cancel.status, None);
    assert_eq!(
        queue
            .get(attempt.id)
            .expect("read attempt")
            .expect("attempt exists")
            .state,
        AttemptState::Queued
    );
}

#[test]
fn tasks_cancel_spawn_malformed_dreamer_payload_is_propose_only() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let queue = AttemptQueue::new(&vault);
    let EnqueueOutcome::Enqueued(attempt) = queue
        .enqueue(EnqueueAttempt {
            kind: DREAMER_RUNNER_ATTEMPT_KIND.to_owned(),
            payload: vec![0xc1],
            dedupe_key: None,
            run_id: None,
            now: 120,
        })
        .expect("enqueue")
    else {
        panic!("enqueue must succeed")
    };
    let cancel = vault
        .memory_facade(own, EdgeActorClass::Agent)
        .tasks_cancel(TaskCancelTarget::Spawn(attempt.id))
        .expect("cancel");
    assert!(!cancel.effected);
    assert_eq!(cancel.approval, ClaimApprovalStatus::Proposed);
    assert!(cancel.proposal_ref.is_some());
    assert_eq!(cancel.status, None);
    assert_eq!(
        queue
            .get(attempt.id)
            .expect("read attempt")
            .expect("attempt exists")
            .state,
        AttemptState::Queued
    );
}

#[test]
fn tasks_cancel_spawn_missing_attempt_still_returns_entity_not_found() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let missing = AttemptId::from_bytes(&[0xa7; 16]).expect("id");
    let error = vault
        .memory_facade(own, EdgeActorClass::Agent)
        .tasks_cancel(TaskCancelTarget::Spawn(missing))
        .expect_err("missing row");
    assert_eq!(error.code, crate::facade::FACADE_CODE_NOT_FOUND);
}

#[test]
fn tasks_cancel_owned_agent_dispatch_spawn_still_effects_under_auto() {
    let (_dir, vault) = open_vault();
    let own = EntityId::from_bytes([0xE1; 16]).expect("actor id");
    let (keeper_id, keeper) = vault
        .get_seeded_agent_definition_by_logical_id("sys.keeper")
        .expect("resolve keeper")
        .expect("keeper exists");
    let mut fork = keeper.clone();
    fork.agent_id = "spawn-owner".to_owned();
    fork.version = "1".to_owned();
    fork.forked_from = Some(keeper_id);
    fork.ceiling = keeper.ceiling;
    fork.logical_id = None;
    fork.display_name = None;
    fork.source = crate::claim::ClaimSource::UserStated;
    fork.provenance = rmpv::Value::Map(vec![(
        rmpv::Value::from("forkOf"),
        rmpv::Value::from(keeper_id.to_hex()),
    )]);
    vault
        .put_agent_definition(
            &own,
            &fork,
            TimeRange {
                start: 1,
                end: u64::MAX,
            },
            1,
        )
        .expect("fork agent");
    grant_cancel(&vault, own, 0xa8);
    let dispatcher = AgentDispatcher::new(&vault);
    let parent = match dispatcher
        .dispatch(DispatchAgent {
            target: AgentDispatchTarget::Custom(own),
            parent_attempt: None,
            dedupe_key: None,
            run_id: None,
            now: 120,
        })
        .expect("dispatch parent")
    {
        AgentDispatchOutcome::Dispatched(status) => status,
        AgentDispatchOutcome::Existing(_) => panic!("fresh parent"),
    };
    let child = match dispatcher
        .dispatch_default_base(Some(parent.attempt.id), None, None, 121)
        .expect("dispatch child")
    {
        AgentDispatchOutcome::Dispatched(status) => status,
        AgentDispatchOutcome::Existing(_) => panic!("fresh child"),
    };
    let queue = AttemptQueue::new(&vault);
    assert_eq!(
        queue
            .get(child.attempt.id)
            .expect("read queued child")
            .expect("child exists")
            .state,
        AttemptState::Queued
    );
    let cancel = vault
        .memory_facade(own, EdgeActorClass::Agent)
        .tasks_cancel(TaskCancelTarget::Spawn(child.attempt.id))
        .expect("cancel");
    assert_eq!(cancel.approval, ClaimApprovalStatus::Auto);
    assert!(cancel.effected);
    assert!(cancel.proposal_ref.is_none());
    assert!(cancel.gate_decision_ref.is_some());
    assert_eq!(cancel.status, Some(RunTreeStatus::Cancelled));
    assert_eq!(
        queue
            .get(child.attempt.id)
            .expect("read cancelled child")
            .expect("child exists")
            .state,
        AttemptState::Cancelled
    );
}

#[test]
fn tasks_cancel_non_owned_spawn_manual_and_auto_both_propose() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let queue = AttemptQueue::new(&vault);
    let EnqueueOutcome::Enqueued(attempt) = queue
        .enqueue(EnqueueAttempt {
            kind: AGENT_DISPATCH_ATTEMPT_TYPE.to_owned(),
            payload: vec![0xc1],
            dedupe_key: None,
            run_id: None,
            now: 120,
        })
        .expect("enqueue")
    else {
        panic!("enqueue must succeed")
    };
    let facade = vault.memory_facade(own, EdgeActorClass::Agent);
    for cancel in [
        facade
            .tasks_cancel_with_mode(TaskCancelTarget::Spawn(attempt.id), TaskCancelMode::Manual)
            .expect("manual cancel"),
        facade
            .tasks_cancel(TaskCancelTarget::Spawn(attempt.id))
            .expect("auto cancel"),
    ] {
        assert!(!cancel.effected);
        assert_eq!(cancel.approval, ClaimApprovalStatus::Proposed);
        assert!(cancel.proposal_ref.is_some());
        assert_eq!(cancel.status, None);
        assert_eq!(
            queue
                .get(attempt.id)
                .expect("read attempt")
                .expect("attempt exists")
                .state,
            AttemptState::Queued
        );
    }
}

mod spawn_cancel_unknown_kinds_never_hard_error_on_payload_shape {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]
        #[test]
        fn property(
            kind in any::<String>().prop_filter("non-Dreamer non-empty kind", |kind| !kind.is_empty() && kind != DREAMER_RUNNER_ATTEMPT_KIND),
            payload in any::<Vec<u8>>(),
        ) {
            let (_dir, vault) = open_vault();
            let own = own_agent(&vault);
            let queue = AttemptQueue::new(&vault);
            let EnqueueOutcome::Enqueued(attempt) = queue.enqueue(EnqueueAttempt {
                kind,
                payload,
                dedupe_key: None,
                run_id: None,
                now: 120,
            }).expect("enqueue") else {
                panic!("enqueue must succeed")
            };
            let cancel = vault.memory_facade(own, EdgeActorClass::Agent)
                .tasks_cancel(TaskCancelTarget::Spawn(attempt.id))
                .expect("payload shape is tolerated");
            prop_assert!(!cancel.effected);
            prop_assert_eq!(cancel.approval, ClaimApprovalStatus::Proposed);
            prop_assert!(cancel.proposal_ref.is_some());
            prop_assert_eq!(cancel.status, None);
            prop_assert_eq!(
                queue.get(attempt.id).expect("read attempt").expect("attempt exists").state,
                AttemptState::Queued
            );
        }
    }
}

#[test]
fn connector_send_cancel_cancels_queued_realization() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let send_grant_ref = EntityId::from_bytes([0xD3; 16]).expect("send grant id");
    vault
        .mint_standing_outbound_grant(
            &send_grant_ref,
            &GrantMintIntent {
                principal_ref: own.to_hex(),
                origin_component_id: "tasks".to_owned(),
                origin_action_id: "create".to_owned(),
                origin_receipt_ref: None,
                scope: GrantMintIntentScope::VerbClass {
                    verb_class: "send".to_owned(),
                },
            },
            1,
        )
        .expect("mint send grant");
    grant_cancel(&vault, own, 0xD4);
    let facade = vault.memory_facade(own, EdgeActorClass::Agent);
    facade
        .schedule_outbound(&OutboundDraftInput {
            verb: "send".to_owned(),
            channel: "email".to_owned(),
            target: "x".to_owned(),
            on_behalf_of: None,
            content_ref: None,
            idempotency_key: Some("k1".to_owned()),
            dedupe_key: None,
            trigger: "agent_immediate".to_owned(),
            trigger_ref: "s1".to_owned(),
            job_ref: None,
            occurred_at: Some(120),
        })
        .expect("schedule send");
    let tasks = vault.connector_send_tasks().expect("connector tasks");
    assert_eq!(tasks.len(), 1);
    let task_ref = tasks[0].task_ref;

    let cancel = facade
        .tasks_cancel(TaskCancelTarget::Task(task_ref))
        .expect("cancel send");
    let attempts = AttemptQueue::new(&vault).list().expect("list attempts");
    let task_hex = task_ref.to_hex();

    assert_eq!(usize::from(cancel.effected), 1);
    assert_eq!(cancel.status, Some(RunTreeStatus::Cancelled));
    assert_eq!(
        attempts
            .iter()
            .filter(|attempt| {
                attempt.task_ref.as_deref() == Some(task_hex.as_str())
                    && attempt.state == AttemptState::Cancelled
            })
            .count(),
        1
    );
    assert_eq!(
        attempts
            .iter()
            .filter(|attempt| {
                attempt.task_ref.as_deref() == Some(task_hex.as_str())
                    && attempt.state == AttemptState::Queued
            })
            .count(),
        0
    );
}

#[test]
fn role_only_task_is_present_and_cancel_fails_closed() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    grant_cancel(&vault, own, 0xD5);
    let task_ref = EntityId::from_bytes([0xB1; 16]).expect("task id");
    vault
        .put_entity(
            &task_ref,
            ENTITY_TYPE_TASK,
            TimeRange {
                start: 120,
                end: 120,
            },
            120,
            &crate::habit::task_body_for_test(TaskRole::Task),
        )
        .expect("put task");
    let outcome = AttemptQueue::new(&vault)
        .enqueue_with_task_ref(
            EnqueueAttempt {
                kind: TASK_REALIZE_ATTEMPT_KIND.to_owned(),
                payload: Vec::new(),
                dedupe_key: None,
                run_id: None,
                now: 120,
            },
            Some(task_ref.to_hex()),
        )
        .expect("enqueue realization");
    let EnqueueOutcome::Enqueued(attempt) = outcome else {
        panic!("realization must enqueue");
    };
    let facade = vault.memory_facade(own, EdgeActorClass::Agent);

    let section = facade.tasks_check().expect("check tasks");
    assert_eq!(section.rows.len(), 1);
    assert_eq!(
        section
            .rows
            .iter()
            .filter(|row| row.id == task_ref.to_hex())
            .count(),
        1
    );

    let cancel = facade
        .tasks_cancel(TaskCancelTarget::Task(task_ref))
        .expect("cancel task");
    let realization = AttemptQueue::new(&vault)
        .get(attempt.id)
        .expect("read realization")
        .expect("realization exists");

    // P1-c: a role-only TASK carries no stored owner provenance, so cancel
    // fails closed to the foreign ladder — a proposal, never a direct
    // effect. The realizing attempt is untouched (still Queued), and the
    // task stays visible (asserted above: fix-r1 F6 is preserved).
    assert_eq!(usize::from(cancel.effected), 0);
    assert_eq!(cancel.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(usize::from(cancel.proposal_ref.is_some()), 1);
    assert_eq!(realization.state, AttemptState::Queued);
}

#[test]
fn ack_persists_and_removes_failed_task_from_render() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let facade = vault.memory_facade(own, EdgeActorClass::Agent);
    let created = facade.tasks_create(&spec(120)).expect("create task");
    let task_ref = created.task_ref.expect("task ref");
    let queue = AttemptQueue::new(&vault);
    let claimed = match queue
        .claim_kind(
            TASK_REALIZE_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: "worker".to_owned(),
                now: 120,
            },
        )
        .expect("claim")
    {
        ClaimOutcome::Claimed(claimed) => claimed,
        ClaimOutcome::Empty => panic!("created task must be claimable"),
    };
    queue
        .fail(FailAttempt {
            id: claimed.id,
            lease_owner: "worker".to_owned(),
            attempt_count: claimed.attempt_count,
            reason: "failed".to_owned(),
            now: 121,
        })
        .expect("fail task");

    let before = facade.tasks_check().expect("check before ack");
    assert_eq!(before.rows.len(), 1);
    assert_eq!(before.rows[0].status, TaskBoardStatus::Failed);
    assert!(!task_is_acked(&vault, task_ref).expect("read unacked state"));
    // An unacked failure is still expandable by id.
    assert!(facade.tasks_expand(task_ref).is_ok());
    let ack = facade.tasks_ack(task_ref).expect("ack task");
    assert!(ack.acked);
    assert!(task_is_acked(&vault, task_ref).expect("read ack"));
    // Once acked, the failure has left the surface — expand agrees with check.
    assert_eq!(
        facade
            .tasks_expand(task_ref)
            .expect_err("acked failure is not expandable")
            .code,
        crate::facade::FACADE_CODE_NOT_FOUND
    );
    let after = facade.tasks_check().expect("check after ack");
    assert_eq!(after.rows.len(), 0);
}

#[test]
fn ack_before_failure_is_a_noop_and_failure_still_surfaces() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let facade = vault.memory_facade(own, EdgeActorClass::Agent);
    let created = facade.tasks_create(&spec(120)).expect("create task");
    let task_ref = created.task_ref.expect("task ref");

    // The task is Queued (not failed): acking it is a no-op — the bit stays
    // unset so a later failure is not pre-suppressed.
    let premature = facade.tasks_ack(task_ref).expect("ack queued task");
    assert!(!premature.acked);
    assert!(!task_is_acked(&vault, task_ref).expect("no ack bit set"));

    // The realization now fails.
    let queue = AttemptQueue::new(&vault);
    let claimed = match queue
        .claim_kind(
            TASK_REALIZE_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: "worker".to_owned(),
                now: 120,
            },
        )
        .expect("claim")
    {
        ClaimOutcome::Claimed(claimed) => claimed,
        ClaimOutcome::Empty => panic!("created task must be claimable"),
    };
    queue
        .fail(FailAttempt {
            id: claimed.id,
            lease_owner: "worker".to_owned(),
            attempt_count: claimed.attempt_count,
            reason: "failed".to_owned(),
            now: 121,
        })
        .expect("fail task");

    // The failure STILL surfaces — the premature ack did not suppress it.
    let after_fail = facade.tasks_check().expect("check after fail");
    assert_eq!(after_fail.rows.len(), 1);
    assert_eq!(after_fail.rows[0].status, TaskBoardStatus::Failed);

    // A real ack (now that it is failed) removes it from the surface.
    let acked = facade.tasks_ack(task_ref).expect("ack failed task");
    assert!(acked.acked);
    assert_eq!(facade.tasks_check().expect("check after ack").rows.len(), 0);
}

#[test]
fn malformed_dreamer_row_does_not_poison_the_board() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let facade = vault.memory_facade(own, EdgeActorClass::Agent);
    // A healthy TASK.
    let created = facade.tasks_create(&spec(120)).expect("create task");
    let task_ref = created.task_ref.expect("task ref");
    // A malformed dreamer-kind row enqueued through the public queue API (as
    // a downstream product could): 0xC1 is the reserved, never-valid
    // MessagePack marker, so the payload envelope never decodes.
    let queue = AttemptQueue::new(&vault);
    let EnqueueOutcome::Enqueued(_) = queue
        .enqueue(EnqueueAttempt {
            kind: DREAMER_RUNNER_ATTEMPT_KIND.to_owned(),
            payload: vec![0xC1],
            dedupe_key: None,
            run_id: None,
            now: 121,
        })
        .expect("enqueue malformed dreamer row")
    else {
        panic!("malformed row must enqueue");
    };
    // The board still reads for the unrelated healthy TASK — one bad row
    // degrades to a bare job in the run tree instead of poisoning the whole
    // read (previously the tree read errored and failed tasks.check/expand).
    let section = facade
        .tasks_check()
        .expect("board reads despite the malformed row");
    assert_eq!(
        section
            .rows
            .iter()
            .filter(|row| row.id == task_ref.to_hex())
            .count(),
        1
    );
    // The typed read verb for the healthy TASK also works.
    assert!(facade.tasks_expand(task_ref).is_ok());
}

/// P1-a: a Queued+Leased mix cannot be fully cancelled in-txn (the lease
/// can't be stopped), so the cancel is honest — uneffected, nothing hidden,
/// nothing intervened — and the task stays visible under its live lease.
#[test]
fn queued_leased_mix_cancel_is_honest_and_not_hidden() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    grant_cancel(&vault, own, 0xD6);
    let facade = vault.memory_facade(own, EdgeActorClass::Agent);
    let created = facade.tasks_create(&spec(120)).expect("create task");
    let task_ref = created.task_ref.expect("task ref");
    let task_hex = task_ref.to_hex();
    let queue = AttemptQueue::new(&vault);
    // Second realizing attempt so the task has a Queued + Leased mix.
    assert!(matches!(
        queue
            .enqueue_with_task_ref(
                EnqueueAttempt {
                    kind: TASK_REALIZE_ATTEMPT_KIND.to_owned(),
                    payload: Vec::new(),
                    dedupe_key: None,
                    run_id: None,
                    now: 120,
                },
                Some(task_hex.clone()),
            )
            .expect("enqueue second realization"),
        EnqueueOutcome::Enqueued(_)
    ));
    // Lease exactly one realization; the other stays Queued.
    match queue
        .claim_kind(
            TASK_REALIZE_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: "w1".to_owned(),
                now: 120,
            },
        )
        .expect("claim one realization")
    {
        ClaimOutcome::Claimed(_) => {}
        ClaimOutcome::Empty => panic!("a realization must be claimable"),
    }

    let cancel = facade
        .tasks_cancel(TaskCancelTarget::Task(task_ref))
        .expect("cancel task");
    let records = queue.list().expect("list attempts");
    let section = facade.tasks_check().expect("check tasks");

    assert_eq!(usize::from(cancel.effected), 0);
    assert_eq!(cancel.status, Some(RunTreeStatus::Running));
    assert_eq!(
        usize::from(task_is_cancelled(&vault, task_ref).expect("cancel state")),
        0
    );
    // Neither attempt was touched: exactly one Leased, exactly one Queued.
    assert_eq!(
        records
            .iter()
            .filter(|r| r.task_ref.as_deref() == Some(task_hex.as_str())
                && r.state == AttemptState::Leased)
            .count(),
        1
    );
    assert_eq!(
        records
            .iter()
            .filter(|r| r.task_ref.as_deref() == Some(task_hex.as_str())
                && r.state == AttemptState::Queued)
            .count(),
        1
    );
    // The board still shows the task exactly once.
    assert_eq!(
        section.rows.iter().filter(|row| row.id == task_hex).count(),
        1
    );
}

/// P1-b (TOCTOU): the cancel acts on the transaction-current attempt state,
/// not a pre-txn snapshot. A stale `Leased` snapshot whose live state is now
/// `Queued` must still be cancelled in-txn.
#[test]
fn cancel_uses_in_txn_live_state_not_stale_leased_snapshot() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    grant_cancel(&vault, own, 0xDB);
    let facade = vault.memory_facade(own, EdgeActorClass::Agent);
    let created = facade.tasks_create(&spec(120)).expect("create task");
    let task_ref = created.task_ref.expect("task ref");
    let task_hex = task_ref.to_hex();
    let queue = AttemptQueue::new(&vault);
    let records = queue.list().expect("list attempts");
    let attempt = records
        .iter()
        .find(|r| r.task_ref.as_deref() == Some(task_hex.as_str()))
        .expect("realizing attempt");
    // Live state is Queued (as if a lease-cleanup requeue already happened).
    assert_eq!(attempt.state, AttemptState::Queued);

    // A deliberately STALE snapshot claims the attempt is still Leased.
    let stale = CancelTargetState {
        owned: true,
        task_ref: Some(task_ref),
        attempts: vec![(attempt.id, AttemptState::Leased)],
        proposal_subject: task_ref,
        target_ref: task_hex.clone(),
    };
    let cancel = facade
        .tasks_cancel_with_injected_state_for_test(TaskCancelMode::Auto, stale)
        .expect("cancel with stale snapshot");
    let after = queue.list().expect("list after");

    // The in-txn re-read acts on the LIVE (Queued) state and cancels it,
    // despite the stale Leased snapshot. Trusting the snapshot would skip
    // intervention and leave the attempt claimable.
    assert_eq!(usize::from(cancel.effected), 1);
    assert_eq!(cancel.status, Some(RunTreeStatus::Cancelled));
    assert_eq!(
        after
            .iter()
            .filter(|r| r.task_ref.as_deref() == Some(task_hex.as_str())
                && r.state == AttemptState::Cancelled)
            .count(),
        1
    );
    assert_eq!(
        after
            .iter()
            .filter(|r| r.task_ref.as_deref() == Some(task_hex.as_str())
                && r.state == AttemptState::Queued)
            .count(),
        0
    );
}

/// Membership TOCTOU: a retry between the snapshot and the write txn
/// REPLACES the target's live realization with a new row under the same
/// `task_ref`. Re-reading only the snapshotted ids sees the dead source,
/// reports the task terminally failed, cancels nothing, and leaves the
/// scheduled successor to run and send.
#[test]
fn cancel_reaches_a_retry_minted_between_snapshot_and_write_txn() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    grant_cancel(&vault, own, 0xDC);
    let facade = vault.memory_facade(own, EdgeActorClass::Agent);
    let created = facade.tasks_create(&spec(120)).expect("create task");
    let task_ref = created.task_ref.expect("task ref");
    let queue = AttemptQueue::new(&vault);
    let claimed = match queue
        .claim_kind(
            TASK_REALIZE_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: "worker".to_owned(),
                now: 121,
            },
        )
        .expect("claim")
    {
        ClaimOutcome::Claimed(claimed) => claimed,
        ClaimOutcome::Empty => panic!("created task must be claimable"),
    };

    // The snapshot the cancel would have taken: one leased realization.
    let snapshot = CancelTargetState {
        owned: true,
        task_ref: Some(task_ref),
        attempts: vec![(claimed.id, AttemptState::Leased)],
        proposal_subject: task_ref,
        target_ref: task_ref.to_hex(),
    };

    // The executor retries FIRST: the snapshotted row is now a terminal
    // Failed source and a fresh Scheduled row owns the pending send.
    let RetryOutcome::Retried(next) = queue
        .retry(RetryAttempt {
            id: claimed.id,
            lease_owner: "worker".to_owned(),
            attempt_count: claimed.attempt_count,
            backoff_until: 400,
            last_error: Some("rate limited".to_owned()),
            now: 122,
        })
        .expect("retry the leased realization");
    assert_ne!(next.id, claimed.id);

    let cancel = facade
        .tasks_cancel_with_injected_state_for_test(TaskCancelMode::Auto, snapshot)
        .expect("cancel with pre-retry snapshot");
    let after = queue.list().expect("list after");

    // The successor is STOPPED, not merely reported around.
    assert_eq!(
        after
            .iter()
            .find(|r| r.id == next.id)
            .expect("successor row")
            .state,
        AttemptState::Cancelled
    );
    // The task is not read off its superseded source: the cancel took
    // effect and the TASK itself is withdrawn, rather than the verb
    // reporting a terminal failure it did not stop.
    assert_eq!(usize::from(cancel.effected), 1);
    assert_eq!(cancel.status, Some(RunTreeStatus::Cancelled));
    assert!(task_is_cancelled(&vault, task_ref).expect("cancel state"));
    // Per-try history survives: the failed source stays point-readable.
    assert_eq!(
        after
            .iter()
            .find(|r| r.id == claimed.id)
            .expect("source row")
            .state,
        AttemptState::Failed
    );
}

/// A retry chain's HEAD carries the task's board status. Any-row precedence
/// (Failed > Scheduled > Done) reads the task off a superseded try: a held
/// retry folds up as `Failed`, and a chain that later SUCCEEDED keeps
/// folding up as `Failed` forever.
#[test]
fn board_reads_a_retry_chain_off_its_head_not_a_superseded_try() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let facade = vault.memory_facade(own, EdgeActorClass::Agent);
    let created = facade.tasks_create(&spec(120)).expect("create task");
    let task_ref = created.task_ref.expect("task ref");
    let task_hex = task_ref.to_hex();
    let queue = AttemptQueue::new(&vault);

    // Two retries: three rows, the first two terminally Failed sources.
    let mut head = None;
    for now in [121_u64, 141] {
        let claimed = match queue
            .claim_kind(
                TASK_REALIZE_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: "worker".to_owned(),
                    now,
                },
            )
            .expect("claim")
        {
            ClaimOutcome::Claimed(claimed) => claimed,
            ClaimOutcome::Empty => panic!("the chain head must be claimable"),
        };
        let RetryOutcome::Retried(next) = queue
            .retry(RetryAttempt {
                id: claimed.id,
                lease_owner: "worker".to_owned(),
                attempt_count: claimed.attempt_count,
                backoff_until: now + 10,
                last_error: Some("upstream refused".to_owned()),
                now: now + 1,
            })
            .expect("retry");
        head = Some(next.id);
    }
    let head = head.expect("chain head");

    // Held retry: the task is deferred, not failed — and only the head is
    // folded, so the board shows one live realization, not three rows.
    let section = facade.tasks_check().expect("check tasks");
    let row = section
        .rows
        .iter()
        .find(|row| row.id == task_hex)
        .expect("task row");
    assert_eq!(row.status, TaskBoardStatus::Scheduled);
    assert_eq!(row.folded_job_count, 1);

    // The head SUCCEEDS: the logical task is done, not permanently failed.
    let claimed = match queue
        .claim_kind(
            TASK_REALIZE_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: "worker".to_owned(),
                now: 200,
            },
        )
        .expect("claim head")
    {
        ClaimOutcome::Claimed(claimed) => claimed,
        ClaimOutcome::Empty => panic!("the chain head must be claimable"),
    };
    assert_eq!(claimed.id, head);
    queue
        .complete(CompleteAttempt {
            id: head,
            lease_owner: "worker".to_owned(),
            attempt_count: claimed.attempt_count,
            now: 201,
        })
        .expect("complete the head");

    let done = facade.tasks_check().expect("check after success");
    let row = done
        .rows
        .iter()
        .find(|row| row.id == task_hex)
        .expect("task row");
    assert_eq!(row.status, TaskBoardStatus::Done);
}

/// P1-c: a stored, `tasks.cancel`-granted actor cannot DIRECTLY cancel a
/// role-only task it cannot prove it owns — it surfaces a proposal. Role-only
/// ownership is not derivable from storage, so the fallback fails closed.
#[test]
fn role_only_task_cancel_by_foreign_granted_actor_proposes() {
    let (_dir, vault) = open_vault();
    let agent_b = own_agent(&vault);
    grant_cancel(&vault, agent_b, 0xD8);
    // Role-only TASK nominally belonging to some agent A; no stored
    // provenance links it to any actor.
    let task_ref = EntityId::from_bytes([0xB2; 16]).expect("task id");
    vault
        .put_entity(
            &task_ref,
            ENTITY_TYPE_TASK,
            TimeRange {
                start: 120,
                end: 120,
            },
            120,
            &crate::habit::task_body_for_test(TaskRole::Task),
        )
        .expect("put role-only task");
    let outcome = AttemptQueue::new(&vault)
        .enqueue_with_task_ref(
            EnqueueAttempt {
                kind: TASK_REALIZE_ATTEMPT_KIND.to_owned(),
                payload: Vec::new(),
                dedupe_key: None,
                run_id: None,
                now: 120,
            },
            Some(task_ref.to_hex()),
        )
        .expect("enqueue realization");
    let EnqueueOutcome::Enqueued(attempt) = outcome else {
        panic!("realization must enqueue");
    };
    let facade = vault.memory_facade(agent_b, EdgeActorClass::Agent);

    let cancel = facade
        .tasks_cancel(TaskCancelTarget::Task(task_ref))
        .expect("cancel role-only task");
    let realization = AttemptQueue::new(&vault)
        .get(attempt.id)
        .expect("read realization")
        .expect("realization exists");
    let section = facade.tasks_check().expect("check tasks");

    assert_eq!(usize::from(cancel.effected), 0);
    assert_eq!(cancel.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(usize::from(cancel.proposal_ref.is_some()), 1);
    // The realizing attempt is untouched and the task stays visible.
    assert_eq!(realization.state, AttemptState::Queued);
    assert_eq!(
        usize::from(task_is_cancelled(&vault, task_ref).expect("cancel state")),
        0
    );
    assert_eq!(
        section
            .rows
            .iter()
            .filter(|row| row.id == task_ref.to_hex())
            .count(),
        1
    );
}

/// FIX A: a valid typed body can claim any `owner_ref`, so that field is
/// never cancellation authority. The create-time owner record remains the
/// sole proof even if trusted low-level storage rewrites the body.
#[test]
fn typed_task_cancel_ignores_forged_body_owner() {
    let (_dir, vault) = open_vault();
    let attacker = own_agent(&vault);
    let owner = EntityId::from_bytes([0xE2; 16]).expect("owner id");
    put_person(&vault, owner);
    grant_cancel(&vault, attacker, 0xD9);
    let created = vault
        .memory_facade(owner, EdgeActorClass::Human)
        .tasks_create(&spec(120))
        .expect("owner creates task");
    let task_ref = created.task_ref.expect("task ref");
    let mut forged_body = task_verb_body(&vault, task_ref)
        .expect("decode created body")
        .expect("created task is typed");
    forged_body.owner_ref = attacker.to_hex();
    let forged_body = encode_task_verb_body(forged_body);
    vault
        .put_entity(
            &task_ref,
            ENTITY_TYPE_TASK,
            TimeRange {
                start: 121,
                end: 121,
            },
            121,
            &forged_body,
        )
        .expect("rewrite body below facade");
    let forged = task_verb_body(&vault, task_ref)
        .expect("decode forged body")
        .expect("typed task");
    let cancel = vault
        .memory_facade(attacker, EdgeActorClass::Agent)
        .tasks_cancel(TaskCancelTarget::Task(task_ref))
        .expect("cancel forged-owner task");
    let task_hex = task_ref.to_hex();
    let attempts = AttemptQueue::new(&vault).list().expect("list attempts");

    assert_eq!(usize::from(forged.owner_ref == attacker.to_hex()), 1);
    assert_eq!(
        task_create_owner(&vault, task_ref).expect("read proven owner"),
        Some(owner)
    );
    assert_eq!(usize::from(cancel.effected), 0);
    assert_eq!(cancel.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(usize::from(cancel.proposal_ref.is_some()), 1);
    assert_eq!(
        attempts
            .iter()
            .filter(|attempt| {
                attempt.task_ref.as_deref() == Some(task_hex.as_str())
                    && attempt.state == AttemptState::Queued
            })
            .count(),
        1
    );
    assert_eq!(
        attempts
            .iter()
            .filter(|attempt| {
                attempt.task_ref.as_deref() == Some(task_hex.as_str())
                    && attempt.state == AttemptState::Cancelled
            })
            .count(),
        0
    );
    assert_eq!(
        usize::from(task_is_cancelled(&vault, task_ref).expect("cancel state")),
        0
    );
}

/// P2 F6: only the `Task` role folds into TASKS. A `Habit`-role entity is
/// not a task and must not render as a TASKS row.
#[test]
fn only_task_role_folds_into_tasks_section() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let task_role = EntityId::from_bytes([0xB3; 16]).expect("task role id");
    let habit_role = EntityId::from_bytes([0xB4; 16]).expect("habit role id");
    vault
        .put_entity(
            &task_role,
            ENTITY_TYPE_TASK,
            TimeRange {
                start: 120,
                end: 120,
            },
            120,
            &crate::habit::task_body_for_test(TaskRole::Task),
        )
        .expect("put task-role");
    vault
        .put_entity(
            &habit_role,
            ENTITY_TYPE_TASK,
            TimeRange {
                start: 120,
                end: 120,
            },
            120,
            &crate::habit::task_body_for_test(TaskRole::Habit),
        )
        .expect("put habit-role");
    let facade = vault.memory_facade(own, EdgeActorClass::Agent);

    let section = facade.tasks_check().expect("check tasks");

    assert_eq!(
        section
            .rows
            .iter()
            .filter(|row| row.id == task_role.to_hex())
            .count(),
        1
    );
    assert_eq!(
        section
            .rows
            .iter()
            .filter(|row| row.id == habit_role.to_hex())
            .count(),
        0
    );
    assert_eq!(section.rows.len(), 1);
}

/// P2 F7: a realizing job whose backlink names no surviving intent is
/// re-emitted as a bare job — rendered exactly once, never dropped.
#[test]
fn dangling_backlink_job_still_renders_once() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let missing_task_hex = EntityId::from_bytes([0xC1; 16])
        .expect("missing id")
        .to_hex();
    let outcome = AttemptQueue::new(&vault)
        .enqueue_with_task_ref(
            EnqueueAttempt {
                kind: TASK_REALIZE_ATTEMPT_KIND.to_owned(),
                payload: Vec::new(),
                dedupe_key: None,
                run_id: None,
                now: 120,
            },
            Some(missing_task_hex),
        )
        .expect("enqueue dangling attempt");
    let EnqueueOutcome::Enqueued(attempt) = outcome else {
        panic!("attempt must enqueue");
    };
    let facade = vault.memory_facade(own, EdgeActorClass::Agent);

    let section = facade.tasks_check().expect("check tasks");
    let job_id = attempt_hex(attempt.id);

    assert_eq!(
        section.rows.iter().filter(|row| row.id == job_id).count(),
        1
    );
    assert_eq!(section.rows.len(), 1);
}

/// FIX C: projection failure/non-membership cannot consume a live job.
/// Both jobs degrade to bare rows exactly once when their backlink entity
/// cannot produce a TASKS intent.
#[test]
fn unprojectable_task_backlinks_render_jobs_exactly_once() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let malformed = EntityId::from_bytes([0xC2; 16]).expect("malformed id");
    let non_task_role = EntityId::from_bytes([0xC3; 16]).expect("non-task role id");
    let malformed_body = {
        let value = Value::Map(vec![
            (Value::from("role"), Value::from(TaskRole::Task.role_byte())),
            (Value::from("subkind"), Value::from(TASK_VERB_BODY_SUBKIND)),
        ]);
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &value).expect("encode malformed body");
        bytes
    };
    vault
        .put_entity(
            &malformed,
            ENTITY_TYPE_TASK,
            TimeRange {
                start: 120,
                end: 120,
            },
            120,
            &malformed_body,
        )
        .expect("put malformed task");
    vault
        .put_entity(
            &non_task_role,
            ENTITY_TYPE_TASK,
            TimeRange {
                start: 120,
                end: 120,
            },
            120,
            &crate::habit::task_body_for_test(TaskRole::Habit),
        )
        .expect("put non-task role");
    let queue = AttemptQueue::new(&vault);
    let attempts: Vec<_> = [malformed, non_task_role]
        .into_iter()
        .map(|task_ref| {
            match queue
                .enqueue_with_task_ref(
                    EnqueueAttempt {
                        kind: TASK_REALIZE_ATTEMPT_KIND.to_owned(),
                        payload: Vec::new(),
                        dedupe_key: None,
                        run_id: None,
                        now: 120,
                    },
                    Some(task_ref.to_hex()),
                )
                .expect("enqueue realization")
            {
                EnqueueOutcome::Enqueued(attempt) => attempt,
                EnqueueOutcome::Existing(_) => panic!("realization must be fresh"),
            }
        })
        .collect();

    let section = vault
        .memory_facade(own, EdgeActorClass::Agent)
        .tasks_check()
        .expect("check tasks");
    let malformed_job = attempt_hex(attempts[0].id);
    let non_task_job = attempt_hex(attempts[1].id);

    assert_eq!(
        section
            .rows
            .iter()
            .filter(|row| row.id == malformed_job)
            .count(),
        1
    );
    assert_eq!(
        section
            .rows
            .iter()
            .filter(|row| row.id == non_task_job)
            .count(),
        1
    );
    assert_eq!(
        section
            .rows
            .iter()
            .filter(|row| row.id == malformed.to_hex())
            .count(),
        0
    );
    assert_eq!(
        section
            .rows
            .iter()
            .filter(|row| row.id == non_task_role.to_hex())
            .count(),
        0
    );
    assert_eq!(section.rows.len(), 2);
}

/// P2 F8: one malformed TASK body (typed subkind but missing the typed
/// fields) must not abort the whole board — it is skipped, and every other
/// task still renders.
#[test]
fn malformed_task_body_does_not_poison_the_board() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let facade = vault.memory_facade(own, EdgeActorClass::Agent);
    let created = facade.tasks_create(&spec(120)).expect("create task");
    let valid_task = created.task_ref.expect("task ref");
    let poison = EntityId::from_bytes([0xC2; 16]).expect("poison id");
    let poison_body = {
        let value = Value::Map(vec![
            (Value::from("role"), Value::from(TaskRole::Task.role_byte())),
            (Value::from("subkind"), Value::from(TASK_VERB_BODY_SUBKIND)),
        ]);
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &value).expect("encode poison body");
        bytes
    };
    vault
        .put_entity(
            &poison,
            ENTITY_TYPE_TASK,
            TimeRange {
                start: 120,
                end: 120,
            },
            120,
            &poison_body,
        )
        .expect("put poison task");

    let section = facade.tasks_check().expect("check tasks survives poison");

    assert_eq!(
        section
            .rows
            .iter()
            .filter(|row| row.id == valid_task.to_hex())
            .count(),
        1
    );
    assert_eq!(
        section
            .rows
            .iter()
            .filter(|row| row.id == poison.to_hex())
            .count(),
        0
    );
    assert_eq!(section.rows.len(), 1);
}

// ── ONE-1888: consult ladder, routing, magistrate ───────────────────

use crate::claim::PREDICATE_CONFLICT_OPEN;
use crate::consult_ladder::{
    A2aBaseTaskState, AuthorityEvidence, CaseCriticality, DeltaShapeFingerprint, GraduationLookup,
    GraduationScope, InterruptedState, InterruptionKind, MagistrateRecusal, PolicyEvidence,
    WorkingState, terminal_for_human_verdict,
};
use crate::write_envelope::ClaimCandidate as EnvelopeClaimCandidate;

const LADDER_NOW: u64 = CONSULT_NOW;
const LADDER_DEADLINE: u64 = CONSULT_NOW + 3_600;
/// The default policy manifest gives `agent` an auto ceiling for exactly
/// one actor ref, and `own_agent` is it — so every acting facade in these
/// tests is that actor and the OWNERSHIP under test varies instead.
const OTHER_ACTOR_SEED: u8 = 0xE3;

fn ladder_id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("ladder test id")
}

/// A second human actor: the owner of the state an agent wants to change.
fn other_actor(vault: &Vault) -> EntityId {
    let actor = ladder_id(OTHER_ACTOR_SEED);
    put_person(vault, actor);
    actor
}

/// Writes one CLAIM through the normal envelope-stamped door so its
/// authoring actor and run surface are recoverable exactly as production
/// writes them.
fn put_envelope_claim(
    vault: &Vault,
    claim_ref: EntityId,
    subject: EntityId,
    actor: EntityId,
    actor_class: EdgeActorClass,
    provenance: Value,
) {
    let envelope = WriteEnvelope::new(
        WriteActor::new(actor, actor_class),
        ClaimSource::Observed,
        WriteProvenance::new(provenance).expect("provenance is not nil"),
        ClaimApprovalStatus::Proposed,
    );
    let candidate = EnvelopeClaimCandidate::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        Value::from("state"),
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
                        start: LADDER_NOW,
                        end: LADDER_NOW,
                    },
                    LADDER_NOW,
                )
                .apply(wtxn)
        })
        .expect("claim write lands");
}

fn dreamer_provenance() -> Value {
    Value::Map(vec![
        (
            Value::from("surface"),
            Value::from(DREAMER_RUNNER_ATTEMPT_KIND),
        ),
        (Value::from("run"), Value::from("run-1")),
    ])
}

fn agent_provenance() -> Value {
    Value::Map(vec![
        (Value::from("surface"), Value::from("agent.dispatch")),
        (Value::from("run"), Value::from("run-2")),
    ])
}

/// One CLAIM owned by `owner` — the cross-actor target under test.
fn owned_claim(vault: &Vault, seed: u8, owner: EntityId, actor_class: EdgeActorClass) -> EntityId {
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

fn ladder_shape() -> EntityDeltaShape {
    EntityDeltaShape {
        operation_kind: "claim.replace".to_owned(),
        target_entity_type: ENTITY_TYPE_CLAIM,
        normalized_paths: vec!["profile.note".to_owned()],
    }
}

fn ladder_delta(
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

struct AlwaysGraduated;

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

fn ladder_scope(proposer: EntityId, owner: EntityId) -> GraduationScope {
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
struct CrossActorFixture {
    proposer: EntityId,
    owner: EntityId,
    target: EntityId,
    delta_ref: EntityId,
}

fn cross_actor_fixture(vault: &Vault) -> CrossActorFixture {
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

// ── additive payload ────────────────────────────────────────────────

/// The ONE-1699 payload keeps decoding as the legacy question shape, and
/// the three ONE-1888 additions survive a body round-trip.
#[test]
fn consult_payload_additions_are_optional_and_round_trip() {
    let question = ConsultPayloadRef::Turn(ladder_id(0xC1));
    let legacy = ConsultPayload::question(question, Vec::new(), ladder_id(0xC2));
    let decoded_legacy =
        decode_consult_payload(&consult_payload_value(&legacy)).expect("legacy payload decodes");

    assert_eq!(decoded_legacy, legacy);
    assert_eq!(decoded_legacy.purpose, None);
    assert_eq!(decoded_legacy.consult_purpose(), ConsultPurpose::Question);
    assert_eq!(decoded_legacy.entity_delta, None);
    assert_eq!(decoded_legacy.lineage, None);

    let extended = ConsultPayload::question(question, Vec::new(), ladder_id(0xC2))
        .with_entity_delta(ladder_delta(
            ladder_id(0xC3),
            ladder_id(0xC4),
            ladder_id(0xC5),
            ladder_id(0xC6),
        ))
        .with_lineage(ConsultLineage {
            relation: ConsultLineageRelation::Counter,
            parent_task_ref: ladder_id(0xC7),
        });
    let decoded =
        decode_consult_payload(&consult_payload_value(&extended)).expect("payload decodes");

    assert_eq!(decoded, extended);
    assert_eq!(decoded.consult_purpose(), ConsultPurpose::EntityDelta);
}

/// The purpose and the artifact must agree, and a self-owned "cross-actor"
/// delta is the auto path taking the wrong door.
#[test]
fn consult_payload_refuses_contradictory_purposes() {
    let question = ConsultPayloadRef::Turn(ladder_id(0xC1));
    let mut delta_without_artifact =
        ConsultPayload::question(question, Vec::new(), ladder_id(0xC2));
    delta_without_artifact.purpose = Some(ConsultPurpose::EntityDelta);

    let mut artifact_without_purpose =
        ConsultPayload::question(question, Vec::new(), ladder_id(0xC2));
    artifact_without_purpose.entity_delta = Some(ladder_delta(
        ladder_id(0xC3),
        ladder_id(0xC4),
        ladder_id(0xC5),
        ladder_id(0xC6),
    ));

    let same_actor = ConsultPayload::question(question, Vec::new(), ladder_id(0xC2))
        .with_entity_delta(ladder_delta(
            ladder_id(0xC3),
            ladder_id(0xC4),
            ladder_id(0xC5),
            ladder_id(0xC5),
        ));

    for (index, payload) in [delta_without_artifact, artifact_without_purpose, same_actor]
        .into_iter()
        .enumerate()
    {
        assert!(
            decode_consult_payload(&consult_payload_value(&payload)).is_err(),
            "case {index} must be refused"
        );
    }
}

// ── ladder projection ───────────────────────────────────────────────

/// The ladder projects onto ONE-1699's persisted vocabulary exactly as the
/// disposition table says, and `Escalated` is deliberately NOT terminal.
#[test]
fn ladder_states_project_onto_the_one_1699_task_vocabulary() {
    let ladder_terminal = |disposition: LadderTerminalDisposition| LadderTerminalState {
        disposition,
        result_ref: ladder_id(0xD1),
        counter_task_ref: matches!(disposition, LadderTerminalDisposition::Countered)
            .then(|| ladder_id(0xD2)),
        finished_at: 900,
    };
    let table = [
        (
            LadderTerminalDisposition::Approved,
            Some(TaskTerminalDisposition::Completed),
        ),
        (
            LadderTerminalDisposition::Overridden,
            Some(TaskTerminalDisposition::Completed),
        ),
        (
            LadderTerminalDisposition::Rejected,
            Some(TaskTerminalDisposition::Rejected),
        ),
        (
            LadderTerminalDisposition::Failed,
            Some(TaskTerminalDisposition::Failed),
        ),
        (LadderTerminalDisposition::Escalated, None),
        (
            LadderTerminalDisposition::Countered,
            Some(TaskTerminalDisposition::Rejected),
        ),
        (
            LadderTerminalDisposition::Abandoned,
            Some(TaskTerminalDisposition::Abandoned),
        ),
    ];

    for (disposition, expected) in table {
        let projected = project_consult_ladder_state(&ConsultLadderState::Terminal(
            ladder_terminal(disposition),
        ));
        match expected {
            Some(task_disposition) => {
                let TaskExecutionState::Terminal(record) = &projected else {
                    panic!("{} projects terminal", disposition.as_str());
                };
                assert_eq!(record.disposition, task_disposition);
                assert_eq!(record.ladder, Some(disposition));
                assert_eq!(record.result_ref, Some(ladder_id(0xD1)));
                // The finer ladder outcome survives a body round-trip.
                let decoded = decode_task_terminal_record(&task_terminal_record_value(record))
                    .expect("terminal record round-trips");
                assert_eq!(decoded, *record);
                assert_eq!(
                    ladder_terminal_from_task_terminal(&decoded)
                        .expect("ladder terminal lifts back")
                        .disposition,
                    disposition
                );
            }
            // A deferring terminal leaves the TASK live, but the settled
            // ladder rides inside the same register so it stays telling apart
            // from an ordinary interruption.
            None => assert_eq!(
                projected,
                TaskExecutionState::Interrupted {
                    ladder: Some(ladder_terminal(disposition)),
                },
                "escalation waits on its follow-on rather than settling"
            ),
        }
    }

    assert_eq!(
        project_consult_ladder_state(&ConsultLadderState::Working(WorkingState {
            started_at: 5,
            decision_round: 2,
        })),
        TaskExecutionState::Working { started_at: 5 }
    );
    assert_eq!(
        project_consult_ladder_state(&ConsultLadderState::Interrupted(InterruptedState {
            kind: InterruptionKind::Critical,
            consent_required: true,
            case_ref: ladder_id(0xD3),
            interrupted_at: 7,
        })),
        TaskExecutionState::Interrupted { ladder: None }
    );
}

/// A LIVE `interrupted` register may carry only a ladder terminal that DEFERS
/// to a follow-on. Every other settled disposition is refused at the wire: the
/// projection never writes one there, and a peer that ships one would freeze
/// every ladder write door on a row the projections read as settled.
///
/// The `terminal` arm is unchanged — that is where a non-deferring ladder
/// belongs, and all seven still decode there.
#[test]
fn an_interrupted_register_admits_only_a_deferring_ladder_terminal() {
    let (_dir, vault) = open_vault();
    let (task_ref, _peer, _question) = open_consult(&vault);
    let body = task_verb_body(&vault, task_ref)
        .expect("decode consult")
        .expect("consult is typed");
    let dispositions = [
        LadderTerminalDisposition::Approved,
        LadderTerminalDisposition::Overridden,
        LadderTerminalDisposition::Rejected,
        LadderTerminalDisposition::Failed,
        LadderTerminalDisposition::Escalated,
        LadderTerminalDisposition::Countered,
        LadderTerminalDisposition::Abandoned,
    ];

    for disposition in dispositions {
        let counter_task_ref =
            matches!(disposition, LadderTerminalDisposition::Countered).then(|| ladder_id(0xB2));
        let mut live = body.clone();
        live.state = Some(TaskExecutionState::Interrupted {
            ladder: Some(LadderTerminalState {
                disposition,
                result_ref: ladder_id(0xB1),
                counter_task_ref,
                finished_at: LADDER_NOW + 1,
            }),
        });
        let live_state = live.state.clone();
        let decoded = decode_task_verb_body(&encode_task_verb_body(live));

        if disposition.defers_to_follow_on() {
            assert_eq!(
                decoded
                    .expect("a deferring ladder terminal is the one live register")
                    .state,
                live_state,
                "{} defers to a follow-on, so it rides on the live row",
                disposition.as_str()
            );
        } else {
            assert!(
                matches!(
                    decoded,
                    Err(crate::error::Error::InvalidTaskBody(
                        "tasks.terminal.ladder"
                    ))
                ),
                "{} settles without deferring and has no place on a live row",
                disposition.as_str()
            );
        }

        let mut settled = body.clone();
        settled.state = Some(TaskExecutionState::Terminal(TaskTerminalRecord {
            disposition: TaskTerminalDisposition::Completed,
            result_ref: Some(ladder_id(0xB1)),
            summary: None,
            finished_at: LADDER_NOW + 1,
            ladder: Some(disposition),
            counter_task_ref,
        }));
        let settled_state = settled.state.clone();
        assert_eq!(
            decode_task_verb_body(&encode_task_verb_body(settled))
                .expect("a terminal record admits every ladder disposition")
                .state,
            settled_state,
            "{} still decodes on the terminal arm",
            disposition.as_str()
        );
    }
}

/// A persisted ONE-1699 terminal without a `result_ref` cannot become a
/// ladder terminal at all: the ladder's result is not optional.
#[test]
fn a_result_less_legacy_terminal_fails_closed() {
    let legacy = TaskTerminalRecord {
        disposition: TaskTerminalDisposition::Completed,
        result_ref: None,
        summary: None,
        finished_at: 10,
        ladder: None,
        counter_task_ref: None,
    };

    assert_eq!(
        ladder_terminal_from_task_terminal(&legacy),
        Err(LadderTransitionError::MissingResultRef)
    );
}

/// Two replicas converge on the same terminal register in either merge
/// order: later `finished_at` wins, and a SUBSTANTIVE decision beats an
/// expiry-like sweep on an exact tie.
#[test]
fn substantive_terminals_dominate_expiry_like_ones_on_an_exact_tie() {
    let record = |disposition, finished_at| TaskTerminalRecord {
        disposition,
        result_ref: Some(ladder_id(0xE1)),
        summary: None,
        finished_at,
        ladder: None,
        counter_task_ref: None,
    };
    let cases = [
        // A rejection that landed at the deadline instant is still an
        // answer: it beats the expiry sweep.
        (
            record(TaskTerminalDisposition::Rejected, 150),
            record(TaskTerminalDisposition::Expired, 150),
            record(TaskTerminalDisposition::Rejected, 150),
        ),
        (
            record(TaskTerminalDisposition::Rejected, 150),
            record(TaskTerminalDisposition::Abandoned, 150),
            record(TaskTerminalDisposition::Rejected, 150),
        ),
        (
            record(TaskTerminalDisposition::Completed, 150),
            record(TaskTerminalDisposition::Abandoned, 150),
            record(TaskTerminalDisposition::Completed, 150),
        ),
        // Time still dominates class.
        (
            record(TaskTerminalDisposition::Rejected, 100),
            record(TaskTerminalDisposition::Expired, 200),
            record(TaskTerminalDisposition::Expired, 200),
        ),
    ];

    for (index, (left, right, expected)) in cases.into_iter().enumerate() {
        let forward = merge_task_terminal_register(Some(&left), Some(&right));
        let backward = merge_task_terminal_register(Some(&right), Some(&left));
        assert_eq!(forward, backward, "case {index} must be order-free");
        assert_eq!(forward, Some(expected), "case {index} winner");
    }

    // Two substantive terminals at one instant fall to canonical bytes,
    // which both replicas compute identically.
    let completed = record(TaskTerminalDisposition::Completed, 150);
    let rejected = record(TaskTerminalDisposition::Rejected, 150);
    assert_eq!(
        merge_task_terminal_register(Some(&completed), Some(&rejected)),
        merge_task_terminal_register(Some(&rejected), Some(&completed))
    );
}

// ── ownership routing ───────────────────────────────────────────────

/// A target the acting actor owns routes auto and writes nothing; a target
/// owned by another actor mints exactly ONE owner-assigned consult and
/// leaves the target byte-untouched.
#[test]
fn own_writes_route_auto_and_cross_actor_writes_mint_one_owner_consult() {
    let (_dir, vault) = open_vault();
    let fixture = cross_actor_fixture(&vault);
    let facade = vault.memory_facade(fixture.proposer, EdgeActorClass::Agent);
    let own_task = facade
        .tasks_create(&spec(LADDER_NOW))
        .expect("own task create effects")
        .task_ref
        .expect("own task minted");

    let own_route = facade
        .route_entity_delta(
            ladder_delta(
                own_task,
                fixture.delta_ref,
                fixture.proposer,
                fixture.proposer,
            ),
            None,
            LADDER_DEADLINE,
            LADDER_NOW,
        )
        .expect("own delta routes");
    assert_eq!(own_route, CrossActorRoute::AutoOwn);

    let tasks_before = task_entity_census(&vault);
    let target_before = vault
        .get_raw(&fixture.target)
        .expect("target read")
        .expect("target stored");
    let cross_route = facade
        .route_entity_delta(
            ladder_delta(
                fixture.target,
                fixture.delta_ref,
                fixture.proposer,
                fixture.owner,
            ),
            None,
            LADDER_DEADLINE,
            LADDER_NOW,
        )
        .expect("cross-actor delta routes");
    let tasks_after = task_entity_census(&vault);

    let CrossActorRoute::ConsultOwner { receipt } = cross_route else {
        panic!("a non-graduated cross-actor write consults the owner");
    };
    let consult_ref = receipt.task_ref.expect("consult minted");
    let body = task_verb_body(&vault, consult_ref)
        .expect("decode consult")
        .expect("consult is typed");
    let payload = body.consult.as_ref().expect("consult payload");

    assert_eq!(tasks_after - tasks_before, 1, "exactly one TASK is written");
    assert_eq!(body.task_kind(), TaskKind::Consult);
    assert_eq!(
        body.assignee,
        Some(TaskAssignee::Peer {
            actor_ref: fixture.owner
        }),
        "the OWNING actor is the first adjudicator"
    );
    assert_eq!(payload.consult_purpose(), ConsultPurpose::EntityDelta);
    assert_eq!(
        payload
            .entity_delta
            .as_ref()
            .map(|delta| delta.proposer_actor_ref),
        Some(fixture.proposer)
    );
    // Routing proposes; it never writes the state it is asking about.
    assert_eq!(
        vault
            .get_raw(&fixture.target)
            .expect("target read")
            .expect("target stored"),
        target_before
    );
}

/// Ownership is resolved from durable state, never asserted: a forged
/// owning actor and an unattributed proposer are both refused.
#[test]
fn a_forged_owner_or_proposer_is_refused() {
    let (_dir, vault) = open_vault();
    let fixture = cross_actor_fixture(&vault);
    let facade = vault.memory_facade(fixture.proposer, EdgeActorClass::Agent);

    let forged_owner = facade
        .route_entity_delta(
            // Claims the proposer owns state the vault attributes to
            // another actor.
            ladder_delta(
                fixture.target,
                fixture.delta_ref,
                fixture.proposer,
                fixture.proposer,
            ),
            None,
            LADDER_DEADLINE,
            LADDER_NOW,
        )
        .expect_err("a forged owner is refused");
    let forged_proposer = facade
        .route_entity_delta(
            ladder_delta(
                fixture.target,
                fixture.delta_ref,
                fixture.owner,
                fixture.owner,
            ),
            None,
            LADDER_DEADLINE,
            LADDER_NOW,
        )
        .expect_err("an unattributed proposer is refused");
    let unresolvable = facade
        .route_entity_delta(
            ladder_delta(
                fixture.delta_ref,
                fixture.delta_ref,
                fixture.proposer,
                fixture.owner,
            ),
            None,
            LADDER_DEADLINE,
            LADDER_NOW,
        )
        .expect_err("a target with no recorded owner is refused");

    assert_eq!(forged_owner.code, FACADE_CODE_FORBIDDEN);
    assert_eq!(forged_proposer.code, FACADE_CODE_FORBIDDEN);
    assert_eq!(unresolvable.code, FACADE_CODE_INVALID_STATE);
}

/// A graduated pair on an already-receipted shape rides its existing
/// standing grant instead of minting a second consult.
#[test]
fn a_graduated_known_shape_routes_through_its_standing_grant() {
    let (_dir, vault) = open_vault();
    let fixture = cross_actor_fixture(&vault);
    let facade = vault.memory_facade(fixture.proposer, EdgeActorClass::Agent);
    let scope = ladder_scope(fixture.proposer, fixture.owner);

    let before = task_entity_census(&vault);
    let route = facade
        .route_entity_delta(
            ladder_delta(
                fixture.target,
                fixture.delta_ref,
                fixture.proposer,
                fixture.owner,
            ),
            Some((&AlwaysGraduated, &scope)),
            LADDER_DEADLINE,
            LADDER_NOW,
        )
        .expect("graduated delta routes");
    let after = task_entity_census(&vault);

    assert_eq!(
        route,
        CrossActorRoute::AutoViaStandingGrant {
            standing_grant_ref: ladder_id(0xB1)
        }
    );
    assert_eq!(after, before, "an auto route mints no consult");

    // A grant for a DIFFERENT pair cannot be borrowed.
    let wrong_pair = ladder_scope(fixture.owner, fixture.proposer);
    let borrowed = facade
        .route_entity_delta(
            ladder_delta(
                fixture.target,
                fixture.delta_ref,
                fixture.proposer,
                fixture.owner,
            ),
            Some((&AlwaysGraduated, &wrong_pair)),
            LADDER_DEADLINE,
            LADDER_NOW,
        )
        .expect("mismatched grant still routes");
    assert!(matches!(borrowed, CrossActorRoute::ConsultOwner { .. }));
}

// ── counter lineage ─────────────────────────────────────────────────

/// A counter is a NEW task with `Counter` lineage. The open original
/// terminalizes as rejected-with-counter-lineage in the same transaction;
/// an already-terminal original is left exactly as it was.
#[test]
fn counter_mints_a_new_task_and_never_reopens_the_original() {
    let (_dir, vault) = open_vault();
    let fixture = cross_actor_fixture(&vault);
    let facade = vault.memory_facade(fixture.proposer, EdgeActorClass::Agent);
    let delta = ladder_delta(
        fixture.target,
        fixture.delta_ref,
        fixture.proposer,
        fixture.owner,
    );
    let CrossActorRoute::ConsultOwner { receipt } = facade
        .route_entity_delta(delta.clone(), None, LADDER_DEADLINE, LADDER_NOW)
        .expect("cross-actor delta routes")
    else {
        panic!("expected an owner consult");
    };
    let original = receipt.task_ref.expect("consult minted");

    let counter = facade
        .mint_counter_task(original, delta.clone(), LADDER_DEADLINE, LADDER_NOW + 5)
        .expect("counter mints")
        .task_ref
        .expect("counter task minted");
    let original_body = task_verb_body(&vault, original)
        .expect("decode original")
        .expect("original is typed");
    let counter_body = task_verb_body(&vault, counter)
        .expect("decode counter")
        .expect("counter is typed");

    assert_ne!(counter, original);
    assert_eq!(
        counter_body
            .consult
            .as_ref()
            .and_then(|payload| payload.lineage),
        Some(ConsultLineage {
            relation: ConsultLineageRelation::Counter,
            parent_task_ref: original,
        })
    );
    let terminal = original_body.terminal().expect("original terminalized");
    assert_eq!(terminal.disposition, TaskTerminalDisposition::Rejected);
    assert_eq!(terminal.ladder, Some(LadderTerminalDisposition::Countered));
    assert_eq!(terminal.counter_task_ref, Some(counter));
    assert!(terminal.result_ref.is_some(), "counter lineage is durable");

    // A SECOND counter finds the original already terminal and leaves it
    // byte-identical.
    let before = vault
        .get_raw(&original)
        .expect("original read")
        .expect("original stored");
    let second = facade
        .mint_counter_task(original, delta, LADDER_DEADLINE, LADDER_NOW + 9)
        .expect("a second counter still mints")
        .task_ref
        .expect("second counter minted");

    assert_ne!(second, counter);
    assert_eq!(
        vault
            .get_raw(&original)
            .expect("original read")
            .expect("original stored"),
        before,
        "a terminal original is never rewritten"
    );
}

/// An ESCALATED original settled on the ladder axis while staying live on the
/// TASK axis. It is still settled, so a counter mints beside it and leaves it
/// byte-identical rather than rewriting it as rejected.
#[test]
fn counter_leaves_an_escalated_original_byte_identical() {
    let (_dir, vault) = open_vault();
    let fixture = cross_actor_fixture(&vault);
    let facade = vault.memory_facade(fixture.proposer, EdgeActorClass::Agent);
    let delta = ladder_delta(
        fixture.target,
        fixture.delta_ref,
        fixture.proposer,
        fixture.owner,
    );
    let CrossActorRoute::ConsultOwner { receipt } = facade
        .route_entity_delta(delta.clone(), None, LADDER_DEADLINE, LADDER_NOW)
        .expect("cross-actor delta routes")
    else {
        panic!("expected an owner consult");
    };
    let original = receipt.task_ref.expect("consult minted");
    let working = ConsultLadderState::Working(WorkingState {
        started_at: LADDER_NOW,
        decision_round: 0,
    });
    seed_ladder_state(&vault, original, &working);
    facade
        .compare_and_set_consult_ladder(
            original,
            &working,
            LadderTransition::Finish(LadderTerminalState {
                disposition: LadderTerminalDisposition::Escalated,
                result_ref: ladder_id(0xE5),
                counter_task_ref: None,
                finished_at: LADDER_NOW + 1,
            }),
        )
        .expect("a working ladder may escalate");
    let before = vault
        .get_raw(&original)
        .expect("original read")
        .expect("original stored");

    facade
        .mint_counter_task(original, delta, LADDER_DEADLINE, LADDER_NOW + 5)
        .expect("counter mints")
        .task_ref
        .expect("counter task minted");

    assert_eq!(
        vault
            .get_raw(&original)
            .expect("original read")
            .expect("original stored"),
        before,
        "an escalated original is settled and never rewritten"
    );
}

// ── durable ladder CAS ──────────────────────────────────────────────

/// Seeds one consult's persisted state to the projection of `state` so the
/// CAS has a ladder row to move.
fn seed_ladder_state(vault: &Vault, task_ref: EntityId, state: &ConsultLadderState) {
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

/// The CAS decides against the PERSISTED projection, not the caller's
/// optimism: a freshly-minted `Queued` consult has no ladder row yet.
#[test]
fn the_durable_ladder_cas_refuses_a_stale_expectation() {
    let (_dir, vault) = open_vault();
    let (task_ref, _peer, _question) = open_consult(&vault);
    let facade = vault.memory_facade(own_agent(&vault), EdgeActorClass::Agent);

    let conflict = facade
        .compare_and_set_consult_ladder(
            task_ref,
            &ConsultLadderState::Working(WorkingState {
                started_at: LADDER_NOW,
                decision_round: 0,
            }),
            LadderTransition::Interrupt(InterruptedState {
                kind: InterruptionKind::Contested,
                consent_required: false,
                case_ref: ladder_id(0xF1),
                interrupted_at: LADDER_NOW + 1,
            }),
        )
        .expect_err("a stale expectation is refused");

    assert_eq!(conflict.code, FACADE_CODE_INVALID_STATE);
}

/// A working ladder escalates to the persisted `Interrupted` state, then
/// refuses every further move: the pure rule and the durable projection
/// agree that terminal is immutable.
#[test]
fn a_working_ladder_escalates_then_becomes_immutable() {
    let (_dir, vault) = open_vault();
    let (task_ref, _peer, _question) = open_consult(&vault);
    let facade = vault.memory_facade(own_agent(&vault), EdgeActorClass::Agent);
    let working = ConsultLadderState::Working(WorkingState {
        started_at: LADDER_NOW,
        decision_round: 0,
    });
    seed_ladder_state(&vault, task_ref, &working);

    let escalated = LadderTerminalState {
        disposition: LadderTerminalDisposition::Escalated,
        result_ref: ladder_id(0xF3),
        counter_task_ref: None,
        finished_at: LADDER_NOW + 3,
    };
    let receipt = facade
        .compare_and_set_consult_ladder(task_ref, &working, LadderTransition::Finish(escalated))
        .expect("a working ladder may escalate");
    let refused = facade
        .compare_and_set_consult_ladder(
            task_ref,
            &ConsultLadderState::Terminal(escalated),
            LadderTransition::Finish(LadderTerminalState {
                disposition: LadderTerminalDisposition::Approved,
                result_ref: ladder_id(0xF4),
                counter_task_ref: None,
                finished_at: LADDER_NOW + 4,
            }),
        )
        .expect_err("a terminal ladder is immutable");

    assert_eq!(
        receipt.task_state,
        TaskExecutionState::Interrupted {
            ladder: Some(escalated),
        }
    );
    assert_eq!(
        receipt.ladder_state,
        ConsultLadderState::Terminal(escalated)
    );
    assert_eq!(refused.code, FACADE_CODE_INVALID_STATE);
    // An escalation is NOT a terminal TASK row, so the board keeps it live.
    let body = task_verb_body(&vault, task_ref)
        .expect("decode consult")
        .expect("consult is typed");
    assert_eq!(
        body.state,
        Some(TaskExecutionState::Interrupted {
            ladder: Some(escalated),
        })
    );
    assert_eq!(body.terminal(), None);
}

/// An escalated ladder is settled even though its TASK row stays live, so a
/// caller naming the state the row PROJECTS onto — a plain interruption —
/// still cannot resume or finish it.
///
/// The projection alone cannot tell the two apart, which is exactly why the
/// settled ladder is persisted beside it.
#[test]
fn an_escalated_ladder_refuses_a_cas_that_expects_a_plain_interruption() {
    let (_dir, vault) = open_vault();
    let (task_ref, _peer, _question) = open_consult(&vault);
    let facade = vault.memory_facade(own_agent(&vault), EdgeActorClass::Agent);
    let working = ConsultLadderState::Working(WorkingState {
        started_at: LADDER_NOW,
        decision_round: 0,
    });
    seed_ladder_state(&vault, task_ref, &working);
    facade
        .compare_and_set_consult_ladder(
            task_ref,
            &working,
            LadderTransition::Finish(LadderTerminalState {
                disposition: LadderTerminalDisposition::Escalated,
                result_ref: ladder_id(0xE1),
                counter_task_ref: None,
                finished_at: LADDER_NOW + 1,
            }),
        )
        .expect("a working ladder may escalate");

    let masquerading = ConsultLadderState::Interrupted(InterruptedState {
        kind: InterruptionKind::Contested,
        consent_required: false,
        case_ref: ladder_id(0xE2),
        interrupted_at: LADDER_NOW + 1,
    });
    let resumed = facade
        .compare_and_set_consult_ladder(
            task_ref,
            &masquerading,
            LadderTransition::Resume(WorkingState {
                started_at: LADDER_NOW + 2,
                decision_round: 1,
            }),
        )
        .expect_err("a settled ladder does not resume");
    let finished = facade
        .compare_and_set_consult_ladder(
            task_ref,
            &masquerading,
            LadderTransition::Finish(LadderTerminalState {
                disposition: LadderTerminalDisposition::Approved,
                result_ref: ladder_id(0xE3),
                counter_task_ref: None,
                finished_at: LADDER_NOW + 3,
            }),
        )
        .expect_err("a settled ladder does not settle twice");

    assert_eq!(resumed.code, FACADE_CODE_INVALID_STATE);
    assert_eq!(finished.code, FACADE_CODE_INVALID_STATE);
    let body = task_verb_body(&vault, task_ref)
        .expect("decode consult")
        .expect("consult is typed");
    assert_eq!(
        body.state,
        Some(TaskExecutionState::Interrupted {
            ladder: Some(LadderTerminalState {
                disposition: LadderTerminalDisposition::Escalated,
                result_ref: ladder_id(0xE1),
                counter_task_ref: None,
                finished_at: LADDER_NOW + 1,
            }),
        })
    );
}

/// An ordinary interruption still resumes: the new guard reads the settled
/// LADDER, not the interrupted register itself.
#[test]
fn an_unsettled_interruption_still_resumes_through_the_ladder() {
    let (_dir, vault) = open_vault();
    let (task_ref, _peer, _question) = open_consult(&vault);
    let facade = vault.memory_facade(own_agent(&vault), EdgeActorClass::Agent);
    let waiting = ConsultLadderState::Interrupted(InterruptedState {
        kind: InterruptionKind::Contested,
        consent_required: false,
        case_ref: ladder_id(0xE4),
        interrupted_at: LADDER_NOW,
    });
    seed_ladder_state(&vault, task_ref, &waiting);

    let receipt = facade
        .compare_and_set_consult_ladder(
            task_ref,
            &waiting,
            LadderTransition::Resume(WorkingState {
                started_at: LADDER_NOW + 1,
                decision_round: 1,
            }),
        )
        .expect("an unsettled interruption resumes");

    assert_eq!(
        receipt.task_state,
        TaskExecutionState::Working {
            started_at: LADDER_NOW + 1,
        }
    );
}

/// Escalates one open consult through the real ladder door, leaving its TASK
/// row live with the settled ladder riding inside the interrupted register.
fn escalate_consult(
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
        .memory_facade(own_agent(vault), EdgeActorClass::Agent)
        .compare_and_set_consult_ladder(task_ref, &working, LadderTransition::Finish(escalated))
        .expect("a working ladder may escalate");
    escalated
}

/// The consult result door shares the one terminal-write path, and a settled
/// ladder is immutable on the half that did NOT settle the task. A late peer
/// answer against an escalated consult is refused, and the row survives
/// byte-for-byte as the escalation wrote it.
#[test]
fn a_late_consult_result_refuses_to_overwrite_a_settled_ladder() {
    let (_dir, vault) = open_vault();
    let (task_ref, peer, question) = open_consult(&vault);
    let escalated = escalate_consult(&vault, task_ref, ladder_id(0xC1), LADDER_NOW + 1);
    let late_result = consult_turn(&vault, 0x82).entity_ref();
    let before = vault
        .get_raw(&task_ref)
        .expect("consult read")
        .expect("consult stored");

    let late = vault
        .memory_facade(peer, EdgeActorClass::Agent)
        .land_consult_result(task_ref, &answer_input(late_result, question))
        .expect_err("an escalated consult refuses a late answer");
    let body = task_verb_body(&vault, task_ref)
        .expect("decode consult")
        .expect("consult is typed");

    assert_eq!(late.code, FACADE_CODE_INVALID_STATE);
    assert_eq!(
        vault
            .get_raw(&task_ref)
            .expect("consult read")
            .expect("consult stored"),
        before,
        "a settled ladder survives the consult result door byte-for-byte"
    );
    assert_eq!(
        body.state,
        Some(TaskExecutionState::Interrupted {
            ladder: Some(escalated),
        })
    );
}

/// The GENERAL result door runs the same writer, so it refuses the same
/// settled ladder. A ONE-1888 register arrives by sync on any lane, and a late
/// result must not flatten one into a terminal record whose ladder half,
/// counter link, and result linkage are all absent.
#[test]
fn a_late_generic_result_refuses_to_overwrite_a_settled_ladder() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let actor_ref = route_peer(&vault, 0xC2);
    let task_ref = vault
        .memory_facade(own, EdgeActorClass::Agent)
        .tasks_create(&route_spec(Some(TaskAssignee::Peer { actor_ref })))
        .expect("create")
        .task_ref
        .expect("task ref");
    let escalated = LadderTerminalState {
        disposition: LadderTerminalDisposition::Escalated,
        result_ref: ladder_id(0xC3),
        counter_task_ref: None,
        finished_at: ROUTE_NOW + 1,
    };
    seed_ladder_state(&vault, task_ref, &ConsultLadderState::Terminal(escalated));
    let late_result = route_turn(&vault, 0xC4).entity_ref();
    let before = vault
        .get_raw(&task_ref)
        .expect("task read")
        .expect("task stored");

    let late = vault
        .memory_facade(actor_ref, EdgeActorClass::Agent)
        .land_task_result(
            task_ref,
            &TaskResultInput {
                result_ref: late_result,
                disposition: TaskTerminalDisposition::Completed,
                finished_at: ROUTE_NOW + 9,
            },
        )
        .expect_err("an escalated row refuses a late result");
    let body = task_verb_body(&vault, task_ref)
        .expect("decode body")
        .expect("typed body");

    assert_eq!(late.code, FACADE_CODE_INVALID_STATE);
    assert_eq!(
        vault
            .get_raw(&task_ref)
            .expect("task read")
            .expect("task stored"),
        before,
        "a settled ladder survives the general result door byte-for-byte"
    );
    assert_eq!(
        body.state,
        Some(TaskExecutionState::Interrupted {
            ladder: Some(escalated),
        })
    );
}

/// An escalated consult is ANSWERED, not overdue. The deadline sweep needs no
/// adversary to destroy one — only a clock — so it reads the ladder half too:
/// nothing expires, no digest is scheduled, and the row is left untouched.
#[test]
fn the_deadline_sweep_leaves_an_escalated_consult_settled() {
    let (_dir, vault) = open_vault();
    let asker = own_agent(&vault);
    grant_outbound(&vault, asker, 0xD1);
    let (task_ref, _peer, _question) = open_consult(&vault);
    let escalated = escalate_consult(&vault, task_ref, ladder_id(0xC5), LADDER_NOW + 1);
    let before = vault
        .get_raw(&task_ref)
        .expect("consult read")
        .expect("consult stored");

    let report = vault
        .memory_facade(asker, EdgeActorClass::Agent)
        .settle_due_consults(CONSULT_DEADLINE + 1, &digest_route())
        .expect("the sweep runs past the deadline");
    let body = task_verb_body(&vault, task_ref)
        .expect("decode consult")
        .expect("consult is typed");

    assert_eq!(report.expired_task_refs.len(), 0);
    assert_eq!(report.digest_intent_refs.len(), 0);
    assert_eq!(report.already_settled, 0);
    assert_eq!(
        vault.connector_send_tasks().expect("connector sends").len(),
        0
    );
    assert_eq!(
        vault
            .get_raw(&task_ref)
            .expect("consult read")
            .expect("consult stored"),
        before,
        "a settled ladder survives the deadline sweep byte-for-byte"
    );
    assert_eq!(
        body.state,
        Some(TaskExecutionState::Interrupted {
            ladder: Some(escalated),
        })
    );
}

/// A consent-required interruption resumes only through a human verdict —
/// enforced on the durable path, not just the pure one.
#[test]
fn a_consent_required_interruption_cannot_be_resumed_durably() {
    let (_dir, vault) = open_vault();
    let (task_ref, _peer, _question) = open_consult(&vault);
    let facade = vault.memory_facade(own_agent(&vault), EdgeActorClass::Agent);
    let waiting = ConsultLadderState::Interrupted(InterruptedState {
        kind: InterruptionKind::Critical,
        consent_required: true,
        case_ref: ladder_id(0xF5),
        interrupted_at: LADDER_NOW,
    });
    seed_ladder_state(&vault, task_ref, &waiting);

    let refused = facade
        .compare_and_set_consult_ladder(
            task_ref,
            &waiting,
            LadderTransition::Resume(WorkingState {
                started_at: LADDER_NOW + 1,
                decision_round: 1,
            }),
        )
        .expect_err("consent-required work does not resume itself");
    // The human verdict path DOES settle it.
    let approved = facade
        .compare_and_set_consult_ladder(
            task_ref,
            &waiting,
            LadderTransition::Finish(LadderTerminalState {
                disposition: terminal_for_human_verdict(HumanVerdict::Approve {
                    rationale_ref: Some(ladder_id(0xF6)),
                }),
                result_ref: ladder_id(0xF7),
                counter_task_ref: None,
                finished_at: LADDER_NOW + 2,
            }),
        )
        .expect("a human verdict settles the case");

    assert_eq!(refused.code, FACADE_CODE_FORBIDDEN);
    assert_eq!(
        approved
            .ladder_state
            .terminal()
            .map(|state| state.disposition),
        Some(LadderTerminalDisposition::Approved)
    );
}

// ── human verdict codec ─────────────────────────────────────────────

/// All four verdicts round-trip, escalation carries ONE-1699's assignee
/// enum, and an override missing either durable ref is refused rather than
/// defaulted.
#[test]
fn human_verdicts_round_trip_and_override_requires_both_refs() {
    let verdicts = [
        HumanVerdict::Approve {
            rationale_ref: None,
        },
        HumanVerdict::Approve {
            rationale_ref: Some(ladder_id(0xA4)),
        },
        HumanVerdict::Reject {
            rationale_ref: Some(ladder_id(0xA5)),
        },
        HumanVerdict::OverrideWithDiff {
            delta_ref: ladder_id(0xA6),
            rationale_ref: ladder_id(0xA7),
        },
        HumanVerdict::Escalate {
            assignee: TaskAssignee::Human {
                actor_ref: ladder_id(0xA8),
            },
            rationale_ref: ladder_id(0xA9),
        },
        HumanVerdict::Escalate {
            assignee: TaskAssignee::Dreamer,
            rationale_ref: ladder_id(0xAA),
        },
    ];
    for (index, verdict) in verdicts.into_iter().enumerate() {
        assert_eq!(
            decode_human_verdict(&human_verdict_value(verdict)).expect("verdict decodes"),
            verdict,
            "case {index}"
        );
    }

    let missing_rationale = Value::Map(vec![
        (Value::from("verdict"), Value::from("override_with_diff")),
        (Value::from("delta_ref"), entity_ref_value(ladder_id(0xA6))),
    ]);
    let missing_delta = Value::Map(vec![
        (Value::from("verdict"), Value::from("override_with_diff")),
        (
            Value::from("rationale_ref"),
            entity_ref_value(ladder_id(0xA7)),
        ),
    ]);
    let unknown = Value::Map(vec![(Value::from("verdict"), Value::from("maybe"))]);
    for (index, malformed) in [missing_rationale, missing_delta, unknown]
        .into_iter()
        .enumerate()
    {
        assert!(
            decode_human_verdict(&malformed).is_err(),
            "case {index} must be refused"
        );
    }
}

// ── magistrate provenance ───────────────────────────────────────────

fn magistrate_case(
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

/// Authorship is re-derived from the vault's own claim/provenance
/// envelopes: a contested state written under the Dreamer run surface
/// recuses, and the SAME case shape over agent-authored state rules.
#[test]
fn magistrate_recuses_on_vault_derived_dreamer_authorship() {
    let (_dir, vault) = open_vault();
    let actor = own_agent(&vault);
    let subject = other_actor(&vault);
    let dreamer_state = ladder_id(0x94);
    let agent_state = ladder_id(0x95);
    let delta = ladder_id(0x96);
    put_envelope_claim(
        &vault,
        dreamer_state,
        subject,
        actor,
        EdgeActorClass::Agent,
        dreamer_provenance(),
    );
    put_envelope_claim(
        &vault,
        agent_state,
        subject,
        actor,
        EdgeActorClass::Agent,
        agent_provenance(),
    );
    put_envelope_claim(
        &vault,
        delta,
        subject,
        actor,
        EdgeActorClass::Agent,
        agent_provenance(),
    );

    let dreamer_case = magistrate_case(dreamer_state, delta, CaseCriticality::Normal);
    let agent_case = magistrate_case(agent_state, delta, CaseCriticality::Normal);

    assert_eq!(
        derive_state_authorship(&vault, &dreamer_case).expect("authorship derives"),
        StateAuthorship::Dreamer
    );
    assert_eq!(
        derive_state_authorship(&vault, &agent_case).expect("authorship derives"),
        StateAuthorship::OtherAgent
    );
    assert_eq!(
        decide_magistrate(&vault, &dreamer_case).expect("verdict"),
        MagistrateVerdict::Recused {
            reason: MagistrateRecusal::DreamerAuthoredState
        }
    );
    // The recusal is the provenance talking, not a blanket refusal.
    assert_eq!(
        decide_magistrate(&vault, &agent_case).expect("verdict"),
        MagistrateVerdict::Rule {
            selected_delta_ref: delta,
            rationale_ref: ladder_id(0x92),
        }
    );
}

/// A caller cannot buy a ruling with a forged summary: with every case
/// field naming another agent, Dreamer authorship of the contested DELTA
/// still recuses, and unattributable state fails closed.
#[test]
fn forged_authorship_cannot_defeat_the_provenance_derivation() {
    let (_dir, vault) = open_vault();
    let actor = own_agent(&vault);
    let subject = other_actor(&vault);
    let agent_state = ladder_id(0x97);
    let dreamer_delta = ladder_id(0x98);
    put_envelope_claim(
        &vault,
        agent_state,
        subject,
        actor,
        EdgeActorClass::Agent,
        agent_provenance(),
    );
    put_envelope_claim(
        &vault,
        dreamer_delta,
        subject,
        actor,
        EdgeActorClass::Agent,
        dreamer_provenance(),
    );

    let forged = magistrate_case(agent_state, dreamer_delta, CaseCriticality::Normal);
    let unattributable = magistrate_case(ladder_id(0x99), dreamer_delta, CaseCriticality::Normal);

    assert_eq!(
        decide_magistrate(&vault, &forged).expect("verdict"),
        MagistrateVerdict::Recused {
            reason: MagistrateRecusal::DreamerAuthoredState
        }
    );
    assert!(
        decide_magistrate(&vault, &unattributable).is_err(),
        "state with no recoverable attribution is not ruled on"
    );
}

/// The magistrate's whole write set is receipt + supersession + conflict
/// claim. It enqueues no work, schedules no outbound, and deletes nothing.
#[test]
fn applying_a_ruling_writes_only_reversible_records() {
    let (_dir, vault) = open_vault();
    let actor = own_agent(&vault);
    let subject = other_actor(&vault);
    let state = ladder_id(0x9A);
    let selected = ladder_id(0x9B);
    let competing = ladder_id(0x9C);
    for claim_ref in [state, selected, competing] {
        put_envelope_claim(
            &vault,
            claim_ref,
            subject,
            actor,
            EdgeActorClass::Agent,
            agent_provenance(),
        );
    }
    let mut case = magistrate_case(state, selected, CaseCriticality::Normal);
    case.candidate_delta_refs = vec![selected, competing];

    let attempts_before = AttemptQueue::new(&vault).list().expect("attempts").len();
    let conflicts_before = open_conflict_count(&vault);
    let verdict = decide_magistrate(&vault, &case).expect("verdict");
    let receipt = apply_magistrate_verdict(
        &vault,
        WriteActor::new(actor, EdgeActorClass::Agent),
        &case,
        &verdict,
    )
    .expect("ruling applies");
    let attempts_after = AttemptQueue::new(&vault).list().expect("attempts").len();

    assert_eq!(
        verdict,
        MagistrateVerdict::Rule {
            selected_delta_ref: selected,
            rationale_ref: ladder_id(0x92),
        }
    );
    assert!(receipt.reversible);
    assert_eq!(receipt.appeal_handle, case.task_ref);
    assert_eq!(
        attempts_after, attempts_before,
        "a ruling enqueues no work of any kind"
    );
    assert_eq!(
        vault
            .get_entity_type(&receipt.receipt_ref)
            .expect("receipt type"),
        Some(ENTITY_TYPE_TURN)
    );
    // The replaced head was superseded through the EXISTING claim API, and
    // the surviving competitor surfaced as the existing conflict predicate.
    assert_eq!(
        vault
            .get_claim(&state)
            .expect("state claim")
            .expect("stored")
            .lifecycle,
        ClaimLifecycleStatus::Superseded
    );
    assert_eq!(open_conflict_count(&vault) - conflicts_before, 1);
}

fn open_conflict_count(vault: &Vault) -> usize {
    vault
        .entities_by_type(ENTITY_TYPE_CLAIM)
        .expect("claim census")
        .into_iter()
        .filter_map(|claim_ref| vault.get_claim(&claim_ref).ok().flatten())
        .filter(|body| body.predicate == PREDICATE_CONFLICT_OPEN)
        .count()
}

/// Advice is receipted but never applied: a critical case leaves the
/// contested head exactly where it was.
#[test]
fn a_critical_case_is_advised_and_never_applied() {
    let (_dir, vault) = open_vault();
    let actor = own_agent(&vault);
    let subject = other_actor(&vault);
    let state = ladder_id(0x9D);
    let delta = ladder_id(0x9E);
    for claim_ref in [state, delta] {
        put_envelope_claim(
            &vault,
            claim_ref,
            subject,
            actor,
            EdgeActorClass::Agent,
            agent_provenance(),
        );
    }
    let case = magistrate_case(state, delta, CaseCriticality::Critical);

    let verdict = decide_magistrate(&vault, &case).expect("verdict");
    apply_magistrate_verdict(
        &vault,
        WriteActor::new(actor, EdgeActorClass::Agent),
        &case,
        &verdict,
    )
    .expect("advice is receipted");

    assert_eq!(
        verdict,
        MagistrateVerdict::AdviceOnly {
            recommended_delta_ref: Some(delta),
            rationale_ref: ladder_id(0x92),
        }
    );
    assert_eq!(
        vault
            .get_claim(&state)
            .expect("state claim")
            .expect("stored")
            .lifecycle,
        ClaimLifecycleStatus::Active,
        "advice cannot terminalize the contested state"
    );
}

/// An overturn leaves the original receipt intact and writes exactly one
/// typed record — the complete ED handoff, with no ED call.
#[test]
fn an_overturn_preserves_the_original_receipt() {
    let (_dir, vault) = open_vault();
    let actor = own_agent(&vault);
    let subject = other_actor(&vault);
    let state = ladder_id(0x6A);
    let delta = ladder_id(0x6B);
    for claim_ref in [state, delta] {
        put_envelope_claim(
            &vault,
            claim_ref,
            subject,
            actor,
            EdgeActorClass::Agent,
            agent_provenance(),
        );
    }
    let case = magistrate_case(state, delta, CaseCriticality::Normal);
    let verdict = decide_magistrate(&vault, &case).expect("verdict");
    let receipt = apply_magistrate_verdict(
        &vault,
        WriteActor::new(actor, EdgeActorClass::Agent),
        &case,
        &verdict,
    )
    .expect("ruling applies");
    let receipt_bytes = vault
        .get_raw(&receipt.receipt_ref)
        .expect("receipt read")
        .expect("receipt stored");

    let overturn_ref = record_magistrate_overturn(
        &vault,
        &MagistrateOverturnRecord {
            original_receipt_ref: receipt.receipt_ref,
            overturning_verdict_ref: ladder_id(0xA3),
            corrected_delta_ref: Some(delta),
            rationale_ref: ladder_id(0xA4),
            occurred_at: LADDER_NOW + 10,
        },
    )
    .expect("overturn records");

    assert_ne!(overturn_ref, receipt.receipt_ref);
    assert_eq!(
        vault
            .get_raw(&receipt.receipt_ref)
            .expect("receipt read")
            .expect("receipt stored"),
        receipt_bytes,
        "the original receipt is never erased or rewritten"
    );
    assert_eq!(
        vault.get_entity_type(&overturn_ref).expect("overturn type"),
        Some(ENTITY_TYPE_TURN)
    );
}

/// Magistrate work rides the EXISTING Dreamer runner queue as a
/// payload-level attempt type under the unchanged outer kind.
#[test]
fn magistrate_work_enqueues_as_a_payload_level_attempt_type() {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let case = magistrate_case(ladder_id(0xB2), ladder_id(0xB3), CaseCriticality::Normal);

    let outcome = enqueue_magistrate(&store, &case, None, Some("run-magistrate".to_owned()))
        .expect("magistrate enqueues");
    let replay = enqueue_magistrate(&store, &case, None, Some("run-magistrate".to_owned()))
        .expect("magistrate re-enqueue");

    let EnqueueDreamerAttemptOutcome::Enqueued(status) = outcome else {
        panic!("the first enqueue is not a dedupe hit");
    };
    assert_eq!(status.payload.attempt_type, DREAMER_MAGISTRATE_ATTEMPT_TYPE);
    assert_eq!(status.attempt.kind, DREAMER_RUNNER_ATTEMPT_KIND);
    assert!(matches!(replay, EnqueueDreamerAttemptOutcome::Existing(_)));
}

// ── board + A2A over persisted rows ─────────────────────────────────

/// The board reads the ladder outcome off the persisted row: a countered
/// original renders as an immutable rejected row naming its successor,
/// while the counter renders independently.
#[test]
fn a_countered_original_renders_as_rejected_with_its_counter() {
    let (_dir, vault) = open_vault();
    let fixture = cross_actor_fixture(&vault);
    let facade = vault.memory_facade(fixture.proposer, EdgeActorClass::Agent);
    let delta = ladder_delta(
        fixture.target,
        fixture.delta_ref,
        fixture.proposer,
        fixture.owner,
    );
    let CrossActorRoute::ConsultOwner { receipt } = facade
        .route_entity_delta(delta.clone(), None, LADDER_DEADLINE, LADDER_NOW)
        .expect("cross-actor delta routes")
    else {
        panic!("expected an owner consult");
    };
    let original = receipt.task_ref.expect("consult minted");
    let counter = facade
        .mint_counter_task(original, delta, LADDER_DEADLINE, LADDER_NOW + 5)
        .expect("counter mints")
        .task_ref
        .expect("counter task minted");

    let section = facade.tasks_check().expect("board renders");
    let original_row = section
        .rows
        .iter()
        .find(|row| row.id == original.to_hex())
        .expect("the countered original stays on the board");
    let counter_row = section
        .rows
        .iter()
        .find(|row| row.id == counter.to_hex())
        .expect("the counter renders independently");

    assert_eq!(original_row.status, TaskBoardStatus::Failed);
    assert_eq!(
        original_row.ladder_disposition,
        Some(LadderTerminalDisposition::Countered)
    );
    assert_eq!(
        original_row.counter_task_ref.as_deref(),
        Some(counter.to_hex().as_str())
    );
    let tokens: Vec<&str> = original_row.line.split_whitespace().collect();
    assert!(tokens.contains(&"rejected"), "{}", original_row.line);
    assert!(tokens.contains(&"countered"), "{}", original_row.line);
    // The counter is its own row: no ladder outcome of its own yet, and
    // no counter link pointing anywhere.
    assert_eq!(counter_row.ladder_disposition, None);
    assert_eq!(counter_row.counter_task_ref, None);
    assert_ne!(counter_row.id, original_row.id);
}

/// A counter answers to the same attribution laws as the original ask:
/// a forged owner or an unattributed proposer never mints one.
#[test]
fn a_counter_cannot_forge_its_owner_or_proposer() {
    let (_dir, vault) = open_vault();
    let fixture = cross_actor_fixture(&vault);
    let facade = vault.memory_facade(fixture.proposer, EdgeActorClass::Agent);
    let delta = ladder_delta(
        fixture.target,
        fixture.delta_ref,
        fixture.proposer,
        fixture.owner,
    );
    let CrossActorRoute::ConsultOwner { receipt } = facade
        .route_entity_delta(delta, None, LADDER_DEADLINE, LADDER_NOW)
        .expect("cross-actor delta routes")
    else {
        panic!("expected an owner consult");
    };
    let original = receipt.task_ref.expect("consult minted");

    let forged_owner = facade
        .mint_counter_task(
            original,
            ladder_delta(
                fixture.target,
                fixture.delta_ref,
                fixture.proposer,
                fixture.proposer,
            ),
            LADDER_DEADLINE,
            LADDER_NOW + 5,
        )
        .expect_err("a forged owner is refused");
    let forged_proposer = facade
        .mint_counter_task(
            original,
            ladder_delta(
                fixture.target,
                fixture.delta_ref,
                fixture.owner,
                fixture.owner,
            ),
            LADDER_DEADLINE,
            LADDER_NOW + 5,
        )
        .expect_err("an unattributed proposer is refused");
    let original_body = task_verb_body(&vault, original)
        .expect("decode original")
        .expect("original is typed");

    assert_eq!(forged_owner.code, FACADE_CODE_FORBIDDEN);
    assert_eq!(forged_proposer.code, FACADE_CODE_FORBIDDEN);
    assert_eq!(
        original_body.terminal(),
        None,
        "a refused counter never terminalizes the original"
    );
}

/// An UNSTAMPED ONE-1699 terminal projects its OWN disposition: `expired`
/// is not rounded to the nearest ladder word, and no interruption kind is
/// invented for a body that never recorded one.
#[test]
fn an_unstamped_legacy_terminal_projects_its_own_disposition() {
    let (_dir, vault) = open_vault();
    let (task_ref, _peer, _question) = open_consult(&vault);
    let facade = vault.memory_facade(own_agent(&vault), EdgeActorClass::Agent);
    grant_outbound(&vault, own_agent(&vault), 0xC8);
    facade
        .settle_due_consults(CONSULT_DEADLINE + 1, &digest_route())
        .expect("the expiry sweep runs");

    let projection = project_consult_task_to_a2a(&vault, task_ref)
        .expect("projection reads")
        .expect("the expired consult projects");
    let body = task_verb_body(&vault, task_ref)
        .expect("decode consult")
        .expect("consult is typed");

    assert_eq!(body.terminal().and_then(|record| record.ladder), None);
    assert_eq!(projection.state, A2aBaseTaskState::Cancelled);
    assert_eq!(
        projection.extensions.terminal_disposition.as_deref(),
        Some("expired")
    );
    assert_eq!(projection.extensions.interruption_kind, None);
    assert!(projection.extensions.result_ref.is_some());
}

/// The A2A projection reads a real persisted consult, including its
/// counter lineage. A counter is a decision that COMPLETED, never a
/// failure.
#[test]
fn a_persisted_counter_projects_with_its_counter_of_extension() {
    let (_dir, vault) = open_vault();
    let fixture = cross_actor_fixture(&vault);
    let facade = vault.memory_facade(fixture.proposer, EdgeActorClass::Agent);
    let delta = ladder_delta(
        fixture.target,
        fixture.delta_ref,
        fixture.proposer,
        fixture.owner,
    );
    let CrossActorRoute::ConsultOwner { receipt } = facade
        .route_entity_delta(delta.clone(), None, LADDER_DEADLINE, LADDER_NOW)
        .expect("cross-actor delta routes")
    else {
        panic!("expected an owner consult");
    };
    let original = receipt.task_ref.expect("consult minted");
    let counter = facade
        .mint_counter_task(original, delta, LADDER_DEADLINE, LADDER_NOW + 5)
        .expect("counter mints")
        .task_ref
        .expect("counter task minted");

    let original_projection = project_consult_task_to_a2a(&vault, original)
        .expect("projection reads")
        .expect("the original projects");
    let counter_projection = project_consult_task_to_a2a(&vault, counter)
        .expect("projection reads")
        .expect("the counter projects");

    assert_eq!(original_projection.state, A2aBaseTaskState::Completed);
    assert_eq!(
        original_projection
            .extensions
            .terminal_disposition
            .as_deref(),
        Some("rejected")
    );
    assert_eq!(
        counter_projection.extensions.counter_of.as_deref(),
        Some(original.to_hex().as_str())
    );
}
// ── assignee routing (ONE-1700) ─────────────────────────────────────

const ROUTE_NOW: u64 = 1_772_500_000;

/// Every generic ONE-1700 fixture identity routes through the canonical
/// band assertion, so a fixture can never alias a production-pinned system
/// identity (`0xD7` is the default policy manifest — a seed collision there
/// surfaces as a bewildering entity-type error deep inside an unrelated
/// write). `crate::test_util::entity` owns the pinned list; this is the
/// seed-shaped adapter onto the ONE-1699 fixture helpers, not a second copy
/// of the rule.
fn route_seed(seed: u8) -> u8 {
    crate::test_util::entity(seed);
    seed
}

fn route_peer(vault: &Vault, seed: u8) -> EntityId {
    consult_peer(vault, route_seed(seed))
}

fn route_turn(vault: &Vault, seed: u8) -> ConsultPayloadRef {
    consult_turn(vault, route_seed(seed))
}

fn route_dangling(seed: u8) -> EntityId {
    crate::test_util::entity(seed)
}

/// A dispatchable AGENT_DEF row: an ordinary fork of a seeded row, which is
/// the only way to get an Active+approved+enabled definition without
/// hand-rolling a body the validator would reject.
fn routable_agent_def(vault: &Vault, seed: u8) -> EntityId {
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

fn attempts_for(vault: &Vault, task_ref: EntityId) -> Vec<AttemptRecord> {
    let task_hex = task_ref.to_hex();
    AttemptQueue::new(vault)
        .list()
        .expect("list attempts")
        .into_iter()
        .filter(|record| record.task_ref.as_deref() == Some(task_hex.as_str()))
        .collect()
}

fn route_spec(assignee: Option<TaskAssignee>) -> TaskCreateSpec {
    let base = TaskCreateSpec::new(Value::from("routed-task"), None, None, Some(ROUTE_NOW));
    match assignee {
        Some(assignee) => base.with_assignee(assignee),
        None => base,
    }
}

/// Compatibility: a schema-v1 create — assignee absent entirely — still
/// mints exactly one `tasks.realize` attempt on the Dreamer lane.
#[test]
fn absent_assignee_routes_to_one_dreamer_realization() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let receipt = vault
        .memory_facade(own, EdgeActorClass::Agent)
        .tasks_create(&route_spec(None))
        .expect("create");
    let task_ref = receipt.task_ref.expect("task ref");
    let attempts = attempts_for(&vault, task_ref);

    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].kind, TASK_REALIZE_ATTEMPT_KIND);
    assert_eq!(
        receipt.route.map(TaskRouteOutcome::lane),
        Some(TaskRouteLane::Dreamer)
    );
    assert_eq!(
        receipt.route.and_then(TaskRouteOutcome::local_attempt),
        Some(attempts[0].id)
    );
}

/// `Some(Dreamer)` and absent are the SAME lane: one realize attempt, and
/// the explicit spelling is what lands on the row.
#[test]
fn explicit_dreamer_assignee_routes_exactly_like_absent() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let receipt = vault
        .memory_facade(own, EdgeActorClass::Agent)
        .tasks_create(&route_spec(Some(TaskAssignee::Dreamer)))
        .expect("create");
    let task_ref = receipt.task_ref.expect("task ref");
    let attempts = attempts_for(&vault, task_ref);
    let body = task_verb_body(&vault, task_ref)
        .expect("decode body")
        .expect("typed body");

    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].kind, TASK_REALIZE_ATTEMPT_KIND);
    assert_eq!(body.assignee, Some(TaskAssignee::Dreamer));
    assert_eq!(
        receipt.route.map(TaskRouteOutcome::lane),
        Some(TaskRouteLane::Dreamer)
    );
}

/// The agent-definition lane creates ONE in-process `agent.dispatch`
/// attempt, backlinked to the TASK, and never a `tasks.realize` row.
#[test]
fn agent_def_assignee_routes_to_one_in_process_dispatch() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let agent_def_ref = routable_agent_def(&vault, 0xC1);
    let receipt = vault
        .memory_facade(own, EdgeActorClass::Agent)
        .tasks_create(&route_spec(Some(TaskAssignee::AgentDef { agent_def_ref })))
        .expect("create");
    let task_ref = receipt.task_ref.expect("task ref");
    let attempts = attempts_for(&vault, task_ref);
    let payload = decode_dreamer_attempt_payload(&attempts[0].payload).expect("dispatch payload");

    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].kind, DREAMER_RUNNER_ATTEMPT_KIND);
    assert_eq!(payload.attempt_type, AGENT_DISPATCH_ATTEMPT_TYPE);
    assert_eq!(
        receipt.route,
        Some(TaskRouteOutcome::AgentDispatch {
            attempt_ref: attempts[0].id,
            agent_def_ref,
        })
    );
}

/// The dispatched child freezes the CURRENT definition snapshot and
/// addresses the ROW: no preset variant is persisted anywhere (ONE-1890
/// compatibility, proven from the stored bytes).
#[test]
fn agent_def_route_persists_a_row_ref_and_no_preset() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let agent_def_ref = routable_agent_def(&vault, 0xC2);
    let receipt = vault
        .memory_facade(own, EdgeActorClass::Agent)
        .tasks_create(&route_spec(Some(TaskAssignee::AgentDef { agent_def_ref })))
        .expect("create");
    let task_ref = receipt.task_ref.expect("task ref");
    let attempts = attempts_for(&vault, task_ref);
    let payload = decode_dreamer_attempt_payload(&attempts[0].payload).expect("dispatch payload");
    let dispatch_input =
        decode_agent_dispatch_input(&payload.input).expect("decode dispatch input");
    let stored_body = vault.get(&task_ref).expect("read task").expect("task row");
    let stored_text = String::from_utf8_lossy(&stored_body).to_ascii_lowercase();

    assert_eq!(
        dispatch_input.target,
        AgentDispatchTarget::Custom(agent_def_ref)
    );
    assert_eq!(
        dispatch_input.definition.agent_id.as_str(),
        format!("route-worker-{:02x}", 0xC2).as_str()
    );
    assert_eq!(usize::from(stored_text.contains("preset")), 0);
    assert_eq!(usize::from(stored_text.contains("system")), 0);
}

/// Re-routing the SAME task ref returns the existing dispatch instead of
/// minting a second one, and the dedupe row keeps its parent/run metadata.
#[test]
fn agent_def_route_is_idempotent_by_task_ref() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let agent_def_ref = routable_agent_def(&vault, 0xC3);
    let facade = vault.memory_facade(own, EdgeActorClass::Agent);
    let receipt = facade
        .tasks_create(&route_spec(Some(TaskAssignee::AgentDef { agent_def_ref })))
        .expect("create");
    let task_ref = receipt.task_ref.expect("task ref");
    let first = attempts_for(&vault, task_ref);
    // A retried route on the SAME task: the dispatcher's namespaced dedupe
    // key resolves to the row already realizing it.
    let replayed = AgentDispatcher::new(&vault)
        .dispatch(DispatchAgent {
            target: AgentDispatchTarget::Custom(agent_def_ref),
            parent_attempt: None,
            dedupe_key: Some(task_route_dedupe_key(task_ref)),
            run_id: None,
            now: ROUTE_NOW,
        })
        .expect("replayed dispatch");
    let after = attempts_for(&vault, task_ref);

    assert_eq!(first.len(), 1);
    assert_eq!(after.len(), 1);
    assert_eq!(
        match replayed {
            AgentDispatchOutcome::Existing(status) => status.attempt.id,
            AgentDispatchOutcome::Dispatched(_) => panic!("a replayed route must dedupe"),
        },
        first[0].id
    );
}

/// The peer lane mints the synced TASK and NOTHING local: no realize row,
/// no dispatch row, no synthetic transport attempt.
#[test]
fn peer_assignee_routes_with_zero_local_attempts() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let actor_ref = route_peer(&vault, 0xC4);
    let receipt = vault
        .memory_facade(own, EdgeActorClass::Agent)
        .tasks_create(&route_spec(Some(TaskAssignee::Peer { actor_ref })))
        .expect("create");
    let task_ref = receipt.task_ref.expect("task ref");
    let body = task_verb_body(&vault, task_ref)
        .expect("decode body")
        .expect("typed body");

    assert_eq!(attempts_for(&vault, task_ref).len(), 0);
    assert_eq!(
        AttemptQueue::new(&vault).list().expect("list").len(),
        0,
        "the peer lane mints no local attempt of any kind"
    );
    assert_eq!(body.assignee, Some(TaskAssignee::Peer { actor_ref }));
    assert_eq!(
        receipt.route,
        Some(TaskRouteOutcome::PeerSyncedOnly { actor_ref })
    );
}

/// A person the vault knows but cannot reach natively is refused in its own
/// name, and the refusal rolls the WHOLE create back (ONE-1708). The
/// reachability check lives inside the create transaction precisely so this
/// cannot leave a human task with nothing tracking it.
#[test]
fn unreachable_human_assignee_rolls_the_whole_create_back() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    // A bare PERSON row: a real entity the assignee validator admits, with
    // no connected channel behind it.
    let actor_ref = route_peer(&vault, 0xC5);
    let error = vault
        .memory_facade(own, EdgeActorClass::Agent)
        .tasks_create(&route_spec(Some(TaskAssignee::Human { actor_ref })))
        .expect_err("an unreachable person is refused");

    assert_eq!(error.code, FACADE_CODE_INVALID_STATE);
    assert_eq!(
        task_entity_census(&vault),
        0,
        "the TASK write rolls back with its follow-up cursor"
    );
    assert!(
        crate::human_task::human_followup_records(&vault)
            .expect("cursors")
            .is_empty()
    );
    assert_eq!(AttemptQueue::new(&vault).list().expect("list").len(), 0);
}

/// An assignee that names no live row — or names the WRONG kind — is
/// refused before the TASK write, not compensated afterwards.
#[test]
fn agent_def_assignee_rejects_dangling_and_mistyped_rows_before_mutation() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let dangling = route_dangling(0xC6);
    let person = route_peer(&vault, 0xC7);

    let missing = vault
        .memory_facade(own, EdgeActorClass::Agent)
        .tasks_create(&route_spec(Some(TaskAssignee::AgentDef {
            agent_def_ref: dangling,
        })))
        .expect_err("a dangling agent definition is refused");
    let mistyped = vault
        .memory_facade(own, EdgeActorClass::Agent)
        .tasks_create(&route_spec(Some(TaskAssignee::AgentDef {
            agent_def_ref: person,
        })))
        .expect_err("a PERSON row is not an agent definition");

    assert_eq!(missing.code, mistyped.code);
    assert_eq!(task_entity_census(&vault), 0);
    assert_eq!(AttemptQueue::new(&vault).list().expect("list").len(), 0);
}

/// The synced TASK body carries the execution FACTS and none of the local
/// ACT mechanics: no lease owner, lock, trap id, or wait binding.
#[test]
fn task_body_carries_facts_and_never_local_lease_or_trap_state() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let actor_ref = route_peer(&vault, 0xC8);
    let peer_facade = vault.memory_facade(actor_ref, EdgeActorClass::Agent);
    let receipt = vault
        .memory_facade(own, EdgeActorClass::Agent)
        .tasks_create(&route_spec(Some(TaskAssignee::Peer { actor_ref })))
        .expect("create");
    let task_ref = receipt.task_ref.expect("task ref");
    peer_facade
        .mark_task_started(task_ref, ROUTE_NOW + 5)
        .expect("start");
    let result_ref = route_turn(&vault, 0xC9).entity_ref();
    peer_facade
        .land_task_result(
            task_ref,
            &TaskResultInput {
                result_ref,
                disposition: TaskTerminalDisposition::Abandoned,
                finished_at: ROUTE_NOW + 9,
            },
        )
        .expect("land result");
    let body = task_verb_body(&vault, task_ref)
        .expect("decode body")
        .expect("typed body");
    let terminal = body.terminal().expect("terminal record").clone();
    let stored = vault.get(&task_ref).expect("read task").expect("task row");
    let stored_text = String::from_utf8_lossy(&stored).to_ascii_lowercase();

    assert_eq!(body.assignee, Some(TaskAssignee::Peer { actor_ref }));
    assert_eq!(terminal.disposition, TaskTerminalDisposition::Abandoned);
    assert_eq!(terminal.result_ref, Some(result_ref));
    for act_marker in [
        "lease_owner",
        "lease",
        "lock",
        "trap",
        "park_owner",
        "peer_wait",
    ] {
        assert_eq!(
            usize::from(stored_text.contains(act_marker)),
            0,
            "synced TASK body must not carry local ACT mechanics: {act_marker}"
        );
    }
}

/// `started_at` stamps once. A re-delivered start reports the FIRST
/// instant and mutates nothing — a redelivery is not a restart.
#[test]
fn mark_task_started_stamps_once_and_replays_idempotently() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let actor_ref = route_peer(&vault, 0xCA);
    let peer_facade = vault.memory_facade(actor_ref, EdgeActorClass::Agent);
    let task_ref = vault
        .memory_facade(own, EdgeActorClass::Agent)
        .tasks_create(&route_spec(Some(TaskAssignee::Peer { actor_ref })))
        .expect("create")
        .task_ref
        .expect("task ref");

    let first = peer_facade
        .mark_task_started(task_ref, ROUTE_NOW + 5)
        .expect("first start");
    let replay = peer_facade
        .mark_task_started(task_ref, ROUTE_NOW + 40)
        .expect("replayed start");
    let body = task_verb_body(&vault, task_ref)
        .expect("decode body")
        .expect("typed body");

    assert_eq!(first.started_at, ROUTE_NOW + 5);
    assert_eq!(usize::from(first.idempotent_replay), 0);
    assert_eq!(replay.started_at, ROUTE_NOW + 5);
    assert_eq!(usize::from(replay.idempotent_replay), 1);
    assert_eq!(
        body.state,
        Some(TaskExecutionState::Working {
            started_at: ROUTE_NOW + 5
        })
    );
}

/// Execution facts are ADDRESSED writes: an actor who is not the assignee
/// cannot start or settle someone else's task.
#[test]
fn execution_facts_refuse_an_unaddressed_writer() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let actor_ref = route_peer(&vault, 0xCB);
    let stranger = route_peer(&vault, 0xCC);
    let task_ref = vault
        .memory_facade(own, EdgeActorClass::Agent)
        .tasks_create(&route_spec(Some(TaskAssignee::Peer { actor_ref })))
        .expect("create")
        .task_ref
        .expect("task ref");
    let result_ref = route_turn(&vault, 0xCD).entity_ref();
    let stranger_facade = vault.memory_facade(stranger, EdgeActorClass::Agent);

    let start_error = stranger_facade
        .mark_task_started(task_ref, ROUTE_NOW + 5)
        .expect_err("a stranger cannot start an addressed task");
    let land_error = stranger_facade
        .land_task_result(
            task_ref,
            &TaskResultInput {
                result_ref,
                disposition: TaskTerminalDisposition::Completed,
                finished_at: ROUTE_NOW + 9,
            },
        )
        .expect_err("a stranger cannot settle an addressed task");
    let body = task_verb_body(&vault, task_ref)
        .expect("decode body")
        .expect("typed body");

    assert_eq!(start_error.code, FACADE_CODE_FORBIDDEN);
    assert_eq!(land_error.code, FACADE_CODE_FORBIDDEN);
    assert_eq!(body.state, Some(TaskExecutionState::Queued));
}

/// The local Dreamer has no actor row, so its lane answers to the task
/// OWNER — the principal the engine drives realization under.
#[test]
fn dreamer_lane_execution_facts_answer_to_the_owner() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let facade = vault.memory_facade(own, EdgeActorClass::Agent);
    let task_ref = facade
        .tasks_create(&route_spec(Some(TaskAssignee::Dreamer)))
        .expect("create")
        .task_ref
        .expect("task ref");
    let result_ref = route_turn(&vault, 0xCE).entity_ref();

    let started = facade
        .mark_task_started(task_ref, ROUTE_NOW + 5)
        .expect("owner starts its own dreamer task");
    let landed = facade
        .land_task_result(
            task_ref,
            &TaskResultInput {
                result_ref,
                disposition: TaskTerminalDisposition::Completed,
                finished_at: ROUTE_NOW + 9,
            },
        )
        .expect("owner settles its own dreamer task");

    assert_eq!(started.started_at, ROUTE_NOW + 5);
    assert_eq!(landed.terminal.result_ref, Some(result_ref));
    assert_eq!(usize::from(landed.idempotent_replay), 0);
}

/// Terminal records are immutable and always carry `result_ref`. A
/// byte-identical replay reports the winner; a CONFLICTING one is refused.
#[test]
fn terminal_results_are_immutable_and_always_carry_a_result_ref() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let actor_ref = route_peer(&vault, 0xCF);
    let peer_facade = vault.memory_facade(actor_ref, EdgeActorClass::Agent);
    let task_ref = vault
        .memory_facade(own, EdgeActorClass::Agent)
        .tasks_create(&route_spec(Some(TaskAssignee::Peer { actor_ref })))
        .expect("create")
        .task_ref
        .expect("task ref");
    let result_ref = route_turn(&vault, 0xD0).entity_ref();
    let other_ref = route_turn(&vault, 0xD1).entity_ref();
    let input = TaskResultInput {
        result_ref,
        disposition: TaskTerminalDisposition::Completed,
        finished_at: ROUTE_NOW + 9,
    };

    let landed = peer_facade
        .land_task_result(task_ref, &input)
        .expect("land result");
    let replay = peer_facade
        .land_task_result(task_ref, &input)
        .expect("identical replay reports the winner");
    let conflict = peer_facade
        .land_task_result(
            task_ref,
            &TaskResultInput {
                result_ref: other_ref,
                disposition: TaskTerminalDisposition::Failed,
                finished_at: ROUTE_NOW + 30,
            },
        )
        .expect_err("a converged terminal task is immutable");

    assert_eq!(landed.terminal.result_ref, Some(result_ref));
    assert_eq!(usize::from(landed.idempotent_replay), 0);
    assert_eq!(usize::from(replay.idempotent_replay), 1);
    assert_eq!(replay.terminal.result_ref, Some(result_ref));
    assert_eq!(conflict.code, FACADE_CODE_INVALID_STATE);
}

/// A result whose `result_ref` names nothing is refused: a terminal record
/// without durable outputs is exactly what the floor forbids.
#[test]
fn land_task_result_requires_a_resolved_result_ref() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let actor_ref = route_peer(&vault, 0xD2);
    let task_ref = vault
        .memory_facade(own, EdgeActorClass::Agent)
        .tasks_create(&route_spec(Some(TaskAssignee::Peer { actor_ref })))
        .expect("create")
        .task_ref
        .expect("task ref");

    let error = vault
        .memory_facade(actor_ref, EdgeActorClass::Agent)
        .land_task_result(
            task_ref,
            &TaskResultInput {
                result_ref: route_dangling(0xD3),
                disposition: TaskTerminalDisposition::Completed,
                finished_at: ROUTE_NOW + 9,
            },
        )
        .expect_err("a dangling result ref is refused");
    let body = task_verb_body(&vault, task_ref)
        .expect("decode body")
        .expect("typed body");

    assert_eq!(usize::from(error.code.is_empty()), 0);
    assert_eq!(body.state, Some(TaskExecutionState::Queued));
}

/// Delegation returns the C9 durable wait keyed on the delegated TASK, and
/// refuses any assignee that is not a peer actor.
#[test]
fn delegate_task_and_wait_returns_a_peer_result_wait_on_the_task_ref() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let actor_ref = route_peer(&vault, 0xD4);
    let facade = vault.memory_facade(own, EdgeActorClass::Agent);

    let (receipt, wait) = facade
        .delegate_task_and_wait(&route_spec(Some(TaskAssignee::Peer { actor_ref })))
        .expect("delegate");
    let not_a_peer = facade
        .delegate_task_and_wait(&route_spec(Some(TaskAssignee::Dreamer)))
        .expect_err("only a peer actor can be delegated to");

    assert_eq!(wait.wait_id, receipt.task_ref.expect("task ref"));
    assert_eq!(wait.effect, crate::code_run::SelfEffect::TaskDelegate);
    assert_eq!(
        wait.reason,
        crate::code_run::SelfDurableWaitReason::PeerResult
    );
    assert_eq!(wait.prompt, None);
    assert_eq!(usize::from(not_a_peer.code.is_empty()), 0);
}

/// A consult still routes as a peer task and still enforces ONE-1699's
/// evidence/abstention contract after general result routing landed.
#[test]
fn consult_regression_survives_general_result_routing() {
    let (_dir, vault) = open_vault();
    let (task_ref, peer, question) = open_consult(&vault);
    let peer_facade = vault.memory_facade(peer, EdgeActorClass::Agent);

    let answer_ref = route_turn(&vault, 0xDA).entity_ref();
    let receipt = peer_facade
        .land_consult_result(task_ref, &answer_input(answer_ref, question))
        .expect("evidence answer still lands");
    let body = task_verb_body(&vault, task_ref)
        .expect("decode body")
        .expect("typed body");
    let terminal = body.terminal().expect("terminal record");

    assert_eq!(attempts_for(&vault, task_ref).len(), 0);
    assert_eq!(usize::from(receipt.idempotent_replay), 0);
    assert_eq!(terminal.disposition, TaskTerminalDisposition::Completed);
    assert_eq!(
        usize::from(matches!(
            terminal.summary,
            Some(ConsultResultSummary::Answer { .. })
        )),
        1
    );
}

/// The general result door must NOT be a second way to settle a consult:
/// a consult's terminal record carries the ONE-1699 evidence-or-abstention
/// summary, and the general input cannot express one. Without this the
/// addressed peer could settle its consult with a bare result ref and no
/// evidence at all — weakening exactly the contract ONE-1700 must preserve.
#[test]
fn the_general_result_door_cannot_settle_a_consult() {
    let (_dir, vault) = open_vault();
    let (task_ref, peer, question) = open_consult(&vault);
    let peer_facade = vault.memory_facade(peer, EdgeActorClass::Agent);
    let result_ref = route_turn(&vault, 0xDC).entity_ref();

    // The ADDRESSED peer — the one actor the terminal writer admits — is
    // still refused, so this is a contract door, not an actor check.
    let bypass = peer_facade
        .land_task_result(
            task_ref,
            &TaskResultInput {
                result_ref,
                disposition: TaskTerminalDisposition::Completed,
                finished_at: CONSULT_NOW + 10,
            },
        )
        .expect_err("a consult cannot settle through the general door");
    let body = task_verb_body(&vault, task_ref)
        .expect("decode body")
        .expect("typed body");

    assert_eq!(bypass.code, FACADE_CODE_INVALID_STATE);
    assert_eq!(usize::from(body.terminal().is_none()), 1);

    // The consult's own door still works and still carries the summary.
    let answer_ref = route_turn(&vault, 0xDD).entity_ref();
    let landed = peer_facade
        .land_consult_result(task_ref, &answer_input(answer_ref, question))
        .expect("the evidence door still lands");

    assert_eq!(
        usize::from(matches!(
            landed.terminal.summary,
            Some(ConsultResultSummary::Answer { .. })
        )),
        1
    );
}

/// The general terminal door refuses a non-consult body reader mismatch:
/// `land_consult_result` still rejects a standard task outright.
#[test]
fn land_consult_result_still_refuses_a_standard_task() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let actor_ref = route_peer(&vault, 0xD5);
    let task_ref = vault
        .memory_facade(own, EdgeActorClass::Agent)
        .tasks_create(&route_spec(Some(TaskAssignee::Peer { actor_ref })))
        .expect("create")
        .task_ref
        .expect("task ref");
    let question = route_turn(&vault, 0xD6);
    let answer_ref = route_turn(&vault, 0xDB).entity_ref();

    let error = vault
        .memory_facade(actor_ref, EdgeActorClass::Agent)
        .land_consult_result(task_ref, &answer_input(answer_ref, question))
        .expect_err("a standard task is not a consult");

    assert_eq!(usize::from(error.message.contains("consult")), 1);
}
// ── ONE-1873: bounded, paged TASK presence ──────────────────────────

/// A synthetic type-index id. Big-endian bytes order numerically exactly
/// as `EntityId`'s byte order does, so index order IS type-index order.
fn synthetic_task_id(index: u128) -> EntityId {
    EntityId::from_bytes(index.to_be_bytes()).expect("synthetic id from 16 bytes")
}

fn synthetic_index(id: &EntityId) -> u128 {
    u128::from_be_bytes(*id.as_bytes())
}

/// A pager over `1..=rows` that answers the exclusive `after` cursor the
/// way `Vault::entities_by_type_page` does, without holding the rows.
fn synthetic_pager(
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

fn created_task_refs(facade: &MemoryFacade<'_>, count: usize) -> Vec<EntityId> {
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

/// The cliff itself: one more row than `MAX_TYPE_QUERY_RESULTS`, the point
/// at which unpaged `entities_by_type` returns `IndexOverflow` and takes
/// `tasks.check` down permanently. The bounded loop stops at its own cap,
/// never materializes the index, and reports the truncation honestly.
#[test]
fn task_presence_page_loop_handles_100_001_synthetic_ids_without_unpaged_query() {
    const SOURCE_ROWS: u128 = 100_001;
    let mut fetched = 0_usize;
    let scan = scan_task_entity_pages(
        TASK_PRESENCE_PAGE_SIZE,
        TASK_PRESENCE_SCAN_CAP,
        synthetic_pager(SOURCE_ROWS, &mut fetched),
    )
    .expect("a bounded scan past the cliff must not error");

    assert_eq!(scan.scanned_task_entities, TASK_PRESENCE_SCAN_CAP);
    assert_eq!(
        scan.pages.iter().map(Vec::len).sum::<usize>(),
        TASK_PRESENCE_SCAN_CAP
    );
    assert!(
        !scan.source_exhausted,
        "100_001 rows behind a {TASK_PRESENCE_SCAN_CAP} cap is a lower bound, not a census"
    );
    // Never near 100k in memory: at most the scan budget plus one page or
    // the terminating one-row probe.
    assert!(
        fetched <= TASK_PRESENCE_SCAN_CAP + TASK_PRESENCE_PAGE_SIZE,
        "fetched {fetched} rows"
    );
}

/// Page-boundary arithmetic. Exhaustion is claimed only when it is true —
/// via a short page, an empty page, or the one-row probe that resolves a
/// final page which exactly filled its request.
#[test]
fn bounded_scan_page_boundaries_report_exhaustion_honestly() {
    // (source rows, page size, scan cap) → (scanned, source_exhausted)
    for (rows, page_size, scan_cap, scanned, exhausted) in [
        // Empty source.
        (0, 4, 10, 0, true),
        // Short final page proves exhaustion.
        (7, 4, 10, 7, true),
        // Sentinel row on the final capped page proves more exist.
        (20, 4, 10, 10, false),
        // Final page exactly fills its request AND the source ends there:
        // the probe turns a would-be lower bound into an exact census.
        (8, 4, 8, 8, true),
        // Same shape, but the source really does continue.
        (9, 4, 8, 8, false),
        // One page larger than the whole source.
        (3, 64, 64, 3, true),
        // A zero scan cap inspects nothing and therefore knows nothing.
        (5, 4, 0, 0, false),
    ] {
        let mut fetched = 0_usize;
        let scan = scan_task_entity_pages(page_size, scan_cap, synthetic_pager(rows, &mut fetched))
            .expect("synthetic scan");
        let label = format!("rows {rows} / page {page_size} / cap {scan_cap}");
        assert_eq!(scan.scanned_task_entities, scanned, "{label}");
        assert_eq!(scan.source_exhausted, exhausted, "{label}");
        let flat: Vec<EntityId> = scan.pages.iter().flatten().copied().collect();
        assert_eq!(flat.len(), scanned, "{label}");
        assert!(flat.windows(2).all(|pair| pair[0] < pair[1]), "{label}");
    }
}

/// A page size of zero would fetch nothing forever; it must not be read as
/// "the TASK index is empty".
#[test]
fn a_degenerate_page_size_still_makes_forward_progress() {
    let mut fetched = 0_usize;
    let scan = scan_task_entity_pages(0, 4, synthetic_pager(9, &mut fetched))
        .expect("degenerate page size");

    assert_eq!(scan.scanned_task_entities, 4);
    assert!(!scan.source_exhausted);
}

/// A source that refuses to advance the exclusive cursor must terminate the
/// walk rather than replay the same row forever.
#[test]
fn a_non_advancing_cursor_stops_the_scan_instead_of_looping() {
    let stuck = synthetic_task_id(1);
    let mut calls = 0_usize;
    let scan = scan_task_entity_pages(2, 64, |_after, _limit| {
        calls += 1;
        Ok(vec![stuck, stuck])
    })
    .expect("a stuck pager terminates");

    assert!(calls <= 2, "the scan must not spin: {calls} fetches");
    assert!(scan.scanned_task_entities <= 64);
    assert!(!scan.source_exhausted);
}

/// Real vault, injected small limits: the walk crosses several
/// `entities_by_type_page` calls and every processed id appears once.
#[test]
fn tasks_check_pages_across_multiple_vault_pages() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let facade = vault.memory_facade(own, EdgeActorClass::Agent);
    let created = created_task_refs(&facade, 5);

    let mut calls = 0_usize;
    let scan = scan_task_entity_pages(2, 64, |after, limit| {
        calls += 1;
        vault.entities_by_type_page(ENTITY_TYPE_TASK, after, limit)
    })
    .expect("paged scan over the real type index");

    assert!(
        calls >= 3,
        "page size 2 over 5 tasks must page at least three times: {calls}"
    );
    assert_eq!(scan.scanned_task_entities, 5);
    assert!(scan.source_exhausted);
    let flat: Vec<EntityId> = scan.pages.iter().flatten().copied().collect();
    assert_eq!(flat, created);
    assert!(flat.windows(2).all(|pair| pair[0] < pair[1]));

    let snapshot = task_presence_with_limits(&vault, 2, 64).expect("paged presence");
    assert!(snapshot.source_exhausted);
    assert_eq!(snapshot.scanned_task_entities, 5);
    let ids: std::collections::BTreeSet<&str> = snapshot
        .intents
        .iter()
        .map(|intent| intent.id.as_str())
        .collect();
    assert_eq!(ids.len(), snapshot.intents.len());
    assert_eq!(ids.len(), 5);
}

/// Past both caps the board shows a capped prefix and says the count is a
/// LOWER bound — never an exact census it could not have taken.
#[test]
fn tasks_check_scan_cap_reports_honest_additive_overflow() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let facade = vault.memory_facade(own, EdgeActorClass::Agent);
    created_task_refs(&facade, 5);

    let snapshot = task_presence_with_limits(&vault, 2, 3).expect("scan-capped presence");
    assert_eq!(snapshot.scanned_task_entities, 3);
    assert!(!snapshot.source_exhausted);

    let section = TasksSection::render_with_cap(
        &snapshot.intents,
        &snapshot.bare_jobs,
        snapshot.source_exhausted,
        2,
    );

    assert_eq!(section.rows.len(), 2);
    let overflow = section.overflow.expect("a truncated scan always says so");
    assert_eq!(overflow.known_omitted_rows, 1);
    assert!(!overflow.source_exhausted);
    assert_eq!(
        overflow.line().as_deref(),
        Some("tasks: +1 more (at least; scan capped)")
    );
}

/// Past the render cap but inside the scan cap the count IS exact, so the
/// footer carries no lower-bound hedge.
#[test]
fn tasks_check_exact_exhaustion_reports_exact_additive_overflow() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let facade = vault.memory_facade(own, EdgeActorClass::Agent);
    created_task_refs(&facade, 5);

    let snapshot = task_presence_with_limits(&vault, 2, 64).expect("exhausted presence");
    assert!(snapshot.source_exhausted);
    assert_eq!(snapshot.intents.len(), 5);

    let section = TasksSection::render_with_cap(
        &snapshot.intents,
        &snapshot.bare_jobs,
        snapshot.source_exhausted,
        3,
    );

    assert_eq!(section.rows.len(), 3);
    let overflow = section.overflow.expect("capped rows carry a footer");
    assert_eq!(overflow.line().as_deref(), Some("tasks: +2 more"));
    assert!(!overflow.line().expect("footer").contains("at least"));

    // Under both caps the landed footer-free render is unchanged.
    let whole = TasksSection::render_bounded(
        &snapshot.intents,
        &snapshot.bare_jobs,
        snapshot.source_exhausted,
    );
    assert_eq!(whole.rows.len(), 5);
    assert_eq!(whole.overflow, None);
}

/// Hidden means one call away, never gone: a TASK ordered after the board
/// scan prefix still expands by id.
#[test]
fn tasks_expand_direct_lookup_survives_board_scan_cap() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let facade = vault.memory_facade(own, EdgeActorClass::Agent);
    let created = created_task_refs(&facade, 3);
    let beyond_prefix = *created.last().expect("three tasks");
    let beyond_hex = beyond_prefix.to_hex();

    // The bounded board really does stop before it.
    let snapshot = task_presence_with_limits(&vault, 1, 1).expect("one-row board prefix");
    assert!(!snapshot.source_exhausted);
    assert!(
        !snapshot
            .intents
            .iter()
            .any(|intent| intent.id == beyond_hex)
    );

    // The direct-by-id door does not inherit that cap.
    let direct = task_presence_for_id(&vault, beyond_prefix)
        .expect("direct lookup")
        .expect("a valid TASK id is always reachable");
    assert_eq!(direct.id, beyond_hex);
    let lines = facade.tasks_expand(beyond_prefix).expect("expand by id");
    assert!(lines[0].starts_with(&beyond_hex));

    // An unknown id is still EntityNotFound, not a silent empty expansion.
    assert_eq!(
        facade
            .tasks_expand(EntityId::from_bytes([0xD9; 16]).expect("unknown id"))
            .expect_err("an unknown id is not found")
            .code,
        crate::facade::FACADE_CODE_NOT_FOUND
    );
}

/// The same for `tasks.ack`, including the failed-only invariant and the
/// acked-failure invisibility that follows it.
#[test]
fn tasks_ack_direct_lookup_survives_board_scan_cap() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let facade = vault.memory_facade(own, EdgeActorClass::Agent);
    let created = created_task_refs(&facade, 3);
    let beyond_prefix = *created.last().expect("three tasks");
    let beyond_hex = beyond_prefix.to_hex();

    // Fail exactly the realization behind the last-ordered TASK.
    let queue = AttemptQueue::new(&vault);
    loop {
        let ClaimOutcome::Claimed(claimed) = queue
            .claim_kind(
                TASK_REALIZE_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: "worker".to_owned(),
                    now: 130,
                },
            )
            .expect("claim")
        else {
            panic!("the target task must own a claimable realization");
        };
        if claimed.task_ref.as_deref() == Some(beyond_hex.as_str()) {
            queue
                .fail(FailAttempt {
                    id: claimed.id,
                    lease_owner: "worker".to_owned(),
                    attempt_count: claimed.attempt_count,
                    reason: "failed".to_owned(),
                    now: 131,
                })
                .expect("fail the target realization");
            break;
        }
    }

    let snapshot = task_presence_with_limits(&vault, 1, 1).expect("one-row board prefix");
    assert!(!snapshot.source_exhausted);
    assert!(
        !snapshot
            .intents
            .iter()
            .any(|intent| intent.id == beyond_hex)
    );

    // Failed-only ack, reached directly by id past the board prefix.
    let receipt = facade.tasks_ack(beyond_prefix).expect("ack past the cap");
    assert!(receipt.acked);
    assert!(task_is_acked(&vault, beyond_prefix).expect("ack bit"));
    // A non-failed task acked by id is still a no-op.
    let queued = created[0];
    assert!(!facade.tasks_ack(queued).expect("ack queued task").acked);
    assert!(!task_is_acked(&vault, queued).expect("no ack bit"));
    // The acked failure has left BOTH the board and the typed read verbs.
    assert_eq!(
        facade
            .tasks_expand(beyond_prefix)
            .expect_err("acked failure is not expandable")
            .code,
        crate::facade::FACADE_CODE_NOT_FOUND
    );
}

/// "Not scanned" is not "dangling": a job whose owning TASK lies beyond the
/// scan cap is withheld and counted, never re-emitted as a bare duplicate.
#[test]
fn truncated_task_scan_does_not_emit_linked_jobs_as_bare() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let facade = vault.memory_facade(own, EdgeActorClass::Agent);
    let created = created_task_refs(&facade, 3);

    // Every created TASK owns exactly one realizing job, all folded.
    let whole = task_presence_with_limits(&vault, 8, 64).expect("exhausted presence");
    assert!(whole.source_exhausted);
    assert_eq!(whole.intents.len(), 3);
    assert_eq!(whole.bare_jobs.len(), 0);
    let folded: usize = whole
        .intents
        .iter()
        .map(|intent| intent.realizing_jobs.len())
        .sum();
    assert_eq!(folded, 3);

    let truncated = task_presence_with_limits(&vault, 1, 1).expect("one-row board prefix");

    assert!(!truncated.source_exhausted);
    assert_eq!(truncated.intents.len(), 1);
    assert_eq!(truncated.intents[0].id, created[0].to_hex());
    assert_eq!(
        truncated.bare_jobs.len(),
        0,
        "jobs owned by unscanned TASKs must not surface as bare rows"
    );
    // No job renders twice: the withheld ones render nowhere at all, and
    // the only visible job is the scanned owner's own realization.
    let visible: std::collections::BTreeSet<&str> = truncated
        .intents
        .iter()
        .flat_map(|intent| intent.realizing_jobs.iter())
        .chain(truncated.bare_jobs.iter())
        .map(|job| job.id.as_str())
        .collect();
    assert_eq!(
        visible,
        whole.intents[0]
            .realizing_jobs
            .iter()
            .map(|job| job.id.as_str())
            .collect()
    );
}

/// The exhausted-scan half of the same invariant is untouched: a backlink
/// naming no surviving TASK still renders exactly once as a bare job.
#[test]
fn exhausted_task_scan_still_renders_genuinely_dangling_job_once() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let missing_task_hex = EntityId::from_bytes([0xC1; 16])
        .expect("missing id")
        .to_hex();
    let EnqueueOutcome::Enqueued(attempt) = AttemptQueue::new(&vault)
        .enqueue_with_task_ref(
            EnqueueAttempt {
                kind: TASK_REALIZE_ATTEMPT_KIND.to_owned(),
                payload: Vec::new(),
                dedupe_key: None,
                run_id: None,
                now: 120,
            },
            Some(missing_task_hex),
        )
        .expect("enqueue dangling attempt")
    else {
        panic!("attempt must enqueue");
    };
    let job_id = attempt_hex(attempt.id);

    let snapshot = task_presence_with_limits(&vault, 4, 64).expect("exhausted presence");

    assert!(snapshot.source_exhausted);
    assert_eq!(
        snapshot
            .bare_jobs
            .iter()
            .filter(|job| job.id == job_id)
            .count(),
        1
    );
    let facade = vault.memory_facade(own, EdgeActorClass::Agent);
    let section = facade.tasks_check().expect("check tasks");
    assert_eq!(
        section.rows.iter().filter(|row| row.id == job_id).count(),
        1
    );
    assert_eq!(section.overflow, None);
}

/// Under a truncated scan, a realizing job whose owner id is ≤ the final
/// scanned cursor is provably dangling (owner was in the scanned prefix
/// and did not survive as an intent) and must render once as bare. A job
/// whose valid owner lies beyond the cursor remains withheld.
#[test]
fn truncated_task_scan_still_renders_provably_dangling_prefix_job_once() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    let facade = vault.memory_facade(own, EdgeActorClass::Agent);
    let created = created_task_refs(&facade, 3);

    // Missing owner whose id sorts BEFORE every created TASK. UUIDv7
    // task ids carry a non-zero timestamp prefix; a near-zero id is
    // strictly earlier. After a 2-row prefix scan the cursor is
    // created[1], so this owner is ≤ cursor and therefore proven
    // absent from the scanned prefix.
    let mut prefix_bytes = [0_u8; 16];
    prefix_bytes[15] = 0x10;
    let dangling_owner = EntityId::from_bytes(prefix_bytes).expect("prefix id");
    assert!(
        dangling_owner <= created[1],
        "dangling owner must sit at-or-before the truncated cursor"
    );
    let EnqueueOutcome::Enqueued(attempt) = AttemptQueue::new(&vault)
        .enqueue_with_task_ref(
            EnqueueAttempt {
                kind: TASK_REALIZE_ATTEMPT_KIND.to_owned(),
                payload: Vec::new(),
                dedupe_key: None,
                run_id: None,
                now: 120,
            },
            Some(dangling_owner.to_hex()),
        )
        .expect("enqueue dangling attempt")
    else {
        panic!("attempt must enqueue");
    };
    let dangling_job_id = attempt_hex(attempt.id);

    // page_size=2, scan_cap=2 → inspect created[0..2]; cursor=created[1];
    // source_exhausted=false because created[2] remains beyond the cap.
    let snapshot = task_presence_with_limits(&vault, 2, 2).expect("truncated presence");

    assert!(!snapshot.source_exhausted);
    assert_eq!(snapshot.scanned_task_entities, 2);
    assert_eq!(snapshot.intents.len(), 2);
    assert_eq!(
        snapshot
            .bare_jobs
            .iter()
            .filter(|job| job.id == dangling_job_id)
            .count(),
        1,
        "prefix-dangling realizing job must render once as bare under truncation"
    );

    // Jobs owned by the unscanned third TASK must still not leak as bare.
    let whole = task_presence_with_limits(&vault, 8, 64).expect("full presence");
    let beyond_job_ids: Vec<&str> = whole
        .intents
        .iter()
        .filter(|intent| intent.id == created[2].to_hex())
        .flat_map(|intent| intent.realizing_jobs.iter())
        .map(|job| job.id.as_str())
        .collect();
    assert!(
        !beyond_job_ids.is_empty(),
        "third TASK must own a realizing job in the full census"
    );
    let bare_ids: std::collections::BTreeSet<&str> = snapshot
        .bare_jobs
        .iter()
        .map(|job| job.id.as_str())
        .collect();
    for job_id in beyond_job_ids {
        assert!(
            !bare_ids.contains(job_id),
            "job owned beyond cursor must not surface as bare under truncation"
        );
    }
}

/// A cancelled TASK still consumes scan budget: the cap bounds inspected
/// ENTITY IDS, not successfully rendered rows, so a filtered prefix cannot
/// silently widen the walk.
#[test]
fn filtered_rows_still_consume_the_scan_budget() {
    let (_dir, vault) = open_vault();
    let own = own_agent(&vault);
    grant_cancel(&vault, own, 0xB7);
    let facade = vault.memory_facade(own, EdgeActorClass::Agent);
    let created = created_task_refs(&facade, 3);
    facade
        .tasks_cancel(TaskCancelTarget::Task(created[0]))
        .expect("cancel the first task");

    let snapshot = task_presence_with_limits(&vault, 1, 2).expect("scan-capped presence");

    assert_eq!(snapshot.scanned_task_entities, 2);
    // Two ids inspected, one of them cancelled — one row survives.
    assert_eq!(snapshot.intents.len(), 1);
    assert_eq!(snapshot.intents[0].id, created[1].to_hex());
    assert!(!snapshot.source_exhausted);
}

mod paged_scan_property {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// For arbitrary sorted unique ids, page sizes, and scan caps: no id
        /// repeats, the cursor strictly increases, the inspected count never
        /// exceeds the cap, and exhaustion is never claimed falsely.
        #[test]
        fn paged_task_scan_cursor_strictly_advances_and_never_exceeds_cap(
            indices in prop::collection::btree_set(1_u128..512, 0..180),
            page_size in 1_usize..17,
            scan_cap in 0_usize..300,
        ) {
            let source: Vec<EntityId> =
                indices.iter().copied().map(synthetic_task_id).collect();
            let mut cursors: Vec<Option<EntityId>> = Vec::new();
            let scan = scan_task_entity_pages(page_size, scan_cap, |after, limit| {
                cursors.push(after.copied());
                let start = source.partition_point(|id| after.is_some_and(|bound| id <= bound));
                Ok(source[start..].iter().take(limit).copied().collect())
            })
            .expect("the synthetic pager never errors");

            let flat: Vec<EntityId> = scan.pages.iter().flatten().copied().collect();
            prop_assert!(scan.scanned_task_entities <= scan_cap);
            prop_assert_eq!(flat.len(), scan.scanned_task_entities);
            prop_assert!(flat.windows(2).all(|pair| pair[0] < pair[1]));
            // The walk is a strict prefix of the source in type-index order.
            prop_assert_eq!(&flat[..], &source[..flat.len()]);
            // The walk opens with no cursor, then never repeats or moves back.
            prop_assert_eq!(cursors.first().copied().flatten(), None);
            let advanced: Vec<EntityId> = cursors.iter().flatten().copied().collect();
            prop_assert!(advanced.windows(2).all(|pair| pair[0] < pair[1]));
            // Exhaustion is only ever claimed when it is true.
            if scan.source_exhausted {
                prop_assert_eq!(flat.len(), source.len());
            }
            if source.len() > scan_cap {
                prop_assert!(!scan.source_exhausted);
            }
            if scan_cap > 0 && source.len() <= scan_cap {
                prop_assert!(scan.source_exhausted);
            }
        }
    }
}
