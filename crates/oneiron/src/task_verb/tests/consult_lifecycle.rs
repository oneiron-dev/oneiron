//! Task verb tests: Consult create and schema, result contract, replica settle, answer-vs-expiry, fan-out, expiry digest and sync.

use super::support::*;
use super::*;

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
        .memory(own, EdgeActorClass::Agent)
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
        .memory(own, EdgeActorClass::Agent)
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
    let facade = vault.memory(asker, EdgeActorClass::Agent);
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
            .filter(|code| *code == crate::memory::MEMORY_CODE_BAD_REQUEST
                || *code == crate::memory::MEMORY_CODE_NOT_FOUND)
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
        .memory(stranger, EdgeActorClass::Agent)
        .land_consult_result(task_ref, &answer_input(result_ref, question))
        .expect_err("a stranger may not answer an addressed consult");
    let evidence_free = vault
        .memory(peer, EdgeActorClass::Agent)
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
        .memory(peer, EdgeActorClass::Agent)
        .land_consult_result(task_ref, &answer_input(result_ref, question))
        .expect("the addressed peer answers");
    let stored = task_verb_body(&vault, task_ref)
        .expect("decode body")
        .expect("typed body");

    assert_eq!(by_stranger.code, crate::memory::MEMORY_CODE_FORBIDDEN);
    assert_eq!(evidence_free.code, crate::memory::MEMORY_CODE_BAD_REQUEST);
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
    let facade = vault.memory(peer, EdgeActorClass::Agent);

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
    assert_eq!(conflicting.code, crate::memory::MEMORY_CODE_INVALID_STATE);
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
        .memory(asker, EdgeActorClass::Agent)
        .tasks_create(&consult_spec(question, peer, CONSULT_DEADLINE))
        .expect("second consult")
        .task_ref
        .expect("second task ref");
    let result_ref = consult_turn(&vault, 0x80).entity_ref();
    let peer_facade = vault.memory(peer, EdgeActorClass::Agent);
    peer_facade
        .land_consult_result(answered, &answer_input(result_ref, question))
        .expect("the first consult is answered before the deadline");

    let report = vault
        .memory(asker, EdgeActorClass::Agent)
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
    assert_eq!(late.code, crate::memory::MEMORY_CODE_INVALID_STATE);
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
    let facade = vault.memory(asker, EdgeActorClass::Agent);
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

    assert_eq!(duplicated.code, crate::memory::MEMORY_CODE_BAD_REQUEST);
    assert_eq!(empty.code, crate::memory::MEMORY_CODE_BAD_REQUEST);
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
    let facade = vault.memory(asker, EdgeActorClass::Agent);

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
    let facade = vault.memory(asker, EdgeActorClass::Agent);
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
    let facade = vault.memory(asker, EdgeActorClass::Agent);
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
