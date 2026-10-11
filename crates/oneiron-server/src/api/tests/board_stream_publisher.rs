//! Own-task events reach STREAM subscribers through serve's board publisher.

use super::*;

/// Polls the server's stream registry until `probe` answers, or panics.
async fn eventually<T>(
    server: &Arc<SyncServer>,
    mut probe: impl FnMut(&mut oneiron::context_board::BoardStreamRegistry) -> Option<T>,
) -> T {
    for _ in 0..200 {
        if let Some(found) = probe(server.mcp_registry.lock().await.streams_mut()) {
            return found;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("the board publisher never routed the committed TASK");
}

/// D2b-1 row 4 (ARCH-0067 §5): "Wake-class events are mintable from own-task
/// events", default subscription "my tasks · consults to me". An ask lands a
/// consult on its responder's STREAM connection as a WAKE, and the answer
/// reaches the asker's next tool result as a CARRIER delta. Nothing here
/// injects an event: both come from the committed TASKs.
#[tokio::test]
async fn an_ask_wakes_its_responder_and_the_answer_rides_the_askers_next_result() {
    let (_dir, server) = auth_test_server();
    let _publisher = server.spawn_board_publisher();
    let actor = seeded_test_entity_id(0xd2b1_0004);
    let credential = "d2b1-board-publisher";
    register_mcp_actor(&server, credential, actor, oneiron::EdgeActorClass::Human).await;
    let connection = {
        let registry = server.mcp_registry.lock().await;
        registry
            .resolve(
                &mcp_registered_credential(&server, credential),
                1,
                |_, _| true,
            )
            .expect("credential resolves")
            .stream_connection
    };
    // The keyframe a STREAM consumer holds before any delta can ride.
    let (status, _) = route_json(
        server.clone(),
        mcp_endpoint_call_request(
            "/mcp",
            credential,
            "publisher-setup",
            "setup_oneiron",
            mcp_endpoint_envelope(actor, "read_board"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let turn = seeded_test_entity_id(0xd2b1_0005);
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![(
            rmpv::Value::from("role"),
            rmpv::Value::from("question"),
        )]),
    )
    .expect("turn body");
    server
        .vault()
        .put_entity(
            &turn,
            oneiron::registry::ENTITY_TYPE_TURN,
            oneiron::TimeRange { start: 2, end: 2 },
            2,
            &body,
        )
        .expect("question turn");
    let reference = oneiron::task_verb::ConsultPayloadRef::parse(
        server.vault(),
        &format!("tn_{}", turn.to_hex()),
    )
    .expect("turn ref");
    let memory = server.vault().memory(actor, oneiron::EdgeActorClass::Human);
    let ask = oneiron::task_verb::TaskAskSpec {
        intent_key: "d2b1-board-publisher".into(),
        ..oneiron::task_verb::TaskAskSpec::shorthand(
            Some(oneiron::task_verb::TaskAskTarget::Responder(
                oneiron::task_verb::TaskAssignee::Human { actor_ref: actor },
            )),
            oneiron::task_verb::TaskAskQuestion::new(reference),
            Some(u64::MAX),
            oneiron::task_verb::TaskAskDefault::AskMe,
        )
    };
    let receipt = memory.tasks_ask(&ask).expect("ask lands");

    let wake = eventually(&server, |streams| streams.next_wake(&connection)).await;
    assert_eq!(
        wake.actor_ref,
        actor.to_hex(),
        "the consult's addressee is woken"
    );
    let member = wake.task_ref.clone();

    memory
        .tasks_answer(
            &receipt.handle,
            &oneiron::task_verb::TaskAskWord::new(actor),
        )
        .expect("answer lands");
    // The done delta queues behind the answer's commit; the next arbitrary
    // tool result drains it.
    let key = format!("tasks:{member}");
    let mut delta = None;
    for attempt in 0..200 {
        let (status, result) = route_json(
            server.clone(),
            mcp_endpoint_call_request(
                MCP_TOOL_FIRST_PATH,
                credential,
                &format!("publisher-next-{attempt}"),
                "describe",
                mcp_endpoint_envelope(actor, "read_tasks"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let frame = &result["result"]["carrier"]["frame"];
        if let Some(rows) = frame["kind"]["payload"].as_array()
            && let Some(row) = rows.iter().find(|row| row["key"] == key.as_str())
        {
            delta = Some(row.clone());
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let delta = delta.expect("the answered consult rides the asker's next tool result");
    let line = delta["line"].as_str().expect("delta line");
    assert!(
        line.split_whitespace().any(|token| token == "done"),
        "{line}"
    );
}

/// A fresh human actor with a registered STREAM connection that holds its
/// keyframe (the setup call also binds its reader).
async fn stream_actor(
    server: &Arc<SyncServer>,
    seed: u128,
    credential: &str,
) -> (
    oneiron::EntityId,
    oneiron::context_board::StreamConnectionId,
) {
    let actor = seeded_test_entity_id(seed);
    register_mcp_actor(server, credential, actor, oneiron::EdgeActorClass::Human).await;
    let connection = server
        .mcp_registry
        .lock()
        .await
        .resolve(&mcp_registered_credential(server, credential), 1, |_, _| {
            true
        })
        .expect("credential resolves")
        .stream_connection;
    let (status, _) = route_json(
        server.clone(),
        mcp_endpoint_call_request(
            "/mcp",
            credential,
            "publisher-setup",
            "setup_oneiron",
            mcp_endpoint_envelope(actor, "read_board"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    (actor, connection)
}

/// `actor` asks itself one question: the consult wakes `actor`.
fn ask(
    server: &SyncServer,
    actor: oneiron::EntityId,
    seed: u128,
) -> oneiron::task_verb::TaskAskReceipt {
    let turn = seeded_test_entity_id(seed);
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![(
            rmpv::Value::from("role"),
            rmpv::Value::from("question"),
        )]),
    )
    .expect("turn body");
    server
        .vault()
        .put_entity(
            &turn,
            oneiron::registry::ENTITY_TYPE_TURN,
            oneiron::TimeRange { start: 2, end: 2 },
            2,
            &body,
        )
        .expect("question turn");
    let reference = oneiron::task_verb::ConsultPayloadRef::parse(
        server.vault(),
        &format!("tn_{}", turn.to_hex()),
    )
    .expect("turn ref");
    server
        .vault()
        .memory(actor, oneiron::EdgeActorClass::Human)
        .tasks_ask(&oneiron::task_verb::TaskAskSpec {
            intent_key: format!("d2b1-board-{seed}"),
            ..oneiron::task_verb::TaskAskSpec::shorthand(
                Some(oneiron::task_verb::TaskAskTarget::Responder(
                    oneiron::task_verb::TaskAssignee::Human { actor_ref: actor },
                )),
                oneiron::task_verb::TaskAskQuestion::new(reference),
                Some(u64::MAX),
                oneiron::task_verb::TaskAskDefault::AskMe,
            )
        })
        .expect("ask lands")
}

/// `actor` asks itself and answers at once: the answer queues a done delta
/// for `actor`. Returns the ask's TASKs.
fn ask_and_answer(
    server: &SyncServer,
    actor: oneiron::EntityId,
    seed: u128,
) -> Vec<oneiron::EntityId> {
    let receipt = ask(server, actor, seed);
    server
        .vault()
        .memory(actor, oneiron::EdgeActorClass::Human)
        .tasks_answer(
            &receipt.handle,
            &oneiron::task_verb::TaskAskWord::new(actor),
        )
        .expect("answer lands");
    receipt.task_refs
}

/// Waits until `witness` has been woken by its own later consult. The
/// publisher routes announcements in commit order, so everything committed
/// before that ask has been routed by then. The witness's wakes are drained
/// while it waits, so a later fence never returns on an earlier wake.
async fn publisher_passed(
    server: &Arc<SyncServer>,
    witness: oneiron::EntityId,
    connection: &oneiron::context_board::StreamConnectionId,
    seed: u128,
) {
    let asked = ask(server, witness, seed)
        .task_refs
        .iter()
        .map(oneiron::EntityId::to_hex)
        .collect::<Vec<_>>();
    eventually(server, |streams| {
        streams
            .drain_wakes(connection)
            .iter()
            .any(|wake| asked.contains(&wake.task_ref))
            .then_some(())
    })
    .await;
}

/// The carrier rows the next few tool results deliver to the connection
/// `credential` holds, each call sent under `envelope`.
async fn delivered_rows(server: &Arc<SyncServer>, credential: &str, envelope: Value) -> Vec<Value> {
    let mut rows = Vec::new();
    for attempt in 0..3 {
        let (status, result) = route_json(
            server.clone(),
            mcp_endpoint_call_request(
                MCP_TOOL_FIRST_PATH,
                credential,
                &format!("delivered-{attempt}"),
                "describe",
                envelope.clone(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{result}");
        if let Some(payload) = result["result"]["carrier"]["frame"]["kind"]["payload"].as_array() {
            rows.extend(payload.iter().cloned());
        }
    }
    rows
}

fn names_any(rows: &[Value], tasks: &[oneiron::EntityId]) -> bool {
    rows.iter().any(|row| {
        tasks
            .iter()
            .any(|task| row["key"] == format!("tasks:{}", task.to_hex()).as_str())
    })
}

/// A matching core:read grant narrows `actor`'s read to TURNs; without one,
/// its slip alone would read its own TASK.
fn reads_turns_only(server: &SyncServer, actor: oneiron::EntityId, seed: u128) {
    let mut read = oneiron::federation::Scope::top();
    read.verbs = oneiron::federation::ScopeAxis::Some(["read".to_owned()].into());
    let owner = server.vault().ensure_embedded_owner_actor().expect("owner");
    oneiron::conversation_dag::test_support::put_test_policy_manifest(
        server.vault(),
        oneiron::WriteActor::new(owner, oneiron::EdgeActorClass::Human),
        seeded_test_entity_id(seed),
        &json!({
            "schema_version": "1.2", "pack_id": "turns-only", "pack_version": "1",
            "min_engine_version": "0.0.0", "defaults": {}, "rules": [], "actor_ceilings": [],
            "scoped_grants": [{
                "actor_ref": actor.to_hex(),
                "effector": "core:read",
                "scope": serde_json::to_value(read).unwrap(),
                "selectors": {"entity_types": [oneiron::registry::ENTITY_TYPE_TURN]},
                "receipt_required": false,
            }],
        }),
    )
    .expect("turns-only read grant");
}

/// Astra #1353 finding 1: a subscription is not a read grant. The owner's
/// live read admits TURNs only, so its own TASKs never reach its STREAM: no
/// WAKE for its open consult, and no done delta on its next results.
#[tokio::test]
async fn a_task_outside_its_owners_read_grant_never_reaches_their_stream() {
    let (_dir, server) = auth_test_server();
    let _publisher = server.spawn_board_publisher();
    let (actor, connection) = stream_actor(&server, 0xd2b1_0010, "d2b1-turns-only").await;
    let (witness, witness_connection) = stream_actor(&server, 0xd2b1_0011, "d2b1-witness").await;
    reads_turns_only(&server, actor, 0xd2b1_0012);

    // An open consult would wake its owner; a done one would ride a result.
    ask(&server, actor, 0xd2b1_0015);
    let tasks = ask_and_answer(&server, actor, 0xd2b1_0013);
    publisher_passed(&server, witness, &witness_connection, 0xd2b1_0014).await;

    assert!(
        server
            .mcp_registry
            .lock()
            .await
            .streams_mut()
            .next_wake(&connection)
            .is_none(),
        "an unreadable TASK woke its owner"
    );
    let rows = delivered_rows(
        &server,
        "d2b1-turns-only",
        mcp_endpoint_envelope(actor, "read_tasks"),
    )
    .await;
    assert!(!names_any(&rows, &tasks), "{rows:?}");
}

/// Astra #1353 finding 1: a queued line is read again when it would ride. The
/// done delta is queued, the TASK is erased, and the line is never delivered.
#[tokio::test]
async fn an_erased_tasks_queued_line_is_never_delivered() {
    let (_dir, server) = auth_test_server();
    let _publisher = server.spawn_board_publisher();
    let (actor, _) = stream_actor(&server, 0xd2b1_0020, "d2b1-erased").await;
    let (witness, witness_connection) =
        stream_actor(&server, 0xd2b1_0021, "d2b1-erase-witness").await;

    let tasks = ask_and_answer(&server, actor, 0xd2b1_0022);
    publisher_passed(&server, witness, &witness_connection, 0xd2b1_0023).await;
    for task in &tasks {
        server
            .vault()
            .delete_entity_with_reason(task, oneiron::DeleteReason::UserHardDelete)
            .expect("erase the TASK");
    }

    let rows = delivered_rows(
        &server,
        "d2b1-erased",
        mcp_endpoint_envelope(actor, "read_tasks"),
    )
    .await;
    assert!(!names_any(&rows, &tasks), "{rows:?}");
}

/// Claims the next queued realization and fails it: the TASK it realizes
/// folds to `failed`.
fn fail_next_realization(server: &SyncServer) {
    let queue = oneiron::AttemptQueue::new(server.vault());
    let now = server.vault().now_recorded_at();
    let oneiron::attempt_queue::ClaimOutcome::Claimed(leased) = queue
        .claim_kind(
            "tasks.realize",
            oneiron::attempt_queue::ClaimAttempt {
                lease_owner: "board-wake-worker".to_owned(),
                now,
            },
        )
        .expect("claim")
    else {
        panic!("a realization is queued");
    };
    queue
        .fail(oneiron::attempt_queue::FailAttempt {
            id: leased.id,
            lease_owner: "board-wake-worker".to_owned(),
            attempt_count: leased.attempt_count,
            reason: "the worker stopped".to_owned(),
            now,
        })
        .expect("fail");
}

/// ARCH-0067 `#wake-envelope-id`: a TASK that fails, is realized again and
/// fails again queues two WAKEs with two envelope ids, and the host's drain
/// hands each over once. Nothing between the two failures is announced.
#[tokio::test]
async fn a_task_that_fails_twice_wakes_its_owner_twice_and_each_wake_drains_once() {
    let (_dir, server) = auth_test_server();
    let _publisher = server.spawn_board_publisher();
    let (actor, connection) = stream_actor(&server, 0xb0a1_0001, "wake-fails-twice").await;
    let (witness, witness_connection) =
        stream_actor(&server, 0xb0a1_0002, "wake-fails-twice-witness").await;
    let task = server
        .vault()
        .memory(actor, oneiron::EdgeActorClass::Human)
        .tasks_create(&oneiron::task_verb::TaskCreateSpec::new(
            rmpv::Value::from("fails twice"),
            None,
            None,
            None,
        ))
        .expect("create")
        .task_ref
        .expect("task ref");

    fail_next_realization(&server);
    let mut wakes = Vec::new();
    eventually(&server, |streams| {
        wakes.extend(streams.drain_wakes(&connection));
        (!wakes.is_empty()).then_some(())
    })
    .await;
    // The TASK is realized again, and that try fails too.
    oneiron::AttemptQueue::new(server.vault())
        .enqueue_with_task_ref(
            oneiron::attempt_queue::EnqueueAttempt {
                kind: "tasks.realize".to_owned(),
                payload: Vec::new(),
                dedupe_key: None,
                run_id: None,
                now: server.vault().now_recorded_at(),
            },
            Some(task.to_hex()),
        )
        .expect("realize again");
    fail_next_realization(&server);
    eventually(&server, |streams| {
        wakes.extend(streams.drain_wakes(&connection));
        (wakes.len() >= 2).then_some(())
    })
    .await;

    assert_eq!(wakes.len(), 2, "{wakes:?}");
    let failed = format!("{}:failed:", task.to_hex());
    for wake in &wakes {
        assert_eq!(wake.task_ref, task.to_hex());
        assert!(wake.event_ref.starts_with(&failed), "{}", wake.event_ref);
    }
    assert_ne!(wakes[0].event_ref, wakes[1].event_ref);
    // Each was handed over once: once the publisher has passed, nothing is
    // left to drain.
    publisher_passed(&server, witness, &witness_connection, 0xb0a1_0003).await;
    assert!(
        server
            .mcp_registry
            .lock()
            .await
            .streams_mut()
            .drain_wakes(&connection)
            .is_empty()
    );
}

/// `actor`'s STREAM connection under a credential narrowed to `world`, holding
/// its keyframe (the setup call also binds its reader).
async fn narrowed_stream(
    server: &Arc<SyncServer>,
    actor: oneiron::EntityId,
    credential: &str,
    world: oneiron::EntityId,
) -> (Value, oneiron::context_board::StreamConnectionId) {
    let scope = crate::mcp::McpConnectorScope::scoped(Some(world), None);
    register_scoped_mcp_actor(server, credential, actor, scope.clone()).await;
    let connection = server
        .mcp_registry
        .lock()
        .await
        .resolve(&mcp_registered_credential(server, credential), 1, |_, _| {
            true
        })
        .expect("credential resolves")
        .stream_connection;
    let (status, result) = route_json(
        server.clone(),
        mcp_endpoint_call_request(
            "/mcp",
            credential,
            "narrowed-setup",
            "setup_oneiron",
            mcp_scoped_envelope(actor, "read_board", &scope),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(result.get("error").is_none(), "{result:#}");
    (mcp_scoped_envelope(actor, "read_tasks", &scope), connection)
}

/// ARCH-0067 §5, "Default subscription: my tasks · my children · consults to
/// me", for a world-narrowed connection. One actor holds two credentials: one
/// narrowed to base reality, where its TASKs are born, and one narrowed to
/// another world. The first hears its own task's failed WAKE and done CARRIER
/// delta; the second hears neither.
#[tokio::test]
async fn a_world_narrowed_connection_hears_its_own_tasks_only_inside_its_world() {
    let (_dir, server) = auth_test_server();
    let _publisher = server.spawn_board_publisher();
    let actor = seeded_test_entity_id(0xb0a1_0010);
    let (inside, inside_connection) = narrowed_stream(
        &server,
        actor,
        "wake-base-reality",
        oneiron::claim::base_world_id(),
    )
    .await;
    let (outside, outside_connection) = narrowed_stream(
        &server,
        actor,
        "wake-other-world",
        seeded_test_entity_id(0xb0a1_0011),
    )
    .await;
    let (witness, witness_connection) =
        stream_actor(&server, 0xb0a1_0012, "wake-narrowed-witness").await;
    let failed = server
        .vault()
        .memory(actor, oneiron::EdgeActorClass::Human)
        .tasks_create(&oneiron::task_verb::TaskCreateSpec::new(
            rmpv::Value::from("fails inside its world"),
            None,
            None,
            None,
        ))
        .expect("create")
        .task_ref
        .expect("task ref");

    fail_next_realization(&server);
    let wake = eventually(&server, |streams| streams.next_wake(&inside_connection)).await;
    assert_eq!(wake.task_ref, failed.to_hex());
    assert!(
        wake.event_ref
            .starts_with(&format!("{}:failed:", failed.to_hex()))
    );
    let done = ask_and_answer(&server, actor, 0xb0a1_0013);
    publisher_passed(&server, witness, &witness_connection, 0xb0a1_0014).await;

    let rows = delivered_rows(&server, "wake-base-reality", inside).await;
    assert!(names_any(&rows, &done), "{rows:?}");
    assert!(
        server
            .mcp_registry
            .lock()
            .await
            .streams_mut()
            .next_wake(&outside_connection)
            .is_none(),
        "a TASK outside the world woke its owner"
    );
    let rows = delivered_rows(&server, "wake-other-world", outside).await;
    assert!(
        !names_any(&rows, &done) && !names_any(&rows, &[failed]),
        "{rows:?}"
    );
}

/// Both read checks hold for a narrowed connection: a queued `tasks:` line is
/// read again when it would ride. Of two answered asks, the erased one never
/// rides; and once the reader can no longer read TASKs, a third never does.
#[tokio::test]
async fn a_narrowed_connection_never_carries_an_erased_or_unreadable_task() {
    let (_dir, server) = auth_test_server();
    let _publisher = server.spawn_board_publisher();
    let actor = seeded_test_entity_id(0xb0a1_0020);
    let (envelope, _) = narrowed_stream(
        &server,
        actor,
        "wake-narrowed-reads",
        oneiron::claim::base_world_id(),
    )
    .await;
    let (witness, witness_connection) =
        stream_actor(&server, 0xb0a1_0021, "wake-reads-witness").await;

    let kept = ask_and_answer(&server, actor, 0xb0a1_0022);
    let erased = ask_and_answer(&server, actor, 0xb0a1_0023);
    publisher_passed(&server, witness, &witness_connection, 0xb0a1_0024).await;
    for task in &erased {
        server
            .vault()
            .delete_entity_with_reason(task, oneiron::DeleteReason::UserHardDelete)
            .expect("erase the TASK");
    }
    let rows = delivered_rows(&server, "wake-narrowed-reads", envelope.clone()).await;
    assert!(names_any(&rows, &kept), "{rows:?}");
    assert!(!names_any(&rows, &erased), "{rows:?}");

    let hidden = ask_and_answer(&server, actor, 0xb0a1_0025);
    publisher_passed(&server, witness, &witness_connection, 0xb0a1_0026).await;
    reads_turns_only(&server, actor, 0xb0a1_0027);
    let rows = delivered_rows(&server, "wake-narrowed-reads", envelope).await;
    assert!(!names_any(&rows, &hidden), "{rows:?}");
}

/// Claims the next queued realization and completes it: the TASK it realizes
/// folds to `done`.
fn complete_next_realization(server: &SyncServer) {
    let queue = oneiron::AttemptQueue::new(server.vault());
    let now = server.vault().now_recorded_at();
    let oneiron::attempt_queue::ClaimOutcome::Claimed(leased) = queue
        .claim_kind(
            "tasks.realize",
            oneiron::attempt_queue::ClaimAttempt {
                lease_owner: "board-done-worker".to_owned(),
                now,
            },
        )
        .expect("claim")
    else {
        panic!("a realization is queued");
    };
    queue
        .complete(oneiron::attempt_queue::CompleteAttempt {
            id: leased.id,
            lease_owner: "board-done-worker".to_owned(),
            attempt_count: leased.attempt_count,
            now,
        })
        .expect("complete");
}

/// `tasks.create` over MCP under `actor`'s `credential` narrowed to `world`;
/// the TASK it minted.
async fn mcp_create(
    server: &Arc<SyncServer>,
    credential: &str,
    actor: oneiron::EntityId,
    world: oneiron::EntityId,
    label: &str,
) -> oneiron::EntityId {
    let scope = crate::mcp::McpConnectorScope::scoped(Some(world), None);
    let (status, created) = route_json(
        server.clone(),
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            credential,
            label,
            "tasks.create",
            mcp_merge_args(
                mcp_scoped_envelope(actor, "write_tasks", &scope),
                json!({ "arguments": { "spec": { "goal": label }, "label": label } }),
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    created["result"]["structuredContent"]["output"]["task_ref"]
        .as_str()
        .and_then(|hex| oneiron::EntityId::from_hex(hex).ok())
        .unwrap_or_else(|| panic!("{credential} creates its TASK: {created:#}"))
}

/// Whether the TASKS section `credential`'s board serves lists `task`.
async fn board_lists(
    server: &Arc<SyncServer>,
    credential: &str,
    envelope: Value,
    task: oneiron::EntityId,
) -> bool {
    let (status, described) = route_json(
        server.clone(),
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            credential,
            "board-tasks",
            "describe",
            envelope,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{described}");
    described["result"]["structuredContent"]["output"]["rows"]
        .as_array()
        .unwrap_or_else(|| panic!("{credential} reads its TASKS section: {described:#}"))
        .iter()
        .any(|row| row["id"] == task.to_hex().as_str())
}

/// The MCP error code `describe` answers `credential` for one TASK; `None`
/// when the card is served.
async fn describe_refusal(
    server: &Arc<SyncServer>,
    credential: &str,
    envelope: Value,
    task: oneiron::EntityId,
) -> Option<Value> {
    let (status, described) = route_json(
        server.clone(),
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            credential,
            "describe-task",
            "describe",
            mcp_merge_args(
                envelope,
                json!({ "arguments": { "task_ref": task.to_hex() } }),
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{described}");
    described
        .get("error")
        .map(|error| error["data"]["error_code"].clone())
}

/// What the /v1 read lane answers `authorization` for one TASK's timeline.
async fn timeline_status(
    server: &Arc<SyncServer>,
    authorization: String,
    task: oneiron::EntityId,
) -> StatusCode {
    route_json(
        server.clone(),
        core_request_with_authz(
            "GET",
            &format!("/v1/core/memory/{}/timeline", task.to_hex()),
            authorization,
            None,
        ),
    )
    .await
    .0
}

/// ARCH-0067 §5, "my tasks", for a writer narrowed to a world other than
/// base reality. The TASKs it creates over MCP are born in its world, so it
/// hears one's failed WAKE and another's done CARRIER delta, and reads both
/// on MCP and on the /v1 read lane. The same actor's credentials narrowed to
/// another world and to base reality hear neither and read neither; the
/// owner and the actor's vault-wide credential still read them.
#[tokio::test]
async fn a_world_narrowed_writer_hears_and_reads_its_own_tasks() {
    let (_dir, server) = auth_test_server();
    let _publisher = server.spawn_board_publisher();
    let actor = seeded_test_entity_id(0xb1a5_0001);
    let world = seeded_test_entity_id(0xb1a5_0002);
    let (inside, inside_connection) = narrowed_stream(&server, actor, "birth-inside", world).await;
    let (other, other_connection) = narrowed_stream(
        &server,
        actor,
        "birth-other-world",
        seeded_test_entity_id(0xb1a5_0003),
    )
    .await;
    let (base, base_connection) = narrowed_stream(
        &server,
        actor,
        "birth-base-reality",
        oneiron::claim::base_world_id(),
    )
    .await;
    register_mcp_actor(
        &server,
        "birth-vault-wide",
        actor,
        oneiron::EdgeActorClass::Human,
    )
    .await;
    let (witness, witness_connection) = stream_actor(&server, 0xb1a5_0004, "birth-witness").await;

    let failed = mcp_create(&server, "birth-inside", actor, world, "fails in its world").await;
    fail_next_realization(&server);
    let wake = eventually(&server, |streams| streams.next_wake(&inside_connection)).await;
    assert_eq!(wake.task_ref, failed.to_hex());
    assert!(
        wake.event_ref
            .starts_with(&format!("{}:failed:", failed.to_hex()))
    );
    let done = mcp_create(&server, "birth-inside", actor, world, "done in its world").await;
    complete_next_realization(&server);
    // The executor lands its result on the TASK body. That content put keeps
    // the TASK where it was born.
    let result = seeded_test_entity_id(0xb1a5_0006);
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![(
            rmpv::Value::from("role"),
            rmpv::Value::from("question"),
        )]),
    )
    .expect("turn body");
    server
        .vault()
        .put_entity(
            &result,
            oneiron::registry::ENTITY_TYPE_TURN,
            oneiron::TimeRange { start: 2, end: 2 },
            2,
            &body,
        )
        .expect("result turn");
    server
        .vault()
        .memory(actor, oneiron::EdgeActorClass::Human)
        .land_task_result(
            done,
            &oneiron::task_verb::TaskResultInput {
                result_ref: result,
                disposition: oneiron::task_verb::TaskTerminalDisposition::Completed,
                finished_at: server.vault().now_recorded_at(),
            },
        )
        .expect("the result lands");
    publisher_passed(&server, witness, &witness_connection, 0xb1a5_0005).await;
    let rows = delivered_rows(&server, "birth-inside", inside.clone()).await;
    assert!(names_any(&rows, &[done]), "{rows:?}");

    let tasks = [failed, done];
    for task in tasks {
        let born = server
            .vault()
            .record_scope(&task)
            .expect("record scope")
            .expect("a local TASK is stamped");
        assert_eq!(
            born.worlds,
            oneiron::federation::ScopeAxis::Some([oneiron::federation::ScopeId(world)].into())
        );
        assert!(board_lists(&server, "birth-inside", inside.clone(), task).await);
        for credential in ["birth-inside", "birth-vault-wide"] {
            assert_eq!(
                timeline_status(&server, format!("Bearer {credential}"), task).await,
                StatusCode::OK,
                "{credential}"
            );
        }
        assert_eq!(
            timeline_status(&server, owner_bearer(), task).await,
            StatusCode::OK
        );
    }
    for (credential, envelope, connection) in [
        ("birth-other-world", other, other_connection),
        ("birth-base-reality", base, base_connection),
    ] {
        assert!(
            server
                .mcp_registry
                .lock()
                .await
                .streams_mut()
                .next_wake(&connection)
                .is_none(),
            "{credential} heard a TASK born outside its world"
        );
        let rows = delivered_rows(&server, credential, envelope.clone()).await;
        assert!(!names_any(&rows, &tasks), "{credential}: {rows:?}");
        for task in tasks {
            assert!(!board_lists(&server, credential, envelope.clone(), task).await);
            assert_eq!(
                describe_refusal(&server, credential, envelope.clone(), task).await,
                Some(Value::from("mcp_scope_refused")),
                "{credential}"
            );
            assert_eq!(
                timeline_status(&server, format!("Bearer {credential}"), task).await,
                StatusCode::NOT_FOUND,
                "{credential}"
            );
        }
    }
}

/// ARCH-0067 §5, "consults to me", inside one world. A writer whose surface
/// is bound to a world (the binding the MCP gateway gives a narrowed
/// connector) consults a peer. The consult is born in that world, so the
/// peer's connection narrowed to it hears the consult and reads it, and the
/// peer's connection narrowed to another world does neither.
#[tokio::test]
async fn a_consult_born_in_a_world_reaches_its_addressee_there() {
    let (_dir, server) = auth_test_server();
    let _publisher = server.spawn_board_publisher();
    let asker = seeded_test_entity_id(0xb1a5_0010);
    let addressee = seeded_test_entity_id(0xb1a5_0011);
    let world = seeded_test_entity_id(0xb1a5_0012);
    let (_, inside_connection) = narrowed_stream(&server, addressee, "consult-inside", world).await;
    let (other, other_connection) = narrowed_stream(
        &server,
        addressee,
        "consult-other-world",
        seeded_test_entity_id(0xb1a5_0013),
    )
    .await;
    narrowed_stream(&server, asker, "consult-asker", world).await;
    let (witness, witness_connection) = stream_actor(&server, 0xb1a5_0014, "consult-witness").await;

    let turn = seeded_test_entity_id(0xb1a5_0015);
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![(
            rmpv::Value::from("role"),
            rmpv::Value::from("question"),
        )]),
    )
    .expect("turn body");
    server
        .vault()
        .put_entity(
            &turn,
            oneiron::registry::ENTITY_TYPE_TURN,
            oneiron::TimeRange { start: 2, end: 2 },
            2,
            &body,
        )
        .expect("question turn");
    let question = oneiron::task_verb::ConsultPayloadRef::parse(
        server.vault(),
        &format!("tn_{}", turn.to_hex()),
    )
    .expect("turn ref");
    let now = server.vault().now_recorded_at();
    let consult = server
        .vault()
        .memory(asker, oneiron::EdgeActorClass::Human)
        .with_birth_position(oneiron::federation::record_scope::BirthPosition {
            world: Some(world),
            facet: None,
        })
        .tasks_create(
            &oneiron::task_verb::TaskCreateSpec::new(rmpv::Value::Nil, None, None, Some(now))
                .with_kind(oneiron::task_verb::TaskKind::Consult)
                .with_consult(oneiron::task_verb::ConsultPayload::question(
                    question,
                    Vec::new(),
                    seeded_test_entity_id(0xb1a5_0016),
                ))
                .with_assignee(oneiron::task_verb::TaskAssignee::Peer {
                    actor_ref: addressee,
                })
                .with_ttl(oneiron::task_verb::TaskTtl::after(now, 3_600)),
        )
        .expect("consult lands")
        .task_ref
        .expect("the consult mints one TASK");

    let wake = eventually(&server, |streams| streams.next_wake(&inside_connection)).await;
    assert_eq!(wake.task_ref, consult.to_hex());
    assert!(
        wake.event_ref
            .starts_with(&format!("{}:arrived:", consult.to_hex()))
    );
    assert_eq!(
        timeline_status(&server, "Bearer consult-inside".to_owned(), consult).await,
        StatusCode::OK
    );
    publisher_passed(&server, witness, &witness_connection, 0xb1a5_0017).await;
    assert!(
        server
            .mcp_registry
            .lock()
            .await
            .streams_mut()
            .next_wake(&other_connection)
            .is_none(),
        "a consult born in another world woke its addressee"
    );
    assert_eq!(
        describe_refusal(&server, "consult-other-world", other, consult).await,
        Some(Value::from("mcp_scope_refused"))
    );
    assert_eq!(
        timeline_status(&server, "Bearer consult-other-world".to_owned(), consult).await,
        StatusCode::NOT_FOUND
    );
}

/// The whole answer the /v1 read lane gives `credential` for `id`'s timeline:
/// its status and body, with the addressed id and the per-response request
/// id written out, so two answers compare as wholes.
async fn timeline_answer(
    server: &Arc<SyncServer>,
    credential: &str,
    id: oneiron::EntityId,
) -> (StatusCode, String) {
    let (status, mut body) = route_json(
        server.clone(),
        core_request_with_authz(
            "GET",
            &format!("/v1/core/memory/{}/timeline", id.to_hex()),
            format!("Bearer {credential}"),
            None,
        ),
    )
    .await;
    if let Some(request) = body.pointer_mut("/error/requestId") {
        *request = Value::from("<request>");
    }
    (status, body.to_string().replace(&id.to_hex(), "<id>"))
}

/// The whole `describe` page `credential` reads with no TASK named.
async fn describe_page(server: &Arc<SyncServer>, credential: &str, envelope: Value) -> Value {
    let (status, described) = route_json(
        server.clone(),
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            credential,
            "describe-page",
            "describe",
            envelope,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{described}");
    described["result"]["structuredContent"].clone()
}

/// Astra on #1401 (P2): a TASK born in a world a credential cannot read adds
/// to none of that credential's counts (ARCH-0067 §5, DEC-0005). A
/// base-only credential's `describe` page is the same whole page before and
/// after another world's writer creates a TASK, and the /v1 timeline gives
/// it the same whole 404 for that TASK and for an id nothing holds.
#[tokio::test]
async fn a_task_born_outside_a_credential_moves_no_count() {
    let (_dir, server) = auth_test_server();
    let actor = seeded_test_entity_id(0xb1a5_0020);
    let world = seeded_test_entity_id(0xb1a5_0021);
    let base_world = oneiron::claim::base_world_id();
    narrowed_stream(&server, actor, "count-inside", world).await;
    let (base, _) = narrowed_stream(&server, actor, "count-base", base_world).await;
    let own = mcp_create(&server, "count-base", actor, base_world, "base work").await;
    let before = describe_page(&server, "count-base", base.clone()).await;
    assert!(
        board_lists(&server, "count-base", base.clone(), own).await,
        "{before:#}"
    );

    let born = mcp_create(&server, "count-inside", actor, world, "work in its world").await;
    assert_eq!(
        describe_page(&server, "count-base", base).await,
        before,
        "a TASK born outside the credential changed its page"
    );
    let absent = seeded_test_entity_id(0xb1a5_0022);
    let answer = timeline_answer(&server, "count-base", absent).await;
    assert_eq!(answer.0, StatusCode::NOT_FOUND, "{}", answer.1);
    assert_eq!(timeline_answer(&server, "count-base", born).await, answer);
}

/// Astra on #1401 (P2): deleting a TASK does not move it out of the world it
/// was born in. A credential narrowed to another world gets the same whole
/// 404 for the TASK's timeline while it lives, once its owner has deleted
/// it, and for an id nothing holds. The owner and the writer's vault-wide
/// credential still read the deleted TASK's timeline.
#[tokio::test]
async fn a_deleted_task_stays_in_the_world_it_was_born_in() {
    let (_dir, server) = auth_test_server();
    let actor = seeded_test_entity_id(0xb1a5_0030);
    let world = seeded_test_entity_id(0xb1a5_0031);
    narrowed_stream(&server, actor, "deleted-inside", world).await;
    narrowed_stream(
        &server,
        actor,
        "deleted-outside",
        seeded_test_entity_id(0xb1a5_0032),
    )
    .await;
    register_mcp_actor(
        &server,
        "deleted-vault-wide",
        actor,
        oneiron::EdgeActorClass::Human,
    )
    .await;
    let task = mcp_create(&server, "deleted-inside", actor, world, "deleted later").await;
    let absent = seeded_test_entity_id(0xb1a5_0033);
    let answer = timeline_answer(&server, "deleted-outside", absent).await;
    assert_eq!(answer.0, StatusCode::NOT_FOUND, "{}", answer.1);
    assert_eq!(
        timeline_answer(&server, "deleted-outside", task).await,
        answer,
        "live"
    );

    server
        .vault()
        .delete_entity_with_reason(&task, oneiron::DeleteReason::UserDelete)
        .expect("the owner deletes the TASK");
    assert_eq!(
        timeline_answer(&server, "deleted-outside", task).await,
        answer,
        "deleted"
    );
    assert_eq!(
        timeline_status(&server, owner_bearer(), task).await,
        StatusCode::OK
    );
    assert_eq!(
        timeline_answer(&server, "deleted-vault-wide", task).await.0,
        StatusCode::OK
    );
}
