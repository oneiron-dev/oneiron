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
/// before that ask has been routed by then.
async fn publisher_passed(
    server: &Arc<SyncServer>,
    witness: oneiron::EntityId,
    connection: &oneiron::context_board::StreamConnectionId,
    seed: u128,
) {
    ask(server, witness, seed);
    eventually(server, |streams| streams.next_wake(connection)).await;
}

/// The carrier rows the next few tool results deliver to `actor`.
async fn delivered_rows(
    server: &Arc<SyncServer>,
    credential: &str,
    actor: oneiron::EntityId,
) -> Vec<Value> {
    let mut rows = Vec::new();
    for attempt in 0..3 {
        let (status, result) = route_json(
            server.clone(),
            mcp_endpoint_call_request(
                MCP_TOOL_FIRST_PATH,
                credential,
                &format!("delivered-{attempt}"),
                "describe",
                mcp_endpoint_envelope(actor, "read_tasks"),
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

/// Astra #1353 finding 1: a subscription is not a read grant. The owner's
/// live read admits TURNs only, so its own TASK never reaches its STREAM: no
/// WAKE, and no done delta on its next results.
#[tokio::test]
async fn a_task_outside_its_owners_read_grant_never_reaches_their_stream() {
    let (_dir, server) = auth_test_server();
    let _publisher = server.spawn_board_publisher();
    let (actor, connection) = stream_actor(&server, 0xd2b1_0010, "d2b1-turns-only").await;
    let (witness, witness_connection) = stream_actor(&server, 0xd2b1_0011, "d2b1-witness").await;
    // A matching core:read grant narrows the actor's read to TURNs; without
    // one, its slip alone would read its own TASK.
    let mut read = oneiron::federation::Scope::top();
    read.verbs = oneiron::federation::ScopeAxis::Some(["read".to_owned()].into());
    let owner = server.vault().ensure_embedded_owner_actor().expect("owner");
    oneiron::conversation_dag::test_support::put_test_policy_manifest(
        server.vault(),
        oneiron::WriteActor::new(owner, oneiron::EdgeActorClass::Human),
        seeded_test_entity_id(0xd2b1_0012),
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
    let rows = delivered_rows(&server, "d2b1-turns-only", actor).await;
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

    let rows = delivered_rows(&server, "d2b1-erased", actor).await;
    assert!(!names_any(&rows, &tasks), "{rows:?}");
}
