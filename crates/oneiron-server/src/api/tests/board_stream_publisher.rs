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
