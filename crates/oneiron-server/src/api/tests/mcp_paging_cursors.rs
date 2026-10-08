//! Setup page budgets/end-markers, one-time bound cursors, mutating-use refusal, concurrent continuations.

use super::*;

/// ONE-1704 M6: a `More` page's handle is CONSUMABLE — page one plus the page
/// it continues are exactly the producer's set — and it is BOUND to the
/// connector, tool, arguments, and snapshot it was minted under.
#[tokio::test]
async fn mcp_page_cursor_continues_exactly_once_and_is_bound() {
    let (_dir, server) = auth_test_server();
    let actor_ref = seeded_test_entity_id(0x1704_00e1);
    let credential = "one-1704-cursor-credential";
    let other = "one-1704-cursor-other-credential";
    register_mcp_actor(
        &server,
        credential,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;
    register_mcp_actor(&server, other, actor_ref, oneiron::EdgeActorClass::Human).await;

    let setup = |credential: &'static str, id: &'static str, page: Value| {
        mcp_endpoint_call_request(
            "/mcp",
            credential,
            id,
            "setup_oneiron",
            mcp_merge_args(
                mcp_endpoint_envelope(actor_ref, "read_board"),
                json!({ "page": page }),
            ),
        )
    };

    // Page one: the first five verbs, an explicit `More`, and an opaque handle.
    let (_, first) = route_json(
        server.clone(),
        setup(credential, "cursor-1", json!({ "limit": 5 })),
    )
    .await;
    let first = &first["result"]["structuredContent"];
    let page_one = mcp_setup_verb_names(first);
    assert_eq!(page_one.len(), 5, "{first:?}");
    assert_eq!(first["meta"]["end"], Value::from("More"));
    assert!(
        first["meta"]["page"]
            .get("continuation_unavailable")
            .is_none(),
        "a continuable More names no unavailability: {first:?}"
    );
    let cursor = first["meta"]["page"]["cursor"]
        .as_str()
        .expect("a non-terminal page carries an opaque successor")
        .to_owned();
    assert!(cursor.starts_with("mcpc1:"), "{cursor}");

    // BOUND: another connector, another tool, and another argument set are each
    // refused fail-closed, and none of them consumes the live handle.
    let wrong_connector = mcp_refusal(
        &server,
        setup(
            other,
            "cursor-connector",
            json!({ "limit": 5, "cursor": cursor.clone() }),
        ),
    )
    .await;
    assert_mcp_structured_error(&wrong_connector, "mcp_page_cursor_invalid");
    assert_eq!(
        wrong_connector["error"]["data"]["field"],
        Value::from("page.cursor")
    );

    let wrong_tool = mcp_refusal(
        &server,
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            credential,
            "cursor-tool",
            "describe",
            mcp_merge_args(
                mcp_endpoint_envelope(actor_ref, "read_tasks"),
                json!({ "page": { "limit": 5, "cursor": cursor.clone() } }),
            ),
        ),
    )
    .await;
    assert_mcp_structured_error(&wrong_tool, "mcp_page_cursor_invalid");

    // A real producer-query mismatch is refused, while changing only the page
    // window is allowed. `cache` is outside the transport-only page member and
    // therefore remains part of the bound identity.
    let wrong_arguments = mcp_refusal(
        &server,
        mcp_endpoint_call_request(
            "/mcp",
            credential,
            "cursor-args",
            "setup_oneiron",
            mcp_merge_args(
                mcp_endpoint_envelope(actor_ref, "read_board"),
                json!({
                    "cache": { "ttl_ms": 1 },
                    "page": { "limit": 5, "cursor": cursor.clone() },
                }),
            ),
        ),
    )
    .await;
    assert_mcp_structured_error(&wrong_arguments, "mcp_page_cursor_invalid");

    // Page two may choose a DIFFERENT transport page limit. The retained
    // producer snapshot still supplies exactly the rows page one left behind,
    // with an explicit `Complete` and no further handle.
    let (_, second) = route_json(
        server.clone(),
        setup(
            credential,
            "cursor-2",
            json!({ "limit": mcp_expected_generated_names().len(), "cursor": cursor.clone() }),
        ),
    )
    .await;
    let second = &second["result"]["structuredContent"];
    let page_two = mcp_setup_verb_names(second);
    assert_eq!(second["meta"]["end"], Value::from("Complete"));
    assert!(second["meta"]["page"].get("cursor").is_none(), "{second:?}");
    assert_eq!(second["meta"]["page"]["hidden"], Value::from(0));

    let whole = mcp_expected_generated_names()
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    assert_eq!(page_two.len(), whole.len() - 5, "{second:?}");
    let mut union = page_one.clone();
    union.extend(page_two.clone());
    assert_eq!(
        union, whole,
        "page one plus the continued page IS the uncapped producer set"
    );
    for name in &page_two {
        assert!(
            !page_one.contains(name),
            "the pages must be disjoint: {name}"
        );
    }

    // ONE-TIME: the consumed handle is refused on replay, never silently
    // restarted at page one.
    let replay = mcp_refusal(
        &server,
        setup(
            credential,
            "cursor-replay",
            json!({ "limit": 5, "cursor": cursor }),
        ),
    )
    .await;
    assert_mcp_structured_error(&replay, "mcp_page_cursor_invalid");

    // SNAPSHOT-RETAINED (ONE-1704 repair): a continuation is a continuation of
    // the IMMUTABLE producer snapshot its handle carries. An unrelated later
    // board epoch cannot make those retained rows wrong, so it does not destroy
    // the enumeration either — while every producer-identity axis above
    // (connector, tool, arguments) stays refused.
    let (_, fresh) = route_json(
        server.clone(),
        setup(credential, "cursor-4", json!({ "limit": 5 })),
    )
    .await;
    let retained_cursor = fresh["result"]["structuredContent"]["meta"]["page"]["cursor"]
        .as_str()
        .expect("a fresh successor handle")
        .to_owned();
    {
        let mut registry = server.mcp_registry.lock().await;
        let connection = registry
            .resolve(
                &mcp_registered_credential(&server, credential),
                1,
                |_, _| true,
            )
            .expect("credential resolves")
            .stream_connection;
        // A different board STATE advances the snapshot epoch by exactly one,
        // reading no clock at all.
        let moved = crate::mcp::mcp_board_state_hash("VaultWide", &["moved".to_owned()]);
        let latest = registry.board_snapshot_epoch(&connection, moved);
        assert!(
            latest > 1,
            "an unrelated board state moved this connection's latest epoch",
        );
    }
    let (_, continued) = route_json(
        server.clone(),
        setup(
            credential,
            "cursor-epoch-moved",
            json!({ "limit": whole.len(), "cursor": retained_cursor.clone() }),
        ),
    )
    .await;
    assert!(
        continued.get("error").is_none(),
        "a moved unrelated board epoch must not refuse a retained continuation: {continued:?}"
    );
    let continued = &continued["result"]["structuredContent"];
    assert_eq!(
        mcp_setup_verb_names(continued),
        whole[5..].to_vec(),
        "the continuation returns exactly the retained producer remainder: {continued:?}"
    );
    assert_eq!(continued["meta"]["end"], Value::from("Complete"));
    // Still one-time: the handle the moved epoch did not invalidate is spent.
    let replayed = mcp_refusal(
        &server,
        setup(
            credential,
            "cursor-epoch-replay",
            json!({ "limit": whole.len(), "cursor": retained_cursor }),
        ),
    )
    .await;
    assert_mcp_structured_error(&replayed, "mcp_page_cursor_invalid");
}

/// ONE-1704 M6: a live cursor from a read producer cannot reach a mutating
/// or subscription producer. The typed refusal happens before either facade or
/// dispatcher, and the retained cursor/stream state stays untouched.
#[tokio::test]
async fn mcp_cursor_refusal_precedes_mutating_and_subscription_dispatch() {
    let (_dir, server) = auth_test_server();
    let actor_ref = seeded_test_entity_id(0x1704_00f1);
    let credential = "one-1704-cursor-pre-dispatch";
    register_mcp_actor(
        &server,
        credential,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    let (_, first) = route_json(
        server.clone(),
        mcp_endpoint_call_request(
            "/mcp",
            credential,
            "preflight-setup",
            "setup_oneiron",
            mcp_merge_args(
                mcp_endpoint_envelope(actor_ref, "read_board"),
                json!({ "page": { "limit": 1 } }),
            ),
        ),
    )
    .await;
    let cursor = first["result"]["structuredContent"]["meta"]["page"]["cursor"]
        .as_str()
        .expect("page one minted a live setup continuation")
        .to_owned();
    let cursor_handle = cursor.clone();
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
    let subscribed_before = {
        let mut registry = server.mcp_registry.lock().await;
        registry
            .streams_mut()
            .connection_state(&connection)
            .expect("the connector owns a stream connection")
            .subscribed
            .clone()
    };
    let task_ids_before = task_ids(&server, actor_ref);

    let create_refusal = mcp_refusal(
        &server,
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            credential,
            "preflight-create",
            "tasks.create",
            mcp_merge_args(
                mcp_endpoint_envelope(actor_ref, "write_tasks"),
                json!({
                    "arguments": { "spec": { "kind": "review" } },
                    "page": { "cursor": cursor.clone() },
                }),
            ),
        ),
    )
    .await;
    assert_mcp_structured_error(&create_refusal, "mcp_page_cursor_invalid");

    let cancel_refusal = mcp_refusal(
        &server,
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            credential,
            "preflight-cancel",
            "cancel",
            mcp_merge_args(
                mcp_endpoint_envelope(actor_ref, "write_tasks"),
                json!({
                    "arguments": { "task_ref": actor_ref.to_hex() },
                    "page": { "cursor": cursor.clone() },
                }),
            ),
        ),
    )
    .await;
    assert_mcp_structured_error(&cancel_refusal, "mcp_page_cursor_invalid");

    let subscribe_refusal = mcp_refusal(
        &server,
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            credential,
            "preflight-subscribe",
            "board.subscribe",
            mcp_merge_args(
                mcp_endpoint_envelope(actor_ref, "read_board"),
                json!({
                    "arguments": { "scopes": ["my_tasks"] },
                    "page": { "cursor": cursor },
                }),
            ),
        ),
    )
    .await;
    assert_mcp_structured_error(&subscribe_refusal, "mcp_page_cursor_invalid");

    let task_ids_after = task_ids(&server, actor_ref);
    assert_eq!(
        task_ids_after, task_ids_before,
        "cursor refusal did not create/cancel a task"
    );
    let mut registry = server.mcp_registry.lock().await;
    assert!(
        registry.page_continuation_live(&connection),
        "unsupported cursor presentations do not consume the live read continuation"
    );
    assert!(
        registry.page_continuation_live_cursor(&connection, &cursor_handle),
        "the refused presentations consumed no cursor at all, this one included"
    );
    assert_eq!(
        registry.live_page_continuations(&connection),
        1,
        "exactly the one live read continuation remains"
    );
    assert_eq!(
        registry
            .streams_mut()
            .connection_state(&connection)
            .expect("the stream connection remains attached")
            .subscribed,
        subscribed_before,
        "cursor refusal did not change board subscriptions",
    );
}

/// The row ids of the TASKS section `describe` renders for one actor.
fn task_ids(server: &Arc<SyncServer>, actor_ref: oneiron::EntityId) -> Vec<String> {
    let oneiron::task_verb::TaskDescription::Section(section) = server
        .vault
        .memory(actor_ref, oneiron::EdgeActorClass::Human)
        .describe(None)
        .expect("the task producer is readable")
    else {
        panic!("describe without a task returns the TASKS section");
    };
    section.rows.into_iter().map(|row| row.id).collect()
}

/// ONE-1704 repair: one connection holds SEVERAL live continuations and
/// consumes them independently.
#[tokio::test]
async fn mcp_two_live_cursors_on_one_connection_continue_independently() {
    let (_dir, server) = auth_test_server();
    let actor_ref = seeded_test_entity_id(0x1704_0101);
    let credential = "one-1704-two-cursor-credential";
    register_mcp_actor(
        &server,
        credential,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    // Two different producer QUERIES on one connection: `board_budget_tok` is
    // bound argument identity, the page member is not.
    let setup = |id: &'static str, budget: u32, page: Value| {
        mcp_endpoint_call_request(
            "/mcp",
            credential,
            id,
            "setup_oneiron",
            mcp_merge_args(
                mcp_endpoint_envelope(actor_ref, "read_board"),
                json!({ "board_budget_tok": budget, "page": page }),
            ),
        )
    };
    let cursor_of = |body: &Value| {
        body["result"]["structuredContent"]["meta"]["page"]["cursor"]
            .as_str()
            .expect("a non-terminal page carries an opaque successor")
            .to_owned()
    };

    let (_, first) = route_json(
        server.clone(),
        setup("two-cursor-a1", 900, json!({ "limit": 2 })),
    )
    .await;
    let (_, second) = route_json(
        server.clone(),
        setup("two-cursor-b1", 1000, json!({ "limit": 3 })),
    )
    .await;
    let first_cursor = cursor_of(&first);
    let second_cursor = cursor_of(&second);
    assert_ne!(first_cursor, second_cursor);

    let connection = {
        let registry = server.mcp_registry.lock().await;
        let connection = registry
            .resolve(
                &mcp_registered_credential(&server, credential),
                1,
                |_, _| true,
            )
            .expect("credential resolves")
            .stream_connection;
        assert_eq!(
            registry.live_page_continuations(&connection),
            2,
            "a second More page does not destroy the first page's handle"
        );
        assert!(registry.page_continuation_live_cursor(&connection, &first_cursor));
        assert!(registry.page_continuation_live_cursor(&connection, &second_cursor));
        connection
    };

    let whole = mcp_expected_generated_names()
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();

    // Consuming the SECOND handle consumes exactly that handle.
    let (_, second_page) = route_json(
        server.clone(),
        setup(
            "two-cursor-b2",
            1000,
            json!({ "limit": 50, "cursor": second_cursor }),
        ),
    )
    .await;
    let second_page = &second_page["result"]["structuredContent"];
    assert_eq!(mcp_setup_verb_names(second_page), whole[3..].to_vec());
    assert_eq!(second_page["meta"]["end"], Value::from("Complete"));
    {
        let registry = server.mcp_registry.lock().await;
        assert_eq!(
            registry.live_page_continuations(&connection),
            1,
            "consuming one cursor consumed only that cursor"
        );
        assert!(registry.page_continuation_live_cursor(&connection, &first_cursor));
    }

    // The first is still exactly where page one left it.
    let (_, first_page) = route_json(
        server.clone(),
        setup(
            "two-cursor-a2",
            900,
            json!({ "limit": 50, "cursor": first_cursor }),
        ),
    )
    .await;
    let first_page = &first_page["result"]["structuredContent"];
    assert_eq!(mcp_setup_verb_names(first_page), whole[2..].to_vec());
    assert_eq!(first_page["meta"]["end"], Value::from("Complete"));
    let registry = server.mcp_registry.lock().await;
    assert_eq!(registry.live_page_continuations(&connection), 0);
}
