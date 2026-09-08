//! Legacy catalog retirement, actor-derived effective scopes, world/facet ceilings, board epoch monotonicity.

use super::*;

#[tokio::test]
async fn mcp_legacy_catalog_is_unknown_tool_on_both_endpoints() {
    let (_dir, server) = test_server();
    let actor_ref = seeded_test_entity_id(0x1704_0071);
    let credential = "one-1704-legacy-credential";
    register_mcp_actor(
        &server,
        credential,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;
    let scope = crate::mcp::mcp_effective_scope_value(&crate::mcp::McpConnectorScope::vault_wide());

    let legacy = crate::mcp::McpToolName::all()
        .iter()
        .map(|tool| tool.as_str())
        .collect::<Vec<_>>();
    assert_eq!(legacy.len(), 7, "the retired census is seven names");

    for (index, name) in legacy.iter().enumerate() {
        for path in ["/mcp", MCP_TOOL_FIRST_PATH] {
            let body = mcp_refusal(
                &server,
                mcp_endpoint_call_request(
                    path,
                    credential,
                    &format!("legacy-{index}"),
                    name,
                    mcp_merge_args(
                        mcp_endpoint_envelope(actor_ref, "read_board"),
                        json!({ "target": { "entity_ref": actor_ref.to_hex() } }),
                    ),
                ),
            )
            .await;
            assert_mcp_structured_error(&body, "unknown_tool");
            assert_scoped_refusal(&body, &scope, &format!("{name} on {path}"));
        }
    }

    // Neither frozen listing names them either.
    for path in ["/mcp", MCP_TOOL_FIRST_PATH] {
        let (_, listing) = route_json(
            server.clone(),
            mcp_list_request(path, credential, "legacy-list"),
        )
        .await;
        let names = mcp_listed_tool_names(&listing);
        for name in &legacy {
            assert!(!names.contains(name), "{name} must not be listed on {path}");
        }
    }
}

#[tokio::test]
async fn mcp_actor_derived_errors_all_carry_effective_scope() {
    let (_dir, server) = test_server();
    let wide_actor = seeded_test_entity_id(0x1704_0081);
    let wide = "one-1704-scope-error-credential";
    register_mcp_actor(&server, wide, wide_actor, oneiron::EdgeActorClass::Human).await;
    let wide_scope =
        crate::mcp::mcp_effective_scope_value(&crate::mcp::McpConnectorScope::vault_wide());

    // 1. Decode/validation, after the credential resolved.
    let body = mcp_refusal(
        &server,
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            wide,
            "scope-args",
            "board.expand",
            mcp_merge_args(
                mcp_endpoint_envelope(wide_actor, "read_board"),
                json!({ "arguments": { "frame_epoch": 3 } }),
            ),
        ),
    )
    .await;
    assert_mcp_structured_error(&body, "tool_args_invalid");
    assert_scoped_refusal(&body, &wide_scope, "tool_args_invalid");

    // 2. Actor mismatch.
    let body = mcp_refusal(
        &server,
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            wide,
            "scope-mismatch",
            "tasks.check",
            mcp_endpoint_envelope(seeded_test_entity_id(0x1704_0082), "read_tasks"),
        ),
    )
    .await;
    assert_mcp_structured_error(&body, "mcp_actor_mismatch");
    assert_scoped_refusal(&body, &wide_scope, "mcp_actor_mismatch");

    // 3. Board/task dispatch refusal from the engine's own verb dispatcher.
    for (id, arguments, label) in [
        (
            "scope-stale",
            json!({ "arguments": { "key": "TASKS", "frame_epoch": 9_999 } }),
            "stale frame",
        ),
        (
            "scope-missing",
            json!({ "arguments": { "key": "NO_SUCH_SECTION" } }),
            "missing target",
        ),
    ] {
        let body = mcp_refusal(
            &server,
            mcp_endpoint_call_request(
                MCP_TOOL_FIRST_PATH,
                wide,
                id,
                "board.expand",
                mcp_merge_args(mcp_endpoint_envelope(wide_actor, "read_board"), arguments),
            ),
        )
        .await;
        assert_mcp_structured_error(&body, "verb_dispatch_failed");
        assert_scoped_refusal(&body, &wide_scope, label);
    }

    // 4. Facade/engine failure behind an admitted call.
    let stray = seeded_test_entity_id(0x1704_0083);
    server
        .vault
        .put_entity(
            &stray,
            ENTITY_TYPE_TURN,
            oneiron::TimeRange {
                start: 100,
                end: 100,
            },
            101,
            b"not a task",
        )
        .expect("seed a non-task entity");
    let body = mcp_refusal(
        &server,
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            wide,
            "scope-facade",
            "tasks.expand",
            mcp_merge_args(
                mcp_endpoint_envelope(wide_actor, "read_tasks"),
                json!({ "arguments": { "task_ref": stray.to_hex() } }),
            ),
        ),
    )
    .await;
    assert_scoped_refusal(&body, &wide_scope, "facade failure");

    // 5. Bound-verb ceiling refusal.
    let bound_actor = seeded_test_entity_id(0x1704_0084);
    let bound = "one-1704-bound-verb-credential";
    register_bound_verb_mcp_actor(&server, bound, bound_actor, &["tasks.check"]).await;
    let body = mcp_refusal(
        &server,
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            bound,
            "scope-unbound",
            "board.refresh",
            mcp_endpoint_envelope(bound_actor, "read_board"),
        ),
    )
    .await;
    assert_mcp_structured_error(&body, "mcp_verb_not_bound");
    assert_scoped_refusal(&body, &wide_scope, "mcp_verb_not_bound");

    // 6. Scope refusal on a narrowed credential's STREAM routing request.
    let narrow_actor = seeded_test_entity_id(0x1704_0085);
    let narrow_scope_value =
        crate::mcp::McpConnectorScope::scoped(Some(seeded_test_entity_id(0x1704_0086)), None);
    let narrow = "one-1704-narrow-scope-credential";
    register_scoped_mcp_actor(&server, narrow, narrow_actor, narrow_scope_value.clone()).await;
    let body = mcp_refusal(
        &server,
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            narrow,
            "scope-stream",
            "board.subscribe",
            mcp_merge_args(
                mcp_scoped_envelope(narrow_actor, "read_board", &narrow_scope_value),
                json!({ "arguments": { "scopes": ["memories"] } }),
            ),
        ),
    )
    .await;
    assert_mcp_structured_error(&body, "mcp_scope_refused");
    assert_scoped_refusal(
        &body,
        &crate::mcp::mcp_effective_scope_value(&narrow_scope_value),
        "mcp_scope_refused",
    );

    // Only a failure BEFORE the credential resolved is legitimately scope-less.
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({ "jsonrpc": "2.0", "id": "no-cred", "method": "tools/list" }).to_string(),
        ))
        .expect("uncredentialed MCP request");
    let body = mcp_refusal(&server, request).await;
    assert_mcp_structured_error(&body, "mcp_auth_required");
    assert!(
        body["error"]["data"].get("effective_scope").is_none(),
        "a pre-credential refusal has no scope to state: {body:?}"
    );
}

/// ONE-1704 M3/B3/B4/B5: the world and facet axes are enforced INDEPENDENTLY,
/// the world ceiling reaches non-CLAIM rows, and a narrowed connection receives
/// no carrier frame at all while a vault-wide one is unchanged.
#[tokio::test]
async fn mcp_narrow_credential_cannot_cross_world_or_facet() {
    let (_dir, server) = test_server();
    let actor_ref = seeded_test_entity_id(0x1704_0091);
    let facet_a = seeded_test_entity_id(0x1704_0092);
    let facet_b = seeded_test_entity_id(0x1704_0093);
    let world_a = seeded_test_entity_id(0x1704_0094);
    let world_b = seeded_test_entity_id(0x1704_0095);
    // Each axis gets its OWN fixture: a facet-only credential carries no world
    // narrowing and a world-only credential carries no facet narrowing, so
    // neither refusal can be inferred from the other.
    let facet_only_a = crate::mcp::McpConnectorScope::scoped(None, Some(facet_a));
    let facet_only_b = crate::mcp::McpConnectorScope::scoped(None, Some(facet_b));
    let world_only_a = crate::mcp::McpConnectorScope::scoped(Some(world_a), None);
    let vault_wide = crate::mcp::McpConnectorScope::vault_wide();
    let cred_facet_a = "one-1704-facet-a";
    let cred_facet_b = "one-1704-facet-b";
    let cred_world_a = "one-1704-world-a";
    let cred_wide = "one-1704-cross-wide";
    // ONE actor, FOUR credentials, disjoint registered scopes.
    register_scoped_mcp_actor(&server, cred_facet_a, actor_ref, facet_only_a.clone()).await;
    register_scoped_mcp_actor(&server, cred_facet_b, actor_ref, facet_only_b.clone()).await;
    register_scoped_mcp_actor(&server, cred_world_a, actor_ref, world_only_a.clone()).await;
    register_mcp_actor(
        &server,
        cred_wide,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    // A row that belongs to facet A and to nothing else. It carries no world
    // key, because only a CLAIM can.
    let owned = seeded_test_entity_id(0x1704_0096);
    server
        .vault
        .put_entity(
            &owned,
            ENTITY_TYPE_TURN,
            oneiron::TimeRange {
                start: 100,
                end: 100,
            },
            101,
            b"facet-a row",
        )
        .expect("seed a facet-scoped row");
    // ONE-1645's write-time `FacetOf` table admits CLAIM|TURN|EVENT -> FACET
    // only, and reads BOTH endpoint types from STORED rows: an endpoint with no
    // entity row is unknowable-typed and fails closed exactly like a wrong one.
    // The facet this scope names must therefore be an established FACET fact
    // before anything stamps it.
    server
        .vault
        .put_entity(
            &facet_a,
            oneiron::registry::ENTITY_TYPE_FACET,
            oneiron::TimeRange {
                start: 100,
                end: 100,
            },
            101,
            b"facet a",
        )
        .expect("seed the facet the edge points at");
    server
        .vault
        .put_edge(&owned, oneiron::EdgeKind::FacetOf, &facet_a, 1.0)
        .expect("seed the facet edge");

    // Two CLAIM rows, one in each world.
    let in_world = seeded_test_entity_id(0x1704_0097);
    let other_world = seeded_test_entity_id(0x1704_0098);
    seed_world_claim(&server, in_world, actor_ref, world_a);
    seed_world_claim(&server, other_world, actor_ref, world_b);

    let read = |credential: &'static str,
                id: &'static str,
                scope: &crate::mcp::McpConnectorScope,
                target: oneiron::EntityId| {
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            credential,
            id,
            "tasks.expand",
            mcp_merge_args(
                mcp_scoped_envelope(actor_ref, "read_tasks", scope),
                json!({ "arguments": { "task_ref": target.to_hex() } }),
            ),
        )
    };

    // FACET axis, with no world narrowing anywhere in the fixture: the owning
    // credential clears the gate and fails downstream on the row's TYPE, and
    // the other facet never reaches the facade at all.
    let own = mcp_refusal(
        &server,
        read(cred_facet_a, "facet-read-a", &facet_only_a, owned),
    )
    .await;
    assert_ne!(
        own["error"]["data"]["error_code"],
        Value::from("mcp_scope_refused"),
        "the owning facet credential must clear the scope gate: {own:?}"
    );
    let cross_facet = mcp_refusal(
        &server,
        read(cred_facet_b, "facet-read-b", &facet_only_b, owned),
    )
    .await;
    assert_mcp_structured_error(&cross_facet, "mcp_scope_refused");

    // WORLD axis, with no facet narrowing anywhere in the fixture.
    // 1. A non-CLAIM row carries no world key, so it cannot be proven in-world
    //    and is refused fail-closed — symmetric with the facet axis.
    let no_world_key = mcp_refusal(
        &server,
        read(cred_world_a, "world-read-turn", &world_only_a, owned),
    )
    .await;
    assert_mcp_structured_error(&no_world_key, "mcp_scope_refused");
    // 2. A CLAIM in another world stays refused.
    let cross_world = mcp_refusal(
        &server,
        read(cred_world_a, "world-read-other", &world_only_a, other_world),
    )
    .await;
    assert_mcp_structured_error(&cross_world, "mcp_scope_refused");
    // 3. An IN-WORLD claim is still admitted: the ceiling narrows, it does not
    //    close. The call then fails downstream on the row's type, as it should.
    let in_world_read = mcp_refusal(
        &server,
        read(cred_world_a, "world-read-own", &world_only_a, in_world),
    )
    .await;
    assert_ne!(
        in_world_read["error"]["data"]["error_code"],
        Value::from("mcp_scope_refused"),
        "an in-world claim must clear the world ceiling: {in_world_read:?}"
    );

    // No cross WRITE: the refusal happens BEFORE the ack ever dispatches.
    let foreign_write = mcp_refusal(
        &server,
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            cred_facet_b,
            "cross-write-b",
            "tasks.ack",
            mcp_merge_args(
                mcp_scoped_envelope(actor_ref, "ack_task", &facet_only_b),
                json!({ "arguments": { "task_ref": owned.to_hex() } }),
            ),
        ),
    )
    .await;
    assert_mcp_structured_error(&foreign_write, "mcp_scope_refused");

    // ONE-1704 B4: a queued frame is delivered to a VAULT-WIDE connection and
    // to no narrowed one, however same-actor and however queued.
    let (conn_facet_a, conn_facet_b, conn_wide, run_a, run_b) = {
        let mut registry = server.mcp_registry.lock().await;
        let a = registry
            .resolve(cred_facet_a, 1, |_, _| true)
            .expect("facet credential a resolves");
        let b = registry
            .resolve(cred_facet_b, 1, |_, _| true)
            .expect("facet credential b resolves");
        let wide = registry
            .resolve(cred_wide, 1, |_, _| true)
            .expect("the vault-wide credential resolves");
        for connection in [&a.stream_connection, &wide.stream_connection] {
            registry.enqueue_stream_frame(
                connection,
                oneiron::context_board::BoardStreamFrame {
                    epoch: 3,
                    kind: oneiron::context_board::FrameKind::Keyframe("queued".to_owned()),
                },
            );
        }
        (
            a.stream_connection.clone(),
            b.stream_connection.clone(),
            wide.stream_connection,
            crate::mcp::mcp_code_run_id("shared-run", &a),
            crate::mcp::mcp_code_run_id("shared-run", &b),
        )
    };
    assert_ne!(
        conn_facet_a, conn_facet_b,
        "two credentials own two connections"
    );
    assert_ne!(conn_facet_a, conn_wide);

    let check =
        |credential: &'static str, id: &'static str, scope: &crate::mcp::McpConnectorScope| {
            mcp_endpoint_call_request(
                MCP_TOOL_FIRST_PATH,
                credential,
                id,
                "tasks.check",
                mcp_scoped_envelope(actor_ref, "read_tasks", scope),
            )
        };
    let (_, b_first) = route_json(
        server.clone(),
        check(cred_facet_b, "carrier-b", &facet_only_b),
    )
    .await;
    assert!(
        b_first["result"].get("carrier").is_none(),
        "a frame queued for another credential must not ride here: {b_first:?}"
    );
    // The narrowed connection the frame WAS queued for still receives nothing:
    // the engine's router cannot filter world/facet, so the fail-closed
    // delivery for a narrowed connection is none at all.
    for id in ["carrier-a1", "carrier-a2"] {
        let (_, narrowed) =
            route_json(server.clone(), check(cred_facet_a, id, &facet_only_a)).await;
        assert!(
            narrowed["result"].get("carrier").is_none(),
            "a narrowed connection receives zero carrier frames: {narrowed:?}"
        );
    }
    // Vault-wide delivery is untouched: exactly one frame, exactly once.
    let (_, wide_first) = route_json(
        server.clone(),
        check(cred_wide, "carrier-wide-1", &vault_wide),
    )
    .await;
    assert_eq!(
        wide_first["result"]["carrier"]["class"],
        Value::from("carrier"),
        "a vault-wide connection carries its own queued frame: {wide_first:?}"
    );
    let (_, wide_second) = route_json(
        server.clone(),
        check(cred_wide, "carrier-wide-2", &vault_wide),
    )
    .await;
    assert!(
        wide_second["result"].get("carrier").is_none(),
        "one queued frame rides exactly once: {wide_second:?}"
    );

    // No claim-id COLLISION: one actor, one reused handle, two credentials.
    assert_ne!(run_a, run_b);
}

#[tokio::test]
async fn mcp_board_epoch_is_state_monotonic() {
    let (_dir, server) = test_server();
    let actor_ref = seeded_test_entity_id(0x1704_00a1);
    let credential = "one-1704-epoch-credential";
    register_mcp_actor(
        &server,
        credential,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    let setup = |id: &'static str| {
        mcp_endpoint_call_request(
            "/mcp",
            credential,
            id,
            "setup_oneiron",
            mcp_endpoint_envelope(actor_ref, "read_board"),
        )
    };
    let (_, first) = route_json(server.clone(), setup("epoch-1")).await;
    let epoch = first["result"]["structuredContent"]["board"]["epoch"]
        .as_u64()
        .expect("setup states a board epoch");

    // A second call with NO state change keeps the same epoch, however much
    // wall-clock time passed between them: the epoch is state, not a timer.
    let (_, second) = route_json(server.clone(), setup("epoch-2")).await;
    assert_eq!(
        second["result"]["structuredContent"]["board"]["epoch"],
        Value::from(epoch),
        "an unchanged board keeps its epoch: {second:?}"
    );

    // The registry RETAINS the exact snapshot setup returned, and that is what
    // a later expand fences against.
    let connection = {
        let registry = server.mcp_registry.lock().await;
        let actor = registry
            .resolve(credential, 1, |_, _| true)
            .expect("credential resolves");
        assert_eq!(
            registry
                .board_snapshot(&actor.stream_connection)
                .expect("the registry retains the snapshot")
                .epoch,
            epoch,
        );
        actor.stream_connection.clone()
    };

    // A frame at the retained epoch is NOT stale.
    let (_, fresh) = route_json(
        server.clone(),
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            credential,
            "epoch-expand",
            "board.expand",
            mcp_merge_args(
                mcp_endpoint_envelope(actor_ref, "read_board"),
                json!({ "arguments": { "key": "VERBS", "frame_epoch": epoch } }),
            ),
        ),
    )
    .await;
    assert!(
        fresh.get("error").is_none(),
        "a clock that moved must not stale a fresh frame: {fresh:?}"
    );

    // A frame at any other epoch IS stale — the fence still fires.
    let stale = mcp_refusal(
        &server,
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            credential,
            "epoch-stale",
            "board.expand",
            mcp_merge_args(
                mcp_endpoint_envelope(actor_ref, "read_board"),
                json!({ "arguments": { "key": "VERBS", "frame_epoch": epoch + 1 } }),
            ),
        ),
    )
    .await;
    assert_mcp_structured_error(&stale, "verb_dispatch_failed");

    // The production epoch minter itself: a state change advances by exactly
    // one however little wall-clock time passed, and NOTHING can make it go
    // back — it reads no clock at all, so a rollback has nothing to regress.
    let mut registry = server.mcp_registry.lock().await;
    let state_a = crate::mcp::mcp_board_state_hash("VaultWide", &["row-a".to_owned()]);
    let state_b = crate::mcp::mcp_board_state_hash("VaultWide", &["row-b".to_owned()]);
    let base = registry.board_snapshot_epoch(&connection, state_a);
    assert_eq!(
        registry.board_snapshot_epoch(&connection, state_a),
        base,
        "an unchanged state never advances",
    );
    let advanced = registry.board_snapshot_epoch(&connection, state_b);
    assert_eq!(advanced, base + 1, "a state change advances by exactly one");
    assert_eq!(
        registry.board_snapshot_epoch(&connection, state_a),
        advanced + 1,
        "returning to an earlier STATE still moves forward: the epoch never regresses",
    );
}
