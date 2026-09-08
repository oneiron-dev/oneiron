//! Tool-first vs /mcp listings, setup keyframe, execute_code retirement, narrowed admission, arg gating.

use super::*;

#[tokio::test]
async fn mcp_endpoints_register_distinct_tool_listings() {
    let (_dir, server) = test_server();
    let actor_ref = seeded_test_entity_id(0x1704_0001);
    let credential = "one-1704-listing-credential";
    register_mcp_actor(
        &server,
        credential,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    let (status, primary) = route_json(
        server.clone(),
        mcp_list_request("/mcp", credential, "primary-list"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(primary["result"]["surfaceMode"], Value::from("primary"));
    // ONE-1704 B1: the primary catalog is the one tool this release ships.
    assert_eq!(mcp_listed_tool_names(&primary), vec!["setup_oneiron"]);
    assert!(
        !serde_json::to_string(&primary["result"])
            .expect("listing serializes")
            .contains("execute_code"),
        "a retired tool must not appear in the listing bytes: {primary:?}"
    );
    assert!(
        primary["result"].get("actor").is_none(),
        "a listing must not echo the caller: {primary:?}"
    );

    let (status, tool_first) = route_json(
        server,
        mcp_list_request(MCP_TOOL_FIRST_PATH, credential, "tool-first-list"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        tool_first["result"]["surfaceMode"],
        Value::from("tool_first")
    );
    assert_eq!(
        mcp_listed_tool_names(&tool_first),
        mcp_expected_generated_names(),
        "the tool-first listing is generated from the exported verb rows"
    );
    for name in mcp_listed_tool_names(&tool_first) {
        assert!(!name.starts_with("oneiron."), "{name} must not be listed");
    }
}

#[tokio::test]
async fn mcp_tools_list_bytes_are_identical_across_credentials_and_scopes() {
    let (_dir, server) = test_server();
    let wide_actor = seeded_test_entity_id(0x1704_0011);
    let scoped_actor = seeded_test_entity_id(0x1704_0012);
    register_mcp_actor(
        &server,
        "one-1704-wide-credential",
        wide_actor,
        oneiron::EdgeActorClass::Human,
    )
    .await;
    register_scoped_mcp_actor(
        &server,
        "one-1704-scoped-credential",
        scoped_actor,
        crate::mcp::McpConnectorScope::scoped(
            Some(seeded_test_entity_id(0x1704_0013)),
            Some(seeded_test_entity_id(0x1704_0014)),
        ),
    )
    .await;

    for path in ["/mcp", MCP_TOOL_FIRST_PATH] {
        let (_, wide) = route_json(
            server.clone(),
            mcp_list_request(path, "one-1704-wide-credential", "same-id"),
        )
        .await;
        let (_, scoped) = route_json(
            server.clone(),
            mcp_list_request(path, "one-1704-scoped-credential", "same-id"),
        )
        .await;
        assert_eq!(
            serde_json::to_string(&wide["result"]).expect("result serializes"),
            serde_json::to_string(&scoped["result"]).expect("result serializes"),
            "{path} listing must be byte-identical for every credential",
        );
    }
}

#[tokio::test]
async fn mcp_cross_endpoint_tool_calls_are_unknown_tool() {
    let (_dir, server) = test_server();
    let actor_ref = seeded_test_entity_id(0x1704_0021);
    let credential = "one-1704-cross-credential";
    register_mcp_actor(
        &server,
        credential,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    let (status, body) = route_json(
        server.clone(),
        mcp_endpoint_call_request(
            "/mcp",
            credential,
            "cross-1",
            "board.expand",
            mcp_merge_args(
                mcp_endpoint_envelope(actor_ref, "read_board"),
                json!({ "arguments": { "key": "TASKS" } }),
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_mcp_structured_error(&body, "unknown_tool");
    assert!(
        body["error"]["data"]["effective_scope"].is_object(),
        "an actor-derived refusal states its scope: {body:?}"
    );

    let (_, body) = route_json(
        server,
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            credential,
            "cross-2",
            "setup_oneiron",
            mcp_endpoint_envelope(actor_ref, "read_board"),
        ),
    )
    .await;
    assert_mcp_structured_error(&body, "unknown_tool");
}

#[tokio::test]
async fn mcp_setup_returns_keyframe_grammar_instructions_and_no_carrier() {
    let (_dir, server) = test_server();
    let actor_ref = seeded_test_entity_id(0x1704_0031);
    let credential = "one-1704-setup-credential";
    register_mcp_actor(
        &server,
        credential,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    let (status, body) = route_json(
        server,
        mcp_endpoint_call_request(
            "/mcp",
            credential,
            "setup-1",
            "setup_oneiron",
            mcp_merge_args(
                mcp_endpoint_envelope(actor_ref, "read_board"),
                json!({ "board_budget_tok": 800, "cache": { "ttl_ms": 900_000 } }),
            ),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.get("error").is_none(),
        "unexpected MCP error: {body:?}"
    );
    let result = &body["result"];
    let structured = &result["structuredContent"];
    assert_eq!(structured["tool"], Value::from("setup_oneiron"));
    assert!(
        structured["board"]["keyframe"]
            .as_str()
            .is_some_and(|text| text.contains("surface=\"board\"")),
        "{structured:?}"
    );
    assert_eq!(
        structured["board"]["render"]["budget_tok"],
        Value::from(800)
    );
    assert!(
        structured["board"]["render"]["floor_exceeds_cap"].is_boolean(),
        "render metadata passes through losslessly: {structured:?}"
    );
    assert_eq!(
        structured["verb_grammar"]["verbs"].as_array().map(Vec::len),
        Some(mcp_expected_generated_names().len()),
    );
    assert!(
        structured["instructions"]
            .as_str()
            .is_some_and(|text| !text.trim().is_empty()),
        "{structured:?}"
    );
    assert_mcp_result_metadata(&structured["meta"]);
    // A foreign TTL never widens ours, and setup never pairs its fresh
    // keyframe with an older carrier.
    assert_eq!(structured["meta"]["ttlMs"], Value::from(0));
    assert!(result.get("carrier").is_none(), "{result:?}");
}

/// ONE-1704 B2: a direct `execute_code` call is refused with ONE stable typed
/// code on BOTH routes, under full and narrowed credentials, BEFORE any run
/// exists — and it stays refused even with a host bound, because the retirement
/// is at the wire and not merely a missing provider.
#[tokio::test]
async fn mcp_direct_execute_code_is_typed_unavailable_before_any_run() {
    bind_mcp_test_code_host();
    let (_dir, server) = test_server();
    let wide_actor = seeded_test_entity_id(0x1704_0041);
    let wide = "one-1704-code-credential";
    register_mcp_actor(&server, wide, wide_actor, oneiron::EdgeActorClass::Human).await;

    let narrow_actor = seeded_test_entity_id(0x1704_0042);
    let narrow_scope =
        crate::mcp::McpConnectorScope::scoped(Some(seeded_test_entity_id(0x1704_0043)), None);
    let narrow = "one-1704-code-narrow-credential";
    register_scoped_mcp_actor(&server, narrow, narrow_actor, narrow_scope.clone()).await;

    let entered_before = mcp_fixture_code_runs();
    let code_args = json!({
        "run_ref": "one-1704-run",
        "page": { "limit": 4 },
        "task": "search memory for the launch plan, then park an outbound effect",
    });

    for (label, credential, envelope) in [
        (
            "vault-wide",
            wide,
            mcp_endpoint_envelope(wide_actor, "run_code"),
        ),
        (
            "narrowed",
            narrow,
            mcp_scoped_envelope(narrow_actor, "run_code", &narrow_scope),
        ),
    ] {
        for path in ["/mcp", MCP_TOOL_FIRST_PATH] {
            let body = mcp_refusal(
                &server,
                mcp_endpoint_call_request(
                    path,
                    credential,
                    &format!("code-{label}"),
                    "execute_code",
                    mcp_merge_args(envelope.clone(), code_args.clone()),
                ),
            )
            .await;
            assert_mcp_structured_error(&body, "execute_code_unavailable");
            assert_eq!(
                body["error"]["data"]["field"],
                Value::from("name"),
                "{label} on {path}: {body:?}"
            );
            // Nothing a run would have published reaches the wire: no run
            // handle, no resume block, no terminal claim, no durable wait.
            let serialized = serde_json::to_string(&body).expect("refusal serializes");
            for forbidden in ["\"resume\"", "\"run_id\"", "\"terminal\"", "\"wait_id\""] {
                assert!(
                    !serialized.contains(forbidden),
                    "{label} on {path}: a refusal must publish no {forbidden}: {body:?}"
                );
            }
            assert!(body.get("result").is_none(), "{label} on {path}: {body:?}");
        }
    }

    assert_eq!(
        mcp_fixture_code_runs(),
        entered_before,
        "zero runs were created: the bound host was never entered",
    );

    // The tool is not listed on either endpoint either.
    for path in ["/mcp", MCP_TOOL_FIRST_PATH] {
        let (_, listing) =
            route_json(server.clone(), mcp_list_request(path, wide, "code-list")).await;
        assert!(
            !mcp_listed_tool_names(&listing).contains(&"execute_code"),
            "{path} must not list a tool this release cannot run: {listing:?}"
        );
    }
}

/// ONE-1704 B3: narrowed admission is fail-closed on the world and facet axes
/// INDEPENDENTLY, for `execute_code` and for `tasks.create` alike, and a
/// vault-wide credential is untouched.
#[tokio::test]
async fn mcp_narrowed_admission_refuses_unscoped_execution_on_each_axis() {
    let (_dir, server) = test_server();
    let actor_ref = seeded_test_entity_id(0x1704_00d1);
    let world_only =
        crate::mcp::McpConnectorScope::scoped(Some(seeded_test_entity_id(0x1704_00d2)), None);
    let facet_only =
        crate::mcp::McpConnectorScope::scoped(None, Some(seeded_test_entity_id(0x1704_00d3)));
    let vault_wide = crate::mcp::McpConnectorScope::vault_wide();
    register_scoped_mcp_actor(
        &server,
        "one-1704-world-only",
        actor_ref,
        world_only.clone(),
    )
    .await;
    register_scoped_mcp_actor(
        &server,
        "one-1704-facet-only",
        actor_ref,
        facet_only.clone(),
    )
    .await;
    register_mcp_actor(
        &server,
        "one-1704-axis-wide",
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    let create =
        |credential: &'static str, id: &'static str, scope: &crate::mcp::McpConnectorScope| {
            mcp_endpoint_call_request(
                MCP_TOOL_FIRST_PATH,
                credential,
                id,
                "tasks.create",
                mcp_merge_args(
                    mcp_scoped_envelope(actor_ref, "write_tasks", scope),
                    json!({ "arguments": { "spec": { "kind": "review" } } }),
                ),
            )
        };

    // The world axis alone refuses, with NO facet narrowing in the fixture.
    let world_refusal = mcp_refusal(
        &server,
        create("one-1704-world-only", "axis-world", &world_only),
    )
    .await;
    assert_mcp_structured_error(&world_refusal, "mcp_scope_refused");
    assert_scoped_refusal(
        &world_refusal,
        &crate::mcp::mcp_effective_scope_value(&world_only),
        "world-only tasks.create",
    );

    // The facet axis alone refuses, with NO world narrowing in the fixture.
    let facet_refusal = mcp_refusal(
        &server,
        create("one-1704-facet-only", "axis-facet", &facet_only),
    )
    .await;
    assert_mcp_structured_error(&facet_refusal, "mcp_scope_refused");
    assert_scoped_refusal(
        &facet_refusal,
        &crate::mcp::mcp_effective_scope_value(&facet_only),
        "facet-only tasks.create",
    );

    // A vault-wide credential is NOT scope-refused: an actor-wide create is
    // exactly its ceiling, whatever the facade then decides.
    let (_, wide_create) = route_json(
        server.clone(),
        create("one-1704-axis-wide", "axis-wide", &vault_wide),
    )
    .await;
    assert_ne!(
        wide_create["error"]["data"]["error_code"],
        Value::from("mcp_scope_refused"),
        "a vault-wide credential must clear the admission: {wide_create:?}"
    );

    // The same admission refuses `execute_code` on each axis on its own. The
    // wire never reaches this — B2 refuses the name first — so the admission
    // itself is exercised directly, which is the door a future scoped-positive
    // program would have to open.
    let args = crate::mcp::validate_mcp_endpoint_tool_args(
        crate::mcp::McpEndpointTool::ExecuteCode,
        mcp_merge_args(
            mcp_scoped_envelope(actor_ref, "run_code", &world_only),
            json!({ "run_ref": "axis-run", "task": "read the board" }),
        ),
    )
    .expect("the retired argument shape still decodes");
    for (label, credential, scope) in [
        ("world-only", "one-1704-world-only", &world_only),
        ("facet-only", "one-1704-facet-only", &facet_only),
        ("vault-wide", "one-1704-axis-wide", &vault_wide),
    ] {
        let context = crate::api::resolve_mcp_gateway_actor(
            crate::mcp::McpSurfaceMode::Primary,
            "axis-admission",
            &mcp_credential_headers(credential),
            &server,
        )
        .await
        .expect("credential resolves");
        let admitted = crate::api::mcp_admit_scoped_call(&server, &args, &context);
        if scope.is_narrow() {
            let error = admitted.expect_err(&format!("{label} must be refused"));
            assert!(
                format!("{error:?}").contains("mcp_scope_refused"),
                "{label}: {error:?}"
            );
        } else {
            admitted.unwrap_or_else(|error| {
                panic!("{label} must clear the admission: {error:?}");
            });
        }
    }
}

/// ONE-1704 / Codex 3907570260: a JSON number's own TEXT survives the HTTP
/// request boundary, so the wire admits exactly what the schema advertises.
///
/// `18446744073709551615.0` is the mathematical `u64::MAX` that Draft 2020-12
/// `type: integer` accepts. The gateway routes the JSON-RPC envelope through a
/// `serde_json::Value`, which — on this build's feature set — rounds that
/// number through `f64` into a value printing ABOVE the advertised ceiling.
/// The arguments are therefore read back out of the REQUEST BYTES, so the
/// decoder still sees the spelling the caller actually sent.
#[tokio::test]
async fn mcp_tool_call_preserves_request_number_text_at_advertised_integers() {
    let (_dir, server) = test_server();
    let actor_ref = seeded_test_entity_id(0x1704_0052);
    let credential = "one-1704-raw-number";
    register_mcp_actor(
        &server,
        credential,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    // The candidate is substituted as TEXT, so it never becomes a `Value` on
    // the way out either: these are the exact bytes a client would put on the
    // wire.
    let call = |id: &str, ttl_ms: &str| {
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {
                "name": "tasks.check",
                "arguments": mcp_merge_args(
                    mcp_endpoint_envelope(actor_ref, "read_tasks"),
                    json!({ "cache": { "ttl_ms": "__oneiron_raw_ttl__" } }),
                ),
            },
        })
        .to_string()
        .replace("\"__oneiron_raw_ttl__\"", ttl_ms);
        Request::builder()
            .method("POST")
            .uri(MCP_TOOL_FIRST_PATH)
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, format!("Bearer {credential}"))
            .body(Body::from(body))
            .expect("raw mcp endpoint request")
    };

    // The exact advertised ceiling, spelled with a fraction, is ADMITTED.
    let (status, body) = route_json(
        server.clone(),
        call("raw-ceiling", "18446744073709551615.0"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.get("error").is_none(),
        "the advertised integer ceiling must decode over the wire: {body:?}"
    );
    assert_eq!(
        body["result"]["structuredContent"]["tool"],
        Value::from("tasks.check")
    );

    // One above the ceiling, and a value that is not an integer at all, are
    // still refused at the same door: the repair moved a spelling, not a bound.
    for (id, ttl_ms) in [
        ("raw-above", "18446744073709551616"),
        ("raw-above-fraction", "18446744073709551615.5"),
        ("raw-fraction", "1.5"),
        ("raw-negative", "-1.0"),
    ] {
        let refusal = mcp_refusal(&server, call(id, ttl_ms)).await;
        assert_eq!(
            refusal["error"]["data"]["kind"],
            Value::from("tool_args_invalid"),
            "cache.ttl_ms {ttl_ms} must stay refused: {refusal:?}"
        );
    }
}

#[tokio::test]
async fn mcp_tool_first_verb_call_carries_scope_page_and_cache_metadata() {
    let (_dir, server) = test_server();
    let actor_ref = seeded_test_entity_id(0x1704_0051);
    let credential = "one-1704-verb-credential";
    register_mcp_actor(
        &server,
        credential,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    let (status, body) = route_json(
        server,
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            credential,
            "verb-1",
            "tasks.check",
            mcp_merge_args(
                mcp_endpoint_envelope(actor_ref, "read_tasks"),
                json!({ "page": { "limit": 7 }, "cache": { "ttl_ms": 60_000 } }),
            ),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.get("error").is_none(),
        "unexpected MCP error: {body:?}"
    );
    let structured = &body["result"]["structuredContent"];
    assert_eq!(structured["tool"], Value::from("tasks.check"));
    assert_eq!(structured["family"], Value::from("tasks"));
    assert_eq!(structured["verb"], Value::from("check"));
    assert_eq!(structured["output"]["kind"], Value::from("tasks_section"));
    assert_mcp_result_metadata(&structured["meta"]);
    assert_eq!(structured["meta"]["page"]["granted"], Value::from(7));
    assert_eq!(
        structured["meta"]["surface_mode"],
        Value::from("tool_first")
    );
}

#[tokio::test]
async fn mcp_missing_credential_returns_the_structured_error_contract() {
    let (_dir, server) = test_server();
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({ "jsonrpc": "2.0", "id": "no-credential", "method": "tools/list" }).to_string(),
        ))
        .expect("uncredentialed MCP request");

    let (status, body) = route_json(server, request).await;

    assert_eq!(status, StatusCode::OK);
    assert_mcp_structured_error(&body, "mcp_auth_required");
    assert_eq!(
        body["error"]["data"]["request_id"],
        Value::from("no-credential")
    );
}

#[tokio::test]
async fn mcp_endpoint_tool_args_are_gated_before_execution() {
    let (_dir, server) = test_server();
    let actor_ref = seeded_test_entity_id(0x1704_0061);
    let credential = "one-1704-args-credential";
    register_mcp_actor(
        &server,
        credential,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    let (status, body) = route_json(
        server,
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            credential,
            "args-1",
            "board.expand",
            mcp_merge_args(
                mcp_endpoint_envelope(actor_ref, "read_board"),
                json!({ "arguments": { "frame_epoch": 3 } }),
            ),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_mcp_structured_error(&body, "tool_args_invalid");
    assert_eq!(body["error"]["data"]["field"], Value::from("key"));
}
