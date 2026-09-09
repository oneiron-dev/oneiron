//! Negotiated result content, board omission/health axes, discover vocabulary, carrier drain, skills-pack onramp.

use super::*;

/// ONE-1704 repair: a client on the NEGOTIATED protocol receives usable result
/// data in `content`, not only through the `structuredContent` side channel.
#[tokio::test]
async fn mcp_results_carry_usable_data_in_negotiated_content() {
    let (_dir, server) = test_server();
    let actor_ref = seeded_test_entity_id(0x1704_0105);
    let credential = "one-1704-negotiated-content";
    register_mcp_actor(
        &server,
        credential,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    let (_, handshake) = route_json(
        server.clone(),
        mcp_endpoint_request(
            "/mcp",
            credential,
            json!({ "jsonrpc": "2.0", "id": "negotiated-init", "method": "initialize" }),
        ),
    )
    .await;
    assert_eq!(
        handshake["result"]["protocolVersion"],
        Value::from(MCP_PROTOCOL_VERSION),
        "the content contract below is the one this handshake negotiates"
    );

    let (_, setup) = route_json(
        server.clone(),
        mcp_endpoint_call_request(
            "/mcp",
            credential,
            "negotiated-setup",
            "setup_oneiron",
            mcp_endpoint_envelope(actor_ref, "read_board"),
        ),
    )
    .await;
    let result = &setup["result"];
    let content = result["content"]
        .as_array()
        .expect("the negotiated result carries content");
    assert_eq!(content.len(), 2, "{result:?}");
    assert_eq!(content[0]["type"], Value::from("text"));
    assert_eq!(content[1]["type"], Value::from("text"));
    let data = serde_json::from_str::<Value>(
        content[1]["text"]
            .as_str()
            .expect("the data content item is text"),
    )
    .expect("the negotiated content item states the result data as JSON");
    assert_eq!(
        data, result["structuredContent"],
        "the negotiated content and the structured side channel state the SAME data"
    );
    assert_eq!(data["tool"], Value::from("setup_oneiron"));
    assert!(
        data["board"]["keyframe"]
            .as_str()
            .is_some_and(|text| !text.trim().is_empty()),
        "{data:?}"
    );
    assert_eq!(
        data["verb_grammar"]["verbs"].as_array().map(Vec::len),
        Some(mcp_expected_generated_names().len()),
    );
    assert_eq!(data["meta"]["end"], Value::from("Complete"));

    // A carrier frame stays BESIDE the result: it is not folded into the
    // negotiated content, and the content still states the tool's own data.
    let connection = {
        let registry = server.mcp_registry.lock().await;
        registry
            .resolve(credential, 1, |_, _| true)
            .expect("credential resolves")
            .stream_connection
    };
    {
        let mut registry = server.mcp_registry.lock().await;
        registry.enqueue_stream_frame(
            &connection,
            oneiron::context_board::BoardStreamFrame {
                epoch: 4,
                kind: oneiron::context_board::FrameKind::Keyframe("queued board".to_owned()),
            },
        );
    }
    let (_, checked) = route_json(
        server.clone(),
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            credential,
            "negotiated-check",
            "tasks.check",
            mcp_endpoint_envelope(actor_ref, "read_tasks"),
        ),
    )
    .await;
    let result = &checked["result"];
    assert_eq!(result["carrier"]["class"], Value::from("carrier"));
    let content = result["content"]
        .as_array()
        .expect("the negotiated result carries content");
    assert_eq!(content.len(), 2, "{result:?}");
    let data = serde_json::from_str::<Value>(
        content[1]["text"]
            .as_str()
            .expect("the data content item is text"),
    )
    .expect("the negotiated content item states the result data as JSON");
    assert_eq!(data, result["structuredContent"]);
    assert_eq!(data["tool"], Value::from("tasks.check"));
    assert_eq!(data["output"]["kind"], Value::from("tasks_section"));
    assert!(
        data.get("carrier").is_none(),
        "a carrier frame is never folded into the tool's own content: {data:?}"
    );
}

/// ONE-1704 repair: a board page's omission count is the REQUESTED SCOPE's
/// filtering only. A render window's truncation is stated on its own axis, and
/// a section the scope did not narrow is not reported partial because another
/// section was.
#[test]
fn mcp_board_page_omissions_count_requested_scope_only() {
    let expand = crate::mcp::McpVerbBinding::BoardExpand;
    let refresh = crate::mcp::McpVerbBinding::BoardRefresh;
    let subscribe = crate::mcp::McpVerbBinding::BoardSubscribe;
    let healthy = crate::mcp::McpRetrievalHealth::Healthy;
    let omissions = McpBoardOmissions {
        scope_omitted: 3,
        window_truncated: 2,
        source_exhausted: true,
    };

    let tasks = json!({ "kind": "expanded", "key": "TASKS", "lines": ["a", "b"] });
    let source = mcp_board_verb_page_source(expand, &tasks, omissions);
    assert_eq!(source.produced, 2);
    assert_eq!(source.scope_omitted, 3);
    assert_eq!(source.window_truncated, 2);
    assert_eq!(source.withheld(), 5);
    assert_eq!(source.health(), crate::mcp::McpRetrievalHealth::Partial);

    // Another section's page is not partial because a TASKS row was outside
    // the credential's ceiling.
    let verbs = json!({ "kind": "expanded", "key": "VERBS", "lines": ["board.expand"] });
    let source = mcp_board_verb_page_source(expand, &verbs, omissions);
    assert_eq!(source.produced, 1);
    assert_eq!(source.scope_omitted, 0);
    assert_eq!(source.window_truncated, 0);
    assert_eq!(source.health(), healthy);

    // A refresh renders the whole board, so both axes ride it — apart.
    let frame = json!({ "kind": "frame", "frame": { "epoch": 1 } });
    let source = mcp_board_verb_page_source(refresh, &frame, omissions);
    assert_eq!(source.produced, 1);
    assert_eq!(source.scope_omitted, 3);
    assert_eq!(source.window_truncated, 2);

    // A capped scan is a WINDOW fact and is degraded, never a scope omission.
    let capped_scan = McpBoardOmissions {
        scope_omitted: 0,
        window_truncated: 4,
        source_exhausted: false,
    };
    let capped = mcp_board_verb_page_source(refresh, &frame, capped_scan);
    assert_eq!(capped.scope_omitted, 0);
    assert_eq!(capped.window_truncated, 4);
    assert_eq!(capped.health(), crate::mcp::McpRetrievalHealth::Degraded);

    // A subscription receipt states itself completely on both axes.
    let receipt = json!({ "kind": "subscription", "active": [] });
    let source = mcp_board_verb_page_source(subscribe, &receipt, omissions);
    assert_eq!(source.scope_omitted, 0);
    assert_eq!(source.window_truncated, 0);
    assert_eq!(source.health(), healthy);
}

/// ONE-1704 repair: setup health is derived from the board's COMPLETE omission
/// facts, not from the requested scope's filtering alone.
///
/// A vault-wide connector omits no row by scope, so the old derivation called
/// EVERY board it rendered healthy — including one whose render WINDOW had
/// truncated rows away, and one whose own TASK scan stopped at its cap and so
/// cannot say what it skipped. Both are incomplete boards, and setup said
/// `healthy` over them.
#[test]
fn mcp_setup_health_reads_every_board_omission_axis() {
    let omissions = |scope_omitted, window_truncated, source_exhausted| McpBoardOmissions {
        scope_omitted,
        window_truncated,
        source_exhausted,
    };
    let healthy = crate::mcp::McpRetrievalHealth::Healthy;
    let partial = crate::mcp::McpRetrievalHealth::Partial;
    let degraded = crate::mcp::McpRetrievalHealth::Degraded;

    // A complete board is the only healthy one.
    assert_eq!(omissions(0, 0, true).health(), healthy);

    // The exact defect: a vault-wide connector's board whose bounded renderer
    // could not return every TASKS row. Nothing was omitted by scope, and the
    // board is still incomplete.
    assert_eq!(omissions(0, 7, true).health(), partial);

    // A scan that stopped at its own cap does not know what it skipped, so it
    // is degraded even with nothing counted on either axis.
    assert_eq!(omissions(0, 0, false).health(), degraded);
    assert_eq!(omissions(0, 7, false).health(), degraded);

    // The scope axis keeps its settled meaning, and the two axes together
    // never read healthier than either alone.
    assert_eq!(omissions(3, 0, true).health(), partial);
    assert_eq!(omissions(3, 7, true).health(), partial);
    assert_eq!(omissions(3, 0, false).health(), degraded);

    // It is the SAME derivation every other producer states, so a board's
    // health and a page's health cannot drift apart.
    for (scope_omitted, window_truncated, source_exhausted) in [
        (0, 0, true),
        (0, 7, true),
        (3, 0, true),
        (3, 7, true),
        (0, 0, false),
        (3, 7, false),
    ] {
        assert_eq!(
            omissions(scope_omitted, window_truncated, source_exhausted).health(),
            crate::mcp::McpPageSource::scoped_window(
                0,
                scope_omitted,
                window_truncated,
                source_exhausted,
            )
            .health(),
            "board health and producer health must be one meaning",
        );
    }
}

/// ONE-1704 repair: `/api/core/discover` describes the MCP surfaces this
/// process actually REGISTERS, and says which endpoint each name is callable
/// on.
///
/// The capability vocabulary used to be derived from the retired plain-verb
/// catalog alone, so discovery advertised names both endpoints answer
/// `unknown_tool` for and advertised none of the names they do accept.
#[test]
fn discovery_states_the_registered_mcp_surfaces_and_their_endpoints() {
    let flags = serde_json::to_value(feature_flags()).expect("feature flags serialize");
    let capabilities = flags["capabilities"]
        .as_array()
        .expect("capabilities is an array")
        .iter()
        .map(|token| token.as_str().expect("a capability is a string").to_owned())
        .collect::<Vec<_>>();

    // Every REGISTERED tool is advertised, and its endpoint is named beside it.
    let mut expected_endpoint_tokens = std::collections::BTreeSet::new();
    for mode in crate::mcp::McpSurfaceMode::ALL {
        let surface = crate::mcp::registered_surface(mode);
        assert!(
            !surface.tool_names().is_empty(),
            "{} registers at least one tool",
            mode.as_str()
        );
        for name in surface.tool_names() {
            assert!(
                surface.resolve(name).is_some(),
                "{name} is advertised only because {} accepts it",
                mode.as_str(),
            );
            assert!(
                capabilities.contains(&format!("{MCP_TOOL_CAPABILITY_PREFIX}{name}")),
                "discovery advertises the registered tool {name}",
            );
            expected_endpoint_tokens.insert(format!(
                "{MCP_ENDPOINT_CAPABILITY_PREFIX}{mode}.{name}",
                mode = mode.as_str(),
            ));
        }
    }

    // The endpoint vocabulary is EXACTLY the registrations: nothing advertised
    // that a surface would reject, and nothing registered left unstated.
    let advertised_endpoint_tokens = capabilities
        .iter()
        .filter(|token| token.starts_with(MCP_ENDPOINT_CAPABILITY_PREFIX))
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(advertised_endpoint_tokens, expected_endpoint_tokens);
    assert_eq!(
        capabilities
            .iter()
            .filter(|token| token.starts_with(MCP_ENDPOINT_CAPABILITY_PREFIX))
            .count(),
        expected_endpoint_tokens.len(),
        "each endpoint token is advertised exactly once",
    );

    // The primary endpoint is the ONE setup tool, and the verbs live on the
    // tool-first endpoint. A caller can tell them apart from discovery alone.
    assert!(capabilities.contains(&format!(
        "{MCP_ENDPOINT_CAPABILITY_PREFIX}primary.{}",
        crate::mcp::MCP_SETUP_TOOL
    )));
    assert!(capabilities.contains(&format!(
        "{MCP_ENDPOINT_CAPABILITY_PREFIX}tool_first.tasks.create"
    )));
    assert!(
        !capabilities.contains(&format!(
            "{MCP_ENDPOINT_CAPABILITY_PREFIX}tool_first.{}",
            crate::mcp::MCP_SETUP_TOOL
        )),
        "a tool one endpoint registers is not advertised on the other",
    );

    // `execute_code` is registered on neither endpoint in this release, so no
    // endpoint token names it.
    for mode in crate::mcp::McpSurfaceMode::ALL {
        assert!(
            crate::mcp::registered_surface(mode)
                .resolve(crate::mcp::MCP_EXECUTE_CODE_TOOL)
                .is_none(),
        );
        assert!(!capabilities.contains(&format!(
            "{MCP_ENDPOINT_CAPABILITY_PREFIX}{mode}.{tool}",
            mode = mode.as_str(),
            tool = crate::mcp::MCP_EXECUTE_CODE_TOOL,
        )));
    }

    // Discovery stays deterministic: the same registrations, the same bytes.
    assert_eq!(
        serde_json::to_value(feature_flags()).expect("feature flags serialize"),
        flags,
    );
}

#[tokio::test]
async fn mcp_carrier_drains_exactly_once_on_next_arbitrary_result() {
    let (_dir, server) = test_server();
    let actor_ref = seeded_test_entity_id(0x1704_00c1);
    let credential = "one-1704-carrier-credential";
    register_mcp_actor(
        &server,
        credential,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    let connection = {
        let registry = server.mcp_registry.lock().await;
        registry
            .resolve(credential, 1, |_, _| true)
            .expect("credential resolves")
            .stream_connection
    };

    // ONE-1704 carrier repair: a setup CONTINUATION restates the keyframe page
    // one already delivered, so it must NOT re-mint it. Re-minting superseded
    // the same-epoch delta queued behind it and then drained the duplicate
    // away, and the transition reached no result at all.
    let setup_page = |id: &'static str, page: Value| {
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
    let (_, page_one) = route_json(
        server.clone(),
        setup_page("carrier-page-1", json!({ "limit": 1 })),
    )
    .await;
    let page_one = &page_one["result"]["structuredContent"];
    let board_epoch = page_one["board"]["epoch"]
        .as_u64()
        .expect("setup states a board epoch");
    let cursor = page_one["meta"]["page"]["cursor"]
        .as_str()
        .expect("a capped setup page carries a successor handle")
        .to_owned();
    {
        let mut registry = server.mcp_registry.lock().await;
        registry.enqueue_stream_frame(
            &connection,
            oneiron::context_board::BoardStreamFrame {
                epoch: board_epoch,
                kind: oneiron::context_board::FrameKind::Delta(vec![
                    oneiron::context_board::DeltaRow {
                        key: "TASKS:continuation".to_owned(),
                        line: "queued after page one".to_owned(),
                    },
                ]),
            },
        );
    }
    let (_, continued) = route_json(
        server.clone(),
        setup_page("carrier-page-2", json!({ "limit": 50, "cursor": cursor })),
    )
    .await;
    assert_eq!(
        continued["result"]["carrier"],
        json!({
            "class": "carrier",
            "frame": {
                "epoch": board_epoch,
                "kind": {
                    "kind": "delta",
                    "payload": [{ "key": "TASKS:continuation", "line": "queued after page one" }],
                },
            },
        }),
        "a setup continuation drains the queued same-epoch delta instead of \
         re-minting page one's keyframe: {continued:?}"
    );

    {
        let mut registry = server.mcp_registry.lock().await;
        registry.enqueue_stream_frame(
            &connection,
            oneiron::context_board::BoardStreamFrame {
                epoch: 5,
                kind: oneiron::context_board::FrameKind::Keyframe("queued board".to_owned()),
            },
        );
        registry.enqueue_stream_frame(
            &connection,
            oneiron::context_board::BoardStreamFrame {
                epoch: 5,
                kind: oneiron::context_board::FrameKind::Delta(vec![
                    oneiron::context_board::DeltaRow {
                        key: "TASKS:0".to_owned(),
                        line: "queued".to_owned(),
                    },
                ]),
            },
        );
    }

    let check = |id: &'static str| {
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            credential,
            id,
            "tasks.check",
            mcp_endpoint_envelope(actor_ref, "read_tasks"),
        )
    };

    // The NEXT arbitrary successful result — a `tasks.*` one, which used to
    // strand the queue forever — carries exactly one top-level carrier frame,
    // beside the semantic content and never inside it. The engine hands back
    // the pending KEYFRAME first.
    let (status, first) = route_json(server.clone(), check("carrier-1")).await;
    assert_eq!(status, StatusCode::OK);
    let result = &first["result"];
    assert_eq!(result["carrier"]["class"], Value::from("carrier"));
    assert!(result["carrier"]["frame"].is_object(), "{result:?}");
    assert_eq!(
        result["carrier"]["frame"]["epoch"],
        Value::from(5),
        "{result:?}"
    );
    assert_eq!(
        result["carrier"]["frame"]["kind"]["kind"],
        Value::from("keyframe"),
        "result one carries the keyframe: {result:?}"
    );
    assert_eq!(
        result["carrier"]["frame"]["kind"]["payload"],
        Value::from("queued board"),
        "{result:?}"
    );
    assert!(
        result["structuredContent"].get("carrier").is_none(),
        "a frame is data BESIDE the result, never inside it: {result:?}"
    );

    // ONE-1704 M7: the same-epoch delta the engine kept behind that keyframe is
    // a NEWER transition, so it rides the NEXT result instead of being drained
    // away. Exactly one frame per result, and zero transitions lost.
    let (_, second) = route_json(server.clone(), check("carrier-2")).await;
    let second_frame = &second["result"]["carrier"]["frame"];
    assert_eq!(second["result"]["carrier"]["class"], Value::from("carrier"));
    assert_eq!(second_frame["epoch"], Value::from(5), "{second:?}");
    assert_eq!(
        second_frame["kind"]["kind"],
        Value::from("delta"),
        "result two carries the same-epoch delta: {second:?}"
    );
    assert_eq!(
        second_frame["kind"]["payload"][0]["key"],
        Value::from("TASKS:0"),
        "{second:?}"
    );
    assert_eq!(
        second_frame["kind"]["payload"][0]["line"],
        Value::from("queued"),
        "{second:?}"
    );

    // And the call after THAT carries none: nothing is replayed.
    let (_, third) = route_json(server.clone(), check("carrier-3a")).await;
    assert!(
        third["result"].get("carrier").is_none(),
        "the queue drains exactly once per frame: {third:?}"
    );

    // A setup keyframe supersedes and DRAINS what is queued behind it, so a
    // fresh keyframe never rides beside an older carrier and the next result
    // does not inherit one either.
    {
        let mut registry = server.mcp_registry.lock().await;
        registry.enqueue_stream_frame(
            &connection,
            oneiron::context_board::BoardStreamFrame {
                epoch: 6,
                kind: oneiron::context_board::FrameKind::Keyframe("stale board".to_owned()),
            },
        );
    }
    let (_, setup) = route_json(
        server.clone(),
        mcp_endpoint_call_request(
            "/mcp",
            credential,
            "carrier-setup",
            "setup_oneiron",
            mcp_endpoint_envelope(actor_ref, "read_board"),
        ),
    )
    .await;
    assert!(setup["result"].get("carrier").is_none(), "{setup:?}");
    let (_, after_setup) = route_json(server, check("carrier-3")).await;
    assert!(
        after_setup["result"].get("carrier").is_none(),
        "setup superseded and drained the older queue: {after_setup:?}"
    );
}
