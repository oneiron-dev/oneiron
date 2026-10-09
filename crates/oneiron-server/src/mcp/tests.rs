use super::*;
use serde::Deserialize;

const ACTOR_ID: &str = "11111111111111111111111111111111";

/// The server-owned validation fixture.
///
/// ONE-1704 M1: it is the ENDPOINT census and nothing else. There are no
/// legacy `oneiron.*` cases because there is no legacy wire surface to census —
/// a name neither endpoint registered is `unknown_tool`, which the gateway
/// rows prove at the wire instead.
#[derive(Debug, Deserialize)]
struct McpToolValidationFixture {
    /// ONE-1704 endpoint-mode census: the tools an endpoint REGISTERS, keyed
    /// by the mode that registered them.
    endpoint_cases: Vec<McpEndpointValidationFixtureCase>,
}

#[derive(Debug, Deserialize)]
struct McpEndpointValidationFixtureCase {
    name: String,
    mode: String,
    tool: String,
    valid: bool,
    args: Value,
}

fn id(seed: u128) -> EntityId {
    EntityId::from_bytes(seed.to_be_bytes()).expect("test id should be nonzero")
}

fn registry() -> McpConnectorActorRegistry {
    McpConnectorActorRegistry::new(McpCredentialHashKey::from_bytes([42; 32]))
}

fn actor_ceiling_for(
    actor_class: EdgeActorClass,
    actor_ref: EntityId,
) -> impl FnOnce(&str, &str) -> bool {
    let expected_actor_ref = actor_ref.to_hex();
    move |gate_actor_class, gate_actor_ref| {
        gate_actor_class == actor_class.gate_actor_class() && gate_actor_ref == expected_actor_ref
    }
}

fn actor_json() -> Value {
    json!({
        "actor_ref": ACTOR_ID,
        "actor_class": "agent",
        "gate_actor_class": "agent",
        "gate_actor_ref": ACTOR_ID,
        "scope": {},
    })
}

fn consent_json(purpose: &str) -> Value {
    json!({
        "policy_ref": "policy:foreign-mcp",
        "purpose": purpose,
    })
}

fn unexpected_actor_ceiling_lookup(_: &str, _: &str) -> bool {
    panic!("actor ceiling lookup should not run after credential failure")
}

fn assert_closed_object_schemas(value: &Value, path: &str) {
    match value {
        Value::Object(map) => {
            // A typed map (the ask's disclosure) keys on data, not fields;
            // every value is still constrained by its item schema.
            let typed_map = map.get("properties").is_none()
                && map
                    .get("additionalProperties")
                    .is_some_and(Value::is_object);
            if matches!(map.get("type"), Some(Value::String(kind)) if kind == "object")
                && !typed_map
            {
                assert_eq!(
                    map.get("additionalProperties"),
                    Some(&Value::Bool(false)),
                    "object schema at {path} must be closed"
                );
            }

            for (key, child) in map {
                assert_closed_object_schemas(child, &format!("{path}.{key}"));
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                assert_closed_object_schemas(item, &format!("{path}[{index}]"));
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

#[test]
fn unknown_and_expired_connector_keys_fail_closed() {
    let mut registry = registry();
    registry
        .register(
            "expired-key",
            McpConnectorActorRecord::new(
                id(0xC001),
                EdgeActorClass::Agent,
                McpConnectorScope::vault_wide(),
            )
            .with_expiry(20),
        )
        .expect("expired key registration succeeds");

    assert_eq!(
        registry.resolve("missing-key", 19, unexpected_actor_ceiling_lookup),
        Err(McpConnectorActorResolutionError::UnknownCredential)
    );
    assert_eq!(
        registry.resolve("expired-key", 20, unexpected_actor_ceiling_lookup),
        Err(McpConnectorActorResolutionError::ExpiredCredential)
    );
}

#[test]
fn revoked_connector_key_fails_closed() {
    let mut registry = registry();
    registry
        .register(
            "revoked-key",
            McpConnectorActorRecord::new(
                id(0xD001),
                EdgeActorClass::Agent,
                McpConnectorScope::vault_wide(),
            ),
        )
        .expect("revoked key registration succeeds");

    assert_eq!(
        registry.revoke("revoked-key", 12),
        Ok(McpConnectorActorRevokeStatus::Revoked)
    );

    assert_eq!(
        registry.resolve("revoked-key", 13, unexpected_actor_ceiling_lookup),
        Err(McpConnectorActorResolutionError::RevokedCredential)
    );
}

#[test]
fn blank_and_duplicate_connector_keys_fail_closed() {
    let mut registry = registry();
    let record = McpConnectorActorRecord::new(
        id(0xE001),
        EdgeActorClass::Agent,
        McpConnectorScope::vault_wide(),
    );

    assert_eq!(
        registry.register("  ", record.clone()),
        Err(McpConnectorActorRegistrationError::EmptyCredential)
    );

    registry
        .register("connector-key", record.clone())
        .expect("first registration succeeds");
    assert_eq!(
        registry.register("connector-key", record),
        Err(McpConnectorActorRegistrationError::DuplicateCredential)
    );
}

#[test]
fn credential_whitespace_is_canonicalized_for_all_lookups() {
    let actor = id(0xF001);
    let mut registry = registry();
    let record = McpConnectorActorRecord::new(
        actor,
        EdgeActorClass::Agent,
        McpConnectorScope::vault_wide(),
    );

    registry
        .register(" connector-key ", record.clone())
        .expect("registration trims credential");
    assert_eq!(
        registry.register("connector-key", record),
        Err(McpConnectorActorRegistrationError::DuplicateCredential)
    );

    assert_eq!(
        registry
            .resolve(
                "\tconnector-key\n",
                10,
                actor_ceiling_for(EdgeActorClass::Agent, actor),
            )
            .expect("trimmed lookup resolves")
            .actor_ref,
        actor
    );
    assert_eq!(
        registry.revoke(" connector-key ", 11),
        Ok(McpConnectorActorRevokeStatus::Revoked)
    );
    assert_eq!(
        registry.resolve("connector-key", 12, unexpected_actor_ceiling_lookup),
        Err(McpConnectorActorResolutionError::RevokedCredential)
    );
}

#[test]
fn registry_debug_does_not_print_credentials_or_hash_key() {
    let mut registry = registry();
    registry
        .register(
            "very-secret-connector-key",
            McpConnectorActorRecord::new(
                id(0xF101),
                EdgeActorClass::Agent,
                McpConnectorScope::vault_wide(),
            ),
        )
        .expect("registration succeeds");

    let debug = format!("{registry:?}");
    assert!(debug.contains("record_count"));
    assert!(!debug.contains("very-secret-connector-key"));
    assert!(!debug.contains("42"));
}

#[test]
fn missing_actor_ceiling_fails_closed_after_credential_resolves() {
    let actor = id(0xF501);
    let mut registry = registry();
    registry
        .register(
            "connector-key",
            McpConnectorActorRecord::new(
                actor,
                EdgeActorClass::Agent,
                McpConnectorScope::vault_wide(),
            ),
        )
        .expect("registration succeeds");

    assert_eq!(
        registry.resolve("connector-key", 10, |_, _| false),
        Err(McpConnectorActorResolutionError::MissingActorCeiling)
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// ONE-1704 — endpoint surface modes
// ═══════════════════════════════════════════════════════════════════════════

fn mode_named(name: &str) -> McpSurfaceMode {
    McpSurfaceMode::ALL
        .into_iter()
        .find(|mode| mode.as_str() == name)
        .unwrap_or_else(|| panic!("{name} is not a registerable surface mode"))
}

fn endpoint_envelope(tool: &str) -> Value {
    json!({
        "schema_version": MCP_TOOL_ARGS_SCHEMA_VERSION,
        "actor": actor_json(),
        "consent": consent_json(tool),
    })
}

#[test]
fn endpoint_tool_schemas_are_closed_and_versioned() {
    for mode in McpSurfaceMode::ALL {
        for tool in registered_surface(mode).tools() {
            let schema = tool.schema();
            assert_eq!(schema.name, tool.name());
            assert!(!schema.description.trim().is_empty());
            let root = &schema.input_schema;
            assert_eq!(root["$schema"], MCP_SCHEMA_DRAFT);
            assert_eq!(root["additionalProperties"], false);
            assert_eq!(
                root["properties"]["schema_version"]["const"],
                MCP_TOOL_ARGS_SCHEMA_VERSION,
            );
            assert_closed_object_schemas(root, schema.name.as_str());
        }
    }
    // The protocol field name survives serialization.
    let serialized =
        serde_json::to_value(McpEndpointTool::Setup.schema()).expect("endpoint schema serializes");
    assert!(serialized.get("inputSchema").is_some());
    assert!(serialized.get("input_schema").is_none());
}

#[test]
fn mcp_endpoint_tool_validation_fixtures_gate_args_before_execution() {
    let fixture: McpToolValidationFixture = serde_json::from_str(include_str!(
        "../../tests/fixtures/mcp_tool_args.validation.json"
    ))
    .expect("fixture should parse");

    assert!(
        fixture.endpoint_cases.len() >= 30,
        "the endpoint census must stay broad",
    );
    for case in fixture.endpoint_cases {
        let mode = mode_named(&case.mode);
        let tool = registered_surface(mode)
            .resolve(&case.tool)
            .unwrap_or_else(|| panic!("{} names a tool registered on {}", case.name, case.mode));
        let result = validate_mcp_endpoint_tool_args(tool, case.args);
        if case.valid {
            result.unwrap_or_else(|error| {
                panic!("{} should validate but failed: {error}", case.name)
            });
        } else {
            assert!(result.is_err(), "{} should fail validation", case.name);
        }
    }
}

/// ONE-1704 M3: durable ids are derived from the IMMUTABLE connector-scope
/// identity through ONE central function, so one actor reusing one key under
/// two disjoint credentials can never collide or replay.
#[test]
fn claim_id_scopes_by_credential_scope_identity() {
    let actor = id(0xD001);
    let world_a = id(0xD0A1);
    let world_b = id(0xD0B1);
    let mut registry = registry();
    for (credential, world) in [("credential-a", world_a), ("credential-b", world_b)] {
        registry
            .register(
                credential,
                McpConnectorActorRecord::new(
                    actor,
                    EdgeActorClass::Agent,
                    McpConnectorScope::scoped(Some(world), None),
                ),
            )
            .expect("registration succeeds");
    }
    let resolve = |credential: &str| {
        registry
            .resolve(
                credential,
                10,
                actor_ceiling_for(EdgeActorClass::Agent, actor),
            )
            .expect("connector resolves")
    };
    let a = resolve("credential-a");
    let b = resolve("credential-b");

    // Everything actor-derived is EQUAL; only the credential and the scope it
    // was registered under differ. That is exactly the collision the old
    // actor-only derivation could not see.
    assert_eq!(a.actor_ref, b.actor_ref);
    assert_eq!(a.gate_actor_ref, b.gate_actor_ref);
    assert_eq!(a.gate_actor_class, b.gate_actor_class);
    assert_ne!(a.stream_connection, b.stream_connection);

    for namespace in ["execute_code.run", "claim", "proposal"] {
        assert_ne!(
            mcp_scoped_identity_id(namespace, "one-1704-key", &a),
            mcp_scoped_identity_id(namespace, "one-1704-key", &b),
            "{namespace}: two credentials must not map one reused key onto one row",
        );
    }

    // Scope alone discriminates, with the credential identity held EQUAL.
    let restated = McpResolvedActor {
        auth: None,
        scope: McpConnectorScope::scoped(Some(world_b), None),
        ..a.clone()
    };
    assert_eq!(restated.stream_connection, a.stream_connection);
    assert_ne!(
        mcp_scoped_identity_id("claim", "one-1704-key", &a),
        mcp_scoped_identity_id("claim", "one-1704-key", &restated),
    );

    // Two namespaces under ONE credential never collide either, and one
    // credential replaying one key is deterministic.
    assert_ne!(
        mcp_scoped_identity_id("claim", "one-1704-key", &a),
        mcp_scoped_identity_id("proposal", "one-1704-key", &a),
    );
    assert_eq!(
        mcp_scoped_identity_id("claim", "one-1704-key", &a),
        mcp_scoped_identity_id("claim", "one-1704-key", &a),
    );

    // The `execute_code` run handle IS that one derivation, not a second rule.
    assert_eq!(
        mcp_code_run_id("one-1704-run", &a),
        mcp_scoped_identity_id("execute_code.run", "one-1704-run", &a),
    );
    assert_ne!(
        mcp_code_run_id("one-1704-run", &a),
        mcp_code_run_id("one-1704-run", &b),
    );
}

/// A canonical payload carrying EVERY advertised top-level property of one
/// registered tool.
fn endpoint_census_args(tool: McpEndpointTool) -> Value {
    let mut args = json!({
        "schema_version": MCP_TOOL_ARGS_SCHEMA_VERSION,
        "actor": actor_json(),
        "consent": consent_json("endpoint_census"),
        "page": { "limit": 3, "forceful_override": false },
        "cache": { "ttl_ms": 1_000 },
    });
    let object = args.as_object_mut().expect("census args are an object");
    match tool {
        McpEndpointTool::Setup => {
            object.insert("board_budget_tok".to_owned(), json!(400));
        }
        McpEndpointTool::ExecuteCode => {
            object.insert("run_ref".to_owned(), json!("census-run"));
            object.insert("task".to_owned(), json!("summarize the current board"));
        }
        McpEndpointTool::Verb(verb) => {
            object.insert("arguments".to_owned(), endpoint_census_arguments(verb));
        }
    }
    args
}

/// The minimal in-grammar `arguments` object for one generated verb.
fn endpoint_census_arguments(verb: McpGeneratedVerbTool) -> Value {
    match verb.name {
        "tasks.outcomes" => json!({"spec":{"group_ref":ACTOR_ID}}),
        "tasks.answer" => {
            json!({"spec":{"handle":{"group_ref":ACTOR_ID},"word":{"result_ref":ACTOR_ID,"option":null,"inform_for":null,"provenance_refs":[]}}})
        }
        "tasks.ask" => {
            json!({"spec":{"intent_key":"ask-test","who":{"responder":{"human":{"actor_ref":ACTOR_ID}}},"what":{"reference":{"turn":ACTOR_ID},"revision":1,"options":{},"context_refs":[],"label":null,"outcome_binding":null},"until":9999999999_u64,"decide":"first"}})
        }
        "tasks.wait" => {
            json!({"spec":{"handle":{"group_ref":ACTOR_ID},"step_key":"step-one"}})
        }
        "rooms.list" => json!({}),
        "rooms.messages" | "rooms.find" | "rooms.render" => json!({"room_ref":ACTOR_ID}),
        "rooms.claim" | "rooms.get" | "rooms.trunk" => {
            json!({"room_ref":ACTOR_ID,"turn_ref":ACTOR_ID})
        }
        "rooms.speak" => json!({"room_ref":ACTOR_ID,"spec":{}}),
        "board.expand" => json!({ "key": "TASKS" }),
        "board.refresh" | "describe" => json!({}),
        "board.subscribe" | "board.unsubscribe" => {
            json!({ "scopes": ["my_tasks"] })
        }
        "tasks.update" | "cancel" => {
            json!({ "task_ref": ACTOR_ID })
        }
        "tasks.create" => json!({ "spec": { "kind": "review" } }),
        _ => json!({ "request": {} }),
    }
}

#[test]
fn stream_connection_is_credential_derived_and_never_argument_derived() {
    let actor = id(0xE001);
    let mut registry = registry();
    registry
        .register(
            "stream-key",
            McpConnectorActorRecord::new(
                actor,
                EdgeActorClass::Agent,
                McpConnectorScope::vault_wide(),
            ),
        )
        .expect("registration succeeds");
    assert!(registry.stream_connection_attached("stream-key"));

    let resolved = registry
        .resolve(
            "stream-key",
            10,
            actor_ceiling_for(EdgeActorClass::Agent, actor),
        )
        .expect("connector resolves");
    assert!(
        resolved
            .stream_connection
            .0
            .starts_with(MCP_STREAM_CONNECTION_PREFIX)
    );
    assert!(
        !resolved.stream_connection.0.contains("stream-key"),
        "the credential itself never appears in the connection id",
    );
    assert!(
        !resolved.stream_connection.0.contains(&actor.to_hex()),
        "the connection is the FINGERPRINT's, not the actor's",
    );

    // Whitespace canonicalization reaches the same fingerprint, so the same
    // credential always owns the same connection.
    let again = registry
        .resolve(
            "  stream-key  ",
            11,
            actor_ceiling_for(EdgeActorClass::Agent, actor),
        )
        .expect("connector resolves");
    assert_eq!(again.stream_connection, resolved.stream_connection);
}

#[test]
fn revoke_unregister_and_prune_detach_process_local_stream_state() {
    let actor = id(0xE101);
    let record = || {
        McpConnectorActorRecord::new(
            actor,
            EdgeActorClass::Agent,
            McpConnectorScope::vault_wide(),
        )
    };
    let frame = || oneiron::context_board::BoardStreamFrame {
        epoch: 1,
        kind: oneiron::context_board::FrameKind::Keyframe("board".to_owned()),
    };

    for lifecycle in ["revoke", "unregister", "prune"] {
        let mut registry = registry();
        let stored = match lifecycle {
            "prune" => record().with_expiry(5),
            _ => record(),
        };
        registry.register("stream-key", stored).expect("registers");
        let resolved = registry
            .resolve(
                "stream-key",
                1,
                actor_ceiling_for(EdgeActorClass::Agent, actor),
            )
            .expect("connector resolves");
        registry.enqueue_stream_frame(&resolved.stream_connection, frame());
        registry.mint_page_cursor(&resolved.stream_connection, MCP_SETUP_TOOL, [7; 32], 3, 2);
        assert!(
            registry.stream_connection_attached("stream-key"),
            "{lifecycle}: state must exist before teardown",
        );
        assert!(
            registry.page_continuation_live(&resolved.stream_connection),
            "{lifecycle}: the continuation must exist before teardown",
        );

        match lifecycle {
            "revoke" => {
                assert_eq!(
                    registry.revoke("stream-key", 9),
                    Ok(McpConnectorActorRevokeStatus::Revoked),
                );
            }
            "unregister" => assert!(registry.unregister("stream-key")),
            _ => assert_eq!(registry.prune_revoked_or_expired(9), 1),
        }

        assert!(
            !registry.stream_connection_attached("stream-key"),
            "{lifecycle} must detach the connector's STREAM state",
        );
        assert!(
            registry
                .next_carrier_frame(&resolved.stream_connection)
                .is_none(),
            "{lifecycle} must drop queued frames with the connection",
        );
        assert!(
            !registry.page_continuation_live(&resolved.stream_connection),
            "{lifecycle} must drop the live page continuation with the connection",
        );
    }
}

// ─── ONE-1704 M6: bound, consumable page continuations ─────────────────────

/// The digest one continuation is bound to, for a page wish of `limit`.
fn cursor_digest(query_limit: u32, cursor: Option<&str>) -> [u8; 32] {
    // `page` is transport-only and is removed in its entirety. Keep a separate
    // producer-query field so the mismatch assertion below tests a real query
    // identity change rather than a different pagination window.
    mcp_page_argument_digest(&json!({
        "schema_version": MCP_TOOL_ARGS_SCHEMA_VERSION,
        "query": { "limit": query_limit },
        "page": { "limit": 5, "forceful_override": false, "cursor": cursor },
    }))
}

/// ONE-1704 M6: a continuation handle is BOUND to its connector, tool,
/// arguments, snapshot epoch, and position; every mismatch and every replay is
/// a fail-closed refusal, never a silent restart at page one.
#[test]
fn page_cursors_are_bound_consumed_once_and_refused_on_every_mismatch() {
    let actor = id(0xF001);
    let mut registry = registry();
    for credential in ["cursor-key", "other-key"] {
        registry
            .register(
                credential,
                McpConnectorActorRecord::new(
                    actor,
                    EdgeActorClass::Agent,
                    McpConnectorScope::vault_wide(),
                ),
            )
            .expect("registration succeeds");
    }
    let connection = registry
        .resolve(
            "cursor-key",
            10,
            actor_ceiling_for(EdgeActorClass::Agent, actor),
        )
        .expect("connector resolves")
        .stream_connection;
    let other = registry
        .resolve(
            "other-key",
            10,
            actor_ceiling_for(EdgeActorClass::Agent, actor),
        )
        .expect("connector resolves")
        .stream_connection;
    assert_ne!(
        connection, other,
        "two credentials own two connections, so two continuations",
    );

    let digest = cursor_digest(5, None);
    let cursor = registry.mint_page_cursor(&connection, MCP_SETUP_TOOL, digest, 7, 5);
    // Opaque: a versioned prefix over keyed-hash bytes, with no offset,
    // count, or query material a caller could read or arithmetic on.
    let opaque = cursor
        .strip_prefix("mcpc1:")
        .unwrap_or_else(|| panic!("a continuation handle is prefixed: {cursor}"));
    assert_eq!(opaque.len(), 32, "{cursor}");
    assert_eq!(
        opaque.chars().filter(char::is_ascii_hexdigit).count(),
        32,
        "{cursor}",
    );
    assert!(registry.page_continuation_live(&connection));

    // The binding excludes the entire PAGE object: the same producer query
    // carrying a changed window or the handle back digests identically.
    assert_eq!(digest, cursor_digest(5, Some(cursor.as_str())));
    assert_ne!(digest, cursor_digest(4, None));

    // Wrong connector: another credential's connection never holds this handle.
    assert_eq!(
        registry.consume_page_cursor(&other, MCP_SETUP_TOOL, digest, 7, &cursor),
        Err(McpPageCursorError::Unknown),
    );
    // Wrong tool, wrong arguments, wrong snapshot epoch — each on its own axis.
    assert_eq!(
        registry.consume_page_cursor(&connection, "describe", digest, 7, &cursor),
        Err(McpPageCursorError::ToolMismatch),
    );
    let other_digest = cursor_digest(4, None);
    assert_eq!(
        registry.consume_page_cursor(&connection, MCP_SETUP_TOOL, other_digest, 7, &cursor),
        Err(McpPageCursorError::ArgumentsMismatch),
    );
    assert_eq!(
        registry.consume_page_cursor(&connection, MCP_SETUP_TOOL, digest, 8, &cursor),
        Err(McpPageCursorError::SnapshotMismatch),
    );
    // A token minted for another POSITION is a different token, and it is not
    // this connection's live handle.
    let other_position = registry.page_cursor_token(&connection, MCP_SETUP_TOOL, digest, 7, 6);
    assert_ne!(other_position, cursor);
    assert_eq!(
        registry.consume_page_cursor(&connection, MCP_SETUP_TOOL, digest, 7, &other_position),
        Err(McpPageCursorError::Unknown),
    );
    assert!(
        registry.page_continuation_live(&connection),
        "a refused presentation is not a consumption",
    );

    // The bound handle continues from the position it was minted for, ONCE.
    assert_eq!(
        registry.consume_page_cursor(&connection, MCP_SETUP_TOOL, digest, 7, &cursor),
        Ok(5),
    );
    assert!(!registry.page_continuation_live(&connection));
    assert_eq!(
        registry.consume_page_cursor(&connection, MCP_SETUP_TOOL, digest, 7, &cursor),
        Err(McpPageCursorError::Unknown),
        "a replayed handle is refused, never a silent page one",
    );

    // ONE stable wire code for every axis, and it carries a recovery path.
    for error in [
        McpPageCursorError::Unknown,
        McpPageCursorError::ToolMismatch,
        McpPageCursorError::ArgumentsMismatch,
        McpPageCursorError::SnapshotMismatch,
        McpPageCursorError::Unsupported,
    ] {
        assert_eq!(error.error_code(), MCP_PAGE_CURSOR_INVALID_CODE);
        assert!(!error.to_string().trim().is_empty());
    }
    assert!(!mcp_recovery_suggestions(MCP_PAGE_CURSOR_INVALID_CODE).is_empty());
}

/// The exact producer material one retained continuation carries.
fn page_snapshot(row: &str) -> McpPageSnapshot {
    McpPageSnapshot {
        output: json!({ "kind": "expanded", "lines": [row] }),
        source: McpPageSource::complete(1),
        health: McpRetrievalHealth::Healthy,
        keyframe: None,
    }
}

/// ONE-1704 repair: ONE connection owns MANY outstanding continuations.
///
/// A second `More` page used to overwrite the first page's retained row, so a
/// client could not hold two live reads and one refusal destroyed an unrelated
/// enumeration. Each cursor is now its own row: consuming one consumes exactly
/// one, and every refusal consumes none.
#[test]
fn one_connection_owns_many_independent_continuations() {
    let actor = id(0xF201);
    let mut registry = registry();
    for credential in ["multi-key", "multi-other-key"] {
        registry
            .register(
                credential,
                McpConnectorActorRecord::new(
                    actor,
                    EdgeActorClass::Agent,
                    McpConnectorScope::vault_wide(),
                ),
            )
            .expect("registration succeeds");
    }
    let connection = registry
        .resolve(
            "multi-key",
            10,
            actor_ceiling_for(EdgeActorClass::Agent, actor),
        )
        .expect("connector resolves")
        .stream_connection;
    let other = registry
        .resolve(
            "multi-other-key",
            10,
            actor_ceiling_for(EdgeActorClass::Agent, actor),
        )
        .expect("connector resolves")
        .stream_connection;

    let setup_digest = mcp_page_argument_digest(&json!({ "query": "setup" }));
    let tasks_digest = mcp_page_argument_digest(&json!({ "query": "tasks" }));
    let first = registry.mint_page_cursor_with_snapshot(
        &connection,
        MCP_SETUP_TOOL,
        setup_digest,
        3,
        5,
        Some(page_snapshot("first")),
    );
    let second = registry.mint_page_cursor_with_snapshot(
        &connection,
        "describe",
        tasks_digest,
        4,
        2,
        Some(page_snapshot("second")),
    );
    assert_ne!(first, second);
    assert_eq!(
        registry.live_page_continuations(&connection),
        2,
        "a second More page does not destroy the first page's handle",
    );
    assert!(registry.page_continuation_live_cursor(&connection, &first));
    assert!(registry.page_continuation_live_cursor(&connection, &second));
    assert_eq!(
        registry.live_page_continuations(&other),
        0,
        "another connector owns none of them",
    );

    // Every refusal axis, and none of them consumes anything.
    let mut refused = |owner: &StreamConnectionId, tool: &str, digest: [u8; 32]| {
        registry
            .consume_page_cursor_state(owner, tool, digest, None, &first)
            .expect_err("this presentation must be refused")
    };
    assert_eq!(
        refused(&other, MCP_SETUP_TOOL, setup_digest),
        McpPageCursorError::Unknown,
    );
    assert_eq!(
        refused(&connection, "describe", setup_digest),
        McpPageCursorError::ToolMismatch,
    );
    assert_eq!(
        refused(&connection, MCP_SETUP_TOOL, tasks_digest),
        McpPageCursorError::ArgumentsMismatch,
    );
    // A caller that PINS another producer epoch is refused on that axis too.
    assert_eq!(
        registry.consume_page_cursor(&connection, MCP_SETUP_TOOL, setup_digest, 9, &first),
        Err(McpPageCursorError::SnapshotMismatch),
    );
    assert_eq!(
        registry.live_page_continuations(&connection),
        2,
        "a refused presentation consumes nothing, sibling handles included",
    );

    // Consuming one consumes exactly one, and returns ITS retained producer.
    let continued = registry
        .consume_page_cursor_state(&connection, MCP_SETUP_TOOL, setup_digest, None, &first)
        .expect("the first handle continues its own producer");
    assert_eq!(continued.position, 5);
    assert_eq!(continued.snapshot_epoch, 3);
    assert_eq!(continued.snapshot, Some(page_snapshot("first")));
    assert!(!registry.page_continuation_live_cursor(&connection, &first));
    assert!(
        registry.page_continuation_live_cursor(&connection, &second),
        "the sibling continuation survives its sibling's consumption",
    );
    assert_eq!(registry.live_page_continuations(&connection), 1);

    // The second is still consumable, independently and exactly once.
    let continued = registry
        .consume_page_cursor_state(&connection, "describe", tasks_digest, None, &second)
        .expect("the second handle continues its own producer");
    assert_eq!(continued.position, 2);
    assert_eq!(continued.snapshot, Some(page_snapshot("second")));
    assert_eq!(registry.live_page_continuations(&connection), 0);
    assert_eq!(
        registry.consume_page_cursor_state(&connection, "describe", tasks_digest, None, &second),
        Err(McpPageCursorError::Unknown),
        "a replayed handle is refused, never a silent page one",
    );
}

/// ONE-1704 repair: a retained continuation is validated against the IMMUTABLE
/// producer snapshot it carries, not against the latest board epoch.
///
/// An unrelated board change between page one and page two cannot make page two
/// wrong — it is served from retained rows — so it must not destroy the
/// enumeration either. Producer identity stays bound on every other axis.
#[test]
fn a_retained_continuation_outlives_an_unrelated_board_epoch_change() {
    let actor = id(0xF202);
    let mut registry = registry();
    registry
        .register(
            "epoch-key",
            McpConnectorActorRecord::new(
                actor,
                EdgeActorClass::Agent,
                McpConnectorScope::vault_wide(),
            ),
        )
        .expect("registration succeeds");
    let connection = registry
        .resolve(
            "epoch-key",
            10,
            actor_ceiling_for(EdgeActorClass::Agent, actor),
        )
        .expect("connector resolves")
        .stream_connection;

    let digest = mcp_page_argument_digest(&json!({ "query": "tasks" }));
    let produced = registry.board_snapshot_epoch(
        &connection,
        mcp_board_state_hash("VaultWide", &["row-a".to_owned()]),
    );
    let cursor = registry.mint_page_cursor_with_snapshot(
        &connection,
        "describe",
        digest,
        produced,
        1,
        Some(page_snapshot("retained")),
    );

    // An UNRELATED later render moves this connection's latest board epoch.
    let latest = registry.board_snapshot_epoch(
        &connection,
        mcp_board_state_hash("VaultWide", &["row-b".to_owned()]),
    );
    assert_eq!(latest, produced + 1, "the latest board epoch moved");

    // Producer identity is still enforced on every axis that IS the producer.
    assert_eq!(
        registry.consume_page_cursor_state(&connection, MCP_SETUP_TOOL, digest, None, &cursor),
        Err(McpPageCursorError::ToolMismatch),
    );
    assert_eq!(
        registry.consume_page_cursor_state(
            &connection,
            "describe",
            mcp_page_argument_digest(&json!({ "query": "other" })),
            None,
            &cursor,
        ),
        Err(McpPageCursorError::ArgumentsMismatch),
    );
    // A caller that PINS a producer epoch other than the retained one is still
    // refused: the fence moved, it did not disappear.
    assert_eq!(
        registry.consume_page_cursor(&connection, "describe", digest, latest, &cursor),
        Err(McpPageCursorError::SnapshotMismatch),
    );

    let continued = registry
        .consume_page_cursor_state(&connection, "describe", digest, None, &cursor)
        .expect("the retained continuation survives an unrelated board epoch change");
    assert_eq!(continued.position, 1);
    assert_eq!(
        continued.snapshot_epoch, produced,
        "the continuation is of the producer snapshot it was minted against",
    );
    assert_eq!(continued.snapshot, Some(page_snapshot("retained")));
}

/// A small Draft 2020-12 evaluator for the closed schema vocabulary this
/// endpoint publishes. It deliberately evaluates the schema VALUE, rather than
/// approximating an integer range in Rust, so lexical forms such as `1.0` and
/// `1e0` exercise the standard's mathematical-integer rule.
#[allow(clippy::cognitive_complexity, clippy::too_many_lines)]
fn draft2020_12_accepts(schema: &Value, instance: &Value) -> bool {
    if let Some(constant) = schema.get("const")
        && !json_numbers_equal(constant, instance)
    {
        return false;
    }
    if let Some(values) = schema.get("enum").and_then(Value::as_array)
        && !values
            .iter()
            .any(|candidate| json_numbers_equal(candidate, instance))
    {
        return false;
    }
    if let Some(schemas) = schema.get("oneOf").and_then(Value::as_array)
        && schemas
            .iter()
            .filter(|schema| draft2020_12_accepts(schema, instance))
            .count()
            != 1
    {
        return false;
    }
    if let Some(schemas) = schema.get("anyOf").and_then(Value::as_array)
        && !schemas
            .iter()
            .any(|schema| draft2020_12_accepts(schema, instance))
    {
        return false;
    }
    if let Some(kind) = schema.get("type").and_then(Value::as_str)
        && !draft_type_accepts(kind, instance)
    {
        return false;
    }
    if let Some(object) = instance.as_object() {
        if let Some(required) = schema.get("required").and_then(Value::as_array)
            && required
                .iter()
                .any(|name| name.as_str().is_some_and(|name| !object.contains_key(name)))
        {
            return false;
        }
        if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
            let properties = schema.get("properties").and_then(Value::as_object);
            if object
                .keys()
                .any(|name| !properties.is_some_and(|properties| properties.contains_key(name)))
            {
                return false;
            }
        }
        if let Some(properties) = schema.get("properties").and_then(Value::as_object)
            && object.iter().any(|(name, value)| {
                properties
                    .get(name)
                    .is_some_and(|schema| !draft2020_12_accepts(schema, value))
            })
        {
            return false;
        }
    }
    if let Some(array) = instance.as_array() {
        if schema
            .get("minItems")
            .and_then(Value::as_u64)
            .is_some_and(|minimum| array.len() < minimum as usize)
        {
            return false;
        }
        if let Some(item_schema) = schema.get("items")
            && array
                .iter()
                .any(|item| !draft2020_12_accepts(item_schema, item))
        {
            return false;
        }
    }
    if let Some(string) = instance.as_str() {
        if schema
            .get("minLength")
            .and_then(Value::as_u64)
            .is_some_and(|minimum| string.chars().count() < minimum as usize)
            || schema
                .get("maxLength")
                .and_then(Value::as_u64)
                .is_some_and(|maximum| string.chars().count() > maximum as usize)
        {
            return false;
        }
        if let Some(pattern) = schema.get("pattern").and_then(Value::as_str) {
            let matches = match pattern {
                "\\S" => !string.chars().all(char::is_whitespace),
                "^[0-9a-f]{32}$" => {
                    string.len() == 32
                        && string
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                }
                _ => true,
            };
            if !matches {
                return false;
            }
        }
    }
    if instance.is_number() {
        if let Some(minimum) = schema.get("minimum")
            && !draft_number_at_least(instance, minimum)
        {
            return false;
        }
        if let Some(maximum) = schema.get("maximum")
            && !draft_number_at_most(instance, maximum)
        {
            return false;
        }
    }
    true
}

fn draft_type_accepts(kind: &str, instance: &Value) -> bool {
    match kind {
        "object" => instance.is_object(),
        "array" => instance.is_array(),
        "string" => instance.is_string(),
        "boolean" => instance.is_boolean(),
        "integer" => instance.as_number().is_some_and(json_number_is_integer),
        "number" => instance.is_number(),
        "null" => instance.is_null(),
        _ => false,
    }
}

fn json_number_is_integer(number: &serde_json::Number) -> bool {
    let text = number.to_string();
    let unsigned = text.strip_prefix('-').unwrap_or(&text);
    parse_json_unsigned_integer(unsigned, u128::MAX).is_ok()
}

fn unsigned_json_number(instance: &Value) -> Option<u128> {
    instance
        .as_number()
        .and_then(|number| parse_json_unsigned_integer(&number.to_string(), u128::MAX).ok())
}

fn json_numbers_equal(left: &Value, right: &Value) -> bool {
    match (unsigned_json_number(left), unsigned_json_number(right)) {
        (Some(left), Some(right)) => left == right,
        _ => left == right,
    }
}

fn draft_number_at_least(instance: &Value, minimum: &Value) -> bool {
    unsigned_json_number(instance).is_some_and(|actual| {
        unsigned_json_number(minimum).is_some_and(|minimum| actual >= minimum)
    })
}

fn draft_number_at_most(instance: &Value, maximum: &Value) -> bool {
    unsigned_json_number(instance).is_some_and(|actual| {
        unsigned_json_number(maximum).is_some_and(|maximum| actual <= maximum)
    })
}

/// One argument template with the audited numeric field replaced by the
/// candidate's own JSON text.
fn with_number(mut args: Value, pointer: &str, number: &str) -> Value {
    let instance =
        serde_json::from_str::<Value>(number).expect("a numeric candidate is valid JSON");
    let slot = args
        .pointer_mut(pointer)
        .unwrap_or_else(|| panic!("{pointer} names a field the template carries"));
    *slot = instance;
    args
}

/// One argument template rendered as JSON TEXT, each named position carrying a
/// candidate's EXACT spelling.
///
/// The number never becomes a `serde_json::Value` on the way in, which is the
/// whole point of these rows: a template built with [`with_number`] has already
/// rounded `18446744073709551615.0` through `f64` before any decoder sees it,
/// so it can only ever audit what the parsed walk can still tell apart.
fn raw_args_with_numbers(template: &Value, slots: &[(&str, &str)]) -> String {
    let mut args = template.clone();
    for (index, (pointer, _)) in slots.iter().enumerate() {
        let slot = args
            .pointer_mut(pointer)
            .unwrap_or_else(|| panic!("{pointer} names a field the template carries"));
        *slot = Value::from(format!("__oneiron_raw_number_{index}__"));
    }
    let mut rendered = args.to_string();
    for (index, (pointer, number)) in slots.iter().enumerate() {
        let quoted = format!("\"__oneiron_raw_number_{index}__\"");
        assert!(
            rendered.contains(&quoted),
            "{pointer} survives template rendering"
        );
        rendered = rendered.replace(&quoted, number);
    }
    rendered
}

fn raw_args_with_number(template: &Value, pointer: &str, number: &str) -> String {
    raw_args_with_numbers(template, &[(pointer, number)])
}

/// Whether the RAW decode boundary admits one candidate spelling: the bytes go
/// in exactly as the caller wrote them, the way the gateway hands them over.
fn raw_endpoint_decode_admits(
    tool: McpEndpointTool,
    template: &Value,
    pointer: &str,
    number: &str,
) -> bool {
    validate_mcp_endpoint_tool_args(
        tool,
        McpToolArguments::from_raw_json(raw_args_with_number(template, pointer, number)),
    )
    .is_ok()
}

/// ONE-1704 / Codex 3907570260: the decoder keeps a JSON number's own TEXT
/// until the schema-directed integer decision has been taken.
///
/// `18446744073709551615.0` is the mathematical `u64::MAX`, which Draft
/// 2020-12 `type: integer` admits. Parsed into a `serde_json::Value` first — as
/// this build must, carrying `preserve_order` and not `arbitrary_precision` —
/// it rounds through `f64` into a value that prints ABOVE that ceiling, and
/// `cache.ttl_ms` and `frame_epoch` refused what their own advertised schema
/// accepts. Every row below enters through the RAW boundary, so the first one
/// fails under the old lossy path.
#[test]
fn raw_decode_boundary_preserves_advertised_integer_number_text() {
    let expand = registered_surface(McpSurfaceMode::ToolFirst)
        .resolve("board.expand")
        .expect("board.expand is registered");
    let mut expand_args = endpoint_envelope("read_board");
    expand_args["arguments"] = json!({ "key": "TASKS", "frame_epoch": 0 });
    expand_args["cache"] = json!({ "ttl_ms": 0 });

    // Both advertised `u64` positions, one nested a level deeper than the
    // other, judged at the same ceiling.
    for pointer in ["/arguments/frame_epoch", "/cache/ttl_ms"] {
        for (number, admitted) in [
            // THE repair: the exact `u64::MAX`, spelled with a fraction.
            ("18446744073709551615.0", true),
            // ... and as an exponent, which its text proves just as integral.
            ("1.8446744073709551615e19", true),
            // The bounds that already held, unmoved.
            ("0", true),
            ("1", true),
            ("18446744073709551615", true),
            // Integral spellings the standard admits.
            ("0.0", true),
            ("1.0", true),
            ("1e0", true),
            ("0e0", true),
            // One above the maximum is still refused, by one.
            ("18446744073709551616", false),
            ("18446744073709551615.5", false),
            // Not an integer at all.
            ("1.5", false),
            // Negative, at an unsigned position.
            ("-1", false),
            ("-1.0", false),
            // Beyond anything this domain can restate without loss.
            ("1e30", false),
        ] {
            assert_eq!(
                raw_endpoint_decode_admits(expand, &expand_args, pointer, number),
                admitted,
                "{pointer} at {number}: the raw boundary and the advertised integer domain disagree",
            );
        }

        // What the raw boundary is FOR. The same value handed over as an
        // already-parsed `Value` has lost its spelling before this door is
        // reached — `f64` rounded it above the ceiling — so it is refused.
        // That is the path every row above used to take.
        assert!(
            validate_mcp_endpoint_tool_args(
                expand,
                with_number(expand_args.clone(), pointer, "18446744073709551615.0",),
            )
            .is_err(),
            "{pointer}: a rounded `Value` cannot carry the caller's ceiling value",
        );
    }
}

/// Raw fractional epochs must not become rounded integer epochs at admission.
#[test]
fn raw_board_expand_refuses_high_precision_fractional_epochs() {
    let expand = registered_surface(McpSurfaceMode::ToolFirst)
        .resolve("board.expand")
        .expect("board.expand is registered");
    let mut args = endpoint_envelope("read_board");
    args["arguments"] = json!({ "key": "TASKS", "frame_epoch": 0 });

    let integral = raw_args_with_number(&args, "/arguments/frame_epoch", "1.0");
    let admitted =
        validate_mcp_endpoint_tool_args(expand, McpToolArguments::from_raw_json(integral))
            .expect("an exact integral spelling is valid");
    let McpValidatedToolArgs::Verb(verb) = admitted else {
        panic!("board.expand is a verb")
    };
    assert_eq!(verb.payload.arguments.frame_epoch, Some(1));

    for token in ["1.00000000000000000001", "9007199254740993.5"] {
        let raw = raw_args_with_number(&args, "/arguments/frame_epoch", token);
        assert!(
            matches!(
                validate_mcp_endpoint_tool_args(expand, McpToolArguments::from_raw_json(raw)),
                Err(McpToolValidationError::Decode {
                    tool: "board.expand",
                    ..
                })
            ),
            "fractional raw epoch {token} must be refused before rounding"
        );
    }
}

/// Duplicate object keys use the same last-occurrence value as `serde_json`.
/// A discarded fractional epoch (or discarded whole arguments object) is not
/// an admitted field; a live fractional epoch must still fail closed.
#[test]
fn raw_board_expand_integer_walk_ignores_shadowed_object_members() {
    let expand = registered_surface(McpSurfaceMode::ToolFirst)
        .resolve("board.expand")
        .expect("board.expand is registered");
    let mut args = endpoint_envelope("read_board");
    args["arguments"] = json!({ "key": "TASKS", "frame_epoch": 1 });
    let base = args.to_string();
    let shadowed_field = base.replacen(
        "\"frame_epoch\":1",
        "\"frame_epoch\":1.5,\"frame_epoch\":1",
        1,
    );
    let shadowed_parent = base.replacen(
        "\"arguments\":",
        "\"arguments\":{\"key\":\"TASKS\",\"frame_epoch\":1.5},\"arguments\":",
        1,
    );
    let live_fraction = base.replacen(
        "\"frame_epoch\":1",
        "\"frame_epoch\":1,\"frame_epoch\":1.5",
        1,
    );
    for raw in [shadowed_field, shadowed_parent] {
        assert_ne!(raw, base, "a duplicate was inserted");
        let parsed: Value = serde_json::from_str(&raw).expect("valid JSON");
        let expected = validate_mcp_endpoint_tool_args(expand, parsed)
            .expect("parsed arguments select the final integer epoch");
        let actual = validate_mcp_endpoint_tool_args(expand, McpToolArguments::from_raw_json(raw))
            .expect("raw arguments must select the same epoch");
        assert_eq!(actual, expected);
        let McpValidatedToolArgs::Verb(verb) = actual else {
            panic!("board.expand is a verb")
        };
        assert_eq!(verb.payload.arguments.frame_epoch, Some(1));
    }
    assert_ne!(live_fraction, base, "a live fractional epoch was inserted");
    assert!(matches!(
        validate_mcp_endpoint_tool_args(expand, McpToolArguments::from_raw_json(live_fraction)),
        Err(McpToolValidationError::Decode {
            tool: "board.expand",
            ..
        })
    ));
}

/// The repair is SCHEMA-DIRECTED, so a free-form payload the catalog types `{}`
/// is never rewritten: a caller's `spec` that says `1.0` still stores `1.0`,
/// and a number the integer positions WOULD have restated is left alone here.
#[test]
fn raw_decode_boundary_leaves_free_form_numbers_untouched() {
    let create = registered_surface(McpSurfaceMode::ToolFirst)
        .resolve("tasks.create")
        .expect("tasks.create is registered");
    let mut args = endpoint_envelope("write_tasks");
    args["arguments"] = json!({ "spec": { "kind": "review", "weight": 0, "epoch": 0 } });
    let raw = raw_args_with_numbers(
        &args,
        &[
            ("/arguments/spec/weight", "1.0"),
            ("/arguments/spec/epoch", "18446744073709551615.0"),
        ],
    );

    let decoded = validate_mcp_endpoint_tool_args(create, McpToolArguments::from_raw_json(raw))
        .expect("a free-form spec decodes");
    let McpValidatedToolArgs::Verb(verb) = decoded else {
        panic!("tasks.create decodes to a verb payload");
    };
    let spec = verb.payload.arguments.spec.expect("spec is present");
    assert_eq!(
        serde_json::to_string(&spec["weight"]).expect("a free-form number reserializes"),
        "1.0",
        "a free-form number keeps the caller's own spelling",
    );
    assert_ne!(
        spec["epoch"],
        Value::from(u64::MAX),
        "the integer repair must not reach a position the schema types as free form",
    );
}

#[test]
fn page_argument_digest_excludes_page_and_sorts_nested_objects() {
    let first = json!({
        "schema_version": MCP_TOOL_ARGS_SCHEMA_VERSION,
        "arguments": { "outer": { "b": 2, "a": [ { "z": true, "y": false } ] } },
    });
    let second = json!({
        "arguments": { "outer": { "a": [ { "y": false, "z": true } ], "b": 2 } },
        "schema_version": MCP_TOOL_ARGS_SCHEMA_VERSION,
        "page": { "limit": 1, "forceful_override": true, "cursor": "mcpc1:any" },
    });
    assert_eq!(
        mcp_page_argument_digest(&first),
        mcp_page_argument_digest(&second),
        "page and recursive object insertion order are not query identity",
    );
    let changed = json!({
        "schema_version": MCP_TOOL_ARGS_SCHEMA_VERSION,
        "arguments": { "outer": { "b": 3, "a": [ { "z": true, "y": false } ] } },
    });
    assert_ne!(
        mcp_page_argument_digest(&first),
        mcp_page_argument_digest(&changed),
        "a producer-query value remains bound",
    );
}

/// ONE-1704 repair: `tasks.create` refuses a label the engine's board row
/// ceiling could not render, at the WRITER, before anything is persisted.
///
/// The generated schema and the runtime admission previously accepted any
/// nonblank label, so a label just over `MAX_BOARD_ROW_BYTES` could be stored
/// and then make the rendered intent row — and with it the whole TASKS section
/// — unrenderable for every later reader of that board.
#[test]
fn tasks_create_label_is_bounded_by_the_board_row_ceiling() {
    use oneiron::context_board::{TASK_LABEL_MAX_BYTES, TASK_ROW_FIXED_TOKEN_BYTES};
    // One limit system: the bound IS the engine's row ceiling less the fixed
    // tokens the rendered row adds beside the label.
    assert_eq!(
        TASK_LABEL_MAX_BYTES + TASK_ROW_FIXED_TOKEN_BYTES,
        oneiron::context_board::MAX_BOARD_ROW_BYTES,
        "the label ceiling is derived from the row ceiling, not invented beside it",
    );

    let create = registered_surface(McpSurfaceMode::ToolFirst)
        .resolve("tasks.create")
        .expect("tasks.create is registered");
    let args_with_label = |label: &str| {
        let mut args = endpoint_envelope("write_tasks");
        args["arguments"] = json!({ "spec": { "kind": "review" }, "label": label });
        args
    };
    let decode = |label: &str| {
        validate_mcp_endpoint_tool_args(create, McpToolArguments::from(args_with_label(label)))
    };

    // The advertised closed schema states the same ceiling, so a caller learns
    // it from `tools/list` rather than from a refusal.
    let schema = create.schema().input_schema;
    assert_eq!(
        schema["properties"]["arguments"]["properties"]["label"]["maxLength"],
        Value::from(TASK_LABEL_MAX_BYTES),
    );

    // Exactly at the boundary: admitted, and carried through unchanged.
    let boundary = "x".repeat(TASK_LABEL_MAX_BYTES);
    let McpValidatedToolArgs::Verb(verb) =
        decode(&boundary).expect("a label exactly at the ceiling is admitted")
    else {
        panic!("tasks.create decodes to a verb payload");
    };
    assert_eq!(
        verb.payload.arguments.label.as_deref(),
        Some(boundary.as_str()),
        "the boundary label reaches the writer unchanged",
    );

    // One byte over: the established typed argument error, on the label's own
    // field, before any facade is reached.
    let over = "x".repeat(TASK_LABEL_MAX_BYTES + 1);
    let error = decode(&over).expect_err("a label one byte over the ceiling is refused");
    assert!(
        matches!(
            &error,
            McpToolValidationError::Field { tool, field, .. }
                if *tool == "tasks.create" && *field == "arguments.label"
        ),
        "the refusal names the label field: {error}",
    );

    // The bound is on BYTES because the row ceiling is: a multi-byte label
    // inside the advertised code-point ceiling is still refused here.
    let multibyte = "é".repeat(TASK_LABEL_MAX_BYTES / 2 + 1);
    assert!(
        multibyte.chars().count() <= TASK_LABEL_MAX_BYTES,
        "the multi-byte case is inside the advertised code-point ceiling",
    );
    assert!(multibyte.len() > TASK_LABEL_MAX_BYTES);
    decode(&multibyte).expect_err("a multi-byte label over the byte ceiling is refused");

    // Every ordinary label an actual caller writes is untouched, and a blank
    // one keeps its settled refusal.
    let McpValidatedToolArgs::Verb(verb) =
        decode("review the draft").expect("an ordinary label is admitted")
    else {
        panic!("tasks.create decodes to a verb payload");
    };
    assert_eq!(
        verb.payload.arguments.label.as_deref(),
        Some("review the draft")
    );
    decode("   ").expect_err("a blank label keeps its settled refusal");
}

#[test]
fn nullable_integer_spec_field_accepts_an_integral_float() {
    let tool = registered_surface(McpSurfaceMode::ToolFirst)
        .resolve("tasks.ask")
        .expect("tasks.ask is registered");
    let args = endpoint_census_args(tool);
    let raw = raw_args_with_number(&args, "/arguments/spec/until", "1.0e9");
    let McpValidatedToolArgs::Verb(decoded) =
        validate_mcp_endpoint_tool_args(tool, McpToolArguments::from_raw_json(raw))
            .expect("nullable integral float is admitted")
    else {
        panic!("tasks.ask decodes to a verb payload");
    };
    let spec: oneiron::task_verb::TaskAskSpec =
        serde_json::from_value(decoded.payload.arguments.spec.expect("spec"))
            .expect("typed ask spec");
    assert_eq!(spec.until, Some(1_000_000_000));

    let mut parsed = args;
    parsed["arguments"]["spec"]["until"] = json!(1.0e9);
    let McpValidatedToolArgs::Verb(decoded) =
        validate_mcp_endpoint_tool_args(tool, parsed).expect("parsed integral float is admitted")
    else {
        panic!("tasks.ask decodes to a verb payload");
    };
    let spec: oneiron::task_verb::TaskAskSpec =
        serde_json::from_value(decoded.payload.arguments.spec.expect("spec"))
            .expect("typed ask spec");
    assert_eq!(spec.until, Some(1_000_000_000));
}

#[test]
fn advertised_turn_ref_default_validates_against_its_own_schema() {
    let tool = registered_surface(McpSurfaceMode::ToolFirst)
        .resolve("rooms.messages")
        .expect("rooms.messages is listed");
    let schema = tool.schema().input_schema;
    let turn_ref = &schema["properties"]["arguments"]["properties"]["turn_ref"];
    assert_eq!(turn_ref["default"], Value::Null);
    assert!(
        turn_ref["type"]
            .as_array()
            .expect("nullable type")
            .contains(&json!("null"))
    );
    assert_eq!(turn_ref["pattern"], super::tool_catalog::ENTITY_ID_PATTERN);
    let mut args = endpoint_census_args(tool);
    args["arguments"]["turn_ref"] = Value::Null;
    assert!(validate_mcp_endpoint_tool_args(tool, args).is_ok());
}

#[test]
fn envelope_constraints_survive_a_non_object_typed_schema() {
    let merged = super::endpoint_schema::merge_verb_argument_schema(
        Value::Bool(true),
        json!({ "type": "string", "pattern": super::tool_catalog::ENTITY_ID_PATTERN }),
    );
    assert_eq!(merged["allOf"][0], true);
    assert_eq!(
        merged["allOf"][1]["pattern"],
        super::tool_catalog::ENTITY_ID_PATTERN
    );
}

#[test]
fn a_dollar_row_with_no_schema_is_not_advertised() {
    assert!(
        oneiron::task_verb::sdk::mcp_arguments_schema_from_input("tasks.ask", &Value::Bool(false))
            .is_none()
    );
}

#[test]
fn agent_verb_schemas_follow_manifest_inputs_and_argument_paths() {
    let manifest: Value =
        serde_json::from_str(include_str!("../../../../scripts/sdk/agent-verbs.json"))
            .expect("manifest");
    let surface = McpRegisteredSurface::register(McpSurfaceMode::ToolFirst).expect("surface");
    for row in manifest["verbs"].as_array().expect("verb rows") {
        let name = row["name"].as_str().expect("verb name");
        if row["context"] == "definition" {
            assert!(oneiron::task_verb::sdk::AgentVerb::from_name(name).is_none());
            assert!(surface.resolve(name).is_none());
            continue;
        }
        let input = oneiron::task_verb::sdk::input_schema(name).expect("input schema");
        if name == "tasks.ask" {
            let branches = input["anyOf"]
                .as_array()
                .expect("rich and short ask branches");
            assert_eq!(branches.len(), 2);
            let rich = branches
                .iter()
                .find(|branch| {
                    branch["required"]
                        .as_array()
                        .is_some_and(|fields| fields.contains(&json!("intent_key")))
                })
                .expect("rich");
            let short = branches
                .iter()
                .find(|branch| {
                    branch["required"]
                        .as_array()
                        .is_some_and(|fields| !fields.contains(&json!("intent_key")))
                })
                .expect("short");
            for branch in [rich, short] {
                assert_eq!(branch["type"], "object");
                assert_eq!(branch["additionalProperties"], false);
                assert!(
                    branch["required"]
                        .as_array()
                        .unwrap()
                        .contains(&json!("what"))
                );
            }
            assert!(short["properties"].get("intent_key").is_none());
        } else {
            assert_eq!(input["type"], "object", "{name}");
        }
        // ARCH-0028: every callable row is a tool; no row carries an opt-out.
        assert!(row.get("mcp").is_none(), "{name} curates the tool list");
        let tool = surface
            .resolve(name)
            .unwrap_or_else(|| panic!("{name} is not projected"));
        let schema = tool.schema().input_schema;
        let arguments = &schema["properties"]["arguments"];
        let projected = oneiron::task_verb::sdk::mcp_arguments_schema(name).expect("arguments");
        assert_eq!(arguments["required"], projected["required"], "{name}");
        assert_eq!(arguments["additionalProperties"], false, "{name}");
        // A row that names no projection takes its whole input as `spec`.
        let default_fields = json!({"spec": "$"});
        let fields = row.get("mcp_fields").unwrap_or(&default_fields);
        for (field, path) in fields.as_object().expect("argument paths") {
            let path = path.as_str().expect("path");
            let pointer = if path == "$" {
                String::new()
            } else {
                path.trim_start_matches('=')
                    .split('.')
                    .map(|part| format!("/properties/{part}"))
                    .collect()
            };
            let expected = input.pointer(&pointer).expect("typed input field");
            assert_eq!(&projected["properties"][field], expected, "{name}.{field}");
            let shipped = &arguments["properties"][field];
            if let Some(properties) = expected.as_object() {
                for (key, value) in properties {
                    if key == "type" && value.is_array() && shipped[key] != *value {
                        assert!(value.as_array().expect("types").contains(&shipped[key]));
                    } else {
                        // Schemars stores numeric bounds as f64; the envelope
                        // publishes exact integers. Compare their values, not
                        // the spelling, without rounding through another f64.
                        let expected = if matches!(key.as_str(), "minimum" | "maximum") {
                            super::codec::schema_normalized_arguments(
                                &json!({"type": "integer"}),
                                value.clone().into(),
                            )
                            .expect("numeric schema bound")
                        } else {
                            value.clone()
                        };
                        assert_eq!(shipped[key], expected, "{name}.{field}.{key}");
                    }
                }
            } else {
                assert_eq!(shipped, expected, "{name}.{field}");
            }
        }
    }
    let ask = oneiron::task_verb::sdk::input_schema("tasks.ask").unwrap();
    let question =
        json!({"reference":{"turn": ACTOR_ID},"revision":1,"options":{},"context_refs":[]});
    let short = json!({"what":question,"who":{"people":[ACTOR_ID]}});
    let rich = json!({"intent_key":"rich-collect","what":question,"decide":null});
    for value in [&short, &rich] {
        assert!(draft2020_12_accepts(ask, value));
        assert!(
            serde_json::from_value::<oneiron::task_verb::sdk::TaskAskRequest>(value.clone())
                .is_ok()
        );
    }
    for invalid in [
        json!({"who":{"people":[ACTOR_ID]}}),
        json!({"intent_key":"rich-no-question"}),
        json!({"what":question,"decide":null}),
        json!({"what":question,"need":{"count":1,"of":"any"}}),
        json!({"what":question,"on_disagree":{"branch":"hold","surface":"card"}}),
    ] {
        assert!(!draft2020_12_accepts(ask, &invalid));
        assert!(
            serde_json::from_value::<oneiron::task_verb::sdk::TaskAskRequest>(invalid).is_err()
        );
    }
    assert!(oneiron::task_verb::sdk::input_schema("tasks.missing").is_none());
    assert!(oneiron::task_verb::sdk::mcp_arguments_schema("tasks.missing").is_none());
}
