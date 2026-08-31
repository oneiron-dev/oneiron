use super::*;
use serde::Deserialize;

const ACTOR_ID: &str = "11111111111111111111111111111111";
const RESULT_ID: &str = "77777777777777777777777777777777";

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

#[test]
fn mcp_tool_schema_serializes_protocol_input_schema_field() {
    let schema =
        serde_json::to_value(mcp_tool_schema(McpToolName::Read)).expect("schema serializes");

    assert!(schema.get("inputSchema").is_some());
    assert!(schema.get("input_schema").is_none());
}

#[test]
fn mcp_tool_schemas_are_closed_and_versioned() {
    let schemas = mcp_tool_schemas();
    assert_eq!(schemas.len(), McpToolName::all().len());

    for schema in schemas {
        let root = &schema.input_schema;
        assert_eq!(root["$schema"], MCP_SCHEMA_DRAFT);
        assert_eq!(root["type"], "object");
        assert_eq!(root["additionalProperties"], false);
        assert_eq!(
            root["properties"]["schema_version"]["const"],
            MCP_TOOL_ARGS_SCHEMA_VERSION
        );
        assert!(
            root["required"]
                .as_array()
                .expect("required is an array")
                .contains(&Value::String("schema_version".to_owned())),
            "{} must require schema_version",
            schema.name
        );
        assert_closed_object_schemas(root, schema.name);
    }
}

/// The retired plain-verb validators still preserve every metadata field they
/// ever did.
///
/// The fixture rows that used to carry these payloads are gone with the wire
/// surface (ONE-1704 M1), so the SAME assertions are made directly here: the
/// private adapter's argument decoding did not lose an axis when its wire name
/// did.
#[test]
fn legacy_ask_arguments_preserve_context_pack_and_consent_metadata() {
    let context_pack = json!({
        "schema_version": MCP_CONTEXT_PACK_REF_SCHEMA_VERSION,
        "context_version": "v4",
        "pack_ref": "context-pack:one-1215",
        "retrieval_run_id": "retrieval:one-1215",
        "result_ids": [RESULT_ID],
        "budget_ref": "budget:standard",
    });
    let consent = json!({
        "policy_ref": "policy:foreign-mcp",
        "purpose": "answer_question",
        "approval_ref": "approval:one-1215",
        "consent_receipt_ref": "consent:one-1215",
        "require_human_approval": false,
    });

    let ask = json!({
        "schema_version": MCP_TOOL_ARGS_SCHEMA_VERSION,
        "actor": actor_json(),
        "context_pack": context_pack.clone(),
        "consent": consent.clone(),
        "query": "what is the launch plan?",
    });
    let McpValidatedToolArgs::Ask(ask) = validate_mcp_tool_args(McpToolName::Ask, ask)
        .expect("ask arguments validate")
    else {
        panic!("oneiron.ask must validate into the Ask arm");
    };
    assert_eq!(ask.actor.actor_ref, ACTOR_ID);
    assert_eq!(ask.context_pack.result_ids, vec![RESULT_ID.to_owned()]);
    assert_eq!(ask.consent.approval_ref.as_deref(), Some("approval:one-1215"));
    assert_eq!(
        ask.consent.consent_receipt_ref.as_deref(),
        Some("consent:one-1215")
    );

    let routed = json!({
        "schema_version": MCP_TOOL_ARGS_SCHEMA_VERSION,
        "actor": actor_json(),
        "context_pack": context_pack,
        "consent": consent,
        "query": "what is the launch plan?",
        "route": { "model_tier": "routed-small" },
    });
    let McpValidatedToolArgs::RoutedAsk(routed) =
        validate_mcp_tool_args(McpToolName::RoutedAsk, routed)
            .expect("routed ask arguments validate")
    else {
        panic!("oneiron.ask_routed must validate into the RoutedAsk arm");
    };
    assert_eq!(routed.actor.actor_ref, ACTOR_ID);
    assert_eq!(routed.context_pack.result_ids, vec![RESULT_ID.to_owned()]);
    assert_eq!(
        routed.consent.approval_ref.as_deref(),
        Some("approval:one-1215")
    );
    assert_eq!(
        routed.consent.consent_receipt_ref.as_deref(),
        Some("consent:one-1215")
    );
    assert_eq!(routed.route.model_tier, "routed-small");
}

#[test]
fn mcp_tool_schemas_express_preflight_shape_invariants() {
    let actor = actor_schema();
    assert_eq!(actor["oneOf"].as_array().expect("actor oneOf").len(), 2);

    let context_pack = context_pack_ref_schema();
    assert_eq!(
        context_pack["anyOf"]
            .as_array()
            .expect("context-pack handle anyOf")
            .len(),
        3
    );
    assert_eq!(
        context_pack["properties"]["pack_ref"]["pattern"],
        Value::String("\\S".to_owned())
    );

    let read_target = read_target_schema();
    assert_eq!(
        read_target["oneOf"]
            .as_array()
            .expect("read target selector oneOf")
            .len(),
        3
    );
    assert_eq!(
        read_target["properties"]["short_ref"]["pattern"],
        Value::String(SHORT_REF_PATTERN.to_owned())
    );

    let edit = edit_tool_schema();
    let edit_verbs = edit["allOf"]
        .as_array()
        .expect("edit verb-specific constraints")
        .iter()
        .map(|branch| {
            branch["if"]["properties"]["verb"]["const"]
                .as_str()
                .expect("verb const")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        edit_verbs,
        vec![
            "propose_claim",
            "attest_edge_provenance",
            "supersede_claim",
            "retract_claim",
            "propose_entity",
            "post_task",
            "report_task",
            "channel_send"
        ]
    );
    let attest_branch = &edit["allOf"]
        .as_array()
        .expect("edit verb-specific constraints")[1];
    assert_eq!(
        attest_branch["then"]["properties"]["subject"]["required"],
        json!(["edge"])
    );
    assert_eq!(
        attest_branch["then"]["properties"]["subject"]["properties"]["edge"]["properties"]["kind"]
            ["minimum"],
        Value::from(9)
    );
}

#[test]
fn edit_accepts_exact_canonical_write_verbs() {
    let base = || {
        json!({
            "schema_version": MCP_TOOL_ARGS_SCHEMA_VERSION,
            "actor": actor_json(),
            "consent": consent_json("write_memory"),
            "idempotency_key": "mcp-test-canonical-verb",
        })
    };
    let cases = [
        json!({
            "verb": "propose_claim",
            "subject": { "entity": ACTOR_ID },
            "predicate": "profile.fixture",
            "value": true,
            "confidence": 0.8,
        }),
        json!({
            "verb": "attest_edge_provenance",
            "subject": {
                "edge": {
                    "source": ACTOR_ID,
                    "kind": 9,
                    "target": RESULT_ID
                }
            },
            "confidence": 0.8,
        }),
        json!({
            "verb": "supersede_claim",
            "old_claim_id": RESULT_ID,
            "predicate": "profile.fixture",
            "value": "updated",
            "confidence": 0.8,
        }),
        json!({
            "verb": "retract_claim",
            "claim_id": RESULT_ID,
            "reason": "user_retraction",
        }),
        json!({
            "verb": "propose_entity",
            "entity_type": 1,
            "occurred": { "start": 10, "end": 10 },
            "data": { "txt": "fixture" },
        }),
        json!({
            "verb": "post_task",
            "brief": {
                "objective": "fixture",
                "intent": "test validation",
                "constraints": [],
                "success_criteria": ["accepted"],
                "escalation_rule": "none"
            },
        }),
        json!({
            "verb": "report_task",
            "job_id": "job:fixture",
            "outcome": "succeeded",
            "summary": "done",
        }),
        json!({
            "verb": "channel_send",
            "channel": "fixture",
            "payload": { "txt": "hello" },
        }),
    ];

    for case in cases {
        let mut args = base();
        args.as_object_mut()
            .expect("base args object")
            .extend(case.as_object().expect("case object").clone());
        validate_mcp_tool_args(McpToolName::Edit, args)
            .expect("canonical edit verb should validate");
    }
}

#[test]
fn read_target_context_pack_errors_use_nested_field() {
    let error = validate_mcp_tool_args(
        McpToolName::Read,
        json!({
            "schema_version": MCP_TOOL_ARGS_SCHEMA_VERSION,
            "actor": {
                "actor_ref": ACTOR_ID,
                "actor_class": "agent",
                "gate_actor_class": "agent",
                "gate_actor_ref": ACTOR_ID,
                "scope": {},
            },
            "consent": {
                "policy_ref": "policy:foreign-mcp",
                "purpose": "read_context",
            },
            "target": {
                "context_pack": {
                    "schema_version": "context_pack_ref.v2",
                    "pack_ref": "context-pack:one-1215",
                },
            },
        }),
    )
    .expect_err("invalid nested context-pack version should fail");

    assert!(
        error
            .to_string()
            .starts_with("oneiron.read.target.context_pack:"),
        "{error}"
    );
}

#[test]
fn read_target_short_ref_uses_hydrate_parser_shape() {
    let error = validate_mcp_tool_args(
        McpToolName::Read,
        json!({
            "schema_version": MCP_TOOL_ARGS_SCHEMA_VERSION,
            "actor": actor_json(),
            "consent": consent_json("read_context"),
            "target": {
                "short_ref": "not-a-ref",
            },
        }),
    )
    .expect_err("invalid short ref should fail before hydrate");

    assert!(
        error.to_string().contains("shortId:contentHashHex"),
        "{error}"
    );

    validate_mcp_tool_args(
        McpToolName::Read,
        json!({
            "schema_version": MCP_TOOL_ARGS_SCHEMA_VERSION,
            "actor": actor_json(),
            "consent": consent_json("read_context"),
            "target": {
                "short_ref": "ab123:4f",
            },
        }),
    )
    .expect("hydrate-shaped short ref should validate");
}

#[test]
fn edit_rejects_legacy_remember_verb() {
    let error = validate_mcp_tool_args(
        McpToolName::Edit,
        json!({
            "schema_version": MCP_TOOL_ARGS_SCHEMA_VERSION,
            "actor": actor_json(),
            "consent": consent_json("write_memory"),
            "verb": "remember",
            "idempotency_key": "mcp-test-legacy-remember",
            "subject": { "entity": ACTOR_ID },
            "predicate": "profile.legacy",
            "value": true,
            "confidence": 0.9,
        }),
    )
    .expect_err("legacy remember verb should fail");

    assert!(error.to_string().contains("unknown variant"), "{error}");
}

#[test]
fn propose_entity_rejects_impossible_occurrence_range() {
    let error = validate_mcp_tool_args(
        McpToolName::Edit,
        json!({
            "schema_version": MCP_TOOL_ARGS_SCHEMA_VERSION,
            "actor": actor_json(),
            "consent": consent_json("write_memory"),
            "verb": "propose_entity",
            "idempotency_key": "mcp-test-impossible-range",
            "entity_type": 1,
            "occurred": { "start": 20, "end": 10 },
            "data": {
                "txt": "Impossible range"
            },
        }),
    )
    .expect_err("start greater than end should fail");

    assert!(
        error
            .to_string()
            .contains("occurred.start: must be less than or equal"),
        "{error}"
    );
}

#[test]
fn decode_errors_describe_schema_shape_not_json_syntax() {
    let error = validate_mcp_tool_args(
        McpToolName::Ask,
        json!({ "schema_version": MCP_TOOL_ARGS_SCHEMA_VERSION }),
    )
    .expect_err("missing required fields should fail decode");

    let message = error.to_string();
    assert!(message.contains("not valid for the tool schema"));
    assert!(!message.contains("not valid JSON"));
}

fn assert_closed_object_schemas(value: &Value, path: &str) {
    match value {
        Value::Object(map) => {
            if matches!(map.get("type"), Some(Value::String(kind)) if kind == "object") {
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

fn calendar_args(operation: Value) -> Value {
    json!({
        "schema_version": MCP_TOOL_ARGS_SCHEMA_VERSION,
        "actor": actor_json(),
        "consent": consent_json("read_calendar"),
        "operation": operation,
    })
}

#[test]
fn oneiron_calendar_schema_is_closed_and_op_specific() {
    let catalog = mcp_tool_schemas();
    assert_eq!(
        catalog
            .iter()
            .filter(|schema| schema.name == "oneiron.calendar")
            .count(),
        1,
        "the catalog carries exactly one calendar tool"
    );
    assert_eq!(
        McpToolName::Calendar.operations(),
        &["read", "search", "freebusy", "invite"],
        "the operation set is closed at exactly four ops"
    );

    let schema = mcp_tool_schema(McpToolName::Calendar).input_schema;
    let branches = schema["properties"]["operation"]["oneOf"]
        .as_array()
        .expect("operation branches");
    let ops = branches
        .iter()
        .map(|branch| {
            branch["properties"]["op"]["const"]
                .as_str()
                .expect("op const")
        })
        .collect::<Vec<_>>();
    assert_eq!(ops, McpToolName::Calendar.operations());

    let invite = branches.last().expect("invite branch");
    assert_eq!(
        invite["required"],
        json!([
            "op",
            "method",
            "uid",
            "sequence",
            "ics_blob_ref",
            "recipient"
        ]),
        "the invite arm requires C7's exact typed payload, not an outbound draft"
    );
    assert_eq!(
        invite["properties"]["method"]["enum"],
        json!(["REQUEST", "CANCEL"])
    );

    // Every accepted op decodes; nothing outside the set does.
    for operation in [
        json!({ "op": "read", "event_ref": RESULT_ID }),
        json!({ "op": "search", "text": "review", "limit": 5 }),
        json!({ "op": "freebusy", "range": { "start": 10, "end": 20 } }),
        json!({
            "op": "invite",
            "method": "REQUEST",
            "uid": "uid-1",
            "sequence": 0,
            "ics_blob_ref": "blob:one-1791",
            "recipient": "guest@example.test",
        }),
    ] {
        validate_mcp_tool_args(McpToolName::Calendar, calendar_args(operation))
            .expect("closed calendar op validates");
    }

    for rejected in [
        // Unknown op.
        json!({ "op": "delete", "event_ref": RESULT_ID }),
        // Field from another arm.
        json!({ "op": "read", "event_ref": RESULT_ID, "range": { "start": 1, "end": 2 } }),
        // Missing invite field.
        json!({
            "op": "invite",
            "method": "REQUEST",
            "uid": "uid-1",
            "sequence": 0,
            "recipient": "guest@example.test",
        }),
        // An outbound draft is not an invite payload.
        json!({
            "op": "invite",
            "verb": "send",
            "channel": "email",
            "target": "guest@example.test",
        }),
        // Method outside REQUEST|CANCEL.
        json!({
            "op": "invite",
            "method": "REPLY",
            "uid": "uid-1",
            "sequence": 0,
            "ics_blob_ref": "blob:one-1791",
            "recipient": "guest@example.test",
        }),
        // Malformed ref and range.
        json!({ "op": "read", "event_ref": "not-an-entity-id" }),
        json!({ "op": "freebusy", "range": { "start": 20, "end": 10 } }),
    ] {
        assert!(
            validate_mcp_tool_args(McpToolName::Calendar, calendar_args(rejected.clone())).is_err(),
            "calendar op must be rejected: {rejected}"
        );
    }
}

#[test]
fn mcp_tool_catalog_stays_closed_over_seven_tools() {
    let names = McpToolName::all()
        .iter()
        .map(|tool| tool.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec![
            "oneiron.nav",
            "oneiron.read",
            "oneiron.edit",
            "oneiron.ask",
            "oneiron.ask_routed",
            "oneiron.calendar",
            "oneiron.book",
        ]
    );
    for name in &names {
        assert_eq!(
            McpToolName::from_name(name).map(McpToolName::as_str),
            Some(*name),
            "{name} round-trips through the closed catalog"
        );
    }
    // The catalog grows by ratified tool, never by guess: a plausible-looking
    // name that no ticket owns must still fail to resolve.
    for absent in ["oneiron.booking", "oneiron.book.hold", "oneiron.schedule"] {
        assert!(
            McpToolName::from_name(absent).is_none(),
            "{absent} must not resolve to a tool"
        );
    }
}

#[test]
fn owner_key_resolves_to_human_gate_actor_identity() {
    let owner = id(0xA001);
    let mut registry = registry();
    registry
        .register(
            "owner-key",
            McpConnectorActorRecord::new(
                owner,
                EdgeActorClass::Human,
                McpConnectorScope::vault_wide(),
            ),
        )
        .expect("owner key registration succeeds");

    let resolved = registry
        .resolve(
            "owner-key",
            10,
            actor_ceiling_for(EdgeActorClass::Human, owner),
        )
        .expect("owner resolves");

    assert_eq!(resolved.actor_ref, owner);
    assert_eq!(resolved.actor_class, EdgeActorClass::Human);
    assert_eq!(resolved.gate_actor_class, "human");
    assert_eq!(resolved.gate_actor_ref, owner.to_hex());
    assert_eq!(resolved.scope, McpConnectorScope::vault_wide());
    assert_eq!(
        resolved.write_actor(),
        WriteActor::new(owner, EdgeActorClass::Human)
    );
}

#[test]
fn connector_key_resolves_to_agent_identity_and_scope() {
    let connector = id(0xB001);
    let world = id(0xB002);
    let facet = id(0xB003);
    let mut registry = registry();
    registry
        .register(
            "connector-key",
            McpConnectorActorRecord::new(
                connector,
                EdgeActorClass::Agent,
                McpConnectorScope::scoped(Some(world), Some(facet)),
            )
            .with_expiry(20),
        )
        .expect("connector key registration succeeds");

    let resolved = registry
        .resolve(
            "connector-key",
            19,
            actor_ceiling_for(EdgeActorClass::Agent, connector),
        )
        .expect("connector resolves before expiry");

    assert_eq!(resolved.actor_ref, connector);
    assert_eq!(resolved.gate_actor_class, "agent");
    assert_eq!(resolved.gate_actor_ref, connector.to_hex());
    assert_eq!(
        resolved.scope,
        McpConnectorScope::scoped(Some(world), Some(facet))
    );
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
fn double_revoke_preserves_original_timestamp() {
    let mut registry = registry();
    registry
        .register(
            "connector-key",
            McpConnectorActorRecord::new(
                id(0xF201),
                EdgeActorClass::Agent,
                McpConnectorScope::vault_wide(),
            ),
        )
        .expect("registration succeeds");

    assert_eq!(
        registry.revoke("connector-key", 12),
        Ok(McpConnectorActorRevokeStatus::Revoked)
    );
    assert_eq!(
        registry.revoke("connector-key", 99),
        Ok(McpConnectorActorRevokeStatus::AlreadyRevoked { revoked_at: 12 })
    );
}

#[test]
fn prune_and_unregister_remove_stale_credentials() {
    let mut registry = registry();
    registry
        .register(
            "expired-key",
            McpConnectorActorRecord::new(
                id(0xF301),
                EdgeActorClass::Agent,
                McpConnectorScope::vault_wide(),
            )
            .with_expiry(10),
        )
        .expect("expired key registration succeeds");
    registry
        .register(
            "revoked-key",
            McpConnectorActorRecord::new(
                id(0xF302),
                EdgeActorClass::Agent,
                McpConnectorScope::vault_wide(),
            )
            .with_revoked_at(11),
        )
        .expect("revoked key registration succeeds");
    registry
        .register(
            "active-key",
            McpConnectorActorRecord::new(
                id(0xF303),
                EdgeActorClass::Agent,
                McpConnectorScope::vault_wide(),
            ),
        )
        .expect("active key registration succeeds");

    assert_eq!(registry.prune_revoked_or_expired(11), 2);
    assert_eq!(registry.len(), 1);
    assert!(registry.unregister(" active-key "));
    assert!(registry.is_empty());
}

#[test]
fn resolved_actor_exposes_only_gate_actor_identity_not_authority() {
    let actor = id(0xF401);
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

    let resolved = registry
        .resolve(
            "connector-key",
            10,
            actor_ceiling_for(EdgeActorClass::Agent, actor),
        )
        .expect("connector resolves");

    assert_eq!(resolved.gate_actor_class, "agent");
    assert_eq!(resolved.gate_actor_ref, actor.to_hex());
    assert_eq!(
        resolved.write_actor(),
        WriteActor::new(actor, EdgeActorClass::Agent)
    );
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

// ── ONE-1936: explicit lifecycle-target mapping per verb ─────────────────

fn edit_args(case: Value) -> McpEditToolArgs {
    let mut args = json!({
        "schema_version": MCP_TOOL_ARGS_SCHEMA_VERSION,
        "actor": actor_json(),
        "consent": consent_json("write_memory"),
        "idempotency_key": "mcp-test-lifecycle-target",
    });
    args.as_object_mut()
        .expect("base args object")
        .extend(case.as_object().expect("case object").clone());
    let McpValidatedToolArgs::Edit(args) =
        validate_mcp_tool_args(McpToolName::Edit, args).expect("edit args validate")
    else {
        panic!("oneiron.edit must validate into edit args");
    };
    *args
}

#[test]
fn lifecycle_target_ref_maps_each_write_verb_to_its_named_field() {
    // supersede_claim → old_claim_id.
    assert_eq!(
        edit_args(json!({
            "verb": "supersede_claim",
            "old_claim_id": RESULT_ID,
            "predicate": "profile.fixture",
            "value": "updated",
            "confidence": 0.8,
        }))
        .lifecycle_target_ref(),
        Some(RESULT_ID)
    );

    // retract_claim → claim_id.
    assert_eq!(
        edit_args(json!({
            "verb": "retract_claim",
            "claim_id": RESULT_ID,
            "reason": "user_retraction",
        }))
        .lifecycle_target_ref(),
        Some(RESULT_ID)
    );

    // Replacement-style attest → old_claim_id, now admitted by the schema.
    assert_eq!(
        edit_args(json!({
            "verb": "attest_edge_provenance",
            "subject": { "edge": { "source": ACTOR_ID, "kind": 9, "target": RESULT_ID } },
            "old_claim_id": ACTOR_ID,
            "confidence": 0.8,
        }))
        .lifecycle_target_ref(),
        Some(ACTOR_ID)
    );

    // A FIRST attestation names no prior, so it has no lifecycle target.
    assert_eq!(
        edit_args(json!({
            "verb": "attest_edge_provenance",
            "subject": { "edge": { "source": ACTOR_ID, "kind": 9, "target": RESULT_ID } },
            "confidence": 0.8,
        }))
        .lifecycle_target_ref(),
        None
    );

    // Verbs that propose something new never carry one.
    assert_eq!(
        edit_args(json!({
            "verb": "propose_claim",
            "subject": { "entity": ACTOR_ID },
            "predicate": "profile.fixture",
            "value": true,
            "confidence": 0.8,
        }))
        .lifecycle_target_ref(),
        None
    );
}

#[test]
fn attest_old_claim_id_is_validated_as_an_entity_ref() {
    let error = validate_mcp_tool_args(
        McpToolName::Edit,
        json!({
            "schema_version": MCP_TOOL_ARGS_SCHEMA_VERSION,
            "actor": actor_json(),
            "consent": consent_json("write_memory"),
            "idempotency_key": "mcp-test-attest-bad-prior",
            "verb": "attest_edge_provenance",
            "subject": { "edge": { "source": ACTOR_ID, "kind": 9, "target": RESULT_ID } },
            "old_claim_id": "not-an-entity-ref",
            "confidence": 0.8,
        }),
    )
    .expect_err("a malformed prior ref must be rejected at validation");
    assert!(
        error.to_string().starts_with("oneiron.edit.old_claim_id:"),
        "{error}"
    );
}

#[test]
fn attest_schema_branch_admits_old_claim_id() {
    let edit = edit_tool_schema();
    let attest_branch = &edit["allOf"]
        .as_array()
        .expect("edit verb-specific constraints")[1];
    let forbidden = attest_branch["then"]["not"]["anyOf"]
        .as_array()
        .expect("attest forbidden list")
        .iter()
        .filter_map(|entry| entry["required"][0].as_str())
        .collect::<Vec<_>>();
    assert!(
        !forbidden.contains(&"old_claim_id"),
        "replacement-style attestation must be allowed to name its prior: {forbidden:?}"
    );
}

// ─── ONE-1930: short-ref parsing at the MCP boundary ───

/// Every short-ref case the MCP validator accepts or rejects, and why.
///
/// The prefix is no longer pinned at exactly two letters — `validate_short_ref_parts`
/// delegates to `oneiron::parse_presentation_id`, so a longer prefix is a
/// well-formed ref that fails later at RESOLUTION rather than at the boundary.
/// The two-letter FLOOR stays: `session_overlay.rs` mints room aliases as
/// `s<digits>` and they must not parse as durable ids.
const SHORT_REF_CASES: &[(&str, bool)] = &[
    ("ab123:4f", true),
    ("mc4:0a", true),
    ("sm3:FF", true),
    ("vt5:00", true),
    // Undeclared prefix: syntactically fine, resolves to nothing later.
    ("zz9:a3", true),
    // Longer prefixes parse now; the old hand-rolled slice rejected them.
    ("abcd12:a3", true),
    // Session-overlay room alias — must stay outside the durable grammar.
    ("s1:a3", false),
    ("not-a-ref", false),
    ("ab:4f", false),    // missing digits
    ("AB123:4f", false), // uppercase prefix
    ("ab123:4", false),  // one hex digit
    ("ab123:zz", false), // non-hex content hash
    ("ab123", false),    // no content hash
];

#[test]
fn short_ref_validation_follows_the_shared_presentation_grammar() {
    for (reference, expected_valid) in SHORT_REF_CASES {
        let result = validate_mcp_tool_args(
            McpToolName::Read,
            json!({
                "schema_version": MCP_TOOL_ARGS_SCHEMA_VERSION,
                "actor": actor_json(),
                "consent": consent_json("read_context"),
                "target": { "short_ref": reference },
            }),
        );
        assert_eq!(
            result.is_ok(),
            *expected_valid,
            "short ref {reference:?}: {result:?}"
        );
    }
}

/// The advertised JSON-schema pattern and the validator must admit the same
/// refs, or clients pre-reject ids the server would have accepted.
#[test]
fn short_ref_schema_pattern_matches_the_validator() {
    /// Minimal matcher for the one pattern shape this schema uses:
    /// `^[a-z]{2,}[0-9]+:[0-9A-Fa-f]{2}$`.
    fn pattern_matches(reference: &str) -> bool {
        assert_eq!(
            SHORT_REF_PATTERN, "^[a-z]{2,}[0-9]+:[0-9A-Fa-f]{2}$",
            "this matcher models exactly one pattern; update both together"
        );
        let Some((short_id, hash)) = reference.split_once(':') else {
            return false;
        };
        let letters = short_id.bytes().take_while(u8::is_ascii_lowercase).count();
        let digits = &short_id[letters..];
        letters >= 2
            && !digits.is_empty()
            && digits.bytes().all(|byte| byte.is_ascii_digit())
            && hash.len() == 2
            && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
    }

    for (reference, expected_valid) in SHORT_REF_CASES {
        assert_eq!(
            pattern_matches(reference),
            *expected_valid,
            "schema pattern disagrees with the validator on {reference:?}"
        );
    }
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
fn primary_endpoint_registers_exactly_two_sorted_tools() {
    let surface = registered_surface(McpSurfaceMode::Primary);
    assert_eq!(surface.mode(), McpSurfaceMode::Primary);
    assert_eq!(surface.tool_names(), vec!["execute_code", "setup_oneiron"]);

    let mut sorted = surface.tool_names();
    sorted.sort_unstable();
    assert_eq!(surface.tool_names(), sorted, "the listing ships sorted");

    // No plain verb, board verb, or task verb is REGISTERED on the primary
    // endpoint, whatever schemas exist in this process.
    for name in surface.tool_names() {
        assert!(!name.starts_with("oneiron."), "{name} must not be listed");
        assert!(!name.starts_with("board."), "{name} must not be listed");
        assert!(!name.starts_with("tasks."), "{name} must not be listed");
    }
}

#[test]
fn tool_first_endpoint_is_generated_from_the_exported_verb_rows() {
    let surface = registered_surface(McpSurfaceMode::ToolFirst);
    let mut expected = exported_verb_rows();
    expected.sort_unstable();
    assert_eq!(surface.tool_names(), expected);
    assert_eq!(
        expected.len(),
        oneiron::board_verb::BOARD_VERBS.len() + oneiron::task_verb::TASKS_VERBS.len(),
    );

    // Every registered tool IS a projection of a row: nothing hand-written.
    for tool in surface.tools() {
        let McpEndpointTool::Verb(verb) = tool else {
            panic!("{} is not generated from a verb row", tool.name());
        };
        assert!(expected.contains(&verb.name));
        assert_eq!(format!("{}.{}", verb.family.as_str(), verb.verb), verb.name);
    }
}

#[test]
fn duplicate_and_unprojectable_verb_rows_fail_construction() {
    assert_eq!(
        project_verb_rows(&["board.expand", "board.expand"]),
        Err(McpSurfaceConstructionError::DuplicateVerbRow {
            row: "board.expand"
        }),
    );
    for row in ["boardexpand", "board.", "board.expand.deep", "ledger.post"] {
        assert_eq!(
            project_verb_rows(&[row]),
            Err(McpSurfaceConstructionError::UnprojectableVerbRow { row }),
            "{row} must not project onto a tool",
        );
    }
    // The shipped table itself projects cleanly, which is why registration of
    // the tool-first endpoint cannot fail in production.
    assert!(generated_verb_tools().is_ok());
}

#[test]
fn a_tool_registered_on_one_endpoint_is_unknown_on_the_other() {
    let primary = registered_surface(McpSurfaceMode::Primary);
    let tool_first = registered_surface(McpSurfaceMode::ToolFirst);

    for name in tool_first.tool_names() {
        assert!(
            primary.resolve(name).is_none(),
            "{name} must not resolve on the primary endpoint",
        );
    }
    for name in primary.tool_names() {
        assert!(
            tool_first.resolve(name).is_none(),
            "{name} must not resolve on the tool-first endpoint",
        );
    }
    // Their schemas nonetheless exist in this process.
    assert!(tool_first.resolve("board.expand").is_some());
    assert!(primary.resolve(MCP_SETUP_TOOL).is_some());
}

#[test]
fn endpoint_listings_are_frozen_and_carry_no_actor_material() {
    for mode in McpSurfaceMode::ALL {
        let registered = registered_surface(mode);
        let frozen = serde_json::to_string(registered.listing()).expect("listing serializes");
        // A second, independently constructed registration of the same mode
        // produces the same bytes: nothing per-caller can reach the listing.
        let rebuilt = serde_json::to_string(
            McpRegisteredSurface::register(mode)
                .expect("mode registers")
                .listing(),
        )
        .expect("listing serializes");
        assert_eq!(frozen, rebuilt, "{} listing is not frozen", mode.as_str());
        assert!(
            !frozen.contains(ACTOR_ID),
            "{} listing names an actor",
            mode.as_str(),
        );
        assert!(
            !frozen.contains("connector"),
            "{} listing echoes credential material",
            mode.as_str(),
        );
    }
    assert_ne!(
        serde_json::to_string(registered_surface(McpSurfaceMode::Primary).listing())
            .expect("listing serializes"),
        serde_json::to_string(registered_surface(McpSurfaceMode::ToolFirst).listing())
            .expect("listing serializes"),
        "the two endpoints are distinct surfaces",
    );
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

#[test]
fn endpoint_args_reject_unknown_fields_everywhere() {
    let setup = registered_surface(McpSurfaceMode::Primary)
        .resolve(MCP_SETUP_TOOL)
        .expect("setup is registered");
    let mut args = endpoint_envelope("read_board");
    args["surface_mode"] = Value::String("tool_first".to_owned());
    assert!(
        validate_mcp_endpoint_tool_args(setup, args).is_err(),
        "no request field may name or select a surface mode",
    );
}

#[test]
fn setup_payload_carries_keyframe_grammar_and_instructions() {
    let verbs = generated_verb_tools().expect("verb rows project");
    let section = mcp_verb_board_section(&verbs).expect("VERBS section is valid");
    let header = BoardBlockHeader {
        epoch: 12,
        scope: mcp_effective_scope_label(&McpConnectorScope::vault_wide()),
    };
    let payload = mcp_setup_payload(
        &header,
        std::slice::from_ref(&section),
        BoardBudgetRequest {
            harness_default_tok: MCP_BOARD_BUDGET_TOK,
            caller_limit_tok: Some(64),
            explicit_override_tok: None,
        },
    )
    .expect("setup payload assembles");

    assert_eq!(payload.board.epoch, 12);
    assert!(payload.board.text.contains("legend:"));
    assert_eq!(payload.verb_grammar, verbs);
    assert_eq!(payload.instructions, MCP_SETUP_INSTRUCTIONS);

    // A caller can NARROW the board budget; the render metadata rides through
    // losslessly, `floor_exceeds_cap` included.
    assert_eq!(payload.board.metadata.budget_tok, 64);
    let value = payload.to_value();
    assert_eq!(value["board"]["render"]["budget_tok"], 64);
    assert_eq!(
        value["board"]["render"]["floor_exceeds_cap"],
        Value::Bool(payload.board.metadata.floor_exceeds_cap),
    );
    assert_eq!(
        value["board"]["render"]["budget_source"]["kind"],
        "adaptive_min"
    );
    assert_eq!(
        value["verb_grammar"]["schema_version"],
        MCP_VERB_GRAMMAR_SCHEMA_VERSION,
    );
    assert_eq!(
        value["verb_grammar"]["verbs"].as_array().map(Vec::len),
        Some(verbs.len()),
    );
    assert_eq!(value["instructions"], MCP_SETUP_INSTRUCTIONS);
}

#[test]
fn result_metadata_states_scope_health_end_and_refuses_cache() {
    let scope = McpConnectorScope::scoped(Some(id(0xC001)), None);
    let metadata = McpResultMetadata::new(
        "req-1",
        McpSurfaceMode::Primary,
        scope.clone(),
        McpRetrievalHealth::Degraded,
        McpPageBudget::resolve(
            Some(McpPageRequest {
                limit: Some(4),
                forceful_override: false,
            }),
            McpPageSource::complete(2),
        ),
        vec!["ask for a smaller page".to_owned()],
        Some(McpCacheHint {
            ttl_ms: Some(86_400_000),
        }),
    );
    let value = metadata.to_value();

    assert_eq!(value["schema_version"], MCP_RESULT_META_SCHEMA_VERSION);
    assert_eq!(value["request_id"], "req-1");
    assert_eq!(value["surface_mode"], "primary");
    assert_eq!(value["retrieval_health"], "degraded");
    assert_eq!(value["end"], "Complete");
    assert_eq!(value["page"]["granted"], 4);
    assert_eq!(value["page"]["returned"], 2);
    assert_eq!(value["help"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        value["effective_scope"],
        mcp_effective_scope_value(&scope),
        "the effective scope travels with the result",
    );
    // A foreign TTL never widens ours.
    assert_eq!(value["ttlMs"], MCP_RESULT_TTL_MS);
    assert_eq!(value["cacheScope"], MCP_RESULT_CACHE_SCOPE);
}

#[test]
fn adaptive_page_budget_narrows_and_marks_a_full_page_as_more() {
    let page = |limit: Option<u32>, forced: bool, source: McpPageSource| {
        McpPageBudget::resolve(
            limit.map(|limit| McpPageRequest {
                limit: Some(limit),
                forceful_override: forced,
            }),
            source,
        )
    };

    let uncapped = page(None, false, McpPageSource::complete(3));
    assert_eq!(uncapped.granted, MCP_PAGE_ITEM_CAP);
    assert_eq!(uncapped.end(), McpResultEnd::Complete);
    assert_eq!(uncapped.cursor, None);

    let over_ceiling = page(
        Some(MCP_PAGE_ITEM_CAP + 500),
        false,
        McpPageSource::complete(1),
    );
    assert_eq!(over_ceiling.granted, MCP_PAGE_ITEM_CAP);
    assert!(!over_ceiling.forceful_override_honoured);

    // A caller cannot grow its own budget by asking; only an explicit forceful
    // override can, and the record says it did.
    let forced = page(
        Some(MCP_PAGE_ITEM_CAP + 500),
        true,
        McpPageSource::complete(1),
    );
    assert_eq!(forced.granted, MCP_PAGE_ITEM_CAP + 500);
    assert!(forced.forceful_override_honoured);

    // A FULL page that hides a successor is `More` and carries a cursor: the
    // budget capped four produced rows down to two.
    let full = page(Some(2), false, McpPageSource::complete(4));
    assert_eq!(full.granted, 2);
    assert_eq!(full.returned, 2);
    assert_eq!(full.hidden, 2);
    assert_eq!(full.end(), McpResultEnd::More);
    assert!(
        full.cursor
            .as_deref()
            .is_some_and(|cursor| cursor.starts_with("mcpc1:")),
        "a non-terminal page carries an opaque successor: {full:?}",
    );
    assert_eq!(full.cap(vec![json!(1), json!(2), json!(3), json!(4)]).len(), 2);

    // An exactly-full page from an EXHAUSTED producer hides nothing and is
    // stated Complete rather than inferred.
    let exact = page(Some(2), false, McpPageSource::complete(2));
    assert_eq!(exact.end(), McpResultEnd::Complete);
    assert_eq!(exact.cursor, None);

    // An EMPTY terminal page still states Complete explicitly.
    let empty = page(Some(5), false, McpPageSource::complete(0));
    assert_eq!(empty.returned, 0);
    assert_eq!(empty.end(), McpResultEnd::Complete);

    // Producer-side truncation can never be reported Complete or Healthy.
    let capped_scan = page(None, false, McpPageSource::truncated(3, 0, false));
    assert_eq!(capped_scan.end(), McpResultEnd::More);
    assert!(capped_scan.cursor.is_some());
    assert_eq!(
        McpPageSource::truncated(3, 0, false).health(),
        McpRetrievalHealth::Degraded,
    );
    assert_eq!(
        McpPageSource::truncated(3, 2, true).health(),
        McpRetrievalHealth::Partial,
    );
    assert_eq!(
        McpPageSource::complete(3).health(),
        McpRetrievalHealth::Healthy,
    );
}

#[test]
fn foreign_ttl_never_widens_the_endpoint_cache_policy() {
    for foreign in [None, Some(0), Some(1), Some(u64::MAX)] {
        assert_eq!(
            clamp_foreign_cache_ttl_ms(foreign),
            MCP_RESULT_TTL_MS,
            "a foreign ttl of {foreign:?} must not widen ours",
        );
    }
}

#[test]
fn every_structured_error_code_carries_recovery_suggestions() {
    for code in [
        "unknown_tool",
        "tool_args_invalid",
        "mcp_actor_mismatch",
        "mcp_auth_required",
        "mcp_credential_unknown",
        "mcp_credential_expired",
        "mcp_credential_revoked",
        "mcp_actor_ceiling_missing",
        "scoped_mcp_grant_required",
        "board_render_failed",
        "verb_dispatch_failed",
        "an_error_code_no_one_has_minted_yet",
    ] {
        let suggestions = mcp_recovery_suggestions(code);
        assert!(!suggestions.is_empty(), "{code} carries no recovery path");
        for suggestion in &suggestions {
            assert!(
                !suggestion.trim().is_empty(),
                "{code} has a blank suggestion"
            );
        }
    }
}

/// ONE-1704 M1: the seven retired plain-verb names are registered on NEITHER
/// endpoint, and the frozen listings are unchanged by their retirement.
#[test]
fn legacy_plain_verb_names_are_unregistered_on_both_endpoints() {
    let legacy = McpToolName::all()
        .iter()
        .map(|tool| tool.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        legacy,
        vec![
            "oneiron.nav",
            "oneiron.read",
            "oneiron.edit",
            "oneiron.ask",
            "oneiron.ask_routed",
            "oneiron.calendar",
            "oneiron.book",
        ],
        "the retired census is exactly these seven names",
    );

    for mode in McpSurfaceMode::ALL {
        let surface = registered_surface(mode);
        let names = surface.tool_names();
        let listing = serde_json::to_string(surface.listing()).expect("listing serializes");
        for name in &legacy {
            assert!(
                surface.resolve(name).is_none(),
                "{name} must not resolve on the {} endpoint",
                mode.as_str(),
            );
            assert!(
                !names.contains(name),
                "{name} must not be listed on the {} endpoint",
                mode.as_str(),
            );
            assert!(
                !listing.contains(name),
                "{name} must not appear anywhere in the {} listing bytes",
                mode.as_str(),
            );
        }
    }

    // The frozen listings themselves are unchanged by the retirement.
    assert_eq!(
        registered_surface(McpSurfaceMode::Primary).tool_names(),
        vec!["execute_code", "setup_oneiron"],
    );
    let mut generated = exported_verb_rows();
    generated.sort_unstable();
    assert_eq!(
        registered_surface(McpSurfaceMode::ToolFirst).tool_names(),
        generated,
    );
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
    match verb.binding {
        McpVerbBinding::BoardExpand => json!({ "key": "TASKS" }),
        McpVerbBinding::BoardRefresh | McpVerbBinding::TasksCheck => json!({}),
        McpVerbBinding::BoardSubscribe | McpVerbBinding::BoardUnsubscribe => {
            json!({ "scopes": ["my_tasks"] })
        }
        McpVerbBinding::TasksAck | McpVerbBinding::TasksCancel | McpVerbBinding::TasksExpand => {
            json!({ "task_ref": ACTOR_ID })
        }
        McpVerbBinding::TasksCreate => json!({ "spec": { "kind": "review" } }),
    }
}

/// ONE-1704 M6: `page.limit` is refused at every runtime door that advertises
/// `minimum: 1`, and the advertised `required` array is EXACTLY what the
/// decoder refuses to do without — an exhaustive, two-sided census over every
/// registered tool on both endpoints.
#[test]
fn page_limit_zero_rejected_and_schema_decoder_agree() {
    let mut audited = 0_usize;
    for mode in McpSurfaceMode::ALL {
        for tool in registered_surface(mode).tools() {
            let tool = *tool;
            let schema = tool.schema().input_schema;
            let name = tool.name();

            // Every registered tool advertises the same page grammar, and its
            // runtime door agrees that zero is out of it.
            assert_eq!(
                schema["properties"]["page"]["properties"]["limit"]["minimum"],
                Value::from(1),
                "{name} must advertise the page floor",
            );
            let mut zero_page = endpoint_census_args(tool);
            zero_page["page"] = json!({ "limit": 0 });
            let refusal = validate_mcp_endpoint_tool_args(tool, zero_page)
                .expect_err("a zero page must be refused at the runtime door");
            assert!(
                matches!(&refusal, McpToolValidationError::Field { field, .. } if *field == "page.limit"),
                "{name} refused a zero page for the wrong reason: {refusal}",
            );

            // The advertised closed schema and the decoder accept the same
            // payloads: a property the schema calls required must be one the
            // decoder refuses to do without, and one it does not must be one
            // the decoder still accepts without.
            let required = schema["required"]
                .as_array()
                .expect("every tool advertises a required array")
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .expect("required names are strings")
                        .to_owned()
                })
                .collect::<Vec<_>>();
            let properties = schema["properties"]
                .as_object()
                .expect("every tool advertises properties")
                .clone();
            let full = endpoint_census_args(tool);
            validate_mcp_endpoint_tool_args(tool, full.clone())
                .unwrap_or_else(|error| panic!("{name} census payload must validate: {error}"));

            for property in properties.keys() {
                let mut narrowed = full.clone();
                narrowed
                    .as_object_mut()
                    .expect("census args are an object")
                    .remove(property);
                let decoder_accepts = validate_mcp_endpoint_tool_args(tool, narrowed).is_ok();
                assert_eq!(
                    decoder_accepts,
                    !required.contains(property),
                    "{name}: advertised required {required:?} disagrees with the decoder on \
                     {property}",
                );
                audited += 1;
            }
        }
    }
    // Both endpoints, every registered tool, every advertised property.
    assert!(audited >= 60, "the census must stay exhaustive: {audited}");
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
        assert!(
            registry.stream_connection_attached("stream-key"),
            "{lifecycle}: state must exist before teardown",
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
    }
}

#[test]
fn a_setup_keyframe_supersedes_frames_queued_behind_it() {
    let actor = id(0xE201);
    let mut registry = registry();
    registry
        .register(
            "carrier-key",
            McpConnectorActorRecord::new(
                actor,
                EdgeActorClass::Agent,
                McpConnectorScope::vault_wide(),
            ),
        )
        .expect("registers");
    let resolved = registry
        .resolve(
            "carrier-key",
            1,
            actor_ceiling_for(EdgeActorClass::Agent, actor),
        )
        .expect("connector resolves");
    let connection = &resolved.stream_connection;

    registry.enqueue_stream_frame(
        connection,
        oneiron::context_board::BoardStreamFrame {
            epoch: 7,
            kind: oneiron::context_board::FrameKind::Keyframe("older".to_owned()),
        },
    );
    registry.enqueue_stream_frame(
        connection,
        oneiron::context_board::BoardStreamFrame {
            epoch: 7,
            kind: oneiron::context_board::FrameKind::Delta(vec![
                oneiron::context_board::DeltaRow {
                    key: "TASKS:0".to_owned(),
                    line: "queued".to_owned(),
                },
            ]),
        },
    );
    // The fresh setup keyframe replaces the epoch and clears what was queued.
    registry.enqueue_stream_frame(
        connection,
        oneiron::context_board::BoardStreamFrame {
            epoch: 8,
            kind: oneiron::context_board::FrameKind::Keyframe("fresh".to_owned()),
        },
    );

    let drained = registry
        .next_carrier_frame(connection)
        .expect("one coalesced frame");
    assert_eq!(drained.epoch, 8);
    assert_eq!(
        drained.kind,
        oneiron::context_board::FrameKind::Keyframe("fresh".to_owned()),
    );
    // AT MOST ONE carrier per result: the lane is empty behind it.
    assert!(registry.next_carrier_frame(connection).is_none());
}
