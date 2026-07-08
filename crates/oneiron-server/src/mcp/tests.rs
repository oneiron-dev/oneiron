use super::*;
use serde::Deserialize;

const ACTOR_ID: &str = "11111111111111111111111111111111";
const RESULT_ID: &str = "77777777777777777777777777777777";

#[derive(Debug, Deserialize)]
struct McpToolValidationFixture {
    cases: Vec<McpToolValidationFixtureCase>,
}

#[derive(Debug, Deserialize)]
struct McpToolValidationFixtureCase {
    name: String,
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

#[test]
fn mcp_tool_validation_fixtures_gate_args_before_execution() {
    let fixture: McpToolValidationFixture = serde_json::from_str(include_str!(
        "../../tests/fixtures/mcp_tool_args.validation.json"
    ))
    .expect("fixture should parse");

    for case in fixture.cases {
        let tool = McpToolName::from_name(&case.tool)
            .unwrap_or_else(|| panic!("{} names a known tool", case.name));
        let result = validate_mcp_tool_args(tool, case.args);
        if case.valid {
            let validated = result.unwrap_or_else(|error| {
                panic!("{} should validate but failed: {error}", case.name)
            });
            assert_fixture_preserved_metadata(&case.name, &validated);
        } else {
            assert!(result.is_err(), "{} should fail validation", case.name);
        }
    }
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

fn assert_fixture_preserved_metadata(name: &str, validated: &McpValidatedToolArgs) {
    match validated {
        McpValidatedToolArgs::Ask(args) => {
            assert_eq!(args.actor.actor_ref, ACTOR_ID, "{name} actor_ref");
            assert_eq!(
                args.context_pack.result_ids,
                vec![RESULT_ID.to_owned()],
                "{name} results"
            );
            assert_eq!(
                args.consent.approval_ref.as_deref(),
                Some("approval:one-1215"),
                "{name} approval"
            );
            assert_eq!(
                args.consent.consent_receipt_ref.as_deref(),
                Some("consent:one-1215"),
                "{name} consent receipt"
            );
        }
        McpValidatedToolArgs::RoutedAsk(args) => {
            assert_eq!(args.actor.actor_ref, ACTOR_ID, "{name} actor_ref");
            assert_eq!(
                args.context_pack.result_ids,
                vec![RESULT_ID.to_owned()],
                "{name} results"
            );
            assert_eq!(
                args.consent.approval_ref.as_deref(),
                Some("approval:one-1215"),
                "{name} approval"
            );
            assert_eq!(
                args.consent.consent_receipt_ref.as_deref(),
                Some("consent:one-1215"),
                "{name} consent receipt"
            );
            assert_eq!(args.route.model_tier, "routed-small", "{name} route");
        }
        McpValidatedToolArgs::Nav(_)
        | McpValidatedToolArgs::Read(_)
        | McpValidatedToolArgs::Edit(_) => {}
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
