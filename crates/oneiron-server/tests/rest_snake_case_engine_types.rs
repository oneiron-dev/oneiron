//! Engine-crate types inside the server's HTTP bodies, and Oneiron's own MCP
//! tool arguments, use the engine's snake_case field names, and no camelCase
//! spelling of a renamed field is read on input (Engine RULING 15 Nov 21:00
//! under UC02-REST-SNAKE-SCOPE = A; UC-02-TS-FIELD-NAMES = A).
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --features oneiron/test-support --test
//! rest_snake_case_engine_types`.

use oneiron_server::mcp::{
    MCP_INVOKE_ACTION_TOOL, MCP_TOOL_ARGS_SCHEMA_VERSION, McpInvokeActionToolArgs, McpSurfaceMode,
    try_registered_surface_with_execution,
};
use serde_json::{Value, json};

/// `meta.empty` of an empty context-pack reply (oneiron-store `EmptyContext`)
/// names `retrieval_quality` and `total_in_scope`.
#[test]
fn empty_context_names_its_fields_in_snake_case() {
    let empty = oneiron::EmptyContext {
        retrieval_quality: Default::default(),
        reason: oneiron::EmptyReason::FilterMatchedNone,
        total_in_scope: 3,
        hint: "Try removing filters".to_owned(),
    };
    let value = serde_json::to_value(&empty).expect("serialize the empty context");
    let object = value.as_object().expect("an object");
    assert_eq!(object.get("total_in_scope"), Some(&json!(3)), "{value}");
    assert!(object.contains_key("retrieval_quality"), "{value}");
    for camel in ["totalInScope", "retrievalQuality"] {
        assert!(
            !object.contains_key(camel),
            "still names `{camel}`: {value}"
        );
    }
}

/// `invoke_action`'s arguments mirror the `POST /v1/core/actions/{verb}`
/// body: every registered listing names `idempotency_key` and `live_run`.
#[test]
fn mcp_invoke_action_schema_names_its_body_fields_in_snake_case() {
    for mode in McpSurfaceMode::ALL {
        for code_host in [false, true] {
            let surface = try_registered_surface_with_execution(mode, code_host)
                .expect("the surface registers");
            let tool = surface
                .listing()
                .as_array()
                .expect("the listing is a list")
                .iter()
                .find(|entry| entry["name"] == MCP_INVOKE_ACTION_TOOL)
                .unwrap_or_else(|| panic!("{mode:?} lists {MCP_INVOKE_ACTION_TOOL}"));
            let schema = &tool["inputSchema"];
            let properties = schema["properties"].as_object().expect("properties");
            for snake in ["idempotency_key", "live_run"] {
                assert!(
                    properties.contains_key(snake),
                    "{mode:?} names `{snake}`: {schema}"
                );
            }
            for camel in ["idempotencyKey", "liveRun"] {
                assert!(
                    !properties.contains_key(camel),
                    "{mode:?} still names `{camel}`: {schema}"
                );
            }
            let required: Vec<&str> = schema["required"]
                .as_array()
                .expect("required")
                .iter()
                .filter_map(Value::as_str)
                .collect();
            assert!(required.contains(&"idempotency_key"), "{schema}");
        }
    }
}

fn invoke_action_args(key: &str, live_run: &str) -> Value {
    json!({
        "schema_version": MCP_TOOL_ARGS_SCHEMA_VERSION,
        "actor": {
            "actor_ref": "actor:snake-case",
            "actor_class": "agent",
            "gate_actor_class": "agent",
            "gate_actor_ref": "actor:snake-case",
            "scope": {},
        },
        "consent": { "policy_ref": "policy:snake-case", "purpose": "snake_case" },
        "verb": "census.action",
        "args": [],
        key: "census-key",
        live_run: "census-live-run",
    })
}

/// The snake_case arguments decode; the camelCase spellings are unknown
/// fields and are refused.
#[test]
fn mcp_invoke_action_args_read_snake_case_and_refuse_camel_case() {
    let args: McpInvokeActionToolArgs =
        serde_json::from_value(invoke_action_args("idempotency_key", "live_run"))
            .expect("snake_case arguments decode");
    assert_eq!(args.idempotency_key, "census-key");
    assert_eq!(args.live_run.as_deref(), Some("census-live-run"));

    let refused = serde_json::from_value::<McpInvokeActionToolArgs>(invoke_action_args(
        "idempotencyKey",
        "liveRun",
    ))
    .expect_err("camelCase arguments are refused");
    assert!(
        refused
            .to_string()
            .contains("unknown field `idempotencyKey`"),
        "{refused}"
    );
}

/// A `WRONG_ROOT` refusal's correction (oneiron-contracts `MemoryWrongRoot`,
/// flattened into the REST facade error, the remote client's error body and
/// the live-query error) names `schema_ref`, and a camelCase `schemaRef` is
/// no correction on input.
#[test]
fn wrong_root_correction_names_schema_ref_in_snake_case() {
    let refusal = oneiron::memory::MemoryError::wrong_root(
        "tasks.cancel",
        "cancel",
        "oneiron:sdk/agent-verbs#cancel",
    );
    let value = serde_json::to_value(&refusal).expect("serialize the refusal");
    assert_eq!(
        value["schema_ref"],
        json!("oneiron:sdk/agent-verbs#cancel"),
        "{value}"
    );
    assert!(value.get("schemaRef").is_none(), "{value}");

    let mut camel = value.clone();
    let object = camel.as_object_mut().expect("an object");
    let schema = object.remove("schema_ref").expect("schema_ref");
    object.insert("schemaRef".to_owned(), schema);
    let decoded: oneiron::memory::MemoryError =
        serde_json::from_value(camel).expect("the refusal still decodes");
    assert!(
        decoded.wrong_root.is_none(),
        "a camelCase `schemaRef` is read as a correction: {decoded:?}"
    );
}

/// A body that is neither MessagePack nor JSON reaches the hydrate item, the
/// core query rows and the server's entity projection as its bytes under
/// `body_bytes` (oneiron `redacted_memory_body`), never `bodyBytes`.
#[test]
fn opaque_body_names_its_bytes_in_snake_case() {
    // One MessagePack value with a byte after it, and no JSON at all.
    let value = oneiron::batch::export::redacted_memory_body(&[0x01, 0x02]);
    assert_eq!(value, json!({ "body_bytes": [1, 2] }), "{value}");
}
