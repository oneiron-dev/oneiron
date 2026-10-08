//! ONE-1819 [BK-08] MCP-side gates for `oneiron.book`.
//!
//! The tool schema, the argument validator, and the scoped-grant decision are
//! all exercised against the shipped implementation. The connector-credential
//! registry is crate-private, so the rows that need a REGISTERED credential
//! assert the gateway's wiring against its source instead of driving a
//! credential through it; every such row is marked where it appears.

// Integration-test helpers (non-`#[test]` fns) are not covered by
// allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]

use oneiron_server::mcp::{
    MCP_BOOK_OPERATIONS, MCP_TOOL_ARGS_SCHEMA_VERSION, McpToolName, mcp_tool_schema,
    mcp_tool_schemas, validate_mcp_tool_args,
};
use serde_json::{Value, json};

const ACTOR_ID: &str = "11111111111111111111111111111111";
const PAGE_TOKEN: &str = "bkp_0123456789abcdef0123456789abcdef";

fn actor_json() -> Value {
    json!({
        "actor_ref": ACTOR_ID,
        "actor_class": "agent",
        "gate_actor_class": "agent",
        "gate_actor_ref": ACTOR_ID,
        "scope": { "world_ref": null, "facet_ref": null },
    })
}

fn consent_json() -> Value {
    json!({
        "policy_ref": "policy:foreign-mcp",
        "purpose": "book_meeting",
        "approval_ref": null,
        "consent_receipt_ref": null,
        "require_human_approval": false,
    })
}

fn book_args(operation: Value) -> Value {
    json!({
        "schema_version": MCP_TOOL_ARGS_SCHEMA_VERSION,
        "actor": actor_json(),
        "consent": consent_json(),
        "page_token": PAGE_TOKEN,
        "operation": operation,
    })
}

fn availability_operation() -> Value {
    json!({
        "op": "availability",
        "input": {
            "event_type": "intro-call",
            "window": { "start": 1_000, "end": 100_000 },
            "visitor_tz": "UTC",
            "constraint": null,
            "session_ref": "sess-mcp-book",
        },
    })
}

fn confirm_operation() -> Value {
    json!({
        "op": "book",
        "input": {
            "stage": "confirm",
            "input": {
                "hold_token": "a".repeat(64),
                "booker_email": "visitor@example.com",
                "intake": [],
                "session_ref": "sess-mcp-book",
                "idempotency_key": "confirm-1",
            },
        },
    })
}

// -------------------------------------------------------------------------
// One tool, four ops
// -------------------------------------------------------------------------

#[test]
fn mcp_book_is_one_tool_four_ops() {
    let catalog = mcp_tool_schemas();
    assert_eq!(
        catalog
            .iter()
            .filter(|schema| schema.name == "oneiron.book")
            .count(),
        1,
        "the catalog carries exactly one booking tool"
    );
    // Never per-op tools.
    for schema in &catalog {
        assert!(
            !schema.name.starts_with("oneiron.book."),
            "the catalog must not mint a per-operation booking tool: {}",
            schema.name
        );
    }
    assert_eq!(
        McpToolName::Book.operations(),
        &["availability", "book", "reschedule", "cancel"],
        "the operation set is closed at exactly four ops"
    );
    assert_eq!(McpToolName::Book.as_str(), "oneiron.book");
    assert_eq!(
        McpToolName::from_name("oneiron.book"),
        Some(McpToolName::Book)
    );

    let schema = mcp_tool_schema(McpToolName::Book).input_schema;
    assert_eq!(schema["additionalProperties"], json!(false));
    assert_eq!(
        schema["properties"]["schema_version"]["const"],
        json!(MCP_TOOL_ARGS_SCHEMA_VERSION)
    );
    assert_eq!(
        schema["properties"]["page_token"]["pattern"],
        json!("^bkp_[0-9a-f]{32}$"),
        "the page handle is an opaque token, not an entity id"
    );
    let branches = schema["properties"]["operation"]["oneOf"]
        .as_array()
        .expect("operation branches");
    let ops: Vec<&str> = branches
        .iter()
        .map(|branch| branch["properties"]["op"]["const"].as_str().unwrap())
        .collect();
    assert_eq!(ops, MCP_BOOK_OPERATIONS.to_vec());

    // Every advertised op validates, and only those.
    for operation in [
        availability_operation(),
        json!({
            "op": "book",
            "input": {
                "stage": "hold",
                "input": {
                    "event_type": "intro-call",
                    "selected_slot": { "start_utc": 1_000, "end_utc": 2_800 },
                    "visitor_tz": "UTC",
                    "constraint": null,
                    "session_ref": "sess-mcp-book",
                    "checkout_lease_token": null,
                    "idempotency_key": "hold-1",
                },
            },
        }),
        confirm_operation(),
        json!({
            "op": "reschedule",
            "input": {
                "reschedule_token": "b".repeat(64),
                "selected_slot": { "start_utc": 1_000, "end_utc": 2_800 },
                "visitor_tz": "UTC",
                "idempotency_key": "rs-1",
            },
        }),
        json!({
            "op": "cancel",
            "input": { "cancel_token": "c".repeat(64), "idempotency_key": "cx-1" },
        }),
    ] {
        assert!(
            validate_mcp_tool_args(McpToolName::Book, book_args(operation.clone())).is_ok(),
            "advertised operation must validate: {operation}"
        );
    }

    // An unknown op, an unknown envelope field, and an unknown input field are
    // all rejected rather than ignored.
    let unknown_op = json!({ "op": "invite", "input": {} });
    assert!(validate_mcp_tool_args(McpToolName::Book, book_args(unknown_op)).is_err());

    let mut widened = book_args(availability_operation());
    widened
        .as_object_mut()
        .unwrap()
        .insert("smuggled".to_owned(), json!(1));
    assert!(validate_mcp_tool_args(McpToolName::Book, widened).is_err());

    let mut smuggled_input = availability_operation();
    smuggled_input["input"]
        .as_object_mut()
        .unwrap()
        .insert("page_ref".to_owned(), json!(ACTOR_ID));
    assert!(
        validate_mcp_tool_args(McpToolName::Book, book_args(smuggled_input)).is_err(),
        "an internal reference cannot be smuggled into a booking input"
    );

    // The wrong schema version is refused.
    let mut stale = book_args(availability_operation());
    stale
        .as_object_mut()
        .unwrap()
        .insert("schema_version".to_owned(), json!("mcp_tool_args.v0"));
    assert!(validate_mcp_tool_args(McpToolName::Book, stale).is_err());
}
