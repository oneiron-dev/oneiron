//! ONE-1819 [BK-08] `oneiron.book` MCP tool — catalog and argument validation.
//!
//! The seam this pins is ownership: the closed catalog grows exactly ONE
//! BK-owned tool with a schema-validated four-op discriminator, CAL-09's
//! `oneiron.calendar` keeps its own single-tool/four-op shape untouched, and
//! strict argument validation happens in `crate::mcp` — before the gateway
//! resolves an actor, before any scoped-grant check, and long before the shared
//! booking executor runs.

// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]

use oneiron_server::mcp::{
    MCP_BOOK_OPERATIONS, MCP_CALENDAR_OPERATIONS, MCP_TOOL_ARGS_SCHEMA_VERSION, McpToolName,
    McpValidatedToolArgs, mcp_tool_schemas, validate_mcp_tool_args,
};
use serde_json::{Value, json};

const ACTOR_ID: &str = "11111111111111111111111111111111";
const PAGE_TOKEN: &str = "bp7:c4";

fn actor_json() -> Value {
    json!({
        "actor_ref": ACTOR_ID,
        "actor_class": "agent",
        "gate_actor_class": "agent",
        "gate_actor_ref": ACTOR_ID,
        "scope": {},
    })
}

fn book_args(operation: Value) -> Value {
    json!({
        "schema_version": MCP_TOOL_ARGS_SCHEMA_VERSION,
        "actor": actor_json(),
        "consent": {
            "policy_ref": "policy:foreign-mcp",
            "purpose": "book_meeting",
        },
        "operation": operation,
    })
}

fn availability_operation() -> Value {
    json!({
        "op": "availability",
        "page_token": PAGE_TOKEN,
        "input": {
            "event_type": "intro",
            "window": { "start": 1_800_000_000_u64, "end": 1_800_600_000_u64 },
            "visitor_tz": "Europe/Warsaw",
            "constraint": null,
            "session_ref": "visitor-session-1",
        },
    })
}

fn book_hold_operation() -> Value {
    json!({
        "op": "book",
        "page_token": PAGE_TOKEN,
        "input": {
            "stage": "hold",
            "input": {
                "event_type": "intro",
                "selected_slot": { "start_utc": 1_800_000_000_u64, "end_utc": 1_800_001_800_u64 },
                "visitor_tz": "Europe/Warsaw",
                "constraint": null,
                "session_ref": "visitor-session-1",
                "checkout_lease_token": null,
                "idempotency_key": "idem-hold-1",
            },
        },
    })
}

fn book_confirm_operation() -> Value {
    json!({
        "op": "book",
        "page_token": PAGE_TOKEN,
        "input": {
            "stage": "confirm",
            "input": {
                "hold_token": "hold-token-1",
                "booker_email": "visitor@example.com",
                "intake": [{ "field_key": "topic", "value": "intro call" }],
                "session_ref": "visitor-session-1",
                "idempotency_key": "idem-confirm-1",
            },
        },
    })
}

fn reschedule_operation() -> Value {
    json!({
        "op": "reschedule",
        "page_token": PAGE_TOKEN,
        "input": {
            "reschedule_token": "rs-token-1",
            "selected_slot": { "start_utc": 1_800_003_600_u64, "end_utc": 1_800_005_400_u64 },
            "visitor_tz": "Europe/Warsaw",
            "idempotency_key": "idem-reschedule-1",
        },
    })
}

fn cancel_operation() -> Value {
    json!({
        "op": "cancel",
        "page_token": PAGE_TOKEN,
        "input": {
            "cancel_token": "cx-token-1",
            "idempotency_key": "idem-cancel-1",
        },
    })
}

/// One tool, four ops — never four tools.
#[test]
fn mcp_book_is_one_tool_four_ops() {
    let names = McpToolName::all()
        .iter()
        .map(|tool| tool.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        names.iter().filter(|name| **name == "oneiron.book").count(),
        1,
        "exactly one booking tool must exist: {names:?}"
    );
    for absent in [
        "oneiron.book.availability",
        "oneiron.booking",
        "oneiron.availability",
        "oneiron.reschedule",
        "oneiron.cancel",
    ] {
        assert!(
            McpToolName::from_name(absent).is_none(),
            "{absent} must not resolve to a tool"
        );
    }

    assert_eq!(
        McpToolName::Book.operations().to_vec(),
        vec!["availability", "book", "reschedule", "cancel"],
        "the booking op set is closed and ordered"
    );
    assert_eq!(
        McpToolName::Book.operations().to_vec(),
        MCP_BOOK_OPERATIONS.to_vec()
    );
    assert_eq!(
        McpToolName::from_name("oneiron.book"),
        Some(McpToolName::Book)
    );

    // The advertised schema is the one tool's schema, and it is closed.
    let schemas = mcp_tool_schemas();
    let book = schemas
        .iter()
        .find(|schema| schema.name == "oneiron.book")
        .expect("tools/list advertises oneiron.book");
    assert_eq!(book.input_schema["type"], "object");
    assert_eq!(book.input_schema["additionalProperties"], false);
    assert_eq!(
        book.input_schema["properties"]["schema_version"]["const"],
        MCP_TOOL_ARGS_SCHEMA_VERSION
    );
    let branches = book.input_schema["properties"]["operation"]["oneOf"]
        .as_array()
        .expect("the operation schema is a closed union");
    assert_eq!(branches.len(), 4, "one closed branch per operation");
    let advertised = branches
        .iter()
        .map(|branch| {
            branch["properties"]["op"]["const"]
                .as_str()
                .expect("each branch pins its op")
        })
        .collect::<Vec<_>>();
    assert_eq!(advertised, ["availability", "book", "reschedule", "cancel"]);
    for branch in branches {
        assert_eq!(branch["additionalProperties"], false);
    }
}

/// CAL-09 keeps its tool: this diff adds `Book` branches and changes no
/// calendar behaviour.
#[test]
fn mcp_book_preserves_calendar_tool_ownership() {
    assert_eq!(
        McpToolName::from_name("oneiron.calendar"),
        Some(McpToolName::Calendar)
    );
    assert_eq!(
        McpToolName::Calendar.operations().to_vec(),
        vec!["read", "search", "freebusy", "invite"]
    );
    assert_eq!(
        McpToolName::Calendar.operations().to_vec(),
        MCP_CALENDAR_OPERATIONS.to_vec()
    );
    assert!(
        mcp_tool_schemas()
            .iter()
            .any(|schema| schema.name == "oneiron.calendar"),
        "the calendar tool must stay advertised"
    );
}

/// Every operation validates, carries the asserted actor forward, and reports
/// its own discriminator.
#[test]
fn mcp_book_accepts_every_operation_and_preserves_actor() {
    use oneiron::booking::agent_api::BookingAgentOperation;

    for (operation, expected_op, expected) in [
        (
            availability_operation(),
            "availability",
            BookingAgentOperation::Availability,
        ),
        (book_hold_operation(), "book", BookingAgentOperation::Book),
        (book_confirm_operation(), "book", BookingAgentOperation::Book),
        (
            reschedule_operation(),
            "reschedule",
            BookingAgentOperation::Reschedule,
        ),
        (cancel_operation(), "cancel", BookingAgentOperation::Cancel),
    ] {
        let validated = validate_mcp_tool_args(McpToolName::Book, book_args(operation))
            .unwrap_or_else(|error| panic!("{expected_op} should validate: {error}"));
        let McpValidatedToolArgs::Book(args) = validated else {
            panic!("{expected_op} must validate into the Book arm");
        };
        assert_eq!(args.actor().actor_ref, ACTOR_ID, "{expected_op} actor_ref");
        assert_eq!(args.operation.op(), expected_op);
        assert_eq!(args.operation(), expected);
        assert_eq!(args.page_token(), PAGE_TOKEN);
    }
}

/// Unknown ops, unknown fields, cross-arm payloads, and a wrong schema version
/// all fail closed.
#[test]
fn mcp_book_rejects_unknown_ops_and_fields() {
    // Unknown operation.
    assert!(
        validate_mcp_tool_args(
            McpToolName::Book,
            book_args(json!({ "op": "freebusy", "page_token": PAGE_TOKEN, "input": {} })),
        )
        .is_err(),
        "an operation outside the closed set must fail"
    );

    // Unknown field at the tool root.
    let mut args = book_args(availability_operation());
    args["surprise"] = json!(true);
    assert!(
        validate_mcp_tool_args(McpToolName::Book, args).is_err(),
        "an unknown root field must fail"
    );

    // Unknown field inside an operation arm.
    let mut operation = availability_operation();
    operation["ttl_secs"] = json!(600);
    assert!(
        validate_mcp_tool_args(McpToolName::Book, book_args(operation)).is_err(),
        "an unknown operation field must fail"
    );

    // A caller-supplied hold TTL has no field to arrive in.
    let mut operation = book_hold_operation();
    operation["input"]["input"]["ttl_secs"] = json!(3600);
    assert!(
        validate_mcp_tool_args(McpToolName::Book, book_args(operation)).is_err(),
        "a hold TTL must have no field to arrive in"
    );

    // Cancel payload smuggled into a reschedule arm.
    let mut operation = reschedule_operation();
    operation["input"]["cancel_token"] = json!("cx-token-1");
    assert!(
        validate_mcp_tool_args(McpToolName::Book, book_args(operation)).is_err(),
        "a cross-arm field must fail"
    );

    // Wrong tool-args schema version.
    let mut args = book_args(cancel_operation());
    args["schema_version"] = json!("mcp_tool_args.v0");
    assert!(
        validate_mcp_tool_args(McpToolName::Book, args).is_err(),
        "an unsupported schema version must fail"
    );
}

/// Public booking handles are opaque. An internal entity id is refused as a
/// page token AND as an action-scoped token, on the MCP door exactly as on the
/// HTTP one.
#[test]
fn mcp_book_refuses_entity_ids_as_public_tokens() {
    let entity_id = "7e0000000000000000000000000000aa";

    let mut operation = availability_operation();
    operation["page_token"] = json!(entity_id);
    assert!(
        validate_mcp_tool_args(McpToolName::Book, book_args(operation)).is_err(),
        "an entity id must not be accepted as a page token"
    );

    let mut operation = cancel_operation();
    operation["input"]["cancel_token"] = json!(entity_id);
    assert!(
        validate_mcp_tool_args(McpToolName::Book, book_args(operation)).is_err(),
        "an entity id must not be accepted as a cancel token"
    );

    let mut operation = reschedule_operation();
    operation["input"]["reschedule_token"] = json!(entity_id);
    assert!(
        validate_mcp_tool_args(McpToolName::Book, book_args(operation)).is_err(),
        "an entity id must not be accepted as a reschedule token"
    );
}

/// Structural refusals that must not reach the shared executor: an inverted
/// slot, an inverted window, and a blank caller key.
#[test]
fn mcp_book_rejects_structurally_impossible_requests() {
    let mut operation = book_hold_operation();
    operation["input"]["input"]["selected_slot"] =
        json!({ "start_utc": 1_800_001_800_u64, "end_utc": 1_800_000_000_u64 });
    assert!(
        validate_mcp_tool_args(McpToolName::Book, book_args(operation)).is_err(),
        "an inverted slot must fail"
    );

    let mut operation = availability_operation();
    operation["input"]["window"] = json!({ "start": 1_800_600_000_u64, "end": 1_800_000_000_u64 });
    assert!(
        validate_mcp_tool_args(McpToolName::Book, book_args(operation)).is_err(),
        "an inverted window must fail"
    );

    let mut operation = availability_operation();
    operation["input"]["session_ref"] = json!("   ");
    assert!(
        validate_mcp_tool_args(McpToolName::Book, book_args(operation)).is_err(),
        "a blank session_ref must fail"
    );

    let mut operation = cancel_operation();
    operation["input"]["idempotency_key"] = json!("");
    assert!(
        validate_mcp_tool_args(McpToolName::Book, book_args(operation)).is_err(),
        "a blank idempotency key must fail"
    );
}
