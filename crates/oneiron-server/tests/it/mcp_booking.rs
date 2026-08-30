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

use std::collections::BTreeSet;

use oneiron::booking::constraint::CONSTRAINT_SCHEMA_VERSION;
use oneiron::outbound_consent::{
    DataClass, ScopedMcpConsentDecision, ScopedMcpEscalationReason, evaluate_scoped_mcp_call,
};
use oneiron::outbound_grant::StandingOutboundGrantScope;
use oneiron_server::mcp::{
    MCP_BOOK_OPERATIONS, MCP_SERVER_NAME, MCP_TOOL_ARGS_SCHEMA_VERSION, McpBookToolArgs,
    McpToolName, McpValidatedToolArgs, mcp_tool_schema, mcp_tool_schemas, validate_mcp_tool_args,
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

fn decoded(operation: Value) -> McpBookToolArgs {
    match validate_mcp_tool_args(McpToolName::Book, book_args(operation)).unwrap() {
        McpValidatedToolArgs::Book(args) => *args,
        other => panic!("oneiron.book must validate into the Book arm, got {other:?}"),
    }
}

fn source(relative: &str) -> String {
    std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(relative))
        .unwrap()
}

/// A grant that authorizes exactly the endpoints named, at the ceiling named.
fn grant(tool: &str, ceiling: DataClass, endpoints: &[&str]) -> StandingOutboundGrantScope {
    StandingOutboundGrantScope::ScopedMcp {
        server: MCP_SERVER_NAME.to_owned(),
        tool: tool.to_owned(),
        data_class_ceiling: ceiling,
        endpoint_allowlist: endpoints.iter().map(|entry| (*entry).to_owned()).collect(),
    }
}

fn decide(scope: &StandingOutboundGrantScope, args: &McpBookToolArgs) -> ScopedMcpConsentDecision {
    let call = args.scoped_mcp_call();
    evaluate_scoped_mcp_call(scope.scoped_mcp_grant().unwrap(), call.as_call())
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

#[test]
fn mcp_book_actor_must_match_credential() {
    // The actor the tool claims survives validation and is exactly what the
    // gateway compares against the authenticated connector credential.
    let args = decoded(availability_operation());
    assert_eq!(args.actor().actor_ref, ACTOR_ID);
    assert_eq!(args.actor().gate_actor_ref, ACTOR_ID);

    // `mcp_validated_actor` covers the Book arm, so `ensure_mcp_actor_matches`
    // sees it; and the matcher is called once, on the shared path every tool
    // takes, before any tool executes. (The connector registry is
    // crate-private, so this is asserted on the wiring rather than driven
    // through a registered credential.)
    let gateway = source("src/api/mcp_gateway.rs");
    let actor_arms = gateway
        .split_once("pub(crate) fn mcp_validated_actor(")
        .expect("the actor extractor exists")
        .1;
    let actor_arms = &actor_arms[..actor_arms.find("\n}\n").unwrap()];
    assert!(
        actor_arms.contains("McpValidatedToolArgs::Book(args) => args.actor()"),
        "every booking op participates in actor extraction"
    );
    let call_site = gateway
        .find("ensure_mcp_actor_matches(&args, &actor)?;")
        .expect("the matcher is called on the shared tools/call path");
    let dispatch = gateway
        .find("execute_mcp_tool(server, args, &actor).await")
        .expect("dispatch follows the matcher");
    assert!(
        call_site < dispatch,
        "the actor match runs before any tool executes"
    );
    assert_eq!(
        gateway.matches("ensure_mcp_actor_matches(").count(),
        2,
        "the matcher has one definition and one call site"
    );
}

// -------------------------------------------------------------------------
// Scoped-MCP grant
// -------------------------------------------------------------------------

#[test]
fn mcp_book_requires_scoped_grant() {
    let availability = decoded(availability_operation());
    let confirm = decoded(confirm_operation());

    // The call axes are derived from the call, never asserted by the caller.
    let call = availability.scoped_mcp_call();
    assert_eq!(call.server, MCP_SERVER_NAME);
    assert_eq!(call.tool, "oneiron.book");
    assert_eq!(call.resolved_endpoint, "booking.availability");
    assert_eq!(call.payload_data_class, DataClass::Public);
    assert_eq!(
        confirm.scoped_mcp_call().payload_data_class,
        DataClass::Personal,
        "confirm names a person by email and is personal-class"
    );

    let endpoints: Vec<String> = MCP_BOOK_OPERATIONS
        .iter()
        .map(|op| format!("booking.{op}"))
        .collect();
    let endpoint_refs: Vec<&str> = endpoints.iter().map(String::as_str).collect();

    // A grant that names this server, this tool, this endpoint, and a ceiling
    // that covers the payload authorizes the call.
    let full = grant("oneiron.book", DataClass::Personal, &endpoint_refs);
    assert_eq!(
        decide(&full, &availability),
        ScopedMcpConsentDecision::AutoFire
    );
    assert_eq!(decide(&full, &confirm), ScopedMcpConsentDecision::AutoFire);

    // Wrong tool.
    let wrong_tool = grant("oneiron.calendar", DataClass::Personal, &endpoint_refs);
    assert_eq!(
        decide(&wrong_tool, &availability),
        ScopedMcpConsentDecision::Escalate(ScopedMcpEscalationReason::WrongTool)
    );

    // Wrong server.
    let wrong_server = StandingOutboundGrantScope::ScopedMcp {
        server: "someone-elses-server".to_owned(),
        tool: "oneiron.book".to_owned(),
        data_class_ceiling: DataClass::Personal,
        endpoint_allowlist: endpoints.clone(),
    };
    assert_eq!(
        decide(&wrong_server, &availability),
        ScopedMcpConsentDecision::Escalate(ScopedMcpEscalationReason::WrongServer)
    );

    // Operation not allowlisted: browsing is granted, cancelling is not.
    let browse_only = grant(
        "oneiron.book",
        DataClass::Personal,
        &["booking.availability"],
    );
    assert_eq!(
        decide(&browse_only, &availability),
        ScopedMcpConsentDecision::AutoFire
    );
    let cancel = decoded(json!({
        "op": "cancel",
        "input": { "cancel_token": "c".repeat(64), "idempotency_key": "cx-1" },
    }));
    assert_eq!(
        decide(&browse_only, &cancel),
        ScopedMcpConsentDecision::Escalate(ScopedMcpEscalationReason::EndpointNotAllowed)
    );

    // Over ceiling: a public-class grant may browse and hold, never confirm.
    let public_only = grant("oneiron.book", DataClass::Public, &endpoint_refs);
    assert_eq!(
        decide(&public_only, &availability),
        ScopedMcpConsentDecision::AutoFire
    );
    assert_eq!(
        decide(&public_only, &confirm),
        ScopedMcpConsentDecision::Escalate(ScopedMcpEscalationReason::DataClassCeilingExceeded)
    );

    // An empty allowlist is not a wildcard.
    let empty = grant("oneiron.book", DataClass::Personal, &[]);
    assert_eq!(
        decide(&empty, &availability),
        ScopedMcpConsentDecision::Escalate(ScopedMcpEscalationReason::InvalidGrant)
    );

    // The gateway requires the grant BEFORE the shared executor, performs no
    // admission pre-check, and fails closed when no grant is named.
    let gateway = source("src/api/mcp_gateway.rs");
    let book = gateway
        .split_once("pub(crate) async fn execute_mcp_book(")
        .expect("the booking dispatcher exists")
        .1;
    let book = &book[..book.find("\n}\n").unwrap()];
    let authorize = book
        .find("authorize_scoped_mcp_book(")
        .expect("the grant check runs");
    let execute = book
        .find("execute_booking_operation_for_mcp(")
        .expect("the shared executor runs");
    assert!(
        authorize < execute,
        "the scoped grant is evaluated before the shared executor"
    );
    for guard in ["enforce_slot_list", "enforce_hold", "enforce_book"] {
        assert!(
            !gateway.contains(guard),
            "the gateway must not pre-check booking admission with {guard}"
        );
    }
    assert!(
        gateway.contains("scoped-MCP grant does not exist"),
        "an absent grant fails closed"
    );
    assert!(
        gateway.contains("scoped-MCP grant is not live"),
        "a revoked grant fails closed"
    );
    assert!(
        gateway.contains("scoped-MCP grant belongs to another principal"),
        "a wrong-principal grant fails closed"
    );
}

// -------------------------------------------------------------------------
// Calendar ownership
// -------------------------------------------------------------------------

#[test]
fn mcp_book_preserves_calendar_tool_ownership() {
    // The calendar tool keeps its name, its four ops, and its schema shape.
    assert_eq!(
        McpToolName::Calendar.operations(),
        &["read", "search", "freebusy", "invite"],
        "this diff does not alter the calendar operation set"
    );
    let calendar = mcp_tool_schema(McpToolName::Calendar).input_schema;
    assert_eq!(
        calendar["$id"],
        json!("https://oneiron.local/schemas/mcp/calendar.args.v1.json")
    );
    let calendar_ops: Vec<&str> = calendar["properties"]["operation"]["oneOf"]
        .as_array()
        .unwrap()
        .iter()
        .map(|branch| branch["properties"]["op"]["const"].as_str().unwrap())
        .collect();
    assert_eq!(calendar_ops, vec!["read", "search", "freebusy", "invite"]);
    assert!(
        calendar["properties"].get("page_token").is_none(),
        "the calendar tool gained no booking field"
    );

    // The two tools share no operation vocabulary.
    let calendar_op_set: BTreeSet<&str> =
        McpToolName::Calendar.operations().iter().copied().collect();
    let book_op_set: BTreeSet<&str> = McpToolName::Book.operations().iter().copied().collect();
    assert!(
        calendar_op_set.is_disjoint(&book_op_set),
        "booking must not reuse or shadow a calendar operation"
    );

    // The booking tool has its own schema identity.
    let book = mcp_tool_schema(McpToolName::Book).input_schema;
    assert_eq!(
        book["$id"],
        json!("https://oneiron.local/schemas/mcp/book.args.v1.json")
    );
    assert_eq!(
        book["properties"]["operation"]["oneOf"]
            .as_array()
            .unwrap()
            .len(),
        4
    );

    // The gateway still dispatches calendar through its own executor, and the
    // booking arm is additive.
    let gateway = source("src/api/mcp_gateway.rs");
    assert!(
        gateway.contains(
            "McpValidatedToolArgs::Calendar(args) => execute_mcp_calendar(server, args, actor)"
        ),
        "the calendar dispatch arm is unchanged"
    );
    assert_eq!(
        gateway
            .matches("pub(crate) fn execute_mcp_calendar(")
            .count(),
        1
    );

    // The booking constraint schema is pinned to the merged constraint seam,
    // not to a second version of it.
    let constraint = &book["properties"]["operation"]["oneOf"][0]["properties"]["input"]["properties"]
        ["constraint"]["oneOf"][1]["oneOf"][0]["properties"]["value"];
    assert_eq!(
        constraint["properties"]["schema_version"]["const"],
        json!(CONSTRAINT_SCHEMA_VERSION)
    );
}
