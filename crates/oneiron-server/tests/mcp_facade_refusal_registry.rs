#![cfg(oneiron_test_support)]
//! The MCP gateway answers each engine refusal code with one JSON-RPC number
//! and one stable kind (UC-11 PR 6): a missing row -32004, a typed refusal
//! -32020, an engine fault or a model that did not answer -32603, and any
//! other code an argument error, -32602. A kind the gateway does not name
//! is `facade_error`. The pins are main's answers, so the registry PR must
//! keep every one. Run with:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --features oneiron/test-support --test mcp_facade_refusal_registry`.

use oneiron_server::test_doors::mcp_refusal_status::mcp_refusal;

/// Each engine code, and the number and kind the gateway answers it with.
const PINNED: [(&str, i64, &str); 23] = [
    ("NOT_FOUND", -32004, "facade_error"),
    ("FORBIDDEN", -32020, "facade_error"),
    ("OWNER_BINDING_REQUIRED", -32020, "owner_binding_required"),
    ("BUDGET_SPENT", -32020, "budget_spent"),
    ("IDENTITY_UNSETTLED", -32020, "identity_unsettled"),
    (
        "HOST_ACTION_REQUIRES_SUPPORT_GRANT",
        -32020,
        "host_action_requires_support_grant",
    ),
    (
        "OFF_RECORD_ROOM_MANAGEMENT_CONSENT_UNAVAILABLE",
        -32020,
        "off_record_room_management_consent_unavailable",
    ),
    (
        "AGENT_THREAD_WALK_IN_FORBIDDEN",
        -32020,
        "agent_thread_walk_in_forbidden",
    ),
    (
        "SANDBOX_PROPOSAL_DISK_FLOOR",
        -32020,
        "sandbox_proposal_disk_floor",
    ),
    ("MODEL_PIN_UNAVAILABLE", -32020, "model_pin_unavailable"),
    ("PACED_HOLD", -32020, "paced_hold"),
    ("INVALID_STATE", -32020, "facade_error"),
    ("AUTHORITY_CLOCK_CORRUPT", -32020, "authority_clock_corrupt"),
    ("WORLD_RECIPIENT_LIMIT", -32020, "world_recipient_limit"),
    (
        "WORLD_PLACEMENT_UNVERIFIABLE",
        -32020,
        "world_placement_unverifiable",
    ),
    ("writes_frozen", -32020, "writes_frozen"),
    ("render_deadline", -32020, "render_deadline"),
    ("render_memory_floor", -32020, "render_memory_floor"),
    ("render_disk_floor", -32020, "render_disk_floor"),
    ("INTERNAL_SERVER_ERROR", -32603, "facade_error"),
    ("MODEL_UNAVAILABLE", -32603, "model_unavailable"),
    ("BAD_REQUEST", -32602, "facade_error"),
    ("A_CODE_NO_ROW_NAMES", -32602, "facade_error"),
];

#[test]
fn gateway_answers_each_code_with_its_pinned_number_and_kind() {
    let moved: Vec<String> = PINNED
        .iter()
        .filter_map(|&(code, number, kind)| {
            let answered = mcp_refusal(code);
            (answered != (number, kind))
                .then(|| format!("{code}: pinned ({number}, {kind}), answered {answered:?}"))
        })
        .collect();
    assert!(
        moved.is_empty(),
        "codes answered off their pins: {moved:#?}"
    );
}
