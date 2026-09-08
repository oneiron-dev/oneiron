//! JSON schemas for each MCP tool, including booking and calendar operations.

use super::schema_parts::{
    actor_schema, ask_effort_schema, ask_route_schema, citation_mode_schema, closed_object_schema,
    consent_schema, context_pack_ref_schema, edit_forbidden_except, edit_provenance_subject_schema,
    edit_subject_schema, entity_id_schema, nonblank_string_schema, occurred_range_schema,
    read_target_schema, schema_version_property, tool_schema_root,
};
use oneiron::booking::constraint::CONSTRAINT_SCHEMA_VERSION;
use serde_json::Value;
use serde_json::json;

pub(super) fn nav_tool_schema() -> Value {
    tool_schema_root(
        "https://oneiron.local/schemas/mcp/nav.args.v1.json",
        json!({
            "schema_version": schema_version_property(),
            "actor": actor_schema(),
            "consent": consent_schema(),
            "mode": { "type": "string", "enum": ["search", "timeline", "list", "hydrate"] },
            "query": nonblank_string_schema(),
            "limit": { "type": "integer", "minimum": 1, "maximum": u32::MAX },
            "cursor": nonblank_string_schema(),
            "context_pack": context_pack_ref_schema(),
        }),
        &["schema_version", "actor", "consent", "mode"],
    )
}

pub(super) fn read_tool_schema() -> Value {
    tool_schema_root(
        "https://oneiron.local/schemas/mcp/read.args.v1.json",
        json!({
            "schema_version": schema_version_property(),
            "actor": actor_schema(),
            "consent": consent_schema(),
            "target": read_target_schema(),
        }),
        &["schema_version", "actor", "consent", "target"],
    )
}

pub(super) fn edit_tool_schema() -> Value {
    let mut schema = tool_schema_root(
        "https://oneiron.local/schemas/mcp/edit.args.v1.json",
        json!({
            "schema_version": schema_version_property(),
            "actor": actor_schema(),
            "consent": consent_schema(),
            "verb": {
                "type": "string",
                "enum": [
                    "propose_claim",
                    "attest_edge_provenance",
                    "supersede_claim",
                    "retract_claim",
                    "propose_entity",
                    "post_task",
                    "report_task",
                    "channel_send",
                ],
            },
            "idempotency_key": nonblank_string_schema(),
            "dry_run": { "type": "boolean" },
            "subject": edit_subject_schema(),
            "predicate": nonblank_string_schema(),
            "value": {},
            "confidence": { "type": "number", "minimum": 0, "maximum": 1 },
            "evidence": {},
            "valid_from": { "type": "integer", "minimum": 0, "maximum": u64::MAX },
            "valid_to": { "type": "integer", "minimum": 0, "maximum": u64::MAX },
            "salience": { "type": "number" },
            "world": entity_id_schema(),
            "scope": {},
            "old_claim_id": entity_id_schema(),
            "claim_id": entity_id_schema(),
            "reason": nonblank_string_schema(),
            "explanation": nonblank_string_schema(),
            "entity_type": { "type": "integer", "minimum": 0, "maximum": 255 },
            "occurred": occurred_range_schema(),
            "data": {},
            "initial_claims": { "type": "array", "maxItems": 16, "items": {} },
            "brief": {},
            "job_id": nonblank_string_schema(),
            "outcome": nonblank_string_schema(),
            "summary": nonblank_string_schema(),
            "result_claims": { "type": "array", "maxItems": 8, "items": {} },
            "channel": nonblank_string_schema(),
            "payload": {},
            "supersession_status": nonblank_string_schema(),
            "source_revision_ref": nonblank_string_schema(),
            "body_snapshot_ref": nonblank_string_schema(),
            "reasoning_effort": nonblank_string_schema(),
        }),
        &[
            "schema_version",
            "actor",
            "consent",
            "verb",
            "idempotency_key",
        ],
    );
    schema
        .as_object_mut()
        .expect("tool schema root is an object")
        .insert(
            "allOf".to_owned(),
            json!([
                {
                    "if": {
                        "properties": { "verb": { "const": "propose_claim" } },
                        "required": ["verb"],
                    },
                    "then": {
                        "required": ["subject", "predicate", "value", "confidence"],
                        "not": edit_forbidden_except(&[
                            "subject",
                            "predicate",
                            "value",
                            "confidence",
                            "evidence",
                            "valid_from",
                            "valid_to",
                            "salience",
                            "world",
                            "scope",
                        ]),
                    },
                },
                {
                    "if": {
                        "properties": { "verb": { "const": "attest_edge_provenance" } },
                        "required": ["verb"],
                    },
                    "then": {
                        "required": ["subject", "confidence"],
                        "properties": {
                            "subject": edit_provenance_subject_schema(),
                        },
                        "not": edit_forbidden_except(&[
                            "subject",
                            "confidence",
                            "old_claim_id",
                            "supersession_status",
                            "source_revision_ref",
                            "body_snapshot_ref",
                            "reasoning_effort",
                        ]),
                    },
                },
                {
                    "if": {
                        "properties": { "verb": { "const": "supersede_claim" } },
                        "required": ["verb"],
                    },
                    "then": {
                        "required": ["old_claim_id", "predicate", "value", "confidence"],
                        "not": edit_forbidden_except(&[
                            "old_claim_id",
                            "predicate",
                            "value",
                            "confidence",
                            "evidence",
                            "valid_from",
                            "valid_to",
                            "salience",
                            "reason",
                        ]),
                    },
                },
                {
                    "if": {
                        "properties": { "verb": { "const": "retract_claim" } },
                        "required": ["verb"],
                    },
                    "then": {
                        "required": ["claim_id", "reason"],
                        "not": edit_forbidden_except(&["claim_id", "reason", "explanation"]),
                    },
                },
                {
                    "if": {
                        "properties": { "verb": { "const": "propose_entity" } },
                        "required": ["verb"],
                    },
                    "then": {
                        "required": ["entity_type", "occurred", "data"],
                        "not": edit_forbidden_except(&[
                            "entity_type",
                            "occurred",
                            "data",
                            "initial_claims",
                        ]),
                    },
                },
                {
                    "if": {
                        "properties": { "verb": { "const": "post_task" } },
                        "required": ["verb"],
                    },
                    "then": {
                        "required": ["brief"],
                        "not": edit_forbidden_except(&["brief"]),
                    },
                },
                {
                    "if": {
                        "properties": { "verb": { "const": "report_task" } },
                        "required": ["verb"],
                    },
                    "then": {
                        "required": ["job_id", "outcome", "summary"],
                        "not": edit_forbidden_except(&["job_id", "outcome", "summary", "result_claims"]),
                    },
                },
                {
                    "if": {
                        "properties": { "verb": { "const": "channel_send" } },
                        "required": ["verb"],
                    },
                    "then": {
                        "required": ["channel", "payload"],
                        "not": edit_forbidden_except(&["channel", "payload"]),
                    },
                },
            ]),
        );
    schema
}

pub(super) fn ask_tool_schema() -> Value {
    tool_schema_root(
        "https://oneiron.local/schemas/mcp/ask.args.v1.json",
        json!({
            "schema_version": schema_version_property(),
            "actor": actor_schema(),
            "context_pack": context_pack_ref_schema(),
            "consent": consent_schema(),
            "query": nonblank_string_schema(),
            "effort": ask_effort_schema(),
            "citation_mode": citation_mode_schema(),
        }),
        &[
            "schema_version",
            "actor",
            "context_pack",
            "consent",
            "query",
        ],
    )
}

pub(super) fn routed_ask_tool_schema() -> Value {
    tool_schema_root(
        "https://oneiron.local/schemas/mcp/ask_routed.args.v1.json",
        json!({
            "schema_version": schema_version_property(),
            "actor": actor_schema(),
            "context_pack": context_pack_ref_schema(),
            "consent": consent_schema(),
            "query": nonblank_string_schema(),
            "route": ask_route_schema(),
            "effort": ask_effort_schema(),
            "citation_mode": citation_mode_schema(),
        }),
        &[
            "schema_version",
            "actor",
            "context_pack",
            "consent",
            "query",
            "route",
        ],
    )
}

pub(super) fn calendar_tool_schema() -> Value {
    tool_schema_root(
        "https://oneiron.local/schemas/mcp/calendar.args.v1.json",
        json!({
            "schema_version": schema_version_property(),
            "actor": actor_schema(),
            "consent": consent_schema(),
            "operation": calendar_operation_schema(),
        }),
        &["schema_version", "actor", "consent", "operation"],
    )
}

/// One closed branch per operation. The `op` discriminator is the only shared
/// key; every other field belongs to exactly one arm.
pub(super) fn calendar_operation_schema() -> Value {
    json!({
        "oneOf": [
            closed_object_schema(
                &["op", "event_ref"],
                json!({
                    "op": { "const": "read" },
                    "event_ref": entity_id_schema(),
                }),
            ),
            closed_object_schema(
                &["op"],
                json!({
                    "op": { "const": "search" },
                    "calendars": calendar_selectors_schema(),
                    "range": calendar_range_schema(),
                    "text": nonblank_string_schema(),
                    "limit": { "type": "integer", "minimum": 1, "maximum": u32::MAX },
                }),
            ),
            closed_object_schema(
                &["op", "range"],
                json!({
                    "op": { "const": "freebusy" },
                    "calendars": calendar_selectors_schema(),
                    "range": calendar_range_schema(),
                }),
            ),
            closed_object_schema(
                &["op", "method", "uid", "sequence", "ics_blob_ref", "recipient"],
                json!({
                    "op": { "const": "invite" },
                    "method": { "type": "string", "enum": ["REQUEST", "CANCEL"] },
                    "uid": nonblank_string_schema(),
                    "sequence": { "type": "integer", "minimum": 0, "maximum": u32::MAX },
                    "ics_blob_ref": nonblank_string_schema(),
                    "recipient": nonblank_string_schema(),
                }),
            ),
        ],
    })
}

/// `oneiron.book`'s single tagged-op schema.
///
/// One tool, four ops, and the exact same envelope `oneiron.calendar` carries.
/// A per-op tool would be four names in the closed catalog for one capability.
pub(super) fn book_tool_schema() -> Value {
    tool_schema_root(
        "https://oneiron.local/schemas/mcp/book.args.v1.json",
        json!({
            "schema_version": schema_version_property(),
            "actor": actor_schema(),
            "consent": consent_schema(),
            "page_token": booking_page_token_schema(),
            "operation": book_operation_schema(),
        }),
        &[
            "schema_version",
            "actor",
            "consent",
            "page_token",
            "operation",
        ],
    )
}

/// One closed branch per booking operation, in the instructions block's
/// canonical order. The `op` discriminator is the only shared key.
pub(crate) fn book_operation_schema() -> Value {
    json!({
        "oneOf": [
            closed_object_schema(
                &["op", "input"],
                json!({
                    "op": { "const": "availability" },
                    "input": booking_availability_input_schema(),
                }),
            ),
            closed_object_schema(
                &["op", "input"],
                json!({
                    "op": { "const": "book" },
                    "input": booking_book_input_schema(),
                }),
            ),
            closed_object_schema(
                &["op", "input"],
                json!({
                    "op": { "const": "reschedule" },
                    "input": booking_reschedule_input_schema(),
                }),
            ),
            closed_object_schema(
                &["op", "input"],
                json!({
                    "op": { "const": "cancel" },
                    "input": booking_cancel_input_schema(),
                }),
            ),
        ],
    })
}

/// An opaque booking page handle. The prefix is what makes it structurally
/// impossible to pass an entity id here by accident.
pub(crate) fn booking_page_token_schema() -> Value {
    json!({
        "type": "string",
        "pattern": "^bkp_[0-9a-f]{32}$",
    })
}

/// An opaque action-scoped booking credential minted by the lifecycle.
fn booking_action_token_schema() -> Value {
    json!({
        "type": "string",
        "pattern": "^[0-9a-f]{64}$",
    })
}

fn booking_utc_window_schema() -> Value {
    closed_object_schema(
        &["start", "end"],
        json!({
            "start": { "type": "integer", "minimum": 0, "maximum": u64::MAX },
            "end": { "type": "integer", "minimum": 0, "maximum": u64::MAX },
        }),
    )
}

pub(super) fn booking_selected_slot_schema() -> Value {
    closed_object_schema(
        &["start_utc", "end_utc"],
        json!({
            "start_utc": { "type": "integer", "minimum": 0, "maximum": u64::MAX },
            "end_utc": { "type": "integer", "minimum": 0, "maximum": u64::MAX },
        }),
    )
}

fn booking_constraint_object_schema() -> Value {
    closed_object_schema(
        &["schema_version", "utc_window", "allow_flex_pool"],
        json!({
            "schema_version": { "const": CONSTRAINT_SCHEMA_VERSION },
            "weekdays": {
                "type": "array",
                "maxItems": 7,
                "items": {
                    "enum": [
                        "monday", "tuesday", "wednesday", "thursday",
                        "friday", "saturday", "sunday",
                    ]
                },
            },
            "local_time_windows": {
                "type": "array",
                "items": closed_object_schema(
                    &["start_minute", "end_minute"],
                    json!({
                        "start_minute": { "type": "integer", "minimum": 0, "maximum": 1440 },
                        "end_minute": { "type": "integer", "minimum": 0, "maximum": 1440 },
                    }),
                ),
            },
            "utc_window": { "oneOf": [{ "type": "null" }, booking_utc_window_schema()] },
            "allow_flex_pool": { "type": "boolean" },
        }),
    )
}

/// Either a prebuilt canonical constraint or bounded free text. Free text is
/// normalized by ONE-1816 inside the executor and never reaches the oracle.
fn booking_constraint_input_schema() -> Value {
    json!({
        "oneOf": [
            closed_object_schema(
                &["kind", "value"],
                json!({
                    "kind": { "const": "object" },
                    "value": booking_constraint_object_schema(),
                }),
            ),
            closed_object_schema(
                &["kind", "value"],
                json!({
                    "kind": { "const": "free_text" },
                    "value": { "type": "string", "minLength": 1 },
                }),
            ),
        ],
    })
}

pub(crate) fn booking_availability_input_schema() -> Value {
    closed_object_schema(
        &[
            "event_type",
            "window",
            "visitor_tz",
            "constraint",
            "session_ref",
        ],
        json!({
            "event_type": nonblank_string_schema(),
            "window": booking_utc_window_schema(),
            "visitor_tz": nonblank_string_schema(),
            "constraint": { "oneOf": [{ "type": "null" }, booking_constraint_input_schema()] },
            "session_ref": nonblank_string_schema(),
        }),
    )
}

fn booking_hold_input_schema() -> Value {
    closed_object_schema(
        &[
            "event_type",
            "selected_slot",
            "visitor_tz",
            "constraint",
            "session_ref",
            "checkout_lease_token",
            "idempotency_key",
        ],
        json!({
            "event_type": nonblank_string_schema(),
            "selected_slot": booking_selected_slot_schema(),
            "visitor_tz": nonblank_string_schema(),
            "constraint": { "oneOf": [{ "type": "null" }, booking_constraint_object_schema()] },
            "session_ref": nonblank_string_schema(),
            // No TTL field exists, by construction: a hold's lifetime is the
            // server default or a server-issued lease, never a caller's ask.
            "checkout_lease_token": {
                "oneOf": [{ "type": "null" }, booking_action_token_schema()]
            },
            "idempotency_key": nonblank_string_schema(),
        }),
    )
}

fn booking_confirm_input_schema() -> Value {
    closed_object_schema(
        &[
            "hold_token",
            "booker_email",
            "intake",
            "session_ref",
            "idempotency_key",
        ],
        json!({
            "hold_token": booking_action_token_schema(),
            "booker_email": nonblank_string_schema(),
            "intake": {
                "type": "array",
                "items": closed_object_schema(
                    &["field_key", "value"],
                    json!({
                        "field_key": nonblank_string_schema(),
                        "value": { "type": "string" },
                    }),
                ),
            },
            "session_ref": nonblank_string_schema(),
            "idempotency_key": nonblank_string_schema(),
        }),
    )
}

pub(crate) fn booking_book_input_schema() -> Value {
    json!({
        "oneOf": [
            closed_object_schema(
                &["stage", "input"],
                json!({
                    "stage": { "const": "hold" },
                    "input": booking_hold_input_schema(),
                }),
            ),
            closed_object_schema(
                &["stage", "input"],
                json!({
                    "stage": { "const": "confirm" },
                    "input": booking_confirm_input_schema(),
                }),
            ),
        ],
    })
}

pub(crate) fn booking_reschedule_input_schema() -> Value {
    closed_object_schema(
        &[
            "reschedule_token",
            "selected_slot",
            "visitor_tz",
            "idempotency_key",
        ],
        json!({
            "reschedule_token": booking_action_token_schema(),
            "selected_slot": booking_selected_slot_schema(),
            "visitor_tz": nonblank_string_schema(),
            "idempotency_key": nonblank_string_schema(),
        }),
    )
}

pub(crate) fn booking_cancel_input_schema() -> Value {
    closed_object_schema(
        &["cancel_token", "idempotency_key"],
        json!({
            "cancel_token": booking_action_token_schema(),
            "idempotency_key": nonblank_string_schema(),
        }),
    )
}

fn calendar_selectors_schema() -> Value {
    json!({
        "type": "array",
        "items": closed_object_schema(&[], json!({ "system": nonblank_string_schema() })),
    })
}

pub(super) fn calendar_range_schema() -> Value {
    closed_object_schema(
        &["start", "end"],
        json!({
            "start": { "type": "integer", "minimum": 0, "maximum": u64::MAX },
            "end": { "type": "integer", "minimum": 0, "maximum": u64::MAX },
        }),
    )
}
