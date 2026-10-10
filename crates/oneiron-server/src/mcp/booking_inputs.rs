//! JSON schemas for the booking agent API's operation inputs (BK-08), merged
//! into the OpenAPI components.

use super::schema_parts::{closed_object_schema, nonblank_string_schema};
use oneiron::booking::constraint::CONSTRAINT_SCHEMA_VERSION;
use serde_json::Value;
use serde_json::json;

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

fn booking_selected_slot_schema() -> Value {
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
