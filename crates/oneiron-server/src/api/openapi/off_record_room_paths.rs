//! The participants' off-record room routes (`/v1/core/off-record`, ARCH-0052
//! D5): each route takes its verb row's own input and answers its output,
//! both read from the generated row table, as the facade publishes the same
//! rows at `/v1/core/facade/<verb>`. No route keeps a call receipt, and the
//! export answers an attachment.

use serde_json::{Map, Value, json};

use oneiron::task_verb::sdk::{AgentVerb, input_schema, output_schema};

/// One room route as `api::off_record_rooms::routes` serves it under
/// `/v1/core/off-record`: its method, path, verb row and the scope it needs.
struct RoomRoute {
    method: &'static str,
    path: &'static str,
    verb: &'static str,
    scope: &'static str,
}

const ROOM_ROUTES: &[RoomRoute] = &[
    RoomRoute {
        method: "get",
        path: "/v1/core/off-record",
        verb: "vault.off_record.rooms.status",
        scope: "core:read",
    },
    RoomRoute {
        method: "post",
        path: "/v1/core/off-record/start",
        verb: "vault.off_record.rooms.start",
        scope: "core:write",
    },
    RoomRoute {
        method: "post",
        path: "/v1/core/off-record/witness",
        verb: "vault.off_record.rooms.witness",
        scope: "core:write",
    },
    RoomRoute {
        method: "post",
        path: "/v1/core/off-record/save",
        verb: "vault.off_record.rooms.save",
        scope: "core:write",
    },
    RoomRoute {
        method: "post",
        path: "/v1/core/off-record/export",
        verb: "vault.off_record.rooms.export",
        scope: "core:read",
    },
    RoomRoute {
        method: "post",
        path: "/v1/core/off-record/save-from-here",
        verb: "vault.off_record.rooms.save_from_here",
        scope: "core:write",
    },
    RoomRoute {
        method: "post",
        path: "/v1/core/off-record/suggest-save",
        verb: "vault.off_record.rooms.suggest_save",
        scope: "core:propose or core:write",
    },
    RoomRoute {
        method: "post",
        path: "/v1/core/off-record/confirm-save",
        verb: "vault.off_record.rooms.confirm_save",
        scope: "core:write",
    },
    RoomRoute {
        method: "post",
        path: "/v1/core/off-record/decline-save",
        verb: "vault.off_record.rooms.decline_save",
        scope: "core:write",
    },
];

/// The file name the export's attachment carries (`off_record_rooms::export`).
const EXPORT_ATTACHMENT: &str = "attachment; filename=\"off-record-talk.json\"";

/// The core envelope every room route refuses in.
const CORE_ERROR_ENVELOPE: &str = "#/components/schemas/ApiErrorEnvelope";

/// Each refusal a room route answers, by its status.
const REFUSALS: &[(&str, &str)] = &[
    (
        "400",
        "The input is malformed, or names no stretch this room can hold.",
    ),
    ("401", "The request carries no valid credential."),
    (
        "403",
        "The credential lacks the route's scope, off-record stretches are turned off, or the caller does not hold this vault's save grant (an agent is told to ask a holder).",
    ),
    (
        "404",
        "The room or its stretch does not resolve, or the caller is not on its roster.",
    ),
    (
        "409",
        "The stretch is not in a state the route admits: closing, already started, full, or holding no suggestion.",
    ),
    ("500", "The stretch's work did not finish."),
];

/// Adds each room route's operation to `spec`'s paths.
pub(super) fn merge_off_record_room_paths(spec: &mut Value) {
    let Some(paths) = spec.get_mut("paths").and_then(Value::as_object_mut) else {
        return;
    };
    for route in ROOM_ROUTES {
        let (Some(request), Some(answer)) = (input_schema(route.verb), output_schema(route.verb))
        else {
            continue;
        };
        let action = route.verb.rsplit('.').next().unwrap_or(route.verb);
        let mut operation = Map::new();
        operation.insert("tags".to_owned(), json!(["off_record"]));
        operation.insert(
            "operationId".to_owned(),
            json!(format!("off_record_room_{action}")),
        );
        operation.insert(
            "summary".to_owned(),
            json!(AgentVerb::from_name(route.verb).map_or("", AgentVerb::description)),
        );
        operation.insert(
            "description".to_owned(),
            json!(format!(
                "Requires the caller's {} credential, acting as the person or agent its slip names. The `{}` row's own route: nothing of the stretch lands in a call receipt or the idempotency store.",
                route.scope, route.verb
            )),
        );
        operation.insert("security".to_owned(), json!([{ "CoreBearer": [] }]));
        if route.method == "get" {
            operation.insert("parameters".to_owned(), query_parameters(request));
        } else {
            operation.insert(
                "requestBody".to_owned(),
                json!({"required": true, "content": {"application/json": {"schema": request}}}),
            );
        }
        operation.insert(
            "responses".to_owned(),
            responses(answer, route.verb == "vault.off_record.rooms.export"),
        );
        let entry = paths
            .entry(route.path.to_owned())
            .or_insert_with(|| json!({}));
        if let Some(entry) = entry.as_object_mut() {
            entry.insert(route.method.to_owned(), Value::Object(operation));
        }
    }
}

/// A GET route's input, as the query parameters `axum::extract::Query`
/// reads: one per property of the row's input schema.
fn query_parameters(request: &Value) -> Value {
    let required: Vec<&str> = request
        .get("required")
        .and_then(Value::as_array)
        .map_or_else(Vec::new, |names| {
            names.iter().filter_map(Value::as_str).collect()
        });
    let parameters = request
        .get("properties")
        .and_then(Value::as_object)
        .map_or_else(Vec::new, |properties| {
            properties
                .iter()
                .map(|(name, schema)| {
                    json!({
                        "name": name,
                        "in": "query",
                        "required": required.contains(&name.as_str()),
                        "schema": schema
                    })
                })
                .collect()
        });
    Value::Array(parameters)
}

/// A room route's answer, with the no-record receipt header every reply
/// carries, and each refusal in the core envelope.
fn responses(answer: Value, attachment: bool) -> Value {
    let mut headers = Map::new();
    headers.insert(
        "x-oneiron-receipt-ref".to_owned(),
        json!({"schema": {"type": "string", "const": "none; no-record"}}),
    );
    if attachment {
        headers.insert(
            "Content-Disposition".to_owned(),
            json!({"schema": {"type": "string", "const": EXPORT_ATTACHMENT}}),
        );
    }
    let description = if attachment {
        "The caller's own copy of the talk they can see, as a JSON attachment, with a content-free notice posted to the room."
    } else {
        "The row's typed answer."
    };
    let mut responses = Map::new();
    responses.insert(
        "200".to_owned(),
        json!({
            "description": description,
            "headers": Value::Object(headers),
            "content": {"application/json": {"schema": answer}}
        }),
    );
    for &(status, description) in REFUSALS {
        responses.insert(
            status.to_owned(),
            json!({
                "description": description,
                "content": {"application/json": {"schema": {"$ref": CORE_ERROR_ENVELOPE}}}
            }),
        );
    }
    Value::Object(responses)
}
