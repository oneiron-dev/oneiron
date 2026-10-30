//! A removed device's own routes in the OpenAPI document (OF-150, OF-158,
//! FIX 1300), moved whole out of `owner_paths`.

use serde_json::{Value, json};

/// A removed device's own routes (OF-150, OF-158, FIX 1300): no bearer, as
/// its slips are revoked; the revoked slip rides `x-oneiron-left-slip`, with
/// its holder proof in `x-oneiron-binding`, and each call spends its nonce.
const LEFT_SLIP_ROUTES: &[(&str, &str)] = &[
    (
        "/v1/shared/left-notices",
        "The removed person's own loss-of-access notices, each signed by this host's root key. Optional application/json body: `authority_heads` (array of 64-hex authority-entry hashes; omitted or empty requests the full handoff chain). The JSON answer has `notices` (signed shared-act outcomes) and `handoff` (array of hex-encoded signed authority rows, parents first: the ReRoot and host-root RotateKey rows that hand the root on from those heads to this host's signing root, and every row they stand on that those heads do not cover; empty when already folded).",
    ),
    (
        "/v1/shared/removal-export",
        "Every archive export-first removals delivered to the removed person, still within its term.",
    ),
    (
        "/v1/shared/removal-export/{receipt_id}",
        "The one archive the removal receipt receipt_id delivered to the removed person, while within its term; not found after it.",
    ),
    (
        "/v1/shared/removal-delivery",
        "Every archive owed to the removed person at its current delivery version, still within its term; with none owed the session holds for a wake, then answers none.",
    ),
    (
        "/v1/shared/removal-delivery/ack",
        "The removed person's ack of one archive's delivery version; answers whether it stores the current one.",
    ),
];

/// A left-slip route's optional JSON body and its answer's schema:
/// `/v1/shared/left-notices` names both (FIX 3372); the delivery ack names
/// its `{receipt_id, version}` body and `{state}` answer; the export and
/// delivery routes take no body and answer a plain object.
fn left_slip_shapes(path: &str) -> (Option<Value>, Value) {
    if path == "/v1/shared/removal-delivery/ack" {
        let body = json!({
            "required": true,
            "content": {"application/json": {"schema": {
                "type": "object",
                "additionalProperties": false,
                "required": ["receipt_id", "version"],
                "properties": {
                    "receipt_id": {"type": "string", "description": "The removal receipt's id, 32 hex."},
                    "version": {"type": "integer", "description": "The delivery version the holder now stores."}
                }
            }}}
        });
        let answer = json!({
            "type": "object",
            "required": ["state"],
            "properties": {
                "state": {"type": "string", "enum": ["acked", "pending"], "description": "Whether the holder stores the archive's current version."}
            }
        });
        return (Some(body), answer);
    }
    if path != "/v1/shared/left-notices" {
        return (None, json!({"type": "object"}));
    }
    let body = json!({
        "required": false,
        "content": {"application/json": {"schema": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "authority_heads": {"type": "array", "items": {"type": "string"}, "description": "The authority-entry hashes the person's env folded, 64 hex each; omitted or empty asks for the whole handoff chain."}
            }
        }}}
    });
    let answer = json!({
        "type": "object",
        "required": ["notices", "handoff"],
        "properties": {
            "notices": {"type": "array", "items": {"type": "object"}, "description": "The person's signed shared-act outcomes."},
            "handoff": {"type": "array", "items": {"type": "string"}, "description": "The signed authority rows, hex, parents first: the ReRoot and host-root RotateKey rows that hand the root on from those heads to the key that signed `notices`, and every row they stand on that those heads do not cover; empty when already folded."}
        }
    });
    (Some(body), answer)
}

/// Adds the removed device's routes to `spec`'s paths.
pub(crate) fn merge_left_slip_paths(spec: &mut Value) {
    let Some(paths) = spec.get_mut("paths").and_then(Value::as_object_mut) else {
        return;
    };
    for (path, summary) in LEFT_SLIP_ROUTES {
        let mut parameters = vec![
            json!({"name": "x-oneiron-left-slip", "in": "header", "required": true, "schema": {"type": "string"}, "description": "The revoked slip this vault minted for the person."}),
            json!({"name": "x-oneiron-binding", "in": "header", "required": true, "schema": {"type": "string"}, "description": "The slip holder's proof over the request's timestamp and nonce."}),
        ];
        if path.ends_with("{receipt_id}") {
            parameters.push(json!({"name": "receipt_id", "in": "path", "required": true, "schema": {"type": "string"}, "description": "The removal receipt's id, 32 hex."}));
        }
        let (body, answer) = left_slip_shapes(path);
        let mut operation = json!({
            "tags": ["shared"],
            "summary": summary,
            "operationId": format!("left_slip_{}", path.trim_start_matches("/v1/shared/").replace(['/', '-', '{', '}'], "_")),
            "parameters": parameters,
            "responses": {
                "200": {"description": "The removed person's answer.", "content": {"application/json": {"schema": answer}}},
                "401": {"description": "The slip or its proof does not verify, or the nonce was spent.", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ApiError"}}}},
                "404": {"description": "No archive this receipt delivered to the person is within its term.", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ApiError"}}}}
            }
        });
        if let (Some(body), Some(fields)) = (body, operation.as_object_mut()) {
            fields.insert("requestBody".to_owned(), body);
        }
        if let Some(item) = paths
            .entry((*path).to_owned())
            .or_insert_with(|| json!({}))
            .as_object_mut()
        {
            item.insert("post".to_owned(), operation);
        }
    }
}
