//! Shared contract/OpenAPI projection helpers for the API tests.

use super::*;

pub(super) fn normalize_contract_body(body: &mut Value) {
    match body {
        Value::Array(items) => {
            for item in items {
                normalize_contract_body(item);
            }
        }
        Value::Object(object) => {
            for (key, value) in object {
                match key.as_str() {
                    "deleted_at" => *value = Value::from("<deleted-at>"),
                    "query_time_us" => *value = Value::from("<duration-us>"),
                    "request_id" => *value = Value::from("<request-id>"),
                    "requestId" => *value = Value::from("<request-id>"),
                    "last_retrieval_run_id" => *value = Value::from("<retrieval-run-id>"),
                    "retrieval_run_id" => *value = Value::from("<retrieval-run-id>"),
                    _ => normalize_contract_body(value),
                }
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

pub(super) fn contract_exchange(
    name: &str,
    method: &str,
    path: &str,
    auth_scope: Option<&str>,
    request_body: Option<Value>,
    status: StatusCode,
    response_body: Value,
) -> Value {
    contract_exchange_with_auth(
        name,
        method,
        path,
        auth_scope.map_or_else(
            || json!({ "type": "none" }),
            |scope| json!({ "type": "bearer", "scope": scope }),
        ),
        request_body,
        status,
        response_body,
    )
}

/// Records one contract exchange under an explicitly described credential.
///
/// The `auth` descriptor is part of the contract, not decoration: a scoped
/// bearer and an owner-grade one produce genuinely different context-pack
/// bodies (the former is disclosure-clamped), so an exchange that documents
/// the wrong credential documents an unreachable response.
pub(super) fn contract_exchange_with_auth(
    name: &str,
    method: &str,
    path: &str,
    auth: Value,
    request_body: Option<Value>,
    status: StatusCode,
    mut response_body: Value,
) -> Value {
    normalize_contract_body(&mut response_body);
    json!({
        "name": name,
        "request": {
            "method": method,
            "path": path,
            "auth": auth,
            "body": request_body.unwrap_or(Value::Null),
        },
        "response": {
            "status": status.as_u16(),
            "body": response_body,
        },
    })
}

pub(super) fn openapi_component_schema<'a>(spec: &'a Value, name: &str) -> &'a Value {
    spec.pointer(&format!("/components/schemas/{name}"))
        .unwrap_or_else(|| panic!("OpenAPI component schema {name} must exist"))
}

pub(super) fn retrieval_quality_success_snapshot() -> String {
    let mut expected: Value =
        serde_json::from_str(V1_CORE_SUCCESS_CONTRACT_SNAPSHOT).expect("success fixture");
    for exchange in expected.as_array_mut().expect("exchanges") {
        let is_pack = exchange["name"].as_str() == Some("core_context_pack");
        let is_board = exchange["name"].as_str() == Some("core_context_board");
        if !is_pack && !is_board {
            continue;
        }
        // The board carries its retrieval pack nested under `pack`.
        let body = &mut exchange["response"]["body"];
        let body = if is_board { &mut body["pack"] } else { body };
        body["quality"] = json!("passthrough");
        body["confidenceAdjustment"] = json!(-0.35);
        if let Some(empty) = body.get_mut("empty") {
            empty["retrievalQuality"] = json!({
                "quality": "passthrough", "confidenceAdjustment": -0.35,
            });
        }
    }
    serde_json::to_string(&expected).expect("extended success expectation")
}
