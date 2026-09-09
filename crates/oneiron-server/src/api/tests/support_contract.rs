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

pub(super) fn openapi_operation_contract(operation: &Value) -> Value {
    let responses = operation["responses"]
        .as_object()
        .expect("responses object")
        .iter()
        .map(|(status, response)| {
            (
                status.clone(),
                json!({
                    "description": response["description"].clone(),
                    "schema": openapi_json_schema_ref(response),
                }),
            )
        })
        .collect::<Map<_, _>>();
    let parameters = operation["parameters"]
        .as_array()
        .map(|parameters| {
            parameters
                .iter()
                .map(|parameter| {
                    json!({
                        "name": parameter["name"].clone(),
                        "in": parameter["in"].clone(),
                        "required": parameter["required"].clone(),
                        "schema": openapi_schema_shape(&parameter["schema"]),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    json!({
        "operationId": operation["operationId"].clone(),
        "security": operation["security"].clone(),
        "parameters": parameters,
        "requestSchema": operation
            .get("requestBody")
            .map_or(Value::Null, openapi_json_schema_ref),
        "responses": responses,
    })
}

pub(super) fn openapi_json_schema_ref(value: &Value) -> Value {
    value
        .pointer("/content/application~1json/schema")
        .map_or(Value::Null, openapi_schema_shape)
}

pub(super) fn openapi_component_schema<'a>(spec: &'a Value, name: &str) -> &'a Value {
    spec.pointer(&format!("/components/schemas/{name}"))
        .unwrap_or_else(|| panic!("OpenAPI component schema {name} must exist"))
}

pub(super) fn openapi_schema_contract(schema: &Value) -> Value {
    let mut contract = Map::new();
    for key in [
        "$ref",
        "type",
        "format",
        "enum",
        "const",
        "required",
        "default",
        "nullable",
        "additionalProperties",
        "discriminator",
    ] {
        if let Some(value) = schema.get(key) {
            contract.insert(key.to_owned(), value.clone());
        }
    }
    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        let mut property_contract = Map::new();
        for (name, property) in properties {
            property_contract.insert(name.clone(), openapi_schema_contract(property));
        }
        contract.insert("properties".to_owned(), Value::Object(property_contract));
    }
    if let Some(items) = schema.get("items") {
        contract.insert("items".to_owned(), openapi_schema_contract(items));
    }
    for key in ["oneOf", "anyOf", "allOf"] {
        if let Some(schemas) = schema.get(key).and_then(Value::as_array) {
            contract.insert(
                key.to_owned(),
                Value::Array(schemas.iter().map(openapi_schema_contract).collect()),
            );
        }
    }
    Value::Object(contract)
}

pub(super) fn openapi_schema_shape(schema: &Value) -> Value {
    let mut shape = Map::new();
    for key in ["$ref", "type", "format", "enum", "required", "default"] {
        if let Some(value) = schema.get(key) {
            shape.insert(key.to_owned(), value.clone());
        }
    }
    if let Some(items) = schema.get("items") {
        shape.insert("items".to_owned(), openapi_schema_shape(items));
    }
    if let Some(one_of) = schema.get("oneOf").and_then(Value::as_array) {
        shape.insert(
            "oneOf".to_owned(),
            Value::Array(one_of.iter().map(openapi_schema_shape).collect()),
        );
    }
    Value::Object(shape)
}

pub(super) fn retrieval_quality_schema_properties() -> Value {
    json!({
        "quality": {"type": ["string", "null"]},
        "degradation": {"type": ["array", "null"], "items": {"type": "string"}},
        "confidenceAdjustment": {"type": ["number", "null"], "format": "float"}
    })
}

pub(super) fn retrieval_quality_openapi_snapshot() -> String {
    let mut expected: Value =
        serde_json::from_str(V1_CORE_OPENAPI_CONTRACT_SNAPSHOT).expect("OpenAPI fixture");
    for name in ["ResponseMeta", "CoreContextPackResponse"] {
        let properties = expected["components"]["schemas"][name]["properties"]
            .as_object_mut()
            .expect("schema properties");
        properties.extend(
            retrieval_quality_schema_properties()
                .as_object()
                .expect("quality properties")
                .clone(),
        );
    }
    depth_quality::extend_depth_error_contract(&mut expected);
    serde_json::to_string(&expected).expect("extended OpenAPI expectation")
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
