//! The owner surface in the OpenAPI document (FIX 1755): every `/v1/owner`
//! route, with the SDK row whose input it takes where it mirrors one. The
//! routes are axum handlers with no utoipa annotation, so these tables name
//! them; a route added under `api/owner_routes` adds its line to the table
//! its path sorts into.

use serde_json::{Map, Value, json};

mod routes_a_to_e;
mod routes_f_to_packs;
mod routes_pads_to_w;

/// One `/v1/owner` route: its method, its path under `/v1/owner`, what it
/// does, and the SDK row whose input schema its body is.
pub(crate) struct OwnerRoute {
    pub(crate) method: &'static str,
    pub(crate) path: &'static str,
    pub(crate) summary: &'static str,
    pub(crate) row: Option<&'static str>,
}

/// Every `/v1/owner` route, the off-record ones included: three tables in
/// path order, read one after another.
pub(crate) const OWNER_ROUTE_TABLES: &[&[OwnerRoute]] = &[
    routes_a_to_e::ROUTES,
    routes_f_to_packs::ROUTES,
    routes_pads_to_w::ROUTES,
];

/// Adds each owner route to `spec`'s paths: owner-grade bearer, its row's
/// input schema as the JSON body where it has one, its row's output schema as
/// the answer where the SDK publishes one (else a JSON answer of unstated
/// shape), and the one 403 the owner door answers every refusal with.
pub(crate) fn merge_owner_paths(spec: &mut Value) {
    let Some(paths) = spec.get_mut("paths").and_then(Value::as_object_mut) else {
        return;
    };
    for route in OWNER_ROUTE_TABLES.iter().copied().flatten() {
        let path = format!("/v1/owner{}", route.path);
        let item = paths
            .entry(path.clone())
            .or_insert_with(|| json!({}))
            .as_object_mut();
        let Some(item) = item else {
            continue;
        };
        item.insert(route.method.to_owned(), operation(route, &path));
    }
}

fn operation(route: &OwnerRoute, path: &str) -> Value {
    let mut operation = Map::new();
    operation.insert("tags".to_owned(), json!(["owner"]));
    operation.insert("summary".to_owned(), json!(route.summary));
    operation.insert(
        "operationId".to_owned(),
        json!(format!(
            "owner_{}_{}",
            route.method,
            path.trim_start_matches("/v1/owner/")
                .replace(['/', '-', '{', '}'], "_")
        )),
    );
    operation.insert("security".to_owned(), json!([{ "CoreBearer": [] }]));
    let parameters: Vec<Value> = path
        .split('/')
        .filter_map(|segment| segment.strip_prefix('{')?.strip_suffix('}'))
        .map(|name| json!({"name": name, "in": "path", "required": true, "schema": {"type": "string"}}))
        .collect();
    if !parameters.is_empty() {
        operation.insert("parameters".to_owned(), Value::Array(parameters));
    }
    if matches!(route.method, "post" | "put") {
        let schema = route
            .row
            .and_then(oneiron::task_verb::sdk::input_schema)
            .cloned()
            .unwrap_or_else(|| json!({"type": "object"}));
        operation.insert(
            "requestBody".to_owned(),
            json!({"required": true, "content": {"application/json": {"schema": schema}}}),
        );
    }
    // The mapped row's own answer schema where the SDK publishes one (FIX
    // 8194); any other answer is JSON whose shape this table does not state.
    let content = route
        .row
        .and_then(oneiron::task_verb::sdk::output_schema)
        .map_or_else(|| json!({}), |schema| json!({ "schema": schema }));
    let mut answer = json!({
        "description": "The owner action's answer.",
        "content": {"application/json": content}
    });
    if let Some(row) = route.row {
        answer["description"] = json!(format!(
            "The `{row}` row's answer, as its verb hooks' post chain left it."
        ));
    }
    operation.insert(
        "responses".to_owned(),
        json!({
            "200": answer,
            "403": {
                "description": "Not the vault's live owner, on an owner-grade slip: one refusal for every failed check.",
                "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ApiError"}}}
            }
        }),
    );
    Value::Object(operation)
}
