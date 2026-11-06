//! The owner surface in the OpenAPI document (FIX 1755): every `/v1/owner`
//! route, with the SDK row whose input it takes where it mirrors one. The
//! routes are axum handlers with no utoipa annotation, so each owner route
//! leaf declares its rows beside its handlers, in the one table its router
//! is built from; the document reads those tables through
//! `owner_routes::owner_route_rows` (FIX 8931). A route that mirrors no SDK
//! row states its own REST shapes on the same row (FIX 11892).

use serde_json::{Map, Value, json};

/// One `/v1/owner` route: its method, its path under `/v1/owner`, what it
/// does, the SDK row whose input schema its body is, and the REST shapes the
/// route states itself.
pub(crate) struct OwnerRoute {
    pub(crate) method: &'static str,
    pub(crate) path: &'static str,
    pub(crate) summary: &'static str,
    pub(crate) row: Option<&'static str>,
    pub(crate) shape: Option<RestShape>,
}

/// The conflict a route answers when what it was asked on changed in the
/// vault first (`OwnerError::Changed`).
pub(crate) const CHANGED: (&str, &str) = (
    "409",
    "What the request was made on changed in the vault before it was written (`changed_since_review`): read it again and ask again.",
);

/// The REST shapes of an owner route that mirrors no SDK row (FIX 4782, FIX
/// 10289, FIX 11103, FIX 11611): its body and answer, each read from the type
/// the route reads or writes, and each refusal it answers beside the owner
/// door's 403. They replace the generic operation's body and answer, so the
/// document teaches a client the fields the route takes, with no SDK row
/// added.
pub(crate) struct RestShape {
    /// The body the route reads; `None` when it reads none (FIX 11613).
    body: Option<RestBody>,
    answer: RestAnswer,
    refusals: &'static [(&'static str, &'static str)],
}

/// What a shaped route reads as its request body.
enum RestBody {
    /// A JSON body of this schema.
    Json(fn() -> Value),
    /// Raw bytes, named by a JSON manifest in one request header (FIX 12086).
    Bytes(ByteBody),
}

/// A route's raw byte body, not JSON, and the request header whose JSON
/// manifest names what the bytes hold (FIX 12086).
pub(crate) struct ByteBody {
    /// What the bytes are.
    pub(crate) description: &'static str,
    /// The request header that carries the manifest.
    pub(crate) header: &'static str,
    /// What the manifest names.
    pub(crate) header_description: &'static str,
    /// The manifest's schema.
    pub(crate) header_schema: fn() -> Value,
}

/// What a shaped route answers on success.
enum RestAnswer {
    /// The route's typed JSON answer.
    Json(fn() -> Value),
    /// The screen as a PNG image (FIX 11613).
    Png,
}

impl RestShape {
    /// A route that reads a JSON body and answers typed JSON.
    pub(crate) fn json(body: fn() -> Value, answer: fn() -> Value) -> Self {
        Self {
            body: Some(RestBody::Json(body)),
            answer: RestAnswer::Json(answer),
            refusals: &[],
        }
    }

    /// A route that reads a raw byte body, named by the manifest in one
    /// request header, and answers typed JSON (FIX 12086).
    pub(crate) fn bytes(body: ByteBody, answer: fn() -> Value) -> Self {
        Self {
            body: Some(RestBody::Bytes(body)),
            answer: RestAnswer::Json(answer),
            refusals: &[],
        }
    }

    /// A route that reads no body and answers typed JSON: the operation
    /// declares no body (FIX 11613).
    pub(crate) fn no_body(answer: fn() -> Value) -> Self {
        Self {
            body: None,
            answer: RestAnswer::Json(answer),
            refusals: &[],
        }
    }

    /// A route that reads a JSON body and answers the screen as a PNG image
    /// (FIX 11613).
    pub(crate) fn png(body: fn() -> Value) -> Self {
        Self {
            body: Some(RestBody::Json(body)),
            answer: RestAnswer::Png,
            refusals: &[],
        }
    }

    /// The same shapes, with the refusals the route answers beside the owner
    /// door's 403, each as its status and what it means.
    pub(crate) fn refusing(self, refusals: &'static [(&'static str, &'static str)]) -> Self {
        Self { refusals, ..self }
    }

    /// Writes the route's request body (or drops it when the route reads
    /// none), its 200 response and its refusals into `operation`, over what
    /// the generic operation wrote. A byte body also adds its manifest
    /// header to the operation's parameters.
    fn bind(&self, operation: &mut Value) {
        match &self.body {
            Some(RestBody::Json(body)) => {
                operation["requestBody"] =
                    json!({"required": true, "content": {"application/json": {"schema": body()}}});
            }
            Some(RestBody::Bytes(body)) => {
                operation["requestBody"] = json!({
                    "required": true,
                    "description": body.description,
                    "content": {"application/octet-stream": {"schema": {"type": "string", "format": "binary"}}}
                });
                let mut parameters = operation
                    .get("parameters")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                parameters.push(json!({
                    "name": body.header,
                    "in": "header",
                    "required": true,
                    "description": body.header_description,
                    "content": {"application/json": {"schema": (body.header_schema)()}}
                }));
                operation["parameters"] = Value::Array(parameters);
            }
            None => {
                if let Some(operation) = operation.as_object_mut() {
                    operation.remove("requestBody");
                }
            }
        }
        let answer = match self.answer {
            RestAnswer::Json(answer) => json!({
                "description": "The route's typed answer.",
                "content": {"application/json": {"schema": answer()}}
            }),
            RestAnswer::Png => json!({
                "description": "The screen as a PNG.",
                "content": {"image/png": {"schema": {"type": "string", "format": "binary"}}}
            }),
        };
        let Some(responses) = operation
            .get_mut("responses")
            .and_then(Value::as_object_mut)
        else {
            return;
        };
        responses.insert("200".to_owned(), answer);
        for (status, description) in self.refusals {
            responses.insert(
                (*status).to_owned(),
                json!({
                    "description": description,
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ApiError"}}}
                }),
            );
        }
    }
}

/// Adds each owner route to `spec`'s paths, in path order: owner-grade
/// bearer, its row's input schema as the JSON body where it has one, its
/// row's output schema as the answer where the SDK publishes one (else a JSON
/// answer of unstated shape), and the one 403 the owner door answers every
/// refusal with. A route that states its own [`RestShape`] gets that body,
/// answer and refusals instead.
pub(crate) fn merge_owner_paths(spec: &mut Value) {
    let Some(paths) = spec.get_mut("paths").and_then(Value::as_object_mut) else {
        return;
    };
    let mut routes = crate::api::owner_routes::owner_route_rows();
    routes.sort_by_key(|route| route.path);
    for route in &routes {
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
    let mut operation = Value::Object(operation);
    if let Some(shape) = &route.shape {
        shape.bind(&mut operation);
    }
    operation
}
