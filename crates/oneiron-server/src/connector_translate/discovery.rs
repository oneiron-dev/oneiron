//! Google Discovery documents as connector tools (L8-31 D5; canon
//! agent-runtime `#translator-inputs`: "The Google pack starts typed from
//! Google's Discovery documents").
//!
//! Each method under `resources`, at any depth, is one tool, named by its
//! Discovery `id` past the API's own name: `docs.documents.get` is
//! `documents.get`, the name L3-17's typed modules use. Its input is one
//! object with a property per path and query parameter, plus `body` when
//! the method takes a request; its output is the response's schema. The
//! document's global parameters (`key`, `access_token`, `alt`, `fields`
//! and the rest) are no argument: the credential is the key's custody
//! secret as the `Authorization` header, and the reply is always JSON.
//!
//! The installed endpoint stands for the document's `rootUrl`: a tool's
//! path is the `servicePath` and the method's `path` under it, and a
//! `rootUrl` or `baseUrl` on another origin refuses the document. A `{+name}`
//! place in a path takes a value with `/` in it, each part between them one
//! segment (connector_call_host/http_api.rs).
//!
//! Google's schemas refer to each other by id, often in cycles (a table
//! cell holds structural elements, which hold tables), and nest far deeper
//! than one signature can show. A reference is inlined as deep as the
//! tool's schema still fits the admission resolver's bound and its
//! TypeScript the bound `connector.schema` renders within; past that depth,
//! and at a cycle, the referenced schema keeps its own words (its type,
//! description, enum) without its fields. A tool is so typed as far as its
//! signature can be read, and no further.
//!
//! A method that only moves media (an upload with no JSON request, a
//! download with no JSON response) is no tool: code mode carries no binary
//! body. Any other method is a tool for its JSON form; its media forms (the
//! upload paths, `alt=media`) are never sent.

use std::collections::BTreeSet;

use oneiron::connector_key::{HttpMethod, HttpOperation};
use reqwest::Url;
use serde_json::{Map, Number, Value};

use super::{
    BODY_ARGUMENT, InputSchema, MAX_SCHEMA_BYTES, TranslatedTool, Translation, check_origin,
    check_path_template, fits_bounds, is_tool_name, refused,
};

/// The Discovery format this module reads.
const DISCOVERY_VERSION: &str = "v1";

/// The most references inlined along one path. Google's schemas stop
/// fitting a signature well before.
const MAX_REFERENCE_DEPTH: usize = 8;

/// The deepest nesting a translated schema reaches: the admission resolver
/// refuses past 24 levels, and the input object adds one.
const MAX_NESTING: usize = 20;

/// The most schema nodes one expansion builds. A depth that cannot fit is
/// abandoned before it is built whole.
const MAX_NODES: usize = 20_000;

/// How deep `resources` may nest.
const MAX_RESOURCE_DEPTH: usize = 16;

/// The JSON Schema types a Google `type` may name; `any` is no type.
const TYPES: [&str; 7] = [
    "string", "integer", "number", "boolean", "object", "array", "null",
];

pub(super) fn translate(document: &Value, endpoint: &Url) -> oneiron::Result<Translation> {
    let version = document
        .get("discoveryVersion")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if version != DISCOVERY_VERSION {
        return Err(refused(format!(
            "the document is Discovery {version:?}; only {DISCOVERY_VERSION:?} translates"
        )));
    }
    for key in ["rootUrl", "baseUrl"] {
        if let Some(url) = document.get(key).and_then(Value::as_str) {
            check_origin(url, endpoint, &format!("the document's {key}"))?;
        }
    }
    let empty = Map::new();
    let schemas = match document.get("schemas") {
        None => &empty,
        Some(schemas) => schemas
            .as_object()
            .ok_or_else(|| refused("the document's schemas are not an object".to_owned()))?,
    };
    let service = Service {
        api: document
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        prefix: service_prefix(
            document
                .get("servicePath")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        ),
        schemas,
    };
    let mut methods = Vec::new();
    collect_methods(document, 0, &mut methods)?;
    let mut translation = Translation {
        revision: format!("discovery-{DISCOVERY_VERSION}"),
        ..Translation::default()
    };
    let mut names = BTreeSet::new();
    for method in methods {
        let Some(tool) = service.method(method, &mut translation.skipped)? else {
            continue;
        };
        if !names.insert(tool.name.clone()) {
            return Err(refused(format!(
                "two methods are named {} past the API's name",
                tool.name
            )));
        }
        translation.tools.push(tool);
    }
    if translation.tools.is_empty() {
        return Err(refused(
            "the Discovery document lists no method a tool can call".to_owned(),
        ));
    }
    Ok(translation)
}

/// A tool path's prefix under the endpoint, which stands for `rootUrl`:
/// `/`, then the `servicePath` ending in `/`.
fn service_prefix(service_path: &str) -> String {
    let service_path = service_path.trim_start_matches('/');
    if service_path.is_empty() || service_path.ends_with('/') {
        format!("/{service_path}")
    } else {
        format!("/{service_path}/")
    }
}

/// Every method of `node` and of its `resources`, depth first, in the
/// document's order.
fn collect_methods<'a>(
    node: &'a Value,
    depth: usize,
    out: &mut Vec<&'a Value>,
) -> oneiron::Result<()> {
    if depth > MAX_RESOURCE_DEPTH {
        return Err(refused("the document's resources nest too deep".to_owned()));
    }
    if let Some(methods) = node.get("methods") {
        let methods = methods
            .as_object()
            .ok_or_else(|| refused("a `methods` entry is not an object".to_owned()))?;
        out.extend(methods.values());
    }
    if let Some(resources) = node.get("resources") {
        let resources = resources
            .as_object()
            .ok_or_else(|| refused("a `resources` entry is not an object".to_owned()))?;
        for resource in resources.values() {
            collect_methods(resource, depth + 1, out)?;
        }
    }
    Ok(())
}

/// What every method of one document shares.
struct Service<'a> {
    /// The API's `name`, which each method id starts with.
    api: &'a str,
    prefix: String,
    schemas: &'a Map<String, Value>,
}

impl Service<'_> {
    /// `method` as a tool; `None` when it is none, with the reason in
    /// `skipped` (the tool's name and why).
    fn method(
        &self,
        method: &Value,
        skipped: &mut Vec<String>,
    ) -> oneiron::Result<Option<TranslatedTool>> {
        let method = method
            .as_object()
            .ok_or_else(|| refused("a method is not an object".to_owned()))?;
        let text = |key: &str| method.get(key).and_then(Value::as_str).unwrap_or_default();
        let label = format!("{} {}", text("httpMethod"), text("path"));
        let id = text("id");
        if id.is_empty() {
            return Err(refused(format!(
                "method {label} has no id: a tool needs a name the document keeps"
            )));
        }
        let name = id
            .strip_prefix(self.api)
            .and_then(|rest| rest.strip_prefix('.'))
            .filter(|rest| !rest.is_empty())
            .unwrap_or(id);
        if !is_tool_name(name) {
            return Err(refused(format!(
                "method {id}: {name:?} is not a tool name (letters, digits, `_`, `.` and `-`, at \
                 most 128)"
            )));
        }
        let fail = |why: String| refused(format!("method {id} ({label}): {why}"));
        if method.contains_key("mediaUpload") && !method.contains_key("request") {
            skipped.push(format!(
                "{name}: uploads media only, and code mode carries no binary body"
            ));
            return Ok(None);
        }
        if method.get("supportsMediaDownload") == Some(&Value::Bool(true))
            && !method.contains_key("response")
        {
            skipped.push(format!(
                "{name}: answers with media only, and code mode carries no binary body"
            ));
            return Ok(None);
        }
        let verb = match text("httpMethod") {
            "GET" => HttpMethod::Get,
            "HEAD" => HttpMethod::Head,
            "POST" => HttpMethod::Post,
            "PUT" => HttpMethod::Put,
            "PATCH" => HttpMethod::Patch,
            "DELETE" => HttpMethod::Delete,
            other => {
                return Err(fail(format!(
                    "its httpMethod {other:?} is none a tool sends"
                )));
            }
        };
        let path = match text("path") {
            "" => return Err(fail("it has no path".to_owned())),
            // Google's clients join a path that starts with `/` to the root,
            // past the service path.
            absolute if absolute.starts_with('/') => absolute.to_owned(),
            relative => format!("{}{relative}", self.prefix),
        };

        let empty = Map::new();
        let parameters = match method.get("parameters") {
            None => &empty,
            Some(parameters) => parameters
                .as_object()
                .ok_or_else(|| fail("its parameters are not an object".to_owned()))?,
        };
        let mut input = InputSchema::default();
        let mut query = Vec::new();
        let mut path_names = BTreeSet::new();
        for argument in parameter_order(method, parameters).map_err(&fail)? {
            let parameter = &parameters[argument];
            let schema = self
                .parameter_schema(parameter)
                .map_err(|why| fail(format!("parameter {argument}: {why}")))?;
            match parameter
                .get("location")
                .and_then(Value::as_str)
                .unwrap_or_default()
            {
                "path" => {
                    if parameter.get("repeated") == Some(&Value::Bool(true)) {
                        return Err(fail(format!("path parameter {argument} repeats")));
                    }
                    path_names.insert(argument.to_owned());
                    input.add(argument, schema, true).map_err(&fail)?;
                }
                "query" => {
                    let required = parameter.get("required") == Some(&Value::Bool(true));
                    input.add(argument, schema, required).map_err(&fail)?;
                    query.push(argument.to_owned());
                }
                other => {
                    return Err(fail(format!(
                        "parameter {argument} is in {other:?}; only path and query parameters \
                         translate"
                    )));
                }
            }
        }
        check_path_template(&path, &path_names, true).map_err(&fail)?;

        let request = method.get("request");
        let input_schema = match request {
            None => {
                let schema = input.into_schema();
                if serde_json::to_vec(&schema).map_or(usize::MAX, |bytes| bytes.len())
                    > MAX_SCHEMA_BYTES
                {
                    return Err(fail("its input schema is over 64 KiB".to_owned()));
                }
                schema
            }
            Some(request) => {
                let reference = request
                    .get("$ref")
                    .and_then(Value::as_str)
                    .ok_or_else(|| fail("its request names no schema".to_owned()))?;
                self.fitted(reference, |body| {
                    let mut input = input.clone();
                    input.add(BODY_ARGUMENT, body, true)?;
                    Ok(input.into_schema())
                })
                .map_err(&fail)?
                .ok_or_else(|| {
                    fail(
                        "its input schema fits no signature, even with its body untyped".to_owned(),
                    )
                })?
            }
        };
        let output_schema = method
            .get("response")
            .and_then(|response| response.get("$ref"))
            .and_then(Value::as_str)
            .and_then(|reference| self.fitted(reference, Ok).ok().flatten())
            .filter(|schema| schema.get("type") == Some(&Value::String("object".to_owned())));

        let read_only = matches!(verb, HttpMethod::Get | HttpMethod::Head);
        Ok(Some(TranslatedTool {
            name: name.to_owned(),
            description: text("description").trim().to_owned(),
            input_schema,
            output_schema,
            read_only,
            destructive: !read_only,
            idempotent: matches!(
                verb,
                HttpMethod::Get | HttpMethod::Head | HttpMethod::Put | HttpMethod::Delete
            ),
            http: HttpOperation {
                method: verb,
                path,
                query,
                idempotency_header: None,
                json_body: request.is_some(),
            },
        }))
    }

    /// One parameter as a schema: a scalar, or a list of scalars when it
    /// repeats (a query parameter given once per value).
    fn parameter_schema(&self, parameter: &Value) -> Result<Value, String> {
        let mut expansion = Expansion::new(self.schemas, MAX_REFERENCE_DEPTH);
        let mut schema = expansion.schema(parameter, &mut Vec::new(), 1)?;
        if parameter.get("repeated") == Some(&Value::Bool(true)) {
            let mut list = Map::new();
            list.insert("type".to_owned(), Value::String("array".to_owned()));
            if let Some(description) = schema.as_object_mut().and_then(|s| s.remove("description"))
            {
                list.insert("description".to_owned(), description);
            }
            list.insert("items".to_owned(), schema);
            schema = Value::Object(list);
        }
        Ok(schema)
    }

    /// What `build` makes of the schema `reference` names, inlined as deep
    /// as the result still fits both bounds. At depth 0 the reference keeps
    /// only its own words. `None` when not even that fits.
    fn fitted(
        &self,
        reference: &str,
        build: impl Fn(Value) -> Result<Value, String>,
    ) -> Result<Option<Value>, String> {
        let mut fitted = None;
        for depth in 0..=MAX_REFERENCE_DEPTH {
            let mut expansion = Expansion::new(self.schemas, depth);
            let schema = expansion.reference(reference, &Map::new(), &mut Vec::new(), 1)?;
            if expansion.nodes > MAX_NODES {
                break;
            }
            let schema = build(schema)?;
            if !fits_bounds(&schema) {
                break;
            }
            fitted = Some(schema);
            if !expansion.cut {
                // Nothing was left out for depth: a deeper one is the same.
                break;
            }
        }
        Ok(fitted)
    }
}

/// The method's parameter names: those `parameterOrder` lists first, in its
/// order, then the rest in the document's.
fn parameter_order<'a>(
    method: &'a Map<String, Value>,
    parameters: &'a Map<String, Value>,
) -> Result<Vec<&'a str>, String> {
    let mut order: Vec<&str> = Vec::new();
    for name in method
        .get("parameterOrder")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let name = name
            .as_str()
            .ok_or_else(|| "its parameterOrder holds a value that is not a name".to_owned())?;
        if !parameters.contains_key(name) {
            return Err(format!(
                "its parameterOrder names {name}, which is no parameter"
            ));
        }
        if !order.contains(&name) {
            order.push(name);
        }
    }
    for name in parameters.keys() {
        if !order.contains(&name.as_str()) {
            order.push(name);
        }
    }
    Ok(order)
}

/// Google's schema dialect as JSON Schema, references inlined at most
/// `depth` deep along each path.
struct Expansion<'a> {
    schemas: &'a Map<String, Value>,
    depth: usize,
    /// Nodes built so far, against [`MAX_NODES`].
    nodes: usize,
    /// Whether `depth`, not a cycle or the nesting bound, stopped some
    /// reference: a deeper expansion would type more.
    cut: bool,
}

impl<'a> Expansion<'a> {
    fn new(schemas: &'a Map<String, Value>, depth: usize) -> Self {
        Self {
            schemas,
            depth,
            nodes: 0,
            cut: false,
        }
    }

    /// The schema `name` refers to, inlined while the path holds fewer than
    /// `depth` references and does not hold `name` itself; else its own
    /// words. A description or flag beside the reference describes this
    /// use of it, so it wins over the target's.
    fn reference(
        &mut self,
        name: &str,
        beside: &Map<String, Value>,
        stack: &mut Vec<String>,
        nesting: usize,
    ) -> Result<Value, String> {
        let schemas = self.schemas;
        let target = schemas
            .get(name)
            .ok_or_else(|| format!("reference {name} names no schema in the document"))?;
        let cycle = stack.iter().any(|seen| seen == name);
        let deep = stack.len() >= self.depth;
        let mut schema = if cycle || deep || nesting >= MAX_NESTING {
            self.cut |= deep && !cycle && nesting < MAX_NESTING;
            Value::Object(target.as_object().map(words).unwrap_or_default())
        } else {
            stack.push(name.to_owned());
            let schema = self.schema(target, stack, nesting);
            stack.pop();
            schema?
        };
        if let Value::Object(fields) = &mut schema {
            let mut beside = words(beside);
            for key in ["description", "readOnly", "deprecated"] {
                if let Some(value) = beside.remove(key) {
                    fields.insert(key.to_owned(), value);
                }
            }
        }
        Ok(schema)
    }

    fn schema(
        &mut self,
        node: &Value,
        stack: &mut Vec<String>,
        nesting: usize,
    ) -> Result<Value, String> {
        self.nodes += 1;
        if self.nodes > MAX_NODES {
            // The caller sees the count and abandons this depth.
            return Ok(Value::Object(Map::new()));
        }
        let fields = node
            .as_object()
            .ok_or_else(|| "a schema is not an object".to_owned())?;
        if let Some(reference) = fields.get("$ref") {
            let name = reference
                .as_str()
                .ok_or_else(|| "a $ref is not a schema id".to_owned())?;
            return self.reference(name, fields, stack, nesting);
        }
        let mut out = words(fields);
        if let Some(properties) = fields.get("properties") {
            let properties = properties
                .as_object()
                .ok_or_else(|| "a schema's properties are not an object".to_owned())?;
            let mut translated = Map::new();
            let mut required = Vec::new();
            for (name, child) in properties {
                // Discovery marks a required field on the field itself.
                if child.get("required") == Some(&Value::Bool(true)) {
                    required.push(Value::String(name.clone()));
                }
                translated.insert(name.clone(), self.schema(child, stack, nesting + 1)?);
            }
            out.insert("properties".to_owned(), Value::Object(translated));
            if !required.is_empty() {
                out.insert("required".to_owned(), Value::Array(required));
            }
        }
        for key in ["items", "additionalProperties"] {
            match fields.get(key) {
                None => {}
                Some(flag @ Value::Bool(_)) => {
                    out.insert(key.to_owned(), flag.clone());
                }
                Some(child) => {
                    let child = self.schema(child, stack, nesting + 1)?;
                    out.insert(key.to_owned(), child);
                }
            }
        }
        Ok(Value::Object(out))
    }
}

/// A schema's own words as JSON Schema, without its fields: its type,
/// description, enum, format, pattern, numeric bounds (Google writes them
/// as strings), `readOnly` and `deprecated`. The rest of Google's words
/// (`id`, `enumDescriptions`, `annotations`, `location`, `default`, ...)
/// only annotate, and a default is the API's to apply.
fn words(fields: &Map<String, Value>) -> Map<String, Value> {
    let mut out = Map::new();
    for (key, value) in fields {
        let word = match key.as_str() {
            "type" if value.as_str().is_some_and(|kind| TYPES.contains(&kind)) => {
                Some(value.clone())
            }
            "description" | "format" | "pattern" if value.is_string() => Some(value.clone()),
            "readOnly" | "deprecated" if value.is_boolean() => Some(value.clone()),
            "enum" if value.as_array().is_some_and(|options| !options.is_empty()) => {
                Some(value.clone())
            }
            "minimum" | "maximum" => bound(value),
            _ => None,
        };
        if let Some(word) = word {
            out.insert(key.clone(), word);
        }
    }
    out
}

/// A numeric bound, given as a number or as Google's decimal string.
fn bound(value: &Value) -> Option<Value> {
    match value {
        Value::Number(_) => Some(value.clone()),
        Value::String(text) => text
            .parse::<i64>()
            .ok()
            .map(Number::from)
            .or_else(|| text.parse::<f64>().ok().and_then(Number::from_f64))
            .map(Value::Number),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn endpoint() -> Url {
        Url::parse("https://notes.example.com/").unwrap()
    }

    /// A small document in Google's shape: a nested resource, a cyclic
    /// schema, a repeated query parameter, string bounds, a reserved
    /// expansion, a JSON method that also takes media, and a media-only one.
    fn notes_document() -> Value {
        json!({
            "kind": "discovery#restDescription",
            "discoveryVersion": "v1",
            "name": "notes",
            "version": "v1",
            "rootUrl": "https://notes.example.com/",
            "servicePath": "notes/v1/",
            "baseUrl": "https://notes.example.com/notes/v1/",
            "parameters": {
                "key": {"type": "string", "location": "query"},
                "alt": {"type": "string", "enum": ["json", "media"], "location": "query"}
            },
            "schemas": {
                "Note": {"id": "Note", "type": "object", "properties": {
                    "id": {"type": "string", "readOnly": true},
                    "text": {"type": "string", "description": "What the note says."},
                    "size": {"type": "string", "format": "int64"},
                    "parent": {"$ref": "Note", "description": "The note this one answers."},
                    "tags": {"type": "array", "items": {"type": "string"}},
                    "labels": {"type": "object", "additionalProperties": {"type": "string"}}
                }},
                "ListNotesResponse": {"id": "ListNotesResponse", "type": "object", "properties": {
                    "notes": {"type": "array", "items": {"$ref": "Note"}},
                    "nextPageToken": {"type": "string"}
                }}
            },
            "resources": {
                "notes": {
                    "methods": {
                        "get": {
                            "id": "notes.notes.get", "path": "notes/{noteId}", "httpMethod": "GET",
                            "description": "Reads one note.",
                            "parameters": {
                                "view": {"type": "string", "enum": ["BASIC", "FULL"],
                                         "enumDescriptions": ["Text only.", "Everything."],
                                         "location": "query"},
                                "noteId": {"type": "string", "required": true, "location": "path"}
                            },
                            "parameterOrder": ["noteId"],
                            "response": {"$ref": "Note"}
                        },
                        "list": {
                            "id": "notes.notes.list", "path": "notes", "httpMethod": "GET",
                            "parameters": {
                                "pageSize": {"type": "integer", "format": "int32", "location": "query",
                                             "minimum": "1", "maximum": "100"},
                                "tag": {"type": "string", "repeated": true, "location": "query",
                                        "description": "Notes with every tag."}
                            },
                            "response": {"$ref": "ListNotesResponse"}
                        },
                        "create": {
                            "id": "notes.notes.create", "path": "notes", "httpMethod": "POST",
                            "request": {"$ref": "Note"}, "response": {"$ref": "Note"},
                            "supportsMediaUpload": true,
                            "mediaUpload": {"accept": ["*/*"], "protocols": {"simple": {
                                "multipart": true, "path": "/upload/notes/v1/notes"}}}
                        },
                        "export": {
                            "id": "notes.notes.export", "path": "notes/{noteId}:export",
                            "httpMethod": "GET", "supportsMediaDownload": true,
                            "parameters": {"noteId": {"type": "string", "required": true, "location": "path"}},
                            "parameterOrder": ["noteId"]
                        }
                    },
                    "resources": {
                        "comments": {"methods": {"delete": {
                            "id": "notes.notes.comments.delete", "path": "{+name}",
                            "httpMethod": "DELETE",
                            "parameters": {"name": {"type": "string", "required": true, "location": "path",
                                                    "pattern": "^notes/[^/]+/comments/[^/]+$"}},
                            "parameterOrder": ["name"]
                        }}}
                    }
                }
            }
        })
    }

    fn tool<'a>(translation: &'a Translation, name: &str) -> &'a TranslatedTool {
        translation
            .tools
            .iter()
            .find(|tool| tool.name == name)
            .unwrap_or_else(|| panic!("no tool {name}"))
    }

    fn refusal(document: &Value) -> String {
        match translate(document, &endpoint()) {
            Err(oneiron::Error::InvalidConfig(reason)) => reason,
            other => panic!("expected a refusal, got {:?}", other.map(|t| t.tools.len())),
        }
    }

    #[test]
    fn each_method_is_one_tool_named_past_the_api_name() {
        let translation = translate(&notes_document(), &endpoint()).unwrap();
        assert_eq!(translation.revision, "discovery-v1");
        let names: Vec<&str> = translation
            .tools
            .iter()
            .map(|tool| tool.name.as_str())
            .collect();
        assert_eq!(
            names,
            [
                "notes.get",
                "notes.list",
                "notes.create",
                "notes.comments.delete"
            ]
        );
        assert_eq!(
            translation.skipped,
            ["notes.export: answers with media only, and code mode carries no binary body"]
        );

        let get = tool(&translation, "notes.get");
        assert!(get.read_only && !get.destructive && get.idempotent);
        assert_eq!(get.description, "Reads one note.");
        assert_eq!(get.http.method, HttpMethod::Get);
        assert_eq!(get.http.path, "/notes/v1/notes/{noteId}");
        assert_eq!(get.http.query, ["view"]);
        assert!(!get.http.json_body);
        // `parameterOrder` first; Google's global parameters are none.
        assert_eq!(
            get.input_schema,
            json!({"type": "object", "properties": {
                "noteId": {"type": "string"},
                "view": {"type": "string", "enum": ["BASIC", "FULL"]}
            }, "required": ["noteId"], "additionalProperties": false})
        );

        let list = tool(&translation, "notes.list");
        assert_eq!(list.http.query, ["pageSize", "tag"]);
        assert_eq!(
            list.input_schema["properties"],
            json!({
                "pageSize": {"type": "integer", "minimum": 1, "maximum": 100},
                "tag": {"type": "array", "description": "Notes with every tag.",
                        "items": {"type": "string"}}
            })
        );

        // A method that also takes media is a tool for its JSON form.
        let create = tool(&translation, "notes.create");
        assert!(!create.read_only && create.destructive && !create.idempotent);
        assert!(create.http.json_body);
        assert_eq!(create.http.path, "/notes/v1/notes");
        assert_eq!(create.input_schema["required"], json!(["body"]));
        assert_eq!(
            create.input_schema["properties"]["body"]["properties"]["text"],
            json!({"type": "string", "description": "What the note says."})
        );

        let delete = tool(&translation, "notes.comments.delete");
        assert!(!delete.read_only && delete.destructive && delete.idempotent);
        assert_eq!(delete.http.path, "/notes/v1/{+name}");
        // Screening reads no `pattern` in an input; the API checks it.
        assert_eq!(
            delete.input_schema["properties"]["name"],
            json!({"type": "string"})
        );
    }

    #[test]
    fn a_cycle_keeps_the_referenced_schemas_own_words() {
        let translation = translate(&notes_document(), &endpoint()).unwrap();
        let output = tool(&translation, "notes.get")
            .output_schema
            .clone()
            .unwrap();
        assert_eq!(
            output["properties"]["parent"],
            json!({"type": "object", "description": "The note this one answers."})
        );
        assert_eq!(output["properties"]["id"]["readOnly"], json!(true));
        // A reply's schema only types it: its formats stay for the doc comment.
        assert_eq!(output["properties"]["size"]["format"], json!("int64"));
        assert_eq!(
            output["properties"]["labels"]["additionalProperties"],
            json!({"type": "string"})
        );

        let list = tool(&translation, "notes.list")
            .output_schema
            .clone()
            .unwrap();
        assert_eq!(
            list["properties"]["notes"]["items"]["properties"]["parent"]["type"],
            json!("object")
        );
        assert!(
            tool(&translation, "notes.comments.delete")
                .output_schema
                .is_none()
        );
    }

    #[test]
    fn a_schema_too_large_for_one_signature_is_typed_less_deep() {
        let mut document = notes_document();
        let leaf: Map<String, Value> = (0..40)
            .map(|index| {
                (
                    format!("field{index}"),
                    json!({"type": "string",
                           "description": "A field whose words take room in every signature."}),
                )
            })
            .collect();
        let wide: Map<String, Value> = (0..40)
            .map(|index| (format!("part{index}"), json!({"$ref": "Leaf"})))
            .collect();
        document["schemas"]["Leaf"] = json!({"id": "Leaf", "type": "object", "properties": leaf});
        document["schemas"]["Wide"] = json!({"id": "Wide", "type": "object", "properties": wide});
        document["resources"]["notes"]["methods"]["get"]["response"] = json!({"$ref": "Wide"});
        document["resources"]["notes"]["methods"]["create"]["request"] = json!({"$ref": "Wide"});

        let translation = translate(&document, &endpoint()).unwrap();
        let output = tool(&translation, "notes.get")
            .output_schema
            .clone()
            .unwrap();
        assert_eq!(output["properties"]["part0"], json!({"type": "object"}));
        assert!(fits_bounds(&output));
        let input = &tool(&translation, "notes.create").input_schema;
        assert_eq!(
            input["properties"]["body"]["properties"]["part39"],
            json!({"type": "object"})
        );
        assert!(fits_bounds(input));
    }

    #[test]
    fn a_root_on_another_origin_is_refused() {
        let mut document = notes_document();
        document["rootUrl"] = json!("https://other.example/");
        let reason = refusal(&document);
        assert!(reason.contains("https://other.example"), "{reason}");

        let mut document = notes_document();
        document["baseUrl"] = json!("http://notes.example.com/notes/v1/");
        assert!(refusal(&document).contains("baseUrl"));
    }

    #[test]
    fn what_cannot_translate_is_refused_naming_the_method() {
        let mut document = notes_document();
        document["resources"]["notes"]["methods"]["list"]
            .as_object_mut()
            .unwrap()
            .remove("id");
        assert!(refusal(&document).contains("GET notes has no id"));

        let mut document = notes_document();
        document["resources"]["notes"]["methods"]["create"]["request"] = json!({"$ref": "Missing"});
        let reason = refusal(&document);
        assert!(
            reason.contains("method notes.notes.create") && reason.contains("Missing"),
            "{reason}"
        );

        let mut document = notes_document();
        document["resources"]["notes"]["methods"]["get"]["parameters"]["view"]["location"] =
            json!("header");
        assert!(refusal(&document).contains("method notes.notes.get"));

        let mut document = notes_document();
        document["resources"]["notes"]["methods"]["list"]["id"] = json!("notes.notes.get");
        assert!(refusal(&document).contains("two methods are named notes.get"));

        let mut document = notes_document();
        document["discoveryVersion"] = json!("v2");
        assert!(refusal(&document).contains("Discovery \"v2\""));
    }
}
