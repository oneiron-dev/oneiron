//! OpenAPI 3.0 and 3.1 documents as connector tools (L8-31 D4).
//!
//! Each operation is one tool, named by its `operationId`: a guessed name
//! would drift silently when the document changes. Its input is one object
//! with a property per path, query and header parameter, plus `body` for a
//! JSON request body; its output is the first 2xx JSON response's schema.
//! Every `$ref` is resolved inside the document, and OpenAPI's own schema
//! words are rewritten into the JSON Schema the admission resolver reads.
//! What this module cannot translate faithfully refuses the whole document,
//! naming the operation, except an output schema, which only types the
//! reply: one it cannot read is dropped and the reply types as `unknown`.

use std::collections::{BTreeMap, BTreeSet};

use oneiron::connector_key::{HttpMethod, HttpOperation};
use reqwest::Url;
use serde_json::{Map, Value, json};

use super::{TranslatedTool, Translation, refused};

/// The methods a tool may use, in the order OpenAPI lists them.
const METHODS: [(&str, HttpMethod); 6] = [
    ("get", HttpMethod::Get),
    ("put", HttpMethod::Put),
    ("post", HttpMethod::Post),
    ("delete", HttpMethod::Delete),
    ("patch", HttpMethod::Patch),
    ("head", HttpMethod::Head),
];

/// Methods with no tool: no effect an agent asks for.
const SKIPPED_METHODS: [&str; 2] = ["options", "trace"];

/// Headers the host itself sets: the credential door's, the body's and the
/// connection's. A document parameter cannot take one.
const HOST_HEADERS: [&str; 7] = [
    "authorization",
    "cookie",
    "host",
    "content-type",
    "content-length",
    "transfer-encoding",
    "connection",
];

/// The name of the argument that holds the request body.
pub(crate) const BODY_ARGUMENT: &str = "body";

/// The literal schema bound the resolver applies (manifest_drift.rs).
const MAX_SCHEMA_BYTES: usize = 65_536;

/// How deep a schema or a chain of `$ref`s may go.
const MAX_DEPTH: usize = 24;

/// The words a `$ref`'s siblings may carry and still read as the target
/// itself: none changes what the schema admits, except `nullable`, which
/// widens the target's type by `null`.
const ANNOTATIONS: [&str; 9] = [
    "description",
    "title",
    "summary",
    "deprecated",
    "readOnly",
    "writeOnly",
    "example",
    "examples",
    "nullable",
];

pub(super) fn translate(document: &Value, endpoint: &Url) -> oneiron::Result<Translation> {
    let version = document
        .get("openapi")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !(version.starts_with("3.0") || version.starts_with("3.1")) {
        return Err(refused(format!(
            "the document is OpenAPI {version:?}; only 3.0 and 3.1 translate"
        )));
    }
    check_servers(document.get("servers"), endpoint, "the document")?;
    let paths = document
        .get("paths")
        .and_then(Value::as_object)
        .ok_or_else(|| refused("the OpenAPI document has no paths".to_owned()))?;
    let schemes = SecuritySchemes::read(document)?;
    let mut translation = Translation::default();
    let mut names = BTreeSet::new();
    for (path, item) in paths {
        let item = deref(item, document).map_err(refused)?;
        let item = item
            .as_object()
            .ok_or_else(|| refused(format!("path {path} is not an object")))?;
        check_servers(item.get("servers"), endpoint, &format!("path {path}"))?;
        for method in SKIPPED_METHODS {
            if item.contains_key(method) {
                translation.skipped.push(format!(
                    "{} {path}: no tool for this method",
                    method.to_ascii_uppercase()
                ));
            }
        }
        for (key, method) in METHODS {
            let Some(operation) = item.get(key) else {
                continue;
            };
            let tool = Operation {
                document,
                endpoint,
                schemes: &schemes,
                path,
                method,
                path_parameters: item.get("parameters"),
                operation,
            }
            .translate()?;
            if !names.insert(tool.name.clone()) {
                return Err(refused(format!(
                    "operationId {} names two operations",
                    tool.name
                )));
            }
            translation.tools.push(tool);
        }
    }
    if translation.tools.is_empty() {
        return Err(refused(
            "the OpenAPI document lists no operation".to_owned(),
        ));
    }
    Ok(translation)
}

struct Operation<'a> {
    document: &'a Value,
    endpoint: &'a Url,
    schemes: &'a SecuritySchemes,
    path: &'a str,
    method: HttpMethod,
    path_parameters: Option<&'a Value>,
    operation: &'a Value,
}

impl Operation<'_> {
    fn translate(&self) -> oneiron::Result<TranslatedTool> {
        let label = format!("{} {}", self.method.as_str(), self.path);
        let operation = self
            .operation
            .as_object()
            .ok_or_else(|| refused(format!("operation {label} is not an object")))?;
        let name = operation
            .get("operationId")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if name.is_empty() {
            return Err(refused(format!(
                "operation {label} has no operationId: a tool needs a name the document keeps"
            )));
        }
        if name.len() > 128
            || !name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
        {
            return Err(refused(format!(
                "operation {label}: operationId {name:?} is not a tool name (letters, digits, \
                 `_`, `.` and `-`, at most 128)"
            )));
        }
        let fail = |why: String| refused(format!("operation {name} ({label}): {why}"));
        check_servers(
            operation.get("servers"),
            self.endpoint,
            &format!("operation {name}"),
        )?;
        self.schemes
            .check(operation.get("security").or(self.schemes.default.as_ref()))
            .map_err(&fail)?;

        let mut input = InputSchema::default();
        let mut idempotency_header = None;
        let mut query = Vec::new();
        let mut path_names = BTreeSet::new();
        for parameter in self.parameters().map_err(&fail)? {
            let Parameter {
                name: argument,
                location,
                required,
                schema,
            } = parameter;
            match location.as_str() {
                "path" => {
                    path_names.insert(argument.clone());
                    input.add(&argument, schema, true).map_err(&fail)?;
                }
                "query" => {
                    input.add(&argument, schema, required).map_err(&fail)?;
                    query.push(argument);
                }
                "header" if argument.eq_ignore_ascii_case("idempotency-key") => {
                    idempotency_header = Some(argument);
                }
                "header" => {
                    if HOST_HEADERS
                        .iter()
                        .any(|host| argument.eq_ignore_ascii_case(host))
                    {
                        return Err(fail(format!(
                            "header parameter {argument} is one the host sets"
                        )));
                    }
                    let mut schema = schema;
                    if let Value::Object(fields) = &mut schema {
                        fields.insert("x-mcp-header".to_owned(), Value::String(argument.clone()));
                    } else {
                        return Err(fail(format!(
                            "header parameter {argument} needs an object schema"
                        )));
                    }
                    input.add(&argument, schema, required).map_err(&fail)?;
                }
                other => {
                    return Err(fail(format!(
                        "parameter {argument} is in {other:?}; only path, query and header \
                         parameters translate"
                    )));
                }
            }
        }
        check_path_template(self.path, &path_names).map_err(&fail)?;
        let json_body = match operation.get("requestBody") {
            None => false,
            Some(body) => {
                let (schema, required) = self.request_body(body).map_err(&fail)?;
                input.add(BODY_ARGUMENT, schema, required).map_err(&fail)?;
                true
            }
        };
        let input_schema = input.into_schema();
        if serde_json::to_vec(&input_schema)
            .map(|bytes| bytes.len())
            .unwrap_or(usize::MAX)
            > MAX_SCHEMA_BYTES
        {
            return Err(fail("its input schema is over 64 KiB".to_owned()));
        }

        let read_only = matches!(self.method, HttpMethod::Get | HttpMethod::Head);
        let destructive =
            !read_only && operation.get("x-oneiron-destructive") != Some(&Value::Bool(false));
        let idempotent = match self.method {
            HttpMethod::Get | HttpMethod::Head | HttpMethod::Put | HttpMethod::Delete => true,
            HttpMethod::Post | HttpMethod::Patch => idempotency_header.is_some(),
        };
        Ok(TranslatedTool {
            name: name.to_owned(),
            description: description(operation),
            input_schema,
            output_schema: self.output_schema(operation),
            read_only,
            destructive,
            idempotent,
            http: HttpOperation {
                method: self.method,
                path: self.path.to_owned(),
                query,
                idempotency_header,
                json_body,
            },
        })
    }

    /// The path item's parameters with the operation's own, the operation's
    /// winning where both name one place.
    fn parameters(&self) -> Result<Vec<Parameter>, String> {
        let mut by_place: BTreeMap<(String, String), (usize, Parameter)> = BTreeMap::new();
        let lists = [self.path_parameters, self.operation.get("parameters")];
        let mut order = 0;
        for list in lists.into_iter().flatten() {
            let list = list
                .as_array()
                .ok_or_else(|| "its parameters are not a list".to_owned())?;
            for parameter in list {
                let parameter = Parameter::read(parameter, self.document)?;
                let key = (
                    parameter.location.clone(),
                    parameter.name.to_ascii_lowercase(),
                );
                let place = by_place.get(&key).map_or(order, |(place, _)| *place);
                order += 1;
                by_place.insert(key, (place, parameter));
            }
        }
        let mut parameters: Vec<_> = by_place.into_values().collect();
        parameters.sort_by_key(|(place, _)| *place);
        Ok(parameters
            .into_iter()
            .map(|(_, parameter)| parameter)
            .collect())
    }

    fn request_body(&self, body: &Value) -> Result<(Value, bool), String> {
        let body = deref(body, self.document)?;
        let required = body.get("required") == Some(&Value::Bool(true));
        let content = body
            .get("content")
            .and_then(Value::as_object)
            .ok_or_else(|| "its request body names no content".to_owned())?;
        let schema = json_content(content)
            .ok_or_else(|| "its request body is not application/json".to_owned())?
            .get("schema")
            .map(|schema| normalize(schema, self.document, &mut Vec::new(), 0))
            .transpose()?
            .unwrap_or_else(|| json!({}));
        Ok((schema, required))
    }

    /// The first 2xx JSON response's schema when it is an object one. The
    /// output only types the reply, so one this cannot read is dropped.
    fn output_schema(&self, operation: &Map<String, Value>) -> Option<Value> {
        let responses = operation.get("responses")?.as_object()?;
        let mut codes: Vec<&String> = responses
            .keys()
            .filter(|code| code.starts_with('2'))
            .collect();
        // Exact codes first, in order, then the `2XX` range.
        codes.sort_by(|a, b| {
            (a.eq_ignore_ascii_case("2XX"), a.as_str())
                .cmp(&(b.eq_ignore_ascii_case("2XX"), b.as_str()))
        });
        let response = deref(responses.get(codes.first()?.as_str())?, self.document).ok()?;
        let content = response.get("content")?.as_object()?;
        let schema = json_content(content)?.get("schema")?;
        let schema = normalize(schema, self.document, &mut Vec::new(), 0).ok()?;
        let object = schema.get("type") == Some(&json!("object"))
            || schema.get("type").is_none() && schema.get("properties").is_some();
        let size = serde_json::to_vec(&schema).ok()?.len();
        (object && size <= MAX_SCHEMA_BYTES).then_some(schema)
    }
}

struct Parameter {
    name: String,
    location: String,
    required: bool,
    schema: Value,
}

impl Parameter {
    fn read(parameter: &Value, document: &Value) -> Result<Self, String> {
        let parameter = deref(parameter, document)?;
        let name = parameter
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| "a parameter has no name".to_owned())?
            .to_owned();
        let location = parameter
            .get("in")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("parameter {name} names no place (`in`)"))?
            .to_owned();
        if parameter.get("content").is_some() {
            return Err(format!(
                "parameter {name} is given by content; only a schema translates"
            ));
        }
        let mut schema = match parameter.get("schema") {
            Some(schema) => normalize(schema, document, &mut Vec::new(), 0)?,
            None => return Err(format!("parameter {name} has no schema")),
        };
        if let (Value::Object(fields), Some(text)) = (&mut schema, parameter.get("description"))
            && !fields.contains_key("description")
        {
            fields.insert("description".to_owned(), text.clone());
        }
        Ok(Self {
            name,
            location,
            required: parameter.get("required") == Some(&Value::Bool(true)),
            schema,
        })
    }
}

#[derive(Default)]
struct InputSchema {
    properties: Map<String, Value>,
    required: Vec<Value>,
}

impl InputSchema {
    fn add(&mut self, name: &str, schema: Value, required: bool) -> Result<(), String> {
        if self.properties.contains_key(name) {
            return Err(format!("two of its arguments are named {name}"));
        }
        self.properties.insert(name.to_owned(), schema);
        if required {
            self.required.push(Value::String(name.to_owned()));
        }
        Ok(())
    }

    fn into_schema(self) -> Value {
        let mut schema = Map::new();
        schema.insert("type".to_owned(), json!("object"));
        schema.insert("properties".to_owned(), Value::Object(self.properties));
        if !self.required.is_empty() {
            schema.insert("required".to_owned(), Value::Array(self.required));
        }
        schema.insert("additionalProperties".to_owned(), Value::Bool(false));
        Value::Object(schema)
    }
}

/// The operation's summary, then its description.
fn description(operation: &Map<String, Value>) -> String {
    let text = |key: &str| {
        operation
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|text| !text.is_empty())
    };
    match (text("summary"), text("description")) {
        (Some(summary), Some(description)) => format!("{summary}\n\n{description}"),
        (Some(text), None) | (None, Some(text)) => text.to_owned(),
        (None, None) => String::new(),
    }
}

/// `application/json` content, else the first `+json` media type.
fn json_content(content: &Map<String, Value>) -> Option<&Value> {
    let media = |key: &str| {
        key.split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
    };
    content
        .iter()
        .find(|(key, _)| media(key) == "application/json")
        .or_else(|| {
            content
                .iter()
                .find(|(key, _)| media(key).ends_with("+json"))
        })
        .map(|(_, value)| value)
}

/// Every `{name}` in the path is a path parameter, and every path parameter
/// has its place in the path.
fn check_path_template(path: &str, parameters: &BTreeSet<String>) -> Result<(), String> {
    if !path.starts_with('/') {
        return Err(format!("its path {path:?} does not start with `/`"));
    }
    // A dot segment would move the call out from under the endpoint's path
    // once the URL is normalized; `?` and `#` would end the path.
    if path
        .split('/')
        .any(|segment| segment == "." || segment == "..")
        || path.contains(['?', '#', '%', '\\'])
    {
        return Err(format!(
            "its path {path:?} has a dot segment, `?`, `#`, `%` or `\\`"
        ));
    }
    let mut named = BTreeSet::new();
    let mut rest = path;
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        let close = after
            .find('}')
            .ok_or_else(|| format!("its path {path:?} has an unclosed `{{`"))?;
        named.insert(after[..close].to_owned());
        rest = &after[close + 1..];
    }
    if rest.contains('}') {
        return Err(format!("its path {path:?} has a stray `}}`"));
    }
    if let Some(missing) = named.difference(parameters).next() {
        return Err(format!(
            "its path names {{{missing}}}, which no parameter fills"
        ));
    }
    if let Some(unplaced) = parameters.difference(&named).next() {
        return Err(format!(
            "path parameter {unplaced} has no place in its path"
        ));
    }
    Ok(())
}

/// A `servers` entry may only name the installed endpoint's own origin: a
/// call goes to the endpoint the host installed, never where the document
/// points. A relative server URL is a path the endpoint already carries.
fn check_servers(servers: Option<&Value>, endpoint: &Url, at: &str) -> oneiron::Result<()> {
    for server in servers.and_then(Value::as_array).into_iter().flatten() {
        let Some(url) = server.get("url").and_then(Value::as_str) else {
            continue;
        };
        if url.contains('{') {
            return Err(refused(format!(
                "{at}: server URL {url} has variables; install the endpoint it resolves to"
            )));
        }
        let Ok(parsed) = Url::parse(url) else {
            continue;
        };
        if parsed.origin() != endpoint.origin() {
            return Err(refused(format!(
                "{at} sends to {}, not the installed endpoint's origin {}",
                parsed.origin().ascii_serialization(),
                endpoint.origin().ascii_serialization()
            )));
        }
    }
    Ok(())
}

/// The security schemes the host can present: each takes the connector's
/// custody secret as the `Authorization` header, as an MCP connector's does.
struct SecuritySchemes {
    presented: BTreeSet<String>,
    unsupported: BTreeMap<String, String>,
    default: Option<Value>,
}

impl SecuritySchemes {
    fn read(document: &Value) -> oneiron::Result<Self> {
        let mut presented = BTreeSet::new();
        let mut unsupported = BTreeMap::new();
        let schemes = document
            .pointer("/components/securitySchemes")
            .and_then(Value::as_object);
        for (name, scheme) in schemes.into_iter().flatten() {
            let scheme = deref(scheme, document).map_err(refused)?;
            let kind = scheme
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let http = scheme
                .get("scheme")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_ascii_lowercase();
            match kind {
                "http" if http == "bearer" || http == "basic" => {
                    presented.insert(name.clone());
                }
                "oauth2" | "openIdConnect" => {
                    presented.insert(name.clone());
                }
                "http" => {
                    unsupported.insert(name.clone(), format!("http {http}"));
                }
                other => {
                    unsupported.insert(name.clone(), other.to_owned());
                }
            }
        }
        Ok(Self {
            presented,
            unsupported,
            default: document.get("security").cloned(),
        })
    }

    /// One alternative of the requirement list must be met by the
    /// `Authorization` header alone (or by nothing).
    fn check(&self, security: Option<&Value>) -> Result<(), String> {
        let Some(alternatives) = security.and_then(Value::as_array) else {
            return Ok(());
        };
        if alternatives.is_empty() {
            return Ok(());
        }
        let mut seen = Vec::new();
        for alternative in alternatives {
            let Some(names) = alternative.as_object() else {
                continue;
            };
            if names.len() <= 1 && names.keys().all(|name| self.presented.contains(name)) {
                return Ok(());
            }
            seen.extend(names.keys().map(|name| match self.unsupported.get(name) {
                Some(kind) => format!("{name} ({kind})"),
                None => name.clone(),
            }));
        }
        Err(format!(
            "its security ({}) is none the host presents: an `Authorization` header from the \
             connector's custody secret (http bearer or basic, oauth2, openIdConnect)",
            seen.join(", ")
        ))
    }
}

/// Follows a `$ref` to a component (a parameter, a request body, a
/// response, a path item) inside the document.
fn deref<'a>(node: &'a Value, document: &'a Value) -> Result<&'a Value, String> {
    let mut node = node;
    let mut seen = Vec::new();
    while let Some(reference) = node.get("$ref").and_then(Value::as_str) {
        let target = pointer_target(reference, document, &seen)?;
        seen.push(reference.to_owned());
        if seen.len() > MAX_DEPTH {
            return Err(format!("reference {reference} chains too deep"));
        }
        node = target;
    }
    Ok(node)
}

fn pointer_target<'a>(
    reference: &str,
    document: &'a Value,
    stack: &[String],
) -> Result<&'a Value, String> {
    let Some(pointer) = reference.strip_prefix('#') else {
        return Err(format!(
            "reference {reference} points outside the document; only local references translate"
        ));
    };
    if stack.iter().any(|seen| seen == reference) {
        return Err(format!("reference {reference} refers to itself"));
    }
    document
        .pointer(pointer)
        .ok_or_else(|| format!("reference {reference} names nothing in the document"))
}

/// OpenAPI's schema object as the JSON Schema the admission resolver reads:
/// references inlined, `nullable` as a `null` type, 3.0's boolean
/// exclusive bounds as numbers, `example` as `examples`, and the words that
/// only annotate (`discriminator`, `xml`, `externalDocs`, `x-*`) dropped.
fn normalize(
    node: &Value,
    document: &Value,
    stack: &mut Vec<String>,
    depth: usize,
) -> Result<Value, String> {
    if depth > MAX_DEPTH {
        return Err("a schema nests too deep".to_owned());
    }
    let fields = match node {
        Value::Bool(_) => return Ok(node.clone()),
        Value::Object(fields) => fields,
        _ => return Err("a schema is not an object".to_owned()),
    };
    if let Some(reference) = fields.get("$ref").and_then(Value::as_str) {
        let target = pointer_target(reference, document, stack)?;
        stack.push(reference.to_owned());
        let resolved = normalize(target, document, stack, depth + 1);
        stack.pop();
        let resolved = resolved?;
        let siblings: Map<String, Value> = fields
            .iter()
            .filter(|(key, _)| key.as_str() != "$ref")
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        if siblings.is_empty() {
            return Ok(resolved);
        }
        // 3.1 lets a reference carry its own words, and both hold. Words
        // that only annotate overlay the target; any other is a conjunct.
        if let Value::Object(mut target) = resolved {
            if siblings
                .keys()
                .all(|key| ANNOTATIONS.contains(&key.as_str()))
            {
                let own = normalize(&Value::Object(siblings), document, stack, depth + 1)?;
                let Value::Object(own) = own else {
                    unreachable!("an object normalizes to an object")
                };
                target.extend(own);
                if fields.get("nullable") == Some(&Value::Bool(true)) {
                    allow_null(&mut target);
                }
                return Ok(Value::Object(target));
            }
            let mut own = normalize(&Value::Object(siblings), document, stack, depth + 1)?;
            if let Value::Object(own) = &mut own {
                match own.get_mut("allOf") {
                    Some(Value::Array(conjuncts)) => conjuncts.push(Value::Object(target)),
                    _ => {
                        own.insert(
                            "allOf".to_owned(),
                            Value::Array(vec![Value::Object(target)]),
                        );
                    }
                }
            }
            return Ok(own);
        }
        return Ok(resolved);
    }
    let mut out = Map::new();
    for (key, value) in fields {
        match key.as_str() {
            "nullable" | "discriminator" | "xml" | "externalDocs" | "summary" => {}
            _ if key.starts_with("x-") => {}
            "example" => {
                if !fields.contains_key("examples") {
                    out.insert("examples".to_owned(), Value::Array(vec![value.clone()]));
                }
            }
            "properties" | "patternProperties" | "dependentSchemas" | "$defs" | "definitions" => {
                let entries = value
                    .as_object()
                    .ok_or_else(|| format!("a schema's {key} is not an object"))?;
                let mut normalized = Map::new();
                for (name, child) in entries {
                    normalized.insert(name.clone(), normalize(child, document, stack, depth + 1)?);
                }
                out.insert(key.clone(), Value::Object(normalized));
            }
            "items"
            | "additionalProperties"
            | "not"
            | "if"
            | "then"
            | "else"
            | "contains"
            | "propertyNames" => {
                out.insert(key.clone(), normalize(value, document, stack, depth + 1)?);
            }
            "allOf" | "anyOf" | "oneOf" | "prefixItems" => {
                let variants = value
                    .as_array()
                    .ok_or_else(|| format!("a schema's {key} is not a list"))?;
                let normalized = variants
                    .iter()
                    .map(|variant| normalize(variant, document, stack, depth + 1))
                    .collect::<Result<Vec<_>, _>>()?;
                out.insert(key.clone(), Value::Array(normalized));
            }
            "exclusiveMinimum" | "exclusiveMaximum" => match value {
                Value::Bool(true) => {
                    let bound = if key == "exclusiveMinimum" {
                        "minimum"
                    } else {
                        "maximum"
                    };
                    if let Some(limit) = fields.get(bound) {
                        out.insert(key.clone(), limit.clone());
                    }
                }
                Value::Bool(false) => {}
                _ => {
                    out.insert(key.clone(), value.clone());
                }
            },
            "minimum" | "maximum" => {
                let exclusive = if key == "minimum" {
                    "exclusiveMinimum"
                } else {
                    "exclusiveMaximum"
                };
                if fields.get(exclusive) != Some(&Value::Bool(true)) {
                    out.insert(key.clone(), value.clone());
                }
            }
            _ => {
                out.insert(key.clone(), value.clone());
            }
        }
    }
    if fields.get("nullable") == Some(&Value::Bool(true)) {
        allow_null(&mut out);
    }
    Ok(Value::Object(out))
}

/// OpenAPI 3.0's `nullable: true`: the schema's type also admits `null`.
fn allow_null(schema: &mut Map<String, Value>) {
    match schema.get_mut("type") {
        Some(Value::String(kind)) => {
            let kind = std::mem::take(kind);
            schema.insert("type".to_owned(), json!([kind, "null"]));
        }
        Some(Value::Array(kinds)) if !kinds.contains(&json!("null")) => {
            kinds.push(json!("null"));
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint() -> Url {
        Url::parse("http://127.0.0.1:9/api").unwrap()
    }

    fn notes_document() -> Value {
        json!({
            "openapi": "3.1.0",
            "info": {"title": "Notes", "version": "1"},
            "servers": [{"url": "/api"}],
            "security": [{"bearer": []}],
            "components": {
                "securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}},
                "schemas": {
                    "Note": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string"},
                            "text": {"type": "string", "nullable": true},
                            "tags": {"type": "array", "items": {"type": "string"}}
                        },
                        "required": ["id"]
                    }
                },
                "parameters": {
                    "NoteId": {"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}
                }
            },
            "paths": {
                "/notes/{id}": {
                    "parameters": [{"$ref": "#/components/parameters/NoteId"}],
                    "get": {
                        "operationId": "getNote",
                        "summary": "Read one note.",
                        "responses": {"200": {"description": "ok", "content": {
                            "application/json": {"schema": {"$ref": "#/components/schemas/Note"}}}}}
                    },
                    "delete": {"operationId": "deleteNote", "responses": {"204": {"description": "gone"}}}
                },
                "/notes": {
                    "get": {
                        "operationId": "listNotes",
                        "parameters": [{"name": "tag", "in": "query", "schema": {"type": "string"}}],
                        "responses": {"200": {"description": "ok", "content": {"application/json": {
                            "schema": {"type": "array", "items": {"$ref": "#/components/schemas/Note"}}}}}}
                    },
                    "post": {
                        "operationId": "createNote",
                        "parameters": [
                            {"name": "Idempotency-Key", "in": "header", "required": true, "schema": {"type": "string"}},
                            {"name": "X-Trace", "in": "header", "schema": {"type": "string"}}
                        ],
                        "requestBody": {"required": true, "content": {"application/json": {
                            "schema": {"$ref": "#/components/schemas/Note"}}}},
                        "responses": {"201": {"description": "made", "content": {"application/json": {
                            "schema": {"$ref": "#/components/schemas/Note"}}}}}
                    },
                    "options": {"operationId": "notesOptions", "responses": {"200": {"description": "ok"}}}
                }
            }
        })
    }

    fn tool<'a>(translation: &'a Translation, name: &str) -> &'a TranslatedTool {
        translation
            .tools
            .iter()
            .find(|tool| tool.name == name)
            .unwrap()
    }

    #[test]
    fn each_operation_is_one_tool_with_its_place_and_hints() {
        let translation = translate(&notes_document(), &endpoint()).unwrap();
        let names: Vec<&str> = translation
            .tools
            .iter()
            .map(|tool| tool.name.as_str())
            .collect();
        assert_eq!(names, ["getNote", "deleteNote", "listNotes", "createNote"]);
        assert_eq!(
            translation.skipped,
            ["OPTIONS /notes: no tool for this method"]
        );

        let get = tool(&translation, "getNote");
        assert!(get.read_only && !get.destructive && get.idempotent);
        assert_eq!(get.http.method, HttpMethod::Get);
        assert_eq!(get.http.path, "/notes/{id}");
        assert_eq!(get.description, "Read one note.");
        assert_eq!(
            get.input_schema,
            json!({"type": "object", "properties": {"id": {"type": "string"}},
                   "required": ["id"], "additionalProperties": false})
        );
        assert_eq!(
            get.output_schema.as_ref().unwrap()["properties"]["text"]["type"],
            json!(["string", "null"])
        );

        let delete = tool(&translation, "deleteNote");
        assert!(!delete.read_only && delete.destructive && delete.idempotent);
        assert!(delete.output_schema.is_none());

        let list = tool(&translation, "listNotes");
        assert_eq!(list.http.query, ["tag"]);
        // An array reply is not an object: it types as `unknown`.
        assert!(list.output_schema.is_none());

        let create = tool(&translation, "createNote");
        assert!(!create.read_only && create.destructive && create.idempotent);
        assert_eq!(
            create.http.idempotency_header.as_deref(),
            Some("Idempotency-Key")
        );
        assert!(create.http.json_body);
        let properties = create.input_schema["properties"].as_object().unwrap();
        assert_eq!(properties.keys().collect::<Vec<_>>(), ["X-Trace", "body"]);
        assert_eq!(properties["X-Trace"]["x-mcp-header"], json!("X-Trace"));
        assert_eq!(create.input_schema["required"], json!(["body"]));
    }

    #[test]
    fn a_post_without_an_idempotency_key_is_at_most_once() {
        let mut document = notes_document();
        document["paths"]["/notes"]["post"]["parameters"] = json!([]);
        document["paths"]["/notes"]["post"]["x-oneiron-destructive"] = json!(false);
        let translation = translate(&document, &endpoint()).unwrap();
        let create = tool(&translation, "createNote");
        assert!(!create.idempotent && !create.destructive);
        assert!(create.http.idempotency_header.is_none());
    }

    fn refusal(document: &Value) -> String {
        match translate(document, &endpoint()) {
            Err(oneiron::Error::InvalidConfig(reason)) => reason,
            other => panic!("expected a refusal, got {:?}", other.map(|t| t.tools.len())),
        }
    }

    #[test]
    fn what_cannot_translate_is_refused_naming_the_operation() {
        let mut document = notes_document();
        document["paths"]["/notes/{id}"]["delete"]
            .as_object_mut()
            .unwrap()
            .remove("operationId");
        assert!(refusal(&document).contains("DELETE /notes/{id} has no operationId"));

        let mut document = notes_document();
        document["paths"]["/notes"]["post"]["requestBody"]["content"]["application/json"]["schema"] =
            json!({"$ref": "https://schemas.example/note.json"});
        let reason = refusal(&document);
        assert!(reason.contains("operation createNote") && reason.contains("outside the document"));

        let mut document = notes_document();
        document["components"]["schemas"]["Note"]["properties"]["parent"] =
            json!({"$ref": "#/components/schemas/Note"});
        assert!(refusal(&document).contains("refers to itself"));

        let mut document = notes_document();
        document["paths"]["/notes"]["get"]["parameters"] =
            json!([{"name": "session", "in": "cookie", "schema": {"type": "string"}}]);
        assert!(refusal(&document).contains("operation listNotes"));

        let mut document = notes_document();
        document["paths"]["/notes"]["get"]["operationId"] = json!("getNote");
        assert!(refusal(&document).contains("names two operations"));
    }

    #[test]
    fn the_document_cannot_name_another_origin() {
        let mut document = notes_document();
        document["servers"] = json!([{"url": "https://other.example/api"}]);
        let reason = refusal(&document);
        assert!(reason.contains("https://other.example"), "{reason}");

        let mut document = notes_document();
        document["servers"] = json!([{"url": "http://127.0.0.1:9/api"}]);
        assert!(translate(&document, &endpoint()).is_ok());
    }

    #[test]
    fn a_scheme_the_host_cannot_present_is_refused() {
        let mut document = notes_document();
        document["components"]["securitySchemes"]["key"] =
            json!({"type": "apiKey", "in": "query", "name": "key"});
        document["security"] = json!([{"key": []}]);
        let reason = refusal(&document);
        assert!(reason.contains("key (apiKey)"), "{reason}");
    }

    #[test]
    fn openapi_3_0_bounds_and_examples_read_as_json_schema() {
        let schema = json!({"type": "integer", "minimum": 1, "exclusiveMinimum": true,
                            "example": 3, "x-internal": true, "discriminator": {"propertyName": "k"}});
        let normalized = normalize(&schema, &json!({}), &mut Vec::new(), 0).unwrap();
        assert_eq!(
            normalized,
            json!({"type": "integer", "exclusiveMinimum": 1, "examples": [3]})
        );
    }
}
