//! API documents as connector tools (L8-31, canon agent-runtime
//! `#translator-inputs`: "The generic translator also takes OpenAPI and
//! Google Discovery documents").
//!
//! A document is a second way to list a connector's tools: each operation
//! becomes the same [`ListedTool`] an MCP `tools/list` entry does, and from
//! there the built admission takes over unchanged (screening, resolve, the
//! slate, the owner's stamp, consent and the scoped grant check). What MCP
//! learns from the wire, a translated tool carries in its
//! [`HttpOperation`]: where its call goes under the installed endpoint.
//!
//! The format is read from the document itself: an `openapi` key is an
//! OpenAPI 3.0 or 3.1 document, a `discoveryVersion` key a Google Discovery
//! one.
//!
//! [`ListedTool`]: crate::connector_admission_host::ListedTool

mod discovery;
mod openapi;

use std::collections::BTreeSet;

use oneiron::connector_key::HttpOperation;
use reqwest::Url;
use serde_json::{Map, Value, json};

/// The largest document the host reads, from a file or a fetch.
pub(crate) const MAX_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;

/// The name of the argument that holds the request body.
pub(crate) const BODY_ARGUMENT: &str = "body";

/// The literal schema bound the admission resolver applies
/// (manifest_drift.rs).
const MAX_SCHEMA_BYTES: usize = 65_536;

/// One operation as a tool, before admission.
#[derive(Debug, Clone)]
pub(crate) struct TranslatedTool {
    pub(crate) name: String,
    pub(crate) description: String,
    pub(crate) input_schema: Value,
    /// The reply's schema, when the document declares an object one.
    pub(crate) output_schema: Option<Value>,
    pub(crate) read_only: bool,
    pub(crate) destructive: bool,
    /// A retry after an ambiguous reply sends no second effect.
    pub(crate) idempotent: bool,
    pub(crate) http: HttpOperation,
}

#[derive(Debug, Default)]
pub(crate) struct Translation {
    /// The document's format and version, as the connector key pins it in
    /// place of an MCP protocol revision: `openapi-3.0`, `openapi-3.1` or
    /// `discovery-v1`.
    pub(crate) revision: String,
    pub(crate) tools: Vec<TranslatedTool>,
    /// What the document holds that became no tool, each with why. The
    /// register reply lists them.
    pub(crate) skipped: Vec<String>,
}

/// Translates `document` (JSON or YAML) for the connector installed at
/// `endpoint`. Every call of the result goes to `endpoint`.
pub(crate) fn translate(document: &[u8], endpoint: &str) -> oneiron::Result<Translation> {
    if document.len() > MAX_DOCUMENT_BYTES {
        return Err(refused(format!(
            "the API document is over {} MiB",
            MAX_DOCUMENT_BYTES / (1024 * 1024)
        )));
    }
    let endpoint = Url::parse(endpoint)
        .map_err(|_| refused("the installed endpoint is not a URL".to_owned()))?;
    let document: Value = match serde_json::from_slice(document) {
        Ok(document) => document,
        Err(_) => serde_yaml_ng::from_slice(document)
            .map_err(|_| refused("the API document is neither JSON nor YAML".to_owned()))?,
    };
    if document.get("openapi").is_some() {
        return openapi::translate(&document, &endpoint);
    }
    if document.get("discoveryVersion").is_some() {
        return discovery::translate(&document, &endpoint);
    }
    Err(refused(
        "the API document is neither OpenAPI 3.0 or 3.1 (an `openapi` key) nor Google Discovery \
         (a `discoveryVersion` key)"
            .to_owned(),
    ))
}

fn refused(reason: String) -> oneiron::Error {
    oneiron::Error::InvalidConfig(reason)
}

/// A tool name the document keeps: letters, digits, `_`, `.` and `-`, at
/// most 128.
fn is_tool_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
}

/// A URL the document names for its calls may only have the installed
/// endpoint's own origin: a call goes to the endpoint the host installed,
/// never where the document points. A URL that does not parse is a path
/// the endpoint already carries.
fn check_origin(url: &str, endpoint: &Url, at: &str) -> oneiron::Result<()> {
    let Ok(parsed) = Url::parse(url) else {
        return Ok(());
    };
    if parsed.origin() != endpoint.origin() {
        return Err(refused(format!(
            "{at} sends to {}, not the installed endpoint's origin {}",
            parsed.origin().ascii_serialization(),
            endpoint.origin().ascii_serialization()
        )));
    }
    Ok(())
}

/// One tool's arguments as one object schema.
#[derive(Clone, Default)]
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

    /// The object schema, with the words admission screening does not
    /// read taken out (see [`screened_input`]).
    fn into_schema(self) -> Value {
        let mut schema = Map::new();
        schema.insert("type".to_owned(), json!("object"));
        schema.insert("properties".to_owned(), Value::Object(self.properties));
        if !self.required.is_empty() {
            schema.insert("required".to_owned(), Value::Array(self.required));
        }
        schema.insert("additionalProperties".to_owned(), Value::Bool(false));
        let mut schema = Value::Object(schema);
        screened_input(&mut schema);
        schema
    }
}

/// Removes `format` and `pattern` from every schema node of an input
/// schema. Admission screening reads an input schema in a closed profile
/// that admits neither (skill_hub/pack_catalog/tool_schema.rs), so a tool
/// whose arguments carry one is refused at register; real documents carry
/// both on most string arguments. `format` only annotates; a `pattern` the
/// API itself still checks. A property that is *named* `format` or
/// `pattern` stays: only schema words are removed.
fn screened_input(schema: &mut Value) {
    let Value::Object(fields) = schema else {
        return;
    };
    fields.remove("format");
    fields.remove("pattern");
    for (key, value) in fields.iter_mut() {
        match key.as_str() {
            "properties" | "patternProperties" | "dependentSchemas" | "$defs" | "definitions" => {
                if let Value::Object(children) = value {
                    children.values_mut().for_each(screened_input);
                }
            }
            "allOf" | "anyOf" | "oneOf" | "prefixItems" => {
                if let Value::Array(variants) = value {
                    variants.iter_mut().for_each(screened_input);
                }
            }
            "items"
            | "additionalProperties"
            | "not"
            | "if"
            | "then"
            | "else"
            | "contains"
            | "propertyNames" => screened_input(value),
            _ => {}
        }
    }
}

/// Every `{name}` in the path is a path parameter, and every path parameter
/// has its place in the path. With `reserved_expansion`, `{+name}` is also
/// a place (Google Discovery's: the value may hold `/`, each part still one
/// segment).
fn check_path_template(
    path: &str,
    parameters: &BTreeSet<String>,
    reserved_expansion: bool,
) -> Result<(), String> {
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
        let name = &after[..close];
        let name = if reserved_expansion {
            name.strip_prefix('+').unwrap_or(name)
        } else {
            name
        };
        named.insert(name.to_owned());
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

/// Whether `schema` fits both bounds a tool's schema meets after
/// translation: the admission resolver's literal bound, and the signature
/// bound `connector.schema` renders within.
fn fits_bounds(schema: &Value) -> bool {
    serde_json::to_vec(schema).is_ok_and(|bytes| bytes.len() <= MAX_SCHEMA_BYTES)
        && oneiron::connector_key::typescript::renders_within_bound(schema)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_input_schema_loses_format_and_pattern_but_keeps_such_named_properties() {
        let mut input = InputSchema::default();
        input
            .add(
                "when",
                json!({"type": "string", "format": "date-time", "pattern": "^[0-9]"}),
                true,
            )
            .unwrap();
        input
            .add(
                "body",
                json!({"type": "object", "properties": {
                    "format": {"type": "string", "format": "uuid"},
                    "pattern": {"type": "array", "items": {"type": "string", "pattern": "a+"}}
                }}),
                false,
            )
            .unwrap();
        assert_eq!(
            input.into_schema(),
            json!({"type": "object", "properties": {
                "when": {"type": "string"},
                "body": {"type": "object", "properties": {
                    "format": {"type": "string"},
                    "pattern": {"type": "array", "items": {"type": "string"}}
                }}
            }, "required": ["when"], "additionalProperties": false})
        );
    }

    #[test]
    fn a_reserved_expansion_is_a_place_only_where_the_format_has_one() {
        let names = BTreeSet::from(["name".to_owned()]);
        assert!(check_path_template("/v1/{+name}", &names, true).is_ok());
        assert!(check_path_template("/v1/{+name}", &names, false).is_err());
        assert!(check_path_template("/v1/{name}:get", &names, false).is_ok());
    }
}
