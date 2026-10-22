//! The `x-mcp-header` declarations of a tool's input schema (FIX 8810,
//! 9284): which arguments go as HTTP headers, under which names. A named
//! property's annotation declares its parameter; a `patternProperties`
//! entry's or a schema-valued `additionalProperties`'s declares each
//! argument key it governs, by the same rules, once a call names the key.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::invalid_schema;
use crate::Result;

/// What the static listing names a `patternProperties` declaration by,
/// before the pattern: no call has named its keys yet (FIX 9284).
const PATTERN_HEADER_SELECTOR: &str = "patternProperties:";

/// What the static listing names a schema-valued `additionalProperties`
/// declaration by (FIX 9284).
const ADDITIONAL_HEADER_SELECTOR: &str = "additionalProperties";

/// The headers a schema declares for one call's arguments, by parameter,
/// each with every header name it is named under there.
#[derive(Default)]
pub(super) struct DeclaredHeaders<'a> {
    /// Named properties' declarations.
    pub(super) named: BTreeMap<&'a str, BTreeSet<&'a str>>,
    /// The argument keys a `patternProperties` or `additionalProperties`
    /// declaration governs (FIX 9284).
    pub(super) dynamic: BTreeMap<&'a str, BTreeSet<&'a str>>,
}

/// Each `x-mcp-header` parameter `schema` declares where `value` meets it,
/// with every header name it names there: its own for `true`, the given one
/// for a string. A branch's annotation counts as the root's does, and a
/// parameter two branches name differently goes under each name (FIX
/// 8810); `false` declares none, and any other named annotation refuses. A
/// `patternProperties` or schema-valued `additionalProperties` annotation
/// declares each key of `value` it governs by the same rules (FIX 9284);
/// one that cannot declare stays an annotation.
pub(super) fn declared_headers<'a>(
    schema: &'a Value,
    value: &'a Value,
    tool: &str,
) -> Result<DeclaredHeaders<'a>> {
    let mut declared = DeclaredHeaders::default();
    for fields in super::super::tool_schema::applicable_schemas(schema, Some((value, tool)))? {
        let properties = fields.get("properties").and_then(Value::as_object);
        for (parameter, property) in properties.into_iter().flatten() {
            let name = match property.get("x-mcp-header") {
                None | Some(Value::Bool(false)) => continue,
                Some(Value::Bool(true)) => parameter.as_str(),
                Some(Value::String(name)) => name.as_str(),
                Some(_) => return Err(invalid_schema()),
            };
            declared
                .named
                .entry(parameter.as_str())
                .or_default()
                .insert(name);
        }
        for (key, rule) in governed_keys(fields, properties, value) {
            if let Some(name) = dynamic_header_name(key, rule) {
                declared.dynamic.entry(key).or_default().insert(name);
            }
        }
    }
    Ok(declared)
}

/// Each key of `value` a `patternProperties` entry or a schema-valued
/// `additionalProperties` of the object schema `fields` governs, with that
/// rule, as the validator applies them: patterns unanchored, and
/// `additionalProperties` for a key no property or pattern there names. A
/// pattern this host cannot compile governs no key it can name, and leaves
/// none additional (FIX 9284).
fn governed_keys<'a>(
    fields: &'a serde_json::Map<String, Value>,
    properties: Option<&serde_json::Map<String, Value>>,
    value: &'a Value,
) -> Vec<(&'a str, &'a Value)> {
    let patterns: Vec<_> = fields
        .get("patternProperties")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .map(|(pattern, rule)| (super::super::tool_schema::key_pattern(pattern), rule))
        .collect();
    let additional = fields
        .get("additionalProperties")
        .filter(|rule| rule.is_object());
    let mut governed = Vec::new();
    if patterns.is_empty() && additional.is_none() {
        return governed;
    }
    for key in value
        .as_object()
        .into_iter()
        .flat_map(serde_json::Map::keys)
    {
        let mut named = properties.is_some_and(|properties| properties.contains_key(key));
        let mut unknown = false;
        for (pattern, rule) in &patterns {
            match pattern {
                Some(pattern) if pattern.is_match(key) => {
                    named = true;
                    governed.push((key.as_str(), *rule));
                }
                Some(_) => {}
                None => unknown = true,
            }
        }
        if let Some(rule) = additional.filter(|_| !named && !unknown) {
            governed.push((key.as_str(), rule));
        }
    }
    governed
}

/// The header name a dynamic `x-mcp-header` annotation on `rule` gives the
/// argument `key`: its own for `true`, the given one for a string. Anything
/// else stays an annotation (FIX 9284; Engine 10-18).
fn dynamic_header_name<'a>(key: &'a str, rule: &'a Value) -> Option<&'a str> {
    match rule.get("x-mcp-header")? {
        Value::Bool(true) => Some(key),
        Value::String(name) => Some(name.as_str()),
        _ => None,
    }
}

/// The one header a dynamic declaration sends `parameter` as, under
/// `names`, and its value (FIX 9284): by the named path's rules, a string
/// of tab or printable ASCII under one valid header name no other parameter
/// sends, never a destructive tool's `dry_run`. `None` when it cannot be
/// sent so: the declaration stays an annotation and the argument stays in
/// the body, as it went before.
pub(super) fn dynamic_header(
    body: &BTreeMap<String, Value>,
    parameter: &str,
    names: &BTreeSet<&str>,
    headers: &BTreeMap<String, String>,
    destructive_hint: bool,
) -> Option<(String, String)> {
    if destructive_hint && parameter == "dry_run" {
        return None;
    }
    let value = body.get(parameter)?.as_str()?;
    if !value.bytes().all(|c| c == b'\t' || (32..=126).contains(&c)) {
        return None;
    }
    let mut names = names
        .iter()
        .filter_map(|name| canonical_header(name).ok())
        .collect::<BTreeSet<_>>()
        .into_iter();
    let (Some(name), None) = (names.next(), names.next()) else {
        return None;
    };
    (!headers.contains_key(&name)).then(|| (name, value.to_owned()))
}

/// Whether `rule` carries an `x-mcp-header` annotation that declares one.
fn declares_header(rule: &Value) -> bool {
    matches!(
        rule.get("x-mcp-header"),
        Some(Value::Bool(true) | Value::String(_))
    )
}

/// The parameters an `x-mcp-header` annotation in `schema` can send as
/// headers, sorted: those in the root `properties` and in every branch a
/// call may meet (FIX 8810), as [`super::prepare_tool_call`] extracts them.
/// A declaration under `patternProperties` (one this host compiles) or a
/// schema-valued `additionalProperties` names no parameter until a call
/// does, so its selector stands in for it (FIX 9284).
pub fn header_parameters(schema: &Value) -> Vec<String> {
    let mut names = BTreeSet::new();
    for fields in super::super::tool_schema::applicable_schemas(schema, None).unwrap_or_default() {
        for (parameter, property) in fields
            .get("properties")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
        {
            if declares_header(property) {
                names.insert(parameter.clone());
            }
        }
        for (pattern, rule) in fields
            .get("patternProperties")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
        {
            if declares_header(rule) && super::super::tool_schema::key_pattern(pattern).is_some() {
                names.insert(format!("{PATTERN_HEADER_SELECTOR}{pattern}"));
            }
        }
        if fields
            .get("additionalProperties")
            .is_some_and(declares_header)
        {
            names.insert(ADDITIONAL_HEADER_SELECTOR.to_owned());
        }
    }
    names.into_iter().collect()
}

pub(super) fn canonical_header(name: &str) -> Result<String> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c))
    {
        return Err(invalid_schema());
    }
    let name = name.to_ascii_lowercase();
    if matches!(
        name.as_str(),
        "authorization"
            | "host"
            | "cookie"
            | "connection"
            | "transfer-encoding"
            | "mcp-method"
            | "mcp-name"
    ) || name.starts_with("content-")
        || name.starts_with("proxy-")
    {
        return Err(invalid_schema());
    }
    Ok(name)
}
