//! A resolved tool schema as TypeScript (L8-31; agent runtime
//! `#code-mode-translation` and `#d10-built-state`: "schema-to-TypeScript
//! generation, output schemas included"). `connector.schema` hands the caller
//! the type of a tool's `args` and of its delivered reply's
//! `structured_content`, rendered from the schemas the owner approved. Pure
//! text with no compiler and no I/O, so it renders at each read and a
//! renderer change reaches every approved key without a new stamp.
//!
//! The schema is already resolved (`ResolvedConnectorManifest::resolve`): no
//! `$ref` is left. Covered: `type` (one or a list), objects (`properties`,
//! `required`, `additionalProperties`), arrays (`items`, `prefixItems`),
//! `const` and `enum` as literal unions, `anyOf`/`oneOf` as unions, `allOf`
//! as an intersection, and each property's `description` and `format` as a
//! doc comment. Anything else renders `unknown`.

use serde_json::{Map, Value};
use std::collections::BTreeSet;

/// The longest rendering served. A longer one is replaced by its fallback
/// (`object` for arguments, `unknown` for a reply), so one huge schema cannot
/// flood the caller's context.
pub const MAX_TYPESCRIPT_BYTES: usize = 16 * 1024;

/// Nesting past this depth renders `unknown`.
const MAX_DEPTH: usize = 32;

/// The TypeScript type of a tool's `args`, from its resolved input schema;
/// `object` when the rendering is longer than [`MAX_TYPESCRIPT_BYTES`].
#[must_use]
pub fn input_typescript(schema: &Value) -> String {
    bounded(schema, "object")
}

/// The TypeScript type of a delivered reply's `structured_content`, from the
/// tool's resolved output schema; `unknown` when the rendering is longer than
/// [`MAX_TYPESCRIPT_BYTES`].
#[must_use]
pub fn output_typescript(schema: &Value) -> String {
    bounded(schema, "unknown")
}

fn bounded(schema: &Value, fallback: &str) -> String {
    let rendered = render(schema, 0);
    if rendered.len() > MAX_TYPESCRIPT_BYTES {
        fallback.to_owned()
    } else {
        rendered
    }
}

/// One schema node as a type; `depth` is its object nesting, for indentation.
fn render(schema: &Value, depth: usize) -> String {
    if depth > MAX_DEPTH {
        return unknown();
    }
    let node = match schema {
        Value::Bool(true) => return unknown(),
        Value::Bool(false) => return "never".to_owned(),
        Value::Object(node) => node,
        _ => return unknown(),
    };
    if let Some(constant) = node.get("const") {
        return literal(constant).unwrap_or_else(unknown);
    }
    if let Some(Value::Array(values)) = node.get("enum") {
        return match values.iter().map(literal).collect::<Option<Vec<_>>>() {
            Some(literals) if !literals.is_empty() => union(literals),
            _ => unknown(),
        };
    }
    let mut parts = Vec::new();
    if let Some(base) = base(node, depth) {
        parts.push(base);
    }
    // A combinator whose every variant only constrains (no type of its own,
    // as `anyOf: [{"required": ["a"]}, ...]` does) adds nothing to read.
    for key in ["anyOf", "oneOf"] {
        if let Some(Value::Array(variants)) = node.get(key) {
            let variants = union(variants.iter().map(|v| render(v, depth)).collect());
            if variants != unknown() {
                parts.push(variants);
            }
        }
    }
    if let Some(Value::Array(all)) = node.get("allOf") {
        parts.extend(
            all.iter()
                .map(|part| render(part, depth))
                .filter(|part| *part != unknown()),
        );
    }
    match parts.len() {
        0 => unknown(),
        1 => parts.remove(0),
        _ => parts
            .into_iter()
            .map(|part| grouped(&part))
            .collect::<Vec<_>>()
            .join(" & "),
    }
}

/// The node's own type, from `type` or, without one, from the keywords that
/// imply it. `None` when it states none.
fn base(node: &Map<String, Value>, depth: usize) -> Option<String> {
    match node.get("type") {
        Some(Value::String(kind)) => Some(typed(kind, node, depth)),
        Some(Value::Array(kinds)) => Some(union(
            kinds
                .iter()
                .map(|kind| {
                    kind.as_str()
                        .map_or_else(unknown, |kind| typed(kind, node, depth))
                })
                .collect(),
        )),
        _ if node.contains_key("properties") || node.contains_key("additionalProperties") => {
            Some(object(node, depth))
        }
        _ if node.contains_key("items") || node.contains_key("prefixItems") => {
            Some(array(node, depth))
        }
        _ => None,
    }
}

fn typed(kind: &str, node: &Map<String, Value>, depth: usize) -> String {
    match kind {
        "string" => "string".to_owned(),
        "number" | "integer" => "number".to_owned(),
        "boolean" => "boolean".to_owned(),
        "null" => "null".to_owned(),
        "array" => array(node, depth),
        "object" => object(node, depth),
        _ => unknown(),
    }
}

fn array(node: &Map<String, Value>, depth: usize) -> String {
    let rest = match node.get("items") {
        Some(Value::Bool(false)) => None,
        Some(items) => Some(render(items, depth)),
        None => Some(unknown()),
    };
    match node.get("prefixItems") {
        Some(Value::Array(prefix)) => {
            let mut members: Vec<String> = prefix.iter().map(|item| render(item, depth)).collect();
            if let Some(rest) = rest {
                members.push(format!("...{}[]", grouped(&rest)));
            }
            format!("[{}]", members.join(", "))
        }
        _ => format!("{}[]", grouped(&rest.unwrap_or_else(|| "never".to_owned()))),
    }
}

fn object(node: &Map<String, Value>, depth: usize) -> String {
    let pad = "  ".repeat(depth + 1);
    let properties = node.get("properties").and_then(Value::as_object);
    let no_properties = properties.is_none_or(Map::is_empty);
    let required: BTreeSet<&str> = node
        .get("required")
        .and_then(Value::as_array)
        .map(|names| names.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let mut lines = Vec::new();
    for (name, child) in properties.into_iter().flatten() {
        if let Some(doc) = doc_comment(child) {
            lines.push(format!("{pad}{doc}"));
        }
        let optional = if required.contains(name.as_str()) {
            ""
        } else {
            "?"
        };
        lines.push(format!(
            "{pad}{}{optional}: {};",
            property_key(name),
            render(child, depth + 1)
        ));
    }
    // Absent `additionalProperties` admits any other key. A typed index
    // signature beside named properties would have to admit each of their
    // types, so there it reads `unknown`.
    match node.get("additionalProperties") {
        Some(Value::Bool(false)) => {}
        Some(extra @ Value::Object(_)) => {
            let extra = if no_properties {
                render(extra, depth + 1)
            } else {
                unknown()
            };
            lines.push(format!("{pad}[key: string]: {extra};"));
        }
        _ if no_properties => lines.push(format!("{pad}[key: string]: unknown;")),
        _ => {}
    }
    if lines.is_empty() {
        "{}".to_owned()
    } else {
        format!("{{\n{}\n{}}}", lines.join("\n"), "  ".repeat(depth))
    }
}

/// A property's `description` and `format`, as one doc comment line.
fn doc_comment(schema: &Value) -> Option<String> {
    let text = |key: &str| {
        schema
            .get(key)
            .and_then(Value::as_str)
            .map(|text| text.split_whitespace().collect::<Vec<_>>().join(" "))
            .filter(|text| !text.is_empty())
    };
    let doc = match (text("description"), text("format")) {
        (Some(description), Some(format)) => format!("{description} (format: {format})"),
        (Some(description), None) => description,
        (None, Some(format)) => format!("format: {format}"),
        (None, None) => return None,
    };
    Some(format!("/** {} */", doc.replace("*/", "*\\/")))
}

/// A JSON scalar as a TypeScript literal type.
fn literal(value: &Value) -> Option<String> {
    match value {
        Value::Null => Some("null".to_owned()),
        Value::Bool(_) | Value::Number(_) => Some(value.to_string()),
        Value::String(_) => serde_json::to_string(value).ok(),
        Value::Array(_) | Value::Object(_) => None,
    }
}

/// The members as one union, each once in first-seen order; `unknown` when
/// any member is, as TypeScript reads it.
fn union(members: Vec<String>) -> String {
    let mut seen = Vec::new();
    for member in members {
        if member == unknown() {
            return unknown();
        }
        if !seen.contains(&member) {
            seen.push(member);
        }
    }
    match seen.len() {
        0 => "never".to_owned(),
        1 => seen.remove(0),
        _ => seen.join(" | "),
    }
}

/// `text` in parentheses when it is a union or an intersection, so it can
/// stand as an array's element or an intersection's member.
fn grouped(text: &str) -> String {
    if text.contains(" | ") || text.contains(" & ") {
        format!("({text})")
    } else {
        text.to_owned()
    }
}

/// A property name, bare when it is an identifier, else a string literal.
fn property_key(name: &str) -> String {
    let mut chars = name.chars();
    let identifier = chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_' || first == '$')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$');
    if identifier {
        name.to_owned()
    } else {
        Value::String(name.to_owned()).to_string()
    }
}

fn unknown() -> String {
    "unknown".to_owned()
}
