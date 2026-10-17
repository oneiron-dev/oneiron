//! Fail-closed structural JSON Schema subset for resolved outbound descriptors.
use std::collections::BTreeSet;
use std::sync::{Mutex, OnceLock};

use super::tool_call::invalid_schema;
use crate::Result;
use serde_json::Value;

/// How far a value may sit from a whole multiple of `multipleOf` and still
/// count as one, for binary-float steps such as 0.1.
const MULTIPLE_OF_TOLERANCE: f64 = 1e-9;
/// The compiled-size cap for a declared `pattern`; a larger one refuses.
const PATTERN_SIZE_LIMIT: usize = 1 << 20;

/// Checks `value` against a resolved tool schema. A value outside it, or a
/// schema this subset cannot read, refuses. `tool` names the tool in the one
/// log line an unenforceable pattern gets.
pub(super) fn validate(schema: &Value, value: &Value, tool: &str) -> Result<()> {
    if matches(schema, value, tool)? {
        Ok(())
    } else {
        Err(invalid_schema())
    }
}

/// Whether `value` meets `schema`. `Err` is a schema this subset cannot
/// read, never a mismatch, so `not`, `anyOf` and `if` cannot turn a
/// malformed schema into a pass.
fn matches(schema: &Value, value: &Value, tool: &str) -> Result<bool> {
    if let Some(allow) = schema.as_bool() {
        return Ok(allow);
    }
    let fields = schema.as_object().ok_or_else(invalid_schema)?;
    for key in fields.keys() {
        // Reject unsupported assertions rather than silently allowing a call
        // the descriptor prohibits. Annotations carry no validation authority.
        if !matches!(
            key.as_str(),
            "type"
                | "properties"
                | "required"
                | "additionalProperties"
                | "items"
                | "enum"
                | "const"
                | "title"
                | "description"
                | "default"
                | "examples"
                | "$schema"
                | "$id"
                | "deprecated"
                | "readOnly"
                | "writeOnly"
                | "x-mcp-header"
                | "minimum"
                | "maximum"
                | "exclusiveMinimum"
                | "exclusiveMaximum"
                | "multipleOf"
                | "minLength"
                | "maxLength"
                | "pattern"
                | "format"
                | "minItems"
                | "maxItems"
                | "uniqueItems"
                | "minProperties"
                | "maxProperties"
                | "anyOf"
                | "oneOf"
                | "not"
                | "if"
                | "then"
                | "else"
                | "patternProperties"
                | "propertyNames"
                | "dependentRequired"
                | "dependentSchemas"
                | "prefixItems"
                | "contains"
                | "minContains"
                | "maxContains"
        ) {
            return Err(invalid_schema());
        }
    }
    if let Some(kind) = fields.get("type") {
        let accepts = |kind: &Value| -> Result<bool> {
            Ok(match kind.as_str().ok_or_else(invalid_schema)? {
                "null" => value.is_null(),
                "boolean" => value.is_boolean(),
                "string" => value.is_string(),
                "object" => value.is_object(),
                "array" => value.is_array(),
                "number" => value.is_number(),
                "integer" => value.as_f64().is_some_and(|number| number.fract() == 0.0),
                _ => return Err(invalid_schema()),
            })
        };
        let accepted = if let Some(kinds) = kind.as_array() {
            if kinds.is_empty() {
                return Err(invalid_schema());
            }
            kinds
                .iter()
                .map(accepts)
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .any(|v| v)
        } else {
            accepts(kind)?
        };
        if !accepted {
            return Ok(false);
        }
    }
    if let Some(options) = fields.get("enum") {
        let options = options.as_array().ok_or_else(invalid_schema)?;
        if options.is_empty() {
            return Err(invalid_schema());
        }
        if !options.contains(value) {
            return Ok(false);
        }
    }
    if fields
        .get("const")
        .is_some_and(|expected| expected != value)
    {
        return Ok(false);
    }
    if !composition_matches(fields, value, tool)? {
        return Ok(false);
    }
    // `format` stays an annotation, as JSON Schema 2020-12 defaults it.
    if let Some(number) = value.as_f64() {
        if bound(fields, "minimum")?.is_some_and(|min| number < min)
            || bound(fields, "maximum")?.is_some_and(|max| number > max)
            || bound(fields, "exclusiveMinimum")?.is_some_and(|min| number <= min)
            || bound(fields, "exclusiveMaximum")?.is_some_and(|max| number >= max)
        {
            return Ok(false);
        }
        if let Some(step) = bound(fields, "multipleOf")? {
            if step <= 0.0 {
                return Err(invalid_schema());
            }
            let ratio = number / step;
            if (ratio - ratio.round()).abs() > MULTIPLE_OF_TOLERANCE {
                return Ok(false);
            }
        }
    }
    if let Some(text) = value.as_str() {
        let chars = u64::try_from(text.chars().count()).unwrap_or(u64::MAX);
        if count(fields, "minLength")?.is_some_and(|min| chars < min)
            || count(fields, "maxLength")?.is_some_and(|max| chars > max)
        {
            return Ok(false);
        }
        if let Some(pattern) = fields.get("pattern") {
            let pattern = pattern.as_str().ok_or_else(invalid_schema)?;
            if pattern_matches(pattern, text, tool) == Some(false) {
                return Ok(false);
            }
        }
    }
    if let Some(object) = value.as_object()
        && !object_matches(fields, object, tool)?
    {
        return Ok(false);
    }
    if let Some(array) = value.as_array()
        && !array_matches(fields, array, tool)?
    {
        return Ok(false);
    }
    Ok(true)
}

/// `anyOf`, `oneOf`, `not` and `if`/`then`/`else`, each read whole before
/// its answer counts.
fn composition_matches(
    fields: &serde_json::Map<String, Value>,
    value: &Value,
    tool: &str,
) -> Result<bool> {
    let hits = |name: &str| -> Result<Option<usize>> {
        let Some(variants) = fields.get(name) else {
            return Ok(None);
        };
        let variants = variants
            .as_array()
            .filter(|variants| !variants.is_empty())
            .ok_or_else(invalid_schema)?;
        let mut matched = 0;
        for variant in variants {
            if matches(variant, value, tool)? {
                matched += 1;
            }
        }
        Ok(Some(matched))
    };
    if hits("anyOf")? == Some(0) || hits("oneOf")?.is_some_and(|hits| hits != 1) {
        return Ok(false);
    }
    if let Some(negated) = fields.get("not")
        && matches(negated, value, tool)?
    {
        return Ok(false);
    }
    if let Some(condition) = fields.get("if") {
        let branch = if matches(condition, value, tool)? {
            fields.get("then")
        } else {
            fields.get("else")
        };
        if let Some(branch) = branch
            && !matches(branch, value, tool)?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn object_matches(
    fields: &serde_json::Map<String, Value>,
    object: &serde_json::Map<String, Value>,
    tool: &str,
) -> Result<bool> {
    let size = u64::try_from(object.len()).unwrap_or(u64::MAX);
    if count(fields, "minProperties")?.is_some_and(|min| size < min)
        || count(fields, "maxProperties")?.is_some_and(|max| size > max)
    {
        return Ok(false);
    }
    let properties = schema_map(fields, "properties")?;
    let patterns = schema_map(fields, "patternProperties")?
        .map(|patterns| {
            patterns
                .iter()
                .map(|(pattern, rule)| Ok((compiled(pattern)?, rule)))
                .collect::<Result<Vec<_>>>()
        })
        .transpose()?
        .unwrap_or_default();
    if let Some(required) = fields.get("required") {
        for key in required.as_array().ok_or_else(invalid_schema)? {
            if !object.contains_key(key.as_str().ok_or_else(invalid_schema)?) {
                return Ok(false);
            }
        }
    }
    for (key, child) in object {
        let mut named = false;
        if let Some(rule) = properties.and_then(|p| p.get(key)) {
            named = true;
            if !matches(rule, child, tool)? {
                return Ok(false);
            }
        }
        for (pattern, rule) in &patterns {
            if pattern.is_match(key) {
                named = true;
                if !matches(rule, child, tool)? {
                    return Ok(false);
                }
            }
        }
        if !named
            && let Some(rule) = fields.get("additionalProperties")
            && !matches(rule, child, tool)?
        {
            return Ok(false);
        }
        if let Some(rule) = fields.get("propertyNames")
            && !matches(rule, &Value::String(key.clone()), tool)?
        {
            return Ok(false);
        }
    }
    if let Some(dependent) = fields.get("dependentRequired") {
        for (key, names) in dependent.as_object().ok_or_else(invalid_schema)? {
            let names = names.as_array().ok_or_else(invalid_schema)?;
            if object.contains_key(key) {
                for name in names {
                    if !object.contains_key(name.as_str().ok_or_else(invalid_schema)?) {
                        return Ok(false);
                    }
                }
            }
        }
    }
    if let Some(dependent) = schema_map(fields, "dependentSchemas")? {
        let whole = Value::Object(object.clone());
        for (key, rule) in dependent {
            if object.contains_key(key) && !matches(rule, &whole, tool)? {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn array_matches(
    fields: &serde_json::Map<String, Value>,
    array: &[Value],
    tool: &str,
) -> Result<bool> {
    let size = u64::try_from(array.len()).unwrap_or(u64::MAX);
    let unique = fields
        .get("uniqueItems")
        .map(|flag| flag.as_bool().ok_or_else(invalid_schema))
        .transpose()?
        == Some(true);
    if count(fields, "minItems")?.is_some_and(|min| size < min)
        || count(fields, "maxItems")?.is_some_and(|max| size > max)
        || unique
            && array
                .iter()
                .enumerate()
                .any(|(index, item)| array[..index].contains(item))
    {
        return Ok(false);
    }
    // `items` covers what `prefixItems` leaves, as in 2020-12.
    let prefix = fields
        .get("prefixItems")
        .map(|rules| rules.as_array().ok_or_else(invalid_schema))
        .transpose()?
        .map_or(&[][..], Vec::as_slice);
    for (rule, child) in prefix.iter().zip(array) {
        if !matches(rule, child, tool)? {
            return Ok(false);
        }
    }
    if let Some(rule) = fields.get("items") {
        for child in array.iter().skip(prefix.len()) {
            if !matches(rule, child, tool)? {
                return Ok(false);
            }
        }
    }
    if let Some(rule) = fields.get("contains") {
        let mut hits = 0_u64;
        for child in array {
            if matches(rule, child, tool)? {
                hits += 1;
            }
        }
        let least = count(fields, "minContains")?.unwrap_or(1);
        if hits < least || count(fields, "maxContains")?.is_some_and(|most| hits > most) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Whether `text` meets a declared `pattern`. `None` when this host's regex
/// engine cannot compile it (an ECMA-262 lookaround or backreference): the
/// pattern is then an annotation, logged once per tool and pattern, and the
/// call goes on to the connector, which checks its own declaration.
fn pattern_matches(pattern: &str, text: &str, tool: &str) -> Option<bool> {
    match compiled(pattern) {
        Ok(compiled) => Some(compiled.is_match(text)),
        Err(_) => {
            static LOGGED: OnceLock<Mutex<BTreeSet<(String, String)>>> = OnceLock::new();
            let first = LOGGED
                .get_or_init(Mutex::default)
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert((tool.to_owned(), pattern.to_owned()));
            if first {
                tracing::info!(
                    tool,
                    pattern,
                    "a tool's pattern this host cannot compile is not enforced"
                );
            }
            None
        }
    }
}

fn compiled(pattern: &str) -> Result<regex::Regex> {
    regex::RegexBuilder::new(pattern)
        .size_limit(PATTERN_SIZE_LIMIT)
        .build()
        .map_err(|_| invalid_schema())
}

/// A keyword whose value maps names to schemas.
fn schema_map<'a>(
    fields: &'a serde_json::Map<String, Value>,
    name: &str,
) -> Result<Option<&'a serde_json::Map<String, Value>>> {
    fields
        .get(name)
        .map(|value| value.as_object().ok_or_else(invalid_schema))
        .transpose()
}

/// A numeric keyword's bound; a non-number refuses.
fn bound(fields: &serde_json::Map<String, Value>, name: &str) -> Result<Option<f64>> {
    fields
        .get(name)
        .map(|value| value.as_f64().ok_or_else(invalid_schema))
        .transpose()
}

/// A count keyword's bound; anything but a non-negative integer refuses.
fn count(fields: &serde_json::Map<String, Value>, name: &str) -> Result<Option<u64>> {
    fields
        .get(name)
        .map(|value| value.as_u64().ok_or_else(invalid_schema))
        .transpose()
}
