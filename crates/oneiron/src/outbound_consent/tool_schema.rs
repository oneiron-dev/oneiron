//! Fail-closed structural JSON Schema subset for resolved outbound descriptors.
use super::tool_call::invalid_schema;
use crate::Result;
use serde_json::Value;

/// How far a value may sit from a whole multiple of `multipleOf` and still
/// count as one, for binary-float steps such as 0.1.
const MULTIPLE_OF_TOLERANCE: f64 = 1e-9;
/// The compiled-size cap for a declared `pattern`; a larger one refuses.
const PATTERN_SIZE_LIMIT: usize = 1 << 20;

pub(super) fn validate(schema: &Value, value: &Value) -> Result<()> {
    if let Some(allow) = schema.as_bool() {
        return if allow { Ok(()) } else { Err(invalid_schema()) };
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
            return Err(invalid_schema());
        }
    }
    if let Some(options) = fields.get("enum") {
        let options = options.as_array().ok_or_else(invalid_schema)?;
        if options.is_empty() || !options.contains(value) {
            return Err(invalid_schema());
        }
    }
    if fields
        .get("const")
        .is_some_and(|expected| expected != value)
    {
        return Err(invalid_schema());
    }
    // `format` stays an annotation, as JSON Schema 2020-12 defaults it.
    if let Some(number) = value.as_f64() {
        if bound(fields, "minimum")?.is_some_and(|min| number < min)
            || bound(fields, "maximum")?.is_some_and(|max| number > max)
            || bound(fields, "exclusiveMinimum")?.is_some_and(|min| number <= min)
            || bound(fields, "exclusiveMaximum")?.is_some_and(|max| number >= max)
        {
            return Err(invalid_schema());
        }
        if let Some(step) = bound(fields, "multipleOf")? {
            let ratio = number / step;
            if step <= 0.0 || (ratio - ratio.round()).abs() > MULTIPLE_OF_TOLERANCE {
                return Err(invalid_schema());
            }
        }
    }
    if let Some(text) = value.as_str() {
        let chars = u64::try_from(text.chars().count()).unwrap_or(u64::MAX);
        if count(fields, "minLength")?.is_some_and(|min| chars < min)
            || count(fields, "maxLength")?.is_some_and(|max| chars > max)
        {
            return Err(invalid_schema());
        }
        if let Some(pattern) = fields.get("pattern") {
            let pattern = regex::RegexBuilder::new(pattern.as_str().ok_or_else(invalid_schema)?)
                .size_limit(PATTERN_SIZE_LIMIT)
                .build()
                .map_err(|_| invalid_schema())?;
            if !pattern.is_match(text) {
                return Err(invalid_schema());
            }
        }
    }
    if let Some(object) = value.as_object() {
        let size = u64::try_from(object.len()).unwrap_or(u64::MAX);
        if count(fields, "minProperties")?.is_some_and(|min| size < min)
            || count(fields, "maxProperties")?.is_some_and(|max| size > max)
        {
            return Err(invalid_schema());
        }
    }
    if let Some(array) = value.as_array() {
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
            return Err(invalid_schema());
        }
    }
    if let Some(object) = value.as_object() {
        let properties = fields
            .get("properties")
            .map(|v| v.as_object().ok_or_else(invalid_schema))
            .transpose()?;
        if let Some(required) = fields.get("required") {
            for key in required.as_array().ok_or_else(invalid_schema)? {
                if !object.contains_key(key.as_str().ok_or_else(invalid_schema)?) {
                    return Err(invalid_schema());
                }
            }
        }
        for (key, child) in object {
            if let Some(rule) = properties.and_then(|p| p.get(key)) {
                validate(rule, child)?;
            } else if let Some(rule) = fields.get("additionalProperties") {
                validate(rule, child)?;
            }
        }
    }
    if let Some(array) = value.as_array()
        && let Some(rule) = fields.get("items")
    {
        for child in array {
            validate(rule, child)?;
        }
    }
    Ok(())
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
