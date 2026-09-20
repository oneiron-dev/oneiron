//! Fail-closed structural JSON Schema subset for resolved outbound descriptors.
use super::tool_call::invalid_schema;
use crate::Result;
use serde_json::Value;

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
