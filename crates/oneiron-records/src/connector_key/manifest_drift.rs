//! Moved from `crates/oneiron/src/connector_key/manifest_drift.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

pub fn invalid() -> Error {
    Error::InvalidConfig("invalid resolved connector manifest".to_owned())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorToolSchema {
    pub name: String,
    pub permissions: BTreeSet<String>,
    pub triggers: BTreeSet<String>,
    pub input_schema: Value,
}

pub fn resolve_schema(
    node: &Value,
    root: &Value,
    stack: &mut Vec<String>,
    depth: usize,
) -> Result<Value> {
    if depth > 24 {
        return Err(invalid());
    }
    let Some(obj) = node.as_object() else {
        return if node.is_boolean() {
            Ok(node.clone())
        } else {
            Err(invalid())
        };
    };
    if let Some(reference) = obj.get("$ref") {
        if obj.len() != 1 {
            return Err(invalid());
        }
        let reference = reference.as_str().ok_or_else(invalid)?;
        if !reference.starts_with("#/") || stack.iter().any(|s| s == reference) {
            return Err(invalid());
        }
        let target = root.pointer(&reference[1..]).ok_or_else(invalid)?;
        stack.push(reference.to_owned());
        let result = resolve_schema(target, root, stack, depth + 1);
        stack.pop();
        return result;
    }
    let mut result = serde_json::Map::new();
    let mut all_of = None;
    for (key, value) in obj {
        match key.as_str() {
            "$defs" | "definitions" => {}
            "properties" => {
                let properties = value.as_object().ok_or_else(invalid)?;
                let mut out = serde_json::Map::new();
                for (name, child) in properties {
                    out.insert(name.clone(), resolve_schema(child, root, stack, depth + 1)?);
                }
                result.insert(key.clone(), Value::Object(out));
            }
            "items" | "additionalProperties" => {
                result.insert(key.clone(), resolve_schema(value, root, stack, depth + 1)?);
            }
            "allOf" => {
                let variants = value
                    .as_array()
                    .filter(|a| !a.is_empty() && a.len() <= 64)
                    .ok_or_else(invalid)?;
                let mut out = Vec::with_capacity(variants.len());
                for variant in variants {
                    out.push(resolve_schema(variant, root, stack, depth + 1)?);
                }
                all_of = Some(out);
            }
            // Schema lists and single schemas the call validator reads
            // (outbound_consent/tool_schema.rs); each is resolved in place.
            "anyOf" | "oneOf" | "prefixItems" => {
                let variants = value
                    .as_array()
                    .filter(|a| !a.is_empty() && a.len() <= 64)
                    .ok_or_else(invalid)?;
                let mut out = Vec::with_capacity(variants.len());
                for variant in variants {
                    out.push(resolve_schema(variant, root, stack, depth + 1)?);
                }
                result.insert(key.clone(), Value::Array(out));
            }
            "not" | "if" | "then" | "else" | "contains" | "propertyNames" => {
                result.insert(key.clone(), resolve_schema(value, root, stack, depth + 1)?);
            }
            "patternProperties" | "dependentSchemas" => {
                let schemas = value.as_object().ok_or_else(invalid)?;
                let mut out = serde_json::Map::new();
                for (name, child) in schemas {
                    out.insert(name.clone(), resolve_schema(child, root, stack, depth + 1)?);
                }
                result.insert(key.clone(), Value::Object(out));
            }
            "type" | "required" | "enum" | "const" | "title" | "description" | "default"
            | "examples" | "$schema" | "$id" | "deprecated" | "readOnly" | "writeOnly"
            | "x-mcp-header" => {
                result.insert(key.clone(), value.clone());
            }
            // Value assertions and `format`: none carries a schema, so none
            // can hide a ref; the call validator enforces each assertion.
            "minimum" | "maximum" | "exclusiveMinimum" | "exclusiveMaximum" | "multipleOf"
            | "minLength" | "maxLength" | "pattern" | "format" | "minItems" | "maxItems"
            | "uniqueItems" | "minProperties" | "maxProperties" | "dependentRequired"
            | "minContains" | "maxContains" => {
                result.insert(key.clone(), value.clone());
            }
            // Unknown schema-bearing keywords (for example `if` or
            // `dependentSchemas`) can hide refs. Reject, never strip them.
            _ => return Err(invalid()),
        }
    }
    let resolved = if let Some(variants) = all_of {
        let mut conjuncts = Vec::with_capacity(variants.len() + 1);
        conjuncts.push(Value::Object(result));
        conjuncts.extend(variants);
        merge_all_of(&conjuncts)?
    } else {
        Value::Object(result)
    };
    if serde_json::to_vec(&resolved).map_err(|_| invalid())?.len() > 65_536 {
        return Err(invalid());
    }
    Ok(resolved)
}

/// Compile a supported JSON Schema conjunction into the subset consumed by
/// `prepare_tool_call`. `additionalProperties` is deliberately refused when
/// multiple schemas are combined: its property-name scope is local to each
/// conjunct, and merging property declarations can otherwise widen it.
pub fn merge_all_of(schemas: &[Value]) -> Result<Value> {
    let mut objects = Vec::new();
    for schema in schemas {
        match schema {
            Value::Bool(false) => return Ok(Value::Bool(false)),
            Value::Bool(true) => {}
            Value::Object(object) => objects.push(object),
            _ => return Err(invalid()),
        }
    }
    objects.retain(|object| !object.is_empty());
    if objects.is_empty() {
        return Ok(Value::Object(serde_json::Map::new()));
    }
    if objects.len() == 1 {
        return Ok(Value::Object((*objects[0]).clone()));
    }
    if objects
        .iter()
        .any(|object| object.contains_key("additionalProperties"))
    {
        return Err(invalid());
    }

    let mut keys = BTreeSet::new();
    for object in &objects {
        keys.extend(object.keys().cloned());
    }
    let mut merged = serde_json::Map::new();
    for key in keys {
        let values: Vec<&Value> = objects
            .iter()
            .filter_map(|object| object.get(&key))
            .collect();
        match key.as_str() {
            "type" => match intersect_types(&values)? {
                Some(kind) => {
                    merged.insert(key, kind);
                }
                None => return Ok(Value::Bool(false)),
            },
            "required" => {
                let mut required = BTreeSet::new();
                for value in values {
                    for name in value.as_array().ok_or_else(invalid)? {
                        required.insert(name.as_str().ok_or_else(invalid)?.to_owned());
                    }
                }
                merged.insert(
                    key,
                    Value::Array(required.into_iter().map(Value::String).collect()),
                );
            }
            "properties" => {
                let mut properties: BTreeMap<String, Vec<Value>> = BTreeMap::new();
                for value in values {
                    for (name, schema) in value.as_object().ok_or_else(invalid)? {
                        properties
                            .entry(name.clone())
                            .or_default()
                            .push(schema.clone());
                    }
                }
                let mut result = serde_json::Map::new();
                for (name, schemas) in properties {
                    result.insert(name, merge_all_of(&schemas)?);
                }
                merged.insert(key, Value::Object(result));
            }
            "items" => {
                let schemas: Vec<Value> = values.into_iter().cloned().collect();
                merged.insert(key, merge_all_of(&schemas)?);
            }
            "enum" => match intersect_enums(&values)? {
                Some(options) => {
                    merged.insert(key, Value::Array(options));
                }
                None => return Ok(Value::Bool(false)),
            },
            "const" => {
                let first = values[0];
                if values.iter().any(|value| *value != first) {
                    return Ok(Value::Bool(false));
                }
                merged.insert(key, first.clone());
            }
            "title" | "description" | "default" | "examples" | "$schema" | "$id" | "deprecated"
            | "readOnly" | "writeOnly" | "x-mcp-header" => {
                let first = values[0];
                if values.iter().any(|value| *value != first) {
                    // Annotations can affect defaults and header extraction at
                    // consent time, so do not choose one branch arbitrarily.
                    return Err(invalid());
                }
                merged.insert(key, first.clone());
            }
            // Every conjunct's bound holds, so the tightest one does.
            "minimum" | "exclusiveMinimum" | "minLength" | "minItems" | "minProperties" => {
                merged.insert(key, tightest(&values, true)?);
            }
            "maximum" | "exclusiveMaximum" | "maxLength" | "maxItems" | "maxProperties" => {
                merged.insert(key, tightest(&values, false)?);
            }
            "uniqueItems" => {
                let mut unique = false;
                for value in values {
                    unique |= value.as_bool().ok_or_else(invalid)?;
                }
                merged.insert(key, Value::Bool(unique));
            }
            // Two different steps, patterns or formats have no one keyword
            // that means both, so the merge refuses rather than pick one.
            "multipleOf" | "pattern" | "format" => {
                let first = values[0];
                if values.iter().any(|value| *value != first) {
                    return Err(invalid());
                }
                merged.insert(key, first.clone());
            }
            // Independent assertions: one conjunct's, or several that agree,
            // hold as they stand. Differing ones have no single keyword.
            "anyOf" | "oneOf" | "not" | "if" | "then" | "else" | "contains" | "propertyNames"
            | "patternProperties" | "dependentSchemas" | "dependentRequired" | "minContains"
            | "maxContains" => {
                let first = values[0];
                if values.iter().any(|value| *value != first) {
                    return Err(invalid());
                }
                merged.insert(key, first.clone());
            }
            // `prefixItems` changes what another conjunct's `items` covers,
            // so a merge would broaden it.
            "prefixItems" => return Err(invalid()),
            // This also guards future keyword additions from silently being
            // copied through a composition path with unknown semantics.
            _ => return Err(invalid()),
        }
    }
    if let (Some(options), Some(constant)) = (merged.get("enum"), merged.get("const"))
        && !options.as_array().ok_or_else(invalid)?.contains(constant)
    {
        return Ok(Value::Bool(false));
    }
    Ok(Value::Object(merged))
}

/// The tightest of one bound keyword's values across conjuncts: the largest
/// lower bound, or the smallest upper one.
pub fn tightest(values: &[&Value], lower: bool) -> Result<Value> {
    let mut best: Option<(&Value, f64)> = None;
    for value in values {
        let number = value.as_f64().ok_or_else(invalid)?;
        let tighter = best.is_none_or(|(_, current)| {
            if lower {
                number > current
            } else {
                number < current
            }
        });
        if tighter {
            best = Some((value, number));
        }
    }
    best.map(|(value, _)| value.clone()).ok_or_else(invalid)
}

/// JSON Schema's `integer` is a subset of `number`; model integer and
/// non-integer numbers separately so conjunctions do not broaden constraints.
pub fn intersect_types(values: &[&Value]) -> Result<Option<Value>> {
    let mut accepted: Option<BTreeSet<&'static str>> = None;
    for value in values {
        let types: Vec<&str> = if let Some(kind) = value.as_str() {
            vec![kind]
        } else {
            value
                .as_array()
                .filter(|kinds| !kinds.is_empty())
                .ok_or_else(invalid)?
                .iter()
                .map(|kind| kind.as_str().ok_or_else(invalid))
                .collect::<Result<_>>()?
        };
        let mut current = BTreeSet::new();
        for kind in types {
            match kind {
                "null" => {
                    current.insert("null");
                }
                "boolean" => {
                    current.insert("boolean");
                }
                "string" => {
                    current.insert("string");
                }
                "object" => {
                    current.insert("object");
                }
                "array" => {
                    current.insert("array");
                }
                "integer" => {
                    current.insert("integer");
                }
                "number" => {
                    current.insert("integer");
                    current.insert("non_integer_number");
                }
                _ => return Err(invalid()),
            }
        }
        accepted = Some(match accepted {
            Some(previous) => previous.intersection(&current).copied().collect(),
            None => current,
        });
    }
    let accepted = accepted.ok_or_else(invalid)?;
    if accepted.is_empty() {
        return Ok(None);
    }
    let has_integer = accepted.contains("integer");
    let has_non_integer = accepted.contains("non_integer_number");
    if has_non_integer && !has_integer {
        // No supported JSON Schema type denotes only non-integer numbers.
        return Err(invalid());
    }
    let mut result = Vec::new();
    for kind in ["array", "boolean", "null", "object", "string"] {
        if accepted.contains(kind) {
            result.push(kind.to_owned());
        }
    }
    if has_integer && has_non_integer {
        result.push("number".to_owned());
    } else if has_integer {
        result.push("integer".to_owned());
    }
    result.sort();
    if result.len() == 1 {
        Ok(Some(Value::String(result.remove(0))))
    } else {
        Ok(Some(Value::Array(
            result.into_iter().map(Value::String).collect(),
        )))
    }
}

pub fn intersect_enums(values: &[&Value]) -> Result<Option<Vec<Value>>> {
    let mut intersection: Option<Vec<Value>> = None;
    for value in values {
        let options = value
            .as_array()
            .filter(|options| !options.is_empty())
            .ok_or_else(invalid)?;
        let mut normalized = options.clone();
        normalized.sort_by_key(std::string::ToString::to_string);
        normalized.dedup();
        intersection = Some(match intersection {
            Some(mut previous) => {
                previous.retain(|candidate| normalized.contains(candidate));
                previous
            }
            None => normalized,
        });
    }
    let intersection = intersection.ok_or_else(invalid)?;
    Ok((!intersection.is_empty()).then_some(intersection))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorDriftKind {
    Permission,
    Trigger,
    ParameterDefault,
    Schema,
    ProtocolRevision,
}

pub fn defaults(value: &Value) -> Vec<(String, Value)> {
    fn visit(value: &Value, path: &str, out: &mut Vec<(String, Value)>) {
        if let Some(object) = value.as_object() {
            if let Some(default) = object.get("default") {
                out.push((path.to_owned(), default.clone()));
            }
            for (key, child) in object {
                if key != "default" {
                    visit(child, &format!("{path}/{key}"), out);
                }
            }
        } else if let Some(array) = value.as_array() {
            for (index, child) in array.iter().enumerate() {
                visit(child, &format!("{path}/{index}"), out);
            }
        }
    }
    let mut result = Vec::new();
    visit(value, "", &mut result);
    result
}
