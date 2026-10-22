//! Fail-closed structural JSON Schema subset for resolved outbound descriptors.
use std::cmp::Ordering;
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
    if let Some(number) = Number::of(value)
        && !number_matches(fields, number)?
    {
        return Ok(false);
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

/// The `properties` maps that apply to `value` under `schema`: the root's,
/// then those of every `anyOf`/`oneOf` variant, taken `if`/`then`/`else`
/// branch and `dependentSchemas` entry the value meets, nested ones too, as
/// [`validate`] reads them (FIX 8810). With no value, every branch counts:
/// the properties a call can meet at all.
pub(super) fn applicable_properties<'a>(
    schema: &'a Value,
    value: Option<(&Value, &str)>,
) -> Result<Vec<&'a serde_json::Map<String, Value>>> {
    let mut found = Vec::new();
    collect_properties(schema, value, &mut found)?;
    Ok(found)
}

fn collect_properties<'a>(
    schema: &'a Value,
    value: Option<(&Value, &str)>,
    found: &mut Vec<&'a serde_json::Map<String, Value>>,
) -> Result<()> {
    let Some(fields) = schema.as_object() else {
        return Ok(());
    };
    found.extend(fields.get("properties").and_then(Value::as_object));
    let meets =
        |branch: &Value| value.map_or(Ok(true), |(value, tool)| matches(branch, value, tool));
    let mut branches = Vec::new();
    for variants in ["anyOf", "oneOf"].map(|name| fields.get(name).and_then(Value::as_array)) {
        for variant in variants.into_iter().flatten() {
            if meets(variant)? {
                branches.push(variant);
            }
        }
    }
    if let Some(condition) = fields.get("if") {
        let (then, otherwise) = (fields.get("then"), fields.get("else"));
        if value.is_none() {
            branches.extend(then.into_iter().chain(otherwise));
        } else if meets(condition)? {
            branches.extend(then);
        } else {
            branches.extend(otherwise);
        }
    }
    if let Some(dependent) = fields.get("dependentSchemas").and_then(Value::as_object) {
        branches.extend(
            dependent
                .iter()
                .filter(|(key, _)| value.is_none_or(|(value, _)| value.get(key.as_str()).is_some()))
                .map(|(_, rule)| rule),
        );
    }
    for branch in branches {
        collect_properties(branch, value, found)?;
    }
    Ok(())
}

/// Refuses a `$ref` or `allOf` left in any schema position of `schema`. A
/// parameter-name map is read for its schemas, never as one, and a literal
/// (`enum`, `const`, `default`, `examples`) is never read (FIX 8812).
pub(super) fn reject_unresolved(schema: &Value) -> Result<()> {
    let Some(fields) = schema.as_object() else {
        return Ok(());
    };
    if fields.contains_key("$ref") || fields.contains_key("allOf") {
        return Err(invalid_schema());
    }
    for (key, child) in fields {
        match key.as_str() {
            "properties" | "patternProperties" | "dependentSchemas" | "$defs" | "definitions" => {
                for rule in child
                    .as_object()
                    .into_iter()
                    .flat_map(serde_json::Map::values)
                {
                    reject_unresolved(rule)?;
                }
            }
            "anyOf" | "oneOf" | "prefixItems" => {
                for rule in child.as_array().into_iter().flatten() {
                    reject_unresolved(rule)?;
                }
            }
            "items" if child.is_array() => {
                for rule in child.as_array().into_iter().flatten() {
                    reject_unresolved(rule)?;
                }
            }
            "items"
            | "additionalProperties"
            | "not"
            | "if"
            | "then"
            | "else"
            | "propertyNames"
            | "contains" => reject_unresolved(child)?,
            _ => {}
        }
    }
    Ok(())
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

/// Whether `number` meets the numeric keywords in `fields`.
fn number_matches(fields: &serde_json::Map<String, Value>, number: Number) -> Result<bool> {
    let beyond = |name: &str, outside: &[Ordering]| -> Result<bool> {
        Ok(bound(fields, name)?
            .and_then(|bound| number.compare(bound))
            .is_some_and(|order| outside.contains(&order)))
    };
    if beyond("minimum", &[Ordering::Less])?
        || beyond("maximum", &[Ordering::Greater])?
        || beyond("exclusiveMinimum", &[Ordering::Less, Ordering::Equal])?
        || beyond("exclusiveMaximum", &[Ordering::Greater, Ordering::Equal])?
    {
        return Ok(false);
    }
    let Some(step) = bound(fields, "multipleOf")? else {
        return Ok(true);
    };
    if !step.is_positive() {
        return Err(invalid_schema());
    }
    Ok(match (number, step) {
        (Number::Int(number), Number::Int(step)) => number % step == 0,
        _ => {
            let ratio = number.float() / step.float();
            (ratio - ratio.round()).abs() <= MULTIPLE_OF_TOLERANCE
        }
    })
}

/// A JSON number. An integer stays exact (every `i64` and `u64` fits an
/// `i128`), so an integer payload meets an integer bound without rounding
/// either through `f64` (FIX 8809); a real float compares as `f64`.
#[derive(Clone, Copy)]
enum Number {
    Int(i128),
    Float(f64),
}

impl Number {
    fn of(value: &Value) -> Option<Self> {
        let number = value.as_number()?;
        if let Some(int) = number.as_i64() {
            Some(Self::Int(i128::from(int)))
        } else if let Some(int) = number.as_u64() {
            Some(Self::Int(i128::from(int)))
        } else {
            number.as_f64().map(Self::Float)
        }
    }

    fn float(self) -> f64 {
        match self {
            Self::Int(int) => int as f64,
            Self::Float(float) => float,
        }
    }

    /// `self` against `other`: exact when both are integers, as `f64` when
    /// either is a real float.
    fn compare(self, other: Self) -> Option<Ordering> {
        match (self, other) {
            (Self::Int(this), Self::Int(other)) => Some(this.cmp(&other)),
            _ => self.float().partial_cmp(&other.float()),
        }
    }

    fn is_positive(self) -> bool {
        match self {
            Self::Int(int) => int > 0,
            Self::Float(float) => float > 0.0,
        }
    }
}

/// A numeric keyword's bound; a non-number refuses.
fn bound(fields: &serde_json::Map<String, Value>, name: &str) -> Result<Option<Number>> {
    fields
        .get(name)
        .map(|value| Number::of(value).ok_or_else(invalid_schema))
        .transpose()
}

/// A count keyword's bound; anything but a non-negative integer refuses.
fn count(fields: &serde_json::Map<String, Value>, name: &str) -> Result<Option<u64>> {
    fields
        .get(name)
        .map(|value| value.as_u64().ok_or_else(invalid_schema))
        .transpose()
}
