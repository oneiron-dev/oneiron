//! The flat form a parked question asks (FIX 16029; MCP 2025-11-25 form
//! mode): string, number, integer and boolean fields, strings with choices,
//! read at park and checked again against the owner's values at submit.

use serde_json::{Map, Value};

const NOT_FLAT: &str = "the requested schema is not a flat object of primitive fields";
const NOT_PRIMITIVE: &str = "a requested field is not a string, number, integer or boolean";
const WRONG_TYPE: &str = "an answered value is not of its field's type";
const OUT_OF_CHOICES: &str = "an answered value is not one of its field's choices";
const OUT_OF_BOUNDS: &str = "an answered value is outside its field's bounds";

/// A flat form (MCP 2025-11-25 form mode): its fields in the order the
/// provider named them, and the ones it requires.
pub(super) struct FormSchema {
    fields: Vec<(String, FieldKind)>,
    required: Vec<String>,
}

/// One form field's kind, as its schema reads.
enum FieldKind {
    Text {
        choices: Option<Vec<String>>,
        min_length: Option<u64>,
        max_length: Option<u64>,
    },
    Number {
        integer: bool,
        minimum: Option<f64>,
        maximum: Option<f64>,
    },
    Boolean,
}

impl FormSchema {
    pub(super) fn read(schema: &Value) -> Result<Self, &'static str> {
        let schema = schema.as_object().ok_or(NOT_FLAT)?;
        if schema.get("type").and_then(Value::as_str) != Some("object") {
            return Err(NOT_FLAT);
        }
        let mut fields = Vec::new();
        if let Some(properties) = schema.get("properties") {
            for (name, property) in properties.as_object().ok_or(NOT_FLAT)? {
                fields.push((name.clone(), FieldKind::read(property)?));
            }
        }
        let mut required = Vec::new();
        if let Some(names) = schema.get("required") {
            for name in names.as_array().ok_or(NOT_FLAT)? {
                let name = name.as_str().ok_or(NOT_FLAT)?;
                if !fields.iter().any(|(field, _)| field == name) {
                    return Err("the requested schema requires a field it does not name");
                }
                required.push(name.to_owned());
            }
        }
        Ok(Self { fields, required })
    }

    pub(super) fn field_names(&self) -> Vec<String> {
        self.fields.iter().map(|(name, _)| name.clone()).collect()
    }

    /// Whether `content` answers this form: every field it names asked
    /// for, of its kind, and every required one there.
    pub(super) fn check(&self, content: &Map<String, Value>) -> Result<(), &'static str> {
        for (name, value) in content {
            let (_, kind) = self
                .fields
                .iter()
                .find(|(field, _)| field == name)
                .ok_or("the answer names a field the question does not ask for")?;
            kind.check(value)?;
        }
        if self.required.iter().any(|name| !content.contains_key(name)) {
            return Err("the answer leaves out a field the question requires");
        }
        Ok(())
    }
}

impl FieldKind {
    fn read(property: &Value) -> Result<Self, &'static str> {
        let property = property.as_object().ok_or(NOT_PRIMITIVE)?;
        if ["properties", "items", "$ref", "allOf", "anyOf"]
            .iter()
            .any(|key| property.contains_key(*key))
        {
            return Err(NOT_PRIMITIVE);
        }
        let choices = property.contains_key("enum") || property.contains_key("oneOf");
        match property.get("type").and_then(Value::as_str) {
            Some("string") => Ok(Self::Text {
                choices: read_choices(property)?,
                min_length: read_count(property, "minLength")?,
                max_length: read_count(property, "maxLength")?,
            }),
            Some(kind @ ("number" | "integer")) if !choices => Ok(Self::Number {
                integer: kind == "integer",
                minimum: read_bound(property, "minimum")?,
                maximum: read_bound(property, "maximum")?,
            }),
            Some("boolean") if !choices => Ok(Self::Boolean),
            _ => Err(NOT_PRIMITIVE),
        }
    }

    fn check(&self, value: &Value) -> Result<(), &'static str> {
        match (self, value) {
            (
                Self::Text {
                    choices,
                    min_length,
                    max_length,
                },
                Value::String(text),
            ) => {
                if choices
                    .as_ref()
                    .is_some_and(|choices| !choices.contains(text))
                {
                    return Err(OUT_OF_CHOICES);
                }
                let length = u64::try_from(text.chars().count()).unwrap_or(u64::MAX);
                if min_length.is_some_and(|min| length < min)
                    || max_length.is_some_and(|max| length > max)
                {
                    return Err(OUT_OF_BOUNDS);
                }
                Ok(())
            }
            (
                Self::Number {
                    integer,
                    minimum,
                    maximum,
                },
                Value::Number(number),
            ) => {
                let Some(found) = number.as_f64() else {
                    return Err(WRONG_TYPE);
                };
                if *integer && !(number.is_i64() || number.is_u64() || found.fract() == 0.0) {
                    return Err(WRONG_TYPE);
                }
                if minimum.is_some_and(|min| found < min) || maximum.is_some_and(|max| found > max)
                {
                    return Err(OUT_OF_BOUNDS);
                }
                Ok(())
            }
            (Self::Boolean, Value::Bool(_)) => Ok(()),
            _ => Err(WRONG_TYPE),
        }
    }
}

/// A string field's choices: its `enum` values and its `oneOf` options'
/// `const` values; `None` for a field that names neither.
fn read_choices(property: &Map<String, Value>) -> Result<Option<Vec<String>>, &'static str> {
    let mut choices = Vec::new();
    if let Some(values) = property.get("enum") {
        for value in values.as_array().ok_or(NOT_PRIMITIVE)? {
            choices.push(value.as_str().ok_or(NOT_PRIMITIVE)?.to_owned());
        }
    }
    if let Some(options) = property.get("oneOf") {
        for option in options.as_array().ok_or(NOT_PRIMITIVE)? {
            let value = option
                .get("const")
                .and_then(Value::as_str)
                .ok_or(NOT_PRIMITIVE)?;
            choices.push(value.to_owned());
        }
    }
    let named = property.contains_key("enum") || property.contains_key("oneOf");
    if named && choices.is_empty() {
        return Err(NOT_PRIMITIVE);
    }
    Ok(named.then_some(choices))
}

fn read_count(property: &Map<String, Value>, key: &str) -> Result<Option<u64>, &'static str> {
    property
        .get(key)
        .map(|value| value.as_u64().ok_or(NOT_PRIMITIVE))
        .transpose()
}

fn read_bound(property: &Map<String, Value>, key: &str) -> Result<Option<f64>, &'static str> {
    property
        .get(key)
        .map(|value| value.as_f64().ok_or(NOT_PRIMITIVE))
        .transpose()
}
