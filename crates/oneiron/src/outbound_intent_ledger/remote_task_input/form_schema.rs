//! The flat form a parked question asks (FIX 16029; MCP 2025-11-25 form
//! mode): string, number, integer and boolean fields, strings with choices,
//! read at park and checked again against the owner's values at submit.
//!
//! Every constraint a field states is enforced: its type, choices, lengths
//! and bounds (a string's `enum` and its `oneOf` each on its own, so a value
//! must meet both, and `oneOf`'s exactly-one rule with them), a string's
//! `pattern` (read as the ECMA-262 pattern JSON
//! Schema names, its ASCII classes kept ASCII) and the string formats form
//! mode names (`email`, `uri`, `date`, `date-time`). A schema that states a
//! constraint this reader cannot enforce (any other keyword, another
//! format, a pattern this host cannot compile as written) is refused at
//! park, so no question is parked whose constraints are left unenforced.

use serde_json::{Map, Value};

const NOT_FLAT: &str = "the requested schema is not a flat object of primitive fields";
const NOT_PRIMITIVE: &str = "a requested field is not a string, number, integer or boolean";
const UNENFORCEABLE: &str = "the requested schema states a constraint this host cannot enforce";
const WRONG_TYPE: &str = "an answered value is not of its field's type";
const OUT_OF_CHOICES: &str = "an answered value is not one of its field's choices";
const OUT_OF_BOUNDS: &str = "an answered value is outside its field's bounds";
const OUT_OF_PATTERN: &str = "an answered value does not match its field's pattern";
const OUT_OF_FORMAT: &str = "an answered value is not in its field's format";

/// The most memory one compiled pattern may take.
const PATTERN_SIZE_LIMIT: usize = 1 << 20;

/// The keywords a form's object may state: its fields and annotations.
const FORM_KEYWORDS: &[&str] = &[
    "type",
    "properties",
    "required",
    "additionalProperties",
    "title",
    "description",
    "$schema",
    "$id",
    "$comment",
];

/// The keywords any field may state: its type and annotations, none of
/// which constrains a value.
const FIELD_ANNOTATIONS: &[&str] = &[
    "type",
    "title",
    "description",
    "default",
    "examples",
    "$comment",
    "deprecated",
    "readOnly",
    "writeOnly",
];

/// The constraints a string field may state beside its annotations.
const TEXT_KEYWORDS: &[&str] = &[
    "minLength",
    "maxLength",
    "pattern",
    "format",
    "enum",
    "enumNames",
    "oneOf",
];

/// The constraints a number or integer field may state.
const NUMBER_KEYWORDS: &[&str] = &["minimum", "maximum"];

/// The keywords one `oneOf` choice of a string field may state.
const CHOICE_KEYWORDS: &[&str] = &["const", "title", "description"];

/// A flat form (MCP 2025-11-25 form mode): its fields in the order the
/// provider named them, and the ones it requires.
pub(super) struct FormSchema {
    fields: Vec<(String, FieldKind)>,
    required: Vec<String>,
}

/// One form field's kind, as its schema reads.
enum FieldKind {
    Text {
        /// Its `enum`: the value is one of these.
        choices: Option<Vec<String>>,
        /// Its `oneOf` options' `const` values: the value matches exactly
        /// one option, so a value two options name matches none.
        options: Option<Vec<String>>,
        min_length: Option<u64>,
        max_length: Option<u64>,
        pattern: Option<regex::Regex>,
        format: Option<TextFormat>,
    },
    Number {
        integer: bool,
        minimum: Option<f64>,
        maximum: Option<f64>,
    },
    Boolean,
}

/// The string formats MCP form mode names.
#[derive(Clone, Copy)]
enum TextFormat {
    /// An RFC 5321 mailbox: a dot-atom local part and a host name.
    Email,
    /// An RFC 3986 URI: a scheme, then URI characters only.
    Uri,
    /// An RFC 3339 full-date.
    Date,
    /// An RFC 3339 date-time.
    DateTime,
}

impl FormSchema {
    pub(super) fn read(schema: &Value) -> Result<Self, &'static str> {
        let schema = schema.as_object().ok_or(NOT_FLAT)?;
        if schema.get("type").and_then(Value::as_str) != Some("object") {
            return Err(NOT_FLAT);
        }
        states_only(schema, &[FORM_KEYWORDS])?;
        // Any further field is refused at submit, so either answer to
        // `additionalProperties` is kept; a schema for them is not.
        if schema
            .get("additionalProperties")
            .is_some_and(|extra| !extra.is_boolean())
        {
            return Err(UNENFORCEABLE);
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
            Some("string") => {
                states_only(property, &[FIELD_ANNOTATIONS, TEXT_KEYWORDS])?;
                Ok(Self::Text {
                    choices: read_choices(property)?,
                    options: read_options(property)?,
                    min_length: read_count(property, "minLength")?,
                    max_length: read_count(property, "maxLength")?,
                    pattern: read_pattern(property)?,
                    format: read_format(property)?,
                })
            }
            Some(kind @ ("number" | "integer")) if !choices => {
                states_only(property, &[FIELD_ANNOTATIONS, NUMBER_KEYWORDS])?;
                Ok(Self::Number {
                    integer: kind == "integer",
                    minimum: read_bound(property, "minimum")?,
                    maximum: read_bound(property, "maximum")?,
                })
            }
            Some("boolean") if !choices => {
                states_only(property, &[FIELD_ANNOTATIONS])?;
                Ok(Self::Boolean)
            }
            _ => Err(NOT_PRIMITIVE),
        }
    }

    fn check(&self, value: &Value) -> Result<(), &'static str> {
        match (self, value) {
            (
                Self::Text {
                    choices,
                    options,
                    min_length,
                    max_length,
                    pattern,
                    format,
                },
                Value::String(text),
            ) => {
                if choices
                    .as_ref()
                    .is_some_and(|choices| !choices.contains(text))
                {
                    return Err(OUT_OF_CHOICES);
                }
                // `oneOf`: exactly one option matches.
                if options.as_ref().is_some_and(|options| {
                    options.iter().filter(|option| *option == text).count() != 1
                }) {
                    return Err(OUT_OF_CHOICES);
                }
                // JSON Schema counts a string's length in code points.
                let length = u64::try_from(text.chars().count()).unwrap_or(u64::MAX);
                if min_length.is_some_and(|min| length < min)
                    || max_length.is_some_and(|max| length > max)
                {
                    return Err(OUT_OF_BOUNDS);
                }
                if pattern
                    .as_ref()
                    .is_some_and(|pattern| !pattern.is_match(text))
                {
                    return Err(OUT_OF_PATTERN);
                }
                if format.is_some_and(|format| !format.admits(text)) {
                    return Err(OUT_OF_FORMAT);
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

impl TextFormat {
    fn read(name: &str) -> Option<Self> {
        match name {
            "email" => Some(Self::Email),
            "uri" => Some(Self::Uri),
            "date" => Some(Self::Date),
            "date-time" => Some(Self::DateTime),
            _ => None,
        }
    }

    fn admits(self, text: &str) -> bool {
        match self {
            Self::Email => is_email(text),
            Self::Uri => is_uri(text),
            Self::Date => is_full_date(text),
            Self::DateTime => chrono::DateTime::parse_from_rfc3339(text).is_ok(),
        }
    }
}

/// Refuses a schema object that states a keyword none of `allowed` names:
/// a constraint this reader would leave unenforced.
fn states_only(object: &Map<String, Value>, allowed: &[&[&str]]) -> Result<(), &'static str> {
    if object
        .keys()
        .all(|key| allowed.iter().any(|names| names.contains(&key.as_str())))
    {
        Ok(())
    } else {
        Err(UNENFORCEABLE)
    }
}

/// A string field's `enum` values; `None` for a field that names none.
fn read_choices(property: &Map<String, Value>) -> Result<Option<Vec<String>>, &'static str> {
    let Some(values) = property.get("enum") else {
        return Ok(None);
    };
    let mut choices = Vec::new();
    for value in values.as_array().ok_or(NOT_PRIMITIVE)? {
        choices.push(value.as_str().ok_or(NOT_PRIMITIVE)?.to_owned());
    }
    if choices.is_empty() {
        return Err(NOT_PRIMITIVE);
    }
    Ok(Some(choices))
}

/// A string field's `oneOf` options, each its `const` value, in the order
/// named and duplicates kept, so the check counts the options a value
/// matches; `None` for a field that names none.
fn read_options(property: &Map<String, Value>) -> Result<Option<Vec<String>>, &'static str> {
    let Some(options) = property.get("oneOf") else {
        return Ok(None);
    };
    let mut values = Vec::new();
    for option in options.as_array().ok_or(NOT_PRIMITIVE)? {
        states_only(option.as_object().ok_or(NOT_PRIMITIVE)?, &[CHOICE_KEYWORDS])?;
        let value = option
            .get("const")
            .and_then(Value::as_str)
            .ok_or(NOT_PRIMITIVE)?;
        values.push(value.to_owned());
    }
    if values.is_empty() {
        return Err(NOT_PRIMITIVE);
    }
    Ok(Some(values))
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

/// A string field's `pattern`, compiled; refused when this host cannot
/// compile it as the ECMA-262 pattern it states.
fn read_pattern(property: &Map<String, Value>) -> Result<Option<regex::Regex>, &'static str> {
    let Some(pattern) = property.get("pattern") else {
        return Ok(None);
    };
    let pattern = ascii_classes(pattern.as_str().ok_or(NOT_PRIMITIVE)?)?;
    regex::RegexBuilder::new(&pattern)
        .size_limit(PATTERN_SIZE_LIMIT)
        .build()
        .map(Some)
        .map_err(|_| UNENFORCEABLE)
}

/// A string field's `format`; refused when it names one form mode does not.
fn read_format(property: &Map<String, Value>) -> Result<Option<TextFormat>, &'static str> {
    property
        .get("format")
        .map(|format| {
            format
                .as_str()
                .and_then(TextFormat::read)
                .ok_or(UNENFORCEABLE)
        })
        .transpose()
}

/// `pattern` with the ECMA-262 classes `\d`, `\D`, `\w` and `\W`, which are
/// ASCII there and Unicode in this host's regex, written out as their ASCII
/// sets. A negated class inside a bracket and a word boundary have no such
/// spelling here: they are refused.
fn ascii_classes(pattern: &str) -> Result<String, &'static str> {
    let mut out = String::with_capacity(pattern.len());
    let mut in_class = false;
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                let escaped = chars.next().ok_or(UNENFORCEABLE)?;
                match (escaped, in_class) {
                    ('d', false) => out.push_str("[0-9]"),
                    ('D', false) => out.push_str("[^0-9]"),
                    ('w', false) => out.push_str("[0-9A-Za-z_]"),
                    ('W', false) => out.push_str("[^0-9A-Za-z_]"),
                    ('d', true) => out.push_str("0-9"),
                    ('w', true) => out.push_str("0-9A-Za-z_"),
                    ('D' | 'W' | 'b' | 'B', _) => return Err(UNENFORCEABLE),
                    (escaped, _) => {
                        out.push('\\');
                        out.push(escaped);
                    }
                }
            }
            '[' if !in_class => {
                in_class = true;
                out.push(c);
            }
            ']' if in_class => {
                in_class = false;
                out.push(c);
            }
            c => out.push(c),
        }
    }
    Ok(out)
}

/// An RFC 3339 full-date: `YYYY-MM-DD`, a day its month has.
fn is_full_date(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() != 10 || bytes.get(4) != Some(&b'-') || bytes.get(7) != Some(&b'-') {
        return false;
    }
    let (Some(year), Some(month), Some(day)) = (text.get(0..4), text.get(5..7), text.get(8..10))
    else {
        return false;
    };
    if ![year, month, day]
        .iter()
        .all(|part| part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return false;
    }
    match (
        year.parse::<i32>(),
        month.parse::<u32>(),
        day.parse::<u32>(),
    ) {
        (Ok(year), Ok(month), Ok(day)) => {
            chrono::NaiveDate::from_ymd_opt(year, month, day).is_some()
        }
        _ => false,
    }
}

/// An RFC 5321 mailbox as JSON Schema's `email` reads it: a dot-atom local
/// part of at most 64 octets, `@`, and a host name; 254 octets at most.
fn is_email(text: &str) -> bool {
    let Some((local, domain)) = text.rsplit_once('@') else {
        return false;
    };
    text.len() <= 254
        && !local.is_empty()
        && local.len() <= 64
        && local
            .split('.')
            .all(|atom| !atom.is_empty() && atom.bytes().all(is_atext))
        && is_host_name(domain)
}

/// An RFC 5322 `atext` octet.
fn is_atext(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~".contains(&byte)
}

/// A host name: dot-separated labels of letters, digits and inner hyphens,
/// each 63 octets at most, 253 in all.
fn is_host_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

/// An RFC 3986 URI: a scheme (a letter, then letters, digits, `+`, `-` or
/// `.`), `:`, then only unreserved, reserved and percent-encoded octets,
/// with at most one `#`.
fn is_uri(text: &str) -> bool {
    let Some((scheme, rest)) = text.split_once(':') else {
        return false;
    };
    let mut scheme = scheme.bytes();
    if !scheme.next().is_some_and(|byte| byte.is_ascii_alphabetic())
        || !scheme.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
    {
        return false;
    }
    let bytes = rest.as_bytes();
    let mut fragment = false;
    let mut at = 0;
    while let Some(&byte) = bytes.get(at) {
        match byte {
            b'%' => {
                let hex = |offset: usize| bytes.get(at + offset).is_some_and(u8::is_ascii_hexdigit);
                if !(hex(1) && hex(2)) {
                    return false;
                }
                at += 3;
                continue;
            }
            b'#' if !fragment => fragment = true,
            byte if byte.is_ascii_alphanumeric() || b"-._~:/?[]@!$&'()*+,;=".contains(&byte) => {}
            _ => return false,
        }
        at += 1;
    }
    true
}
