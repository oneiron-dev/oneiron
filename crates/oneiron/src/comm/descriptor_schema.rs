//! The JSON Schema half of the claim-class descriptors: compiling a schema,
//! reading a claim value as JSON for it, and the build's compiled `generic`
//! classes, each with its schema compiled once.
//!
//! A schema is Draft 2020-12 with one engine keyword, `maxUtf8Bytes`: a
//! string's UTF-8 length is at most its bound. JSON Schema's own `maxLength`
//! counts code points, and the claim families bound their text in bytes.

use std::sync::LazyLock;

use jsonschema::Keyword;
use jsonschema::paths::{LazyLocation, Location};
use rmpv::Value;
use serde_json::json;

use super::descriptor::ClaimSubjectKind;
use crate::error::{Error, Result};

/// The engine keyword bounding a string's UTF-8 length.
const KEYWORD_MAX_UTF8_BYTES: &str = "maxUtf8Bytes";

/// A CRM-pack token's first and last character: no ASCII capital, no control
/// character and no white space (what `trim` removes).
const TOKEN_END_CHAR: &str =
    r"[^A-Z\u0000-\u0020\u007F-\u00A0\u1680\u2000-\u200A\u2028\u2029\u202F\u205F\u3000]";

/// A CRM-pack token's inner character: no ASCII capital and no control
/// character.
const TOKEN_INNER_CHAR: &str = r"[^A-Z\u0000-\u001F\u007F-\u009F]";

/// A CRM-pack text field's bound, in UTF-8 bytes.
const TOKEN_MAX_UTF8_BYTES: u64 = 512;

/// One compiled `generic` claim class: the subject its claims may name, its
/// value schema, and that schema compiled once.
pub(super) struct GenericClassSeed {
    /// The subject its claims may name.
    pub(super) subject_kind: ClaimSubjectKind,
    /// The value schema.
    pub(super) schema: serde_json::Value,
    /// `schema` compiled; `None` when it does not compile.
    validator: Option<jsonschema::Validator>,
}

impl GenericClassSeed {
    fn new(subject_kind: ClaimSubjectKind, schema: serde_json::Value) -> Self {
        let validator = compile_schema(&schema).ok();
        Self {
            subject_kind,
            schema,
            validator,
        }
    }

    /// Whether `value` meets the class's schema.
    ///
    /// # Errors
    /// The compiled schema does not compile: a build defect, refused rather
    /// than passed.
    pub(super) fn admits_value(&self, value: &serde_json::Value) -> Result<bool> {
        self.validator
            .as_ref()
            .map(|validator| validator.is_valid(value))
            .ok_or(Error::InvariantViolation(
                "a compiled claim-class schema does not compile",
            ))
    }
}

/// `comm.do_not_contact`: an entity subject, and exactly the value the CRM
/// pack's codec admits. A map of a required `scope` and an optional
/// `channel`, each a token of at most 512 UTF-8 bytes in the codec's
/// normalized form: non-empty, no control character, no ASCII capital, and
/// no white space at either end.
static DO_NOT_CONTACT: LazyLock<GenericClassSeed> = LazyLock::new(|| {
    let token_pattern = format!("^{TOKEN_END_CHAR}(?:{TOKEN_INNER_CHAR}*{TOKEN_END_CHAR})?$");
    GenericClassSeed::new(
        ClaimSubjectKind::Entity,
        json!({
            "type": "object",
            "properties": {
                "channel": {"$ref": "#/$defs/token"},
                "scope": {"$ref": "#/$defs/token"}
            },
            "required": ["scope"],
            "additionalProperties": false,
            "$defs": {
                "token": {
                    "type": "string",
                    "minLength": 1,
                    KEYWORD_MAX_UTF8_BYTES: TOKEN_MAX_UTF8_BYTES,
                    "pattern": token_pattern
                }
            }
        }),
    )
});

/// The build's compiled `generic` class for `predicate`, when it has one.
/// Every other compiled class is `builtin`.
pub(super) fn generic_class_seed(predicate: &str) -> Option<&'static GenericClassSeed> {
    match predicate {
        crate::campaign::claims::PREDICATE_COMM_DO_NOT_CONTACT => Some(&*DO_NOT_CONTACT),
        _ => None,
    }
}

/// Whether `value` meets `schema`, the schema of `predicate`'s class: through
/// the compiled class's validator when `schema` is its schema, else compiled
/// here.
pub(super) fn value_meets_schema(
    predicate: &str,
    schema: &serde_json::Value,
    value: &serde_json::Value,
) -> Result<bool> {
    match generic_class_seed(predicate) {
        Some(seed) if seed.schema == *schema => seed.admits_value(value),
        _ => Ok(compile_schema(schema)?.is_valid(value)),
    }
}

/// Checks `schema`, the schema of `predicate`'s class, compiles: known
/// without compiling it again when it is the compiled class's schema.
pub(super) fn check_schema_compiles(predicate: &str, schema: &serde_json::Value) -> Result<()> {
    match generic_class_seed(predicate) {
        Some(seed) if seed.schema == *schema && seed.validator.is_some() => Ok(()),
        _ => compile_schema(schema).map(drop),
    }
}

/// A schema as the body and the semantics hash carry it.
pub(super) fn schema_text(schema: &serde_json::Value) -> String {
    schema.to_string()
}

/// The schema compiled: Draft 2020-12 whatever it declares, with the
/// engine's `maxUtf8Bytes` keyword, local references only (the engine is
/// built without remote resolution).
fn compile_schema(schema: &serde_json::Value) -> Result<jsonschema::Validator> {
    jsonschema::draft202012::options()
        .with_keyword(KEYWORD_MAX_UTF8_BYTES, max_utf8_bytes_keyword)
        .build(schema)
        .map_err(|_| Error::InvalidClaimBody("a claim class's schema is not a valid JSON Schema"))
}

/// `maxUtf8Bytes` compiled: its bound is a non-negative integer.
fn max_utf8_bytes_keyword<'a>(
    _: &'a serde_json::Map<String, serde_json::Value>,
    bound: &'a serde_json::Value,
    path: Location,
) -> std::result::Result<Box<dyn Keyword>, jsonschema::ValidationError<'a>> {
    let Some(max) = bound.as_u64() else {
        return Err(jsonschema::ValidationError::custom(
            path,
            Location::new(),
            bound,
            "maxUtf8Bytes is a non-negative integer",
        ));
    };
    Ok(Box::new(MaxUtf8Bytes(max)))
}

/// A string's UTF-8 length is at most the bound; any other value passes.
struct MaxUtf8Bytes(u64);

impl Keyword for MaxUtf8Bytes {
    fn validate<'i>(
        &self,
        instance: &'i serde_json::Value,
        location: &LazyLocation<'_, '_>,
    ) -> std::result::Result<(), jsonschema::ValidationError<'i>> {
        if self.is_valid(instance) {
            return Ok(());
        }
        Err(jsonschema::ValidationError::custom(
            Location::new(),
            location.into(),
            instance,
            "string is longer than maxUtf8Bytes",
        ))
    }

    fn is_valid(&self, instance: &serde_json::Value) -> bool {
        instance
            .as_str()
            .is_none_or(|text| u64::try_from(text.len()).is_ok_and(|len| len <= self.0))
    }
}

/// A claim value as JSON, for a schema to check. `None` for what JSON cannot
/// hold as it is: bytes, extension types, a map key that is not a string or
/// is repeated, a non-UTF-8 string and a number that is not finite.
pub(super) fn json_value(value: &Value) -> Option<serde_json::Value> {
    Some(match value {
        Value::Nil => serde_json::Value::Null,
        Value::Boolean(flag) => serde_json::Value::Bool(*flag),
        Value::Integer(number) => match number.as_u64() {
            Some(unsigned) => unsigned.into(),
            None => number.as_i64()?.into(),
        },
        Value::F32(number) => serde_json::Number::from_f64(f64::from(*number))?.into(),
        Value::F64(number) => serde_json::Number::from_f64(*number)?.into(),
        Value::String(text) => text.as_str()?.into(),
        Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(json_value).collect::<Option<Vec<_>>>()?)
        }
        Value::Map(entries) => {
            let mut map = serde_json::Map::new();
            for (key, item) in entries {
                if map
                    .insert(key.as_str()?.to_owned(), json_value(item)?)
                    .is_some()
                {
                    return None;
                }
            }
            serde_json::Value::Object(map)
        }
        Value::Binary(_) | Value::Ext(..) => return None,
    })
}
