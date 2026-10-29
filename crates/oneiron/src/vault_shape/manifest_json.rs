//! A policy manifest's JSON form (FIX 2760): the same MessagePack body as a
//! document a seed author can write by hand. A map whose keys are all text
//! reads as an object in its own key order, an array as an array, and text,
//! booleans, nil, integers and 64-bit floats as themselves. The form is
//! offered only where it is lossless: written back, it encodes to exactly
//! the stored bytes. A body holding binary, an extension, a 32-bit float, a
//! non-text or repeated map key, or a number encoded wider than its value
//! needs has no JSON form, and its hex stays the only one.
use super::seed::hex;
use super::{ShapeRow, ShapeSeed};
use rmpv::Value;
use serde_json::{Map, Number, Value as Json};

/// The JSON form of the manifest `body`, when writing it back gives exactly
/// `body`; else none.
pub(super) fn manifest_json(body: &[u8]) -> Option<Json> {
    let mut rest = body;
    let value = rmpv::decode::read_value(&mut rest).ok()?;
    if !rest.is_empty() {
        return None;
    }
    let json = to_json(&value)?;
    (manifest_from_json(&json)?.as_slice() == body).then_some(json)
}

/// The MessagePack bytes a manifest's JSON form writes.
pub(super) fn manifest_from_json(json: &Json) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &from_json(json)?).ok()?;
    Some(bytes)
}

fn to_json(value: &Value) -> Option<Json> {
    Some(match value {
        Value::Nil => Json::Null,
        Value::Boolean(flag) => Json::Bool(*flag),
        Value::Integer(number) => match (number.as_u64(), number.as_i64()) {
            (Some(unsigned), _) => Json::Number(unsigned.into()),
            (None, Some(signed)) => Json::Number(signed.into()),
            (None, None) => return None,
        },
        Value::F64(float) => Json::Number(Number::from_f64(*float)?),
        Value::String(text) => Json::String(text.as_str()?.to_owned()),
        Value::Array(items) => Json::Array(items.iter().map(to_json).collect::<Option<_>>()?),
        Value::Map(entries) => {
            let mut object = Map::with_capacity(entries.len());
            for (key, value) in entries {
                if object
                    .insert(key.as_str()?.to_owned(), to_json(value)?)
                    .is_some()
                {
                    return None;
                }
            }
            Json::Object(object)
        }
        Value::F32(_) | Value::Binary(_) | Value::Ext(..) => return None,
    })
}

fn from_json(json: &Json) -> Option<Value> {
    Some(match json {
        Json::Null => Value::Nil,
        Json::Bool(flag) => Value::Boolean(*flag),
        Json::Number(number) => match (number.as_u64(), number.as_i64()) {
            (Some(unsigned), _) => Value::from(unsigned),
            (None, Some(signed)) => Value::from(signed),
            (None, None) => Value::F64(number.as_f64()?),
        },
        Json::String(text) => Value::from(text.as_str()),
        Json::Array(items) => Value::Array(items.iter().map(from_json).collect::<Option<_>>()?),
        Json::Object(object) => Value::Map(
            object
                .iter()
                .map(|(key, value)| Some((Value::from(key.as_str()), from_json(value)?)))
                .collect::<Option<_>>()?,
        ),
    })
}

impl ShapeSeed {
    /// This seed, each manifest row that states its body by its JSON form
    /// alone given the hex that form writes. A row stating its hex keeps
    /// it: the hex is the authority.
    pub(super) fn with_manifest_bodies(mut self) -> Self {
        for row in &mut self.rows {
            if let ShapeRow::Manifest {
                body,
                json: Some(json),
                ..
            } = row
                && body.is_empty()
                && let Some(bytes) = manifest_from_json(json)
            {
                *body = hex(&bytes);
            }
        }
        self
    }
}
