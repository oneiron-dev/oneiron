//! Unconditional credential removal before any context/export format writer.
use std::collections::HashMap;

use serde_json::{Map, Value};

pub fn writer_credential_key(key: &str) -> bool {
    let normalized = key
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase)
        .collect::<String>();
    matches!(
        normalized.as_str(),
        "apikey"
            | "token"
            | "accesstoken"
            | "refreshtoken"
            | "idtoken"
            | "secret"
            | "secretkey"
            | "password"
            | "passwd"
            | "pwd"
            | "bearer"
            | "authorization"
            | "credentials"
            | "credential"
            | "privatekey"
            | "clientsecret"
            | "valuebytes"
            | "signingkey"
            | "signature"
            | "signatures"
            | "privatekeys"
            | "signingkeys"
    )
}

/// The typed tree's `{"type": "entity_reference", "value": [byte, ...]}` node.
pub fn entity_reference_bytes(fields: &Map<String, Value>) -> Option<Vec<u8>> {
    if fields.len() != 2 || fields.get("type")?.as_str()? != "entity_reference" {
        return None;
    }
    json_bytes(fields.get("value")?.as_array()?)
}

pub fn json_bytes(values: &[Value]) -> Option<Vec<u8>> {
    values
        .iter()
        .map(|value| value.as_u64().and_then(|v| u8::try_from(v).ok()))
        .collect()
}

/// A map key read as a field name, whether text, binary, extension or bytes.
pub fn key_name(key: &rmpv::Value) -> Option<String> {
    let bytes = match key {
        rmpv::Value::String(text) => text.as_bytes().to_vec(),
        rmpv::Value::Binary(bytes) | rmpv::Value::Ext(_, bytes) => bytes.clone(),
        rmpv::Value::Array(values) => messagepack_bytes(values)?,
        _ => return None,
    };
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

pub fn messagepack_bytes(values: &[rmpv::Value]) -> Option<Vec<u8>> {
    values
        .iter()
        .map(|value| value.as_u64().and_then(|v| u8::try_from(v).ok()))
        .collect()
}

/// One JSON reading that keeps every object member: a map keeps only the last
/// of two equal keys, and the id's bytes keep both.
pub enum Json {
    Null,
    Byte(u8),
    Text(String),
    List(Vec<Json>),
    Members(Vec<(String, Json)>),
    Other,
}

impl<'de> serde::Deserialize<'de> for Json {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(JsonVisitor)
    }
}

struct JsonVisitor;

impl<'de> serde::de::Visitor<'de> for JsonVisitor {
    type Value = Json;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_unit<E>(self) -> Result<Json, E> {
        Ok(Json::Null)
    }

    fn visit_bool<E>(self, _: bool) -> Result<Json, E> {
        Ok(Json::Other)
    }

    fn visit_u64<E>(self, value: u64) -> Result<Json, E> {
        Ok(u8::try_from(value).map_or(Json::Other, Json::Byte))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Json, E> {
        Ok(u8::try_from(value).map_or(Json::Other, Json::Byte))
    }

    fn visit_f64<E>(self, _: f64) -> Result<Json, E> {
        Ok(Json::Other)
    }

    fn visit_str<E>(self, value: &str) -> Result<Json, E> {
        Ok(Json::Text(value.to_owned()))
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Json, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element()? {
            items.push(item);
        }
        Ok(Json::List(items))
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Json, A::Error> {
        let mut members = Vec::new();
        while let Some(member) = map.next_entry()? {
            members.push(member);
        }
        Ok(Json::Members(members))
    }
}
