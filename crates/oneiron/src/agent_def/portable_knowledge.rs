//! The selected-knowledge facet's bytes (`knowledge/selected.json`).
//!
//! The first form is a bare JSON array of claim exports whose typed ids
//! (`entity_reference` nodes) hold their bytes as a JSON number array. The
//! source-file credential check reads every such array as an encoded payload,
//! so an id whose bytes happened to decode as a MessagePack container dropped
//! its whole pack. The second form wraps the rows in a format marker and
//! writes each typed id as lowercase hex text, which no check reads as a
//! payload. Both forms are read; only the second is written.
use crate::batch::export::ExportEntity;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const FORMAT_V2: &str = "oneiron.agent-knowledge.v2";

/// A selected-knowledge facet's form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KnowledgeFormat {
    /// A bare array; typed ids are byte arrays. Read, never written.
    V1,
    /// `{"format": "oneiron.agent-knowledge.v2", "claims": [...]}`; typed ids
    /// are lowercase hex text.
    V2,
}

impl KnowledgeFormat {
    /// The form every new facet is written in.
    pub(crate) const CURRENT: Self = Self::V2;
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KnowledgeFile {
    format: String,
    claims: Value,
}

pub(crate) fn encode_agent_knowledge(
    format: KnowledgeFormat,
    rows: &[ExportEntity],
) -> Result<Vec<u8>> {
    match format {
        KnowledgeFormat::V1 => serde_json::to_vec(rows).map_err(|_| invalid()),
        KnowledgeFormat::V2 => {
            let mut claims = serde_json::to_value(rows).map_err(|_| invalid())?;
            rewrite_references(&mut claims, hex_reference)?;
            serde_json::to_vec(&KnowledgeFile {
                format: FORMAT_V2.to_owned(),
                claims,
            })
            .map_err(|_| invalid())
        }
    }
}

/// The rows a facet carries, and the form it carries them in. A second-form
/// id spelled any way but lowercase hex is refused, as is a byte array.
pub(crate) fn decode_agent_knowledge(bytes: &[u8]) -> Result<(KnowledgeFormat, Vec<ExportEntity>)> {
    match serde_json::from_slice(bytes).map_err(|_| invalid())? {
        rows @ Value::Array(_) => Ok((
            KnowledgeFormat::V1,
            serde_json::from_value(rows).map_err(|_| invalid())?,
        )),
        file @ Value::Object(_) => {
            let KnowledgeFile { format, mut claims } =
                serde_json::from_value(file).map_err(|_| invalid())?;
            if format != FORMAT_V2 {
                return Err(invalid());
            }
            rewrite_references(&mut claims, byte_reference)?;
            Ok((
                KnowledgeFormat::V2,
                serde_json::from_value(claims).map_err(|_| invalid())?,
            ))
        }
        _ => Err(invalid()),
    }
}

/// Rewrites the value of every typed id node under `value`. Only
/// `ExportValue::EntityReference` serializes as `{"type": "entity_reference",
/// ...}`: every other node carries another tag, and text always sits inside a
/// node of its own, so no claim content can take that shape.
fn rewrite_references(value: &mut Value, rewrite: fn(&Value) -> Option<Value>) -> Result<()> {
    match value {
        Value::Object(fields)
            if fields.get("type").and_then(Value::as_str) == Some("entity_reference") =>
        {
            let id = fields.get_mut("value").ok_or_else(invalid)?;
            *id = rewrite(id).ok_or_else(invalid)?;
        }
        Value::Object(fields) => {
            for field in fields.values_mut() {
                rewrite_references(field, rewrite)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                rewrite_references(value, rewrite)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn hex_reference(bytes: &Value) -> Option<Value> {
    let bytes = bytes
        .as_array()?
        .iter()
        .map(|byte| byte.as_u64().and_then(|byte| u8::try_from(byte).ok()))
        .collect::<Option<Vec<u8>>>()?;
    Some(Value::String(crate::receipt::hex_lower(&bytes)))
}

fn byte_reference(text: &Value) -> Option<Value> {
    let text = text.as_str()?;
    if text.len() % 2 != 0 || !text.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| {
            u8::from_str_radix(&text[at..at + 2], 16)
                .ok()
                .map(Value::from)
        })
        .collect::<Option<Vec<_>>>()
        .map(Value::Array)
}

fn invalid() -> Error {
    Error::InvalidConfig("agent knowledge facet is not typed JSON".into())
}
