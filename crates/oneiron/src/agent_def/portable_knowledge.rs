//! The selected-knowledge facet's bytes (`knowledge/selected.json`).
//!
//! The first form is a bare JSON array of claim exports whose typed ids
//! (`entity_reference` nodes) hold their bytes as a JSON number array. The
//! source-file credential check reads every such array as an encoded payload,
//! so an id whose bytes happened to decode as a MessagePack container dropped
//! its whole pack. The second form leads the same array with a format marker
//! and writes each typed id as lowercase hex text, which no check reads as a
//! payload. The rows sit at the depth they had, so the check's depth bound
//! reads them as it did. Both forms are read; only the second is written.
use crate::batch::export::ExportEntity;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CLAIM;
use serde_json::Value;

const FORMAT_V2: &str = "oneiron.agent-knowledge.v2";

/// A selected-knowledge facet's form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KnowledgeFormat {
    /// `[row, ...]`; typed ids are byte arrays. Read, never written.
    V1,
    /// `["oneiron.agent-knowledge.v2", row, ...]`; typed ids are lowercase
    /// hex text. A row is an object, so a leading string is only a marker.
    V2,
}

impl KnowledgeFormat {
    /// The form every new facet is written in.
    pub(crate) const CURRENT: Self = Self::V2;
}

pub(crate) fn encode_agent_knowledge(
    format: KnowledgeFormat,
    rows: &[ExportEntity],
) -> Result<Vec<u8>> {
    match format {
        KnowledgeFormat::V1 => serde_json::to_vec(rows).map_err(|_| invalid()),
        KnowledgeFormat::V2 => {
            let mut file = vec![Value::from(FORMAT_V2)];
            for row in rows {
                let mut row = serde_json::to_value(row).map_err(|_| invalid())?;
                rewrite_references(&mut row, hex_reference)?;
                file.push(row);
            }
            serde_json::to_vec(&file).map_err(|_| invalid())
        }
    }
}

/// The rows a facet carries, and the form it carries them in. A second-form
/// id spelled any way but lowercase hex is refused, as is a byte array, and
/// so is any row the export would not have written.
pub(crate) fn decode_agent_knowledge(bytes: &[u8]) -> Result<(KnowledgeFormat, Vec<ExportEntity>)> {
    let Value::Array(mut rows) = serde_json::from_slice(bytes).map_err(|_| invalid())? else {
        return Err(invalid());
    };
    let format = match rows.first() {
        Some(Value::String(marker)) if marker == FORMAT_V2 => KnowledgeFormat::V2,
        Some(Value::String(_)) => return Err(invalid()),
        _ => KnowledgeFormat::V1,
    };
    if format == KnowledgeFormat::V2 {
        rows.remove(0);
        for row in &mut rows {
            rewrite_references(row, byte_reference)?;
        }
    }
    let rows: Vec<ExportEntity> =
        serde_json::from_value(Value::Array(rows)).map_err(|_| invalid())?;
    for row in &rows {
        validate_row(row)?;
    }
    Ok((format, rows))
}

/// A row is a canonical claim export: its id spelled as the engine spells
/// it, a CLAIM, an ordered range, and a body the export serializer itself
/// writes (`ExportBody::validate`). So no node, a hex id included, holds a
/// position the typed tree does not give it, and every reader of the facet
/// (hub packs and birth sources alike) gets rows the export could have made.
fn validate_row(row: &ExportEntity) -> Result<()> {
    if EntityId::from_hex(&row.id)
        .ok()
        .is_none_or(|id| id.to_hex() != row.id)
        || row.entity_type != ENTITY_TYPE_CLAIM
        || row.occurred_start > row.occurred_end
    {
        return Err(invalid());
    }
    row.body.validate(ENTITY_TYPE_CLAIM).map_err(|_| invalid())
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
