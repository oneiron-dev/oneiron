//! Credential-safe, type-preserving MessagePack values for whole-vault JSON.
//!
//! No raw/base64 body is shipped beside this tree. Unknown binary and extension
//! payloads are nulled: an opaque byte string is not proof that it is public data.
use std::io::Cursor;

use rmpv::Value as Mp;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::credential_nulling::{credential_key, null_credentials};
use crate::batch::secret_scan::scan_file_content;
use crate::error::{Error, Result};

/// A MessagePack value with explicit numeric widths and binary-reference types.
/// Map entries stay ordered, including duplicate keys; they are not JSON objects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ExportValue {
    Boolean(bool),
    Integer(String),
    F32(u32),
    F64(u64),
    String(String),
    /// Only validated, fixed-width CLAIM references use this representation.
    EntityReference(Vec<u8>),
    /// Inspectable UTF-8 binary; the decoder restores MessagePack Binary.
    BinaryText(String),
    Array(Vec<Self>),
    Map(Vec<(Self, Self)>),
    #[serde(untagged)]
    Nil,
}

/// Body format is explicit; arbitrary blobs are never hidden behind an encoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "codec",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ExportBody {
    MessagePack(ExportValue),
    Utf8(String),
    Pack(Box<super::ExportPackInstance>),
    HubSource(Box<super::ExportHubSource>),
    Nulled,
}

impl ExportBody {
    pub(crate) fn from_bytes(bytes: &[u8], entity_type: u8) -> Self {
        if crate::registry::zone_of(entity_type) == crate::registry::TypeByteZone::PackHandle {
            return match crate::registry::pack_byte_map::PackInstanceEnvelope::from_bytes(bytes) {
                Ok(value) => Self::Pack(Box::new(super::ExportPackInstance::from_envelope(value))),
                Err(_) => Self::Nulled,
            };
        }
        if entity_type == crate::registry::ENTITY_TYPE_ASSET {
            match crate::skill_hub::decode_source_carrier(bytes) {
                Ok(Some(package)) => {
                    return super::ExportHubSource::from_package(&package)
                        .map(|source| Self::HubSource(Box::new(source)))
                        .unwrap_or(Self::Nulled);
                }
                Err(_) => return Self::Nulled,
                Ok(None) => {}
            }
        }
        let mut cursor = Cursor::new(bytes);
        if let Ok(value) = rmpv::decode::read_value(&mut cursor)
            && cursor.position() == bytes.len() as u64
        {
            let mut exported = export_value(&value, "", entity_type, 0);
            if entity_type == crate::registry::ENTITY_TYPE_CLAIM {
                export_provenance_references(bytes, &mut exported);
            }
            return Self::MessagePack(exported);
        }
        match std::str::from_utf8(bytes) {
            Ok(text) if safe_text(text) => Self::Utf8(text.to_owned()),
            _ => Self::Nulled,
        }
    }

    pub(crate) fn to_bytes(&self) -> Result<Vec<u8>> {
        match self {
            Self::MessagePack(value) => {
                let mut bytes = Vec::new();
                rmpv::encode::write_value(&mut bytes, &value.to_msgpack()?)
                    .map_err(|_| invalid("MessagePack encode failed"))?;
                Ok(bytes)
            }
            Self::Utf8(text) => Ok(text.as_bytes().to_vec()),
            Self::Pack(value) => value.envelope()?.to_bytes(),
            Self::HubSource(value) => value.to_bytes(),
            Self::Nulled => Err(invalid(
                "nulled opaque body needs its owning import adapter",
            )),
        }
    }

    /// Verify imported typed trees through the same serializer transform. No
    /// forged binary tag or proof boolean may smuggle a credential on reimport.
    pub(crate) fn validate(&self, entity_type: u8) -> Result<()> {
        if matches!(self, Self::Nulled) {
            return Ok(());
        }
        if let Self::HubSource(value) = self {
            if entity_type != crate::registry::ENTITY_TYPE_ASSET {
                return Err(invalid("hub source attached to non-asset kind"));
            }
            return value.validate();
        }
        if let Self::Pack(value) = self {
            if crate::registry::zone_of(entity_type) != crate::registry::TypeByteZone::PackHandle {
                return Err(invalid("pack envelope attached to non-pack kind"));
            }
            return value.validate();
        }
        let bytes = self.to_bytes()?;
        if Self::from_bytes(&bytes, entity_type) != *self {
            return Err(invalid(
                "body is not canonical credential-nulled export data",
            ));
        }
        Ok(())
    }
}

// Only the owning, validated edge.provenance value map gets these four
// binary reference fields. An equally named field in arbitrary evidence is
// still subject to ordinary opaque-byte nulling.
fn export_provenance_references(bytes: &[u8], exported: &mut ExportValue) {
    let Ok(claim) = crate::claim::decode_claim_body(bytes, true) else {
        return;
    };
    if claim.predicate != crate::provenance::PREDICATE_EDGE_PROVENANCE {
        return;
    }
    let Ok(record) = crate::provenance::decode_edge_provenance_body(&claim.value) else {
        return;
    };
    if crate::provenance::resolve_persisted_actor_class(&record, claim.evidence.as_ref()).is_err() {
        return;
    }
    let ExportValue::Map(entries) = exported else {
        return;
    };
    let Some(ExportValue::Map(values)) = entries.iter_mut().find_map(|(key, value)| {
        matches!(key, ExportValue::String(key) if key == "val").then_some(value)
    }) else {
        return;
    };
    for (name, bytes) in [
        (
            "actor_entity_ref",
            Some(*record.actor_entity_ref.as_bytes()),
        ),
        (
            "substrate_ref",
            record.substrate_ref.map(|id| *id.as_bytes()),
        ),
        ("source_revision_ref", record.source_revision_ref),
        ("body_snapshot_ref", record.body_snapshot_ref),
    ] {
        if let Some(bytes) = bytes {
            if scan_file_content("", &bytes).is_some() {
                continue;
            }
            if let Some(value) = values.iter_mut().find_map(|(key, value)| {
                matches!(key, ExportValue::String(key) if key == name).then_some(value)
            }) {
                *value = ExportValue::EntityReference(bytes.to_vec());
            }
        }
    }
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("whole-vault export: {reason}"))
}

fn safe_text(text: &str) -> bool {
    let scalar = Value::String(text.to_owned());
    if null_credentials("", &scalar) != scalar {
        return false;
    }
    match serde_json::from_str::<Value>(text) {
        Ok(value @ (Value::Object(_) | Value::Array(_))) => null_credentials("", &value) == value,
        _ => true,
    }
}

fn byte_container_is_opaque_or_tainted(bytes: &[u8]) -> bool {
    if scan_file_content("", bytes).is_some() {
        return true;
    }
    if let Ok(text) = std::str::from_utf8(bytes)
        && let Ok(value @ (Value::Object(_) | Value::Array(_))) =
            serde_json::from_str::<Value>(text)
        && null_credentials("", &value) != value
    {
        return true;
    }
    let mut cursor = Cursor::new(bytes);
    matches!(
        rmpv::decode::read_value(&mut cursor),
        Ok(Mp::Map(_) | Mp::Array(_) | Mp::Binary(_) | Mp::Ext(_, _))
    ) && cursor.position() == bytes.len() as u64
}

fn reference_field(key: &str, bytes: &[u8], entity_type: u8, depth: usize) -> bool {
    if entity_type != crate::registry::ENTITY_TYPE_CLAIM {
        return false;
    }
    if depth > 1 && key != crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY {
        return false;
    }
    match key {
        "subj" => crate::claim::ClaimSubject::decode(bytes).is_ok(),
        "world" | "rel" | "actor_entity_ref" => <[u8; 16]>::try_from(bytes)
            .ok()
            .is_some_and(|id| crate::entity_id::EntityId::from_bytes(id).is_ok()),
        _ => false,
    }
}

fn export_value(value: &Mp, key: &str, entity_type: u8, depth: usize) -> ExportValue {
    if depth >= 24 || credential_key(key) {
        return ExportValue::Nil;
    }
    match value {
        Mp::Nil => ExportValue::Nil,
        Mp::Boolean(value) => ExportValue::Boolean(*value),
        Mp::Integer(value) => ExportValue::Integer(value.to_string()),
        Mp::F32(value) => ExportValue::F32(value.to_bits()),
        Mp::F64(value) => ExportValue::F64(value.to_bits()),
        Mp::String(value) => match value.as_str() {
            Some(value) if safe_text(value) => ExportValue::String(value.to_owned()),
            _ => ExportValue::Nil,
        },
        Mp::Binary(bytes) if reference_field(key, bytes, entity_type, depth) => {
            ExportValue::EntityReference(bytes.clone())
        }
        Mp::Binary(bytes) => {
            // A binary map is not text just because its credential's value is
            // printable. Opaque encodings are intentionally nulled as a whole.
            match std::str::from_utf8(bytes) {
                Ok(text) if safe_text(text) && !text.chars().any(char::is_control) => {
                    ExportValue::BinaryText(text.to_owned())
                }
                _ => ExportValue::Nil,
            }
        }
        Mp::Array(values) => {
            // MessagePack uint8 arrays are another common byte-container. Scan
            // them before JSON encoding, rather than scanning decimal digits.
            let bytes: Option<Vec<u8>> = values
                .iter()
                .map(|value| value.as_u64().and_then(|v| u8::try_from(v).ok()))
                .collect();
            if bytes
                .as_deref()
                .is_some_and(byte_container_is_opaque_or_tainted)
            {
                return ExportValue::Nil;
            }
            ExportValue::Array(
                values
                    .iter()
                    .map(|value| export_value(value, "", entity_type, depth + 1))
                    .collect(),
            )
        }
        Mp::Map(entries) => ExportValue::Map(
            entries
                .iter()
                .map(|(key, value)| {
                    let exported_key = export_value(key, "", entity_type, depth + 1);
                    let exported_value = if matches!(exported_key, ExportValue::Nil) {
                        ExportValue::Nil
                    } else {
                        export_value(
                            value,
                            key.as_str()
                                .or_else(|| match key {
                                    Mp::Binary(bytes) => std::str::from_utf8(bytes).ok(),
                                    _ => None,
                                })
                                .unwrap_or(""),
                            entity_type,
                            depth + 1,
                        )
                    };
                    (exported_key, exported_value)
                })
                .collect(),
        ),
        Mp::Ext(_, _) => ExportValue::Nil,
    }
}

impl ExportValue {
    pub(crate) fn to_msgpack(&self) -> Result<Mp> {
        Ok(match self {
            Self::Nil => Mp::Nil,
            Self::Boolean(value) => Mp::Boolean(*value),
            Self::Integer(value) => {
                if value.starts_with('-') {
                    Mp::from(
                        value
                            .parse::<i64>()
                            .map_err(|_| invalid("invalid signed integer"))?,
                    )
                } else {
                    Mp::from(
                        value
                            .parse::<u64>()
                            .map_err(|_| invalid("invalid unsigned integer"))?,
                    )
                }
            }
            Self::F32(bits) => Mp::F32(f32::from_bits(*bits)),
            Self::F64(bits) => Mp::F64(f64::from_bits(*bits)),
            Self::String(value) => Mp::from(value.as_str()),
            Self::EntityReference(value) => Mp::Binary(value.clone()),
            Self::BinaryText(value) => Mp::Binary(value.as_bytes().to_vec()),
            Self::Array(values) => {
                Mp::Array(values.iter().map(Self::to_msgpack).collect::<Result<_>>()?)
            }
            Self::Map(entries) => Mp::Map(
                entries
                    .iter()
                    .map(|(key, value)| Ok((key.to_msgpack()?, value.to_msgpack()?)))
                    .collect::<Result<_>>()?,
            ),
        })
    }
}
