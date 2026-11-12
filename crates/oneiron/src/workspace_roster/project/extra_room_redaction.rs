//! Served-copy redaction of the extra-room `project_group` body key.
//!
//! Contract: keep the key only for a caller who reads the named project
//! (`super::extra_rooms::project_reader_in_txn`); otherwise serve a copy
//! without it. Stale and malformed keys are removed for everyone. Stored
//! bytes never change. Helpers read the raw rmpv map and tolerate any
//! undecodable body by returning it unchanged.

use crate::Vault;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_CONVERSATION;
use crate::store::conversation_body::ROOM_PROJECT_GROUP_KEY;

/// Valid project id named by the key, else None when absent or malformed.
pub(crate) fn project_group_in_body_bytes(body: &[u8]) -> Option<EntityId> {
    for (key, value) in body_map_entries(body)? {
        if key.as_str() == Some(ROOM_PROJECT_GROUP_KEY) {
            let text = value.as_str()?;
            let id = EntityId::from_hex(text).ok()?;
            return (id.to_hex() == text).then_some(id);
        }
    }
    None
}

/// Copy of `body` without the key; None when absent or undecodable.
pub(crate) fn strip_project_group_from_body_bytes(body: &[u8]) -> Option<Vec<u8>> {
    let entries = body_map_entries(body)?;
    if !entries
        .iter()
        .any(|(key, _)| key.as_str() == Some(ROOM_PROJECT_GROUP_KEY))
    {
        return None;
    }
    let kept: Vec<(rmpv::Value, rmpv::Value)> = entries
        .into_iter()
        .filter(|(key, _)| key.as_str() != Some(ROOM_PROJECT_GROUP_KEY))
        .collect();
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &rmpv::Value::Map(kept)).ok()?;
    Some(out)
}

/// Stored bytes unchanged when keyless or when `caller` reads the project;
/// otherwise a copy without the key.
pub(crate) fn redact_body_bytes_for_caller_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    body: &[u8],
    caller: EntityId,
) -> Result<Vec<u8>> {
    if body.is_empty() {
        return Ok(body.to_vec());
    }
    match project_group_in_body_bytes(body) {
        Some(project) => {
            if super::extra_rooms::project_reader_in_txn(vault, txn, project, caller)? {
                return Ok(body.to_vec());
            }
            Ok(strip_project_group_from_body_bytes(body).unwrap_or_else(|| body.to_vec()))
        }
        None => {
            if !has_project_group_key(body) {
                return Ok(body.to_vec());
            }
            Ok(strip_project_group_from_body_bytes(body).unwrap_or_else(|| body.to_vec()))
        }
    }
}

/// Header-plus-body record copy without the key for another principal; None
/// when unchanged. Scoped export and federated/guest selector strip; own
/// device sync never calls this.
pub(crate) fn strip_project_group_from_record_bytes(
    entity_type: u8,
    record: &[u8],
) -> Option<Vec<u8>> {
    if entity_type != ENTITY_TYPE_CONVERSATION || record.len() < ENTITY_METADATA_HEADER_LEN {
        return None;
    }
    let stripped = strip_project_group_from_body_bytes(&record[ENTITY_METADATA_HEADER_LEN..])?;
    let mut out = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + stripped.len());
    out.extend_from_slice(&record[..ENTITY_METADATA_HEADER_LEN]);
    out.extend_from_slice(&stripped);
    Some(out)
}

/// Whether the key is present in any shape.
fn has_project_group_key(body: &[u8]) -> bool {
    body_map_entries(body).is_some_and(|entries| {
        entries
            .iter()
            .any(|(key, _)| key.as_str() == Some(ROOM_PROJECT_GROUP_KEY))
    })
}

/// Top-level map entries; None for empty, trailing bytes, non-map, or any
/// decode failure.
fn body_map_entries(body: &[u8]) -> Option<Vec<(rmpv::Value, rmpv::Value)>> {
    if body.is_empty() {
        return None;
    }
    let mut cursor = std::io::Cursor::new(body);
    let value = rmpv::decode::read_value(&mut cursor).ok()?;
    if cursor.position() != body.len() as u64 {
        return None;
    }
    match value {
        rmpv::Value::Map(entries) => Some(entries),
        _ => None,
    }
}
