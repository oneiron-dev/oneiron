//! ID/enum/limit/query/format parsing and validation helpers.

use std::str;

use oneiron::{EdgeKind, EntityId, PackFormat};

use super::guard::{with_optional_slice, with_required_slice};
use super::types::{
    ENTITY_ID_LEN, MAX_FFI_DIMENSIONS, MAX_FFI_QUERY_BYTES, MAX_FFI_SEARCH_LIMIT, OneironStatus,
};

pub(super) fn string_from_required(ptr: *const u8, len: usize) -> Result<String, OneironStatus> {
    with_required_slice(ptr, len, |bytes| {
        str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| OneironStatus::Utf8)
    })
}

pub(super) fn string_from_optional(
    ptr: *const u8,
    len: usize,
) -> Result<Option<String>, OneironStatus> {
    with_optional_slice(ptr, len, |bytes| {
        bytes
            .map(|value| {
                str::from_utf8(value)
                    .map(str::to_owned)
                    .map_err(|_| OneironStatus::Utf8)
            })
            .transpose()
    })
}

pub(super) fn parse_id_bytes(bytes: &[u8]) -> Result<EntityId, OneironStatus> {
    if bytes.len() != ENTITY_ID_LEN {
        return Err(OneironStatus::InvalidArg);
    }
    let id: [u8; ENTITY_ID_LEN] = bytes.try_into().map_err(|_| OneironStatus::InvalidArg)?;
    EntityId::from_bytes(id).map_err(|_| OneironStatus::InvalidArg)
}

pub(super) fn parse_entity_id(ptr: *const u8, len: usize) -> Result<EntityId, OneironStatus> {
    with_required_slice(ptr, len, parse_id_bytes)
}

pub(super) fn parse_u8(value: u32) -> Result<u8, OneironStatus> {
    u8::try_from(value).map_err(|_| OneironStatus::InvalidArg)
}

pub(super) fn parse_edge_kind(kind: u32) -> Result<EdgeKind, OneironStatus> {
    let byte = parse_u8(kind)?;
    EdgeKind::try_from_u8(byte).ok_or(OneironStatus::InvalidArg)
}

pub(super) fn parse_search_limit(limit: u32) -> Result<usize, OneironStatus> {
    if limit > MAX_FFI_SEARCH_LIMIT {
        return Err(OneironStatus::InvalidArg);
    }
    Ok(limit as usize)
}

pub(super) fn validate_query_len(query: &str) -> Result<(), OneironStatus> {
    if query.len() > MAX_FFI_QUERY_BYTES {
        return Err(OneironStatus::InvalidArg);
    }
    Ok(())
}

pub(super) fn validate_dimensions(dimensions: usize) -> Result<(), OneironStatus> {
    if dimensions > MAX_FFI_DIMENSIONS {
        return Err(OneironStatus::InvalidArg);
    }
    Ok(())
}

pub(super) fn validate_vector_len(len: usize, expected: usize) -> Result<(), OneironStatus> {
    if len != expected {
        return Err(OneironStatus::InvalidArg);
    }
    Ok(())
}

pub(super) fn ts_to_u64(ts: i64) -> u64 {
    ts.max(0) as u64
}

pub(super) fn engine<T>(result: Result<T, oneiron::Error>) -> Result<T, OneironStatus> {
    result.map_err(|_| OneironStatus::EngineError)
}

pub(super) fn id_array(id: &EntityId) -> [u8; ENTITY_ID_LEN] {
    *id.as_bytes()
}

pub(super) fn created_at_to_i64(created_at: u64) -> Result<i64, OneironStatus> {
    i64::try_from(created_at).map_err(|_| OneironStatus::EngineError)
}

pub(super) fn parse_pack_format(format: Option<&str>) -> PackFormat {
    match format {
        Some("yaml") => PackFormat::Yaml,
        Some("toon") => PackFormat::Toon,
        Some("markdown") => PackFormat::Markdown,
        Some("plaintext") => PackFormat::Plaintext,
        _ => PackFormat::Json,
    }
}

pub(super) fn convert_query_vector(
    query: &[f64],
    dimensions: usize,
) -> Result<Vec<f32>, OneironStatus> {
    validate_vector_len(query.len(), dimensions)?;
    Ok(query.iter().map(|&value| value as f32).collect())
}
