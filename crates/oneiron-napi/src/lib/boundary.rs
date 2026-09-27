//! Shared caps, parse/validate helpers and napi error mapping for the legacy surface.

use napi::bindgen_prelude::*;
use oneiron::{CODEBASE_CONTENT_HASH_LEN, EdgeKind, EntityId};

pub(super) const DEFAULT_NAPI_SEARCH_LIMIT: u32 = 10;

// ONE-1441 WIRE-P1: the `MAX_NAPI_*` names are now ALIASES of the shared
// boundary contract in `oneiron-remote`, which owns the values for both
// bindings and both transports. The names are kept exactly as they were so
// ONE-479 still finds the established seam; only the source of the numbers
// moved, so the N-API boundary and the remote boundary cannot drift into two
// sets of limits that agree only by coincidence.
pub(super) const MAX_NAPI_SEARCH_LIMIT: u32 = oneiron_remote::MAX_SEARCH_LIMIT as u32;

pub(super) const MAX_NAPI_QUERY_BYTES: usize = oneiron_remote::MAX_QUERY_BYTES;

pub(super) const MAX_NAPI_ENTITY_PAYLOAD_BYTES: usize = oneiron_remote::MAX_ENTITY_PAYLOAD_BYTES;

pub(super) const MAX_NAPI_BATCH_ENTITIES: usize = oneiron_remote::MAX_BATCH_ENTITIES;

pub(super) const MAX_NAPI_CODEBASE_FILES: usize = oneiron_remote::MAX_CODEBASE_FILES;

pub(super) const MAX_NAPI_DIMENSIONS: usize = oneiron_remote::MAX_DIMENSIONS;

pub(super) type BoundaryResult<T> = std::result::Result<T, String>;

/// Convert an oneiron error to a napi error.
pub(super) fn to_napi_err(e: oneiron::Error) -> napi::Error {
    napi::Error::from_reason(e.to_string())
}

/// Extract a 16-byte EntityId from a Buffer, returning a napi error if invalid.
pub(super) fn parse_entity_id(buf: &Buffer) -> napi::Result<EntityId> {
    let bytes: [u8; 16] = buf
        .as_ref()
        .try_into()
        .map_err(|_| napi::Error::from_reason("EntityId must be exactly 16 bytes"))?;
    EntityId::from_bytes(bytes).map_err(to_napi_err)
}

/// Convert a signed i64 timestamp to u64, clamping negatives to 0.
pub(super) fn ts_to_u64(ts: i64) -> u64 {
    ts.max(0) as u64
}

/// Validate and narrow a u32 to u8, returning a descriptive error on overflow.
pub(super) fn parse_u8(value: u32, label: &str) -> napi::Result<u8> {
    if value > u8::MAX as u32 {
        return Err(napi::Error::from_reason(format!(
            "{label} must be 0-255, got {value}"
        )));
    }
    Ok(value as u8)
}

/// Validate a u32 as an EdgeKind discriminant.
pub(super) fn parse_edge_kind(kind: u32) -> napi::Result<EdgeKind> {
    let byte = parse_u8(kind, "edge kind")?;
    EdgeKind::try_from_u8(byte)
        .ok_or_else(|| napi::Error::from_reason(format!("invalid edge kind: {kind}")))
}

/// Validate and narrow a Rust timestamp before returning it to JS.
pub(super) fn parse_created_at(created_at: u64) -> BoundaryResult<i64> {
    i64::try_from(created_at)
        .map_err(|_| format!("created_at must fit in signed 64-bit integer, got {created_at}"))
}

/// Validate a user-provided search limit before passing it to core search.
pub(super) fn parse_search_limit(limit: u32) -> BoundaryResult<usize> {
    if limit > MAX_NAPI_SEARCH_LIMIT {
        return Err(format!(
            "limit must be <= {MAX_NAPI_SEARCH_LIMIT}, got {limit}"
        ));
    }
    Ok(limit as usize)
}

/// Check the JS string's UTF-8 size before napi-rs allocates an owned Rust string.
/// JS `.length` measures UTF-16 units and cannot enforce the shared byte cap.
pub(super) fn read_query(query: napi::JsString<'_>) -> napi::Result<String> {
    validate_query_len_bytes(query.utf8_len()?).map_err(napi::Error::from_reason)?;
    query.into_utf8()?.into_owned()
}

/// Check the JS array length before reading any elements into a Rust Vec.
pub(super) fn read_bounded_array<T: FromNapiValue>(
    values: &Array<'_>,
    validate: impl FnOnce(usize) -> BoundaryResult<()>,
) -> napi::Result<Vec<T>> {
    let len = values.len() as usize;
    validate(len).map_err(napi::Error::from_reason)?;
    (0..values.len())
        .map(|index| {
            values.get(index)?.ok_or_else(|| {
                napi::Error::from_reason(format!("array element {index} is missing"))
            })
        })
        .collect()
}

/// Preserve the JS Array ABI, but do not marshal even one element on a bad size.
pub(super) fn read_vector(
    values: &Array<'_>,
    expected: usize,
    label: &str,
) -> napi::Result<Vec<f32>> {
    validate_vector_len(values.len() as usize, expected, label)
        .map_err(napi::Error::from_reason)?;
    (0..values.len())
        .map(|index| {
            Ok(values.get::<f64>(index)?.ok_or_else(|| {
                napi::Error::from_reason(format!("array element {index} is missing"))
            })? as f32)
        })
        .collect()
}

/// Read the nested manifest only once. A JS getter could return a short array
/// for a size check and a long one if we asked for `files` again during DTO
/// conversion, so convert the checked array rather than re-reading the object.
pub(super) fn read_codebase_snapshot(
    snapshot: Object<'_>,
) -> napi::Result<super::types::NapiCodebaseSnapshot> {
    let files: Array<'_> = required_field(&snapshot, "files")?;
    validate_codebase_file_count(files.len() as usize).map_err(napi::Error::from_reason)?;
    let files = read_bounded_array(&files, validate_codebase_file_count)?;
    Ok(super::types::NapiCodebaseSnapshot {
        project_id: required_field(&snapshot, "projectId")?,
        repo_ref: required_field(&snapshot, "repoRef")?,
        commit_hash: snapshot.get::<Option<String>>("commitHash")?.flatten(),
        fork_hash: snapshot.get::<Option<Buffer>>("forkHash")?.flatten(),
        scope_key: snapshot.get::<Option<Buffer>>("scopeKey")?.flatten(),
        files,
    })
}

fn required_field<T: FromNapiValue>(object: &Object<'_>, name: &str) -> napi::Result<T> {
    object
        .get(name)?
        .ok_or_else(|| napi::Error::from_reason(format!("codebase snapshot {name} is required")))
}

/// Validate text query size before it crosses into core search.
pub(super) fn validate_query_len(query: &str) -> BoundaryResult<()> {
    validate_query_len_bytes(query.len())
}

fn validate_query_len_bytes(len: usize) -> BoundaryResult<()> {
    if len > MAX_NAPI_QUERY_BYTES {
        return Err(format!(
            "query must be <= {MAX_NAPI_QUERY_BYTES} bytes, got {len}"
        ));
    }
    Ok(())
}

/// Validate entity payload size before it crosses into core write paths.
pub(super) fn validate_entity_payload_len(len: usize) -> BoundaryResult<()> {
    if len > MAX_NAPI_ENTITY_PAYLOAD_BYTES {
        return Err(format!(
            "entity data payload must be <= {MAX_NAPI_ENTITY_PAYLOAD_BYTES} bytes, got {len}"
        ));
    }
    Ok(())
}

/// Validate batch write size before opening a write transaction.
pub(super) fn validate_batch_size(len: usize) -> BoundaryResult<()> {
    if len > MAX_NAPI_BATCH_ENTITIES {
        return Err(format!(
            "batch_put_entities accepts at most {MAX_NAPI_BATCH_ENTITIES} entities, got {len}"
        ));
    }
    Ok(())
}

/// Validate codebase manifest size before allocating core snapshot entries.
pub(super) fn validate_codebase_file_count(len: usize) -> BoundaryResult<()> {
    if len > MAX_NAPI_CODEBASE_FILES {
        return Err(format!(
            "codebase snapshot accepts at most {MAX_NAPI_CODEBASE_FILES} files, got {len}"
        ));
    }
    Ok(())
}

/// Validate and copy a 32-byte content hash from JS.
pub(super) fn parse_content_hash(buf: &Buffer) -> BoundaryResult<[u8; CODEBASE_CONTENT_HASH_LEN]> {
    buf.as_ref().try_into().map_err(|_| {
        format!(
            "content_hash must be exactly {CODEBASE_CONTENT_HASH_LEN} bytes, got {}",
            buf.len()
        )
    })
}

pub(super) fn parse_fixed_hash<const N: usize>(
    buf: &Buffer,
    label: &str,
) -> BoundaryResult<[u8; N]> {
    buf.as_ref()
        .try_into()
        .map_err(|_| format!("{label} must be exactly {N} bytes, got {}", buf.len()))
}

/// Validate a JS file size before narrowing to u64.
pub(super) fn parse_file_size(size: i64) -> BoundaryResult<u64> {
    u64::try_from(size).map_err(|_| format!("size_bytes must be >= 0, got {size}"))
}

/// Validate configured vector dimensions before opening a vault.
pub(super) fn validate_dimensions(dimensions: usize) -> BoundaryResult<()> {
    if dimensions > MAX_NAPI_DIMENSIONS {
        return Err(format!(
            "dimensions must be <= {MAX_NAPI_DIMENSIONS}, got {dimensions}"
        ));
    }
    Ok(())
}

/// Validate vector length before allocating the narrowed f32 copy.
pub(super) fn validate_vector_len(len: usize, expected: usize, label: &str) -> BoundaryResult<()> {
    if len != expected {
        return Err(format!(
            "{label} length must equal vault dimensions ({expected}), got {len}"
        ));
    }
    Ok(())
}

/// Convert a slice of EntityIds to Buffers.
pub(super) fn entity_ids_to_buffers(ids: Vec<EntityId>) -> Vec<Buffer> {
    ids.into_iter()
        .map(|id| Buffer::from(id.as_bytes().as_slice()))
        .collect()
}
