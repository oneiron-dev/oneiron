//! Edge, search, vector, context-pack, and graph-traversal entry points.

use std::str;

use super::alloc::{
    buffer_from_vec, edge_array_from_vec, id_list_buffer, scored_array_from_vec,
    subtree_array_from_vec,
};
use super::guard::{ffi_guard, with_optional_slice, with_required_slice, with_vault, write_out};
use super::parse::{
    convert_query_vector, created_at_to_i64, engine, id_array, memory_result, parse_edge_kind,
    parse_entity_id, parse_pack_format, parse_search_limit, parse_u8, refuse_unserved_media,
    string_from_optional, string_from_required, validate_query_len,
};
use super::types::{
    DEFAULT_FFI_SEARCH_LIMIT, OneironBuffer, OneironEdgeInfo, OneironEdgeInfoArray,
    OneironScoredEntity, OneironScoredEntityArray, OneironStatus, OneironSubtreeEntry,
    OneironSubtreeEntryArray, OneironVault,
};

/// Store a directed edge between two entities. A bound handle stores it as
/// its caller (`oneiron_vault_bind`).
///
/// # Safety
///
/// `vault` is null or a live handle from `oneiron_vault_open`, not freed
/// during the call. Each non-null input pointer covers its length in readable
/// values and each non-null out pointer is writable, for the whole call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_vault_put_edge(
    vault: *mut OneironVault,
    src_ptr: *const u8,
    src_len: usize,
    kind: u32,
    tgt_ptr: *const u8,
    tgt_len: usize,
    weight: f64,
) -> OneironStatus {
    ffi_guard(|| {
        let result = with_vault(vault, |handle| {
            let src = parse_entity_id(src_ptr, src_len)?;
            let tgt = parse_entity_id(tgt_ptr, tgt_len)?;
            let kind = parse_edge_kind(kind)?;
            match handle.bound_memory() {
                Some(memory) => memory_result(memory.raw_put_edge(&src, kind, &tgt, weight as f32)),
                None => engine(handle.vault.put_edge(&src, kind, &tgt, weight as f32)),
            }
        });
        result.map_or_else(|status| status, |()| OneironStatus::Ok)
    })
}

/// Return outbound edges for a source entity.
///
/// `out_edges` receives a Rust-owned array that must be released with
/// `oneiron_edge_info_array_free`.
///
/// # Safety
///
/// `vault` is null or a live handle from `oneiron_vault_open`, not freed
/// during the call. Each non-null input pointer covers its length in readable
/// values and each non-null out pointer is writable, for the whole call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_vault_edges_out(
    vault: *mut OneironVault,
    src_ptr: *const u8,
    src_len: usize,
    out_edges: *mut OneironEdgeInfoArray,
) -> OneironStatus {
    ffi_guard(|| {
        if let Err(status) = write_out(out_edges, OneironEdgeInfoArray::empty()) {
            return status;
        }
        let result = with_vault(vault, |handle| {
            let src = parse_entity_id(src_ptr, src_len)?;
            let edges = handle.edges_of(&src, true)?;
            let mut out = Vec::with_capacity(edges.len());
            for edge in edges {
                let vad = edge.vad;
                out.push(OneironEdgeInfo {
                    src: id_array(&src),
                    kind: u32::from(edge.kind as u8),
                    tgt: id_array(&edge.target),
                    weight: f64::from(edge.weight),
                    created_at: created_at_to_i64(edge.created_at)?,
                    has_vad: u8::from(vad.is_some()),
                    valence: vad.map_or(0.0, |value| f64::from(value.valence)),
                    arousal: vad.map_or(0.0, |value| f64::from(value.arousal)),
                    dominance: vad.map_or(0.0, |value| f64::from(value.dominance)),
                });
            }
            write_out(out_edges, edge_array_from_vec(out))
        });
        result.map_or_else(|status| status, |()| OneironStatus::Ok)
    })
}

/// Return inbound edges for a target entity.
///
/// `out_edges` receives a Rust-owned array that must be released with
/// `oneiron_edge_info_array_free`.
///
/// # Safety
///
/// `vault` is null or a live handle from `oneiron_vault_open`, not freed
/// during the call. Each non-null input pointer covers its length in readable
/// values and each non-null out pointer is writable, for the whole call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_vault_edges_in(
    vault: *mut OneironVault,
    tgt_ptr: *const u8,
    tgt_len: usize,
    out_edges: *mut OneironEdgeInfoArray,
) -> OneironStatus {
    ffi_guard(|| {
        if let Err(status) = write_out(out_edges, OneironEdgeInfoArray::empty()) {
            return status;
        }
        let result = with_vault(vault, |handle| {
            let tgt = parse_entity_id(tgt_ptr, tgt_len)?;
            let edges = handle.edges_of(&tgt, false)?;
            let mut out = Vec::with_capacity(edges.len());
            for edge in edges {
                let vad = edge.vad;
                out.push(OneironEdgeInfo {
                    src: id_array(&edge.target),
                    kind: u32::from(edge.kind as u8),
                    tgt: id_array(&tgt),
                    weight: f64::from(edge.weight),
                    created_at: created_at_to_i64(edge.created_at)?,
                    has_vad: u8::from(vad.is_some()),
                    valence: vad.map_or(0.0, |value| f64::from(value.valence)),
                    arousal: vad.map_or(0.0, |value| f64::from(value.arousal)),
                    dominance: vad.map_or(0.0, |value| f64::from(value.dominance)),
                });
            }
            write_out(out_edges, edge_array_from_vec(out))
        });
        result.map_or_else(|status| status, |()| OneironStatus::Ok)
    })
}

/// Search for entities by vector similarity.
///
/// `query_len` must equal the vault dimensions. `out_results` receives a
/// Rust-owned array that must be released with
/// `oneiron_scored_entity_array_free`.
///
/// # Safety
///
/// `vault` is null or a live handle from `oneiron_vault_open`, not freed
/// during the call. Each non-null input pointer covers its length in readable
/// values and each non-null out pointer is writable, for the whole call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_vault_search_vector(
    vault: *mut OneironVault,
    query_ptr: *const f64,
    query_len: usize,
    limit: u32,
    out_results: *mut OneironScoredEntityArray,
) -> OneironStatus {
    ffi_guard(|| {
        if let Err(status) = write_out(out_results, OneironScoredEntityArray::empty()) {
            return status;
        }
        let result = with_vault(vault, |handle| {
            let limit = parse_search_limit(limit)?;
            let query = with_required_slice(query_ptr, query_len, |values| {
                convert_query_vector(values, handle.dimensions)
            })?;
            let results = engine(handle.vault.search_vector(&query, limit))?;
            let out = results
                .into_iter()
                .map(|result| OneironScoredEntity {
                    id: id_array(&result.id),
                    score: f64::from(result.score),
                })
                .collect();
            write_out(out_results, scored_array_from_vec(out))
        });
        result.map_or_else(|status| status, |()| OneironStatus::Ok)
    })
}

/// Search for entities by BM25 text matching.
///
/// `query_len` must be at most 8 KiB. `out_results` receives a Rust-owned
/// array that must be released with `oneiron_scored_entity_array_free`.
///
/// # Safety
///
/// `vault` is null or a live handle from `oneiron_vault_open`, not freed
/// during the call. Each non-null input pointer covers its length in readable
/// values and each non-null out pointer is writable, for the whole call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_vault_search_text(
    vault: *mut OneironVault,
    query_ptr: *const u8,
    query_len: usize,
    limit: u32,
    out_results: *mut OneironScoredEntityArray,
) -> OneironStatus {
    ffi_guard(|| {
        if let Err(status) = write_out(out_results, OneironScoredEntityArray::empty()) {
            return status;
        }
        let result = with_vault(vault, |handle| {
            let query = string_from_required(query_ptr, query_len)?;
            validate_query_len(&query)?;
            let limit = parse_search_limit(limit)?;
            let results = engine(handle.vault.search_text(&query, limit))?;
            let out = results
                .into_iter()
                .map(|result| OneironScoredEntity {
                    id: id_array(&result.id),
                    score: f64::from(result.score),
                })
                .collect();
            write_out(out_results, scored_array_from_vec(out))
        });
        result.map_or_else(|status| status, |()| OneironStatus::Ok)
    })
}

/// Store a vector embedding for an entity.
///
/// `vector_len` must equal the vault dimensions. A bound handle stores it as
/// its caller (`oneiron_vault_bind`).
///
/// # Safety
///
/// `vault` is null or a live handle from `oneiron_vault_open`, not freed
/// during the call. Each non-null input pointer covers its length in readable
/// values and each non-null out pointer is writable, for the whole call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_vault_put_vector(
    vault: *mut OneironVault,
    id_ptr: *const u8,
    id_len: usize,
    vector_ptr: *const f64,
    vector_len: usize,
) -> OneironStatus {
    ffi_guard(|| {
        let result = with_vault(vault, |handle| {
            let id = parse_entity_id(id_ptr, id_len)?;
            let vector = with_required_slice(vector_ptr, vector_len, |values| {
                convert_query_vector(values, handle.dimensions)
            })?;
            match handle.bound_memory() {
                Some(memory) => memory_result(memory.raw_put_vector(&id, &vector)),
                None => engine(handle.vault.put_vector(&id, &vector)),
            }
        });
        result.map_or_else(|status| status, |()| OneironStatus::Ok)
    })
}

/// Run a context-pack query and return UTF-8 bytes.
///
/// `query_text_ptr`, `query_vector_ptr`, `format_ptr` and `media_json_ptr`
/// are optional: pass a null pointer with length 0 to omit. If
/// `limit_is_set == 0`, the default limit of 10 is used; otherwise the pack
/// holds up to `limit` items, however many. The returned buffer must be
/// released with `oneiron_buffer_free`.
///
/// `media_json_ptr` is UTF-8 JSON of the served context pack's media query
/// (OF-370): `{"space": "<ai.embed rung id>@<provider>", "mime": "image/png",
/// "bytes_b64": "<standard base64>", "kinds": ["image"]}`, `kinds` optional.
/// JSON of another shape is `InvalidArg`. This library serves no `ai.embed`
/// rung, so once every input validates a pack naming media is refused
/// `ModelUnavailable` and nothing is packed: the media is never dropped.
///
/// # Safety
///
/// `vault` is null or a live handle from `oneiron_vault_open`, not freed
/// during the call. Each non-null input pointer covers its length in readable
/// values and each non-null out pointer is writable, for the whole call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_vault_context_pack(
    vault: *mut OneironVault,
    query_text_ptr: *const u8,
    query_text_len: usize,
    query_vector_ptr: *const f64,
    query_vector_len: usize,
    limit: u32,
    limit_is_set: u8,
    format_ptr: *const u8,
    format_len: usize,
    media_json_ptr: *const u8,
    media_json_len: usize,
    out_buffer: *mut OneironBuffer,
) -> OneironStatus {
    ffi_guard(|| {
        if let Err(status) = write_out(out_buffer, OneironBuffer::empty()) {
            return status;
        }
        let result = with_vault(vault, |handle| {
            let query_text = string_from_optional(query_text_ptr, query_text_len)?;
            if let Some(text) = query_text.as_deref() {
                validate_query_len(text)?;
            }
            let query_vector = with_optional_slice(query_vector_ptr, query_vector_len, |values| {
                values
                    .map(|query| convert_query_vector(query, handle.dimensions))
                    .transpose()
            })?;
            let limit = if limit_is_set == 0 {
                DEFAULT_FFI_SEARCH_LIMIT as usize
            } else {
                parse_search_limit(limit)?
            };
            let format = string_from_optional(format_ptr, format_len)?;
            let pack_format = parse_pack_format(format.as_deref());
            refuse_unserved_media(media_json_ptr, media_json_len)?;
            // The limit caps the pack itself: the channels fetch their
            // fusion list length whatever they are asked for.
            let mut builder = handle.vault.context_pack().format(pack_format).limit(limit);
            if let Some(text) = query_text.as_deref() {
                builder = builder.search_text(text, limit);
            }
            if let Some(vector) = query_vector.as_deref() {
                builder = builder.search_vector(vector, limit);
            }
            let output = engine(builder.run_serialized())?;
            str::from_utf8(&output).map_err(|_| OneironStatus::Utf8)?;
            write_out(out_buffer, buffer_from_vec(output))
        });
        result.map_or_else(|status| status, |()| OneironStatus::Ok)
    })
}

/// Return the stored entity type for an entity.
///
/// Returns `OneironStatus::NotFound` if the entity does not exist.
///
/// # Safety
///
/// `vault` is null or a live handle from `oneiron_vault_open`, not freed
/// during the call. Each non-null input pointer covers its length in readable
/// values and each non-null out pointer is writable, for the whole call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_vault_get_entity_type(
    vault: *mut OneironVault,
    id_ptr: *const u8,
    id_len: usize,
    out_entity_type: *mut u32,
) -> OneironStatus {
    ffi_guard(|| {
        if let Err(status) = write_out(out_entity_type, 0) {
            return status;
        }
        let result = with_vault(vault, |handle| {
            let id = parse_entity_id(id_ptr, id_len)?;
            match handle.entity_type_of(&id)? {
                Some(entity_type) => write_out(out_entity_type, u32::from(entity_type)),
                None => Err(OneironStatus::NotFound),
            }
        });
        result.map_or_else(|status| status, |()| OneironStatus::Ok)
    })
}

/// Return all entity IDs of a given type as packed 16-byte IDs.
///
/// `out_ids.len` is the byte length and is always a multiple of 16 on success.
/// Release the buffer with `oneiron_buffer_free`.
///
/// # Safety
///
/// `vault` is null or a live handle from `oneiron_vault_open`, not freed
/// during the call. Each non-null input pointer covers its length in readable
/// values and each non-null out pointer is writable, for the whole call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_vault_entities_by_type(
    vault: *mut OneironVault,
    entity_type: u32,
    out_ids: *mut OneironBuffer,
) -> OneironStatus {
    ffi_guard(|| {
        if let Err(status) = write_out(out_ids, OneironBuffer::empty()) {
            return status;
        }
        let result = with_vault(vault, |handle| {
            let entity_type = parse_u8(entity_type)?;
            let ids = engine(handle.vault.entities_by_type(entity_type))?;
            write_out(out_ids, id_list_buffer(ids)?)
        });
        result.map_or_else(|status| status, |()| OneironStatus::Ok)
    })
}

/// Return outbound edge targets filtered by kind and optional target type.
///
/// If `has_target_type == 0`, `target_type` is ignored. `out_ids.len` is the
/// byte length and is always a multiple of 16 on success. Release the buffer
/// with `oneiron_buffer_free`.
///
/// # Safety
///
/// `vault` is null or a live handle from `oneiron_vault_open`, not freed
/// during the call. Each non-null input pointer covers its length in readable
/// values and each non-null out pointer is writable, for the whole call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_vault_targets(
    vault: *mut OneironVault,
    src_ptr: *const u8,
    src_len: usize,
    kind: u32,
    target_type: u32,
    has_target_type: u8,
    out_ids: *mut OneironBuffer,
) -> OneironStatus {
    ffi_guard(|| {
        if let Err(status) = write_out(out_ids, OneironBuffer::empty()) {
            return status;
        }
        let result = with_vault(vault, |handle| {
            let src = parse_entity_id(src_ptr, src_len)?;
            let kind = parse_edge_kind(kind)?;
            let target_type = if has_target_type == 0 {
                None
            } else {
                Some(parse_u8(target_type)?)
            };
            let ids = handle.peers_of(&src, kind, target_type, true)?;
            write_out(out_ids, id_list_buffer(ids)?)
        });
        result.map_or_else(|status| status, |()| OneironStatus::Ok)
    })
}

/// Return inbound edge sources filtered by kind and optional source type.
///
/// If `has_source_type == 0`, `source_type` is ignored. `out_ids.len` is the
/// byte length and is always a multiple of 16 on success. Release the buffer
/// with `oneiron_buffer_free`.
///
/// # Safety
///
/// `vault` is null or a live handle from `oneiron_vault_open`, not freed
/// during the call. Each non-null input pointer covers its length in readable
/// values and each non-null out pointer is writable, for the whole call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_vault_sources(
    vault: *mut OneironVault,
    tgt_ptr: *const u8,
    tgt_len: usize,
    kind: u32,
    source_type: u32,
    has_source_type: u8,
    out_ids: *mut OneironBuffer,
) -> OneironStatus {
    ffi_guard(|| {
        if let Err(status) = write_out(out_ids, OneironBuffer::empty()) {
            return status;
        }
        let result = with_vault(vault, |handle| {
            let tgt = parse_entity_id(tgt_ptr, tgt_len)?;
            let kind = parse_edge_kind(kind)?;
            let source_type = if has_source_type == 0 {
                None
            } else {
                Some(parse_u8(source_type)?)
            };
            let ids = handle.peers_of(&tgt, kind, source_type, false)?;
            write_out(out_ids, id_list_buffer(ids)?)
        });
        result.map_or_else(|status| status, |()| OneironStatus::Ok)
    })
}

/// Return subtree descendants via `ChildOf` traversal.
///
/// `out_entries` receives a Rust-owned array that must be released with
/// `oneiron_subtree_entry_array_free`.
///
/// # Safety
///
/// `vault` is null or a live handle from `oneiron_vault_open`, not freed
/// during the call. Each non-null input pointer covers its length in readable
/// values and each non-null out pointer is writable, for the whole call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_vault_subtree(
    vault: *mut OneironVault,
    root_ptr: *const u8,
    root_len: usize,
    max_depth: u32,
    out_entries: *mut OneironSubtreeEntryArray,
) -> OneironStatus {
    ffi_guard(|| {
        if let Err(status) = write_out(out_entries, OneironSubtreeEntryArray::empty()) {
            return status;
        }
        let result = with_vault(vault, |handle| {
            let root = parse_entity_id(root_ptr, root_len)?;
            let entries = engine(handle.vault.subtree(&root, max_depth))?;
            let out = entries
                .into_iter()
                .map(|(id, depth)| OneironSubtreeEntry {
                    id: id_array(&id),
                    depth,
                })
                .collect();
            write_out(out_entries, subtree_array_from_vec(out))
        });
        result.map_or_else(|status| status, |()| OneironStatus::Ok)
    })
}

/// Walk ancestors via `ChildOf` edges as packed 16-byte IDs.
///
/// `out_ids.len` is the byte length and is always a multiple of 16 on success.
/// Release the buffer with `oneiron_buffer_free`.
///
/// # Safety
///
/// `vault` is null or a live handle from `oneiron_vault_open`, not freed
/// during the call. Each non-null input pointer covers its length in readable
/// values and each non-null out pointer is writable, for the whole call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_vault_ancestors(
    vault: *mut OneironVault,
    node_ptr: *const u8,
    node_len: usize,
    out_ids: *mut OneironBuffer,
) -> OneironStatus {
    ffi_guard(|| {
        if let Err(status) = write_out(out_ids, OneironBuffer::empty()) {
            return status;
        }
        let result = with_vault(vault, |handle| {
            let node = parse_entity_id(node_ptr, node_len)?;
            let ids = engine(handle.vault.ancestors(&node))?;
            write_out(out_ids, id_list_buffer(ids)?)
        });
        result.map_or_else(|status| status, |()| OneironStatus::Ok)
    })
}

/// Check whether making `target` a parent of `node` would create a cycle.
///
/// `out_would_cycle` receives `1` for true and `0` for false.
///
/// # Safety
///
/// `vault` is null or a live handle from `oneiron_vault_open`, not freed
/// during the call. Each non-null input pointer covers its length in readable
/// values and each non-null out pointer is writable, for the whole call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_vault_would_create_cycle(
    vault: *mut OneironVault,
    node_ptr: *const u8,
    node_len: usize,
    target_ptr: *const u8,
    target_len: usize,
    out_would_cycle: *mut u8,
) -> OneironStatus {
    ffi_guard(|| {
        if let Err(status) = write_out(out_would_cycle, 0) {
            return status;
        }
        let result = with_vault(vault, |handle| {
            let node = parse_entity_id(node_ptr, node_len)?;
            let target = parse_entity_id(target_ptr, target_len)?;
            let would_cycle = engine(handle.vault.would_create_cycle(&node, &target))?;
            write_out(out_would_cycle, u8::from(would_cycle))
        });
        result.map_or_else(|status| status, |()| OneironStatus::Ok)
    })
}
