//! C ABI for on-device iOS and macOS access to the Oneiron vault.
//!
//! Variable-size outputs are allocated by Rust and returned through
//! `OneironBuffer` or typed array structs. Callers must release those values
//! with the paired `oneiron_*_free` function from this crate. Never pass these
//! pointers to the platform allocator, and never free the same value twice.
//!
//! Sync stubs from the N-API surface (`start_sync` / `stop_sync`) are
//! intentionally not exported here while shared multi-vault sync is disabled.
//! The core read/write N-API vault surface is mirrored by this C ABI.

use std::{
    mem::size_of,
    panic::{AssertUnwindSafe, catch_unwind},
    path::PathBuf,
    ptr, slice, str,
    sync::Arc,
};

use oneiron::{EdgeKind, EntityId, PackFormat, TimeRange, Vault, VaultConfig};

const DEFAULT_FFI_SEARCH_LIMIT: u32 = 10;
const MAX_FFI_SEARCH_LIMIT: u32 = 1_000;
const MAX_FFI_QUERY_BYTES: usize = 8 * 1024;
const MAX_FFI_DIMENSIONS: usize = 16_384;
const ENTITY_ID_LEN: usize = 16;

/// Status code returned by every fallible C entry point.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OneironStatus {
    /// Operation completed successfully.
    Ok = 0,
    /// A required pointer argument was null.
    NullArg = 1,
    /// A scalar, length, enum discriminant, or ID value failed validation.
    InvalidArg = 2,
    /// The requested optional value was not found.
    NotFound = 3,
    /// The engine returned an error.
    EngineError = 4,
    /// A Rust panic was caught before it crossed the C ABI boundary.
    Panic = 5,
    /// Reserved for caller-owned buffer APIs.
    BufferTooSmall = 6,
    /// Input bytes were not valid UTF-8.
    Utf8 = 7,
}

/// Borrowed byte/string input for arrays such as `dict_search_paths`.
///
/// Each element is caller-owned and is only borrowed for the duration of the
/// call. String uses are UTF-8 validated by the receiving function.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OneironByteSlice {
    pub ptr: *const u8,
    pub len: usize,
}

/// Borrowed entity input for `oneiron_vault_batch_put_entities`.
///
/// Each payload is caller-owned and borrowed only for the duration of the
/// call. Entity IDs are fixed-width 16-byte values; `entity_type` must fit in
/// one byte and pass the engine's public entity-type gate.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OneironEntityInput {
    pub id: [u8; 16],
    pub entity_type: u32,
    pub occurred_start: i64,
    pub occurred_end: i64,
    pub learned_at: i64,
    pub data: OneironByteSlice,
}

/// Rust-owned byte buffer returned by variable-size byte outputs.
///
/// The caller must release non-empty buffers with `oneiron_buffer_free`. The
/// caller must not pass `ptr` to `free()` and must not call the free function
/// more than once for the same buffer.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OneironBuffer {
    pub ptr: *mut u8,
    pub len: usize,
    pub cap: usize,
}

impl OneironBuffer {
    const fn empty() -> Self {
        Self {
            ptr: ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }
}

/// C representation of an edge returned by `edges_out` and `edges_in`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OneironEdgeInfo {
    pub src: [u8; 16],
    pub kind: u32,
    pub tgt: [u8; 16],
    pub weight: f64,
    pub created_at: i64,
    pub has_vad: u8,
    pub valence: f64,
    pub arousal: f64,
    pub dominance: f64,
}

/// Rust-owned edge array. Free with `oneiron_edge_info_array_free`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OneironEdgeInfoArray {
    pub ptr: *mut OneironEdgeInfo,
    pub len: usize,
    pub cap: usize,
}

impl OneironEdgeInfoArray {
    const fn empty() -> Self {
        Self {
            ptr: ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }
}

/// C representation of a scored search result.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OneironScoredEntity {
    pub id: [u8; 16],
    pub score: f64,
}

/// Rust-owned scored search result array. Free with
/// `oneiron_scored_entity_array_free`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OneironScoredEntityArray {
    pub ptr: *mut OneironScoredEntity,
    pub len: usize,
    pub cap: usize,
}

impl OneironScoredEntityArray {
    const fn empty() -> Self {
        Self {
            ptr: ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }
}

/// C representation of a subtree traversal entry.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OneironSubtreeEntry {
    pub id: [u8; 16],
    pub depth: u32,
}

/// Rust-owned subtree entry array. Free with
/// `oneiron_subtree_entry_array_free`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OneironSubtreeEntryArray {
    pub ptr: *mut OneironSubtreeEntry,
    pub len: usize,
    pub cap: usize,
}

impl OneironSubtreeEntryArray {
    const fn empty() -> Self {
        Self {
            ptr: ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }
}

/// Opaque vault handle returned by `oneiron_vault_open`.
///
/// Release the handle with `oneiron_vault_free` exactly once.
pub struct OneironVault {
    vault: Arc<Vault>,
    dimensions: usize,
}

fn ffi_guard(f: impl FnOnce() -> OneironStatus) -> OneironStatus {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(status) => status,
        Err(_) => OneironStatus::Panic,
    }
}

fn checked_slice_len<T>(len: usize) -> Result<(), OneironStatus> {
    let elem = size_of::<T>().max(1);
    if len > isize::MAX as usize / elem {
        return Err(OneironStatus::InvalidArg);
    }
    Ok(())
}

fn with_required_slice<T, R>(
    ptr: *const T,
    len: usize,
    f: impl FnOnce(&[T]) -> Result<R, OneironStatus>,
) -> Result<R, OneironStatus> {
    if ptr.is_null() {
        return Err(OneironStatus::NullArg);
    }
    checked_slice_len::<T>(len)?;
    // SAFETY: The caller supplies a non-null pointer to at least `len`
    // contiguous `T` values that stay alive for the duration of this call.
    let values = unsafe { slice::from_raw_parts(ptr, len) };
    f(values)
}

fn with_optional_slice<T, R>(
    ptr: *const T,
    len: usize,
    f: impl FnOnce(Option<&[T]>) -> Result<R, OneironStatus>,
) -> Result<R, OneironStatus> {
    if ptr.is_null() {
        if len == 0 {
            return f(None);
        }
        return Err(OneironStatus::NullArg);
    }
    checked_slice_len::<T>(len)?;
    // SAFETY: The caller supplies a non-null pointer to at least `len`
    // contiguous `T` values that stay alive for the duration of this call.
    let values = unsafe { slice::from_raw_parts(ptr, len) };
    f(Some(values))
}

fn write_out<T>(out: *mut T, value: T) -> Result<(), OneironStatus> {
    if out.is_null() {
        return Err(OneironStatus::NullArg);
    }
    // SAFETY: `out` is non-null and the caller guarantees it points to
    // writable storage for one `T`. `ptr::write` avoids reading old contents.
    unsafe { ptr::write(out, value) };
    Ok(())
}

fn with_vault<R>(
    vault: *mut OneironVault,
    f: impl FnOnce(&OneironVault) -> Result<R, OneironStatus>,
) -> Result<R, OneironStatus> {
    if vault.is_null() {
        return Err(OneironStatus::NullArg);
    }
    // SAFETY: `vault` is a non-null handle previously returned by
    // `oneiron_vault_open` and not yet freed by `oneiron_vault_free`.
    let vault = unsafe { &*vault };
    f(vault)
}

fn string_from_required(ptr: *const u8, len: usize) -> Result<String, OneironStatus> {
    with_required_slice(ptr, len, |bytes| {
        str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| OneironStatus::Utf8)
    })
}

fn string_from_optional(ptr: *const u8, len: usize) -> Result<Option<String>, OneironStatus> {
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

fn parse_id_bytes(bytes: &[u8]) -> Result<EntityId, OneironStatus> {
    if bytes.len() != ENTITY_ID_LEN {
        return Err(OneironStatus::InvalidArg);
    }
    let id: [u8; ENTITY_ID_LEN] = bytes.try_into().map_err(|_| OneironStatus::InvalidArg)?;
    EntityId::from_bytes(id).map_err(|_| OneironStatus::InvalidArg)
}

fn parse_entity_id(ptr: *const u8, len: usize) -> Result<EntityId, OneironStatus> {
    with_required_slice(ptr, len, parse_id_bytes)
}

fn parse_u8(value: u32) -> Result<u8, OneironStatus> {
    u8::try_from(value).map_err(|_| OneironStatus::InvalidArg)
}

fn parse_edge_kind(kind: u32) -> Result<EdgeKind, OneironStatus> {
    let byte = parse_u8(kind)?;
    EdgeKind::try_from_u8(byte).ok_or(OneironStatus::InvalidArg)
}

fn parse_search_limit(limit: u32) -> Result<usize, OneironStatus> {
    if limit > MAX_FFI_SEARCH_LIMIT {
        return Err(OneironStatus::InvalidArg);
    }
    Ok(limit as usize)
}

fn validate_query_len(query: &str) -> Result<(), OneironStatus> {
    if query.len() > MAX_FFI_QUERY_BYTES {
        return Err(OneironStatus::InvalidArg);
    }
    Ok(())
}

fn validate_dimensions(dimensions: usize) -> Result<(), OneironStatus> {
    if dimensions > MAX_FFI_DIMENSIONS {
        return Err(OneironStatus::InvalidArg);
    }
    Ok(())
}

fn validate_vector_len(len: usize, expected: usize) -> Result<(), OneironStatus> {
    if len != expected {
        return Err(OneironStatus::InvalidArg);
    }
    Ok(())
}

fn ts_to_u64(ts: i64) -> u64 {
    ts.max(0) as u64
}

fn engine<T>(result: Result<T, oneiron::Error>) -> Result<T, OneironStatus> {
    result.map_err(|_| OneironStatus::EngineError)
}

fn id_array(id: &EntityId) -> [u8; ENTITY_ID_LEN] {
    *id.as_bytes()
}

fn created_at_to_i64(created_at: u64) -> Result<i64, OneironStatus> {
    i64::try_from(created_at).map_err(|_| OneironStatus::EngineError)
}

fn buffer_from_vec(mut bytes: Vec<u8>) -> OneironBuffer {
    if bytes.is_empty() {
        return OneironBuffer::empty();
    }
    let buffer = OneironBuffer {
        ptr: bytes.as_mut_ptr(),
        len: bytes.len(),
        cap: bytes.capacity(),
    };
    std::mem::forget(bytes);
    buffer
}

fn id_list_buffer(ids: Vec<EntityId>) -> Result<OneironBuffer, OneironStatus> {
    let capacity = ids
        .len()
        .checked_mul(ENTITY_ID_LEN)
        .ok_or(OneironStatus::EngineError)?;
    let mut bytes = Vec::with_capacity(capacity);
    for id in ids {
        bytes.extend_from_slice(id.as_bytes());
    }
    Ok(buffer_from_vec(bytes))
}

fn edge_array_from_vec(mut values: Vec<OneironEdgeInfo>) -> OneironEdgeInfoArray {
    if values.is_empty() {
        return OneironEdgeInfoArray::empty();
    }
    let array = OneironEdgeInfoArray {
        ptr: values.as_mut_ptr(),
        len: values.len(),
        cap: values.capacity(),
    };
    std::mem::forget(values);
    array
}

fn scored_array_from_vec(mut values: Vec<OneironScoredEntity>) -> OneironScoredEntityArray {
    if values.is_empty() {
        return OneironScoredEntityArray::empty();
    }
    let array = OneironScoredEntityArray {
        ptr: values.as_mut_ptr(),
        len: values.len(),
        cap: values.capacity(),
    };
    std::mem::forget(values);
    array
}

fn subtree_array_from_vec(mut values: Vec<OneironSubtreeEntry>) -> OneironSubtreeEntryArray {
    if values.is_empty() {
        return OneironSubtreeEntryArray::empty();
    }
    let array = OneironSubtreeEntryArray {
        ptr: values.as_mut_ptr(),
        len: values.len(),
        cap: values.capacity(),
    };
    std::mem::forget(values);
    array
}

fn free_vec<T>(ptr: *mut T, len: usize, cap: usize) -> OneironStatus {
    if ptr.is_null() {
        return if len == 0 && cap == 0 {
            OneironStatus::Ok
        } else {
            OneironStatus::InvalidArg
        };
    }
    if len > cap {
        return OneironStatus::InvalidArg;
    }
    // SAFETY: The pointer, length, and capacity must be the exact triple
    // returned by this crate for a `Vec<T>` allocation and not freed before.
    unsafe { drop(Vec::from_raw_parts(ptr, len, cap)) };
    OneironStatus::Ok
}

fn parse_pack_format(format: Option<&str>) -> PackFormat {
    match format {
        Some("yaml") => PackFormat::Yaml,
        Some("toon") => PackFormat::Toon,
        Some("markdown") => PackFormat::Markdown,
        Some("plaintext") => PackFormat::Plaintext,
        _ => PackFormat::Json,
    }
}

fn convert_query_vector(query: &[f64], dimensions: usize) -> Result<Vec<f32>, OneironStatus> {
    validate_vector_len(query.len(), dimensions)?;
    Ok(query.iter().map(|&value| value as f32).collect())
}

/// Free a Rust-owned byte buffer returned by this crate.
///
/// Passing a null, zero-length buffer is accepted. Passing a mutated buffer,
/// an already-freed buffer, or memory allocated outside this crate is undefined
/// behavior by the C ABI contract.
#[unsafe(no_mangle)]
pub extern "C" fn oneiron_buffer_free(buffer: OneironBuffer) -> OneironStatus {
    ffi_guard(|| free_vec(buffer.ptr, buffer.len, buffer.cap))
}

/// Free a Rust-owned edge array returned by this crate.
#[unsafe(no_mangle)]
pub extern "C" fn oneiron_edge_info_array_free(array: OneironEdgeInfoArray) -> OneironStatus {
    ffi_guard(|| free_vec(array.ptr, array.len, array.cap))
}

/// Free a Rust-owned scored entity array returned by this crate.
#[unsafe(no_mangle)]
pub extern "C" fn oneiron_scored_entity_array_free(
    array: OneironScoredEntityArray,
) -> OneironStatus {
    ffi_guard(|| free_vec(array.ptr, array.len, array.cap))
}

/// Free a Rust-owned subtree entry array returned by this crate.
#[unsafe(no_mangle)]
pub extern "C" fn oneiron_subtree_entry_array_free(
    array: OneironSubtreeEntryArray,
) -> OneironStatus {
    ffi_guard(|| free_vec(array.ptr, array.len, array.cap))
}

/// Open or create a vault using `VaultConfig::device()`.
///
/// `dimensions == 0` keeps the device preset default. `dict_search_paths` may
/// be null only when `dict_search_paths_len == 0`; otherwise it must point to
/// an array of UTF-8 `OneironByteSlice` values. On success `out_vault` receives
/// an opaque handle that must be released exactly once with `oneiron_vault_free`.
#[unsafe(no_mangle)]
pub extern "C" fn oneiron_vault_open(
    path_ptr: *const u8,
    path_len: usize,
    dimensions: usize,
    dict_search_paths: *const OneironByteSlice,
    dict_search_paths_len: usize,
    out_vault: *mut *mut OneironVault,
) -> OneironStatus {
    ffi_guard(|| {
        write_out(out_vault, ptr::null_mut()).map_or_else(
            |status| status,
            |_| {
                let result = (|| {
                    let path = string_from_required(path_ptr, path_len)?;
                    let mut config = VaultConfig::device();
                    if dimensions != 0 {
                        config.dimensions = dimensions;
                    }
                    validate_dimensions(config.dimensions)?;
                    config.dict_search_paths =
                        with_optional_slice(dict_search_paths, dict_search_paths_len, |paths| {
                            paths.map_or_else(
                                || Ok(Vec::new()),
                                |values| {
                                    values
                                        .iter()
                                        .map(|value| {
                                            string_from_required(value.ptr, value.len)
                                                .map(PathBuf::from)
                                        })
                                        .collect()
                                },
                            )
                        })?;
                    let dimensions = config.dimensions;
                    let vault = engine(Vault::open(&path, config))?;
                    let handle = Box::into_raw(Box::new(OneironVault {
                        vault: Arc::new(vault),
                        dimensions,
                    }));
                    write_out(out_vault, handle)?;
                    Ok(())
                })();
                result.map_or_else(|status| status, |()| OneironStatus::Ok)
            },
        )
    })
}

/// Free an opaque vault handle returned by `oneiron_vault_open`.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn oneiron_vault_free(vault: *mut OneironVault) -> OneironStatus {
    ffi_guard(|| {
        if vault.is_null() {
            return OneironStatus::NullArg;
        }
        // SAFETY: The pointer must be a live handle returned by
        // `oneiron_vault_open` and not previously freed.
        unsafe { drop(Box::from_raw(vault)) };
        OneironStatus::Ok
    })
}

/// Store an entity blob.
#[unsafe(no_mangle)]
pub extern "C" fn oneiron_vault_put_entity(
    vault: *mut OneironVault,
    id_ptr: *const u8,
    id_len: usize,
    entity_type: u32,
    occurred_start: i64,
    occurred_end: i64,
    learned_at: i64,
    data_ptr: *const u8,
    data_len: usize,
) -> OneironStatus {
    ffi_guard(|| {
        let result = with_vault(vault, |handle| {
            let id = parse_entity_id(id_ptr, id_len)?;
            let entity_type = parse_u8(entity_type)?;
            with_required_slice(data_ptr, data_len, |data| {
                engine(handle.vault.put_entity(
                    &id,
                    entity_type,
                    TimeRange {
                        start: ts_to_u64(occurred_start),
                        end: ts_to_u64(occurred_end),
                    },
                    ts_to_u64(learned_at),
                    data,
                ))
            })
        });
        result.map_or_else(|status| status, |()| OneironStatus::Ok)
    })
}

/// Store multiple entity blobs in one vault transaction.
///
/// `entities` may be null only when `entities_len == 0`. Each payload pointer
/// inside the array must be non-null for its byte length.
#[unsafe(no_mangle)]
pub extern "C" fn oneiron_vault_batch_put_entities(
    vault: *mut OneironVault,
    entities: *const OneironEntityInput,
    entities_len: usize,
) -> OneironStatus {
    ffi_guard(|| {
        let result = with_vault(vault, |handle| {
            with_optional_slice(entities, entities_len, |values| {
                let mut batch = handle.vault.batch();
                for entry in values.unwrap_or(&[]) {
                    let id =
                        EntityId::from_bytes(entry.id).map_err(|_| OneironStatus::InvalidArg)?;
                    let entity_type = parse_u8(entry.entity_type)?;
                    let data = with_required_slice(entry.data.ptr, entry.data.len, |data| {
                        Ok(data.to_vec())
                    })?;
                    batch = batch.put(
                        &id,
                        entity_type,
                        TimeRange {
                            start: ts_to_u64(entry.occurred_start),
                            end: ts_to_u64(entry.occurred_end),
                        },
                        ts_to_u64(entry.learned_at),
                        &data,
                    );
                }
                engine(batch.commit())
            })
        });
        result.map_or_else(|status| status, |()| OneironStatus::Ok)
    })
}

/// Retrieve an entity blob by ID.
///
/// Returns `OneironStatus::NotFound` if the entity does not exist. On success,
/// `out_buffer` receives Rust-owned bytes that must be released with
/// `oneiron_buffer_free`.
#[unsafe(no_mangle)]
pub extern "C" fn oneiron_vault_get_entity(
    vault: *mut OneironVault,
    id_ptr: *const u8,
    id_len: usize,
    out_buffer: *mut OneironBuffer,
) -> OneironStatus {
    ffi_guard(|| {
        if let Err(status) = write_out(out_buffer, OneironBuffer::empty()) {
            return status;
        }
        let result = with_vault(vault, |handle| {
            let id = parse_entity_id(id_ptr, id_len)?;
            match engine(handle.vault.get(&id))? {
                Some(bytes) => write_out(out_buffer, buffer_from_vec(bytes)),
                None => Err(OneironStatus::NotFound),
            }
        });
        result.map_or_else(|status| status, |()| OneironStatus::Ok)
    })
}

/// Delete an entity by ID.
///
/// `out_existed` receives `1` if the entity existed and `0` otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn oneiron_vault_delete_entity(
    vault: *mut OneironVault,
    id_ptr: *const u8,
    id_len: usize,
    out_existed: *mut u8,
) -> OneironStatus {
    ffi_guard(|| {
        if let Err(status) = write_out(out_existed, 0) {
            return status;
        }
        let result = with_vault(vault, |handle| {
            let id = parse_entity_id(id_ptr, id_len)?;
            let existed = engine(handle.vault.delete_entity(&id))?;
            write_out(out_existed, u8::from(existed))
        });
        result.map_or_else(|status| status, |()| OneironStatus::Ok)
    })
}

/// Check whether an entity exists.
///
/// `out_exists` receives `1` if the entity exists and `0` otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn oneiron_vault_entity_exists(
    vault: *mut OneironVault,
    id_ptr: *const u8,
    id_len: usize,
    out_exists: *mut u8,
) -> OneironStatus {
    ffi_guard(|| {
        if let Err(status) = write_out(out_exists, 0) {
            return status;
        }
        let result = with_vault(vault, |handle| {
            let id = parse_entity_id(id_ptr, id_len)?;
            let exists = engine(handle.vault.entity_exists(&id))?;
            write_out(out_exists, u8::from(exists))
        });
        result.map_or_else(|status| status, |()| OneironStatus::Ok)
    })
}

/// Store a directed edge between two entities.
#[unsafe(no_mangle)]
pub extern "C" fn oneiron_vault_put_edge(
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
            engine(handle.vault.put_edge(&src, kind, &tgt, weight as f32))
        });
        result.map_or_else(|status| status, |()| OneironStatus::Ok)
    })
}

/// Return outbound edges for a source entity.
///
/// `out_edges` receives a Rust-owned array that must be released with
/// `oneiron_edge_info_array_free`.
#[unsafe(no_mangle)]
pub extern "C" fn oneiron_vault_edges_out(
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
            let edges = engine(handle.vault.edges_out(&src))?;
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
#[unsafe(no_mangle)]
pub extern "C" fn oneiron_vault_edges_in(
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
            let edges = engine(handle.vault.edges_in(&tgt))?;
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
#[unsafe(no_mangle)]
pub extern "C" fn oneiron_vault_search_vector(
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
#[unsafe(no_mangle)]
pub extern "C" fn oneiron_vault_search_text(
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
/// `vector_len` must equal the vault dimensions.
#[unsafe(no_mangle)]
pub extern "C" fn oneiron_vault_put_vector(
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
            engine(handle.vault.put_vector(&id, &vector))
        });
        result.map_or_else(|status| status, |()| OneironStatus::Ok)
    })
}

/// Run a context-pack query and return UTF-8 bytes.
///
/// `query_text_ptr`, `query_vector_ptr`, and `format_ptr` are optional: pass a
/// null pointer with length 0 to omit. If `limit_is_set == 0`, the default
/// limit of 10 is used; otherwise `limit` must be at most 1000. The returned
/// buffer must be released with `oneiron_buffer_free`.
#[unsafe(no_mangle)]
pub extern "C" fn oneiron_vault_context_pack(
    vault: *mut OneironVault,
    query_text_ptr: *const u8,
    query_text_len: usize,
    query_vector_ptr: *const f64,
    query_vector_len: usize,
    limit: u32,
    limit_is_set: u8,
    format_ptr: *const u8,
    format_len: usize,
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
            let mut builder = handle.vault.context_pack().format(pack_format);
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
#[unsafe(no_mangle)]
pub extern "C" fn oneiron_vault_get_entity_type(
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
            match engine(handle.vault.get_entity_type(&id))? {
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
#[unsafe(no_mangle)]
pub extern "C" fn oneiron_vault_entities_by_type(
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
#[unsafe(no_mangle)]
pub extern "C" fn oneiron_vault_targets(
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
            let ids = engine(handle.vault.targets(&src, kind, target_type))?;
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
#[unsafe(no_mangle)]
pub extern "C" fn oneiron_vault_sources(
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
            let ids = engine(handle.vault.sources(&tgt, kind, source_type))?;
            write_out(out_ids, id_list_buffer(ids)?)
        });
        result.map_or_else(|status| status, |()| OneironStatus::Ok)
    })
}

/// Return subtree descendants via `ChildOf` traversal.
///
/// `out_entries` receives a Rust-owned array that must be released with
/// `oneiron_subtree_entry_array_free`.
#[unsafe(no_mangle)]
pub extern "C" fn oneiron_vault_subtree(
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
#[unsafe(no_mangle)]
pub extern "C" fn oneiron_vault_ancestors(
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
#[unsafe(no_mangle)]
pub extern "C" fn oneiron_vault_would_create_cycle(
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

#[cfg(test)]
mod tests {
    use super::*;

    fn id(seed: u8) -> [u8; ENTITY_ID_LEN] {
        let mut id = [0_u8; ENTITY_ID_LEN];
        for (offset, byte) in id.iter_mut().enumerate() {
            *byte = seed.wrapping_add(offset as u8);
        }
        id
    }

    fn open_test_vault(dimensions: usize) -> (tempfile::TempDir, *mut OneironVault) {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().to_str().expect("utf8 temp path");
        let mut vault = ptr::null_mut();
        let status = oneiron_vault_open(
            path.as_ptr(),
            path.len(),
            dimensions,
            ptr::null(),
            0,
            &mut vault,
        );
        assert_eq!(status, OneironStatus::Ok);
        assert!(!vault.is_null());
        (dir, vault)
    }

    #[test]
    fn ffi_round_trips_entity_edge_and_fail_closed_cases() {
        let (_dir, vault) = open_test_vault(4);
        let entity = id(1);
        let target = id(32);
        let payload = b"ffi-payload";
        let target_payload = b"ffi-target";

        assert_eq!(
            oneiron_vault_put_entity(
                vault,
                entity.as_ptr(),
                entity.len(),
                1,
                10,
                20,
                30,
                payload.as_ptr(),
                payload.len(),
            ),
            OneironStatus::Ok
        );
        assert_eq!(
            oneiron_vault_put_entity(
                vault,
                target.as_ptr(),
                target.len(),
                1,
                10,
                20,
                30,
                target_payload.as_ptr(),
                target_payload.len(),
            ),
            OneironStatus::Ok
        );

        let mut exists = 0;
        assert_eq!(
            oneiron_vault_entity_exists(vault, entity.as_ptr(), entity.len(), &mut exists),
            OneironStatus::Ok
        );
        assert_eq!(exists, 1);

        let mut bytes = OneironBuffer::empty();
        assert_eq!(
            oneiron_vault_get_entity(vault, entity.as_ptr(), entity.len(), &mut bytes),
            OneironStatus::Ok
        );
        // SAFETY: `bytes` was returned by this crate and is live until freed.
        let read_back = unsafe { slice::from_raw_parts(bytes.ptr, bytes.len) };
        assert_eq!(read_back, payload);
        assert_eq!(oneiron_buffer_free(bytes), OneironStatus::Ok);

        assert_eq!(
            oneiron_vault_put_edge(
                vault,
                entity.as_ptr(),
                entity.len(),
                EdgeKind::Mentions as u32,
                target.as_ptr(),
                target.len(),
                0.5,
            ),
            OneironStatus::Ok
        );
        let mut edges = OneironEdgeInfoArray::empty();
        assert_eq!(
            oneiron_vault_edges_out(vault, entity.as_ptr(), entity.len(), &mut edges),
            OneironStatus::Ok
        );
        assert_eq!(edges.len, 1);
        // SAFETY: `edges` was returned by this crate and is live until freed.
        let edge_slice = unsafe { slice::from_raw_parts(edges.ptr, edges.len) };
        assert_eq!(edge_slice[0].src, entity);
        assert_eq!(edge_slice[0].tgt, target);
        assert_eq!(edge_slice[0].kind, EdgeKind::Mentions as u32);
        assert_eq!(oneiron_edge_info_array_free(edges), OneironStatus::Ok);

        let mut existed = 0;
        assert_eq!(
            oneiron_vault_delete_entity(vault, entity.as_ptr(), entity.len(), &mut existed),
            OneironStatus::Ok
        );
        assert_eq!(existed, 1);
        assert_eq!(
            oneiron_vault_entity_exists(vault, entity.as_ptr(), entity.len(), &mut exists),
            OneironStatus::Ok
        );
        assert_eq!(exists, 0);

        assert_eq!(
            oneiron_vault_entity_exists(
                ptr::null_mut(),
                entity.as_ptr(),
                entity.len(),
                &mut exists
            ),
            OneironStatus::NullArg
        );
        assert_eq!(
            oneiron_vault_entity_exists(vault, entity.as_ptr(), 15, &mut exists),
            OneironStatus::InvalidArg
        );

        let long_query = "x".repeat(MAX_FFI_QUERY_BYTES + 1);
        let mut scored = OneironScoredEntityArray::empty();
        assert_eq!(
            oneiron_vault_search_text(
                vault,
                long_query.as_ptr(),
                long_query.len(),
                10,
                &mut scored,
            ),
            OneironStatus::InvalidArg
        );
        assert_eq!(
            oneiron_vault_search_text(
                vault,
                b"x".as_ptr(),
                1,
                MAX_FFI_SEARCH_LIMIT + 1,
                &mut scored
            ),
            OneironStatus::InvalidArg
        );

        assert_eq!(
            oneiron_vault_put_edge(
                vault,
                target.as_ptr(),
                target.len(),
                EdgeKind::Mentions as u32,
                target.as_ptr(),
                target.len(),
                f64::NAN,
            ),
            OneironStatus::EngineError
        );

        assert_eq!(oneiron_vault_free(vault), OneironStatus::Ok);
    }

    #[test]
    fn ffi_batch_put_entities_and_boundary_statuses() {
        let (_dir, vault) = open_test_vault(4);
        let first = id(80);
        let second = id(96);
        let first_payload = b"batch-first";
        let second_payload = b"batch-second";
        let entries = [
            OneironEntityInput {
                id: first,
                entity_type: 1,
                occurred_start: 10,
                occurred_end: 10,
                learned_at: 11,
                data: OneironByteSlice {
                    ptr: first_payload.as_ptr(),
                    len: first_payload.len(),
                },
            },
            OneironEntityInput {
                id: second,
                entity_type: 1,
                occurred_start: 12,
                occurred_end: 12,
                learned_at: 13,
                data: OneironByteSlice {
                    ptr: second_payload.as_ptr(),
                    len: second_payload.len(),
                },
            },
        ];

        assert_eq!(
            oneiron_vault_batch_put_entities(vault, entries.as_ptr(), entries.len()),
            OneironStatus::Ok
        );

        let mut bytes = OneironBuffer::empty();
        assert_eq!(
            oneiron_vault_get_entity(vault, first.as_ptr(), first.len(), &mut bytes),
            OneironStatus::Ok
        );
        // SAFETY: `bytes` was returned by this crate and is live until freed.
        let read_back = unsafe { slice::from_raw_parts(bytes.ptr, bytes.len) };
        assert_eq!(read_back, first_payload);
        assert_eq!(oneiron_buffer_free(bytes), OneironStatus::Ok);

        let missing = id(112);
        let mut missing_buffer = OneironBuffer::empty();
        assert_eq!(
            oneiron_vault_get_entity(vault, missing.as_ptr(), missing.len(), &mut missing_buffer,),
            OneironStatus::NotFound
        );
        assert!(missing_buffer.ptr.is_null());
        assert_eq!(missing_buffer.len, 0);

        assert_eq!(
            oneiron_vault_batch_put_entities(vault, ptr::null(), 1),
            OneironStatus::NullArg
        );

        let mut invalid_path_vault = ptr::null_mut();
        let invalid_path = [0xFF_u8];
        assert_eq!(
            oneiron_vault_open(
                invalid_path.as_ptr(),
                invalid_path.len(),
                0,
                ptr::null(),
                0,
                &mut invalid_path_vault,
            ),
            OneironStatus::Utf8
        );
        assert!(invalid_path_vault.is_null());

        assert_eq!(oneiron_vault_free(vault), OneironStatus::Ok);
    }
}
