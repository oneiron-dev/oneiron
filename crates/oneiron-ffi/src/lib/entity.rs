//! Free fns plus vault lifecycle, health, and entity entry points.

use std::{path::PathBuf, ptr, sync::Arc};

use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

use super::alloc::{buffer_from_vec, free_vec};
use super::guard::{ffi_guard, with_optional_slice, with_required_slice, with_vault, write_out};
use super::parse::{
    engine, parse_entity_id, parse_u8, string_from_required, ts_to_u64, validate_dimensions,
};
use super::types::{
    OneironBuffer, OneironByteSlice, OneironEdgeInfoArray, OneironEntityInput,
    OneironScoredEntityArray, OneironStatus, OneironSubtreeEntryArray, OneironVault,
};

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

/// Return a UTF-8 JSON doctor report for an opened vault.
///
/// The report is read-only and mirrors `Vault::doctor()`: it observes the
/// persisted compatibility metadata consumed by open-time storage ABI gates
/// without repairing, rebuilding, or changing on-disk layout. On success,
/// `out_buffer` receives Rust-owned bytes that must be released with
/// `oneiron_buffer_free`.
#[unsafe(no_mangle)]
pub extern "C" fn oneiron_vault_health_json(
    vault: *mut OneironVault,
    out_buffer: *mut OneironBuffer,
) -> OneironStatus {
    ffi_guard(|| {
        if let Err(status) = write_out(out_buffer, OneironBuffer::empty()) {
            return status;
        }
        let result = with_vault(vault, |handle| {
            let report = engine(handle.vault.doctor())?;
            let bytes = serde_json::to_vec(&report).map_err(|_| OneironStatus::EngineError)?;
            write_out(out_buffer, buffer_from_vec(bytes))
        });
        result.map_or_else(|status| status, |()| OneironStatus::Ok)
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
