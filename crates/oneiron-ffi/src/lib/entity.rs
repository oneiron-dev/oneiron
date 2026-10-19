//! Free fns plus vault lifecycle, health, and entity entry points.

use std::{path::PathBuf, ptr, sync::Arc};

use oneiron::{
    EdgeActorClass, EntityId, RawEntityPut, TimeRange, Vault, VaultConfig,
    authority::MachineDeviceClass, parse_actor_key,
};

use super::alloc::{buffer_from_vec, free_vec};
use super::guard::{ffi_guard, with_optional_slice, with_required_slice, with_vault, write_out};
use super::parse::{
    engine, memory_result, parse_entity_id, parse_u8, string_from_optional, string_from_required,
    ts_to_u64, validate_dimensions,
};
use super::types::{
    OneironBuffer, OneironByteSlice, OneironEdgeInfoArray, OneironEntityInput,
    OneironScoredEntityArray, OneironStatus, OneironSubtreeEntryArray, OneironVault, VaultBinding,
};

/// Free a Rust-owned byte buffer returned by this crate.
///
/// Passing a null, zero-length buffer is accepted. Passing a mutated buffer,
/// an already-freed buffer, or memory allocated outside this crate is undefined
/// behavior by the C ABI contract.
///
/// # Safety
///
/// `buffer` is the empty value or one this crate returned, unchanged and not
/// yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_buffer_free(buffer: OneironBuffer) -> OneironStatus {
    ffi_guard(|| free_vec(buffer.ptr, buffer.len, buffer.cap))
}

/// Free a Rust-owned edge array returned by this crate.
///
/// # Safety
///
/// `array` is the empty value or one this crate returned, unchanged and not
/// yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_edge_info_array_free(
    array: OneironEdgeInfoArray,
) -> OneironStatus {
    ffi_guard(|| free_vec(array.ptr, array.len, array.cap))
}

/// Free a Rust-owned scored entity array returned by this crate.
///
/// # Safety
///
/// `array` is the empty value or one this crate returned, unchanged and not
/// yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_scored_entity_array_free(
    array: OneironScoredEntityArray,
) -> OneironStatus {
    ffi_guard(|| free_vec(array.ptr, array.len, array.cap))
}

/// Free a Rust-owned subtree entry array returned by this crate.
///
/// # Safety
///
/// `array` is the empty value or one this crate returned, unchanged and not
/// yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_subtree_entry_array_free(
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
///
/// `device_class` is what kind of machine this install is, as the host
/// declares it (FIX 3833): 0 a computer, the generic default, 1 a phone; any
/// other value is `InvalidArg`. It is set before the vault opens, so the
/// install enrols as it, and it is never read off the operating system.
///
/// # Safety
///
/// `path_ptr` covers `path_len` readable bytes. A non-null
/// `dict_search_paths` covers `dict_search_paths_len` slices, each covering
/// its own readable bytes. A non-null `out_vault` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_vault_open(
    path_ptr: *const u8,
    path_len: usize,
    dimensions: usize,
    dict_search_paths: *const OneironByteSlice,
    dict_search_paths_len: usize,
    device_class: u8,
    out_vault: *mut *mut OneironVault,
) -> OneironStatus {
    ffi_guard(|| {
        write_out(out_vault, ptr::null_mut()).map_or_else(
            |status| status,
            |_| {
                let result = (|| {
                    let (path, config) = device_open_config(
                        path_ptr,
                        path_len,
                        dimensions,
                        dict_search_paths,
                        dict_search_paths_len,
                        device_class,
                    )?;
                    let dimensions = config.dimensions;
                    // Crash output never carries world text: the engine's hook goes in before
                    // any vault opens (owner ruling 2026-10-14, fix 6).
                    oneiron::panic_report::install_panic_hook();
                    let vault = engine(Vault::open(&path, config))?;
                    // Signing doors (delete receipts) need this install's keys from the keystore.
                    vault.install_default_keystore(std::path::Path::new(&path));
                    let handle =
                        Box::into_raw(Box::new(OneironVault::unbound(Arc::new(vault), dimensions)));
                    write_out(out_vault, handle)?;
                    Ok(())
                })();
                result.map_or_else(|status| status, |()| OneironStatus::Ok)
            },
        )
    })
}

/// The path and `VaultConfig::device()` config an open names, checked: the
/// path is UTF-8, `dimensions == 0` keeps the preset's, every dictionary
/// search path is UTF-8, and `device_class` is one [`host_device_class`]
/// reads.
pub(super) fn device_open_config(
    path_ptr: *const u8,
    path_len: usize,
    dimensions: usize,
    dict_search_paths: *const OneironByteSlice,
    dict_search_paths_len: usize,
    device_class: u8,
) -> Result<(String, VaultConfig), OneironStatus> {
    let path = string_from_required(path_ptr, path_len)?;
    let mut config = VaultConfig::device();
    config.machine_device_class = host_device_class(device_class)?;
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
                        .map(|value| string_from_required(value.ptr, value.len).map(PathBuf::from))
                        .collect()
                },
            )
        })?;
    Ok((path, config))
}

/// The class a host declares on a raw open (FIX 3833; CALLS:
/// HOST_OPEN_DEVICE_CLASS = ExplicitHostInput): 0 a computer, the generic
/// default, 1 a phone.
fn host_device_class(device_class: u8) -> Result<MachineDeviceClass, OneironStatus> {
    match device_class {
        0 => Ok(MachineDeviceClass::Computer),
        1 => Ok(MachineDeviceClass::Phone),
        _ => Err(OneironStatus::InvalidArg),
    }
}

/// Open a NEW handle over `vault`'s same open vault whose writes run as one
/// caller (OF-063): the principal `actor_key` names, inside the off-record
/// session `session` names. `vault` itself is unchanged, and the path is
/// never opened again.
///
/// `actor_key` is UTF-8 `human:<ref>`, `agent:<ref>` or `system:<ref>`; the
/// named entity must exist and its stored type admit the class. Pass a null
/// pointer with length 0 to bind the embedded owner instead, as an embedded
/// facade client does. `session` is the UTF-8 off-record session reference;
/// pass a null pointer with length 0 to bind none, so the handle writes
/// outside any session. Binding a bound handle binds the new handle to the
/// caller named here alone.
///
/// The bound handle's puts, batch puts, edges and vectors commit as that
/// caller, below owner grade, once the write's own transaction proves the
/// actor and a shared vault's content-write grant. Its delete runs the
/// `vault.delete` door: owner-only, and an id naming no record is refused
/// `NotFound` with a refusal receipt, which an anonymous off-record session
/// the actor is verified in does not keep. A refusal is `InvalidArg`,
/// `NotFound` or `EngineError`. Reads are the same on every handle.
///
/// On success `out_vault` receives a handle to release with
/// `oneiron_vault_free` exactly once; it keeps the vault open.
///
/// # Safety
///
/// `vault` is null or a live handle from `oneiron_vault_open`,
/// `oneiron_engine_vault` or `oneiron_vault_bind`, not freed during the call.
/// Each non-null input pointer covers its length in readable bytes, and a
/// non-null `out_vault` is writable, for the whole call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_vault_bind(
    vault: *mut OneironVault,
    actor_key_ptr: *const u8,
    actor_key_len: usize,
    session_ptr: *const u8,
    session_len: usize,
    out_vault: *mut *mut OneironVault,
) -> OneironStatus {
    ffi_guard(|| {
        if let Err(status) = write_out(out_vault, ptr::null_mut()) {
            return status;
        }
        let result = with_vault(vault, |handle| {
            let actor_key = string_from_optional(actor_key_ptr, actor_key_len)?;
            let session = string_from_optional(session_ptr, session_len)?
                .map(|session| session.trim().to_owned());
            if session.as_deref().is_some_and(str::is_empty) {
                return Err(OneironStatus::InvalidArg);
            }
            let (actor, actor_class) = match actor_key.as_deref() {
                Some(key) => memory_result(parse_actor_key(&handle.vault, key))?,
                None => (
                    memory_result(handle.vault.ensure_embedded_owner_actor())?,
                    EdgeActorClass::Human,
                ),
            };
            let bound = OneironVault {
                vault: Arc::clone(&handle.vault),
                dimensions: handle.dimensions,
                binding: Some(VaultBinding {
                    actor,
                    actor_class,
                    session,
                }),
            };
            write_out(out_vault, Box::into_raw(Box::new(bound)))
        });
        result.map_or_else(|status| status, |()| OneironStatus::Ok)
    })
}

/// Free an opaque vault handle returned by `oneiron_vault_open`.
///
/// # Safety
///
/// `vault` is null or a live handle from `oneiron_vault_open` that no other
/// call is using and that is never used again.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_vault_free(vault: *mut OneironVault) -> OneironStatus {
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
///
/// # Safety
///
/// `vault` is null or a live handle from `oneiron_vault_open`, not freed
/// during the call. Each non-null input pointer covers its length in readable
/// values and each non-null out pointer is writable, for the whole call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_vault_health_json(
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

/// Store an entity blob. A bound handle stores it as its caller
/// (`oneiron_vault_bind`).
///
/// # Safety
///
/// `vault` is null or a live handle from `oneiron_vault_open`, not freed
/// during the call. Each non-null input pointer covers its length in readable
/// values and each non-null out pointer is writable, for the whole call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_vault_put_entity(
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
            let occurred = TimeRange {
                start: ts_to_u64(occurred_start),
                end: ts_to_u64(occurred_end),
            };
            let learned_at = ts_to_u64(learned_at);
            with_required_slice(data_ptr, data_len, |data| match handle.bound_memory() {
                Some(memory) => memory_result(memory.raw_put_entity(RawEntityPut {
                    id,
                    entity_type,
                    occurred,
                    learned_at,
                    data,
                })),
                None => {
                    engine(
                        handle
                            .vault
                            .put_entity(&id, entity_type, occurred, learned_at, data),
                    )
                }
            })
        });
        result.map_or_else(|status| status, |()| OneironStatus::Ok)
    })
}

/// Store multiple entity blobs in one vault transaction.
///
/// `entities` may be null only when `entities_len == 0`. Each payload pointer
/// inside the array must be non-null for its byte length. A bound handle
/// stores them as its caller (`oneiron_vault_bind`).
///
/// # Safety
///
/// `vault` is null or a live handle from `oneiron_vault_open`, not freed
/// during the call. A non-null `entities` covers `entities_len` inputs, and
/// each input's `data` covers its own readable bytes, for the whole call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_vault_batch_put_entities(
    vault: *mut OneironVault,
    entities: *const OneironEntityInput,
    entities_len: usize,
) -> OneironStatus {
    ffi_guard(|| {
        let result = with_vault(vault, |handle| {
            with_optional_slice(entities, entities_len, |values| {
                let mut parsed = Vec::new();
                for entry in values.unwrap_or(&[]) {
                    let id =
                        EntityId::from_bytes(entry.id).map_err(|_| OneironStatus::InvalidArg)?;
                    let entity_type = parse_u8(entry.entity_type)?;
                    let data = with_required_slice(entry.data.ptr, entry.data.len, |data| {
                        Ok(data.to_vec())
                    })?;
                    let occurred = TimeRange {
                        start: ts_to_u64(entry.occurred_start),
                        end: ts_to_u64(entry.occurred_end),
                    };
                    parsed.push((id, entity_type, occurred, ts_to_u64(entry.learned_at), data));
                }
                if let Some(memory) = handle.bound_memory() {
                    let puts: Vec<RawEntityPut<'_>> = parsed
                        .iter()
                        .map(
                            |(id, entity_type, occurred, learned_at, data)| RawEntityPut {
                                id: *id,
                                entity_type: *entity_type,
                                occurred: *occurred,
                                learned_at: *learned_at,
                                data,
                            },
                        )
                        .collect();
                    return memory_result(memory.raw_put_entities(&puts));
                }
                let mut batch = handle.vault.batch();
                for (id, entity_type, occurred, learned_at, data) in &parsed {
                    batch = batch.put(id, *entity_type, *occurred, *learned_at, data);
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
///
/// # Safety
///
/// `vault` is null or a live handle from `oneiron_vault_open`, not freed
/// during the call. Each non-null input pointer covers its length in readable
/// values and each non-null out pointer is writable, for the whole call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_vault_get_entity(
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
/// `out_existed` receives `1` if the entity existed and `0` otherwise. A
/// bound handle deletes as its caller through the `vault.delete` door
/// (`oneiron_vault_bind`), so an id naming no record is `NotFound`.
///
/// # Safety
///
/// `vault` is null or a live handle from `oneiron_vault_open`, not freed
/// during the call. Each non-null input pointer covers its length in readable
/// values and each non-null out pointer is writable, for the whole call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_vault_delete_entity(
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
            let existed = match handle.bound_memory() {
                Some(memory) => memory_result(memory.raw_delete_entity(&id))?,
                None => engine(handle.vault.delete_entity(&id))?,
            };
            write_out(out_existed, u8::from(existed))
        });
        result.map_or_else(|status| status, |()| OneironStatus::Ok)
    })
}

/// Check whether an entity exists.
///
/// `out_exists` receives `1` if the entity exists and `0` otherwise.
///
/// # Safety
///
/// `vault` is null or a live handle from `oneiron_vault_open`, not freed
/// during the call. Each non-null input pointer covers its length in readable
/// values and each non-null out pointer is writable, for the whole call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn oneiron_vault_entity_exists(
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
