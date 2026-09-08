//! Inline ABI tests: layout stability, round-trips, batch/boundary.

use super::*;
use std::mem::{align_of, offset_of, size_of};

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
fn ffi_struct_layouts_are_c_abi_stable() {
    assert_eq!(size_of::<OneironByteSlice>(), 16);
    assert_eq!(align_of::<OneironByteSlice>(), align_of::<usize>());
    assert_eq!(offset_of!(OneironByteSlice, ptr), 0);
    assert_eq!(offset_of!(OneironByteSlice, len), 8);

    assert_eq!(size_of::<OneironBuffer>(), 24);
    assert_eq!(align_of::<OneironBuffer>(), align_of::<usize>());
    assert_eq!(offset_of!(OneironBuffer, ptr), 0);
    assert_eq!(offset_of!(OneironBuffer, len), 8);
    assert_eq!(offset_of!(OneironBuffer, cap), 16);

    assert_eq!(size_of::<OneironEntityInput>(), 64);
    assert_eq!(align_of::<OneironEntityInput>(), 8);
    assert_eq!(offset_of!(OneironEntityInput, id), 0);
    assert_eq!(offset_of!(OneironEntityInput, entity_type), 16);
    assert_eq!(offset_of!(OneironEntityInput, occurred_start), 24);
    assert_eq!(offset_of!(OneironEntityInput, occurred_end), 32);
    assert_eq!(offset_of!(OneironEntityInput, learned_at), 40);
    assert_eq!(offset_of!(OneironEntityInput, data), 48);

    assert_eq!(size_of::<OneironEdgeInfo>(), 88);
    assert_eq!(align_of::<OneironEdgeInfo>(), 8);
    assert_eq!(offset_of!(OneironEdgeInfo, src), 0);
    assert_eq!(offset_of!(OneironEdgeInfo, kind), 16);
    assert_eq!(offset_of!(OneironEdgeInfo, tgt), 20);
    assert_eq!(offset_of!(OneironEdgeInfo, weight), 40);
    assert_eq!(offset_of!(OneironEdgeInfo, created_at), 48);
    assert_eq!(offset_of!(OneironEdgeInfo, has_vad), 56);
    assert_eq!(offset_of!(OneironEdgeInfo, valence), 64);
    assert_eq!(offset_of!(OneironEdgeInfo, arousal), 72);
    assert_eq!(offset_of!(OneironEdgeInfo, dominance), 80);

    assert_eq!(size_of::<OneironScoredEntity>(), 24);
    assert_eq!(align_of::<OneironScoredEntity>(), 8);
    assert_eq!(offset_of!(OneironScoredEntity, id), 0);
    assert_eq!(offset_of!(OneironScoredEntity, score), 16);

    assert_eq!(size_of::<OneironSubtreeEntry>(), 20);
    assert_eq!(align_of::<OneironSubtreeEntry>(), 4);
    assert_eq!(offset_of!(OneironSubtreeEntry, id), 0);
    assert_eq!(offset_of!(OneironSubtreeEntry, depth), 16);

    assert_eq!(size_of::<OneironEdgeInfoArray>(), 24);
    assert_eq!(size_of::<OneironScoredEntityArray>(), 24);
    assert_eq!(size_of::<OneironSubtreeEntryArray>(), 24);
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

    let mut health = OneironBuffer::empty();
    assert_eq!(
        oneiron_vault_health_json(vault, &mut health),
        OneironStatus::Ok
    );
    // SAFETY: `health` was returned by this crate and is live until freed.
    let health_bytes = unsafe { slice::from_raw_parts(health.ptr, health.len) };
    let health_json: serde_json::Value = serde_json::from_slice(health_bytes).expect("health JSON");
    assert_eq!(
        health_json["storage_abi_version"].as_u64(),
        Some(u64::from(oneiron::store::STORAGE_ABI_VERSION))
    );
    assert!(health_json.get("db_manifest").is_some());
    assert_eq!(oneiron_buffer_free(health), OneironStatus::Ok);

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
        oneiron_vault_entity_exists(ptr::null_mut(), entity.as_ptr(), entity.len(), &mut exists),
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
