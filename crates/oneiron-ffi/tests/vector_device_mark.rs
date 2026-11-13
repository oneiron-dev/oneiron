//! ARCH-0036 device mark (owner ruling EMBED-DEVICE = A, census L9-28): a
//! vector a host puts through the C entry carries the device and runtime that
//! computed it, as the engine's own embedder paths do, so `oneiron doctor`
//! names them instead of `unknown`. A malformed mark is refused and stores
//! nothing; an unmarked put drops the mark of the vector it replaces.
//!
//! Run: `cargo test --locked -p oneiron-ffi --test vector_device_mark`.

use std::ptr;

use oneiron::authority::MachineDeviceClass;
use oneiron::embed::{EmbeddingDevice, EmbeddingProvenance};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_ffi::{
    OneironStatus, OneironVault, oneiron_vault_free, oneiron_vault_open, oneiron_vault_put_entity,
    oneiron_vault_put_vector, oneiron_vault_put_vector_with_provenance,
};

const DIMENSIONS: usize = 4;
const VECTOR: [f64; DIMENSIONS] = [0.1, 0.2, 0.3, 0.4];

fn id(seed: u8) -> [u8; 16] {
    let mut id = [0_u8; 16];
    for (offset, byte) in id.iter_mut().enumerate() {
        *byte = seed.wrapping_add(offset as u8);
    }
    id
}

fn open(path: &str) -> *mut OneironVault {
    let mut vault = ptr::null_mut();
    // SAFETY: `path` and `vault` are live locals that outlive the call.
    let status = unsafe {
        oneiron_vault_open(
            path.as_ptr(),
            path.len(),
            DIMENSIONS,
            ptr::null(),
            0,
            0,
            &mut vault,
        )
    };
    assert_eq!(status, OneironStatus::Ok);
    assert!(!vault.is_null());
    vault
}

fn put_entity(vault: *mut OneironVault, entity: &[u8; 16]) {
    let payload = b"device-mark-entity";
    // SAFETY: `vault` is live and every pointer names a local that outlives the call.
    let status = unsafe {
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
        )
    };
    assert_eq!(status, OneironStatus::Ok);
}

fn put_marked(
    vault: *mut OneironVault,
    entity: &[u8; 16],
    device: &str,
    runtime: &str,
) -> OneironStatus {
    // SAFETY: `vault` is live and every pointer names a local that outlives the call.
    unsafe {
        oneiron_vault_put_vector_with_provenance(
            vault,
            entity.as_ptr(),
            entity.len(),
            VECTOR.as_ptr(),
            VECTOR.len(),
            device.as_ptr(),
            device.len(),
            runtime.as_ptr(),
            runtime.len(),
        )
    }
}

fn put_unmarked(vault: *mut OneironVault, entity: &[u8; 16]) -> OneironStatus {
    // SAFETY: `vault` is live and every pointer names a local that outlives the call.
    unsafe {
        oneiron_vault_put_vector(
            vault,
            entity.as_ptr(),
            entity.len(),
            VECTOR.as_ptr(),
            VECTOR.len(),
        )
    }
}

/// The same vault, opened in Rust with the config the C open uses.
fn reopen(path: &str) -> Vault {
    let mut config = VaultConfig::device();
    config.dimensions = DIMENSIONS;
    config.machine_device_class = MachineDeviceClass::Computer;
    Vault::open(path, config).expect("reopen the vault the C entry wrote")
}

fn provenance(vault: &Vault, entity: &[u8; 16]) -> Option<EmbeddingProvenance> {
    vault
        .embedding_provenance(&EntityId::from_bytes(*entity).expect("entity id"))
        .expect("read the vector's device mark")
}

#[test]
fn a_vector_put_through_the_c_entry_keeps_its_device_mark() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().to_str().expect("utf8 temp path");
    let marked = id(1);
    let replaced = id(40);
    let bad_device = id(80);
    let bad_runtime = id(120);
    let empty_runtime = id(160);
    let engine_marked = id(200);

    let vault = open(path);
    for entity in [
        &marked,
        &replaced,
        &bad_device,
        &bad_runtime,
        &empty_runtime,
        &engine_marked,
    ] {
        put_entity(vault, entity);
    }
    assert_eq!(
        put_marked(vault, &marked, "metal", "host-embedder 2.1 q8"),
        OneironStatus::Ok
    );
    assert_eq!(
        put_marked(vault, &replaced, "cpu", "host-embedder 2.1"),
        OneironStatus::Ok
    );
    // An unmarked put never keeps the mark of the vector it replaces.
    assert_eq!(put_unmarked(vault, &replaced), OneironStatus::Ok);
    // A mark the engine cannot store is refused, and nothing is stored.
    assert_eq!(
        put_marked(vault, &bad_device, "gpu", "host-embedder 2.1"),
        OneironStatus::InvalidArg
    );
    assert_eq!(
        put_marked(vault, &bad_runtime, "cpu", "host\nembedder"),
        OneironStatus::InvalidArg
    );
    assert_eq!(
        put_marked(vault, &empty_runtime, "cpu", ""),
        OneironStatus::InvalidArg
    );
    // SAFETY: `vault` is the live handle opened above, freed once.
    assert_eq!(unsafe { oneiron_vault_free(vault) }, OneironStatus::Ok);

    let vault = reopen(path);
    assert_eq!(
        provenance(&vault, &marked),
        Some(EmbeddingProvenance::new(
            EmbeddingDevice::Metal,
            "host-embedder 2.1 q8"
        ))
    );
    assert_eq!(
        provenance(&vault, &replaced),
        Some(EmbeddingProvenance::unknown())
    );
    assert_eq!(provenance(&vault, &bad_device), None);
    assert_eq!(provenance(&vault, &bad_runtime), None);
    assert_eq!(provenance(&vault, &empty_runtime), None);

    // The engine door the C entry calls marks a vector the same way.
    let engine_marked = EntityId::from_bytes(engine_marked).expect("entity id");
    vault
        .put_vector_with_provenance(
            &engine_marked,
            &[0.4, 0.3, 0.2, 0.1],
            EmbeddingProvenance::new(EmbeddingDevice::Cuda, "host-embedder 3.0"),
        )
        .expect("put a marked vector through the engine door");
    assert_eq!(
        vault
            .embedding_provenance(&engine_marked)
            .expect("read the engine door's mark"),
        Some(EmbeddingProvenance::new(
            EmbeddingDevice::Cuda,
            "host-embedder 3.0"
        ))
    );
}
