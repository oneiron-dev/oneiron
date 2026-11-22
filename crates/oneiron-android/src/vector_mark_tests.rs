//! ARCH-0036 device mark (owner ruling EMBED-DEVICE = A, census L9-28;
//! FIX [ANDROID-PUT-VECTOR-NO-DEVICE-MARK]): a vector the Kotlin host puts
//! carries the device and runtime that computed it, as the C, N-API and Swift
//! puts do, so `oneiron doctor` names them instead of `unknown`. A malformed
//! mark is refused and stores nothing; an unmarked put drops the mark of the
//! vector it replaces.
//!
//! The open names the vault's embedding model (ruling
//! L9-28-HOST-EMBEDDING-MODEL = A): one that names none still refuses every
//! vector put with the engine's typed reason, and a malformed id opens
//! nothing.
//!
//! These run below the JNI boundary, on the native vault the hooks call.
//! Run: `cargo test --locked -p oneiron-android --lib vector_mark_tests`.

use oneiron::EntityId;
use oneiron::authority::MachineDeviceClass;
use oneiron::embed::{EmbeddingDevice, EmbeddingProvenance};

use super::{NativeVault, vector_mark};

/// The embedding model the host names when it opens the vault.
const MODEL: &str = "test/model@v1";
/// The engine's reason for a vector put on a vault that names no model.
const NO_MODEL_REASON: &str = "embedding model is required before writing vectors";

/// The Kotlin open, naming `model`.
fn open(path: &str, model: Option<&str>) -> Result<NativeVault, String> {
    NativeVault::open(
        path,
        MachineDeviceClass::Phone,
        None,
        None,
        model.map(str::to_owned),
    )
}

/// The hex id of a fresh entity.
fn fresh_id() -> String {
    EntityId::now().to_hex()
}

/// Puts `id` as a conversation (kind 4) whose body is the MessagePack map
/// `{"title": "mark"}`, as the README's example does.
fn put_entity(vault: &NativeVault, id: &str) {
    let body = [
        0x81, 0xa5, b't', b'i', b't', b'l', b'e', 0xa4, b'm', b'a', b'r', b'k',
    ];
    vault.put(id, 4, 1, &body).expect("put the vector's entity");
}

/// A vector of the vault's own width.
fn vector(vault: &NativeVault, seed: f32) -> Vec<f32> {
    let width = vault.vault.embedding_dimensions();
    (0..width)
        .map(|index| seed + index as f32 / 1000.0)
        .collect()
}

/// The host's mark, as `putVectorNative` reads it off `VectorProvenance`.
fn mark(device: &str, runtime: &str) -> Result<Option<EmbeddingProvenance>, String> {
    vector_mark(Some(device.to_owned()), Some(runtime.to_owned()))
}

fn provenance(vault: &NativeVault, id: &str) -> Option<EmbeddingProvenance> {
    vault
        .vault
        .embedding_provenance(&EntityId::from_hex(id).expect("hex id"))
        .expect("read the vector's device mark")
}

#[test]
fn a_vector_put_through_the_android_entry_keeps_its_device_mark() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().to_str().expect("utf8 temp path");
    let vault = open(path, Some(MODEL)).expect("open naming the host's model");
    let marked = fresh_id();
    let replaced = fresh_id();
    for id in [&marked, &replaced] {
        put_entity(&vault, id);
    }

    let metal = mark("metal", "host-embedder 2.1 q8").expect("a storable mark");
    vault
        .put_vector(&marked, &vector(&vault, 0.1), metal)
        .expect("a marked put");
    let cpu = mark("cpu", "host-embedder 2.1").expect("a storable mark");
    vault
        .put_vector(&replaced, &vector(&vault, 0.2), cpu)
        .expect("a marked put");
    // An unmarked put never keeps the mark of the vector it replaces.
    vault
        .put_vector(&replaced, &vector(&vault, 0.3), None)
        .expect("an unmarked put");

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
}

#[test]
fn a_mark_the_engine_cannot_store_is_refused() {
    // An unknown family, a control character, an empty runtime, a runtime
    // past 128 bytes, and half a mark.
    let long_runtime = "r".repeat(129);
    for (device, runtime) in [
        (Some("gpu"), Some("host-embedder 2.1")),
        (Some("cpu"), Some("host\nembedder")),
        (Some("cpu"), Some("")),
        (Some("cpu"), Some(long_runtime.as_str())),
        (Some("cpu"), None),
        (None, Some("host-embedder 2.1")),
    ] {
        let refused = vector_mark(device.map(str::to_owned), runtime.map(str::to_owned));
        assert!(
            refused
                .as_ref()
                .is_err_and(|reason| reason.starts_with("provenance: ")),
            "device {device:?}, runtime {runtime:?}: {refused:?}"
        );
    }
    assert_eq!(vector_mark(None, None), Ok(None));
}

#[test]
fn a_bound_vault_puts_its_vector_with_the_device_mark() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().to_str().expect("utf8 temp path");
    let host = open(path, Some(MODEL)).expect("open naming the host's model");
    let entity = fresh_id();
    put_entity(&host, &entity);
    let owner = host.bound(None, None).expect("bind the embedded owner");

    let cuda = mark("cuda", "host-embedder 3.0").expect("a storable mark");
    owner
        .put_vector(&entity, &vector(&owner, 0.4), cuda)
        .expect("the owner's marked put");

    assert_eq!(
        provenance(&host, &entity),
        Some(EmbeddingProvenance::new(
            EmbeddingDevice::Cuda,
            "host-embedder 3.0"
        ))
    );
}

#[test]
fn an_android_open_without_a_model_refuses_every_vector_put() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().to_str().expect("utf8 temp path");
    let vault = open(path, None).expect("open naming no model");
    let entity = fresh_id();
    put_entity(&vault, &entity);

    let metal = mark("metal", "host-embedder 2.1 q8").expect("a storable mark");
    for refused in [
        vault.put_vector(&entity, &vector(&vault, 0.1), None),
        vault.put_vector(&entity, &vector(&vault, 0.1), metal),
    ] {
        assert!(
            refused
                .as_ref()
                .is_err_and(|reason| reason.contains(NO_MODEL_REASON)),
            "{refused:?}"
        );
    }
    assert_eq!(provenance(&vault, &entity), None);
}

#[test]
fn an_android_open_refuses_a_malformed_model_and_keeps_the_first_one() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().to_str().expect("utf8 temp path");

    // A malformed id opens nothing: not `org/name@revision`, or empty.
    for model in ["test-model", "test/model", "test@model/v1", ""] {
        assert!(open(path, Some(model)).is_err(), "{model:?}");
    }

    let entity = fresh_id();
    let vault = open(path, Some(MODEL)).expect("open naming the host's model");
    put_entity(&vault, &entity);
    let cpu = mark("cpu", "host-embedder 2.1").expect("a storable mark");
    vault
        .put_vector(&entity, &vector(&vault, 0.5), cpu)
        .expect("a marked put");
    drop(vault);

    // The vault keeps the first model an open named.
    assert!(open(path, Some("test/other-model@v1")).is_err());
    let vault = open(path, Some(MODEL)).expect("reopen naming the same model");
    assert_eq!(
        provenance(&vault, &entity),
        Some(EmbeddingProvenance::new(
            EmbeddingDevice::Cpu,
            "host-embedder 2.1"
        ))
    );
}
