//! UC-02 B1b: the engine stamps an omitted `occurred_at`.
//!
//! The six write inputs (`WitnessTurn`, `StructuralPutInput`,
//! `HabitCheckinInput`, `AdmitImportedClaimInput`, `BlobArtifactInput`,
//! `AppendBlobVersionRequest`) take `occurred_at: Option<u64>`. An omitted
//! time is the vault's recording clock, read once in the write
//! (UC-02-OCCURRED-AT-CLOCK = A, U2-A1), never the wall clock and never a
//! binding's stamp.
//!
//! The vault here runs on a manual recording clock set weeks before the wall
//! clock, so a stamp equal to it can only come from the recording clock.
//! Each write goes through the generic invoke
//! (`oneiron::task_verb::sdk::invoke`), as every door calls it.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test engine_stamped_occurred_at`
#![cfg(feature = "test-support")]

use std::sync::Arc;

use oneiron::memory::{
    AdmitImportedClaimInput, BlobArtifactInput, EntityView, HabitCheckinInput, Memory,
    StructuralPutInput, WitnessTurn,
};
use oneiron::task_verb::sdk::{AppendBlobVersionRequest, invoke};
use oneiron::test_support::{bind_host_owner, provision_engine_machines, test_host_issuer};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

/// The vault's recording clock: the time other fixtures root their vaults at,
/// weeks before any wall clock this test runs under.
const RECORDED: u64 = 1_790_000_000;

fn vault_on_recording_clock() -> (tempfile::TempDir, Arc<ManualClock>, Vault) {
    let wall = oneiron_base::unix_seconds_now();
    assert!(
        wall > RECORDED + 60,
        "the wall clock {wall} must stand apart from the recording clock {RECORDED}"
    );
    let directory = tempfile::tempdir().expect("temporary vault");
    let clock = ManualClock::new(RECORDED);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(directory.path(), config).expect("fresh vault");
    provision_engine_machines(&vault);
    let owner = vault.ensure_embedded_owner_actor().expect("owner PERSON");
    bind_host_owner(&vault, &test_host_issuer(), owner).expect("owner host binding");
    (directory, clock, vault)
}

fn owner_memory(vault: &Vault) -> Memory<'_> {
    let owner = vault.ensure_embedded_owner_actor().expect("owner PERSON");
    vault.memory(owner, EdgeActorClass::Human)
}

fn entity(memory: &Memory<'_>, entity_ref: &str) -> EntityView {
    memory
        .get_entity(entity_ref)
        .expect("entity read")
        .value
        .unwrap_or_else(|| panic!("{entity_ref} reads"))
}

fn assert_stamped(view: &EntityView, at: u64, what: &str) {
    assert_eq!(
        (view.occurred_start, view.occurred_end, view.learned_at),
        (at, at, at),
        "{what}: occurred and learned at the write's time"
    );
}

/// One fresh turn of one user message, with `occurred_at` only when given.
/// Returns the input, the TURN's ref and the MESSAGE's ref.
fn witness_input(occurred_at: Option<u64>) -> (Value, String, String) {
    let turn = EntityId::now().to_hex();
    let message = EntityId::now().to_hex();
    let mut input = json!({
        "conversation_ref": EntityId::now().to_hex(),
        "turn_ref": turn,
        "messages": [{
            "id": message,
            "author": "user",
            "message_type": "dialogue",
            "content": "hello",
            "metadata": null,
            "is_visible": true,
            "order": 0
        }]
    });
    if let Some(at) = occurred_at {
        input["occurred_at"] = json!(at);
    }
    (input, turn, message)
}

/// Decodes `input` as `T` and reads back the `occurred_at` it holds, so the
/// check compiles against either field type.
fn decoded_occurred_at<T>(input: Value, what: &str) -> Value
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    let decoded: T = serde_json::from_value(input)
        .unwrap_or_else(|error| panic!("{what} without occurred_at: {error}"));
    serde_json::to_value(&decoded).expect("re-encode")["occurred_at"].clone()
}

/// Every one of the six inputs decodes without `occurred_at`, to `None`:
/// the engine, not the door, owns the default.
#[test]
fn each_input_decodes_without_occurred_at() {
    let omitted = [
        decoded_occurred_at::<WitnessTurn>(witness_input(None).0, "WitnessTurn"),
        decoded_occurred_at::<StructuralPutInput>(
            json!({"kind": "PERSON", "body": {"name": "stamped"}}),
            "StructuralPutInput",
        ),
        decoded_occurred_at::<HabitCheckinInput>(
            json!({"habit_ref": EntityId::now().to_hex()}),
            "HabitCheckinInput",
        ),
        decoded_occurred_at::<AdmitImportedClaimInput>(
            json!({
                "source_id": "source",
                "source_record_id": "record-1",
                "subject_ref": EntityId::now().to_hex(),
                "predicate": "name",
                "value": "stamped"
            }),
            "AdmitImportedClaimInput",
        ),
        decoded_occurred_at::<BlobArtifactInput>(
            json!({"name": "notes.txt", "media_type": "text/plain"}),
            "BlobArtifactInput",
        ),
        decoded_occurred_at::<AppendBlobVersionRequest>(
            json!({"artifact_ref": EntityId::now().to_hex(), "content_base64": "aGVsbG8="}),
            "AppendBlobVersionRequest",
        ),
    ];
    assert!(omitted.iter().all(Value::is_null), "{omitted:?}");
}

/// (a) A witnessed turn without `occurred_at` lands, its TURN and MESSAGE
/// stamped at the recording clock; a stated time is kept as given.
#[test]
fn an_omitted_witness_time_is_the_recording_clock() {
    let (_directory, clock, vault) = vault_on_recording_clock();
    let memory = owner_memory(&vault);
    let (input, turn, message) = witness_input(None);
    invoke(&memory, "vault.witness", input).expect("a turn without occurred_at is witnessed");
    assert_stamped(&entity(&memory, &turn), RECORDED, "TURN");
    assert_stamped(&entity(&memory, &message), RECORDED, "MESSAGE");

    clock.set(RECORDED + 600);
    let stated = RECORDED - 3_600;
    let (input, turn, message) = witness_input(Some(stated));
    invoke(&memory, "vault.witness", input).expect("a turn with occurred_at is witnessed");
    assert_stamped(&entity(&memory, &turn), stated, "stated TURN");
    assert_stamped(&entity(&memory, &message), stated, "stated MESSAGE");
}

/// (a) A structural put without `occurred_at` lands at the recording clock,
/// and its learned time follows it.
#[test]
fn an_omitted_structural_put_time_is_the_recording_clock() {
    let (_directory, _clock, vault) = vault_on_recording_clock();
    let memory = owner_memory(&vault);
    let receipt = invoke(
        &memory,
        "vault.structural.put",
        json!({"kind": "PERSON", "body": {"name": "stamped"}}),
    )
    .expect("a structural put without occurred_at lands");
    let id = receipt["id_hex"].as_str().expect("receipt id");
    assert_stamped(&entity(&memory, id), RECORDED, "PERSON");
}

/// A blob artifact and its first version land without `occurred_at`; the
/// artifact is stamped at the recording clock.
#[test]
fn an_omitted_blob_time_is_the_recording_clock() {
    let (_directory, _clock, vault) = vault_on_recording_clock();
    let memory = owner_memory(&vault);
    let receipt = invoke(
        &memory,
        "vault.artifacts.put",
        json!({"name": "notes.txt", "media_type": "text/plain"}),
    )
    .expect("an artifact without occurred_at registers");
    let id = receipt["id_hex"].as_str().expect("receipt id").to_owned();
    assert_stamped(&entity(&memory, &id), RECORDED, "BLOB_ARTIFACT");
    invoke(
        &memory,
        "vault.artifacts.append",
        json!({"artifact_ref": id, "content_base64": "aGVsbG8="}),
    )
    .expect("a version without occurred_at appends");
}
