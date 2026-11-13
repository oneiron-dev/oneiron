//! A context pack read through the in-process read adapter, the one MCP's
//! `memory.context_pack` reads through, in the live stretch its host binds
//! (FIX ROOM-PACK-IN-PROCESS-ADAPTER-READS-BASE; ARCH-0052
//! #e5-read-union-open, ONE-1729: "a route that takes a room's turn should
//! bind the pack too").
//!
//! The owner witnesses one turn into a live stretch, so its MESSAGE is staged
//! in the stretch's overlay and is in no base row. The adapter given the
//! stretch's read, bound for the owner as the accepted route binds it,
//! returns that MESSAGE and registers its retrieval run through the stretch,
//! never in base. The same adapter given no stretch reads base alone.
//!
//! Deterministic: in-process vault, no models, no network.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron --all-features --test stretch_context_pack_adapter`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::claim::ScopedReadActorKey;
use oneiron::code_run::vault_read::{
    CoreContextPackRequest, CoreContextPackResponse, InProcessVaultReadAdapter, VaultReadClient,
};
use oneiron::edge::EdgeActorClass;
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessReceipt, WitnessTurn};
use oneiron::off_record::OffRecordBackendClass;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EntityId, Vault, VaultConfig};
use serde_json::{Value, json};

/// The live stretch the owner's turn is staged in.
const STRETCH: &str = "adapter-pack-stretch";
/// The one word the staged MESSAGE holds, which no base row holds.
const STAGED_WORD: &str = "lanternfish";
/// The engine's thread stack, as the server runs its engine work on.
const ENGINE_STACK_BYTES: usize = 32 * 1024 * 1024;

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    owner_key: ScopedReadActorKey,
    /// The short id of the MESSAGE the owner's turn staged in the stretch.
    staged_message: String,
}

/// A rooted, profiled vault that keeps its retrieval runs, with a live
/// stretch holding one turn the owner witnessed into it.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let mut config = VaultConfig::device();
    config.embedding_model = None;
    config.dimensions = 4;
    config.retrieval_telemetry_capture = true;
    let vault = Vault::open(dir.path(), config).expect("open vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let (owner, owner_proof) = embedded_owner(&vault).expect("authenticated embedded owner");
    let owner_key = vault
        .owner_proof_read_key(&owner_proof)
        .expect("the owner's read key");

    let stretch = vault
        .off_record_session_vault()
        .enter(STRETCH, OffRecordBackendClass::Local)
        .expect("enter the stretch");
    let receipt = vault
        .memory(owner, EdgeActorClass::Human)
        .witness_into_session(
            &stretch,
            &owner_turn(format!("the stretch says {STAGED_WORD}"), 900),
            None,
            None,
        )
        .expect("the owner's turn in the stretch");
    let staged_message = first_message(&receipt);
    drop(stretch);
    Fixture {
        _dir: dir,
        vault,
        owner,
        owner_key,
        staged_message,
    }
}

/// The owner's one-message turn saying `content` at `occurred_at`.
fn owner_turn(content: String, occurred_at: u64) -> WitnessTurn {
    WitnessTurn {
        conversation_ref: String::new(),
        turn_ref: None,
        thread_audience: None,
        messages: vec![WitnessMessage {
            id: None,
            author: WitnessAuthor::User,
            message_type: "dialogue".to_owned(),
            content,
            metadata: None,
            is_visible: true,
            order: 0,
            parts: None,
            quote: None,
        }],
        occurred_at,
        assertions: Default::default(),
    }
}

/// The short id of the first MESSAGE a witness receipt names.
fn first_message(receipt: &WitnessReceipt) -> String {
    receipt
        .message_short_ids
        .first()
        .and_then(|short| short.split(':').next())
        .expect("the turn's MESSAGE")
        .to_owned()
}

/// A pack asking for the staged word.
fn pack_request() -> CoreContextPackRequest {
    serde_json::from_value(json!({"query": STAGED_WORD, "limit": 10}))
        .expect("a context pack request")
}

/// `pack` as the JSON its caller reads.
fn answer(pack: &CoreContextPackResponse) -> Value {
    serde_json::to_value(pack).expect("a context pack answer")
}

/// Whether any object in `answer` names `short_id` as its `short_id`.
fn names_short_id(answer: &Value, short_id: &str) -> bool {
    match answer {
        Value::Object(fields) => {
            fields.get("short_id").and_then(Value::as_str) == Some(short_id)
                || fields.values().any(|value| names_short_id(value, short_id))
        }
        Value::Array(items) => items.iter().any(|value| names_short_id(value, short_id)),
        _ => false,
    }
}

/// Retrieval runs the vault keeps in base.
fn base_runs(vault: &Vault) -> usize {
    vault.retrieval_runs(64).expect("base retrieval runs").len()
}

/// Runs `test` on a thread with the engine's stack.
fn on_engine_stack(name: &str, test: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .name(name.to_owned())
        .stack_size(ENGINE_STACK_BYTES)
        .spawn(test)
        .expect("spawn the test thread")
        .join()
        .expect("the test thread passes");
}

/// The adapter given the stretch's read, bound for the owner, returns the
/// MESSAGE the stretch staged and keeps its retrieval run out of base; the
/// same adapter with no stretch reads base alone.
#[test]
fn an_adapter_pack_in_a_stretch_reads_its_staged_message() {
    on_engine_stack("adapter-stretch-pack", || {
        let fixture = fixture();
        let outside = InProcessVaultReadAdapter::new(&fixture.vault, fixture.owner_key.clone())
            .context_pack(pack_request())
            .expect("the pack outside the stretch");
        let outside = answer(&outside);
        assert!(
            !names_short_id(&outside, &fixture.staged_message),
            "outside the stretch the pack reads base alone: {outside}"
        );

        let runs_before = base_runs(&fixture.vault);
        let rooms = fixture.vault.off_record_session_vault();
        let session = rooms
            .bind_pack_reader(STRETCH, fixture.owner)
            .expect("bind the stretch for the owner")
            .expect("the owner binds their live stretch");
        let read = session.read().expect("the stretch's read");
        let inside = InProcessVaultReadAdapter::new(&fixture.vault, fixture.owner_key.clone())
            .with_room_pack(Some(&read))
            .context_pack(pack_request())
            .expect("the pack in the stretch");
        let inside = answer(&inside);
        assert!(
            names_short_id(&inside["results"], &fixture.staged_message),
            "the pack in the stretch returns its staged MESSAGE {}: {inside}",
            fixture.staged_message
        );
        assert_eq!(
            base_runs(&fixture.vault),
            runs_before,
            "the pack in the stretch registers its run through the stretch, never in base"
        );
    });
}
