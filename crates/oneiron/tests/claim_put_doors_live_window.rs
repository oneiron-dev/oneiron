//! The claim put, candidate and code-run trap doors reach a loaded window
//! live, through the write door's post-commit mirror, without waiting for the
//! window's next cold open (FIX CLAIM-RAW-TXN-DOORS-DROP-LIVE-WINDOW-ROWS).
//!
//! `Vault::put_claim`, `put_claim_candidate_with_landing*`,
//! `put_claim_candidate_with_gate_returning_actual`,
//! `supersede_claim_for_code_run_trap` and `put_edge_for_code_run_trap`
//! committed on a bare write transaction with no post-commit owner, so the
//! rows they wrote reached no loaded live window.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test claim_put_doors_live_window`.
#![cfg(all(feature = "sync", feature = "test-support", oneiron_test_support))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use loro::{LoroDoc, LoroValue, ValueOrContainer};
use oneiron::claim::decode_claim_body;
use oneiron::code_run::{
    HostSelfDispatcher, SelfCall, SelfDispatcher, SelfMemoryPutClaimCall, SelfMemoryPutEdgeCall,
    SelfMemorySupersedeClaimCall,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::sync::bridge::{Materializer, format_edge_key};
use oneiron::sync::manager::WindowManager;
use oneiron::sync::residence::residence_window_for_blob;
use oneiron::sync::window::LoadedWindow;
use oneiron::test_doors::code_run_claim_put::put_claim_as_code_run;
use oneiron::test_support::put_policy_manifest_bytes;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimCandidate, ClaimLifecycleStatus, ClaimSource,
    ClaimSubject, EdgeActorClass, EdgeKind, EntityId, TimeRange, Vault, VaultConfig, WriteActor,
};
use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;
use oneiron_keystore::MemoryKeystore;
use rmpv::Value;

/// 2026-03-15 00:00 UTC: every row is learned then, so all of them ride the
/// base window of March 2026.
const T0: u64 = 1_773_532_800;
/// The live mirror carries a committed row on its own thread: the test looks
/// every `POLL`, at most `POLLS` times (30 s of sleep), with no clock read.
const POLL: Duration = Duration::from_millis(20);
const POLLS: u32 = 1_500;

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

/// A vault with an install signer, as a host opens one.
fn open_vault(dir: &std::path::Path) -> Arc<Vault> {
    let vault = Vault::open(dir, VaultConfig::device()).expect("the vault opens");
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    Arc::new(vault)
}

/// A vault with no policy manifest yet, with an install signer: the trap
/// tests install their own `self.memory.*` policy on it.
fn open_unseeded_vault(dir: &std::path::Path) -> Arc<Vault> {
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open_unseeded_for_test(dir, config).expect("the unseeded vault opens");
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    Arc::new(vault)
}

/// A PERSON row at a fresh id, learned at `T0`.
fn person(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(&id, ENTITY_TYPE_PERSON, at(T0), T0, b"someone")
        .expect("the person");
    id
}

/// A policy manifest that lets `actor`, a human, write `self.memory.*` at
/// `ceiling` from the code run's Generated source, as the gate pin installs
/// for its owner (`tests/gate_pins_claim_producers.rs:481-530`).
fn self_memory_policy(actor: EntityId, ceiling: &str) -> Vec<u8> {
    let axes = || {
        Value::Map(vec![
            (Value::from("criticality"), Value::from("normal")),
            (Value::from("sensitivity"), Value::from("normal")),
        ])
    };
    let manifest = Value::Map(vec![
        (
            Value::from("schema_version"),
            Value::from(oneiron_store::policy_record::POLICY_SCHEMA_VERSION),
        ),
        (Value::from("pack_id"), Value::from("claim-put-doors-trap")),
        (Value::from("pack_version"), Value::from("v1")),
        (
            Value::from("min_engine_version"),
            Value::from(env!("CARGO_PKG_VERSION")),
        ),
        (Value::from("defaults"), axes()),
        (
            Value::from("rules"),
            Value::Array(vec![Value::Map(vec![
                (Value::from("prefix"), Value::from("self.memory.")),
                (Value::from("axes"), axes()),
            ])]),
        ),
        (
            Value::from("actor_ceilings"),
            Value::Array(vec![Value::Map(vec![
                (Value::from("actor_class"), Value::from("human")),
                (Value::from("actor_ref"), Value::from(actor.to_hex())),
                (Value::from("ceiling"), Value::from(ceiling)),
            ])]),
        ),
        (
            Value::from("source_trust"),
            Value::Map(vec![(
                Value::from(ClaimSource::Generated.as_str()),
                Value::Map(vec![
                    (Value::from("max_auto_sensitivity"), Value::from(2_u64)),
                    (Value::from("receipted"), Value::Boolean(true)),
                    (Value::from("warned"), Value::Boolean(true)),
                ]),
            )]),
        ),
    ]);
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &manifest).expect("the manifest encodes");
    data
}

/// The window that holds `raw`'s row, opened and kept loaded.
fn loaded_window_for(vault: &Arc<Vault>, raw: &[u8]) -> (Arc<WindowManager>, Arc<LoadedWindow>) {
    let key = residence_window_for_blob(raw).expect("the row's window");
    let manager = Arc::new(WindowManager::new(
        Arc::clone(vault),
        Arc::new(Materializer::new()),
        "owner",
    ));
    let window = manager.open_window(&key).expect("the window opens");
    (manager, window)
}

/// The bytes the window's doc carries for `id`'s row.
fn carrier(doc: &LoroDoc, id: &EntityId) -> Option<Vec<u8>> {
    match doc.get_map("entities").get(&id.to_hex())? {
        ValueOrContainer::Value(LoroValue::Binary(bytes)) => Some(bytes.to_vec()),
        _ => None,
    }
}

/// The lifecycle of the claim the window carries for `id`.
fn carried_lifecycle(doc: &LoroDoc, id: &EntityId) -> ClaimLifecycleStatus {
    let bytes = carrier(doc, id).expect("the window carries the claim");
    decode_claim_body(&bytes[ENTITY_METADATA_HEADER_LEN..], true)
        .expect("the carried claim decodes")
        .lifecycle
}

/// Waits until the window carries `id`'s row as the store holds it now.
fn wait_until_carried(vault: &Vault, window: &LoadedWindow, id: &EntityId, what: &str) {
    for _ in 0..POLLS {
        let stored = vault
            .get_raw(id)
            .expect("read the row")
            .expect("the row is stored");
        if carrier(&window.doc, id).as_deref() == Some(stored.as_slice()) {
            return;
        }
        std::thread::sleep(POLL);
    }
    panic!("after {POLLS} looks the loaded window still carries {what} as it was before the write");
}

/// Waits until the window carries the edge `edge_key`.
fn wait_until_edge(window: &LoadedWindow, edge_key: &str, what: &str) {
    for _ in 0..POLLS {
        if window.doc.get_map("edges").get(edge_key).is_some() {
            return;
        }
        std::thread::sleep(POLL);
    }
    panic!("after {POLLS} looks the loaded window still carries no {what}");
}

/// A `put_claim` about a person reaches the window that holds the person's
/// month, opened before the put. Red on main a1dc3dd3c27b: the put commits
/// on a bare transaction with no post-commit owner, so the loaded window
/// never carries the claim's row.
#[test]
fn put_claim_reaches_a_loaded_window() {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = open_vault(dir.path());
    let subject = person(&vault);
    let subject_raw = vault
        .get_raw(&subject)
        .expect("read the person")
        .expect("the person is stored");
    let (_manager, window) = loaded_window_for(&vault, &subject_raw);

    let mut body = ClaimBody::new(
        "profile.nickname",
        ClaimSubject::Entity(subject),
        Value::from("x"),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("claim body");
    body.source = Some(ClaimSource::UserStated);
    let id = EntityId::now();
    vault
        .put_claim(&id, &body, at(T0), T0)
        .expect("the owner puts the claim");
    assert_eq!(
        vault
            .get_claim(&id)
            .expect("read the claim")
            .expect("the claim is stored")
            .lifecycle,
        ClaimLifecycleStatus::Active,
        "the store holds the claim active"
    );

    wait_until_carried(&vault, &window, &id, "the put claim");
    let stored = vault
        .get_raw(&id)
        .expect("read the row")
        .expect("the row is stored");
    assert_eq!(
        carrier(&window.doc, &id).as_deref(),
        Some(stored.as_slice()),
        "the loaded window carries the claim's row bytes"
    );
}

/// A code-run candidate put's `actual` row reaches the window that holds the
/// subject's month, opened before the put. Red on main a1dc3dd3c27b: the
/// candidate door commits on a bare transaction, so the loaded window never
/// carries the `actual` row.
#[test]
fn candidate_put_actual_reaches_a_loaded_window() {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = open_vault(dir.path());
    let actor_person = person(&vault);
    let subject = person(&vault);
    let subject_raw = vault
        .get_raw(&subject)
        .expect("read the subject")
        .expect("the subject is stored");
    let (_manager, window) = loaded_window_for(&vault, &subject_raw);

    let actor = WriteActor::new(actor_person, EdgeActorClass::Human);
    let id = EntityId::now();
    let actual = put_claim_as_code_run(
        &vault,
        actor,
        id,
        "profile.nickname",
        subject,
        Value::from("x"),
        T0,
    )
    .expect("the code run puts the claim");
    assert_eq!(
        vault
            .get_claim(&actual)
            .expect("read the claim")
            .expect("the claim is stored")
            .lifecycle,
        ClaimLifecycleStatus::Active,
        "the store holds the actual claim active"
    );

    wait_until_carried(&vault, &window, &actual, "the candidate row");
    let stored = vault
        .get_raw(&actual)
        .expect("read the row")
        .expect("the row is stored");
    assert_eq!(
        carrier(&window.doc, &actual).as_deref(),
        Some(stored.as_slice()),
        "the loaded window carries the actual row bytes"
    );
}

/// The owner's code run, through the host dispatcher.
fn owner_run(vault: &Vault, owner: EntityId) -> HostSelfDispatcher<'_> {
    HostSelfDispatcher::new(
        vault,
        WriteActor::new(owner, EdgeActorClass::Human),
        "claim-put-doors-run",
    )
    .expect("the dispatcher")
}

/// A code run's supersession (`self.memory.supersede_claim`, the trap
/// `supersede_claim_for_code_run_trap`) reaches the window that carries both
/// claims: the old claim's superseded bytes and the Supersedes edge. Red on
/// main a1dc3dd3c27b: the trap commits on a bare transaction, so the loaded
/// window keeps the old claim active and carries no edge.
#[test]
fn trap_supersede_reaches_a_loaded_window() {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = open_unseeded_vault(dir.path());
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    put_policy_manifest_bytes(&vault, EntityId::now(), &self_memory_policy(owner, "auto"))
        .expect("install the policy");
    let subject = person(&vault);
    let run = owner_run(&vault, owner);
    let (old, new) = (EntityId::now(), EntityId::now());
    for (id, value) in [(old, "o"), (new, "oh")] {
        run.dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
            id,
            ClaimCandidate::new(
                "profile.nickname",
                ClaimSubject::Entity(subject),
                Value::from(value),
                0.9,
            ),
            at(T0),
            T0,
        )))
        .expect("the run's claim put");
    }
    let old_raw = vault
        .get_raw(&old)
        .expect("read the old claim")
        .expect("the old claim is stored");
    let (_manager, window) = loaded_window_for(&vault, &old_raw);
    for id in [&old, &new] {
        assert_eq!(
            carried_lifecycle(&window.doc, id),
            ClaimLifecycleStatus::Active,
            "fixture: the window carries each claim as active"
        );
    }
    let edge = format_edge_key(&new, EdgeKind::Supersedes, &old);
    assert!(
        window.doc.get_map("edges").get(&edge).is_none(),
        "fixture: no Supersedes edge before the supersession"
    );

    run.dispatch(SelfCall::MemorySupersedeClaim(
        SelfMemorySupersedeClaimCall::new(new, old, T0 + 100),
    ))
    .expect("the run supersedes the old claim");
    assert_eq!(
        vault
            .get_claim(&old)
            .expect("read the old claim")
            .expect("the old claim is stored")
            .lifecycle,
        ClaimLifecycleStatus::Superseded,
        "the store holds the old claim superseded"
    );
    assert_eq!(
        vault
            .targets(&new, EdgeKind::Supersedes, None)
            .expect("read the edge"),
        vec![old],
        "the store holds the Supersedes edge"
    );

    wait_until_carried(&vault, &window, &old, "the superseded claim");
    assert_eq!(
        carried_lifecycle(&window.doc, &old),
        ClaimLifecycleStatus::Superseded,
        "the loaded window carries the old claim superseded"
    );
    wait_until_edge(&window, &edge, "Supersedes edge");
}

/// A code run's edge put (`self.memory.put_edge`, the trap
/// `put_edge_for_code_run_trap`) reaches the window that holds its source
/// row. Red on main a1dc3dd3c27b: the trap commits on a bare transaction, so
/// the loaded window never carries the edge.
#[test]
fn trap_edge_reaches_a_loaded_window() {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = open_unseeded_vault(dir.path());
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    put_policy_manifest_bytes(&vault, EntityId::now(), &self_memory_policy(owner, "auto"))
        .expect("install the policy");
    let src = person(&vault);
    let tgt = person(&vault);
    let src_raw = vault
        .get_raw(&src)
        .expect("read the source")
        .expect("the source is stored");
    let (_manager, window) = loaded_window_for(&vault, &src_raw);
    let edge = format_edge_key(&src, EdgeKind::Mentions, &tgt);
    assert!(
        window.doc.get_map("edges").get(&edge).is_none(),
        "fixture: no edge before the run's put"
    );

    owner_run(&vault, owner)
        .dispatch(SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
            src,
            EdgeKind::Mentions,
            tgt,
            0.7,
        )))
        .expect("the run puts the edge");
    assert_eq!(
        vault
            .targets(&src, EdgeKind::Mentions, None)
            .expect("read the edge"),
        vec![tgt],
        "the store holds the edge"
    );

    wait_until_edge(&window, &edge, "Mentions edge");
}

/// A refused code-run supersession keeps its gate decision receipt: the
/// policy caps the owner's run at `proposed`, so the trap's Approved gate
/// body is refused, the run answers Err, and the ledger holds the refusal's
/// row. Passes on main a1dc3dd3c27b too (the bare transaction commits the
/// receipt, then refuses): it pins that the write door keeps the receipt.
#[test]
fn trap_supersede_refusal_keeps_its_receipt() {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = open_unseeded_vault(dir.path());
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    put_policy_manifest_bytes(
        &vault,
        EntityId::now(),
        &self_memory_policy(owner, "proposed"),
    )
    .expect("install the capping policy");
    let subject = person(&vault);
    let actor = WriteActor::new(owner, EdgeActorClass::Human);
    let mut claims = Vec::new();
    for value in ["o", "oh"] {
        let id = put_claim_as_code_run(
            &vault,
            actor,
            EntityId::now(),
            "profile.nickname",
            subject,
            Value::from(value),
            T0,
        )
        .expect("the claim lands Proposed");
        claims.push(id);
    }
    let (old, new) = (claims[0], claims[1]);
    let before = vault.gate_decisions(64).expect("read the ledger").len();

    owner_run(&vault, owner)
        .dispatch(SelfCall::MemorySupersedeClaim(
            SelfMemorySupersedeClaimCall::new(new, old, T0 + 100),
        ))
        .expect_err("the gate refuses the run's Approved supersede body");
    let after = vault.gate_decisions(64).expect("read the ledger");
    assert!(
        after.len() > before,
        "the refusal records a decision receipt"
    );
    assert!(
        after
            .iter()
            .any(|row| row.claim_id == Some(*old.as_bytes())),
        "the refusal's receipt names the old claim"
    );
    assert_eq!(
        vault
            .get_claim(&old)
            .expect("read the old claim")
            .expect("the old claim is stored")
            .lifecycle,
        ClaimLifecycleStatus::Active,
        "the refused supersession leaves the old claim active"
    );
}
