//! A derive commit's landed rows reach a loaded live window, through the
//! live mirror, without waiting for the window's next cold open (FIX
//! DERIVE-COMMIT-ITEM-SAVEPOINTS-DROP-POSTCOMMIT-WORK).
//!
//! A derive commit wrote each claim, supersede, settle, evidence and person
//! item inside a nested transaction that nobody owns, so the rows it queued
//! for the live windows' post-commit mirror were dropped. A loaded window
//! kept missing the derived row until its next cold open. With the fix each
//! savepoint goes through the owner-aware helper, which hands the queued
//! rows to the write's owner, so the live mirror carries them.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test derive_commit_live_window`.
#![cfg(all(feature = "sync", feature = "test-support", oneiron_test_support))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use loro::{LoroDoc, LoroValue, ValueOrContainer};
use oneiron::claim::decode_claim_body;
use oneiron::edge::{EdgeConfirmationStatus, EdgeProvenanceFlags};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::sync::bridge::{Materializer, encode_edge_value_for_crdt, format_edge_key};
use oneiron::sync::manager::WindowManager;
use oneiron::sync::residence::residence_window_for_blob;
use oneiron::sync::window::LoadedWindow;
use oneiron::test_doors::consolidation::{consolidate_unbound_turn, open_dreamer_vault};
use oneiron::test_doors::derive::{
    Claim, Derived, Evidence, Named, Settle, Settlement, Supersede, commit, commit_claims,
    open_conflict, row_live, source_version, supports, witness_turn,
};
use oneiron::test_doors::derive_verbs::{define_agent, grant_derive_rows, lease_run};
use oneiron::test_doors::steward::dreamer;
use oneiron::{
    ClaimLifecycleStatus, EdgeActorClass, EdgeInfo, EdgeKind, EntityId, TimeRange, Vault,
};
use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;
use oneiron_keystore::MemoryKeystore;
use serde_json::{Value, json};

const READER: &str = "reader";
/// The live mirror carries a committed row on its own thread: the test looks
/// every `POLL`, at most `POLLS` times (30 s of sleep), with no clock read.
const POLL: Duration = Duration::from_millis(20);
const POLLS: u32 = 1_500;

/// The Dreamer's vault with this install's signing keys loaded, as a host
/// opens one.
fn open_vault(dir: &std::path::Path) -> Arc<Vault> {
    let vault = open_dreamer_vault(dir, READER).expect("the dreamer vault opens");
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    Arc::new(vault)
}

fn put(vault: &Vault, entity_type: u8, body: &[u8]) -> EntityId {
    let id = EntityId::now();
    let at = vault.now_recorded_at();
    vault
        .put_entity(&id, entity_type, TimeRange { start: at, end: at }, at, body)
        .expect("a row");
    id
}

fn turn(vault: &Vault) -> EntityId {
    let body = rmp_serde::to_vec_named(&std::collections::BTreeMap::from([("role", "user")]))
        .expect("a TURN body");
    put(vault, ENTITY_TYPE_TURN, &body)
}

/// A TURN holding its own `words`, spoken by `speaker`.
fn naming_turn(vault: &Vault, speaker: &str, words: &str) -> EntityId {
    let body = rmp_serde::to_vec_named(&std::collections::BTreeMap::from([
        ("speaker", speaker),
        ("text", words),
    ]))
    .expect("a TURN body");
    put(vault, ENTITY_TYPE_TURN, &body)
}

/// The model's reply: one new person, named in T1, and its name.
fn reply() -> String {
    serde_json::json!({
        "persons": [{"id": "new:P1", "name": "Owen", "evidence_turn_refs": ["T1"]}],
        "candidates": [{
            "subject": "new:P1",
            "predicate": "profile.name",
            "value": "Owen",
            "confidence": 0.8,
            "evidence_refs": [{"source": "T1", "quote": "Owen"}],
        }],
    })
    .to_string()
}

/// The wire item naming `name` in `turns`, as `local`.
fn person_item(local: &str, name: &str, turns: &[EntityId]) -> Value {
    let evidence: Vec<Value> = turns.iter().map(|turn| json!({ "stored": turn })).collect();
    json!({
        "kind": "person",
        "spec": { "local": local, "name": name, "evidence": evidence },
    })
}

/// Lands one derived claim; its id.
fn landed_claim(
    vault: &Vault,
    dreamer: EntityId,
    person: EntityId,
    turn: EntityId,
    run: &str,
    local: &'static str,
    value: &str,
) -> EntityId {
    let committed = commit(
        vault,
        dreamer,
        EdgeActorClass::System,
        run,
        &[Derived::Claim(Claim {
            local,
            predicate: "preference.coffee",
            subject: Named::Stored(person),
            value: json!(value),
            evidence: vec![Named::Stored(turn)],
        })],
    )
    .expect("commit");
    let [item] = committed.items.as_slice() else {
        panic!("one item: {:?}", committed.items);
    };
    assert!(item.landed, "the claim lands: {item:?}");
    item.rows[0]
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
        // testkit-lint: allow(sleep) the live mirror runs on its own thread (sync/manager/live_mirror.rs:213) with no change signal a test can wait on
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
        // testkit-lint: allow(sleep) the live mirror runs on its own thread (sync/manager/live_mirror.rs:213) with no change signal a test can wait on
        std::thread::sleep(POLL);
    }
    panic!("after {POLLS} looks the loaded window still carries no {what}");
}

/// The bytes the window's doc carries for the edge `edge_key`.
fn edge_carrier(doc: &LoroDoc, edge_key: &str) -> Option<Vec<u8>> {
    match doc.get_map("edges").get(edge_key)? {
        ValueOrContainer::Value(LoroValue::Binary(bytes)) => Some(bytes.to_vec()),
        _ => None,
    }
}

/// Waits until the window carries the edge `edge_key` with `expected` bytes.
fn wait_until_edge_value(window: &LoadedWindow, edge_key: &str, expected: &[u8], what: &str) {
    for _ in 0..POLLS {
        if edge_carrier(&window.doc, edge_key).as_deref() == Some(expected) {
            return;
        }
        // testkit-lint: allow(sleep) the live mirror runs on its own thread (sync/manager/live_mirror.rs:213) with no change signal a test can wait on
        std::thread::sleep(POLL);
    }
    panic!("after {POLLS} looks the loaded window still carries {what} as it was before the write");
}

/// The stored Supports edge from `source` to `head`.
fn stored_supports_edge(vault: &Vault, source: &EntityId, head: &EntityId) -> EdgeInfo {
    vault
        .edges_out(source)
        .expect("read the source's edges")
        .into_iter()
        .find(|edge| edge.kind == EdgeKind::Supports && edge.target == *head)
        .expect("the Supports edge is stored")
}

/// The store's encoding of the Supports edge's value, as the window's edge
/// backfill encodes it (sync/window/reverse.rs:673-679).
fn stored_supports_edge_value(vault: &Vault, source: &EntityId, head: &EntityId) -> Vec<u8> {
    let edge = stored_supports_edge(vault, source, head);
    encode_edge_value_for_crdt(
        edge.kind,
        edge.weight,
        edge.created_at,
        edge.vad,
        edge.provenance,
    )
    .expect("the edge value encodes")
}

/// A derived claim reaches the loaded window that carries its subject.
/// Red on main 40119849b1fe: the claim item's savepoint drops the row it
/// queued, so the loaded window never carries the derived claim.
#[test]
fn a_derived_claim_reaches_the_loaded_window_that_carries_its_subject() {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = open_vault(dir.path());
    let person = put(&vault, ENTITY_TYPE_PERSON, b"someone");
    let turn = turn(&vault);
    let person_raw = vault
        .get_raw(&person)
        .expect("read the person")
        .expect("the person is stored");
    let (_manager, window) = loaded_window_for(&vault, &person_raw);
    let dreamer = dreamer(&vault).expect("the Dreamer");

    let committed = commit_claims(
        &vault,
        dreamer,
        EdgeActorClass::System,
        "run-1",
        &[Claim {
            local: "kept",
            predicate: "preference.coffee",
            subject: Named::Stored(person),
            value: json!("an oat milk flat white"),
            evidence: vec![Named::Stored(turn)],
        }],
    )
    .expect("the batch commits");
    let [kept] = committed.items.as_slice() else {
        panic!("one item: {:?}", committed.items);
    };
    assert!(kept.landed, "the founded claim lands: {kept:?}");
    let [claim] = kept.rows.as_slice() else {
        panic!("one row: {kept:?}");
    };
    assert_eq!(
        vault
            .get_claim(claim)
            .expect("read the claim")
            .expect("the claim is stored")
            .lifecycle,
        ClaimLifecycleStatus::Active,
        "the store holds the derived claim active"
    );

    wait_until_carried(&vault, &window, claim, "the derived claim");
    let stored = vault
        .get_raw(claim)
        .expect("read the row")
        .expect("the row is stored");
    assert_eq!(
        carrier(&window.doc, claim).as_deref(),
        Some(stored.as_slice()),
        "the loaded window carries the derived claim's row bytes"
    );
}

/// A derived settlement's answer reaches the loaded window that carries its
/// marker.
/// Red on main 40119849b1fe: the settle item's savepoint drops the answer
/// row it queued, so the loaded window never carries the answer.
#[test]
fn a_derived_settlement_answer_reaches_the_loaded_window_that_carries_its_marker() {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = open_vault(dir.path());
    let person = put(&vault, ENTITY_TYPE_PERSON, b"someone");
    let turn = turn(&vault);
    let dreamer = dreamer(&vault).expect("the Dreamer");
    let first = landed_claim(
        &vault,
        dreamer,
        person,
        turn,
        "run-first",
        "first",
        "an oat milk flat white",
    );
    let second = landed_claim(
        &vault,
        dreamer,
        person,
        turn,
        "run-second",
        "second",
        "a cortado",
    );
    let marker = open_conflict(&vault, second, first).expect("an open conflict");
    let marker_raw = vault
        .get_raw(&marker)
        .expect("read the marker")
        .expect("the marker is stored");
    let (_manager, window) = loaded_window_for(&vault, &marker_raw);

    let committed = commit(
        &vault,
        dreamer,
        EdgeActorClass::System,
        "run-settle",
        &[Derived::Settle(Settle {
            local: "keep_second",
            marker: Named::Stored(marker),
            settlement: Settlement::Keep(Named::Stored(second)),
        })],
    )
    .expect("commit");
    let [settled] = committed.items.as_slice() else {
        panic!("one item: {:?}", committed.items);
    };
    assert!(settled.landed, "the settlement lands: {settled:?}");
    let answer = settled.rows[0];
    assert_eq!(
        vault
            .get_claim(&answer)
            .expect("read the answer")
            .expect("the answer is stored")
            .lifecycle,
        ClaimLifecycleStatus::Active,
        "the store holds the settlement answer active"
    );

    wait_until_carried(&vault, &window, &answer, "the settlement answer");
    let stored = vault
        .get_raw(&answer)
        .expect("read the row")
        .expect("the row is stored");
    assert_eq!(
        carrier(&window.doc, &answer).as_deref(),
        Some(stored.as_slice()),
        "the loaded window carries the answer's row bytes"
    );
}

/// A derived Supports edge reaches the loaded window that carries its
/// source.
/// Red on main 40119849b1fe: the evidence item's savepoint drops the source
/// row it queued, so the loaded window never carries the Supports edge.
#[test]
fn a_derived_supports_edge_reaches_the_loaded_window_that_carries_its_source() {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = open_vault(dir.path());
    let dreamer = dreamer(&vault).expect("the Dreamer");
    let pass = consolidate_unbound_turn(&vault, "call me Owen", None, None, &reply())
        .expect("one consolidation pass");
    let [head] = pass.landed.as_slice() else {
        panic!("one landed claim, found {}", pass.landed.len());
    };
    let head = *head;
    let source = witness_turn(&vault, "my name is Owen").expect("a TURN");
    let source_raw = vault
        .get_raw(&source)
        .expect("read the source")
        .expect("the source is stored");
    let (_manager, window) = loaded_window_for(&vault, &source_raw);
    let edge = format_edge_key(&source, EdgeKind::Supports, &head);
    assert!(
        window.doc.get_map("edges").get(&edge).is_none(),
        "fixture: no Supports edge before the evidence commit"
    );

    let committed = commit(
        &vault,
        dreamer,
        EdgeActorClass::System,
        "run-evidence",
        &[Derived::Evidence(Evidence {
            local: "evidence",
            head: Named::Stored(head),
            sources: vec![Named::Stored(source)],
        })],
    )
    .expect("commit");
    let [item] = committed.items.as_slice() else {
        panic!("one item: {:?}", committed.items);
    };
    assert!(item.landed, "the evidence lands: {:?}", item.reasons);
    assert!(
        supports(&vault, source, head).expect("read"),
        "the store holds the Supports edge"
    );

    wait_until_edge(&window, &edge, "Supports edge");
}

/// A derived evidence item on a Supports edge the store already holds
/// reaches the loaded window with the edge's restamped value (REVIEW-10223
/// round 1 P1). The bare edge lands before the window opens, so the cold
/// open carries it and only the evidence item can change it.
/// Red on main 40119849b1fe: the evidence item's savepoint drops the rows it
/// queued. Red at b74da02af9e4 too: the edge already exists, so no edge put
/// queues its source, and the provenance restamp queued nothing; the loaded
/// window keeps the bare edge value.
#[test]
fn a_derived_evidence_item_on_an_existing_supports_edge_reaches_the_loaded_window() {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = open_vault(dir.path());
    let dreamer = dreamer(&vault).expect("the Dreamer");
    let pass = consolidate_unbound_turn(&vault, "call me Owen", None, None, &reply())
        .expect("one consolidation pass");
    let [head] = pass.landed.as_slice() else {
        panic!("one landed claim, found {}", pass.landed.len());
    };
    let head = *head;
    let source = witness_turn(&vault, "my name is Owen").expect("a TURN");
    vault
        .put_edge(&source, EdgeKind::Supports, &head, 1.0)
        .expect("the bare Supports edge");
    assert_eq!(
        stored_supports_edge(&vault, &source, &head).provenance,
        None,
        "fixture: the Supports edge is bare before the evidence commit"
    );
    let source_raw = vault
        .get_raw(&source)
        .expect("read the source")
        .expect("the source is stored");
    let (_manager, window) = loaded_window_for(&vault, &source_raw);
    let edge = format_edge_key(&source, EdgeKind::Supports, &head);
    wait_until_edge(&window, &edge, "bare Supports edge");
    let carried_before =
        edge_carrier(&window.doc, &edge).expect("the cold open carries the bare Supports edge");

    let committed = commit(
        &vault,
        dreamer,
        EdgeActorClass::System,
        "run-evidence-existing-edge",
        &[Derived::Evidence(Evidence {
            local: "evidence",
            head: Named::Stored(head),
            sources: vec![Named::Stored(source)],
        })],
    )
    .expect("commit");
    let [item] = committed.items.as_slice() else {
        panic!("one item: {:?}", committed.items);
    };
    assert!(item.landed, "the evidence lands: {:?}", item.reasons);
    assert_eq!(
        stored_supports_edge(&vault, &source, &head).provenance,
        Some(EdgeProvenanceFlags {
            confirmation_status: EdgeConfirmationStatus::Confirmed,
            actor_class: EdgeActorClass::System,
        }),
        "the store holds the Supports edge restamped by the evidence item"
    );
    let expected = stored_supports_edge_value(&vault, &source, &head);
    assert_ne!(
        expected, carried_before,
        "fixture: the restamp changes the edge value, so the window assert cannot pass vacuously"
    );

    wait_until_edge_value(&window, &edge, &expected, "Supports edge");
}

/// A PERSON minted on a live run reaches the loaded window that carries its
/// naming TURN.
/// Red on main 40119849b1fe: the person item's savepoint drops the PERSON
/// row it queued, so the loaded window never carries the minted PERSON.
#[test]
fn a_person_minted_on_a_live_run_reaches_the_loaded_window_that_carries_its_naming_turn() {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = open_vault(dir.path());
    let agent = define_agent(&vault, "oneiron.agent.derive-person").expect("an agent");
    grant_derive_rows(&vault, &[agent]).expect("the agent's policy rows");
    let run = lease_run(&vault, agent).expect("the agent's live run");
    let said = naming_turn(&vault, "user", "I had lunch with Ann today.");
    let said_raw = vault
        .get_raw(&said)
        .expect("read the TURN")
        .expect("the TURN is stored");
    let (_manager, window) = loaded_window_for(&vault, &said_raw);

    let version = source_version(&vault, agent, EdgeActorClass::Agent, said)
        .expect("read")
        .expect("the agent reads the source");
    let version = serde_json::to_value(version).expect("a version");
    let answer = run
        .commit(
            &vault,
            json!({
                "items": [person_item("ann", "Ann", &[said])],
                "sources": [version],
            }),
        )
        .expect("the batch commits");
    let items = answer["items"].as_array().expect("items");
    assert_eq!(items.len(), 1, "{answer}");
    assert_eq!(items[0]["landed"], true, "the person lands: {answer}");
    let person = EntityId::from_hex(items[0]["rows"][0].as_str().expect("an id"))
        .expect("a 32-character hex id");
    assert!(
        row_live(&vault, person).expect("read"),
        "the store holds the minted PERSON live"
    );

    wait_until_carried(&vault, &window, &person, "the minted PERSON");
    let stored = vault
        .get_raw(&person)
        .expect("read the row")
        .expect("the row is stored");
    assert_eq!(
        carrier(&window.doc, &person).as_deref(),
        Some(stored.as_slice()),
        "the loaded window carries the PERSON's row bytes"
    );
}

/// A derived supersession reaches the loaded window that carries the old
/// claim. The window opens after both claims landed, so its cold open
/// carries them and only the supersede item's rows can change it.
/// Red on main 40119849b1fe: the supersede item's savepoint drops the pair
/// it queued, so the loaded window keeps the old claim active.
#[test]
fn a_derived_supersession_reaches_the_loaded_window_that_carries_the_old_claim() {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = open_vault(dir.path());
    let person = put(&vault, ENTITY_TYPE_PERSON, b"someone");
    let turn = turn(&vault);
    let dreamer = dreamer(&vault).expect("the Dreamer");

    let seeded = commit(
        &vault,
        dreamer,
        EdgeActorClass::System,
        "run-first",
        &[
            Derived::Claim(Claim {
                local: "old",
                predicate: "preference.coffee",
                subject: Named::Stored(person),
                value: json!("a black filter coffee"),
                evidence: vec![Named::Stored(turn)],
            }),
            Derived::Claim(Claim {
                local: "new",
                predicate: "preference.coffee",
                subject: Named::Stored(person),
                value: json!("an oat milk flat white"),
                evidence: vec![Named::Stored(turn)],
            }),
        ],
    )
    .expect("commit");
    assert!(
        seeded.items.iter().all(|item| item.landed),
        "both seed claims land: {:?}",
        seeded.items
    );
    let old = seeded.items[0].rows[0];
    let new = seeded.items[1].rows[0];
    let old_raw = vault
        .get_raw(&old)
        .expect("read the old claim")
        .expect("the old claim is stored");
    let (_manager, window) = loaded_window_for(&vault, &old_raw);
    assert_eq!(
        carried_lifecycle(&window.doc, &old),
        ClaimLifecycleStatus::Active,
        "fixture: the window's cold open carries the old claim active"
    );

    let committed = commit(
        &vault,
        dreamer,
        EdgeActorClass::System,
        "run-supersede",
        &[Derived::Supersede(Supersede {
            local: "replace_old",
            new: Named::Stored(new),
            old: Named::Stored(old),
        })],
    )
    .expect("commit");
    let [replace] = committed.items.as_slice() else {
        panic!("one item: {:?}", committed.items);
    };
    assert!(replace.landed, "the supersession lands: {replace:?}");
    assert_eq!(
        vault
            .get_claim(&old)
            .expect("read the old claim")
            .expect("the old claim is stored")
            .lifecycle,
        ClaimLifecycleStatus::Superseded,
        "the store holds the old claim superseded"
    );

    wait_until_carried(&vault, &window, &old, "the superseded claim");
    assert_eq!(
        carried_lifecycle(&window.doc, &old),
        ClaimLifecycleStatus::Superseded,
        "the loaded window carries the old claim superseded"
    );
}
