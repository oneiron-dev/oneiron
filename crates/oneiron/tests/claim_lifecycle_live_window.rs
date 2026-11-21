//! A claim the owner retracts or supersedes through the public lifecycle
//! doors reaches the loaded window that carries it, through the live
//! mirror, without waiting for the window's next cold open (FIX
//! CLAIM-LIFECYCLE-DOORS-QUEUE-NO-LIVE-WINDOW-ROWS).
//!
//! `Vault::retract_claim` and `Vault::supersede_claim` committed on a bare
//! write transaction with no post-commit owner, so the rows their in-txn
//! doors queued for the live mirror were dropped, and the supersession
//! queued none. A loaded window kept the claim as it was before the close,
//! and so did every peer that reads that window, until the window was built
//! from the store again.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test claim_lifecycle_live_window`.
#![cfg(all(feature = "sync", feature = "test-support"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use loro::{LoroDoc, LoroValue, ValueOrContainer};
use oneiron::claim::decode_claim_body;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::sync::bridge::{Materializer, format_edge_key};
use oneiron::sync::manager::WindowManager;
use oneiron::sync::residence::residence_window_for_blob;
use oneiron::sync::window::LoadedWindow;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EdgeKind,
    EntityId, TimeRange, Vault, VaultConfig,
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

/// An active claim about `person`, through the owner's claim door.
fn claim(vault: &Vault, person: EntityId, value: &str) -> EntityId {
    let mut body = ClaimBody::new(
        "profile.nickname",
        ClaimSubject::Entity(person),
        Value::from(value),
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
    id
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

/// A person and the claims `values` about them, then the window that holds
/// their rows, opened and kept loaded. Every claim's row is in the window.
fn claims_under_a_loaded_window(
    vault: &Arc<Vault>,
    values: &[&str],
) -> (Vec<EntityId>, Arc<WindowManager>, Arc<LoadedWindow>) {
    let person = EntityId::now();
    vault
        .put_entity(&person, ENTITY_TYPE_PERSON, at(T0), T0, b"someone")
        .expect("the person");
    let claims: Vec<EntityId> = values
        .iter()
        .map(|value| claim(vault, person, value))
        .collect();
    let raw = vault
        .get_raw(&claims[0])
        .expect("read the claim's row")
        .expect("the claim's row is stored");
    let key = residence_window_for_blob(&raw).expect("the claim's window");
    let manager = Arc::new(WindowManager::new(
        Arc::clone(vault),
        Arc::new(Materializer::new()),
        "owner",
    ));
    let window = manager.open_window(&key).expect("the window opens");
    for id in &claims {
        assert_eq!(
            carried_lifecycle(&window.doc, id),
            ClaimLifecycleStatus::Active,
            "fixture: the window carries each claim as active"
        );
    }
    (claims, manager, window)
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
    panic!("after {POLLS} looks the loaded window still carries {what} as it was before the close");
}

/// Red on main e48dcb1ba29f: `retract_claim` commits on a bare
/// transaction, which drops the closed claim its in-txn door queued, so the
/// loaded window keeps the claim active.
#[test]
fn a_retract_reaches_the_loaded_window_that_carries_the_claim() {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = open_vault(dir.path());
    let (claims, _manager, window) = claims_under_a_loaded_window(&vault, &["o"]);
    let retracted = claims[0];

    vault
        .retract_claim(&retracted, vault.now_recorded_at())
        .expect("the owner retracts the claim");
    assert_eq!(
        vault
            .get_claim(&retracted)
            .expect("read the claim")
            .expect("the claim is stored")
            .lifecycle,
        ClaimLifecycleStatus::Retracted,
        "the store holds the claim retracted"
    );

    wait_until_carried(&vault, &window, &retracted, "the retracted claim");
    assert_eq!(
        carried_lifecycle(&window.doc, &retracted),
        ClaimLifecycleStatus::Retracted,
        "the loaded window carries the claim retracted"
    );
}

/// Red on main e48dcb1ba29f: `supersede_claim` queues neither claim
/// and commits on a bare transaction, so the loaded window keeps the old
/// claim active and carries no Supersedes edge.
#[test]
fn a_supersession_reaches_the_loaded_window_that_carries_both_claims() {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = open_vault(dir.path());
    let (claims, _manager, window) = claims_under_a_loaded_window(&vault, &["o", "oh"]);
    let (old, new) = (claims[0], claims[1]);
    let edge = format_edge_key(&new, EdgeKind::Supersedes, &old);
    assert!(
        window.doc.get_map("edges").get(&edge).is_none(),
        "fixture: no Supersedes edge before the supersession"
    );

    vault
        .supersede_claim(&new, &old, vault.now_recorded_at())
        .expect("the newer claim supersedes the old one");
    assert_eq!(
        vault
            .get_claim(&old)
            .expect("read the claim")
            .expect("the claim is stored")
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
    assert_eq!(
        carried_lifecycle(&window.doc, &new),
        ClaimLifecycleStatus::Active,
        "the loaded window keeps the newer claim active"
    );
    assert!(
        window.doc.get_map("edges").get(&edge).is_some(),
        "the loaded window carries the newer claim's Supersedes edge"
    );
}
