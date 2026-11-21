//! An edge provenance write's claim rows and its restamped edge reach a
//! loaded live window, through the live mirror, without waiting for the
//! window's next cold open (FIX
//! EVIDENCE-PROVENANCE-RECORD-NOT-QUEUED-FOR-LIVE-WINDOW).
//!
//! The edge provenance writer does not go through the batch builder, so its
//! claim puts and its flag restamps queued nothing for the owner's
//! post-commit mirror. A loaded window missed the new `edge.provenance`
//! claim row, kept the closed prior's old bytes, and kept the subject edge's
//! old value until its next cold open. With the fix the claim puts queue the
//! rows they wrote and the restamp queues the subject's endpoints, so the
//! live mirror carries them.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test edge_provenance_live_window`.
#![cfg(feature = "sync")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use loro::{LoroDoc, LoroValue, ValueOrContainer};
use oneiron::claim::decode_claim_body;
use oneiron::edge::{EdgeConfirmationStatus, EdgeProvenanceFlags};
use oneiron::provenance::{EdgeProvenanceClaimBody, EdgeRef, SupersessionStatus};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_POLICY_MANIFEST};
use oneiron::sync::bridge::{Materializer, encode_edge_value_for_crdt, format_edge_key};
use oneiron::sync::manager::WindowManager;
use oneiron::sync::residence::residence_window_for_blob;
use oneiron::sync::window::LoadedWindow;
use oneiron::{
    ClaimLifecycleStatus, EdgeActorClass, EdgeKind, EntityId, HnswConfig, TimeRange, Vault,
    VaultConfig,
};
use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;
use oneiron_keystore::MemoryKeystore;

/// The live mirror carries a committed row on its own thread: the test looks
/// every `POLL`, at most `POLLS` times (30 s of sleep), with no clock read.
const POLL: Duration = Duration::from_millis(20);
const POLLS: u32 = 1_500;

/// Vault config matching the sync bridge baseline, as a host opens one.
fn test_config() -> VaultConfig {
    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = None;
    cfg.max_readers = 16;
    cfg.hnsw = HnswConfig::default();
    cfg
}

/// A vault with this install's signing keys loaded, as a host opens one.
fn open_vault(dir: &std::path::Path) -> Arc<Vault> {
    let vault = Vault::open(dir, test_config()).expect("the vault opens");
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    Arc::new(vault)
}

fn clear_policy_manifests(vault: &Vault) {
    // The seeded default manifest is local engine state. Public deletion is
    // rejected, and sync mirroring skips it, so legacy sync fixtures no longer
    // remove it during setup.
    assert!(
        vault
            .count_entities_by_type(ENTITY_TYPE_POLICY_MANIFEST)
            .expect("count policy manifests")
            <= 1
    );
}

fn put(vault: &Vault, entity_type: u8, body: &[u8]) -> EntityId {
    let id = EntityId::now();
    let at = vault.now_recorded_at();
    vault
        .put_entity(&id, entity_type, TimeRange { start: at, end: at }, at, body)
        .expect("a row");
    id
}

/// The lifecycle of the provenance claim `id` as the store holds it.
fn lifecycle(vault: &Vault, claim: &EntityId) -> Option<ClaimLifecycleStatus> {
    vault
        .get_claim(claim)
        .expect("read the provenance claim")
        .map(|body| body.lifecycle)
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

/// The bytes the window's doc carries for the edge `edge_key`.
fn edge_carrier(doc: &LoroDoc, edge_key: &str) -> Option<Vec<u8>> {
    match doc.get_map("edges").get(edge_key)? {
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

/// The store's encoding of the subject edge's value, as the window's edge
/// backfill encodes it (sync/window/reverse.rs:673-679).
fn expected_edge_value(vault: &Vault, src: &EntityId, kind: EdgeKind, tgt: &EntityId) -> Vec<u8> {
    let edge = vault
        .edges_out(src)
        .expect("read the source's edges")
        .into_iter()
        .find(|edge| edge.kind == kind && edge.target == *tgt)
        .expect("the subject edge is stored");
    encode_edge_value_for_crdt(
        edge.kind,
        edge.weight,
        edge.created_at,
        edge.vad,
        edge.provenance,
    )
    .expect("the edge value encodes")
}

/// A put's claim and its restamped edge reach the loaded window that carries
/// the edge's source.
/// Red on main 40119849b1fe: the loaded window never carries the new claim
/// and keeps the subject edge's bare value from before the put.
#[test]
fn a_put_edge_provenance_claim_and_its_restamped_edge_reach_the_loaded_window() {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = open_vault(dir.path());
    clear_policy_manifests(&vault);
    let person = put(&vault, ENTITY_TYPE_PERSON, b"person");
    let src = put(&vault, ENTITY_TYPE_PERSON, b"src");
    let tgt = put(&vault, ENTITY_TYPE_PERSON, b"tgt");
    vault
        .put_edge(&src, EdgeKind::Mentions, &tgt, 0.875)
        .expect("the subject edge");
    let src_raw = vault
        .get_raw(&src)
        .expect("read the source")
        .expect("the source is stored");
    let (_manager, window) = loaded_window_for(&vault, &src_raw);
    let edge_key = format_edge_key(&src, EdgeKind::Mentions, &tgt);
    wait_until_edge(&window, &edge_key, "subject edge");
    let carried_before =
        edge_carrier(&window.doc, &edge_key).expect("the cold open carries the subject edge");

    let claim = EntityId::now();
    let subject = EdgeRef::new(src, EdgeKind::Mentions, tgt);
    let body = EdgeProvenanceClaimBody::new(person, 0.75, SupersessionStatus::Confirmed);
    vault
        .put_edge_provenance(
            &claim,
            &subject,
            &body,
            EdgeActorClass::Human,
            vault.now_recorded_at(),
        )
        .expect("the provenance put lands");

    assert!(
        vault.get_raw(&claim).expect("read the claim").is_some(),
        "the store holds the provenance claim"
    );
    assert_eq!(
        lifecycle(&vault, &claim),
        Some(ClaimLifecycleStatus::Active),
        "the store holds the provenance claim active"
    );
    let edge = vault
        .edges_out(&src)
        .expect("read the source's edges")
        .into_iter()
        .find(|edge| edge.kind == EdgeKind::Mentions && edge.target == tgt)
        .expect("the subject edge is stored");
    assert_eq!(
        edge.provenance,
        Some(EdgeProvenanceFlags {
            confirmation_status: EdgeConfirmationStatus::Confirmed,
            actor_class: EdgeActorClass::Human,
        }),
        "the store holds the subject edge restamped"
    );
    let expected = expected_edge_value(&vault, &src, EdgeKind::Mentions, &tgt);
    assert_ne!(
        expected, carried_before,
        "fixture: the restamp changes the edge value, so the window assert cannot pass vacuously"
    );

    wait_until_carried(&vault, &window, &claim, "the provenance claim");
    let stored = vault
        .get_raw(&claim)
        .expect("read the row")
        .expect("the row is stored");
    assert_eq!(
        carrier(&window.doc, &claim).as_deref(),
        Some(stored.as_slice()),
        "the loaded window carries the provenance claim's row bytes"
    );
    wait_until_edge_value(&window, &edge_key, &expected, "restamped subject edge");
    assert_eq!(
        edge_carrier(&window.doc, &edge_key).as_deref(),
        Some(expected.as_slice()),
        "the loaded window carries the restamped edge value"
    );
}

/// A supersession's closed prior and its replacement reach the loaded window
/// that carries the edge's source. The prior lands before the window opens,
/// so the cold open carries it and only the supersede can change it.
/// Red on main 40119849b1fe: the loaded window keeps the prior claim active
/// and never carries the replacement claim.
#[test]
fn a_superseded_provenance_claim_and_its_replacement_reach_the_loaded_window() {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = open_vault(dir.path());
    clear_policy_manifests(&vault);
    let person = put(&vault, ENTITY_TYPE_PERSON, b"person");
    let src = put(&vault, ENTITY_TYPE_PERSON, b"src");
    let tgt = put(&vault, ENTITY_TYPE_PERSON, b"tgt");
    vault
        .put_edge(&src, EdgeKind::Mentions, &tgt, 0.875)
        .expect("the subject edge");
    let subject = EdgeRef::new(src, EdgeKind::Mentions, tgt);
    let prior = EntityId::now();
    vault
        .put_edge_provenance(
            &prior,
            &subject,
            &EdgeProvenanceClaimBody::new(person, 0.75, SupersessionStatus::Confirmed),
            EdgeActorClass::Human,
            vault.now_recorded_at(),
        )
        .expect("the prior lands");
    let src_raw = vault
        .get_raw(&src)
        .expect("read the source")
        .expect("the source is stored");
    let (_manager, window) = loaded_window_for(&vault, &src_raw);
    let edge_key = format_edge_key(&src, EdgeKind::Mentions, &tgt);
    wait_until_edge(&window, &edge_key, "subject edge");
    assert!(
        edge_carrier(&window.doc, &edge_key).is_some(),
        "fixture: the cold open carries the subject edge"
    );
    assert_eq!(
        carried_lifecycle(&window.doc, &prior),
        ClaimLifecycleStatus::Active,
        "fixture: the window's cold open carries the prior active"
    );

    let new = EntityId::now();
    vault
        .supersede_edge_provenance(
            &prior,
            &new,
            &subject,
            &EdgeProvenanceClaimBody::new(person, 0.75, SupersessionStatus::Confirmed),
            EdgeActorClass::Human,
            vault.now_recorded_at(),
        )
        .expect("the supersede lands");

    assert_eq!(
        lifecycle(&vault, &prior),
        Some(ClaimLifecycleStatus::Superseded),
        "the store holds the prior superseded"
    );
    assert!(
        vault.get_raw(&new).expect("read the replacement").is_some(),
        "the store holds the replacement claim"
    );

    wait_until_carried(&vault, &window, &prior, "the superseded claim");
    let stored_prior = vault
        .get_raw(&prior)
        .expect("read the row")
        .expect("the row is stored");
    assert_eq!(
        carrier(&window.doc, &prior).as_deref(),
        Some(stored_prior.as_slice()),
        "the loaded window carries the superseded claim's row bytes"
    );
    assert_eq!(
        carried_lifecycle(&window.doc, &prior),
        ClaimLifecycleStatus::Superseded,
        "the loaded window carries the prior superseded"
    );
    wait_until_carried(&vault, &window, &new, "the replacement claim");
    let stored_new = vault
        .get_raw(&new)
        .expect("read the row")
        .expect("the row is stored");
    assert_eq!(
        carrier(&window.doc, &new).as_deref(),
        Some(stored_new.as_slice()),
        "the loaded window carries the replacement claim's row bytes"
    );
}

/// A retraction's closed claim and its restamped edge reach the loaded window
/// that carries the edge's source. The claim lands before the window opens,
/// so the cold open carries it and only the retract can change it.
/// Red on main 40119849b1fe: the loaded window keeps the claim active and
/// keeps the subject edge's confirmed value.
#[test]
fn a_retracted_provenance_claim_and_its_restamped_edge_reach_the_loaded_window() {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = open_vault(dir.path());
    clear_policy_manifests(&vault);
    let person = put(&vault, ENTITY_TYPE_PERSON, b"person");
    let src = put(&vault, ENTITY_TYPE_PERSON, b"src");
    let tgt = put(&vault, ENTITY_TYPE_PERSON, b"tgt");
    vault
        .put_edge(&src, EdgeKind::Mentions, &tgt, 0.875)
        .expect("the subject edge");
    let subject = EdgeRef::new(src, EdgeKind::Mentions, tgt);
    let claim = EntityId::now();
    vault
        .put_edge_provenance(
            &claim,
            &subject,
            &EdgeProvenanceClaimBody::new(person, 0.75, SupersessionStatus::Confirmed),
            EdgeActorClass::Human,
            vault.now_recorded_at(),
        )
        .expect("the claim lands");
    let src_raw = vault
        .get_raw(&src)
        .expect("read the source")
        .expect("the source is stored");
    let (_manager, window) = loaded_window_for(&vault, &src_raw);
    let edge_key = format_edge_key(&src, EdgeKind::Mentions, &tgt);
    wait_until_edge(&window, &edge_key, "subject edge");
    let carried_before =
        edge_carrier(&window.doc, &edge_key).expect("the cold open carries the subject edge");
    assert_eq!(
        carried_lifecycle(&window.doc, &claim),
        ClaimLifecycleStatus::Active,
        "fixture: the window's cold open carries the claim active"
    );

    vault
        .retract_edge_provenance(&claim, vault.now_recorded_at())
        .expect("the retract lands");

    assert_eq!(
        lifecycle(&vault, &claim),
        Some(ClaimLifecycleStatus::Retracted),
        "the store holds the claim retracted"
    );
    let edge = vault
        .edges_out(&src)
        .expect("read the source's edges")
        .into_iter()
        .find(|edge| edge.kind == EdgeKind::Mentions && edge.target == tgt)
        .expect("the subject edge is stored");
    assert_eq!(
        edge.provenance,
        Some(EdgeProvenanceFlags {
            confirmation_status: EdgeConfirmationStatus::Retracted,
            actor_class: EdgeActorClass::Human,
        }),
        "the store holds the subject edge restamped retracted"
    );
    let expected = expected_edge_value(&vault, &src, EdgeKind::Mentions, &tgt);
    assert_ne!(
        expected, carried_before,
        "fixture: the restamp changes the edge value, so the window assert cannot pass vacuously"
    );

    wait_until_carried(&vault, &window, &claim, "the retracted claim");
    let stored = vault
        .get_raw(&claim)
        .expect("read the row")
        .expect("the row is stored");
    assert_eq!(
        carrier(&window.doc, &claim).as_deref(),
        Some(stored.as_slice()),
        "the loaded window carries the retracted claim's row bytes"
    );
    wait_until_edge_value(&window, &edge_key, &expected, "restamped subject edge");
    assert_eq!(
        edge_carrier(&window.doc, &edge_key).as_deref(),
        Some(expected.as_slice()),
        "the loaded window carries the restamped edge value"
    );
}
