// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! A carried CLAIM row version stops at a structural ceiling (FIX
//! SYNC-CLAIM-ROW-VERSION-FLOOR-POISON; Engine ruling SYNC-CLAIM-ROW-VERSION-CEILING, 27 Nov).
//!
//! Row versions are counters: each local CLAIM write takes the vault-wide floor plus one, and a
//! replicated CLAIM's carried version raises that floor. One replicated CLAIM carrying
//! `u64::MAX` lifted the floor to where floor + 1 overflows, so every later local CLAIM write on
//! the vault failed, across restarts. A carried version past the ceiling is now a malformed row.
//!
//! The replicated CLAIM is a real one a second vault wrote, with its header's row version set by
//! hand. It reaches a fresh vault through the window ingest door (`forward_rematerialize`) or the
//! explicit-tier replay door (`replay_entity`).
//!
//! * `a_replicated_claim_past_the_ceiling_is_refused_and_local_claim_writes_go_on`: the window
//!   door quarantines it as a malformed row (`CorruptedIndex`) and keeps it out of the entities
//!   table, and a later local CLAIM write still lands. Red with the ceiling undone: that write
//!   fails with `IndexOverflow`.
//! * `the_replay_door_refuses_a_claim_past_the_ceiling`: the replay door refuses it as a malformed
//!   row, and a later local CLAIM write still lands. Red with the ceiling undone, at that write.
//! * `a_replicated_claim_far_ahead_under_the_ceiling_still_lands`: a device far ahead of this one
//!   is not refused. Its row lands as carried, and the next local CLAIM write takes a later
//!   version. Green both ways; it guards the fix.
//!
//! `cargo test --locked -p oneiron --all-features --test claim_row_version_ceiling`.
// The harness's MemoryKeystore needs `test-support` (it forwards oneiron-keystore/test-keystore).
#![cfg(all(feature = "sync", feature = "test-support"))]

#[path = "it_sync/sync_harness/mod.rs"]
mod sync_harness;

use oneiron::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};
use oneiron::sync::bridge::Materializer;
use oneiron::sync::client::ImportTier;
use oneiron::sync::quarantine::{QuarantineContainer, quarantined_records};
use oneiron::sync::replay::{ReplicatedEntity, replay_entity};
use oneiron::sync::schema::create_window_doc;
use oneiron::sync::types::WindowKey;
use oneiron::sync::window::forward_rematerialize;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId, ErrorKind, Vault,
};
use oneiron_contracts::record_layout::EntityMetadataHeader;

use crate::sync_harness::{
    ENTITY_METADATA_HEADER_LEN, T0, WINDOW, map_insert_bytes, open_vault_with_memory_keystore,
    test_config, time_range,
};

/// A version far ahead of any vault here, and far under the ceiling (2^48).
const FAR_AHEAD: u64 = 1 << 40;

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir for the vault");
    let vault = open_vault_with_memory_keystore(dir.path(), test_config());
    (dir, vault)
}

/// The PERSON the CLAIMs here are about, written under the same id and bytes on each vault.
fn put_person(vault: &Vault, person: EntityId) {
    vault
        .put_entity(&person, ENTITY_TYPE_PERSON, time_range(T0), T0, b"person")
        .expect("FIXTURE: put the PERSON");
}

fn claim_body(person: EntityId) -> ClaimBody {
    ClaimBody::new(
        "test.row_version_ceiling",
        ClaimSubject::Entity(person),
        rmpv::Value::from("fixture"),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("FIXTURE: claim body")
}

/// A local CLAIM write about `person` on `vault`.
fn write_claim(vault: &Vault, person: EntityId) -> (EntityId, oneiron::Result<()>) {
    let id = EntityId::now();
    let written = vault.put_claim(&id, &claim_body(person), time_range(T0), T0);
    (id, written)
}

/// The receiver under test and a CLAIM about a PERSON both vaults hold, as a second vault wrote
/// it and a window carries it: header and body, its header's row version set to `row_version`.
struct Carried {
    _dirs: [tempfile::TempDir; 2],
    receiver: Vault,
    person: EntityId,
    claim: EntityId,
    blob: Vec<u8>,
}

fn carried_claim(row_version: u64) -> Carried {
    let (source_dir, source) = open_vault();
    let (receiver_dir, receiver) = open_vault();
    let person = EntityId::now();
    put_person(&source, person);
    put_person(&receiver, person);
    let (claim, written) = write_claim(&source, person);
    written.expect("FIXTURE: the source writes the CLAIM");
    let mut blob = source
        .get_raw(&claim)
        .expect("read the source row")
        .expect("the source holds the CLAIM");
    blob[ENTITY_METADATA_HEADER_LEN - 8..ENTITY_METADATA_HEADER_LEN]
        .copy_from_slice(&row_version.to_be_bytes());
    let header = EntityMetadataHeader::parse(&blob).expect("the carried header parses");
    assert_eq!(header.entity_type, ENTITY_TYPE_CLAIM);
    assert_eq!(
        header.row_version, row_version,
        "FIXTURE: the carried row version"
    );
    Carried {
        _dirs: [source_dir, receiver_dir],
        receiver,
        person,
        claim,
        blob,
    }
}

/// Runs the receiver's window ingest over a window that carries `carried`'s CLAIM.
fn ingest_through_window(carried: &Carried) {
    let window = WindowKey::new(WINDOW);
    let doc = create_window_doc("test-user", &window);
    map_insert_bytes(
        &doc.get_map("entities"),
        &carried.claim.to_hex(),
        &carried.blob,
    );
    doc.commit();
    forward_rematerialize(&carried.receiver, &doc, &Materializer::new(), &window)
        .expect("the window pass completes");
}

fn row_version_of(vault: &Vault, id: &EntityId) -> u64 {
    let raw = vault
        .get_raw(id)
        .expect("read the row")
        .expect("the row is stored");
    EntityMetadataHeader::parse(&raw)
        .expect("the stored header parses")
        .row_version
}

#[test]
fn a_replicated_claim_past_the_ceiling_is_refused_and_local_claim_writes_go_on() {
    let carried = carried_claim(u64::MAX);
    ingest_through_window(&carried);

    let (later, written) = write_claim(&carried.receiver, carried.person);
    assert!(
        written.is_ok(),
        "a later local CLAIM write lands after a replicated CLAIM at u64::MAX: {written:?}"
    );
    assert!(
        row_version_of(&carried.receiver, &later) < u64::MAX,
        "the local write takes a counted version"
    );
    assert!(
        carried.receiver.get_raw(&carried.claim).unwrap().is_none(),
        "the CLAIM past the ceiling never reaches the entities table"
    );
    let records = quarantined_records(&carried.receiver).unwrap();
    assert_eq!(records.len(), 1, "one x: row, for the refused CLAIM");
    let (_, record) = &records[0];
    assert_eq!(
        record.reason_code, "CorruptedIndex",
        "refused as a malformed row"
    );
    assert_eq!(record.container, QuarantineContainer::Entities);
}

#[test]
fn the_replay_door_refuses_a_claim_past_the_ceiling() {
    let carried = carried_claim(u64::MAX);
    let replayed = replay_entity(
        &carried.receiver,
        ReplicatedEntity {
            id: carried.claim,
            entity_type: ENTITY_TYPE_CLAIM,
            occurred: time_range(T0),
            learned_at: T0,
            row_version: u64::MAX,
            body: &carried.blob[ENTITY_METADATA_HEADER_LEN..],
        },
        ImportTier::OwnDevice,
    );

    let (_, written) = write_claim(&carried.receiver, carried.person);
    assert!(
        written.is_ok(),
        "a later local CLAIM write lands after a replayed CLAIM at u64::MAX: {written:?}"
    );
    assert_eq!(
        replayed.map_err(|error| error.kind()),
        Err(ErrorKind::CorruptedIndex),
        "the replay door refuses the CLAIM as a malformed row"
    );
    assert!(
        carried.receiver.get_raw(&carried.claim).unwrap().is_none(),
        "the refused CLAIM is not stored"
    );
}

#[test]
fn a_replicated_claim_far_ahead_under_the_ceiling_still_lands() {
    let carried = carried_claim(FAR_AHEAD);
    ingest_through_window(&carried);

    assert_eq!(
        carried.receiver.get_raw(&carried.claim).unwrap().as_deref(),
        Some(carried.blob.as_slice()),
        "a CLAIM from a device far ahead lands as carried"
    );
    assert!(
        quarantined_records(&carried.receiver).unwrap().is_empty(),
        "nothing is refused"
    );
    let (later, written) = write_claim(&carried.receiver, carried.person);
    written.expect("a later local CLAIM write lands");
    assert!(
        row_version_of(&carried.receiver, &later) > FAR_AHEAD,
        "the next local CLAIM write takes a version past the carried one"
    );
}
