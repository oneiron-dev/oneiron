//! Census row L3-27 (ARCH-0044 C5, "Still open, follow-up queued"): off this
//! device, Graph-FS reads on past every claim a device-local world keeps, so
//! no such claim ends a page and the walk has no bound. The walk counts every
//! row it reads, a withheld one too, on the scan kind of the table it walks:
//! `type_index_rows` of the CLAIM type for `/claims/by-id`, `edge_peer_rows`
//! of the subject's inbound `ClaimOf` edges for `/entities/<id>/claims` and
//! `ls -t` of it. Past that row it raises one rule-5 `ScanCheck` and reads on;
//! it never refuses. On this device the run stays one bounded page and counts
//! nothing.
//!
//! On main the three off-device tests fail: the walk keeps no count, so no
//! check is raised. The off-device `ls -t` fails before that: it holds a read
//! transaction, and its withheld-claim filter opened a second one on the
//! thread (`MDB_BAD_RSLOT`).
//!
//! `cargo test --locked -p oneiron --all-features --test graph_fs_withheld_claim_scan`.
#![cfg(feature = "test-support")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::claim::{CallerLocality, ScopedReadActorKey};
use oneiron::graph_fs::GraphFsOptions;
use oneiron::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON, ENTITY_TYPE_WORLD};
use oneiron::store::{EngineScan, ScanCheck};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeKind, EntityId,
    TimeRange, Vault, VaultConfig,
};
use oneiron_authority::federation::scope_codec::{encode_scope_value, read_preset};
use rmpv::Value;

/// Claims the device-local world keeps: more than [`THRESHOLD`].
const WITHHELD: usize = 12;
/// The threshold row both scan kinds get once the fixture is written.
const THRESHOLD: u64 = 8;
/// `EdgeDirection::In`, the first byte of an inbound edge-peer scope.
const INBOUND: u8 = 0;
/// The reader: a base-world `core:read` grant lets it read the subject.
const READER: &str = "reader";

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    subject: EntityId,
}

/// A policy manifest whose one grant lets [`READER`] read the base world, as
/// the Graph-FS unit fixtures grant it (graph_fs/tests.rs).
fn base_read_manifest() -> Vec<u8> {
    let grant = Value::Map(vec![
        (Value::from("actor_ref"), Value::from(READER)),
        (Value::from("effector"), Value::from("core:read")),
        (
            Value::from("scope"),
            encode_scope_value(&read_preset()).expect("read preset encodes"),
        ),
        (
            Value::from("selectors"),
            Value::Map(vec![(Value::from("world_ref"), Value::from("base"))]),
        ),
        (Value::from("receipt_required"), Value::Boolean(false)),
    ]);
    let manifest = Value::Map(vec![
        (Value::from("schema_version"), Value::from("1.2")),
        (
            Value::from("pack_id"),
            Value::from("graph-fs-withheld-claim-scan"),
        ),
        (Value::from("pack_version"), Value::from("1")),
        (Value::from("min_engine_version"), Value::from("0.0.0")),
        (Value::from("defaults"), Value::Map(Vec::new())),
        (Value::from("rules"), Value::Array(Vec::new())),
        (Value::from("actor_ceilings"), Value::Array(Vec::new())),
        (Value::from("scoped_grants"), Value::Array(vec![grant])),
    ]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &manifest).expect("manifest encodes");
    bytes
}

/// A vault whose one subject has [`WITHHELD`] claims, all in a world kept on
/// this machine, with both scan rows set to [`THRESHOLD`] after the writes.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    let at = TimeRange { start: 1, end: 1 };
    let (world, subject) = (EntityId::now(), EntityId::now());
    vault
        .put_entity(&world, ENTITY_TYPE_WORLD, at, 1, b"world")
        .expect("put the world");
    vault
        .put_entity(&subject, ENTITY_TYPE_PERSON, at, 1, b"person")
        .expect("put the subject");
    for _ in 0..WITHHELD {
        let mut body = ClaimBody::new(
            "profile.orchid",
            ClaimSubject::Entity(subject),
            rmpv::Value::from("kept"),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )
        .expect("build a claim");
        body.world = Some(world);
        vault
            .put_claim(&EntityId::now(), &body, at, 1)
            .expect("put a claim");
    }
    oneiron::test_support::put_policy_manifest_bytes(
        &vault,
        EntityId::now(),
        &base_read_manifest(),
    )
    .expect("grant the reader the base world");
    vault
        .keep_world_on_this_machine_for_test(world, true)
        .expect("keep the world on this machine");
    vault
        .set_scan_threshold(EngineScan::TypeIndexRows, THRESHOLD)
        .expect("type-index row");
    vault
        .set_scan_threshold(EngineScan::EdgePeerRows, THRESHOLD)
        .expect("edge-peer row");
    Fixture {
        _dir: dir,
        vault,
        subject,
    }
}

fn claim_type_scope() -> String {
    format!("{ENTITY_TYPE_CLAIM:02x}")
}

fn claim_edge_scope(subject: &EntityId) -> String {
    format!(
        "{INBOUND:02x}{}{:02x}",
        subject.to_hex(),
        EdgeKind::ClaimOf as u8
    )
}

/// The check `scan` of `scope` raised, if any.
fn check(vault: &Vault, scan: EngineScan, scope: &str) -> Option<ScanCheck> {
    vault
        .scan_checks()
        .expect("scan checks")
        .into_iter()
        .find(|check| check.scan == scan.code() && check.scope.as_deref() == Some(scope))
}

fn graph_fs_reader(vault: &Vault, locality: CallerLocality) -> oneiron::claim::ScopedRead<'_> {
    vault.scoped_read(
        ScopedReadActorKey::new(READER)
            .expect("actor key")
            .at(locality),
    )
}

/// The claim walk raised its check, with every withheld claim among the rows
/// it counted.
fn assert_raised(vault: &Vault, scan: EngineScan, scope: &str) {
    let raised = check(vault, scan, scope).unwrap_or_else(|| {
        panic!(
            "an off-device claim walk past its row raises {} of {scope}; checks: {:?}",
            scan.code(),
            vault.scan_checks().expect("scan checks")
        )
    });
    assert_eq!(raised.threshold, THRESHOLD);
    assert!(
        raised.rows >= WITHHELD as u64,
        "the walk counts the claims it reads on past: {raised:?}"
    );
}

#[test]
fn an_off_device_claims_by_id_walk_past_its_row_raises_the_type_index_check() {
    let fixture = fixture();
    let scope = claim_type_scope();
    assert!(check(&fixture.vault, EngineScan::TypeIndexRows, &scope).is_none());

    let reader = graph_fs_reader(&fixture.vault, CallerLocality::OffDevice);
    reader
        .graph_fs(GraphFsOptions::default())
        .readdir("/claims/by-id", None)
        .expect("list claims by id");

    assert_raised(&fixture.vault, EngineScan::TypeIndexRows, &scope);
}

#[test]
fn an_off_device_subject_claims_walk_past_its_row_raises_the_edge_peer_check() {
    let fixture = fixture();
    let scope = claim_edge_scope(&fixture.subject);
    assert!(check(&fixture.vault, EngineScan::EdgePeerRows, &scope).is_none());

    let reader = graph_fs_reader(&fixture.vault, CallerLocality::OffDevice);
    assert!(
        reader
            .is_entity_readable(&fixture.subject)
            .expect("read the subject"),
        "the walk starts only for a subject the reader reads"
    );
    reader
        .graph_fs(GraphFsOptions::default())
        .readdir(
            &format!("/entities/{}/claims", fixture.subject.to_hex()),
            None,
        )
        .expect("list the subject's claims");

    assert_raised(&fixture.vault, EngineScan::EdgePeerRows, &scope);
}

#[test]
fn an_off_device_ls_t_of_subject_claims_past_its_row_raises_the_edge_peer_check() {
    let fixture = fixture();
    let scope = claim_edge_scope(&fixture.subject);
    assert!(check(&fixture.vault, EngineScan::EdgePeerRows, &scope).is_none());

    let reader = graph_fs_reader(&fixture.vault, CallerLocality::OffDevice);
    assert!(
        reader
            .is_entity_readable(&fixture.subject)
            .expect("read the subject"),
        "the walk starts only for a subject the reader reads"
    );
    let listed = reader
        .graph_fs(GraphFsOptions::default())
        .ls(
            &format!("/entities/{}/claims", fixture.subject.to_hex()),
            true,
            None,
        )
        .expect("ls -t the subject's claims");

    assert!(
        listed.bytes().is_empty(),
        "off this device ls -t names no withheld claim: {:?}",
        String::from_utf8_lossy(listed.bytes())
    );
    assert_raised(&fixture.vault, EngineScan::EdgePeerRows, &scope);
}

/// On this device each listing reads one bounded run, which adds nothing to
/// the walk's count.
#[test]
fn on_this_device_the_claim_listings_raise_no_walk_check() {
    let fixture = fixture();
    let subject_claims = format!("/entities/{}/claims", fixture.subject.to_hex());
    let reader = graph_fs_reader(&fixture.vault, CallerLocality::OnDevice);
    let fs = reader.graph_fs(GraphFsOptions::default());
    fs.readdir("/claims/by-id", None)
        .expect("list claims by id");
    fs.readdir(&subject_claims, None)
        .expect("list the subject's claims");
    fs.ls(&subject_claims, true, None)
        .expect("ls -t the subject's claims");

    assert!(
        reader
            .is_entity_readable(&fixture.subject)
            .expect("read the subject"),
        "the subject listings walk only for a subject the reader reads"
    );
    for (scan, scope) in [
        (EngineScan::TypeIndexRows, claim_type_scope()),
        (EngineScan::EdgePeerRows, claim_edge_scope(&fixture.subject)),
    ] {
        let raised = check(&fixture.vault, scan, &scope);
        assert!(raised.is_none(), "on this device: {raised:?}");
    }
}
