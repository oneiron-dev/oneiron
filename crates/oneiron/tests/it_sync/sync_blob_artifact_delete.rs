//! H125: a deleted blob artifact's version bytes leave every replica, while any artifact that
//! still holds the same bytes keeps them through a plain delete. A hard erase takes the bytes and
//! every reference to them off every replica (ARCH-0005a: HardErase pierces refcounting).

#![allow(clippy::unwrap_used)]

use loro::{ExportMode, LoroDoc, VersionVector};
use oneiron::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use oneiron::edge::EdgeActorClass;
use oneiron::edge::EdgeKind;
use oneiron::error::{ArtifactError, Error};
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_ASSET_TEXT, ENTITY_TYPE_PERSON};
use oneiron::sync::bridge::{encode_edge_value_for_crdt, format_edge_key};
use oneiron::sync::types::WindowKey;
use oneiron::sync::window;
use oneiron::{DeleteReason, EntityId, Vault, WriteActor};

use crate::sync_harness::{
    T0, TestNode, WINDOW, exchange, make_entity_blob, map_get_bytes, map_insert_bytes,
    sync_through_doors, time_range, vault_pair,
};

const UNIQUE: &[u8] = b"H125 bytes only the deleted artifact held";
const SHARED: &[u8] = b"H125 bytes two artifacts hold";
const PIERCED: &[u8] = b"ARCH-0005a bytes a hard erase takes from two artifacts";

/// A local artifact on `node` holding `versions` in order, mirrored into its window.
fn upload(node: &mut TestNode, at: u64, versions: &[&[u8]]) -> EntityId {
    let person = EntityId::now();
    node.vault
        .put_entity(&person, ENTITY_TYPE_PERSON, time_range(at), at, b"uploader")
        .unwrap();
    let actor = WriteActor::new(person, EdgeActorClass::Human);
    let artifact = EntityId::now();
    node.vault
        .put_blob_artifact(
            &artifact,
            &BlobArtifactBody::new("h125.bin", "application/octet-stream"),
            time_range(at),
            at,
        )
        .unwrap();
    for (n, bytes) in versions.iter().enumerate() {
        let learned = at + 1 + n as u64;
        node.vault
            .append_blob_artifact_version(
                &artifact,
                bytes,
                &BlobVersionProvenance::UserUpload,
                actor,
                time_range(learned),
                learned,
            )
            .unwrap();
    }
    node.recover(WINDOW);
    artifact
}

fn delete_artifact(node: &mut TestNode, artifact: &EntityId, reason: DeleteReason) {
    node.close_window(WINDOW);
    node.vault
        .delete_entity_with_reason(artifact, reason)
        .unwrap();
    node.recover(WINDOW);
}

/// The ASSET row whose body is exactly `bytes`.
fn asset_of(vault: &Vault, bytes: &[u8]) -> Option<EntityId> {
    vault
        .entities_in_learned_range(0, u64::MAX)
        .unwrap()
        .into_iter()
        .find(|id| {
            vault.get_raw(id).unwrap().is_some_and(|raw| {
                raw.first() == Some(&ENTITY_TYPE_ASSET) && raw.get(25..) == Some(bytes)
            })
        })
}

fn holds(node: &TestNode, asset: &EntityId) -> bool {
    node.vault.get_raw(asset).unwrap().is_some()
}

fn has_body(node: &TestNode, id: &EntityId) -> bool {
    node.vault
        .get_raw(id)
        .unwrap()
        .is_some_and(|raw| raw.len() > 25)
}

fn carries(node: &TestNode, asset: &EntityId) -> bool {
    node.doc(WINDOW)
        .get_map("entities")
        .get(&asset.to_hex())
        .is_some()
}

fn tombstoned(node: &TestNode, id: &EntityId) -> bool {
    node.doc(WINDOW)
        .get_map("tombstones")
        .get(&id.to_hex())
        .is_some()
}

fn reads_erased(node: &TestNode, artifact: &EntityId, version: u64) -> bool {
    matches!(
        node.vault.read_blob_artifact_version(artifact, version),
        Err(Error::Artifact(ArtifactError::BlobVersionErased))
    )
}

/// Bug repro (H125) and done-means: B holds A's artifact as a replica, with no version chain of
/// its own. A plain delete of the artifact on A must take the bytes only it held off B as well, and no
/// stale carrier may bring them back, whether a rematerialization reads it from the window or a
/// lagging peer puts it back; bytes another live artifact holds stay on both vaults until that
/// artifact goes too. Uploading the same bytes again afterwards still reaches B.
#[test]
fn a_deleted_artifact_takes_its_version_bytes_off_every_replica() {
    let (mut a, mut b) = vault_pair();
    let key = WindowKey::new(WINDOW);
    let deleted = upload(&mut a, T0, &[UNIQUE, SHARED]);
    exchange(&a, &b, WINDOW);
    let unique = asset_of(&a.vault, UNIQUE).expect("A stores the unique version");
    let shared = asset_of(&a.vault, SHARED).expect("A stores the shared version");
    assert!(
        holds(&b, &unique) && holds(&b, &shared),
        "the version bytes reach B"
    );
    let stale = map_get_bytes(&a.doc(WINDOW).get_map("entities"), &unique.to_hex())
        .expect("A's window carries the unique bytes");
    let own = upload(&mut b, T0 + 10, &[SHARED]);
    exchange(&a, &b, WINDOW);

    delete_artifact(&mut a, &deleted, DeleteReason::UserDelete);
    exchange(&a, &b, WINDOW);
    for node in [&a, &b] {
        assert!(
            !holds(node, &unique),
            "{}: bytes no live artifact holds are gone",
            node.name
        );
        assert!(
            holds(node, &shared),
            "{}: bytes B's live artifact holds stay",
            node.name
        );
    }

    // Each window still carries the dropped bytes until its export door runs: rematerializing
    // from that stale carrier does not bring them back.
    for node in [&a, &b] {
        assert!(carries(node, &unique), "{}: the stale carrier", node.name);
        window::forward_rematerialize(&node.vault, node.doc(WINDOW), &node.materializer, &key)
            .unwrap();
        assert!(
            !holds(node, &unique),
            "{}: rematerialization resurrected the deleted bytes",
            node.name
        );
    }

    // The export door takes the dropped carrier out of each live document.
    for node in [&a, &b] {
        window::export_window_updates_since(
            &node.vault,
            &key,
            node.doc(WINDOW),
            &VersionVector::default().encode(),
        )
        .unwrap();
    }
    exchange(&a, &b, WINDOW);
    for node in [&a, &b] {
        assert!(
            !carries(node, &unique),
            "{}: the window still carries the deleted bytes",
            node.name
        );
    }

    // A lagging peer that never saw the delete puts the carrier back: B still refuses it.
    let lagging = LoroDoc::new();
    lagging.set_peer_id(3).unwrap();
    lagging
        .import(&b.doc(WINDOW).export(ExportMode::all_updates()).unwrap())
        .unwrap();
    map_insert_bytes(&lagging.get_map("entities"), &unique.to_hex(), &stale);
    lagging.commit();
    let behind = b.doc(WINDOW).oplog_vv();
    b.doc(WINDOW)
        .import(&lagging.export(ExportMode::updates(&behind)).unwrap())
        .unwrap();
    assert!(carries(&b, &unique), "the lagging peer's carrier reached B");
    assert!(
        !holds(&b, &unique),
        "a lagging peer's stale carrier resurrected the deleted bytes"
    );
    exchange(&a, &b, WINDOW);
    assert!(
        !holds(&a, &unique),
        "the lagging carrier passed on to A resurrected the deleted bytes"
    );
    // The export doors take that carrier out again.
    for node in [&a, &b] {
        window::export_window_updates_since(
            &node.vault,
            &key,
            node.doc(WINDOW),
            &VersionVector::default().encode(),
        )
        .unwrap();
    }
    exchange(&a, &b, WINDOW);
    for node in [&a, &b] {
        assert!(
            !carries(node, &unique),
            "{}: the window still carries the lagging peer's copy",
            node.name
        );
    }

    // The last artifact holding the shared bytes goes on B while its window is closed, so B
    // persists and reloads the window: they leave both vaults, and A, which never saw B's
    // reload, still catches up through B's export door.
    delete_artifact(&mut b, &own, DeleteReason::UserHardDelete);
    sync_through_doors(&a, &mut b);
    assert!(!holds(&a, &shared) && !holds(&b, &shared));

    // Positive control: the same bytes uploaded again are a new reference, and they sync.
    upload(&mut a, T0 + 20, &[UNIQUE]);
    sync_through_doors(&a, &mut b);
    assert!(holds(&a, &unique));
    assert!(
        holds(&b, &unique),
        "a re-upload of deleted bytes reaches the replica"
    );
}

/// Done-means (ARCH-0005a, ARCH-0038 carrier 13): A and B each hold an artifact with the same
/// bytes. A hard erase of A's artifact takes the bytes and every reference to them off both
/// vaults, B's through the erase's tombstones, and B's version reads as erased. A lagging peer
/// that never saw the erase sends B's reference and the bytes again: neither vault takes them
/// back, the erase's tombstones still name both carriers, and the vaults still converge.
#[test]
fn a_hard_erase_takes_shared_bytes_and_every_reference_off_every_replica() {
    let (mut a, mut b) = vault_pair();
    let erased = upload(&mut a, T0, &[PIERCED]);
    let other = upload(&mut b, T0 + 10, &[PIERCED]);
    exchange(&a, &b, WINDOW);
    let asset = asset_of(&a.vault, PIERCED).expect("A stores the shared bytes");
    let reference = b
        .vault
        .blob_artifact_head(&other)
        .unwrap()
        .expect("B's artifact has a head")
        .claim_id;
    assert!(holds(&a, &asset) && holds(&b, &asset));
    assert!(has_body(&a, &reference), "B's reference reaches A");
    let entities = a.doc(WINDOW).get_map("entities");
    let stale = [asset, reference].map(|id| {
        let raw = map_get_bytes(&entities, &id.to_hex()).expect("A's window carries it");
        (id, raw)
    });

    delete_artifact(&mut a, &erased, DeleteReason::GdprDelete);
    exchange(&a, &b, WINDOW);
    for node in [&a, &b] {
        assert!(
            !holds(node, &asset),
            "{}: the shared bytes outlived the hard erase",
            node.name
        );
        assert!(
            !has_body(node, &reference),
            "{}: B's reference to the erased bytes kept its body",
            node.name
        );
    }
    assert!(
        reads_erased(&b, &other, 1),
        "B's version did not read as erased"
    );

    // A lagging peer that never saw the erase sends the reference and the bytes again.
    let lagging = LoroDoc::new();
    lagging.set_peer_id(3).unwrap();
    lagging
        .import(&b.doc(WINDOW).export(ExportMode::all_updates()).unwrap())
        .unwrap();
    for (id, raw) in &stale {
        map_insert_bytes(&lagging.get_map("entities"), &id.to_hex(), raw);
    }
    lagging.commit();
    let behind = b.doc(WINDOW).oplog_vv();
    b.doc(WINDOW)
        .import(&lagging.export(ExportMode::updates(&behind)).unwrap())
        .unwrap();
    exchange(&a, &b, WINDOW);
    for node in [&a, &b] {
        assert!(
            !holds(node, &asset),
            "{}: a re-sent reference brought the erased bytes back",
            node.name
        );
        assert!(
            !has_body(node, &reference),
            "{}: the re-sent reference",
            node.name
        );
    }
    assert!(
        reads_erased(&b, &other, 1),
        "B's version read as intact after the re-send"
    );

    // A peer one change behind still catches up, and each erased carrier the window still
    // holds is one the erase's tombstone names, so every vault refuses it.
    sync_through_doors(&a, &mut b);
    for node in [&a, &b] {
        for (id, _) in &stale {
            assert!(
                !carries(node, id) || tombstoned(node, id),
                "{}: the window hands on an erased carrier no tombstone names",
                node.name
            );
        }
    }
}

/// Done-means (Engine ruling on #1465, 10-15): B holds only its own artifact and never sees A's,
/// which holds the same bytes. A learns B's reference, then hard-erases its own artifact. The
/// erase tombstones B's reference and the bytes under its own request, so after sync B serves its
/// version as erased and holds no bytes, though no carrier of A's artifact ever reached it.
#[test]
fn a_hard_erase_reaches_a_replica_that_never_saw_the_erased_artifact() {
    let (mut a, mut b) = vault_pair();
    let key = WindowKey::new(WINDOW);
    let erased = upload(&mut a, T0, &[PIERCED]);
    let other = upload(&mut b, T0 + 10, &[PIERCED]);
    // One way only: A learns B's artifact, B learns nothing of A's.
    let window::WindowExport::Update(to_a) = window::export_window_updates_since(
        &b.vault,
        &key,
        b.doc(WINDOW),
        &a.doc(WINDOW).oplog_vv().encode(),
    )
    .unwrap() else {
        panic!("B's full window answers A with an update");
    };
    a.doc(WINDOW).import(&to_a).unwrap();
    let reference = b
        .vault
        .blob_artifact_head(&other)
        .unwrap()
        .expect("B's artifact has a head")
        .claim_id;
    assert!(has_body(&a, &reference), "B's reference reaches A");
    assert!(
        b.vault.get_raw(&erased).unwrap().is_none(),
        "A's artifact reached B before the erase"
    );
    let asset = asset_of(&b.vault, PIERCED).expect("B stores its bytes");

    delete_artifact(&mut a, &erased, DeleteReason::GdprDelete);
    for id in [reference, asset] {
        assert!(
            tombstoned(&a, &id),
            "the erase published no tombstone for a carrier it pierced"
        );
    }
    sync_through_doors(&a, &mut b);
    assert!(
        reads_erased(&b, &other, 1),
        "B's version did not read as erased"
    );
    assert!(!holds(&b, &asset), "B kept the erased bytes");
    assert!(
        b.vault.get_raw(&erased).unwrap().is_none(),
        "A's artifact reached B"
    );
}

/// Bug repro (#1465 R2, Engine ruling (b); Sol F4, Astra F2): a text derived from bytes a hard
/// erase took that reaches the erasing vault after the erase, with its DerivedFrom edge, goes
/// there as the erase's walk takes every derived text it finds.
#[test]
fn a_derived_text_arriving_after_the_erase_goes_with_the_bytes() {
    let (mut a, b) = vault_pair();
    let erased = upload(&mut a, T0, &[PIERCED]);
    let asset = asset_of(&a.vault, PIERCED).expect("A stores the bytes");
    delete_artifact(&mut a, &erased, DeleteReason::GdprDelete);
    let text = EntityId::now();
    b.put_entity_in_window(
        WINDOW,
        &text,
        &make_entity_blob(
            ENTITY_TYPE_ASSET_TEXT,
            T0 + 30,
            b"words from the erased bytes",
        ),
    );
    map_insert_bytes(
        &b.doc(WINDOW).get_map("edges"),
        &format_edge_key(&text, EdgeKind::DerivedFrom, &asset),
        &encode_edge_value_for_crdt(EdgeKind::DerivedFrom, 1.0, T0 + 30, None, None).unwrap(),
    );
    b.doc(WINDOW).commit();
    exchange(&a, &b, WINDOW);
    assert!(
        !has_body(&a, &text),
        "a late text derived from the erased bytes kept its words"
    );
}

/// Bug repro (#1465 R3, Sol 5; Astra 3; Engine ruling 2): a text derived from bytes a hard erase
/// took, whose DerivedFrom edge reaches the erasing vault in one update and its body in a later
/// one, goes there as it does when both arrive together: the edge leaves an obligation keyed by
/// the text's id, and the text's arrival is scrubbed and fenced at once.
#[test]
fn a_derived_text_arriving_after_its_edge_goes_with_the_bytes() {
    let (mut a, b) = vault_pair();
    let erased = upload(&mut a, T0, &[PIERCED]);
    let asset = asset_of(&a.vault, PIERCED).expect("A stores the bytes");
    delete_artifact(&mut a, &erased, DeleteReason::GdprDelete);
    let text = EntityId::now();
    map_insert_bytes(
        &b.doc(WINDOW).get_map("edges"),
        &format_edge_key(&text, EdgeKind::DerivedFrom, &asset),
        &encode_edge_value_for_crdt(EdgeKind::DerivedFrom, 1.0, T0 + 30, None, None).unwrap(),
    );
    b.doc(WINDOW).commit();
    exchange(&a, &b, WINDOW);
    b.put_entity_in_window(
        WINDOW,
        &text,
        &make_entity_blob(
            ENTITY_TYPE_ASSET_TEXT,
            T0 + 30,
            b"words from the erased bytes",
        ),
    );
    exchange(&a, &b, WINDOW);
    assert!(
        !has_body(&a, &text),
        "a text arriving after its edge kept the words of the erased bytes"
    );
}

/// Bug repro (#1465 R2, Astra F10; Engine ruling): a vault that erased an artifact before a
/// version B appended to it reached it learns those bytes from the reference that arrives later:
/// the artifact's version chain was recorded here, so its erase is typed evidence. It takes its
/// own references to the bytes then and tombstones them under the erase's request, so a third
/// vault holding only another reference to the bytes learns of the erase too.
#[test]
fn a_late_reference_carries_the_erase_to_a_vault_holding_only_another_reference() {
    let (mut a, mut b) = vault_pair();
    let mut c = TestNode::new("node-c", 3);
    c.open_window(WINDOW);
    let erased = upload(&mut a, T0, &[UNIQUE]);
    sync_through_doors(&a, &mut b);
    // B appends the bytes to A's artifact; A erases it before B's version reaches it.
    let person = EntityId::now();
    b.vault
        .put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            time_range(T0 + 5),
            T0 + 5,
            b"uploader",
        )
        .unwrap();
    let late = b
        .vault
        .append_blob_artifact_version(
            &erased,
            PIERCED,
            &BlobVersionProvenance::UserUpload,
            WriteActor::new(person, EdgeActorClass::Human),
            time_range(T0 + 6),
            T0 + 6,
        )
        .unwrap()
        .claim_id;
    upload(&mut a, T0 + 10, &[PIERCED]);
    let theirs = upload(&mut c, T0 + 20, &[PIERCED]);
    let asset = asset_of(&c.vault, PIERCED).expect("C stores its bytes");
    delete_artifact(&mut a, &erased, DeleteReason::GdprDelete);
    // B's version reaches A's window after the erase. (Through A's export door it would park:
    // the erase pins A's window history-free, and B's version depends on history before it.)
    let raw = b.vault.get_raw(&late).unwrap().expect("B's version");
    map_insert_bytes(&a.doc(WINDOW).get_map("entities"), &late.to_hex(), &raw);
    a.doc(WINDOW).commit();
    // The window's replay publishes what the late walk staged, as the host's tick would.
    a.recover(WINDOW);
    let value = map_get_bytes(&a.doc(WINDOW).get_map("tombstones"), &asset.to_hex())
        .expect("the late walk tombstoned the bytes' ASSET");
    // C, holding only its own reference, applies that tombstone.
    map_insert_bytes(
        &c.doc(WINDOW).get_map("tombstones"),
        &asset.to_hex(),
        &value,
    );
    c.doc(WINDOW).commit();
    assert!(
        reads_erased(&c, &theirs, 1),
        "a vault holding only another reference never learned of the erase"
    );
    assert!(!holds(&c, &asset), "C kept the erased bytes");
}

/// Acceptance (#1465 R2, Engine ruling on Astra F12): the erased artifact's own version reads as
/// any hard-deleted record's does, never as its bytes, and the bytes stay erased after a sync
/// round with a peer that still holds them under another reference.
#[test]
fn the_erased_artifacts_own_version_stays_gone_beside_a_peer_holding_the_bytes() {
    let (mut a, mut b) = vault_pair();
    let erased = upload(&mut a, T0, &[PIERCED]);
    let asset = asset_of(&a.vault, PIERCED).expect("A stores the bytes");
    upload(&mut b, T0 + 10, &[PIERCED]);
    delete_artifact(&mut a, &erased, DeleteReason::GdprDelete);
    exchange(&a, &b, WINDOW);
    a.recover(WINDOW);
    assert!(
        matches!(a.vault.read_blob_artifact_version(&erased, 1), Ok(None)),
        "the erased artifact's own version read as something"
    );
    assert!(!holds(&a, &asset), "a peer brought the erased bytes back");
}
