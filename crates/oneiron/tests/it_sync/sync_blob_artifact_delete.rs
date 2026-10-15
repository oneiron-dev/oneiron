//! H125: a deleted blob artifact's version bytes leave every replica, while any artifact that
//! still holds the same bytes keeps them through a plain delete. A hard erase takes the bytes and
//! every reference to them off every replica (ARCH-0005a: HardErase pierces refcounting).

#![allow(clippy::unwrap_used)]

use loro::{ExportMode, LoroDoc, VersionVector};
use oneiron::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use oneiron::edge::EdgeActorClass;
use oneiron::error::{ArtifactError, Error};
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_PERSON};
use oneiron::sync::types::WindowKey;
use oneiron::sync::window;
use oneiron::{DeleteReason, EntityId, Vault, WriteActor};

use crate::sync_harness::{
    T0, TestNode, WINDOW, exchange, map_get_bytes, map_insert_bytes, time_range, vault_pair,
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

/// Brings both windows level the way a sync connection does: each side answers the other's
/// version vector through the window export door, and the other imports that reply. Panics if
/// either side is still behind after five rounds, the bound past which ARCH-0023b re-bootstraps.
fn sync_through_doors(a: &TestNode, b: &TestNode) {
    let key = WindowKey::new(WINDOW);
    for _ in 0..5 {
        let (vv_a, vv_b) = (a.doc(WINDOW).oplog_vv(), b.doc(WINDOW).oplog_vv());
        if vv_a == vv_b {
            return;
        }
        let to_b =
            window::export_window_updates_since(&a.vault, &key, a.doc(WINDOW), &vv_b.encode())
                .unwrap();
        b.doc(WINDOW).import(&to_b).unwrap();
        let to_a =
            window::export_window_updates_since(&b.vault, &key, b.doc(WINDOW), &vv_a.encode())
                .unwrap();
        a.doc(WINDOW).import(&to_a).unwrap();
    }
    assert_eq!(
        a.doc(WINDOW).oplog_vv(),
        b.doc(WINDOW).oplog_vv(),
        "a peer behind the other's window never caught up through its export door"
    );
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
    sync_through_doors(&a, &b);
    assert!(!holds(&a, &shared) && !holds(&b, &shared));

    // Positive control: the same bytes uploaded again are a new reference, and they sync.
    upload(&mut a, T0 + 20, &[UNIQUE]);
    sync_through_doors(&a, &b);
    assert!(holds(&a, &unique));
    assert!(
        holds(&b, &unique),
        "a re-upload of deleted bytes reaches the replica"
    );
}

/// Done-means (ARCH-0005a, ARCH-0038 carrier 13): A and B each hold an artifact with the same
/// bytes. A hard erase of A's artifact takes the bytes and every reference to them off both
/// vaults, B's through the erase's tombstone, and B's version reads as erased. A lagging peer that
/// never saw the erase sends B's reference and the bytes again: neither vault takes them back, and
/// the export doors drop both carriers without pinning a window, so the vaults still converge.
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
    let erased_read = |node: &TestNode| {
        matches!(
            node.vault.read_blob_artifact_version(&other, 1),
            Err(Error::Artifact(ArtifactError::BlobVersionErased))
        )
    };
    assert!(erased_read(&b), "B's version did not read as erased");

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
        erased_read(&b),
        "B's version read as intact after the re-send"
    );

    // The export doors take both carriers out, and a peer one change behind still catches up.
    sync_through_doors(&a, &b);
    for node in [&a, &b] {
        for (id, _) in &stale {
            assert!(
                !carries(node, id),
                "{}: the window still carries an erased carrier",
                node.name
            );
        }
    }
}
