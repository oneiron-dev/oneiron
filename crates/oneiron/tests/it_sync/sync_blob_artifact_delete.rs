//! H125: a deleted blob artifact's version bytes leave every replica, while any artifact that
//! still holds the same bytes keeps them.

#![allow(clippy::unwrap_used)]

use loro::{ExportMode, LoroDoc, VersionVector};
use oneiron::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use oneiron::edge::EdgeActorClass;
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_PERSON};
use oneiron::sync::types::WindowKey;
use oneiron::sync::window;
use oneiron::{DeleteReason, EntityId, Vault, WriteActor};

use crate::sync_harness::{
    T0, TestNode, WINDOW, exchange, map_get_bytes, map_insert_bytes, time_range, vault_pair,
};

const UNIQUE: &[u8] = b"H125 bytes only the deleted artifact held";
const SHARED: &[u8] = b"H125 bytes two artifacts hold";

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

fn delete_artifact(node: &mut TestNode, artifact: &EntityId) {
    node.close_window(WINDOW);
    node.vault
        .delete_entity_with_reason(artifact, DeleteReason::UserHardDelete)
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

fn carries(node: &TestNode, asset: &EntityId) -> bool {
    node.doc(WINDOW)
        .get_map("entities")
        .get(&asset.to_hex())
        .is_some()
}

/// Bug repro (H125) and done-means: B holds A's artifact as a replica, with no version chain of
/// its own. Deleting the artifact on A must take the bytes only it held off B as well, and no
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

    delete_artifact(&mut a, &deleted);
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
    // The export doors take that carrier out again. Each scrub pins its window history-free, so
    // both vaults exchange the scrubs before B's window closes: a peer behind a history-free
    // window needs a full re-bootstrap, which plain updates cannot give it.
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

    // The last artifact holding the shared bytes goes on B: they leave both vaults.
    delete_artifact(&mut b, &own);
    exchange(&a, &b, WINDOW);
    assert!(!holds(&a, &shared) && !holds(&b, &shared));

    // Positive control: the same bytes uploaded again are a new reference, and they sync.
    upload(&mut a, T0 + 20, &[UNIQUE]);
    exchange(&a, &b, WINDOW);
    assert!(holds(&a, &unique));
    assert!(
        holds(&b, &unique),
        "a re-upload of deleted bytes reaches the replica"
    );
}
