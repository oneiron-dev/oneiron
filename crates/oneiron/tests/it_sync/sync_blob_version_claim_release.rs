//! L9-44 (ARCH-0005a #erase-refcount-open, ASTRA-R2-002): the owner's delete of a live artifact's
//! lone `blob.version` claim runs as the release of the version it records (Engine ruling 13 Nov
//! 17:56), so a replica that first syncs after it never receives that version's bytes.
//!
//! Red on main: the delete takes the claim alone. The version and its bytes stay on the origin,
//! so the later replica receives the bytes with no claim naming them, and the artifact's later
//! delete there would leave them.

#![allow(clippy::unwrap_used)]

use loro::VersionVector;
use oneiron::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use oneiron::deletion::{LegalHoldEventKind, LegalHoldTarget};
use oneiron::edge::EdgeActorClass;
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::sync::types::WindowKey;
use oneiron::sync::window;
use oneiron::{DeleteReason, EntityId, Vault, WriteActor};

use crate::sync_harness::ENTITY_METADATA_HEADER_LEN;
use crate::sync_harness::{
    T0, TestNode, WINDOW, exchange, sync_through_doors, test_config, time_range, vault_pair,
};

const RELEASED: &[u8] = b"L9-44 bytes of the version whose claim the owner deletes";
const KEPT: &[u8] = b"L9-44 bytes of the version that stays";

/// A local artifact on `node` holding `versions` in order, mirrored into its window. Returns it
/// and its version claims.
fn upload(node: &mut TestNode, at: u64, versions: &[&[u8]]) -> (EntityId, Vec<EntityId>) {
    let person = EntityId::now();
    node.vault
        .put_entity(&person, ENTITY_TYPE_PERSON, time_range(at), at, b"uploader")
        .unwrap();
    let actor = WriteActor::new(person, EdgeActorClass::Human);
    let artifact = EntityId::now();
    node.vault
        .put_blob_artifact(
            &artifact,
            &BlobArtifactBody::new("l9-44.bin", "application/octet-stream"),
            time_range(at),
            at,
        )
        .unwrap();
    let mut claims = Vec::new();
    for (n, bytes) in versions.iter().enumerate() {
        let learned = at + 1 + n as u64;
        let version = node
            .vault
            .append_blob_artifact_version(
                &artifact,
                bytes,
                &BlobVersionProvenance::UserUpload,
                actor,
                time_range(learned),
                learned,
            )
            .unwrap();
        claims.push(version.claim_id);
    }
    node.recover(WINDOW);
    (artifact, claims)
}

/// Whether an ASSET row holding exactly `bytes` is stored in `vault`.
fn stores(vault: &Vault, bytes: &[u8]) -> bool {
    vault
        .entities_in_learned_range(0, u64::MAX)
        .unwrap()
        .into_iter()
        .any(|id| {
            vault.get_raw(&id).unwrap().is_some_and(|raw| {
                raw.first() == Some(&ENTITY_TYPE_ASSET)
                    && raw.get(ENTITY_METADATA_HEADER_LEN..) == Some(bytes)
            })
        })
}

/// [`vault_pair`] with a legal hold store outside each vault, for a case that
/// places a hold (LEGAL-HOLD-USE = B). The stores outlive the nodes.
fn vault_pair_with_hold_stores() -> (tempfile::TempDir, tempfile::TempDir, TestNode, TestNode) {
    let a_hold = tempfile::tempdir().unwrap();
    let b_hold = tempfile::tempdir().unwrap();
    let mut a = TestNode::with_config(
        "node-a",
        1,
        test_config().with_legal_hold_store(a_hold.path().to_path_buf()),
    );
    let mut b = TestNode::with_config(
        "node-b",
        2,
        test_config().with_legal_hold_store(b_hold.path().to_path_buf()),
    );
    a.open_window(WINDOW);
    b.open_window(WINDOW);
    (a_hold, b_hold, a, b)
}

/// Done-means (Engine 17:56): the owner's lone version-claim delete on A releases that version,
/// and B, which first syncs after it, receives the artifact and the other version but never the
/// released version's bytes.
#[test]
fn an_owner_version_claim_delete_leaves_no_bytes_for_a_later_replica() {
    let (mut a, b) = vault_pair();
    let key = WindowKey::new(WINDOW);
    let (artifact, claims) = upload(&mut a, T0, &[RELEASED, KEPT]);

    a.close_window(WINDOW);
    a.vault
        .delete_entity_with_reason(&claims[0], DeleteReason::UserHardDelete)
        .unwrap();
    a.recover(WINDOW);
    // A's export door takes a dropped carrier out of its live document before B first syncs.
    window::export_window_updates_since(
        &a.vault,
        &key,
        a.doc(WINDOW),
        &VersionVector::default().encode(),
    )
    .unwrap();
    exchange(&a, &b, WINDOW);

    assert!(
        b.vault.get_raw(&artifact).unwrap().is_some(),
        "the artifact reaches the later replica"
    );
    assert!(stores(&b.vault, KEPT), "the kept version's bytes reach it");
    assert!(
        !stores(&b.vault, RELEASED),
        "a replica that first syncs after the owner's delete received the released version's bytes"
    );
    assert!(
        !stores(&a.vault, RELEASED),
        "the origin kept the released version's bytes"
    );
    assert_eq!(
        a.vault.blob_artifact_versions(&artifact).unwrap().len(),
        1,
        "the version the deleted claim records was released on the origin"
    );
}

/// #7640 review round 1: the owner releases a version on B, a replica that received the artifact
/// and its claims but keeps no chain of its own, so only the claim's tombstone travels. A, the
/// uploader, replays it: its chain's version goes with the claim, as on the origin, and reading
/// that version answers nothing instead of a corrupted index.
///
/// Red at #7640's head 5d5d87c2ffa6: A purges the claim and keeps the version that names it, so
/// A still lists two versions and the released one's read fails `CorruptedIndex`.
#[test]
fn an_owner_release_on_a_replica_releases_the_uploaders_chain_version() {
    let (mut a, mut b) = vault_pair();
    let (artifact, claims) = upload(&mut a, T0, &[RELEASED, KEPT]);
    let released = a
        .vault
        .blob_artifact_versions(&artifact)
        .unwrap()
        .into_iter()
        .find(|version| version.claim_id == claims[0])
        .expect("fixture: the uploader's chain records the first version under its claim")
        .version;
    exchange(&a, &b, WINDOW);
    assert!(
        b.vault.get_raw(&claims[0]).unwrap().is_some(),
        "fixture: the replica received the version claim"
    );

    // B deletes with its window closed, so it persists and reloads the window; A, which never saw
    // that reload, catches up through B's export door, as a sync connection does.
    b.close_window(WINDOW);
    b.vault
        .delete_entity_with_reason(&claims[0], DeleteReason::UserHardDelete)
        .unwrap();
    b.recover(WINDOW);
    sync_through_doors(&a, &mut b);
    a.recover(WINDOW);

    assert!(
        a.vault.get_raw(&claims[0]).unwrap().is_none(),
        "fixture: the owner's release reached the uploader as the claim's tombstone"
    );
    let read = a.vault.blob_artifact_version_metadata(&artifact, released);
    assert!(
        matches!(read, Ok(None)),
        "the uploader's chain kept the released version without its claim: {read:?}"
    );
    assert_eq!(
        a.vault.blob_artifact_versions(&artifact).unwrap().len(),
        1,
        "the uploader still lists the version the owner released"
    );
    assert!(
        !stores(&a.vault, RELEASED),
        "the uploader kept the released version's bytes"
    );
    assert!(stores(&a.vault, KEPT), "the other version's bytes stay");
}

/// BLOB-VERSION-HELD-PURGE (Engine ruling 15 Nov 19:25) under LEGAL-HOLD-USE = B: the owner of
/// A, the uploader, holds the artifact. B, a replica, releases a version, so only the claim's
/// tombstone travels, and A's replay of it is not refused: the release takes the claim and the
/// version, while the hold keeps only its sealed copy outside the vault.
///
/// Red at #7640's head 1ad04d0f17e1: the replay refuses only a hold on the claim id itself, so it
/// purges the claim while the held artifact keeps the version, and reading that version answers
/// `CorruptedIndex`.
#[test]
fn a_held_artifact_releases_the_version_whose_claim_a_replica_releases() {
    let (_a_hold, _b_hold, mut a, mut b) = vault_pair_with_hold_stores();
    let (artifact, claims) = upload(&mut a, T0, &[RELEASED, KEPT]);
    let released = a
        .vault
        .blob_artifact_versions(&artifact)
        .unwrap()
        .into_iter()
        .find(|version| version.claim_id == claims[0])
        .expect("fixture: the uploader's chain records the first version under its claim")
        .version;
    exchange(&a, &b, WINDOW);
    assert!(
        b.vault.get_raw(&claims[0]).unwrap().is_some(),
        "fixture: the replica received the version claim"
    );
    let person = a.vault.ensure_embedded_owner_actor().unwrap();
    let owner = a
        .vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .unwrap();
    let hold = a
        .vault
        .place_legal_hold(&owner, vec![LegalHoldTarget::Record(artifact)], None)
        .unwrap();

    // As in the release test above: B deletes with its window closed, and A catches up through
    // B's export door.
    b.close_window(WINDOW);
    b.vault
        .delete_entity_with_reason(&claims[0], DeleteReason::UserHardDelete)
        .unwrap();
    b.recover(WINDOW);
    sync_through_doors(&a, &mut b);
    a.recover(WINDOW);

    assert!(
        b.vault.get_raw(&claims[0]).unwrap().is_none(),
        "fixture: the replica released the version claim"
    );
    let log = a.vault.legal_hold_log(&owner).unwrap();
    assert!(
        !log.iter().any(|event| event.hold_id == hold.hold_id
            && matches!(event.event, LegalHoldEventKind::DeleteRefused)),
        "a legal hold refuses no purge on the uploader: {log:?}"
    );
    assert!(
        a.vault.get_raw(&claims[0]).unwrap().is_none(),
        "the uploader's replay released the claim the hold covers"
    );
    let read = a.vault.blob_artifact_version_metadata(&artifact, released);
    assert!(
        matches!(read, Ok(None)),
        "the released version reads as absent on the uploader: {read:?}"
    );
    assert_eq!(
        a.vault.blob_artifact_versions(&artifact).unwrap().len(),
        1,
        "the uploader's chain released the version the hold covers"
    );
    assert!(
        !stores(&a.vault, RELEASED),
        "the uploader released the held version's bytes"
    );
    assert!(stores(&a.vault, KEPT), "the other version's bytes stay");
    assert!(
        a.vault
            .legal_holds(&owner)
            .unwrap()
            .iter()
            .any(|standing| standing.hold_id == hold.hold_id && standing.lifted_at.is_none()),
        "the hold still stands after the release"
    );
}

/// REVIEW-7640-NO-CHAIN-REPLICA-REPLAY: B, a replica, received the artifact, its claims and both
/// versions' bytes, and keeps no chain of its own. The owner then releases a version on A, the
/// uploader, so only the claim's tombstone travels, and B's replay of it takes the released
/// version's bytes there too, as the owner's release on a vault without the chain does (Engine
/// ruling 13 Nov 17:56: the release takes the claim and the bytes on every replica).
///
/// Red on main af6720cd74e8: B purges the claim alone and keeps its pair and the released
/// version's bytes.
#[test]
fn an_uploaders_release_takes_the_bytes_from_a_replica_that_holds_them() {
    let (mut a, mut b) = vault_pair();
    let (_artifact, claims) = upload(&mut a, T0, &[RELEASED, KEPT]);
    exchange(&a, &b, WINDOW);
    assert!(
        stores(&b.vault, RELEASED),
        "fixture: the replica received the released version's bytes"
    );

    // The release test above, mirrored: A deletes with its window closed, and B catches up
    // through A's export door.
    a.close_window(WINDOW);
    a.vault
        .delete_entity_with_reason(&claims[0], DeleteReason::UserHardDelete)
        .unwrap();
    a.recover(WINDOW);
    sync_through_doors(&b, &mut a);
    b.recover(WINDOW);

    assert!(
        !stores(&a.vault, RELEASED),
        "fixture: the owner's release took the bytes on the uploader"
    );
    assert!(
        b.vault.get_raw(&claims[0]).unwrap().is_none(),
        "fixture: the owner's release reached the replica as the claim's tombstone"
    );
    assert!(
        !stores(&b.vault, RELEASED),
        "the replica kept the released version's bytes after its claim's tombstone"
    );
    assert!(
        stores(&b.vault, KEPT),
        "the other version's bytes stay on the replica"
    );
}

/// REVIEW-7640-NO-CHAIN-REPLICA-REPLAY under BLOB-VERSION-HELD-PURGE (Engine ruling 15 Nov
/// 19:25), under LEGAL-HOLD-USE = B: the owner of B, a replica that keeps no chain, holds the
/// artifact. The uploader A releases a version, and B's replay of the claim's tombstone is not
/// refused: the release takes the claim and its bytes, while the hold keeps only its sealed copy
/// outside the vault.
///
/// Red on main af6720cd74e8: B's replay refuses only a hold on the claim id itself, so it purges
/// the claim of bytes its hold keeps.
#[test]
fn a_held_artifact_on_a_replica_releases_the_claim_whose_version_the_uploader_releases() {
    let (_a_hold, _b_hold, mut a, mut b) = vault_pair_with_hold_stores();
    let (artifact, claims) = upload(&mut a, T0, &[RELEASED, KEPT]);
    exchange(&a, &b, WINDOW);
    assert!(
        b.vault.get_raw(&claims[0]).unwrap().is_some(),
        "fixture: the replica received the version claim"
    );
    let person = b.vault.ensure_embedded_owner_actor().unwrap();
    let owner = b
        .vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .unwrap();
    let hold = b
        .vault
        .place_legal_hold(&owner, vec![LegalHoldTarget::Record(artifact)], None)
        .unwrap();

    // As in the test above: A deletes with its window closed, and B catches up through A's export
    // door.
    a.close_window(WINDOW);
    a.vault
        .delete_entity_with_reason(&claims[0], DeleteReason::UserHardDelete)
        .unwrap();
    a.recover(WINDOW);
    sync_through_doors(&b, &mut a);
    b.recover(WINDOW);

    assert!(
        a.vault.get_raw(&claims[0]).unwrap().is_none(),
        "fixture: the uploader released the version claim"
    );
    let log = b.vault.legal_hold_log(&owner).unwrap();
    assert!(
        !log.iter().any(|event| event.hold_id == hold.hold_id
            && matches!(event.event, LegalHoldEventKind::DeleteRefused)),
        "a legal hold refuses no purge on the replica: {log:?}"
    );
    assert!(
        b.vault.get_raw(&claims[0]).unwrap().is_none(),
        "the replica's replay released the claim the hold covers"
    );
    assert!(
        !stores(&b.vault, RELEASED),
        "the replica released the held version's bytes"
    );
    assert!(
        stores(&b.vault, KEPT),
        "the other version's bytes stay on the replica"
    );
    assert!(
        b.vault
            .legal_holds(&owner)
            .unwrap()
            .iter()
            .any(|standing| standing.hold_id == hold.hold_id && standing.lifted_at.is_none()),
        "the hold still stands after the release"
    );
}
