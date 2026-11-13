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
use oneiron::edge::EdgeActorClass;
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_PERSON};
use oneiron::sync::types::WindowKey;
use oneiron::sync::window;
use oneiron::{DeleteReason, EntityId, Vault, WriteActor};

use crate::sync_harness::ENTITY_METADATA_HEADER_LEN;
use crate::sync_harness::{T0, TestNode, WINDOW, exchange, time_range, vault_pair};

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
