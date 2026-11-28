//! Fable design pass 31, section 2, case 59 over sync readmission (review 2 of stack #10318,
//! P2-1): a fact born on a replica from an ASSET whose bytes that replica no longer holds waits
//! on the ASSET. When the same bytes are uploaded again on the origin, the replica readmits the
//! ASSET as its carrier comes in (H125), and the fact takes the ASSET's floor at the landing:
//! it is never sealed. The local upload of the same bytes is pinned in `read_lineage_floor`
//! (`a_fact_waiting_on_released_bytes_takes_their_floor_when_the_same_bytes_are_uploaded_again`).
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test it_sync -- read_lineage_asset_readmit`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used)]

use oneiron::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use oneiron::edge::EdgeActorClass;
use oneiron::provenance::made_by::{
    MadeBy, MadeByClass, MadeByInput, MadeByInputRole, MadeByProcess,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::test_doors::house_link::put_claim_made_by;
use oneiron::test_doors::read_lineage_floor::{asset_id_of, floor_sealed, floor_waits};
use oneiron::test_doors::source_audience_binding::{bound_row_read_by, reads};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, DeleteReason,
    EntityId, WriteActor,
};

use crate::sync_harness::{
    T0, TestNode, WINDOW, exchange, sync_through_doors, time_range, vault_pair,
};

const BYTES: &[u8] = b"read_lineage_asset_readmit: bytes the replica released, uploaded again";

/// A local artifact on `node` holding `bytes`, mirrored into its window. Returns the artifact
/// and the id of the ASSET that holds the bytes: the same bytes always land at the same id.
fn upload(node: &mut TestNode, at: u64, bytes: &[u8]) -> (EntityId, EntityId) {
    let person = EntityId::now();
    node.vault
        .put_entity(&person, ENTITY_TYPE_PERSON, time_range(at), at, b"uploader")
        .unwrap();
    let artifact = EntityId::now();
    node.vault
        .put_blob_artifact(
            &artifact,
            &BlobArtifactBody::new("read_lineage_asset_readmit.bin", "application/octet-stream"),
            time_range(at),
            at,
        )
        .unwrap();
    let version = node
        .vault
        .append_blob_artifact_version(
            &artifact,
            bytes,
            &BlobVersionProvenance::UserUpload,
            WriteActor::new(person, EdgeActorClass::Human),
            time_range(at + 1),
            at + 1,
        )
        .unwrap();
    node.recover(WINDOW);
    (artifact, asset_id_of(&version.content_hash).unwrap())
}

fn delete_artifact(node: &mut TestNode, artifact: &EntityId) {
    node.close_window(WINDOW);
    node.vault
        .delete_entity_with_reason(artifact, DeleteReason::UserHardDelete)
        .unwrap();
    node.recover(WINDOW);
}

/// An open CLAIM about `owner`, stated by the user, whose birth names `inputs` as its evidence,
/// stamped in a local write on `node` at `at`.
fn claim_born_from(node: &TestNode, owner: EntityId, inputs: &[EntityId], at: u64) -> EntityId {
    let mut body = ClaimBody::new(
        "profile.preference",
        ClaimSubject::Entity(owner),
        rmpv::Value::from("learnt from the mailbox and the released bytes"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .unwrap();
    body.source = Some(ClaimSource::UserStated);
    let made_by = MadeBy {
        inputs: inputs
            .iter()
            .map(|row| MadeByInput {
                row: *row,
                role: MadeByInputRole::Input,
            })
            .collect(),
        process: MadeByProcess {
            actor: owner,
            class: MadeByClass::Stated,
            identity: "read_lineage_asset_readmit.fixture".to_owned(),
            version: "1".to_owned(),
            params_hash: "0".repeat(64),
        },
        at,
        trigger: None,
    };
    let id = EntityId::now();
    put_claim_made_by(&node.vault, id, &body, made_by).unwrap();
    id
}

/// Case 59 over sync readmission: A uploads the bytes and B receives them; A's delete of the
/// last artifact holding them takes them off B. B's owner then writes a fact learnt from a
/// mailbox of B's and from that ASSET, so it waits on the ASSET. A uploads the same bytes again
/// and B readmits the ASSET as its carrier comes in: the fact takes its floor, reads to the
/// mailbox's reader and to no stranger, and is never sealed.
#[test]
fn a_fact_waiting_on_bytes_a_replica_released_takes_their_floor_when_sync_readmits_them() {
    let (mut a, mut b) = vault_pair();
    let (first, asset) = upload(&mut a, T0, BYTES);
    exchange(&a, &b, WINDOW);
    assert!(
        b.vault.get_raw(&asset).unwrap().is_some(),
        "precondition: the bytes reach B",
    );
    delete_artifact(&mut a, &first);
    exchange(&a, &b, WINDOW);
    assert!(
        b.vault.get_raw(&asset).unwrap().is_none(),
        "precondition: the delete of their last artifact takes the bytes off B",
    );

    let owner = b.vault.ensure_embedded_owner_actor().unwrap();
    let reader = EntityId::now();
    let stranger = EntityId::now();
    let mailbox = EntityId::now();
    bound_row_read_by(&b.vault, mailbox, &[owner, reader]).unwrap();
    let fact = claim_born_from(&b, owner, &[mailbox, asset], T0 + 10);
    assert!(
        floor_waits(&b.vault, fact).unwrap(),
        "precondition: a fact born from bytes B no longer holds waits until they return",
    );

    let (_again, readmitted) = upload(&mut a, T0 + 20, BYTES);
    assert_eq!(
        readmitted, asset,
        "precondition: the same bytes land at the same ASSET",
    );
    sync_through_doors(&a, &mut b);
    assert!(
        b.vault.get_raw(&asset).unwrap().is_some(),
        "precondition: B readmits the ASSET whose bytes were uploaded again",
    );
    assert!(
        !floor_sealed(&b.vault, fact).unwrap(),
        "SEALED: the readmission of the same bytes sealed a fact that waited on them",
    );
    assert!(
        !floor_waits(&b.vault, fact).unwrap(),
        "the fact still waits on an ASSET whose bytes B readmitted",
    );
    assert!(
        reads(&b.vault, fact, &[reader]).unwrap(),
        "the mailbox's reader does not read a fact whose sources are all here",
    );
    assert!(
        !reads(&b.vault, fact, &[stranger]).unwrap(),
        "LEAK: a stranger reads a fact learnt from the mailbox",
    );
}
