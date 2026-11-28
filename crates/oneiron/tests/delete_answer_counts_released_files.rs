//! H5R1 T11–T12: an independently held body file is not listed as pending
//! collection, and a hard delete returns the FILE digest it released.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test delete_answer_counts_released_files`.
#![cfg(all(unix, oneiron_test_support))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::compaction::output::{restore_output, store_output};
use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::DeleteReason;
use oneiron::provenance::body::BodyLocation;
use oneiron::registry::ENTITY_TYPE_ASSET;
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;

fn rooted(dir: &tempfile::TempDir) -> (Vault, AuthenticatedOwner) {
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("the owner's proof");
    // The first large put primes the body-instance pool, as in archive_axes_job.rs.
    put_asset(
        &vault,
        &over_inline("a priming line for the body instance pool "),
    );
    (vault, proof)
}

fn over_inline(line: &str) -> Vec<u8> {
    line.repeat(8 * 1024 * 1024 / line.len() + 2).into_bytes()
}

fn put_asset(vault: &Vault, bytes: &[u8]) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_ASSET,
            TimeRange { start: 1, end: 1 },
            1,
            bytes,
        )
        .expect("put the ASSET");
    id
}

fn file_digest(vault: &Vault, id: &EntityId) -> [u8; 32] {
    let bodies = vault.owned_bodies(id).expect("read the ASSET's bodies");
    assert_eq!(bodies.len(), 1, "the ASSET owns one descriptor");
    let held = bodies[0].state.held().expect("the descriptor holds a body");
    assert_eq!(
        held.location,
        BodyLocation::File,
        "the ASSET body is a FILE"
    );
    held.blake3
}

#[test]
fn a_file_a_raw_output_also_holds_is_not_listed_as_still_in_use() {
    let dir = tempfile::tempdir().expect("vault dir");
    let (vault, owner) = rooted(&dir);
    for (reason, line) in [
        (
            DeleteReason::UserHardDelete,
            "file body for owner hard delete ",
        ),
        (DeleteReason::UserDelete, "file body for owner soft delete "),
    ] {
        let bytes = over_inline(line);
        let asset = put_asset(&vault, &bytes);
        let digest = file_digest(&vault, &asset);
        let raw = store_output(&vault, &bytes).expect("store an independent raw output");
        assert_eq!(
            raw.hash, digest,
            "the raw output and ASSET share the digest"
        );

        let (outcome, remaining) = vault
            .delete_entity_as_owner_with_remaining(&owner, &asset, reason)
            .expect("the owner deletes the ASSET");
        assert!(outcome.existed, "the owner delete applied: {reason:?}");
        assert!(
            !remaining
                .iter()
                .any(|entry| entry.code == "files_still_in_use"),
            "the owner delete does not list the file: {reason:?}, {remaining:?}"
        );

        // The hard purge lifts the raw hold when the last descriptor goes.
        // The soft writer leaves it in place, so this case catches Fix B.
        if reason == DeleteReason::UserDelete {
            assert_eq!(outcome.released_file_digests, vec![digest]);
            let restored = restore_output(&vault, raw).expect("the raw output still owns its file");
            assert!(restored == bytes, "the raw output still reads the body");
        }
    }
}

#[test]
fn the_released_file_digests_come_from_the_delete_writer() {
    let dir = tempfile::tempdir().expect("vault dir");
    let (vault, owner) = rooted(&dir);
    let asset = put_asset(
        &vault,
        &over_inline("the delete writer releases this file "),
    );
    let digest = file_digest(&vault, &asset);

    let (outcome, _) = vault
        .delete_entity_as_owner_with_remaining(&owner, &asset, DeleteReason::UserHardDelete)
        .expect("the owner hard-deletes the ASSET");
    assert_eq!(outcome.released_file_digests, vec![digest]);
}
