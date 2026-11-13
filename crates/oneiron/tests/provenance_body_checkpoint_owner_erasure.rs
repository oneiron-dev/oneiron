#![cfg(oneiron_test_support)]

//! Checkpoint body metadata follows its attachment occurrence's erasure.

use std::path::PathBuf;

use oneiron::deletion::DeleteReason;
use oneiron::provenance::body::{BodyState, OwnedBody};
use oneiron::recovery::checkpoint::{CheckpointKey, RestoreReason};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::test_doors::provenance_body_checkpoint as doors;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

const BODY_BYTES: &[u8] = b"benign checkpoint attachment body\n";
const RESULT_PATH: &str = "checkpoint/body";

struct BodyCheckpoint {
    directory: tempfile::TempDir,
    vault: Vault,
    image: PathBuf,
    key: CheckpointKey,
    body: OwnedBody,
}

fn snapshot_owned_body() -> BodyCheckpoint {
    let directory = oneiron::test_support::restore_tempdir();
    let vault = Vault::open(directory.path().join("vault"), VaultConfig::device())
        .expect("open a fresh device vault");
    doors::install_memory_keystore(&vault);
    vault.ensure_vault_key().expect("mint the vault data key");

    let owner = EntityId::now();
    vault
        .put_entity(
            &owner,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"checkpoint body owner",
        )
        .expect("create the body's owning entity");
    let output = doors::publish_owned_result(&vault, owner, RESULT_PATH, BODY_BYTES)
        .expect("publish a real complete owned result");
    let bodies = vault.owned_bodies(&owner).expect("read the owned bodies");
    assert_eq!(bodies.len(), 1, "the owner holds exactly one body");
    let body = bodies.into_iter().next().expect("one owned body");
    assert_eq!(body.owner, owner);
    let BodyState::Complete { body: held } = &body.state else {
        panic!("the published body must be complete: {:?}", body.state);
    };
    assert_eq!(held.blake3, output.raw_blake3);
    assert_eq!(held.bytes, output.raw_len);
    assert_eq!(
        vault
            .get_code_run_raw_output(&output)
            .expect("read the result"),
        Some(BODY_BYTES.to_vec()),
        "the real sink stored the fixture's benign bytes"
    );
    assert_eq!(
        doors::live_holder(&vault, &held.blake3, body.occurrence)
            .expect("read the live digest holder"),
        Some(owner),
        "the publisher must write the holder before the cut"
    );

    let key = vault.checkpoint_key().expect("derive the checkpoint key");
    let image = directory.path().join("image");
    vault
        .snapshot_checkpoint(&image, 100)
        .expect("snapshot the vault with its complete owned body");
    BodyCheckpoint {
        directory,
        vault,
        image,
        key,
        body,
    }
}

impl BodyCheckpoint {
    fn digest(&self) -> [u8; 32] {
        self.body
            .state
            .held()
            .expect("the fixture is complete")
            .blake3
    }

    fn erase_owner(&self) {
        let outcome = self
            .vault
            .delete_entity_with_reason(&self.body.owner, DeleteReason::OwnerErase)
            .expect("erase the owner after the cut");
        assert!(outcome.existed, "the fixture owner existed before erase");
        assert!(
            self.vault
                .owned_bodies(&self.body.owner)
                .expect("read the live descriptors after erase")
                .is_empty(),
            "live OwnerErase must remove the owner's descriptor"
        );
        assert_eq!(
            doors::live_holder(&self.vault, &self.digest(), self.body.occurrence)
                .expect("read the live holder after erase"),
            None,
            "live OwnerErase must remove the digest holder"
        );
    }

    fn open_restored_checkpoint(&self) -> Vault {
        let destination = self.directory.path().join("restored");
        let (restored, _) = Vault::restore_checkpoint(
            &self.image,
            &self.key,
            &destination,
            VaultConfig::device(),
            RestoreReason::Restore,
            200,
        )
        .expect("restore the earlier cut into a fresh directory");
        drop(restored);
        Vault::open(&destination, VaultConfig::device())
            .expect("reopen the restored vault's persisted rows")
    }
}

#[test]
fn owner_erase_leaves_no_body_descriptor_or_holder_in_an_earlier_cut() {
    let checkpoint = snapshot_owned_body();
    checkpoint.erase_owner();

    let descriptor_key = doors::descriptor_key(checkpoint.body.owner, checkpoint.body.occurrence);
    let holder_key = doors::holder_key(checkpoint.digest(), checkpoint.body.occurrence);
    let rows = doors::raw_checkpoint_body_rows(&checkpoint.image, &checkpoint.key)
        .expect("decode the original cut's raw body metadata without restoring");
    for (key, _) in rows {
        assert_ne!(
            key, descriptor_key,
            "PROVENANCE_BODY descriptor key found in the earlier cut: {key:02x?}"
        );
        assert_ne!(
            key, holder_key,
            "PROVENANCE_BODY_DIGEST holder key found in the earlier cut: {key:02x?}"
        );
    }
}

#[test]
fn a_cut_restores_its_body_descriptor_and_holder() {
    let checkpoint = snapshot_owned_body();
    let before_cut = vec![checkpoint.body.clone()];
    let restored = checkpoint.open_restored_checkpoint();

    assert_eq!(
        restored
            .owned_bodies(&checkpoint.body.owner)
            .expect("read the restored descriptors"),
        before_cut,
        "the cut must preserve the complete descriptor unchanged"
    );
    assert_eq!(
        doors::live_holder(&restored, &checkpoint.digest(), checkpoint.body.occurrence)
            .expect("read the restored holder"),
        Some(checkpoint.body.owner),
        "the cut must restore the digest holder"
    );
}

#[test]
fn a_cut_restored_after_owner_erase_brings_back_no_body_descriptor() {
    let checkpoint = snapshot_owned_body();
    checkpoint.erase_owner();
    let restored = checkpoint.open_restored_checkpoint();

    assert!(
        restored
            .owned_bodies(&checkpoint.body.owner)
            .expect("read the restored descriptors after erase")
            .is_empty(),
        "an earlier cut must not restore the erased owner's descriptor, even incomplete"
    );
    assert_eq!(
        doors::live_holder(&restored, &checkpoint.digest(), checkpoint.body.occurrence)
            .expect("read the restored holder after erase"),
        None,
        "an earlier cut must not restore the erased occurrence's holder"
    );
}
