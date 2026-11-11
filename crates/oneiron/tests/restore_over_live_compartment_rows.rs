//! Live restores compare refused families with the image's opened compartments.
//! Needs `test-support` for the temporary-directory helper and memory keystore.

#![cfg(feature = "test-support")]

use std::path::PathBuf;
use std::sync::Arc;

use oneiron::recovery::checkpoint::CheckpointKey;
use oneiron::registry::{ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

fn snapshot_live_vault() -> (tempfile::TempDir, Vault, PathBuf, CheckpointKey) {
    let directory = oneiron::test_support::restore_tempdir();
    let live = Vault::open(directory.path().join("vault"), VaultConfig::device())
        .expect("open a fresh device vault");
    live.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    live.ensure_vault_key().expect("mint the vault data key");
    let key = live.checkpoint_key().expect("derive the checkpoint key");
    let image = directory.path().join("image");
    live.snapshot_checkpoint(&image, 100)
        .expect("snapshot the seeded vault");
    (directory, live, image, key)
}

#[test]
fn restore_over_a_live_vault_with_no_refused_family_changed_goes_ahead() {
    let (directory, live, image, key) = snapshot_live_vault();
    live.put_entity(
        &EntityId::now(),
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"after the cut",
    )
    .expect("write ordinary content after the checkpoint");

    Vault::restore_checkpoint_keeping_authority(
        &image,
        &key,
        &directory.path().join("restored"),
        VaultConfig::device(),
        &live,
        200,
    )
    .expect("unchanged refused families must not block restoring over a live vault");
}

#[test]
fn restore_over_a_live_vault_names_only_the_compartmented_family_that_changed() {
    let (directory, live, image, key) = snapshot_live_vault();
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![(
            rmpv::Value::from("name"),
            rmpv::Value::from("restore comparison machine"),
        )]),
    )
    .expect("encode the machine body");
    live.put_entity(
        &EntityId::now(),
        ENTITY_TYPE_MACHINE,
        TimeRange { start: 1, end: 1 },
        1,
        &body,
    )
    .expect("add one machine identity after the checkpoint");

    let result = Vault::restore_checkpoint_keeping_authority(
        &image,
        &key,
        &directory.path().join("restored"),
        VaultConfig::device(),
        &live,
        200,
    );
    let Err(error) = result else {
        panic!("rolling back a machine identity must be refused");
    };
    let message = error.to_string();
    assert!(message.contains("machine identities"), "{message}");
    assert!(!message.contains("policy manifests"), "{message}");
    assert!(!message.contains("skill hub configuration"), "{message}");
}
