//! A base agent's Steward grant never blocks a checkpoint restore (untangle
//! 6.3b; review of #6913). The grant row is a FEDERATION_GRANT, and that
//! family refuses a restore when it differs from the image. The host stands
//! the Dreamer's grant by default, so the first open after a checkpoint, and
//! every narrowing or grant back, made each earlier checkpoint
//! unrestorable: "restoring this checkpoint would roll back federation
//! grants changed since it was taken".
//!
//! Such a row is standing access, as an owner's agent grant is: it stays as
//! the live vault holds it, and its marker stays with it.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test steward_grant_restore`.
#![cfg(oneiron_test_support)]

use oneiron::test_doors::steward::{
    GrantMark, STEWARD_VERBS, dreamer, grant_mark, open_owner_carrier_vault, stand_steward_grant,
};
use oneiron::{Vault, VaultConfig};

#[test]
fn a_steward_grant_stood_after_a_checkpoint_does_not_block_its_restore() {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = dir.path().join("vault");
    std::fs::create_dir_all(&home).expect("vault dir");
    let live = open_owner_carrier_vault(&home).expect("owner carrier vault");
    // The Dreamer's principal and the checkpoint key are there before the
    // checkpoint, so the grant is the one thing that changes after it.
    let dreamer = dreamer(&live).expect("the Dreamer");
    let key = live.checkpoint_key().expect("the checkpoint key");
    let image = dir.path().join("backup");
    live.snapshot_checkpoint(&image, 100).expect("a checkpoint");

    let grant = stand_steward_grant(&live, dreamer, &STEWARD_VERBS).expect("the grant stands");
    let mark = grant_mark(&live, dreamer).expect("mark");
    assert!(
        matches!(&mark, Some(GrantMark::Minted { grant: marked, .. }) if *marked == grant),
        "the grant stands after the checkpoint: {mark:?}"
    );

    let (restored, _) = Vault::restore_checkpoint_keeping_authority(
        &image,
        &key,
        &dir.path().join("restored"),
        VaultConfig::device(),
        &live,
        200,
    )
    .expect("a Steward grant stood since the checkpoint does not block its restore");
    assert_eq!(
        grant_mark(&restored, dreamer).expect("mark"),
        mark,
        "the restored vault holds the grant and its marker as the live vault does"
    );
}
