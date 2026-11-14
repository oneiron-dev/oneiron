//! An engine-control receipt stays with the change it records (FABLE-6916-1).
//! A knob table such as the projector policy restores live: a restore over the
//! live vault keeps the value the knob holds now. Its receipt (who changed
//! which knob, to what, and when) must stay with it, or the owner reads a knob
//! in force that no receipt explains.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test engine_control_receipts_survive_restore`.
#![cfg(oneiron_test_support)]

use oneiron::dreamer_wake::ProjectorPolicy;
use oneiron::federation::EngineControlActor;
use oneiron::test_doors::steward::{open_owner_carrier_vault, owner};
use oneiron::{Vault, VaultConfig};

/// A value the shipped projector default (one statement) never holds.
const MIN_NEW_STATEMENTS: u32 = 3;

#[test]
fn a_knob_change_after_the_checkpoint_keeps_its_receipt_through_a_restore_over_the_live_vault() {
    let directory = oneiron::test_support::restore_tempdir();
    let live = open_owner_carrier_vault(&directory.path().join("vault")).expect("owner vault");
    live.ensure_vault_key().expect("mint the vault data key");
    let key = live.checkpoint_key().expect("derive the checkpoint key");
    let image = directory.path().join("image");
    live.snapshot_checkpoint(&image, 100)
        .expect("snapshot before the change");

    let live_owner = owner(&live).expect("owner proof");
    let receipt = live
        .set_dreamer_projector_policy_by(
            EngineControlActor::Owner(&live_owner),
            ProjectorPolicy {
                min_new_statements: MIN_NEW_STATEMENTS,
            },
        )
        .expect("the owner sets the projector policy after the checkpoint");
    assert!(
        live.engine_control_changes(&live_owner)
            .expect("receipts on the live vault")
            .iter()
            .any(|(id, _)| *id == receipt),
        "the live vault lists the change's receipt"
    );

    let (copy, _) = Vault::restore_checkpoint_keeping_authority(
        &image,
        &key,
        &directory.path().join("restored"),
        VaultConfig::device(),
        &live,
        200,
    )
    .expect("restore the checkpoint over the live vault");
    assert_eq!(
        copy.dreamer_projector_policy()
            .expect("the copy's projector policy")
            .min_new_statements,
        MIN_NEW_STATEMENTS,
        "the projector policy restores live: the copy keeps the value in force now"
    );
    let copy_owner = owner(&copy).expect("owner proof on the copy");
    let receipts = copy
        .engine_control_changes(&copy_owner)
        .expect("receipts on the copy");
    let kept = receipts.iter().find(|(id, _)| *id == receipt);
    let Some((_, change)) = kept else {
        panic!(
            "the receipt of a knob change that stays in force must survive the restore; \
             the copy lists {} receipts",
            receipts.len()
        );
    };
    assert!(change.owner, "the kept receipt names the owner's act");
    assert_eq!(change.knob, "DREAMER_PROJECTOR_POLICY");
}
