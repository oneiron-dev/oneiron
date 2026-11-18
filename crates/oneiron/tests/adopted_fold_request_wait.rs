//! FIX [STRANGER-GAP-STALLS-ADOPTED-TAIL-FOLD], #9476 review round 1 (P1): the
//! fold past an adopted image reads which tail rows this install believes.
//! Read through the store door's view, that belief resolved a wait a root
//! request committed (FIX 5582), and resolving such a wait reads the fold
//! itself, so on a vault that adopted an image every uncached fold recursed
//! until the stack overflowed. The fold now reads its belief under the pin
//! and the earlier admitter, a request's wait left unresolved.
//!
//! RED at b5a1e5f4 (the test thread overflows its stack, so the binary
//! aborts), GREEN with the fix.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test adopted_fold_request_wait`.
#![cfg(all(oneiron_test_support, feature = "sync", feature = "test-support"))]

use std::sync::Arc;

use oneiron::authority::{
    AuthorityCheckpointUnresolved, HostSlipIssuer, MachineRole, RecoveryRootId,
};
use oneiron::test_doors::authority_adopted_fold::await_root_for_request;
use oneiron::{Vault, VaultConfig};

/// A self-host vault as its own server starts one, this install profiled
/// under the host root.
fn served_self_host() -> (Vault, HostSlipIssuer, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("self-host vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("setup: this install's machine profile under the host root")
        .roster
        .expect("setup: this install has a roster chain");
    (vault, issuer, dir)
}

/// The vault adopts a checkpoint image of its own log, attested by the host
/// root.
fn adopt_own_checkpoint(vault: &Vault, issuer: &HostSlipIssuer) {
    let built = vault
        .build_authority_checkpoint_v2()
        .expect("setup: the held log builds a checkpoint image");
    assert_eq!(
        built.unresolved,
        AuthorityCheckpointUnresolved::default(),
        "setup: a clean log's image holds nothing back, so the vault can adopt it"
    );
    let image = vault
        .write_authority_checkpoint_v2(issuer)
        .expect("setup: the checkpoint image is kept");
    vault
        .host_attest_authority_checkpoint(issuer, image)
        .expect("setup: the host root attests the image");
    let pin = vault
        .authority_checkpoint_pin([7; 32])
        .expect("setup: the pin reads")
        .expect("setup: the attested image pins");
    let bundle = vault
        .authority_checkpoint_bundle(&image)
        .expect("setup: the bundle reads")
        .expect("setup: the kept image bundles");
    vault
        .adopt_authority_checkpoint(&pin, &bundle.image, &bundle.attestations)
        .expect("setup: the vault adopts its own image");
    assert!(
        vault
            .adopted_authority_checkpoint()
            .expect("setup: the adoption reads")
            .is_some(),
        "setup: the adoption stands"
    );
}

/// A wait a root request committed stands on a vault that adopted an image:
/// the fold past the image still reads. The wait's write moves the cache
/// generation, so the fold after it is uncached, as the reviewer's case
/// needs.
#[test]
fn adopted_fold_reads_with_a_request_owned_root_wait() {
    let (vault, issuer, _dir) = served_self_host();
    adopt_own_checkpoint(&vault, &issuer);
    assert!(
        vault.authority_fold().is_ok(),
        "guard: the adopted vault's fold reads before the wait"
    );
    await_root_for_request(&vault, RecoveryRootId([0x5A; 32]), [0xA5; 32])
        .expect("setup: the request's wait is written");
    assert!(
        vault.authority_fold().is_ok(),
        "the fold past the adopted image reads with a root request's wait standing"
    );
}
