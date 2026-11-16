//! A declared hosted custody member this build has no adapter for (a
//! `backup.custody_targets` member, `DeclaredTarget`) never takes a head and
//! never acknowledges one, so every publication pass owed it a head, and
//! every pass (the serve loop runs one each 60 s) sealed a fresh hosted head
//! that nothing took (FIX 5847). A pass now seals no head that only such a
//! member is owed, and still records its `no_adapter` answer.
//!
//! The test keeps one device-only secret in custody, runs a first pass (the
//! folder member takes its head, the hosted member stays pending), then
//! times `PASSES` more passes and prints their mean: on main each one seals
//! a hosted head, with the fix none does. Every pass answers the first
//! pass's status: pending on the hosted member at the same log position.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test custody_no_adapter_member_pass`
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use oneiron::authority::MachineRole;
use oneiron::consent::AuthenticatedOwner;
use oneiron::secret_custody::{
    CustodyClass, CustodyTier, OwnerSecretRegistration, RequestedBinding,
};
use oneiron::store::GateDecisionId;
use oneiron::store::custody_protocol::TargetSpec;
use oneiron::{Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use serde_json::Value;

const HOSTED: &str = "s3:offsite";
const CUSTODY_AT: u64 = 1_780_000_000;
/// Timed passes after the first.
const PASSES: u32 = 40;

/// A rooted vault as a host starts one: the owner bound, this install
/// profiled. Its directory, the vault and the owner's proof.
fn rooted() -> (tempfile::TempDir, Vault, AuthenticatedOwner) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    vault.install_device_keystore(Arc::new(MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof");
    (dir, vault, proof)
}

/// One device-only secret, so this install keeps a custody journal.
fn keep_a_secret(vault: &Vault, proof: &AuthenticatedOwner) {
    vault
        .register_secret_as_owner(
            proof,
            &OwnerSecretRegistration {
                name: "deploy-key",
                class: CustodyClass::CustodyPortable,
                device_only: true,
                rung: CustodyTier::T1Leased,
                bindings: vec![RequestedBinding {
                    effector: "deploy".to_owned(),
                    tier_ceiling: None,
                    scopes: vec!["read".to_owned()],
                }],
                manifest: None,
                value: b"fixture-value",
            },
            CUSTODY_AT,
        )
        .expect("the owner registers a secret");
}

/// One publication pass over the folder member and the declared hosted
/// member, its status as JSON.
fn pass(vault: &Vault, folder: &Path) -> Value {
    let hosted = TargetSpec::declared(HOSTED).expect("a declared hosted member");
    let status = vault
        .publish_custody(folder, &[hosted], None)
        .expect("a publication pass");
    serde_json::to_value(&status).expect("status as JSON")
}

#[test]
fn a_no_adapter_member_leaves_every_pass_status_unchanged() {
    let (dir, vault, proof) = rooted();
    keep_a_secret(&vault, &proof);
    let folder = dir.path().join("custody-folder");
    std::fs::create_dir_all(&folder).expect("the custody folder");

    let first = pass(&vault, &folder);
    assert_eq!(
        first["state"], "custody_target_pending",
        "the hosted member keeps the custody pending: {first}"
    );
    assert!(
        first["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains(HOSTED)),
        "the status names the hosted member as behind: {first}"
    );
    assert!(
        first["log_seq"].as_u64().is_some(),
        "the pass names its log position: {first}"
    );

    let started = Instant::now();
    for index in 0..PASSES {
        let status = pass(&vault, &folder);
        assert_eq!(
            status,
            first,
            "pass {} answers the first pass's status",
            index + 2
        );
    }
    let elapsed = started.elapsed();
    println!(
        "FIX5847-PASSES passes={PASSES} total_ms={:.1} mean_ms={:.2}",
        elapsed.as_secs_f64() * 1000.0,
        elapsed.as_secs_f64() * 1000.0 / f64::from(PASSES)
    );
    println!("FIX5847-STATUS {first}");
}
