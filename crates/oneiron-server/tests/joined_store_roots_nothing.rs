//! R6 1.5 (Engine P0 26 Nov 01:48, Sol claim iii): mel's first serve start, with an
//! `auth_secret`, rooted the store it had just joined. A joined store's authority log stays
//! empty until its first sync adopts the pin its enrolment record holds, so the start's
//! root-project signing (`commands::sign_root_project`) minted a Genesis of mel's own. kel then
//! could not verify mel's machine proofs, and sync, renewal and the checkpoint all failed.
//!
//! A store this install holds a device enrolment for is never rooted at a start. Both serve
//! paths withhold the start's `auth_secret` until the store's first sync, so neither the root
//! project's signature nor the server's host issuer bootstrap (`SyncServer::new`) roots it. A
//! store no enrolment names is rooted as before.
//!
//! Red: the guard taken out of `sign_root_project` (scratch branch); the first test fails.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --test joined_store_roots_nothing`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron_server::test_doors::root_project_signing::{
    fresh_store, sign_root_project, start_withholds_secret, write_join_record,
};

const SECRET: &str = "joined-store-roots-nothing-secret";

/// A store this install enrolled with its home, before its first sync, takes no root at a start
/// with a secret: its authority is its home's, and it arrives by sync.
#[test]
fn a_joined_store_takes_no_root_at_a_start_with_a_secret() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, config) = fresh_store(dir.path()).unwrap();
    let record = write_join_record(&config, &vault).unwrap();
    assert!(record.exists(), "the join's record stands");

    let _ = sign_root_project(&vault, &config, Some(SECRET));
    assert!(
        vault.authority_fold().unwrap().vault_id.is_none(),
        "no Genesis of the device's own"
    );
}

/// The same start on a store no enrolment names roots it, as an install's own first start does.
#[test]
fn a_store_no_enrolment_names_is_rooted_at_a_start_with_a_secret() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, config) = fresh_store(dir.path()).unwrap();

    let _ = sign_root_project(&vault, &config, Some(SECRET));
    assert!(
        vault.authority_fold().unwrap().vault_id.is_some(),
        "an install's own first start roots its store"
    );
}

/// A start on a joined store before its first sync withholds its secret, which keeps
/// `SyncServer::new` from bootstrapping a host issuer and a Genesis too (review round 1 of
/// #10532). A store no enrolment names keeps the secret, and so does a joined store whose log
/// holds authority.
#[test]
fn a_start_on_a_joined_store_withholds_its_secret_until_the_first_sync() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, config) = fresh_store(dir.path()).unwrap();
    assert!(
        !start_withholds_secret(&config, &vault),
        "no enrolment: the start keeps its secret"
    );
    write_join_record(&config, &vault).unwrap();
    assert!(
        start_withholds_secret(&config, &vault),
        "a joined store before its first sync: the start withholds its secret"
    );

    let rooted_dir = tempfile::tempdir().unwrap();
    let (rooted, rooted_config) = fresh_store(rooted_dir.path()).unwrap();
    let _ = sign_root_project(&rooted, &rooted_config, Some(SECRET));
    assert!(rooted.authority_fold().unwrap().vault_id.is_some());
    write_join_record(&rooted_config, &rooted).unwrap();
    assert!(
        !start_withholds_secret(&rooted_config, &rooted),
        "a store whose log holds authority keeps its secret"
    );
}
