//! R6 1.5 (Engine P0 26 Nov 01:48, Sol claim iii): mel's first serve start, with an
//! `auth_secret`, rooted the store it had just joined. A joined store's authority log stays
//! empty until its first sync adopts the pin its enrolment record holds, so the start's
//! root-project signing (`commands::sign_root_project`) minted a Genesis of mel's own. kel then
//! could not verify mel's machine proofs, and sync, renewal and the checkpoint all failed.
//!
//! A store this install holds a device enrolment for is never rooted at a start. The root
//! project's signing skips it, and the server boots it with no host issuer bootstrap, in any
//! posture (`commands::construct_sync_server`). Its secret and authentication stay as
//! configured: review round 2 of #10532 showed that taking the secret away could admit
//! unauthenticated owner requests. A store no enrolment names is rooted as before.
//!
//! Red: both guards taken out, in `sign_root_project` and in `construct_sync_server` (scratch
//! branch). The first, third and fourth tests fail; the second passes.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --test joined_store_roots_nothing`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron_server::test_doors::root_project_signing::{
    construct_sync_server, fresh_hosted_store, fresh_store, sign_root_project, write_join_record,
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

/// The server a start builds over a joined store before its first sync roots nothing, and keeps
/// the start's secret (review round 2 of #10532). The same build over a store no enrolment names
/// roots it, as an install's own first start does.
#[test]
fn the_server_over_a_joined_store_roots_nothing_and_keeps_its_secret() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, config) = fresh_store(dir.path()).unwrap();
    write_join_record(&config, &vault).unwrap();
    let secret = construct_sync_server(vault.clone(), &config, Some(SECRET)).unwrap();
    assert!(
        vault.authority_fold().unwrap().vault_id.is_none(),
        "the server's boot mints no Genesis of the device's own"
    );
    assert_eq!(
        secret.as_deref(),
        Some(SECRET),
        "the start's secret and authentication stand"
    );

    let own_dir = tempfile::tempdir().unwrap();
    let (own, own_config) = fresh_store(own_dir.path()).unwrap();
    construct_sync_server(own.clone(), &own_config, Some(SECRET)).unwrap();
    assert!(
        own.authority_fold().unwrap().vault_id.is_some(),
        "control: the server roots a store no enrolment names"
    );
}

/// A Hosted start bootstraps its host issuer with no secret at all; over a joined store before
/// its first sync it bootstraps none, so it roots nothing either (review round 2 of #10532).
#[test]
fn a_hosted_server_over_a_joined_store_roots_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, config) = fresh_hosted_store(dir.path()).unwrap();
    write_join_record(&config, &vault).unwrap();
    let _ = construct_sync_server(vault.clone(), &config, None);
    assert!(
        vault.authority_fold().unwrap().vault_id.is_none(),
        "the hosted boot mints no Genesis of the device's own"
    );
}
