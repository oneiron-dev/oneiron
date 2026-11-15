//! UC-09 K pins (PLAN-UC-09 "The K-proof"): the queue rows each Dreamer
//! enqueue door stores, before and after a UC-09 PR moves it.
//!
//! Every enqueue writes an `AttemptRecord` and a dedupe-index entry that a
//! vault keeps, so a PR that moves an enqueue door must keep their bytes
//! (M-1 STORED-CHANGE-RULE = A, keep path). The door
//! `oneiron::test_doors::job_kind_rows` enqueues one fixture job per kind,
//! then the same job again, and renders each call's outcome and stored row.
//! This test prints that table (`PIN|` lines, shown by `--show-output`) and
//! asserts the coalesce of the keyed runner job. The READY compares the
//! printed table, and its sha256, at the PR's base and at its head. Built
//! only under `--cfg oneiron_test_support`:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test job_kind_rows -- --show-output`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::test_doors::job_kind_rows::dreamer_core_rows;
use oneiron::{Vault, VaultConfig};

/// A temporary vault with a process-memory device keystore and its embedded
/// owner, as the crate's test opener opens one.
fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault.ensure_embedded_owner_actor().expect("embedded owner");
    (dir, vault)
}

#[test]
fn the_dreamer_enqueue_doors_store_the_pinned_rows() {
    let (_dir, vault) = open_vault();
    let rows = dreamer_core_rows(&vault).expect("the fixture enqueues");
    for row in &rows {
        println!("PIN|{row}");
    }
    assert_eq!(rows.len(), 9, "one line per call");
    assert!(rows[0].starts_with("runner|1|Enqueued|A1|"), "{}", rows[0]);
    assert!(rows[1].starts_with("runner|2|Existing|A1|"), "{}", rows[1]);
    assert!(
        rows[0].contains("|stamp=facet="),
        "the runner job is stamped: {}",
        rows[0]
    );
}
