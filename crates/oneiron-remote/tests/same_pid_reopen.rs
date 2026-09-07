//! ONE-1441 §Test/Shared #3 — same-PID reopen opens one shared native vault.
//!
//! Keep this test in its own integration-test binary: `store_open_count` is
//! process-wide. Other tests that open unrelated vaults must run in separate
//! processes so they cannot change the counter between these assertions.
//! This preserves both the exact open-count and pointer-identity proofs
//! without serializing the rest of the test suite.

use oneiron_remote::{OneironClient, OpenOptions, store_open_count};

/// §Test/Shared #3 — `same_pid_reopen_shares_native_vault`.
///
/// Both halves matter. Sharing without counting would pass on an
/// implementation that opened the store twice and discarded one; counting
/// without comparing pointers would pass on one that handed back an unrelated
/// vault it had opened earlier.
#[test]
fn same_pid_reopen_shares_native_vault() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("vault");
    let options = OpenOptions::default();

    let before = store_open_count();
    let first = OneironClient::open(Some(&path), &options).expect("first open");
    let after_first = store_open_count();
    let second = OneironClient::open(Some(&path), &options).expect("second open");
    let after_second = store_open_count();

    assert_eq!(
        after_first,
        before + 1,
        "the first open opens the store once"
    );
    assert_eq!(
        after_second, after_first,
        "a same-path, same-options reopen must not open the store again"
    );
    assert_eq!(
        first.shared_vault_addr(),
        second.shared_vault_addr(),
        "both handles must point at the same native vault"
    );
    assert_eq!(first.lease_pid(), Some(std::process::id()));
}
