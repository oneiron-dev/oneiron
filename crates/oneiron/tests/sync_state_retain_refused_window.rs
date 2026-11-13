//! A window whose retain the home refused is found again by the residence
//! upkeep's retry (FIX RETAIN-REFUSED-PREFIX-UNDECLARED, OF-534).
//!
//! The sync client marks such a window with an `rr:w:<window>` sync-state row
//! (`SyncClient::mark_retain_refused`), and `retry_refused_retains` lists the
//! marks through `Vault::sync_state_keys_with_prefix("rr:w:")`. No side table
//! declared `rr:w:`, so that scan refused before it read a row: every opened
//! device's steady upkeep logged "Window retain retry failed: storage error:
//! sync_state key \"rr:w:\" is not declared in side_table" (E2E job 16, the
//! SYNC-09 device peer), and a refused window was never asked for again.
//!
//! `cargo test --locked -p oneiron --all-features --test sync_state_retain_refused_window`.
#![allow(clippy::expect_used)]

use oneiron::{Vault, VaultConfig};

/// The retry's scan prefix (`RETAIN_REFUSED_PREFIX`,
/// crates/oneiron/src/sync/client/residence/windows.rs).
const RETAIN_REFUSED_PREFIX: &str = "rr:w:";

#[test]
fn the_retain_retry_scan_finds_each_refused_window() {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open_owned(dir.path(), VaultConfig::device()).expect("vault");

    assert_eq!(
        vault
            .sync_state_keys_with_prefix(RETAIN_REFUSED_PREFIX)
            .expect("the retain retry scans a declared sync-state table"),
        Vec::<String>::new(),
        "a fresh vault holds no refused window"
    );

    let refused = format!("{RETAIN_REFUSED_PREFIX}2026-03");
    vault
        .sync_state_put(&refused, &[1])
        .expect("a refused window's mark is a declared sync-state row");
    assert_eq!(
        vault
            .sync_state_keys_with_prefix(RETAIN_REFUSED_PREFIX)
            .expect("the retain retry scans a declared sync-state table"),
        vec![refused],
        "the retry finds the refused window again"
    );
}
