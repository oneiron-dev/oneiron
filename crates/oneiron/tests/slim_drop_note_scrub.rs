//! FIX 27743 (SLIM-DROP-PERSIST-VS-NOTE-SCRUB-REGISTRY-REENTRY): the slim
//! shed persists every live window before it deregisters them, and held the
//! window registry lock across those persists. A persist merges the window's
//! stored rows into its observed document, so a stored update carrying a NOTE
//! tombstone the live document lacked fired Observer B's NOTE scrub on the
//! shed's thread, and the scrub's list of the live windows waited for the
//! registry lock that thread held: the shed, and every window operation after
//! it, hung for good. The shed now persists outside the registry lock under
//! each window's transition mark, as an unload does. The scrub passes over the
//! windows in transition, and a window it passed over takes the scrub when it
//! next opens.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test slim_drop_note_scrub`.
#![cfg(all(oneiron_test_support, feature = "sync"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use oneiron::test_doors::slim_drop_note_scrub::slim_drop_beside_note_scrub;
use oneiron::{HnswConfig, Vault, VaultConfig};

fn config() -> VaultConfig {
    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = None;
    cfg.max_readers = 16;
    cfg.hnsw = HnswConfig::default();
    cfg
}

/// Opens the vault and installs this install's keystore on it, as a host does
/// after each open, for the tombstone's hard delete.
fn open_vault(path: &Path) -> Arc<Vault> {
    let vault = Arc::new(Vault::open(path, config()).unwrap());
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault
}

#[test]
fn a_slim_shed_over_a_stored_note_delete_returns_and_scrubs_on_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let vault = open_vault(dir.path());
    let run = slim_drop_beside_note_scrub(&vault, Duration::from_secs(5))
        .expect("open the windows and store the tombstone update");

    assert_eq!(
        run.scrubbed_during_drop,
        Some(vec![run.note]),
        "precondition: the deleting window's persist fires the deleted NOTE's scrub of the \
         other live windows on the shed's thread"
    );
    assert!(
        run.drop_returned,
        "the shed returns: the scrub never waits for a registry lock the shed holds"
    );
    assert_eq!(
        (run.dropped_windows, run.drop_error.as_deref()),
        (Some(2), None),
        "the shed persists and drops both windows"
    );
    assert_eq!(run.loaded_after, Some(0), "no window stays loaded");
    assert!(
        run.tombstone_kept,
        "the deleting window, opened again, carries the NOTE's tombstone"
    );
    assert!(
        !run.bundle_left_after_reopen,
        "the bundle window the scrub passed over in transition drops the bundle naming the \
         deleted NOTE when it opens again"
    );
}
