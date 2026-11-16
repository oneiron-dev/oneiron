//! FIX 25183 (REPLACEMENT-FORWARD-VS-NOTE-SCRUB-LOCK-ORDER): a window
//! replacement holds the window registry lock while its forward pass takes the
//! materializer lock. Observer B's tombstone batch takes a deleted NOTE's bundle
//! attachments out of the other live windows, and lists those windows through
//! the registry lock. It did that under the materializer lock, so a NOTE delete
//! landing in one window while another window was replaced left both waiting on
//! each other for good. The scrub now runs once the batch has dropped the
//! materializer lock, and still takes the attachments out.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test note_scrub_lock_order`.
#![cfg(all(oneiron_test_support, feature = "sync"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use oneiron::test_doors::note_scrub_lock_order::note_scrub_beside_replacement;
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
fn a_note_delete_beside_a_replacement_scrubs_without_deadlock() {
    let dir = tempfile::tempdir().unwrap();
    let vault = open_vault(dir.path());
    let run = note_scrub_beside_replacement(&vault, Duration::from_secs(5))
        .expect("open the windows and export the hub snapshot");

    assert!(
        run.replacement_reached_forward_pass,
        "precondition: the replacement forwards its candidate under the registry lock"
    );
    assert_eq!(
        run.scrubbed_during_replacement,
        Some(vec![run.note]),
        "precondition: the deleted NOTE's scrub of the other live windows begins while the \
         replacement holds the registry lock"
    );
    assert!(
        run.replacement_installed && run.tombstone_committed,
        "the replacement and the NOTE delete both return: the scrub never waits for the \
         registry lock while it holds the materializer lock the replacement waits for \
         (replacement installed {}, tombstone committed {})",
        run.replacement_installed,
        run.tombstone_committed
    );
    assert!(
        !run.bundle_left,
        "the other live window no longer carries the bundle naming the deleted NOTE"
    );
}
