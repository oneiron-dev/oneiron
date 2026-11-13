//! FIX 17211: a tombstone publication prunes, in its own commit, the policy
//! revisions no binding reaches any longer. Before the fix they stayed in the
//! window's source-audience map until its next export or persist.
//!
//! One row is bound to a thread policy T under a source policy S, as a mail
//! landing binds it. The window that opens over the row carries both
//! policies. Deleting the row publishes its tombstone, and neither policy is
//! reached after that.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test tombstone_publish_policy_prune`.
#![cfg(all(oneiron_test_support, feature = "sync"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::sync::bridge::Materializer;
use oneiron::sync::manager::WindowManager;
use oneiron::sync::types::WindowKey;
use oneiron::sync::window::{LoadedWindow, reverse_rematerialize};
use oneiron::test_doors::source_audience_binding::{
    carried_policy_revisions, persisted_policy_revisions, thread_bound_row,
};
use oneiron::{EntityId, HnswConfig, Vault, VaultConfig};

/// The window the row lands in: March 2026.
const WINDOW: &str = "2026-03";
/// 2026-03-15 00:00 UTC, inside [`WINDOW`].
const T0: u64 = 1_773_532_800;

fn config() -> VaultConfig {
    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = None;
    cfg.max_readers = 16;
    cfg.hnsw = HnswConfig::default();
    cfg
}

/// The live leg: the window is open, so the publication commits on its
/// shared document.
#[test]
fn tombstone_publish_prunes_unreached_policy() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), config()).unwrap());
    let (row, source, thread) =
        thread_bound_row(&vault, EntityId::now(), T0).expect("land a thread-bound row");
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&vault),
        Arc::new(Materializer::new()),
        "tombstone-policy-prune",
    ));
    let window = manager
        .open_window(&WindowKey::new(WINDOW))
        .expect("open the row's window");
    assert!(
        !carried_policy_revisions(&window.doc, thread).is_empty()
            && !carried_policy_revisions(&window.doc, source).is_empty(),
        "precondition: the open window carries the row's thread and source policies",
    );

    assert!(
        vault.delete_entity(&row).expect("delete the bound row"),
        "the bound row existed",
    );

    assert_eq!(
        (
            carried_policy_revisions(&window.doc, thread),
            carried_policy_revisions(&window.doc, source),
        ),
        (Vec::new(), Vec::new()),
        "the tombstone's own commit drops the thread and source policies no binding reaches",
    );
}

/// The transient leg: no window is open, so the publication loads the
/// persisted window and stores the document it commits.
#[test]
fn transient_tombstone_publish_prunes_unreached_policy() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), config()).unwrap());
    let (row, source, thread) =
        thread_bound_row(&vault, EntityId::now(), T0).expect("land a thread-bound row");
    let key = WindowKey::new(WINDOW);
    let materializer = Arc::new(Materializer::new());
    {
        let window = LoadedWindow::new("local", key.clone(), &vault, &materializer);
        reverse_rematerialize(&vault, &window.doc, &key).expect("mirror the month's rows");
        window.persist_state(&vault).expect("persist the window");
    }
    assert!(
        !persisted_policy_revisions(&vault, WINDOW, thread)
            .expect("read the persisted window")
            .is_empty()
            && !persisted_policy_revisions(&vault, WINDOW, source)
                .expect("read the persisted window")
                .is_empty(),
        "precondition: the persisted window carries the row's thread and source policies",
    );

    assert!(
        vault.delete_entity(&row).expect("delete the bound row"),
        "the bound row existed",
    );

    assert_eq!(
        (
            persisted_policy_revisions(&vault, WINDOW, thread).expect("read the persisted window"),
            persisted_policy_revisions(&vault, WINDOW, source).expect("read the persisted window"),
        ),
        (Vec::new(), Vec::new()),
        "the stored tombstone commit drops the thread and source policies no binding reaches",
    );
}
