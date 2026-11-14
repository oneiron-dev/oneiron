// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
#![cfg(all(feature = "sync", feature = "test-support"))]
//! Census L6-07 (ARCH-0038, RD-23): the erasure sweep reads and scrubs every
//! persisted window on each pass, and the completion gate stays global. A
//! window that holds no history (cut at its tip by an earlier pass, no `u:w:`
//! row since) and that no scrub changes is left as it is: its rows are not
//! rewritten and no `fr:w:` full-resync marker is asserted for it again. A
//! window that gained history, or whose live state a scrub changes, is cut
//! and marked as before.
//!
//! Run: `cargo test --locked -p oneiron --all-features --test sweep_unchanged_window`.

use std::sync::Arc;

use loro::{ExportMode, LoroDoc};
use oneiron::maintain::MaintenanceReport;
use oneiron::sync::bridge::Materializer;
use oneiron::sync::manager::WindowManager;
use oneiron::sync::types::WindowKey;
use oneiron::temporal::TimeRange;
use oneiron::{DeleteReason, EntityId, HnswConfig, Vault, VaultConfig};

/// `window_label_from_timestamp(1_771_027_200) == "2026-02"`, as the sweep
/// executor suite pins it.
const LEARNED_FEB: u64 = 1_771_027_200;
const WINDOW_FEB: &str = "2026-02";
const LEARNED_MAR: u64 = LEARNED_FEB + 31 * 86_400;
const WINDOW_MAR: &str = "2026-03";

/// A carrier no scrub may leave in a window once its id is erased.
const RESIDUE: &[u8] = b"UNCHANGED-WINDOW-RESIDUE-c40e9a71";

fn test_config() -> VaultConfig {
    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = Some("test/model@v1".to_owned());
    cfg.max_readers = 16;
    cfg.hnsw = HnswConfig::default();
    cfg
}

/// A device vault with a memory keystore and its install signer loaded, as
/// the sync harness opens one.
fn open_vault() -> (tempfile::TempDir, Arc<Vault>) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), test_config()).unwrap();
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().unwrap();
    // FIX 7957/9599: isolate subject-month work from bootstrap notifications.
    for key in vault.sync_state_keys_with_prefix("lm:w:1970-01:").unwrap() {
        vault.sync_state_delete(&key).unwrap();
    }
    (dir, Arc::new(vault))
}

fn put(vault: &Vault, id: &EntityId, at: u64, body: &[u8]) {
    vault
        .batch()
        .put(id, 1, TimeRange { start: at, end: at }, at, body)
        .commit()
        .unwrap();
}

fn erase(vault: &Vault, id: &EntityId) {
    let outcome = vault
        .delete_entity_with_reason(id, DeleteReason::GdprDelete)
        .unwrap();
    assert!(outcome.existed, "fixture: the erased entity existed");
}

fn sweep(vault: &Vault) -> MaintenanceReport {
    vault.maintain().run_hard_erase_sweep().run().unwrap()
}

fn row(vault: &Vault, family: &str, window: &str) -> Option<Vec<u8>> {
    vault.sync_state_get(&format!("{family}{window}")).unwrap()
}

fn update_keys(vault: &Vault, window: &str) -> Vec<String> {
    vault
        .sync_state_keys_with_prefix(&format!("u:w:{window}:"))
        .unwrap()
}

/// The rows a cut writes for `window`: its snapshot, state vector and
/// freshness flag, and the `u:w:` keys a cut prunes.
fn cut_rows(vault: &Vault, window: &str) -> (Vec<Option<Vec<u8>>>, Vec<String>) {
    let rows = ["d:w:", "sv:w:", "svf:w:"]
        .into_iter()
        .map(|family| row(vault, family, window))
        .collect();
    (rows, update_keys(vault, window))
}

/// Whether `window` holds no history: a snapshot rooted at its tip and no
/// `u:w:` row on top.
fn history_free(vault: &Vault, window: &str) -> bool {
    let Some(snapshot) = row(vault, "d:w:", window) else {
        return false;
    };
    let doc = LoroDoc::from_snapshot(&snapshot).unwrap();
    update_keys(vault, window).is_empty()
        && doc.is_shallow()
        && doc.shallow_since_frontiers() == doc.oplog_frontiers()
}

fn carries_entity(vault: &Vault, window: &str, id: &EntityId) -> bool {
    let snapshot = row(vault, "d:w:", window).expect("a persisted snapshot");
    let doc = LoroDoc::from_snapshot(&snapshot).unwrap();
    doc.get_map("entities").get(&id.to_hex()).is_some()
}

/// A vault after a first pass: an entity erased in FEB, both windows
/// persisted with history and then cut at their tips and marked for a full
/// resync. Each marker is then cleared, as a peer's full resync clears it.
struct FirstPass {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    manager: Arc<WindowManager>,
    erased: EntityId,
}

fn after_a_first_pass() -> FirstPass {
    let (dir, vault) = open_vault();
    let erased = EntityId::now();
    put(&vault, &erased, LEARNED_FEB, b"first-erased-body");
    put(&vault, &EntityId::now(), LEARNED_MAR, b"march-window-body");
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&vault),
        Arc::new(Materializer::new()),
        "node-a",
    ));
    // Open both windows so the entities are mirrored into the CRDT, and
    // persisted with their history when the windows unload.
    let feb = manager.open_window(&WindowKey::new(WINDOW_FEB)).unwrap();
    let mar = manager.open_window(&WindowKey::new(WINDOW_MAR)).unwrap();
    erase(&vault, &erased);
    drop(feb);
    drop(mar);
    for window in [WINDOW_FEB, WINDOW_MAR] {
        assert!(manager.unload_window(&WindowKey::new(window)).unwrap());
        assert!(
            !history_free(&vault, window),
            "fixture: {window} holds history before the first pass"
        );
    }

    let first = sweep(&vault);
    assert_eq!(first.sweep_jobs_processed, 1, "{first:?}");
    assert!(first.sweep_windows_compacted >= 2, "{first:?}");
    for window in [WINDOW_FEB, WINDOW_MAR] {
        assert!(
            history_free(&vault, window),
            "fixture: the first pass cut {window} at its tip"
        );
        assert_eq!(
            row(&vault, "fr:w:", window).as_deref(),
            Some([1u8].as_slice()),
            "fixture: the first pass marked {window} for a full resync"
        );
        assert!(vault.sync_state_delete(&format!("fr:w:{window}")).unwrap());
    }
    FirstPass {
        _dir: dir,
        vault,
        manager,
        erased,
    }
}

/// Erases a second FEB entity after it was mirrored into the window, so the
/// next pass has an obligation and FEB has history again; MAR is not opened.
fn erase_again_in_feb(pass: &FirstPass) -> EntityId {
    let second = EntityId::now();
    put(
        &pass.vault,
        &second,
        LEARNED_FEB + 60,
        b"second-erased-body",
    );
    let feb = pass
        .manager
        .open_window(&WindowKey::new(WINDOW_FEB))
        .unwrap();
    erase(&pass.vault, &second);
    drop(feb);
    assert!(
        pass.manager
            .unload_window(&WindowKey::new(WINDOW_FEB))
            .unwrap()
    );
    assert!(
        !history_free(&pass.vault, WINDOW_FEB),
        "fixture: FEB holds history again before the second pass"
    );
    second
}

/// RED on main: main cuts every persisted window on every pass and asserts
/// its `fr:w:` marker again, so peers run a full resync of MAR, which no
/// pass changed.
#[test]
fn a_pass_leaves_a_window_that_holds_no_history_as_it_is() {
    let pass = after_a_first_pass();
    let mar_rows = cut_rows(&pass.vault, WINDOW_MAR);
    let second = erase_again_in_feb(&pass);

    let report = sweep(&pass.vault);
    assert_eq!(report.sweep_jobs_processed, 1, "{report:?}");
    assert_eq!(report.sweep_jobs_failed, 0, "{report:?}");

    // FEB gained history: it is cut and marked again.
    assert!(report.sweep_windows_compacted >= 1, "{report:?}");
    assert!(history_free(&pass.vault, WINDOW_FEB));
    assert!(!carries_entity(&pass.vault, WINDOW_FEB, &second));
    assert_eq!(
        row(&pass.vault, "fr:w:", WINDOW_FEB).as_deref(),
        Some([1u8].as_slice()),
        "the window the pass cut sends peers to a full resync"
    );

    // MAR holds no history and no scrub changed it: left as it is.
    assert_eq!(
        row(&pass.vault, "fr:w:", WINDOW_MAR),
        None,
        "the pass sent peers to a full resync of a window it had nothing to cut from"
    );
    assert_eq!(
        cut_rows(&pass.vault, WINDOW_MAR),
        mar_rows,
        "the pass rewrote a window that holds no history"
    );
    assert!(report.sweep_windows_unchanged >= 1, "{report:?}");
}

/// Guard (green on main too): a window that holds no history is still
/// scrubbed, and one whose live state names an erased id is cut and marked.
#[test]
fn a_history_free_window_a_scrub_changes_is_cut_again() {
    let pass = after_a_first_pass();
    // Residue under the erased id in MAR's live state, in a snapshot rooted
    // at its tip: a window with no history that a scrub must change.
    let snapshot = row(&pass.vault, "d:w:", WINDOW_MAR).expect("MAR snapshot");
    let doc = LoroDoc::from_snapshot(&snapshot).unwrap();
    let mut carrier = vec![1u8];
    for _ in 0..3 {
        carrier.extend_from_slice(&LEARNED_MAR.to_be_bytes());
    }
    carrier.extend_from_slice(&0_u64.to_be_bytes());
    carrier.extend_from_slice(RESIDUE);
    doc.get_map("entities")
        .insert(pass.erased.to_hex().as_str(), carrier.as_slice())
        .unwrap();
    doc.commit();
    let crafted = doc
        .export(ExportMode::shallow_snapshot(&doc.oplog_frontiers()))
        .unwrap();
    pass.vault
        .sync_state_put(&format!("d:w:{WINDOW_MAR}"), &crafted)
        .unwrap();
    assert!(
        history_free(&pass.vault, WINDOW_MAR),
        "fixture: the residue rides in a window with no history"
    );
    assert!(carries_entity(&pass.vault, WINDOW_MAR, &pass.erased));
    erase_again_in_feb(&pass);

    let report = sweep(&pass.vault);
    assert_eq!(report.sweep_jobs_processed, 1, "{report:?}");
    assert!(
        !carries_entity(&pass.vault, WINDOW_MAR, &pass.erased),
        "the scrub left the erased id in MAR"
    );
    assert!(history_free(&pass.vault, WINDOW_MAR));
    let snapshot = row(&pass.vault, "d:w:", WINDOW_MAR).unwrap();
    assert!(
        !snapshot.windows(RESIDUE.len()).any(|w| w == RESIDUE),
        "the residue's bytes survive in MAR's snapshot"
    );
    assert_eq!(
        row(&pass.vault, "fr:w:", WINDOW_MAR).as_deref(),
        Some([1u8].as_slice()),
        "a window the scrub changed is cut and sends peers to a full resync"
    );
}
