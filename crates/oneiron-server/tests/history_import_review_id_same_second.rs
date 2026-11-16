//! [HISTORY-IMPORT-REVIEW-ID-SAME-SECOND]: the review id of a history
//! import is keyed by the second it ran, so the second each import owns must
//! be its own: two imports that start in the same second (serve's
//! session-log queue pass and its hosted-import worker) must own different
//! seconds, or they share one review and one inbox row.
//!
//! Owns seconds through `oneiron_server::test_doors::history_import`:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --test history_import_review_id_same_second`.
#![cfg(oneiron_test_support)]

use std::path::Path;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use oneiron::ingest::history::{HistorySource, history_import_review_id};
use oneiron::{Vault, VaultConfig};
use oneiron_server::test_doors::history_import::own_second;

type TestError = Box<dyn std::error::Error>;
type TestResult = Result<(), TestError>;

/// A process-owned vault at `dir`, as `serve` opens it: this process holds
/// its writer lease, so its embedded owner may import.
fn open_vault(dir: &Path) -> Result<Vault, TestError> {
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    Ok(Vault::open_owned(dir, config)?)
}

/// Two imports that start in the same second own different seconds, so each
/// keeps a review of its own.
#[test]
fn concurrent_imports_own_different_seconds() -> TestResult {
    let vault_dir = tempfile::tempdir()?;
    let vault = Arc::new(open_vault(vault_dir.path())?);
    // Past a fresh tick, so both threads read their start second in the same
    // second: without the lock both would then own the second after it.
    let tick = vault.now_recorded_at();
    while vault.now_recorded_at() == tick {
        thread::sleep(Duration::from_millis(10));
    }
    let barrier = Arc::new(Barrier::new(3));
    let mut owners = Vec::new();
    for _ in 0..2 {
        let (vault, barrier) = (Arc::clone(&vault), Arc::clone(&barrier));
        owners.push(thread::spawn(move || {
            barrier.wait();
            own_second(&vault)
        }));
    }
    barrier.wait();
    let mut seconds = Vec::new();
    for owner in owners {
        match owner.join() {
            Ok(owned) => seconds.push(owned?),
            Err(_) => return Err("an owner thread panicked".into()),
        }
    }
    assert_ne!(
        seconds[0], seconds[1],
        "two imports that started in the same second owned one second"
    );
    let source = HistorySource::Chatgpt;
    assert_ne!(
        history_import_review_id(source, seconds[0]),
        history_import_review_id(source, seconds[1]),
        "two imports that started in the same second share one review"
    );
    Ok(())
}
