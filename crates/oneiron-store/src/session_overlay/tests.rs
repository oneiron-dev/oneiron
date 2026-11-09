use super::*;
use crate::overlay_db::OverlayDb;
use heed::types::Bytes;
use heed::{Database, DatabaseFlags, Env, EnvOpenOptions};
use oneiron_contracts::error::OffRecordError;
use oneiron_contracts::temporal::TimeRange;
use std::sync::mpsc::{RecvTimeoutError, sync_channel};
use std::time::{Duration, Instant};

const CONCURRENCY_TIMEOUT: Duration = Duration::from_secs(1);

fn put_op(data: Vec<u8>) -> BatchOp {
    BatchOp::Put {
        id: EntityId::now(),
        entity_type: 1,
        occurred: TimeRange { start: 1, end: 1 },
        learned_at: 1,
        row_version: None,
        data,
        allow_maintenance: false,
        allow_reserved_predicate: false,
        hub_sync_imported: false,
    }
}

/// A journal entry carrying the role and timestamps a witness write would
/// preserve; the budget/atomicity tests care about bytes, not the tag.
fn journal_entry(scope: JournalScope, role: JournalRole, op: BatchOp) -> JournalEntry {
    JournalEntry {
        scope,
        role,
        learned_at: 1,
        occurred: TimeRange { start: 1, end: 1 },
        op,
        source_run: None,
    }
}

fn dupsort_test_db() -> (tempfile::TempDir, Env, Database<Bytes, Bytes>) {
    let dir = tempfile::tempdir().expect("session overlay test temp dir");
    // SAFETY: this test owns the freshly created directory and opens it
    // exactly once; the returned directory outlives the environment.
    let env = unsafe {
        EnvOpenOptions::new()
            .map_size(16 * 1024 * 1024)
            .max_dbs(1)
            .open(dir.path())
            .expect("open session overlay test env")
    };
    let mut wtxn = env.write_txn().expect("open setup write txn");
    let db = env
        .database_options()
        .types::<Bytes, Bytes>()
        .name("rows")
        .flags(DatabaseFlags::DUP_SORT)
        .create(&mut wtxn)
        .expect("create session overlay test database");
    wtxn.commit().expect("commit session overlay setup");
    (dir, env, db)
}

#[test]
fn same_overlay_segments_serialize_across_threads() -> Result<()> {
    let budget = 7;
    let overlay = SessionOverlay::new(budget);
    let (first_installed_tx, first_installed_rx) = sync_channel(0);
    let (release_first_tx, release_first_rx) = sync_channel(0);
    let first_overlay = overlay.clone();
    let first = std::thread::spawn(move || -> Result<()> {
        let segment = first_overlay.install_txn_segment()?;
        first_overlay.put(OverlayKeyspace::Entities, b"a", &[1_u8; 3])?;
        first_installed_tx
            .send(())
            .expect("first install receiver remains live");
        release_first_rx
            .recv()
            .expect("first release sender remains live");
        segment.commit()
    });
    first_installed_rx
        .recv_timeout(CONCURRENCY_TIMEOUT)
        .expect("first segment installs");

    let (second_attempting_tx, second_attempting_rx) = sync_channel(0);
    let (second_installed_tx, second_installed_rx) = sync_channel(0);
    let second_overlay = overlay.clone();
    let second = std::thread::spawn(move || -> Result<()> {
        second_attempting_tx
            .send(())
            .expect("second attempt receiver remains live");
        let segment = second_overlay.install_txn_segment()?;
        second_installed_tx
            .send(())
            .expect("second install receiver remains live");
        match second_overlay.put(OverlayKeyspace::Entities, b"b", &[2_u8; 3]) {
            Err(Error::OffRecord(OffRecordError::OffRecordOverlayFull {
                budget_bytes,
                attempted_bytes,
            })) => {
                assert_eq!(budget_bytes, budget);
                assert_eq!(attempted_bytes, budget + 1);
                segment.commit()
            }
            Err(other) => Err(other),
            Ok(()) => {
                segment.commit()?;
                Err(Error::InvariantViolation(
                    "serialized second segment escaped budget preflight",
                ))
            }
        }
    });
    second_attempting_rx
        .recv_timeout(CONCURRENCY_TIMEOUT)
        .expect("second thread reaches install");

    // Without the per-overlay permit, this arrives while both previews are
    // empty; both puts stage, and one of the later applies tears at the budget.
    let second_was_blocked = match second_installed_rx.recv_timeout(CONCURRENCY_TIMEOUT) {
        Err(RecvTimeoutError::Timeout) => true,
        Ok(()) => false,
        Err(RecvTimeoutError::Disconnected) => {
            panic!("second installer disconnected before reporting")
        }
    };
    release_first_tx
        .send(())
        .expect("first segment remains live until release");
    if second_was_blocked {
        second_installed_rx
            .recv_timeout(CONCURRENCY_TIMEOUT)
            .expect("second segment installs after first commit");
    }

    let first_apply = first.join().expect("first segment thread does not panic");
    let second_apply = second.join().expect("second segment thread does not panic");
    assert!(
        second_was_blocked,
        "second segment installed before the first segment finished"
    );
    match first_apply {
        Ok(()) => {}
        Err(Error::OffRecord(OffRecordError::OffRecordOverlayFull { .. })) => {
            panic!("first post-commit apply returned OffRecordOverlayFull")
        }
        Err(other) => panic!("first post-commit apply failed: {other}"),
    }
    match second_apply {
        Ok(()) => {}
        Err(Error::OffRecord(OffRecordError::OffRecordOverlayFull { .. })) => {
            panic!("second post-commit apply returned OffRecordOverlayFull")
        }
        Err(other) => panic!("second segment failed: {other}"),
    }
    let snapshot = overlay.snapshot()?;
    assert_eq!(snapshot.row_count(OverlayKeyspace::Entities), 1);
    assert_eq!(snapshot.bytes_used(), 4);
    Ok(())
}

#[test]
fn close_wakes_all_blocked_segment_installers() -> Result<()> {
    let overlay = SessionOverlay::new(64);
    let (active_installed_tx, active_installed_rx) = sync_channel(0);
    let (release_active_tx, release_active_rx) = sync_channel(0);
    let active_overlay = overlay.clone();
    let active = std::thread::spawn(move || -> Result<()> {
        let segment = active_overlay.install_txn_segment()?;
        active_installed_tx
            .send(())
            .expect("active install receiver remains live");
        release_active_rx
            .recv()
            .expect("active release sender remains live");
        drop(segment);
        Ok(())
    });
    active_installed_rx
        .recv_timeout(CONCURRENCY_TIMEOUT)
        .expect("active segment installs");

    let (first_attempting_tx, first_attempting_rx) = sync_channel(0);
    let (first_result_tx, first_result_rx) = sync_channel(0);
    let first_overlay = overlay.clone();
    let first_waiter = std::thread::spawn(move || {
        first_attempting_tx
            .send(())
            .expect("first attempt receiver remains live");
        let result = match first_overlay.install_txn_segment() {
            Err(Error::OffRecord(OffRecordError::OffRecordOverlayLeaseClosed { .. })) => Ok(()),
            Err(other) => Err(other),
            Ok(segment) => {
                drop(segment);
                Err(Error::InvariantViolation(
                    "first blocked installer acquired a closing overlay",
                ))
            }
        };
        first_result_tx
            .send(result)
            .expect("first result receiver remains live");
    });

    let (second_attempting_tx, second_attempting_rx) = sync_channel(0);
    let (second_result_tx, second_result_rx) = sync_channel(0);
    let second_overlay = overlay.clone();
    let second_waiter = std::thread::spawn(move || {
        second_attempting_tx
            .send(())
            .expect("second attempt receiver remains live");
        let result = match second_overlay.install_txn_segment() {
            Err(Error::OffRecord(OffRecordError::OffRecordOverlayLeaseClosed { .. })) => Ok(()),
            Err(other) => Err(other),
            Ok(segment) => {
                drop(segment);
                Err(Error::InvariantViolation(
                    "second blocked installer acquired a closing overlay",
                ))
            }
        };
        second_result_tx
            .send(result)
            .expect("second result receiver remains live");
    });

    first_attempting_rx
        .recv_timeout(CONCURRENCY_TIMEOUT)
        .expect("first waiter reaches install");
    second_attempting_rx
        .recv_timeout(CONCURRENCY_TIMEOUT)
        .expect("second waiter reaches install");

    let (close_result_tx, close_result_rx) = sync_channel(0);
    let closing_overlay = overlay.clone();
    let closer = std::thread::spawn(move || {
        close_result_tx
            .send(closing_overlay.close())
            .expect("close result receiver remains live");
    });

    let closing_deadline = Instant::now() + CONCURRENCY_TIMEOUT;
    loop {
        let state = overlay
            .lifecycle
            .lock()
            .expect("overlay lifecycle remains available")
            .state;
        if state == OverlayLifecycleState::Closing {
            break;
        }
        assert!(
            Instant::now() < closing_deadline,
            "closer did not transition the overlay to Closing"
        );
        std::thread::yield_now();
    }

    release_active_tx
        .send(())
        .expect("active segment remains live until release");
    first_result_rx
        .recv_timeout(CONCURRENCY_TIMEOUT)
        .expect("first blocked installer wakes on close")?;
    second_result_rx
        .recv_timeout(CONCURRENCY_TIMEOUT)
        .expect("second blocked installer wakes on close")?;
    close_result_rx
        .recv_timeout(CONCURRENCY_TIMEOUT)
        .expect("closer returns after the active segment drains")?;

    active
        .join()
        .expect("active segment thread does not panic")?;
    first_waiter
        .join()
        .expect("first blocked installer does not panic");
    second_waiter
        .join()
        .expect("second blocked installer does not panic");
    closer.join().expect("closer thread does not panic");
    Ok(())
}

#[test]
fn close_while_holding_own_segment_fails_fast() -> Result<()> {
    let overlay = SessionOverlay::new(64);
    let segment = overlay.install_txn_segment()?;

    match overlay.close() {
        Err(Error::InvariantViolation(message)) => assert_eq!(
            message,
            "session overlay close called while this thread holds an active txn segment"
        ),
        Err(other) => panic!("unexpected close error: {other}"),
        Ok(()) => panic!("same-thread close unexpectedly succeeded"),
    }

    drop(segment);
    let fresh_segment = overlay.install_txn_segment()?;
    let snapshot = overlay.snapshot()?;
    assert_eq!(snapshot.bytes_used(), 0);
    drop(snapshot);
    drop(fresh_segment);
    Ok(())
}

#[test]
fn stage_journal_without_segment_fails_closed() {
    let overlay = SessionOverlay::new(4096);
    let scope = JournalScope::new(EntityId::now(), EntityId::now());

    match overlay.stage_journal_entry(journal_entry(
        scope,
        JournalRole::TurnPut,
        BatchOp::Delete {
            id: EntityId::now(),
        },
    )) {
        Err(Error::InvariantViolation(_)) => {}
        Err(other) => panic!("unexpected error: {other}"),
        Ok(()) => panic!("segment-less journal staging unexpectedly succeeded"),
    }
}

/// The namespace-separation contract. A session alias must not parse as a
/// base short id, or a room alias could collide with — and, through the
/// composed overlay ∪ base read, MASK — a real base entity's alias.
/// Mirrors `api/core.rs::parse_short_ref_parts` /
/// `mcp.rs::validate_short_ref_parts`: two lowercase letters then digits.
fn parses_as_base_short_id(short_id: &str) -> bool {
    let bytes = short_id.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_lowercase()
        && bytes[1].is_ascii_lowercase()
        && bytes[2..].iter().all(u8::is_ascii_digit)
}

#[test]
fn journal_refuses_payloads_outside_its_scrubbed_vocabulary() -> Result<()> {
    let overlay = SessionOverlay::new(4096);
    let segment = overlay.install_txn_segment()?;
    let scope = JournalScope::new(EntityId::now(), EntityId::now());
    let result = overlay.stage_journal_entry(journal_entry(
        scope,
        JournalRole::TurnOwnedArtifact,
        BatchOp::ReconcileLexicalQueryHints {
            source: EntityId::now(),
            keep: Vec::new(),
        },
    ));
    assert!(matches!(result, Err(Error::InvariantViolation(_))));
    segment.commit()?;
    assert!(overlay.snapshot()?.journal_ops(scope).is_empty());
    Ok(())
}

