use super::*;
use crate::overlay_db::OverlayDb;
use crate::temporal::TimeRange;
use heed::types::Bytes;
use heed::{Database, DatabaseFlags, Env, EnvOpenOptions};
use std::sync::mpsc::{RecvTimeoutError, sync_channel};
use std::time::{Duration, Instant};

const CONCURRENCY_TIMEOUT: Duration = Duration::from_secs(1);

fn put_op(data: Vec<u8>) -> BatchOp {
    BatchOp::Put {
        id: EntityId::now(),
        entity_type: 1,
        occurred: TimeRange { start: 1, end: 1 },
        learned_at: 1,
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
            Err(Error::OffRecordOverlayFull {
                budget_bytes,
                attempted_bytes,
            }) => {
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
        Err(Error::OffRecordOverlayFull { .. }) => {
            panic!("first post-commit apply returned OffRecordOverlayFull")
        }
        Err(other) => panic!("first post-commit apply failed: {other}"),
    }
    match second_apply {
        Ok(()) => {}
        Err(Error::OffRecordOverlayFull { .. }) => {
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
            Err(Error::OffRecordOverlayLeaseClosed { .. }) => Ok(()),
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
            Err(Error::OffRecordOverlayLeaseClosed { .. }) => Ok(()),
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
fn apply_is_budget_infallible_after_authoritative_preflight() -> Result<()> {
    let budget = 8;
    let overlay = SessionOverlay::new(budget);
    let segment = overlay.install_txn_segment()?;
    overlay.put(OverlayKeyspace::Entities, b"a", &[1_u8; 5])?;
    segment.commit()?;
    assert_eq!(overlay.snapshot()?.bytes_used(), 6);

    let segment = overlay.install_txn_segment()?;
    match overlay.put(OverlayKeyspace::Entities, b"b", &[2_u8; 2]) {
        Err(Error::OffRecordOverlayFull {
            budget_bytes,
            attempted_bytes,
        }) => {
            assert_eq!(budget_bytes, budget);
            assert_eq!(attempted_bytes, budget + 1);
        }
        Err(other) => panic!("unexpected preflight error: {other}"),
        Ok(()) => panic!("over-budget mutation escaped preflight"),
    }
    match segment.commit() {
        Ok(()) => {}
        Err(Error::OffRecordOverlayFull { .. }) => {
            panic!("empty post-preflight apply returned OffRecordOverlayFull")
        }
        Err(other) => panic!("empty post-preflight apply failed: {other}"),
    }
    assert_eq!(overlay.snapshot()?.bytes_used(), 6);

    // Production staging cannot create this state: preflight above rejects it.
    // Injecting it test-only proves the post-base-commit helper is structurally
    // budget-free and cannot construct OffRecordOverlayFull even at 9/8 bytes.
    let segment = overlay.install_txn_segment()?;
    ACTIVE_SEGMENT.with(|slot| {
        let mut slot = slot.borrow_mut();
        let active = slot.as_mut().expect("the test segment is installed");
        active.mutations.push(OverlayMutation::Put {
            keyspace: OverlayKeyspace::Entities,
            key: b"b".to_vec(),
            value: vec![2_u8; 2],
        });
    });
    match segment.commit() {
        Ok(()) => {}
        Err(Error::OffRecordOverlayFull { .. }) => {
            panic!("post-commit apply reconstructed OffRecordOverlayFull")
        }
        Err(other) => panic!("post-commit apply failed: {other}"),
    }
    let snapshot = overlay.snapshot()?;
    assert_eq!(snapshot.row_count(OverlayKeyspace::Entities), 2);
    assert_eq!(snapshot.bytes_used(), budget + 1);
    Ok(())
}

#[test]
#[allow(clippy::unnecessary_wraps)]
fn different_overlays_keep_segment_concurrency_parallel() -> Result<()> {
    let first_overlay = SessionOverlay::new(64);
    let other_overlay = SessionOverlay::new(64);
    let (first_installed_tx, first_installed_rx) = sync_channel(0);
    let (release_first_tx, release_first_rx) = sync_channel(0);
    let held_overlay = first_overlay.clone();
    let first = std::thread::spawn(move || -> Result<()> {
        let segment = held_overlay.install_txn_segment()?;
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
        .expect("first overlay segment installs");

    let (other_attempting_tx, other_attempting_rx) = sync_channel(0);
    let (other_installed_tx, other_installed_rx) = sync_channel(0);
    let parallel_overlay = other_overlay;
    let other = std::thread::spawn(move || -> Result<()> {
        other_attempting_tx
            .send(())
            .expect("other attempt receiver remains live");
        let segment = parallel_overlay.install_txn_segment()?;
        other_installed_tx
            .send(())
            .expect("other install receiver remains live");
        segment.commit()
    });

    let (same_attempting_tx, same_attempting_rx) = sync_channel(0);
    let (same_installed_tx, same_installed_rx) = sync_channel(0);
    let contended_overlay = first_overlay;
    let same = std::thread::spawn(move || -> Result<()> {
        same_attempting_tx
            .send(())
            .expect("same-overlay attempt receiver remains live");
        let segment = contended_overlay.install_txn_segment()?;
        same_installed_tx
            .send(())
            .expect("same-overlay install receiver remains live");
        segment.commit()
    });
    other_attempting_rx
        .recv_timeout(CONCURRENCY_TIMEOUT)
        .expect("other-overlay thread reaches install");
    same_attempting_rx
        .recv_timeout(CONCURRENCY_TIMEOUT)
        .expect("same-overlay thread reaches install");

    let other_ran_in_parallel = match other_installed_rx.recv_timeout(CONCURRENCY_TIMEOUT) {
        Ok(()) => true,
        Err(RecvTimeoutError::Timeout) => false,
        Err(RecvTimeoutError::Disconnected) => {
            panic!("other-overlay installer disconnected before reporting")
        }
    };
    let same_was_blocked = match same_installed_rx.recv_timeout(CONCURRENCY_TIMEOUT) {
        Err(RecvTimeoutError::Timeout) => true,
        Ok(()) => false,
        Err(RecvTimeoutError::Disconnected) => {
            panic!("same-overlay installer disconnected before reporting")
        }
    };
    release_first_tx
        .send(())
        .expect("first overlay segment remains live until release");
    if !other_ran_in_parallel {
        other_installed_rx
            .recv_timeout(CONCURRENCY_TIMEOUT)
            .expect("other overlay eventually installs");
    }
    if same_was_blocked {
        same_installed_rx
            .recv_timeout(CONCURRENCY_TIMEOUT)
            .expect("same overlay installs after release");
    }

    match first.join().expect("first overlay thread does not panic") {
        Ok(()) => {}
        Err(other) => panic!("first overlay segment failed: {other}"),
    }
    match other.join().expect("other overlay thread does not panic") {
        Ok(()) => {}
        Err(other) => panic!("other overlay segment failed: {other}"),
    }
    match same.join().expect("same overlay thread does not panic") {
        Ok(()) => {}
        Err(other) => panic!("same overlay segment failed: {other}"),
    }
    assert!(
        other_ran_in_parallel,
        "a segment on another overlay was blocked by a global permit"
    );
    assert!(same_was_blocked, "the same-overlay permit was not held");
    Ok(())
}

#[test]
fn put_rejects_budget_plus_one_before_staging() -> Result<()> {
    let budget = 64;
    let overlay = SessionOverlay::new(budget);
    let segment = overlay.install_txn_segment()?;
    let value = vec![0_u8; budget + 1];

    match overlay.put(OverlayKeyspace::Entities, b"k", &value) {
        Err(Error::OffRecordOverlayFull {
            budget_bytes,
            attempted_bytes,
        }) => {
            assert_eq!(budget_bytes, budget);
            assert_eq!(attempted_bytes, budget + 2);
        }
        Err(other) => panic!("unexpected error: {other}"),
        Ok(()) => panic!("budget-plus-one put unexpectedly staged"),
    }
    assert_eq!(overlay.snapshot()?.bytes_used(), 0);
    drop(segment);
    Ok(())
}

#[test]
fn payload_larger_than_budget_is_rejected_before_cloning() -> Result<()> {
    let budget = 8;
    let overlay = SessionOverlay::new(budget);
    let segment = overlay.install_txn_segment()?;
    let value = vec![0_u8; 64];

    match overlay.put(OverlayKeyspace::Entities, b"k", &value) {
        Err(Error::OffRecordOverlayFull {
            budget_bytes,
            attempted_bytes,
        }) => {
            assert_eq!(budget_bytes, budget);
            assert_eq!(attempted_bytes, 65);
        }
        Err(other) => panic!("unexpected put error: {other}"),
        Ok(()) => panic!("unbudgetable put unexpectedly staged"),
    }
    let snapshot = overlay.snapshot()?;
    assert_eq!(snapshot.bytes_used(), 0);
    assert_eq!(snapshot.row_count(OverlayKeyspace::Entities), 0);
    drop(snapshot);

    match overlay.delete_duplicate(OverlayKeyspace::TextPostings, b"k", &value, true) {
        Err(Error::OffRecordOverlayFull {
            budget_bytes,
            attempted_bytes,
        }) => {
            assert_eq!(budget_bytes, budget);
            assert_eq!(attempted_bytes, 65);
        }
        Err(other) => panic!("unexpected delete-duplicate error: {other}"),
        Ok(()) => panic!("unbudgetable delete-duplicate unexpectedly staged"),
    }
    let snapshot = overlay.snapshot()?;
    assert_eq!(snapshot.bytes_used(), 0);
    assert_eq!(snapshot.row_count(OverlayKeyspace::TextPostings), 0);
    drop(snapshot);
    drop(segment);
    Ok(())
}

#[test]
fn dupsort_present_identity_keys_count_toward_budget_before_staging() -> Result<()> {
    let value = vec![7_u8; 16];
    let budget = b"t".len() + value.len();
    let overlay = SessionOverlay::new(budget);
    let segment = overlay.install_txn_segment()?;

    match overlay.put(OverlayKeyspace::TextPostings, b"t", &value) {
        Err(Error::OffRecordOverlayFull {
            budget_bytes,
            attempted_bytes,
        }) => {
            assert_eq!(budget_bytes, budget);
            assert_eq!(attempted_bytes, budget + value.len());
        }
        Err(other) => panic!("unexpected error: {other}"),
        Ok(()) => panic!("DUP_SORT present identity key escaped the overlay budget"),
    }
    let snapshot = overlay.snapshot()?;
    assert_eq!(snapshot.row_count(OverlayKeyspace::TextPostings), 0);
    assert_eq!(snapshot.bytes_used(), 0);
    drop(segment);
    Ok(())
}

#[test]
fn mutations_at_capacity_are_charged_by_net_byte_change() -> Result<()> {
    let budget = 8;
    let overlay = SessionOverlay::new(budget);
    let full_value = vec![7_u8; budget - b"k".len()];

    let segment = overlay.install_txn_segment()?;
    overlay.put(OverlayKeyspace::Entities, b"k", &full_value)?;
    segment.commit()?;
    assert_eq!(overlay.snapshot()?.bytes_used(), budget);

    let segment = overlay.install_txn_segment()?;
    overlay.put(OverlayKeyspace::Entities, b"k", b"x")?;
    assert_eq!(overlay.snapshot()?.bytes_used(), 2);
    segment.commit()?;

    let segment = overlay.install_txn_segment()?;
    overlay.put(OverlayKeyspace::Entities, b"k", &full_value)?;
    segment.commit()?;
    assert_eq!(overlay.snapshot()?.bytes_used(), budget);

    let segment = overlay.install_txn_segment()?;
    overlay.delete(OverlayKeyspace::Entities, b"k")?;
    assert_eq!(overlay.snapshot()?.bytes_used(), 1);
    match overlay.put(OverlayKeyspace::Entities, b"k", &[9_u8; 8]) {
        Err(Error::OffRecordOverlayFull {
            budget_bytes,
            attempted_bytes,
        }) => {
            assert_eq!(budget_bytes, budget);
            assert_eq!(attempted_bytes, budget + 1);
        }
        Err(other) => panic!("unexpected error: {other}"),
        Ok(()) => panic!("net-increasing over-budget put unexpectedly staged"),
    }
    assert_eq!(overlay.snapshot()?.bytes_used(), 1);
    segment.commit()?;
    Ok(())
}

#[test]
fn delete_removes_overlay_only_rows_but_retains_base_masks() -> Result<()> {
    let keyspace = OverlayKeyspace::Entities;
    let key = b"key";

    let overlay_only = SessionOverlay::new(64);
    let segment = overlay_only.install_txn_segment()?;
    overlay_only.put(keyspace, key, b"overlay")?;
    overlay_only.delete_with_base_backing(keyspace, key, false)?;
    segment.commit()?;
    let snapshot = overlay_only.snapshot()?;
    assert_eq!(snapshot.bytes_used(), 0);
    assert_eq!(snapshot.row_count(keyspace), 0);

    // delete -> re-put -> delete on a base-backed key must still end tombstoned:
    // base backing is read from the base row, not the intervening overlay Present.
    let base_backed = SessionOverlay::new(64);
    let segment = base_backed.install_txn_segment()?;
    base_backed.delete_with_base_backing(keyspace, key, true)?;
    base_backed.put(keyspace, key, b"replacement")?;
    base_backed.delete_with_base_backing(keyspace, key, true)?;
    segment.commit()?;
    let snapshot = base_backed.snapshot()?;
    assert_eq!(snapshot.bytes_used(), key.len());
    assert_eq!(
        snapshot.merge_rows(keyspace, vec![(key.to_vec(), b"base".to_vec())]),
        Vec::<(Vec<u8>, Vec<u8>)>::new()
    );
    Ok(())
}

#[test]
fn delete_duplicate_removes_overlay_only_value_without_tombstone() -> Result<()> {
    let keyspace = OverlayKeyspace::TextPostings;
    let key = b"term";
    let mut base_value = vec![0_u8; 17];
    base_value[15] = 1;
    let mut overlay_value = vec![0_u8; 17];
    overlay_value[15] = 2;
    let (_dir, env, base) = dupsort_test_db();
    let mut setup_txn = env.write_txn()?;
    base.put(&mut setup_txn, key, &base_value)?;
    setup_txn.commit()?;

    let overlay = SessionOverlay::new(4096);
    let segment = overlay.install_txn_segment()?;
    overlay.put(keyspace, key, &overlay_value)?;
    overlay.delete_duplicate(keyspace, key, &overlay_value, false)?;
    segment.commit()?;

    let snapshot = overlay.snapshot()?;
    let KeyspaceState::DupSort { rows, .. } = snapshot.state.keyspaces[keyspace.slot()].as_ref()
    else {
        panic!("text postings overlay is not DUP_SORT");
    };
    assert!(
        rows.get(key.as_slice()).is_none(),
        "an emptied overlay-only delta is dropped, not left as a bare row"
    );
    assert_eq!(snapshot.bytes_used(), 0);
    assert!(snapshot.merge_plan(keyspace, |_| true).rows.is_empty());

    let view = OverlayDb::composed(base, overlay, Arc::new(snapshot), keyspace);
    let rtxn = env.read_txn()?;
    let values = view
        .get_duplicates(&rtxn, key)?
        .expect("different base posting remains visible")
        .map(|row| row.map(|(_, value)| value.into_owned()))
        .collect::<Result<Vec<_>>>()?;
    assert_eq!(values, vec![base_value]);
    Ok(())
}

#[test]
fn delete_duplicate_retains_base_backed_tombstone() -> Result<()> {
    let keyspace = OverlayKeyspace::TextPostings;
    let key = b"term";
    let mut value = vec![0_u8; 17];
    value[15] = 1;
    let (_dir, env, base) = dupsort_test_db();
    let mut setup_txn = env.write_txn()?;
    base.put(&mut setup_txn, key, &value)?;
    setup_txn.commit()?;

    let overlay = SessionOverlay::new(4096);
    let segment = overlay.install_txn_segment()?;
    overlay.delete_duplicate(keyspace, key, &value, true)?;
    segment.commit()?;

    let snapshot = overlay.snapshot()?;
    let KeyspaceState::DupSort { rows, .. } = snapshot.state.keyspaces[keyspace.slot()].as_ref()
    else {
        panic!("text postings overlay is not DUP_SORT");
    };
    let delta = rows.get(key.as_slice()).expect("base mask is retained");
    assert!(delta.present.is_empty());
    assert_eq!(delta.deleted.iter().collect::<Vec<_>>(), vec![&value]);
    assert_eq!(snapshot.bytes_used(), key.len() + value.len());

    let view = OverlayDb::composed(base, overlay, Arc::new(snapshot), keyspace);
    let rtxn = env.read_txn()?;
    assert!(view.get_duplicates(&rtxn, key)?.is_none());
    Ok(())
}

#[test]
fn over_budget_journal_entry_is_rejected_before_append() -> Result<()> {
    let budget = 64;
    let overlay = SessionOverlay::new(budget);
    let segment = overlay.install_txn_segment()?;
    let scope = JournalScope::new(EntityId::now(), EntityId::now());

    match overlay.stage_journal_entry(journal_entry(
        scope,
        JournalRole::TurnPut,
        put_op(vec![0_u8; budget + 1]),
    )) {
        Err(Error::OffRecordOverlayFull { budget_bytes, .. }) => {
            assert_eq!(budget_bytes, budget);
        }
        Err(other) => panic!("unexpected error: {other}"),
        Ok(()) => panic!("over-budget journal entry unexpectedly staged"),
    }
    drop(segment);

    let snapshot = overlay.snapshot()?;
    assert_eq!(snapshot.journal_ops(scope).len(), 0);
    assert_eq!(snapshot.bytes_used(), 0);
    Ok(())
}

#[test]
fn abort_reclaims_staged_journal_bytes() -> Result<()> {
    let overlay = SessionOverlay::new(4096);
    let segment = overlay.install_txn_segment()?;
    let scope = JournalScope::new(EntityId::now(), EntityId::now());
    overlay.stage_journal_entry(journal_entry(
        scope,
        JournalRole::TurnPut,
        put_op(vec![7_u8; 128]),
    ))?;
    drop(segment);

    let snapshot = overlay.snapshot()?;
    assert_eq!(snapshot.journal_ops(scope).len(), 0);
    assert_eq!(snapshot.bytes_used(), 0);
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
        Err(Error::InvariantViolation(message)) => assert_eq!(
            message,
            "session overlay write requires an active txn segment"
        ),
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
fn session_short_ids_are_unique_and_outside_the_base_namespace() -> Result<()> {
    let overlay = SessionOverlay::new(4096);
    let segment = overlay.install_txn_segment()?;

    let mut seen = BTreeSet::new();
    for index in 0_u8..5 {
        let id = EntityId::now();
        let (short_id, content_hash) = overlay.alloc_session_short_id(&id, &[index])?;

        assert!(
            !parses_as_base_short_id(&short_id),
            "session alias {short_id} parses as a base short id"
        );
        assert!(
            short_id.starts_with(SESSION_SHORT_ID_SIGIL),
            "session alias {short_id} lacks the room sigil"
        );
        assert_eq!(content_hash, session_short_id_content_hash(&[index]));
        assert!(
            seen.insert(short_id.clone()),
            "session alias {short_id} was allocated twice in one room"
        );

        // Both rows land, and the forward row resolves back to the entity.
        let forward_key = encode_session_short_id_forward_key(&short_id, content_hash);
        let snapshot = overlay.snapshot()?;
        match snapshot.lookup_single(OverlayKeyspace::ShortIds, &forward_key) {
            SnapshotLookup::Present(value) => assert_eq!(value, id.as_bytes()),
            _ => panic!("forward session short-id row missing for {short_id}"),
        }
        match snapshot.lookup_single(OverlayKeyspace::ShortIdsReverse, id.as_bytes()) {
            SnapshotLookup::Present(value) => assert_eq!(value, forward_key),
            _ => panic!("reverse session short-id row missing for {short_id}"),
        }
    }

    drop(segment);
    Ok(())
}

/// Re-allocating keeps the alias stable and retires the stale forward row:
/// the content hash is part of the forward KEY, so a body change would
/// otherwise leave a second forward row resolving the same alias.
#[test]
fn reallocating_keeps_the_alias_and_retires_the_stale_forward_row() -> Result<()> {
    let overlay = SessionOverlay::new(4096);
    let segment = overlay.install_txn_segment()?;

    let id = EntityId::now();
    let (first, first_hash) = overlay.alloc_session_short_id(&id, b"body-one")?;
    let (second, second_hash) = overlay.alloc_session_short_id(&id, b"body-two")?;

    assert_eq!(first, second, "the room alias must be stable for an entity");
    assert_ne!(
        first_hash, second_hash,
        "fixture bodies must hash differently for this test to mean anything"
    );

    let snapshot = overlay.snapshot()?;
    // The stale row was overlay-only, so the delete REMOVES it outright
    // rather than tombstoning it — no wasted budget byte. `Passthrough`
    // then falls through to base, which by the sigil rule can never hold a
    // session alias, so the alias genuinely resolves to nothing.
    assert!(
        matches!(
            snapshot.lookup_single(
                OverlayKeyspace::ShortIds,
                &encode_session_short_id_forward_key(&first, first_hash),
            ),
            SnapshotLookup::Passthrough
        ),
        "the stale forward row survived a content change"
    );
    assert!(
        matches!(
            snapshot.lookup_single(
                OverlayKeyspace::ShortIds,
                &encode_session_short_id_forward_key(&second, second_hash),
            ),
            SnapshotLookup::Present(_)
        ),
        "the refreshed forward row is missing"
    );

    drop(segment);
    Ok(())
}
