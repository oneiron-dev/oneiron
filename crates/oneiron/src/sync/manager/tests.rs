use super::*;
use crate::config::VaultConfig;
use std::sync::mpsc;
use std::time::Duration;

fn test_manager() -> (tempfile::TempDir, Arc<WindowManager>, WindowKey) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
    let manager = Arc::new(WindowManager::new(
        vault,
        Arc::new(Materializer::new()),
        "test-user",
    ));
    (dir, manager, WindowKey::new("2026-03"))
}

#[test]
fn open_window_tracks_issued_handle_before_discard_can_deregister() {
    let (_dir, manager, key) = test_manager();
    // Armed on this test's own manager: a concurrently running test holds a
    // different manager and cannot consume or release this pause (ONE-1608).
    let pause = Arc::new(test_hooks::HandleIssuePause::new());
    manager.arm_handle_issue_pause(Arc::clone(&pause));

    let open_manager = Arc::clone(&manager);
    let open_key = key.clone();
    let open_thread = std::thread::spawn(move || open_manager.open_window(&open_key).unwrap());
    pause.wait_until_reached();
    assert!(
        manager.windows.try_lock().is_err(),
        "window issue must hold the registry lock until the handle is tracked"
    );

    let (discard_tx, discard_rx) = mpsc::channel();
    let discard_manager = Arc::clone(&manager);
    let discard_key = key.clone();
    let discard_thread = std::thread::spawn(move || {
        discard_tx
            .send(discard_manager.discard_window(&discard_key))
            .unwrap();
    });

    pause.release();
    let issued = open_thread.join().unwrap();
    assert!(
        discard_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
        "discard should remove the registry entry after handle issue completes"
    );
    discard_thread.join().unwrap();

    assert!(manager.loaded_keys().is_empty());
    assert!(
        manager.while_window_closed(&key, || ()).is_none(),
        "discard racing handle issue must still leave the issued handle tracked"
    );
    drop(issued);
    assert!(
        manager.while_window_closed(&key, || ()).is_some(),
        "dead issued handles should prune after the external handle drops"
    );
}

#[test]
fn window_lookup_tracks_issued_handle_before_discard_can_deregister() {
    let (_dir, manager, key) = test_manager();
    let initial = manager.open_window(&key).unwrap();
    drop(initial);
    manager.issued_handles.lock().unwrap().remove(&key);

    // Armed after the setup open above, and on this test's own manager, so
    // neither that setup call nor a concurrent test can consume it
    // (ONE-1608).
    let pause = Arc::new(test_hooks::HandleIssuePause::new());
    manager.arm_handle_issue_pause(Arc::clone(&pause));

    let lookup_manager = Arc::clone(&manager);
    let lookup_key = key.clone();
    let lookup_thread = std::thread::spawn(move || lookup_manager.window(&lookup_key).unwrap());
    pause.wait_until_reached();
    assert!(
        manager.windows.try_lock().is_err(),
        "registry lookup must hold the registry lock until the handle is tracked"
    );

    let (discard_tx, discard_rx) = mpsc::channel();
    let discard_manager = Arc::clone(&manager);
    let discard_key = key.clone();
    let discard_thread = std::thread::spawn(move || {
        discard_tx
            .send(discard_manager.discard_window(&discard_key))
            .unwrap();
    });

    pause.release();
    let issued = lookup_thread.join().unwrap();
    assert!(
        discard_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
        "discard should remove the registry entry after handle lookup completes"
    );
    discard_thread.join().unwrap();

    assert!(manager.loaded_keys().is_empty());
    assert!(
        manager.while_window_closed(&key, || ()).is_none(),
        "discard racing handle lookup must still leave the issued handle tracked"
    );
    drop(issued);
    assert!(
        manager.while_window_closed(&key, || ()).is_some(),
        "dead issued handles should prune after the external handle drops"
    );
}

/// Sol R4 F1 (#1456): two sweeps that reach one window at once, the
/// housekeeping pass and an owner's `maintain()`, must not let the one that
/// ends first reopen the window while the other is still between its read
/// and its compaction write. The second is left out, and an open that comes
/// meanwhile waits for the first.
#[test]
fn a_second_sweep_of_a_window_another_holds_closed_leaves_it_closed() {
    let (_dir, manager, key) = test_manager();
    let (opened_tx, opened_rx) = mpsc::channel();

    let ran = manager.while_window_closed(&key, || {
        assert!(
            manager.while_window_closed(&key, || ()).is_none(),
            "the second sweep is left out"
        );
        let open_manager = Arc::clone(&manager);
        let open_key = key.clone();
        std::thread::spawn(move || {
            drop(open_manager.open_window(&open_key).unwrap());
            let _ = opened_tx.send(());
        });
        assert!(
            opened_rx.recv_timeout(Duration::from_millis(300)).is_err(),
            "the window opened while the first sweep held it closed"
        );
    });

    assert!(ran.is_some());
    opened_rx
        .recv_timeout(Duration::from_secs(20))
        .expect("the open goes ahead once the first sweep is done");
}
