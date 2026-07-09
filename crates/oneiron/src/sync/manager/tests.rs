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
    let pause = Arc::new(test_hooks::HandleIssuePause::new());
    test_hooks::arm_handle_issue_pause(Arc::clone(&pause));

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
        manager.window_live_for_sweep(&key),
        "discard racing handle issue must still leave the issued handle tracked"
    );
    drop(issued);
    assert!(
        !manager.window_live_for_sweep(&key),
        "dead issued handles should prune after the external handle drops"
    );
}

#[test]
fn window_lookup_tracks_issued_handle_before_discard_can_deregister() {
    let (_dir, manager, key) = test_manager();
    let initial = manager.open_window(&key).unwrap();
    drop(initial);
    manager.issued_handles.lock().unwrap().remove(&key);

    let pause = Arc::new(test_hooks::HandleIssuePause::new());
    test_hooks::arm_handle_issue_pause(Arc::clone(&pause));

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
        manager.window_live_for_sweep(&key),
        "discard racing handle lookup must still leave the issued handle tracked"
    );
    drop(issued);
    assert!(
        !manager.window_live_for_sweep(&key),
        "dead issued handles should prune after the external handle drops"
    );
}
