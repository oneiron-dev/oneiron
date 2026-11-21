use super::support::*;
use super::*;

/// How long a step started while the soft delete is parked gets to finish
/// before the test reads it as waiting for the publication.
#[cfg(feature = "sync")]
const PARKED_STEP_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// Parks the soft delete of `subject` at `BeforeTombstonePublish`, runs
/// `while_parked` while it is parked, then commits `revoke` when one is given,
/// releases the delete and returns its result with what `while_parked`
/// returned.
#[cfg(feature = "sync")]
fn run_while_soft_delete_parked<T>(
    harness: &PublishBoundaryHarness,
    owner: EntityId,
    subject: EntityId,
    revoke: Option<crate::authority::AuthorityLogEntry>,
    while_parked: impl FnOnce(&PublishBoundaryHarness) -> T,
) -> (MemoryResult<DeleteReceipt>, T) {
    let (arrived_tx, arrived_rx) = std::sync::mpsc::sync_channel(0);
    let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel::<()>(0);
    harness.vault.test_hooks().install_delete_rendezvous(
        crate::deletion::DeleteRendezvous::BeforeTombstonePublish,
        subject,
        arrived_tx,
        resume_rx,
    );
    std::thread::scope(|scope| {
        // Moved in, so a failed assertion in `while_parked` drops the sender
        // while it unwinds and the parked deleter resumes; the scope then
        // joins it instead of waiting on it forever.
        let resume_tx = resume_tx;
        let vault_ref = harness.vault.as_ref();
        let deleter = scope.spawn(move || {
            facade_for(vault_ref, owner)
                .safe_delete(&subject.to_hex(), SafeDeleteReason::UserDelete)
        });
        arrived_rx
            .recv()
            .expect("the deleter must park at BeforeTombstonePublish");
        let parked = while_parked(harness);
        if let Some(revoke) = revoke {
            harness
                .vault
                .put_authority_log_entries(&[(revoke, test_time(3), 3)])
                .expect("commit the revocation while the deleter is parked");
        }
        resume_tx.send(()).expect("release the deleter");
        let deleted = deleter.join().expect("deleter thread must not panic");
        (deleted, parked)
    })
}

/// The window manager the harness attached to its vault.
#[cfg(feature = "sync")]
fn attached_manager(
    harness: &PublishBoundaryHarness,
) -> std::sync::Arc<crate::sync::WindowManager> {
    harness
        .vault
        .live_window_manager
        .lock()
        .expect("manager lock")
        .upgrade()
        .expect("the harness manager stays attached")
}

/// Starts `step` on its own thread and waits [`PARKED_STEP_WAIT`] for it:
/// whether it finished in that time, and its thread.
#[cfg(feature = "sync")]
fn start_beside_parked_delete<T: Send + 'static>(
    step: impl FnOnce() -> T + Send + 'static,
) -> (bool, std::thread::JoinHandle<T>) {
    let (finished_tx, finished_rx) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        let result = step();
        let _ = finished_tx.send(());
        result
    });
    (finished_rx.recv_timeout(PARKED_STEP_WAIT).is_ok(), thread)
}

/// A window replay leaves a soft delete's pending marker to its own publication, and a window open waits for that publication: while the soft arm is parked inside its publication to a closed window, with its `pt:` marker staged, another door's `publish_pending_tombstones` publishes nothing for the id and leaves the marker, and a window open does not finish until the publication has ended, so a revocation landing before the publish still refuses with nothing published, and the window opens without the refused tombstone; the replay leg is red at `610f54397651`, where with no in-flight hold the replay published the marker with no re-proof (a tombstone in the `d:w:` snapshot and a delete-bearing `q:` row), and the open leg is red at `29b552bc35b0`, where the open finished while the delete was parked.
#[cfg(feature = "sync")]
#[test]
fn a_window_replay_leaves_a_soft_delete_marker_to_its_own_publication() {
    {
        let mut harness = PublishBoundaryHarness::open("soft-marker-replay-hold", false);
        let owner = put_owner(&harness.vault);
        let subject = put_person(&harness.vault, 0x2A);
        let revoke = root_binding_with_pending_revocation(&harness.vault, 0x2B, owner);
        let window_key = crate::sync::WindowKey::from_timestamp(1);
        let (outcome, ()) =
            run_while_soft_delete_parked(&harness, owner, subject, Some(revoke), |held| {
                let replayed = crate::sync::window::publish_pending_tombstones(
                    held.vault.as_ref(),
                    &window_key,
                )
                .expect("replay while the soft delete holds its marker");
                assert_eq!(
                    replayed, 0,
                    "transient publish_pending: a held marker replays nothing"
                );
                assert!(
                    !held.snapshot_tombstoned(&subject),
                    "transient publish_pending: no tombstone in the d:w: snapshot"
                );
                assert!(
                    !held.queue_rows_tombstoned(&subject),
                    "transient publish_pending: no delete-bearing q: row"
                );
                assert!(
                    held.replayable_pending_marker(&subject),
                    "transient publish_pending: the pt: marker stays for its own publication"
                );
            });
        let err = outcome.expect_err("a revocation before the publish commit must refuse");
        assert_eq!(err.code, MEMORY_CODE_OWNER_BINDING_REQUIRED);
        harness.assert_nothing_published(&subject, "transient publish_pending");
    }
    {
        let mut harness = PublishBoundaryHarness::open("soft-marker-window-open-hold", false);
        let owner = put_owner(&harness.vault);
        let subject = put_person(&harness.vault, 0x2A);
        let revoke = root_binding_with_pending_revocation(&harness.vault, 0x2B, owner);
        let window_key = crate::sync::WindowKey::from_timestamp(1);
        let manager = attached_manager(&harness);
        let (outcome, (opened_while_parked, opener)) =
            run_while_soft_delete_parked(&harness, owner, subject, Some(revoke), |_| {
                let (manager, window_key) = (std::sync::Arc::clone(&manager), window_key.clone());
                start_beside_parked_delete(move || {
                    manager
                        .open_window(&window_key)
                        .map_err(|error| error.to_string())
                })
            });
        let opened = opener
            .join()
            .expect("opener thread must not panic")
            .expect("the window opens once the publication has ended");
        assert!(
            !opened_while_parked,
            "transient window open: the open waits for the publication the soft delete holds"
        );
        let err = outcome.expect_err("a revocation before the publish commit must refuse");
        assert_eq!(err.code, MEMORY_CODE_OWNER_BINDING_REQUIRED);
        assert!(
            opened
                .doc
                .get_map("tombstones")
                .get(&subject.to_hex())
                .is_none(),
            "transient window open: no tombstone of the refused publication in the opened doc"
        );
        drop(opened);
        assert!(
            manager
                .unload_window(&window_key)
                .expect("unload back to transient"),
            "transient window open: the probe window unloads"
        );
        harness.assert_nothing_published(&subject, "transient window open");
    }
}

/// A peer's history-free snapshot of `window_key` holding one TURN row at
/// `learned_at = 1`, the time of every fixture entity.
#[cfg(feature = "sync")]
fn hub_window_snapshot(window_key: &crate::sync::WindowKey) -> Vec<u8> {
    let hub = crate::sync::schema::create_window_doc("hub", window_key);
    let mut row = vec![crate::registry::ENTITY_TYPE_TURN];
    for _ in 0..3 {
        row.extend_from_slice(&1_u64.to_be_bytes());
    }
    row.extend_from_slice(b"hub row");
    crate::sync::loro_support::map_insert_bytes(
        &hub.get_map("entities"),
        &EntityId::now().to_hex(),
        &row,
    )
    .expect("write the hub row");
    hub.commit();
    hub.export(loro::ExportMode::shallow_snapshot(&hub.oplog_frontiers()))
        .expect("export the hub snapshot")
}

/// A window replacement waits for a soft delete's publication to a closed window and keeps its tombstone: while the soft arm is parked inside that publication, a peer's replacement of the window does not finish; once the publication commits, the installed window carries the tombstone, as does its `d:w:` snapshot; red at `29b552bc35b0`, where the replacement skipped the held `pt:` marker and installed while the delete was parked, so the publication's tombstone never reached the installed window (#9712 review round 1).
#[cfg(feature = "sync")]
#[test]
fn a_window_replacement_waits_for_a_soft_delete_publication_and_keeps_its_tombstone() {
    let harness = PublishBoundaryHarness::open("soft-publish-beside-replacement", false);
    let owner = put_owner(&harness.vault);
    let subject = put_person(&harness.vault, 0x2A);
    let window_key = crate::sync::WindowKey::from_timestamp(1);
    let manager = attached_manager(&harness);
    let snapshot = hub_window_snapshot(&window_key);
    let (deleted, (replaced_while_parked, replacer)) =
        run_while_soft_delete_parked(&harness, owner, subject, None, |_| {
            let (manager, window_key) = (std::sync::Arc::clone(&manager), window_key.clone());
            start_beside_parked_delete(move || {
                manager
                    .replace_window(&window_key, &snapshot, &std::collections::HashMap::new())
                    .map(|(window, _conflicts)| window)
                    .map_err(|error| error.to_string())
            })
        });
    let replaced = replacer
        .join()
        .expect("replacer thread must not panic")
        .expect("the replacement installs once the publication has ended");
    assert!(
        !replaced_while_parked,
        "the replacement waits for the publication the soft delete holds"
    );
    deleted.expect("the bound owner's soft delete publishes");
    assert!(
        replaced
            .doc
            .get_map("tombstones")
            .get(&subject.to_hex())
            .is_some(),
        "the installed window carries the published tombstone"
    );
    assert!(
        harness.snapshot_tombstoned(&subject),
        "the installed window's d:w: snapshot carries the published tombstone"
    );
}
