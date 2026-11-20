use super::support::*;
use super::*;

/// Parks the soft delete of `subject` at `BeforeTombstonePublish`, runs
/// `replay` while it is parked, then commits `revoke`, releases the delete and
/// returns its result.
#[cfg(feature = "sync")]
fn replay_while_parked_then_revoke(
    harness: &PublishBoundaryHarness,
    owner: EntityId,
    subject: EntityId,
    revoke: crate::authority::AuthorityLogEntry,
    replay: impl FnOnce(&PublishBoundaryHarness),
) -> MemoryResult<DeleteReceipt> {
    let (arrived_tx, arrived_rx) = std::sync::mpsc::sync_channel(0);
    let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel::<()>(0);
    harness.vault.test_hooks().install_delete_rendezvous(
        crate::deletion::DeleteRendezvous::BeforeTombstonePublish,
        subject,
        arrived_tx,
        resume_rx,
    );
    std::thread::scope(|scope| {
        // Moved in, so a failed assertion in `replay` drops the sender while
        // it unwinds and the parked deleter resumes; the scope then joins it
        // instead of waiting on it forever.
        let resume_tx = resume_tx;
        let vault_ref = harness.vault.as_ref();
        let deleter = scope.spawn(move || {
            facade_for(vault_ref, owner)
                .safe_delete(&subject.to_hex(), SafeDeleteReason::UserDelete)
        });
        arrived_rx
            .recv()
            .expect("the deleter must park at BeforeTombstonePublish");
        replay(harness);
        harness
            .vault
            .put_authority_log_entries(&[(revoke, test_time(3), 3)])
            .expect("commit the revocation while the deleter is parked");
        resume_tx.send(()).expect("release the deleter");
        deleter.join().expect("deleter thread must not panic")
    })
}

/// A window replay leaves a soft delete's pending marker to its own publication: while the soft arm is parked after its scrub commit with its `pt:` marker staged, another door's `publish_pending_tombstones` and a window open each publish nothing for the id and leave the marker, so a revocation landing before the publish still refuses with nothing published; red at `610f54397651` because with no in-flight hold either replay published the marker with no re-proof, writing the tombstone into the `d:w:` snapshot and a delete-bearing `q:` row.
#[cfg(feature = "sync")]
#[test]
fn a_window_replay_leaves_a_soft_delete_marker_to_its_own_publication() {
    {
        let mut harness = PublishBoundaryHarness::open("soft-marker-replay-hold", false);
        let owner = put_owner(&harness.vault);
        let subject = put_person(&harness.vault, 0x2A);
        let revoke = root_binding_with_pending_revocation(&harness.vault, 0x2B, owner);
        let window_key = crate::sync::WindowKey::from_timestamp(1);
        let outcome = replay_while_parked_then_revoke(&harness, owner, subject, revoke, |held| {
            let replayed =
                crate::sync::window::publish_pending_tombstones(held.vault.as_ref(), &window_key)
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
        let outcome = replay_while_parked_then_revoke(&harness, owner, subject, revoke, |held| {
            let manager = held
                .vault
                .live_window_manager
                .lock()
                .expect("manager lock")
                .upgrade()
                .expect("the harness manager stays attached");
            let opened = manager
                .open_window(&window_key)
                .expect("open the window while the soft delete holds its marker");
            assert!(
                opened
                    .doc
                    .get_map("tombstones")
                    .get(&subject.to_hex())
                    .is_none(),
                "transient window open: no tombstone in the opened doc"
            );
            assert!(
                !held.snapshot_tombstoned(&subject),
                "transient window open: no tombstone in the d:w: snapshot"
            );
            assert!(
                !held.queue_rows_tombstoned(&subject),
                "transient window open: no delete-bearing q: row"
            );
            assert!(
                held.replayable_pending_marker(&subject),
                "transient window open: the pt: marker stays for its own publication"
            );
            drop(opened);
            assert!(
                manager
                    .unload_window(&window_key)
                    .expect("unload back to transient"),
                "transient window open: the probe window unloads"
            );
        });
        let err = outcome.expect_err("a revocation before the publish commit must refuse");
        assert_eq!(err.code, MEMORY_CODE_OWNER_BINDING_REQUIRED);
        harness.assert_nothing_published(&subject, "transient window open");
    }
}
