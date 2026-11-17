//! FIX 25183 (REPLACEMENT-FORWARD-VS-NOTE-SCRUB-LOCK-ORDER): a window
//! replacement holds the window registry lock while its forward pass takes
//! the materializer lock. Observer B's tombstone batch takes a deleted NOTE's
//! bundle attachments out of the other live windows, and lists those windows
//! through the registry lock. That scrub must not wait for the registry lock
//! while it holds the materializer lock.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use loro::ExportMode;

use crate::Vault;
use crate::deletion::TombstoneReason;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_TURN;
use crate::sync::WindowKey;
use crate::sync::bridge::Materializer;
use crate::sync::loro_support::map_insert_bytes;
use crate::sync::manager::WindowManager;
use crate::sync::note::{arm_scrub_entry_hook, seed_waiting_bundle};
use crate::sync::schema::create_window_doc;
use crate::sync::window::arm_index_built_hook;

/// The window whose document takes the NOTE's tombstone.
const DELETING_WINDOW: &str = "2019-01";
/// The window that carries a review bundle naming the NOTE.
const BUNDLE_WINDOW: &str = "2019-02";

/// How a window replacement and a NOTE delete in another window ran side by side.
pub struct ScrubBesideReplacement {
    /// The replacement's forward pass began while it held the registry lock.
    pub replacement_reached_forward_pass: bool,
    /// The NOTEs whose scrub of the other live windows began while the
    /// replacement held the registry lock; `None` when none began then.
    pub scrubbed_during_replacement: Option<Vec<EntityId>>,
    /// The replacement returned installed within the deadline.
    pub replacement_installed: bool,
    /// The tombstone's commit, with its observers, returned within the deadline.
    pub tombstone_committed: bool,
    /// The bundle window still carries the bundle naming the NOTE.
    pub bundle_left: bool,
    /// The NOTE the tombstone deletes.
    pub note: EntityId,
}

/// A TURN carrier stamped `at`.
fn turn_carrier(at: u64) -> Vec<u8> {
    let mut blob = vec![ENTITY_TYPE_TURN];
    for _ in 0..3 {
        blob.extend_from_slice(&at.to_be_bytes());
    }
    blob.extend_from_slice(b"replacement row");
    blob
}

/// A v2 hard tombstone value: `[reason:1][deleted_at:8 LE][request_id:16]`.
fn hard_tombstone(at: u64) -> Vec<u8> {
    let mut value = vec![TombstoneReason::UserHardDelete.wire_byte()];
    value.extend_from_slice(&at.to_le_bytes());
    value.extend_from_slice(&[0x5C; 16]);
    value
}

/// Opens two live windows of one manager over `vault`: one whose document
/// takes a NOTE's hard tombstone, one that carries a review bundle naming that
/// NOTE. A third window of the same manager is replaced by a hub's
/// history-free snapshot on another thread. As that replacement's forward pass
/// begins, under the registry lock and before it takes the materializer lock,
/// the tombstone commits in the first window, and the replacement waits up to
/// `wait` for the commit's NOTE scrub to begin before it goes on. Each side
/// then has its deadline. A side stuck past it is left running and reported
/// as not returned, so the run never hangs.
///
/// # Errors
///
/// A window that does not open, or a hub snapshot that does not export.
pub fn note_scrub_beside_replacement(
    vault: &Arc<Vault>,
    wait: Duration,
) -> Result<ScrubBesideReplacement> {
    let manager = Arc::new(WindowManager::new(
        Arc::clone(vault),
        Arc::new(Materializer::new()),
        "note-scrub-lock-order",
    ));
    let at = vault.store.clock.now_recorded_at();
    let replaced = WindowKey::from_timestamp(at);
    let (deleting, bundled) = (
        WindowKey::new(DELETING_WINDOW),
        WindowKey::new(BUNDLE_WINDOW),
    );
    if replaced == deleting || replaced == bundled {
        return Err(Error::InvariantViolation(
            "the replaced window must be a third window",
        ));
    }
    let deleting_window = manager.open_window(&deleting)?;
    let bundle_window = manager.open_window(&bundled)?;
    let note = EntityId::now();
    let bundle_key = seed_waiting_bundle(&bundle_window.doc, EntityId::now(), note)?;

    let hub = create_window_doc("hub", &replaced);
    map_insert_bytes(
        &hub.get_map("entities"),
        &EntityId::now().to_hex(),
        &turn_carrier(at),
    )?;
    hub.commit();
    let snapshot = hub
        .export(ExportMode::shallow_snapshot(&hub.oplog_frontiers()))
        .map_err(|_| Error::InvariantViolation("the hub snapshot did not export"))?;

    let (pass_tx, pass_rx) = mpsc::channel::<()>();
    let (scrub_tx, scrub_rx) = mpsc::channel::<Vec<EntityId>>();
    let (replaced_tx, replaced_rx) = mpsc::channel::<bool>();
    let (committed_tx, committed_rx) = mpsc::channel::<bool>();
    let scrubbed = Arc::new(Mutex::new(None::<Vec<EntityId>>));

    let replacer = {
        let (manager, scrubbed) = (Arc::clone(&manager), Arc::clone(&scrubbed));
        let key = replaced.clone();
        std::thread::spawn(move || {
            arm_index_built_hook(move || {
                let _ = pass_tx.send(());
                let began = scrub_rx.recv_timeout(wait).ok();
                *scrubbed
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = began;
            });
            let installed = manager
                .replace_window(&key, &snapshot, &HashMap::new())
                .is_ok();
            let _ = replaced_tx.send(installed);
        })
    };
    if pass_rx.recv_timeout(wait).is_err() {
        let replacement_installed = replaced_rx.recv_timeout(wait).unwrap_or(false);
        return Ok(ScrubBesideReplacement {
            replacement_reached_forward_pass: false,
            scrubbed_during_replacement: None,
            replacement_installed,
            tombstone_committed: false,
            bundle_left: true,
            note,
        });
    }

    let deleter = {
        let doc = deleting_window.doc.clone();
        std::thread::spawn(move || {
            arm_scrub_entry_hook(move |notes| {
                let _ = scrub_tx.send(notes.to_vec());
            });
            let inserted = map_insert_bytes(
                &doc.get_map("tombstones"),
                &note.to_hex(),
                &hard_tombstone(at),
            )
            .is_ok();
            doc.commit();
            let _ = committed_tx.send(inserted);
        })
    };

    let replacement_installed = replaced_rx.recv_timeout(wait * 3);
    let tombstone_committed = committed_rx.recv_timeout(wait);
    let returned = replacement_installed.is_ok() && tombstone_committed.is_ok();
    if returned {
        replacer
            .join()
            .map_err(|_| Error::InvariantViolation("the replacement thread panicked"))?;
        deleter
            .join()
            .map_err(|_| Error::InvariantViolation("the deleting thread panicked"))?;
    }
    let scrubbed_during_replacement = scrubbed
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    Ok(ScrubBesideReplacement {
        replacement_reached_forward_pass: true,
        scrubbed_during_replacement,
        replacement_installed: replacement_installed.unwrap_or(false),
        tombstone_committed: tombstone_committed.unwrap_or(false),
        bundle_left: bundle_window
            .doc
            .get_map("note_proposals")
            .get(&bundle_key)
            .is_some(),
        note,
    })
}
