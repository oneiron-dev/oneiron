//! FIX 27743 (SLIM-DROP-PERSIST-VS-NOTE-SCRUB-REGISTRY-REENTRY): the slim
//! shed (`WindowManager::drop_rebuildable_windows`) persists every live window
//! before it deregisters them. A persist merges the window's stored rows into
//! its observed document, so a stored update carrying a NOTE tombstone the live
//! document lacks fires Observer B's NOTE scrub on the shed's own thread. The
//! scrub lists the other live windows through the window registry lock. The
//! shed must not hold that lock across its persists.

use std::sync::{Arc, mpsc};
use std::time::Duration;

use loro::ExportMode;

use crate::Vault;
use crate::deletion::TombstoneReason;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::sync::WindowKey;
use crate::sync::bridge::{Materializer, persist_window_update};
use crate::sync::loro_support::map_insert_bytes;
use crate::sync::manager::WindowManager;
use crate::sync::note::{arm_scrub_entry_hook, seed_waiting_bundle};

/// The window whose stored update carries the NOTE's tombstone.
const DELETING_WINDOW: &str = "2019-01";
/// The window that carries a review bundle naming the NOTE.
const BUNDLE_WINDOW: &str = "2019-02";

/// How a slim shed ran over a window whose stored rows delete a NOTE.
pub struct SlimDropBesideNoteScrub {
    /// The NOTEs whose scrub of the other live windows began on the shed's
    /// thread; `None` when none began within the deadline.
    pub scrubbed_during_drop: Option<Vec<EntityId>>,
    /// The shed returned within its deadline.
    pub drop_returned: bool,
    /// How many windows the shed dropped, when it returned `Ok`.
    pub dropped_windows: Option<u64>,
    /// The shed's error, when it returned one.
    pub drop_error: Option<String>,
    /// How many windows were still loaded after the shed returned; `None`
    /// when it did not return.
    pub loaded_after: Option<usize>,
    /// The deleting window, opened again, carries the NOTE's tombstone.
    pub tombstone_kept: bool,
    /// The bundle window, opened again, still carries the bundle naming the
    /// NOTE.
    pub bundle_left_after_reopen: bool,
    /// The NOTE the tombstone deletes.
    pub note: EntityId,
}

/// A v2 hard tombstone value: `[reason:1][deleted_at:8 LE][request_id:16]`.
fn hard_tombstone(at: u64) -> Vec<u8> {
    let mut value = vec![TombstoneReason::UserHardDelete.wire_byte()];
    value.extend_from_slice(&at.to_le_bytes());
    value.extend_from_slice(&[0x5C; 16]);
    value
}

/// Opens two live windows of one manager over `vault`: one whose stored rows
/// gain an update with a NOTE's hard tombstone its live document lacks, and
/// one that carries a review bundle naming that NOTE. With no handle held,
/// the slim shed then runs on another thread, and each step waits up to
/// `wait` for it: the NOTE scrub the deleting window's persist fires, then
/// the shed's return (three times `wait`). A shed stuck past its deadline is
/// left running and reported as not returned, and nothing more is asked of
/// the manager, so the run never hangs. Once the shed returned, both windows
/// are opened again.
///
/// # Errors
///
/// A window that does not open, or an update that does not export or store.
pub fn slim_drop_beside_note_scrub(
    vault: &Arc<Vault>,
    wait: Duration,
) -> Result<SlimDropBesideNoteScrub> {
    let manager = Arc::new(WindowManager::new(
        Arc::clone(vault),
        Arc::new(Materializer::new()),
        "slim-drop-note-scrub",
    ));
    let (deleting, bundled) = (
        WindowKey::new(DELETING_WINDOW),
        WindowKey::new(BUNDLE_WINDOW),
    );
    let deleting_window = manager.open_window(&deleting)?;
    let bundle_window = manager.open_window(&bundled)?;
    let note = EntityId::now();
    let bundle_key = seed_waiting_bundle(&bundle_window.doc, EntityId::now(), note)?;

    // The update a parallel writer stored for the deleting window: the NOTE's
    // tombstone, which the live document never saw.
    let writer = deleting_window.doc.fork();
    map_insert_bytes(
        &writer.get_map("tombstones"),
        &note.to_hex(),
        &hard_tombstone(vault.store.clock.now_recorded_at()),
    )?;
    writer.commit();
    let update = writer
        .export(ExportMode::updates(&deleting_window.doc.oplog_vv()))
        .map_err(|_| Error::InvariantViolation("the tombstone update did not export"))?;
    persist_window_update(vault, DELETING_WINDOW, &update)?;
    drop(deleting_window);
    drop(bundle_window);

    let (scrub_tx, scrub_rx) = mpsc::channel::<Vec<EntityId>>();
    let (dropped_tx, dropped_rx) = mpsc::channel::<std::result::Result<u64, String>>();
    let shed = {
        let manager = Arc::clone(&manager);
        std::thread::spawn(move || {
            arm_scrub_entry_hook(move |notes| {
                let _ = scrub_tx.send(notes.to_vec());
            });
            let dropped = manager
                .drop_rebuildable_windows()
                .map(|report| report.sync_windows)
                .map_err(|error| error.to_string());
            let _ = dropped_tx.send(dropped);
        })
    };
    let scrubbed_during_drop = scrub_rx.recv_timeout(wait).ok();
    let Ok(dropped) = dropped_rx.recv_timeout(wait * 3) else {
        return Ok(SlimDropBesideNoteScrub {
            scrubbed_during_drop,
            drop_returned: false,
            dropped_windows: None,
            drop_error: None,
            loaded_after: None,
            tombstone_kept: false,
            bundle_left_after_reopen: true,
            note,
        });
    };
    shed.join()
        .map_err(|_| Error::InvariantViolation("the shed thread panicked"))?;
    let loaded_after = manager.loaded_keys().len();

    let tombstone_kept = manager
        .open_window(&deleting)?
        .doc
        .get_map("tombstones")
        .get(&note.to_hex())
        .is_some();
    let bundle_left_after_reopen = manager
        .open_window(&bundled)?
        .doc
        .get_map("note_proposals")
        .get(&bundle_key)
        .is_some();
    let (dropped_windows, drop_error) = match dropped {
        Ok(windows) => (Some(windows), None),
        Err(error) => (None, Some(error)),
    };
    Ok(SlimDropBesideNoteScrub {
        scrubbed_during_drop,
        drop_returned: true,
        dropped_windows,
        drop_error,
        loaded_after: Some(loaded_after),
        tombstone_kept,
        bundle_left_after_reopen,
        note,
    })
}
