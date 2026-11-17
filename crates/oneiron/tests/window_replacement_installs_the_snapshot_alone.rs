// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
//! A window replacement is installed, never merged (fix list row
//! [SYNC-REPLACEMENT-NEVER-MERGED-NO-DOOR]).
//!
//! Canon, ARCH-0023b "Installing a replacement": "The receiver never merges it. It builds a fresh
//! document from the snapshot alone." A local value carries over only where it wins Loro's order;
//! one that loses gives way to the peer's value and comes back as a `ReplacementConflict`.
//!
//! A device and its hub share a row. Unseen by the other, the device edits that row and writes a
//! row of its own, and the hub writes two rows and then edits the shared row, later in Loro's
//! order. The device installs the hub's replacement through the production seam
//! (`window::prepare_replacement`, by the sync harness). It must read the hub's edit of the shared
//! row, name its own edit as the one conflict, keep its own row, and hold no operation of its old
//! window: every operation of the installed window is the snapshot's or one a fresh author wrote,
//! never one under the old window's author, whose counters the snapshot never saw.

#![cfg(feature = "sync")]

#[path = "it_sync/sync_harness/mod.rs"]
mod sync_harness;

use loro::{LoroDoc, LoroValue, PeerID};
use oneiron::EntityId;
use oneiron::sync::types::WindowKey;
use oneiron::sync::window::{self, ReplacementConflict};

use crate::sync_harness::{
    T0, TestNode, WINDOW, make_entity_blob, map_get_bytes, sync_through_doors, vault_pair,
};

/// The device after it installed the hub's replacement of their diverged window.
struct Installed {
    device: TestNode,
    hub: TestNode,
    /// The row both sides edited, the hub last.
    both_edited: EntityId,
    /// The device's edit of that row, which the hub never saw.
    device_edit: Vec<u8>,
    /// The hub's edit of that row, which the device never saw.
    hub_edit: Vec<u8>,
    /// A row only the device wrote.
    device_row: EntityId,
    device_row_blob: Vec<u8>,
    /// The device window's author before the install.
    old_author: PeerID,
    /// The hub's replacement the device installed.
    snapshot: Vec<u8>,
    /// What the install could not carry over.
    conflicts: Vec<ReplacementConflict>,
}

fn install_after_divergence() -> Installed {
    // `vault_pair` pins node-a to peer 1 and node-b to peer 2: the hub also wins an equal-lamport
    // tie.
    let (mut device, hub) = vault_pair();
    let key = WindowKey::new(WINDOW);
    let both_edited = EntityId::now();
    hub.put_entity_in_window(
        WINDOW,
        &both_edited,
        &make_entity_blob(1, T0, b"shared prefix"),
    );
    sync_through_doors(&hub, &mut device);
    assert!(
        device.vault.get_raw(&both_edited).unwrap().is_some(),
        "the device holds the shared row before the two sides diverge"
    );

    // The device edits the shared row first and writes a row of its own; the hub sees neither.
    let device_edit = make_entity_blob(1, T0 + 1, b"device edit");
    device.put_entity_in_window(WINDOW, &both_edited, &device_edit);
    let device_row = EntityId::now();
    let device_row_blob = make_entity_blob(1, T0 + 2, b"device row");
    device.put_entity_in_window(WINDOW, &device_row, &device_row_blob);

    // The hub writes two rows and then edits the shared row: its edit comes later in Loro's order.
    hub.put_entity_in_window(
        WINDOW,
        &EntityId::now(),
        &make_entity_blob(1, T0 + 3, b"hub row one"),
    );
    hub.put_entity_in_window(
        WINDOW,
        &EntityId::now(),
        &make_entity_blob(1, T0 + 4, b"hub row two"),
    );
    let hub_edit = make_entity_blob(1, T0 + 5, b"hub edit");
    hub.put_entity_in_window(WINDOW, &both_edited, &hub_edit);

    let old_author = device.doc(WINDOW).peer_id();
    let snapshot = window::export_window_replacement(&hub.vault, &key, hub.doc(WINDOW), None)
        .unwrap()
        .expect("the hub withholds no test window");
    let conflicts = device.install_replacement(&snapshot);
    Installed {
        device,
        hub,
        both_edited,
        device_edit,
        hub_edit,
        device_row,
        device_row_blob,
        old_author,
        snapshot,
        conflicts,
    }
}

#[test]
fn the_device_holds_the_hubs_value_and_names_its_own_overridden_edit() {
    let run = install_after_divergence();
    let shared = run.both_edited.to_hex();
    let entities = run.device.doc(WINDOW).get_map("entities");
    assert_eq!(
        map_get_bytes(&run.hub.doc(WINDOW).get_map("entities"), &shared),
        Some(run.hub_edit.clone()),
        "the hub's window holds its own edit of the shared row"
    );
    assert_eq!(
        map_get_bytes(&entities, &shared),
        Some(run.hub_edit.clone()),
        "the installed window holds the hub's edit of the row both sides changed"
    );
    assert_eq!(
        run.device.vault.get_raw(&run.both_edited).unwrap(),
        run.hub.vault.get_raw(&run.both_edited).unwrap(),
        "the device reads the hub's edit of the row both sides changed"
    );

    let [conflict] = run.conflicts.as_slice() else {
        panic!(
            "the device's overridden edit is the one value the install could not carry: {:?}",
            run.conflicts
        );
    };
    assert_eq!(
        (conflict.map.as_str(), conflict.key.as_str()),
        ("entities", shared.as_str()),
        "the conflict names the shared row"
    );
    assert!(
        matches!(&conflict.held, Some(LoroValue::Binary(held)) if held.to_vec() == run.device_edit),
        "the conflict carries the device's own edit: {:?}",
        conflict.held
    );

    assert_eq!(
        map_get_bytes(&entities, &run.device_row.to_hex()),
        Some(run.device_row_blob.clone()),
        "the row only the device wrote carries over into the installed window"
    );
    assert!(
        run.device.vault.get_raw(&run.device_row).unwrap().is_some(),
        "the device still reads the row only it wrote"
    );
}

#[test]
fn the_installed_window_holds_none_of_the_old_windows_operations() {
    let run = install_after_divergence();
    let installed = run.device.doc(WINDOW);
    let author = installed.peer_id();
    let installed_vv = installed.oplog_vv();
    assert!(
        installed_vv.get(&run.old_author).is_none(),
        "the installed window holds an operation under the old window's author {}: {installed_vv:?}",
        run.old_author
    );
    assert_ne!(
        author, run.old_author,
        "the installed window writes under a fresh author, never the old window's"
    );
    let snapshot_vv = LoroDoc::from_snapshot(&run.snapshot).unwrap().oplog_vv();
    let strays: Vec<_> = installed_vv
        .iter()
        .filter(|&(peer, end)| *peer != author && snapshot_vv.get(peer) != Some(end))
        .collect();
    assert!(
        strays.is_empty(),
        "operations neither the snapshot's nor the installed window's own author's: {strays:?} \
         (snapshot {snapshot_vv:?}, installed {installed_vv:?})"
    );
}
