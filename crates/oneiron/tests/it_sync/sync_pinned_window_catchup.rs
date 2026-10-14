//! The stall ticket: a window this vault pinned history-free still brings a peer that is
//! behind it level through its export door, and nothing it scrubbed reaches that peer.

#![allow(clippy::unwrap_used)]

use loro::{ExportMode, LoroDoc};
use oneiron::registry::ENTITY_TYPE_DIAGNOSTIC;
use oneiron::sync::types::WindowKey;
use oneiron::sync::window;
use oneiron::{DeleteReason, EntityId};

use crate::sync_harness::{
    T0, TestNode, WINDOW, make_entity_blob, map_get_bytes, map_insert_bytes, sync_through_doors,
    vault_pair,
};

/// What pins B's window history-free.
#[derive(Clone, Copy, Debug)]
enum PinCause {
    /// B erased a row, and a peer withdrew the delete and put the body back.
    WithdrawnDelete,
    /// A peer handed B a diagnostic carrier, which never syncs.
    LocalOnlyCarrier,
}

/// B imports a hostile peer's update built on B's whole window.
fn import_from_hostile_peer(b: &TestNode, edit: impl FnOnce(&LoroDoc)) {
    let hostile = LoroDoc::new();
    hostile.set_peer_id(3).unwrap();
    hostile
        .import(&b.doc(WINDOW).export(ExportMode::all_updates()).unwrap())
        .unwrap();
    edit(&hostile);
    hostile.commit();
    let behind = b.doc(WINDOW).oplog_vv();
    b.doc(WINDOW)
        .import(&hostile.export(ExportMode::updates(&behind)).unwrap())
        .unwrap();
}

/// Puts the carrier `cause` scrubs into B's window; returns its id.
fn plant(b: &mut TestNode, cause: PinCause) -> EntityId {
    let id = EntityId::now();
    match cause {
        PinCause::WithdrawnDelete => {
            b.put_entity_in_window(WINDOW, &id, &make_entity_blob(1, T0 + 3, b"erased body"));
            let body = map_get_bytes(&b.doc(WINDOW).get_map("entities"), &id.to_hex()).unwrap();
            b.close_window(WINDOW);
            b.vault
                .delete_entity_with_reason(&id, DeleteReason::GdprDelete)
                .unwrap();
            b.recover(WINDOW);
            import_from_hostile_peer(b, |hostile| {
                hostile.get_map("tombstones").delete(&id.to_hex()).unwrap();
                map_insert_bytes(&hostile.get_map("entities"), &id.to_hex(), &body);
            });
        }
        PinCause::LocalOnlyCarrier => import_from_hostile_peer(b, |hostile| {
            map_insert_bytes(
                &hostile.get_map("entities"),
                &id.to_hex(),
                &make_entity_blob(ENTITY_TYPE_DIAGNOSTIC, T0 + 3, b"device diagnostic"),
            );
        }),
    }
    assert!(
        b.vault.get_raw(&id).unwrap().is_none(),
        "{cause:?}: B refused the carrier"
    );
    id
}

/// Bug repro (stall ticket) and done-means: A shares B's window prefix, then B commits more than
/// one change A never sees, and B's export door pins the window history-free. The two sides must
/// still come level through their export doors within the convergence bound, A must read every
/// row B holds, and the scrubbed carrier must reach neither A's rows nor A's window.
#[test]
fn a_peer_behind_a_pinned_window_catches_up_through_its_export_door() {
    for cause in [PinCause::WithdrawnDelete, PinCause::LocalOnlyCarrier] {
        let (a, mut b) = vault_pair();
        let key = WindowKey::new(WINDOW);
        let shared = EntityId::now();
        b.put_entity_in_window(WINDOW, &shared, &make_entity_blob(1, T0, b"shared prefix"));
        sync_through_doors(&a, &b);
        assert!(a.vault.get_raw(&shared).unwrap().is_some());

        // B moves on by separate commits A never sees.
        let mut survivors = vec![shared];
        for (n, body) in [b"first survivor".as_slice(), b"second survivor"]
            .into_iter()
            .enumerate()
        {
            let id = EntityId::now();
            b.put_entity_in_window(WINDOW, &id, &make_entity_blob(1, T0 + 1 + n as u64, body));
            survivors.push(id);
        }
        let carrier = plant(&mut b, cause);

        sync_through_doors(&a, &b);
        assert!(
            window::history_free_window_required(&b.vault, &key).unwrap(),
            "{cause:?}: the export door pinned B's window"
        );
        for id in &survivors {
            assert!(
                a.vault.get_raw(id).unwrap().is_some(),
                "{cause:?}: A never received a row B holds"
            );
        }
        assert!(
            a.vault.get_raw(&carrier).unwrap().is_none(),
            "{cause:?}: the scrubbed carrier became a row on A"
        );
        assert!(
            map_get_bytes(&a.doc(WINDOW).get_map("entities"), &carrier.to_hex()).is_none(),
            "{cause:?}: the scrubbed carrier reached A's window"
        );
    }
}
