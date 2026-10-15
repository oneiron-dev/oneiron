//! The stall ticket: a window this vault pinned history-free still brings a peer that is
//! behind it level through its export door, and nothing it scrubbed reaches that peer.

#![allow(clippy::unwrap_used)]

use loro::{ExportMode, LoroDoc};
use oneiron::registry::ENTITY_TYPE_DIAGNOSTIC;
use oneiron::sync::types::WindowKey;
use oneiron::sync::window::{self, WindowExport};
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

/// Which side of the sync connection is the hub (the server) and which the device.
#[derive(Clone, Copy, Debug)]
enum Hub {
    /// B, whose window is pinned, serves A.
    Pinned,
    /// A, which is behind B, serves B.
    Behind,
}

/// Writes two rows into `node`'s window by separate commits; returns their ids.
fn write_two(node: &mut TestNode, at: u64, bodies: [&[u8]; 2]) -> Vec<EntityId> {
    let mut ids = Vec::new();
    for (n, body) in bodies.into_iter().enumerate() {
        let id = EntityId::now();
        node.put_entity_in_window(WINDOW, &id, &make_entity_blob(1, at + n as u64, body));
        ids.push(id);
    }
    ids
}

/// Bug repro (stall ticket) and done-means, per pin cause and per hub: A shares B's window
/// prefix, then B commits more than one change A never sees and its export door pins the window
/// history-free, while A makes edits of its own it never sends (and, in the both-pinned rows,
/// pins its own window too). The two sides must come level through their export doors within
/// the convergence bound; each must hold every row either wrote, A's unsent edits included; no
/// scrubbed carrier may reach the other side's rows or window; and once level, neither door
/// answers the other with a replacement again.
#[test]
fn a_peer_behind_a_pinned_window_catches_up_through_its_export_door() {
    use PinCause::{LocalOnlyCarrier, WithdrawnDelete};
    let rows = [
        (WithdrawnDelete, None, Hub::Pinned),
        (WithdrawnDelete, None, Hub::Behind),
        (LocalOnlyCarrier, None, Hub::Pinned),
        (LocalOnlyCarrier, None, Hub::Behind),
        (WithdrawnDelete, Some(LocalOnlyCarrier), Hub::Pinned),
        (LocalOnlyCarrier, Some(WithdrawnDelete), Hub::Behind),
    ];
    for (cause, own_pin, hub) in rows {
        let row = format!("{cause:?}/{own_pin:?}/{hub:?}");
        let (mut a, mut b) = vault_pair();
        let key = WindowKey::new(WINDOW);
        let shared = EntityId::now();
        b.put_entity_in_window(WINDOW, &shared, &make_entity_blob(1, T0, b"shared prefix"));
        sync_through_doors(&b, &mut a);
        assert!(a.vault.get_raw(&shared).unwrap().is_some());

        // B moves on by separate commits A never sees, then pins; A edits on its own.
        let mut rows_of_b = write_two(&mut b, T0 + 1, [b"first survivor", b"second survivor"]);
        rows_of_b.push(shared);
        let mut carriers = vec![plant(&mut b, cause)];
        let rows_of_a = write_two(&mut a, T0 + 10, [b"unsent edit", b"second unsent edit"]);
        carriers.extend(own_pin.map(|own| plant(&mut a, own)));

        match hub {
            Hub::Pinned => sync_through_doors(&b, &mut a),
            Hub::Behind => sync_through_doors(&a, &mut b),
        }
        assert!(
            window::history_free_window_required(&b.vault, &key).unwrap(),
            "{row}: the export door pinned B's window"
        );
        for node in [&a, &b] {
            for id in rows_of_a.iter().chain(&rows_of_b) {
                assert!(
                    node.vault.get_raw(id).unwrap().is_some(),
                    "{row}: {} lost or never received a row",
                    node.name
                );
            }
            for carrier in &carriers {
                assert!(
                    node.vault.get_raw(carrier).unwrap().is_none(),
                    "{row}: a scrubbed carrier became a row on {}",
                    node.name
                );
                assert!(
                    map_get_bytes(&node.doc(WINDOW).get_map("entities"), &carrier.to_hex())
                        .is_none(),
                    "{row}: a scrubbed carrier reached {}'s window",
                    node.name
                );
            }
        }
        for (from, to) in [(&a, &b), (&b, &a)] {
            let reply = window::export_window_updates_since(
                &from.vault,
                &key,
                from.doc(WINDOW),
                &to.doc(WINDOW).oplog_vv().encode(),
            )
            .unwrap();
            assert!(
                matches!(reply, WindowExport::Update(_)),
                "{row}: level peers keep trading replacements"
            );
        }
    }
}
