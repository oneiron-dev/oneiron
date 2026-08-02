// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
//! ONE-1646 — a CONSENTED `FacetOf` unstamp must PROPAGATE, and it must not be
//! able to come back.
//!
//! `disclosure::gate_facet_of_unstamp` refuses every GENERIC removal of a
//! `FacetOf` stamp, because removing one reclassifies a SURVIVING record into
//! the unfaceted class the P7 conjunct admits as invariant. The only removal
//! the local plane admits is `Vault::unstamp_facet_of`, which consents and
//! acts in ONE commit; the replicated door then APPLIES the echo (the shipped
//! plane-trust posture — see the four-line note on that arm).
//!
//! What this suite pins, all through PRODUCTION seams (no test ever deletes an
//! `edges` key by hand):
//!
//! 1. **The dedicated op emits the whole act.** It appends the consent event,
//!    tears the LMDB rows AND removes the CRDT `edges`-map key. Before this,
//!    the doc kept the stamp, so restart's forward rematerialization wrote it
//!    straight back into LMDB — a consented unstamp silently undid itself and
//!    re-published the survivor to every peer.
//!
//! 2. **The carrier search reaches the SOURCE window** (fix-14 defect 2), even
//!    when it is cold, and even when it has pending `u:w:` rows but no `d:w:`
//!    snapshot. A duplicate key in some other open month is not a substitute
//!    for it.
//!
//! The crash-recovery leg (fix-14 defect 1 — the pair-bound
//! `facet.unstamp_pending.v1` marker that bridges the LMDB txn and the doc
//! removal) lives in `disclosure::tests`, where the crash-injection hook is
//! visible.

#![cfg(feature = "sync")]

mod sync_harness;

use std::sync::Arc;

use loro::ExportMode;
use oneiron::edge::EdgeKind;
use oneiron::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_TURN};
use oneiron::sync::bridge::{Materializer, format_edge_key};
use oneiron::sync::client::{SyncClient, SyncClientConfig};
use oneiron::sync::manager::WindowManager;
use oneiron::sync::queue::SyncQueue;
use oneiron::sync::transport::{self, window_sub_tags};
use oneiron::sync::types::WindowKey;
use oneiron::temporal::TimeRange;
use oneiron::{EntityId, ErrorKind, Vault, VaultConfig};

use sync_harness::{T0, WINDOW, clear_policy_manifests, map_get_bytes, test_config};

/// A month that is NOT [`WINDOW`], for the cold/duplicate-carrier cases.
const OTHER_WINDOW: &str = "2026-04";
/// 2026-04-15 00:00 UTC — squarely inside [`OTHER_WINDOW`].
const T_OTHER: u64 = T0 + 31 * 86_400;

fn id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).unwrap()
}

/// One production node: a vault behind a real [`WindowManager`] and a real
/// [`SyncClient`]. Deliberately NOT the `TestNode` harness — this suite's
/// subject is what the PRODUCTION op and PRODUCTION recovery do, and the
/// harness reaches into `LoadedWindow.doc` directly.
struct Node {
    name: &'static str,
    dir: tempfile::TempDir,
    vault: Arc<Vault>,
    manager: Arc<WindowManager>,
    client: SyncClient,
}

fn config() -> VaultConfig {
    test_config()
}

fn open(name: &'static str, dir: tempfile::TempDir) -> Node {
    open_windows(name, dir, &[WINDOW])
}

fn open_windows(name: &'static str, dir: tempfile::TempDir, windows: &[&str]) -> Node {
    let vault = Arc::new(Vault::open(dir.path(), config()).unwrap());
    clear_policy_manifests(&vault);
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&vault),
        Arc::new(Materializer::new()),
        name,
    ));
    let (client, _rx) = SyncClient::new(Arc::clone(&manager), SyncClientConfig::default()).unwrap();
    // Leak the event receiver: the client drops events into an unbounded
    // channel and nothing in this suite reads them.
    std::mem::forget(_rx);
    let node = Node {
        name,
        dir,
        vault,
        manager,
        client,
    };
    for window in windows {
        node.manager.open_window(&WindowKey::new(*window)).unwrap();
    }
    node
}

fn node(name: &'static str) -> Node {
    open(name, tempfile::tempdir().unwrap())
}

impl Node {
    /// Full restart: every window unloaded (persist-before-deregister), then a
    /// FRESH manager + client over the same on-disk vault, which re-runs the
    /// pinned ARCH-0023b recovery (pt → pm → reverse remat → forward remat).
    /// This is the pass that used to RESTORE an unstamped doc stamp into LMDB.
    fn restart(self) -> Self {
        self.restart_opening(&[WINDOW])
    }

    fn restart_opening(self, windows: &[&str]) -> Self {
        let Self {
            name,
            dir,
            vault,
            manager,
            client,
        } = self;
        for key in manager.loaded_keys() {
            manager.unload_window(&key).unwrap();
        }
        drop(client);
        drop(manager);
        drop(vault);
        open_windows(name, dir, windows)
    }

    /// Closes every live window WITHOUT reopening: the state the cold-source
    /// cases need (durable `d:w:`/`u:w:` rows, no registered doc).
    fn unload_all(&self) {
        for key in self.manager.loaded_keys() {
            self.manager.unload_window(&key).unwrap();
        }
    }

    fn doc_edges_contains(&self, edge_key: &str) -> bool {
        self.window_doc_edges_contains(WINDOW, edge_key)
    }

    fn window_doc_edges_contains(&self, window: &str, edge_key: &str) -> bool {
        let window = self.manager.window(&WindowKey::new(window)).unwrap();
        map_get_bytes(&window.doc.get_map("edges"), edge_key).is_some()
    }

    /// The stamp's presence in a window's DURABLE state, read the way
    /// production recovery reads it: the persisted snapshot with its pending
    /// `u:w:` rows replayed on top, or a pure rebuild from those rows when no
    /// snapshot exists.
    fn persisted_edges_contains(&self, window: &str, edge_key: &str) -> bool {
        let key = WindowKey::new(window);
        let doc = match oneiron::sync::window::load_window_from_state(&self.vault, "local", &key) {
            Ok(doc) => doc,
            Err(err) if err.kind() == ErrorKind::WindowNotFound => {
                oneiron::sync::window::rebuild_window_from_updates(&self.vault, "local", &key)
                    .unwrap()
            }
            Err(err) => panic!("{}: durable read failed: {err:?}", self.name),
        };
        map_get_bytes(&doc.get_map("edges"), edge_key).is_some()
    }

    fn lmdb_stamp(&self, record: &EntityId, facet: &EntityId) -> bool {
        self.vault
            .edge_exists(record, EdgeKind::FacetOf, facet)
            .unwrap()
    }

    /// This node's full window state as Loro update bytes.
    fn export(&self) -> Vec<u8> {
        let window = self.manager.window(&WindowKey::new(WINDOW)).unwrap();
        window.doc.export(ExportMode::all_updates()).unwrap()
    }

    /// Delivers `update` through the PRODUCTION device-plane seam: a
    /// `WindowSync UPDATE` frame handed to `SyncClient::handle_server_message`.
    fn receive_device_update(&mut self, update: &[u8]) {
        let frame = transport::encode_window_sync(WINDOW, window_sub_tags::UPDATE, update)
            .into_result()
            .unwrap();
        self.client
            .handle_server_message(&frame)
            .unwrap_or_else(|e| panic!("{}: device update must be accepted: {e:?}", self.name));
    }
}

fn seed_at(vault: &Vault, id: &EntityId, entity_type: u8, body: &str, learned_at: u64) {
    vault
        .put_entity(
            id,
            entity_type,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            &rmp_serde::to_vec_named(&serde_json::json!({ "txt": body })).unwrap(),
        )
        .unwrap();
}

/// Seeds `record -FacetOf-> facet` in `node`'s LMDB, returning the CRDT edge
/// key the stamp occupies. A TURN source keeps this suite on the PROPAGATION
/// question — the disclosure semantics of a stamped CLAIM are pinned in
/// `disclosure::tests`, and both types sit on the same `FacetOf` table.
fn seed_stamped_record(node: &Node, record: &EntityId, facet: &EntityId) -> String {
    seed_stamped_record_at(node, record, facet, T0)
}

fn seed_stamped_record_at(
    node: &Node,
    record: &EntityId,
    facet: &EntityId,
    learned_at: u64,
) -> String {
    seed_at(&node.vault, facet, ENTITY_TYPE_FACET, "facet", learned_at);
    seed_at(&node.vault, record, ENTITY_TYPE_TURN, "turn", learned_at);
    node.vault
        .batch()
        .edge(record, EdgeKind::FacetOf, facet, 1.0)
        .commit()
        .unwrap();
    format_edge_key(record, EdgeKind::FacetOf, facet)
}

/// Mirrors LMDB into the live doc (reverse remat) via a restart, so the seeded
/// stamp becomes a replicable CRDT row.
fn publish_seed(node: Node) -> Node {
    node.restart()
}

// ─── the production op emits the doc removal ────────────────────────────────

/// THE PROPAGATION REGRESSION — PRODUCTION ONLY.
///
/// `unstamp_facet_of` is called and NOTHING else touches the docs: no
/// `edges.delete`, no hand-built removal frame. The stamp must then be gone
/// from BOTH docs and BOTH LMDBs, and must STAY gone across a restart of both
/// nodes.
///
/// MUTATION PROBE: unwire the doc removal (drop the
/// `remove_facet_of_edge_from_docs` call in `Vault::unstamp_facet_of`) and this
/// fails twice over — A's post-unstamp doc still carries the stamp, so B never
/// learns of the removal, and A's own restart forward-remat writes the
/// surviving doc row back into LMDB.
#[test]
fn unstamp_survives_restart_on_both_nodes() {
    let mut a = node("node-a");
    let mut b = node("node-b");
    let record = id(0xC1);
    let facet = id(0xC2);
    let edge_key = seed_stamped_record(&a, &record, &facet);
    a = publish_seed(a);

    // B learns the stamp through the device-plane seam.
    b.receive_device_update(&a.export());
    assert!(b.doc_edges_contains(&edge_key), "B must learn the stamp");
    assert!(b.lmdb_stamp(&record, &facet), "and materialize it");

    // THE ACT — the dedicated door, and nothing else.
    assert!(a.vault.unstamp_facet_of(&record, &facet, T0 + 1).unwrap());
    assert_eq!(
        a.vault
            .facet_reclassification_ledger(&record, &facet)
            .unwrap()
            .len(),
        1,
        "the consent event is appended in the same act"
    );
    assert!(
        !a.doc_edges_contains(&edge_key),
        "the op must remove the CRDT carrier itself — nothing else will"
    );
    assert!(!a.lmdb_stamp(&record, &facet));

    // The ordinary echo carries it to B.
    b.receive_device_update(&a.export());
    assert!(
        !b.doc_edges_contains(&edge_key),
        "the removal reaches B's doc"
    );
    assert!(
        !b.lmdb_stamp(&record, &facet),
        "and B's LMDB — a consented unstamp must PROPAGATE"
    );

    // NO RESURRECTION. Forward remat writes every surviving doc edge into
    // LMDB; reverse remat re-mirrors every surviving in-range LMDB edge into
    // the doc. A stamp left in either place on either node comes back here.
    let a = a.restart();
    let b = b.restart();
    for node in [&a, &b] {
        assert!(
            !node.doc_edges_contains(&edge_key),
            "{}: the stamp must not resurrect into the doc",
            node.name
        );
        assert!(
            !node.lmdb_stamp(&record, &facet),
            "{}: nor into LMDB",
            node.name
        );
    }
}

/// The unstamp's doc removal is a REPLICABLE op, not a local edit: Observer A
/// persists it as a `u:w:` carrier row and routes it outbound. Without that,
/// the removal would be invisible to a peer that was offline at the time and
/// would be lost on restart.
#[test]
fn the_unstamp_removal_is_persisted_and_routed_outbound() {
    let a = node("node-a");
    let record = id(0xE1);
    let facet = id(0xE2);
    let edge_key = seed_stamped_record(&a, &record, &facet);
    let a = publish_seed(a);

    // A peer holding EXACTLY A's pre-unstamp ops — the removal is a CRDT
    // delete of a specific op, so the check has to run against a doc that has
    // that op, not a look-alike key inserted locally.
    let peer = oneiron::sync::schema::create_window_doc("peer", &WindowKey::new(WINDOW));
    peer.import(&a.export()).unwrap();
    assert!(
        map_get_bytes(&peer.get_map("edges"), &edge_key).is_some(),
        "fixture: the peer starts holding the stamp"
    );

    let queue = SyncQueue::new(Arc::clone(&a.vault)).unwrap();
    queue.clear_all().unwrap();
    let carriers_before = a
        .vault
        .sync_state_keys_with_prefix(&format!("u:w:{WINDOW}:"))
        .unwrap()
        .len();

    assert!(a.vault.unstamp_facet_of(&record, &facet, T0 + 1).unwrap());

    let carriers_after = a
        .vault
        .sync_state_keys_with_prefix(&format!("u:w:{WINDOW}:"))
        .unwrap()
        .len();
    assert!(
        carriers_after > carriers_before,
        "Observer A must persist the removal as a u:w: carrier row \
         ({carriers_before} -> {carriers_after})"
    );

    // Disconnected, so the outbound route falls back to the durable queue —
    // the removal is delivered when the device next connects.
    let updates = queue.drain_updates().unwrap();
    assert_eq!(updates.len(), 1, "exactly the removal is queued outbound");
    assert_eq!(updates[0].window_key, WINDOW);
    peer.import(&updates[0].encoded).unwrap();
    assert!(
        map_get_bytes(&peer.get_map("edges"), &edge_key).is_none(),
        "the queued bytes must carry the REMOVAL, not just the pre-unstamp state"
    );
}

/// The LOCAL doors still refuse on a fully sync-attached node, and the
/// dedicated op still works. The pin that fails if a fix is ever implemented as
/// "relax the local gate" rather than "route through the consenting op".
#[test]
fn the_local_doors_still_refuse_on_a_sync_attached_node() {
    let a = node("node-a");
    let record = id(0xF1);
    let facet = id(0xF2);
    seed_stamped_record(&a, &record, &facet);

    for refusal in [
        a.vault
            .delete_edge(&record, EdgeKind::FacetOf, &facet)
            .expect_err("delete_edge must still refuse"),
        a.vault
            .batch()
            .delete_edge(&record, EdgeKind::FacetOf, &facet)
            .commit()
            .expect_err("BatchOp::DeleteEdge must still refuse"),
        a.vault
            .batch()
            .delete(&facet)
            .commit()
            .expect_err("the FACET-delete cascade must still refuse"),
    ] {
        assert_eq!(refusal.kind(), ErrorKind::FacetUnstampWithoutConsent);
    }
    assert!(
        a.lmdb_stamp(&record, &facet),
        "a refused local unstamp writes nothing"
    );
    assert!(
        a.vault
            .facet_reclassification_ledger(&record, &facet)
            .unwrap()
            .is_empty(),
        "and appends no ledger event"
    );

    assert!(a.vault.unstamp_facet_of(&record, &facet, T0 + 1).unwrap());
    assert!(!a.lmdb_stamp(&record, &facet));
    assert_eq!(
        a.vault
            .facet_reclassification_ledger(&record, &facet)
            .unwrap()
            .len(),
        1
    );
}

// ─── fix-14 defect 2: the carrier search reaches the SOURCE window ──────────

/// THE COLD-SOURCE REGRESSION — a duplicate key in another LIVE month must not
/// stand in for the source window.
///
/// The CRDT stamp lives in the SOURCE entity's `learned_at` month. The earlier
/// search asked the live windows first and returned as soon as ANY of them held
/// a matching key — so with the source month CLOSED and a same-keyed carrier in
/// some other OPEN month, the live hit satisfied the check and the cold source
/// window kept its stamp. It then forward-remats back into LMDB on that
/// window's next open.
///
/// MUTATION PROBE: restore the `if covered_live { return Ok(()) }` early return
/// and this fails — the source window's durable state still carries the stamp,
/// and reopening it restores the LMDB row.
#[test]
fn a_live_duplicate_does_not_stand_in_for_a_cold_source_window() {
    let dir = tempfile::tempdir().unwrap();
    let a = open_windows("node-a", dir, &[WINDOW, OTHER_WINDOW]);
    let record = id(0xB1);
    let facet = id(0xB2);
    // SOURCE window is WINDOW (the record's learned_at month).
    let edge_key = seed_stamped_record(&a, &record, &facet);
    // A second record in OTHER_WINDOW, so that month is live and non-empty.
    let other_record = id(0xB3);
    let other_facet = id(0xB4);
    seed_stamped_record_at(&a, &other_record, &other_facet, T_OTHER);
    let a = a.restart_opening(&[WINDOW, OTHER_WINDOW]);
    assert!(
        a.doc_edges_contains(&edge_key),
        "fixture: the source window carries the stamp"
    );

    // Plant the SAME key in the OTHER month's doc (an echo of the stamp
    // arriving in a different window), so a first-match live search finds a
    // carrier there. Handles are dropped at once — an outstanding
    // `Arc<LoadedWindow>` refuses the unload below.
    let stamp_frame = oneiron::sync::schema::create_window_doc("peer", &WindowKey::new(WINDOW));
    stamp_frame.import(&a.export()).unwrap();
    {
        let other = a.manager.window(&WindowKey::new(OTHER_WINDOW)).unwrap();
        other
            .doc
            .import(&stamp_frame.export(ExportMode::all_updates()).unwrap())
            .unwrap();
    }
    assert!(
        a.window_doc_edges_contains(OTHER_WINDOW, &edge_key),
        "fixture: a duplicate carrier now sits in another live month"
    );

    // THE SHAPE THAT BREAKS A FIRST-MATCH SEARCH: the SOURCE month goes COLD
    // (durable rows only, no live doc) while the duplicate's month stays open.
    // A search that stops at the first live hit is satisfied by the duplicate
    // and never reaches the source's durable state.
    a.manager.unload_window(&WindowKey::new(WINDOW)).unwrap();
    assert!(
        a.persisted_edges_contains(WINDOW, &edge_key),
        "fixture: the cold source window still carries the stamp durably"
    );

    assert!(a.vault.unstamp_facet_of(&record, &facet, T0 + 1).unwrap());

    assert!(
        !a.persisted_edges_contains(WINDOW, &edge_key),
        "the COLD SOURCE window's carrier must go — a live duplicate elsewhere \
         is not a substitute for it"
    );
    assert!(
        !a.window_doc_edges_contains(OTHER_WINDOW, &edge_key),
        "and so must the duplicate — it resurrects the stamp just as well"
    );

    let a = a.restart_opening(&[WINDOW, OTHER_WINDOW]);
    assert!(
        !a.lmdb_stamp(&record, &facet),
        "no carrier anywhere may restore the stamp"
    );
    assert!(!a.doc_edges_contains(&edge_key));
    assert!(!a.window_doc_edges_contains(OTHER_WINDOW, &edge_key));
}

/// THE SNAPSHOTLESS-SOURCE REGRESSION — a source window whose stamp lives only
/// in pending `u:w:` rows.
///
/// `load_window_from_state` requires a `d:w:` snapshot and answers
/// `WindowNotFound` without one. Treating that as "no carrier" left the stamp
/// standing in exactly the state a crash-before-snapshot produces — and
/// production's own open path rebuilds from the pending rows for precisely this
/// case, so the window is anything but unreachable.
///
/// MUTATION PROBE: turn the `WindowNotFound` arm back into `return Ok(())` and
/// this fails — the durable window state still carries the stamp and reopening
/// restores the LMDB row.
#[test]
fn a_snapshotless_source_window_still_loses_its_carrier() {
    let a = node("node-a");
    let record = id(0xB5);
    let facet = id(0xB6);
    let edge_key = seed_stamped_record(&a, &record, &facet);
    let a = publish_seed(a);
    assert!(
        a.doc_edges_contains(&edge_key),
        "fixture: doc holds a stamp"
    );

    // THE CRASH-BEFORE-SNAPSHOT STATE, built from DURABLE ROWS only (the same
    // construction `any_window_scan_finds_a_tombstone_in_a_snapshotless_window`
    // uses): the window's ops live in a pending `u:w:` row and there is no
    // `d:w:` snapshot at all. Real whenever updates persist before a window is
    // ever unloaded or compacted — which is exactly why production's open path
    // and the `rm:` drain both rebuild from these rows.
    let ops = a.export();
    a.unload_all();
    for key in a
        .vault
        .sync_state_keys_with_prefix(&format!("u:w:{WINDOW}:"))
        .unwrap()
    {
        a.vault.sync_state_delete(&key).unwrap();
    }
    a.vault.sync_state_delete(&format!("d:w:{WINDOW}")).unwrap();
    a.vault
        .sync_state_put(&format!("u:w:{WINDOW}:00000001"), &ops)
        .unwrap();
    assert!(
        a.vault
            .sync_state_get(&format!("d:w:{WINDOW}"))
            .unwrap()
            .is_none(),
        "fixture must have NO snapshot row, or it proves nothing"
    );
    assert!(
        a.persisted_edges_contains(WINDOW, &edge_key),
        "fixture: the stamp lives in the pending rows"
    );

    assert!(a.vault.unstamp_facet_of(&record, &facet, T0 + 1).unwrap());
    assert!(
        !a.persisted_edges_contains(WINDOW, &edge_key),
        "the removal must reach a source window that has no snapshot"
    );

    let a = a.restart();
    assert!(
        !a.lmdb_stamp(&record, &facet),
        "so reopening cannot restore the stamp"
    );
    assert!(!a.doc_edges_contains(&edge_key));
}
