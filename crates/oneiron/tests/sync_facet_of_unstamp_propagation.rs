// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
//! ONE-1646 fix-13 — a CONSENTED `FacetOf` unstamp must PROPAGATE, and ONLY a
//! consented one may.
//!
//! Two rules, one seam. `disclosure::gate_facet_of_unstamp` refuses every
//! GENERIC removal of a `FacetOf` stamp, because removing one reclassifies a
//! SURVIVING record into the unfaceted class the P7 conjunct admits as
//! invariant. The only removal the local plane admits is
//! `Vault::unstamp_facet_of`, which consents and acts in ONE commit.
//!
//! 1. **The dedicated op emits the whole act** (fix-13 P1-2). It appends the
//!    consent event, tears the LMDB rows AND removes the CRDT `edges`-map key,
//!    all in one operation. Before this, the doc kept the stamp, so restart's
//!    forward rematerialization wrote it straight back into LMDB — a consented
//!    unstamp silently undid itself and re-published the survivor to every
//!    peer. `unstamp_survives_restart_on_both_nodes` drives the PRODUCTION op
//!    only: no test ever deletes an `edges` key by hand.
//!
//! 2. **The replicated door is PROVENANCE-BOUND** (fix-13 P1-1). Fix-12
//!    relaxed the gate for every Observer-B edge batch on a plane-topology
//!    argument. But Observer B fires for ANY doc mutation, and the lane offers
//!    raw local seams onto the same observed doc, so a bare edge deletion
//!    written through one of them tore the stamp consent-free. The relaxation
//!    now requires the internal device-import origin
//!    (`bridge::import_device_admitted_update`), which only the admitted
//!    device-plane entry points and replays of already-admitted bytes carry.
//!    A raw/queued removal is refused and quarantined instead.

#![cfg(feature = "sync")]

mod sync_harness;

use std::sync::Arc;

use loro::ExportMode;
use oneiron::edge::EdgeKind;
use oneiron::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_TURN};
use oneiron::sync::bridge::{Materializer, format_edge_key};
use oneiron::sync::client::{SyncClient, SyncClientConfig};
use oneiron::sync::manager::WindowManager;
use oneiron::sync::quarantine::{QuarantineContainer, quarantined_records};
use oneiron::sync::queue::SyncQueue;
use oneiron::sync::transport::{self, window_sub_tags};
use oneiron::sync::types::WindowKey;
use oneiron::temporal::TimeRange;
use oneiron::{EntityId, ErrorKind, Vault, VaultConfig};

use sync_harness::{T0, WINDOW, clear_policy_manifests, map_get_bytes, test_config};

fn id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).unwrap()
}

/// One production node: a vault behind a real [`WindowManager`] and a real
/// [`SyncClient`]. Deliberately NOT the `TestNode` harness — this suite's whole
/// subject is which SEAM the bytes arrive through, and the harness imports raw
/// into `LoadedWindow.doc` (correctly classified LOCAL by fix-13).
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
    node.manager.open_window(&WindowKey::new(WINDOW)).unwrap();
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
        open(name, dir)
    }

    fn doc_edges_contains(&self, edge_key: &str) -> bool {
        let window = self.manager.window(&WindowKey::new(WINDOW)).unwrap();
        map_get_bytes(&window.doc.get_map("edges"), edge_key).is_some()
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
    /// That is the entry point `import_device_admitted_update` tags, so this is
    /// the only path in this suite that can open the relaxed door.
    fn receive_device_update(&mut self, update: &[u8]) {
        let frame = transport::encode_window_sync(WINDOW, window_sub_tags::UPDATE, update)
            .into_result()
            .unwrap();
        self.client
            .handle_server_message(&frame)
            .unwrap_or_else(|e| panic!("{}: device update must be accepted: {e:?}", self.name));
    }
}

fn seed(vault: &Vault, id: &EntityId, entity_type: u8, body: &str) {
    vault
        .put_entity(
            id,
            entity_type,
            TimeRange { start: T0, end: T0 },
            T0,
            &rmp_serde::to_vec_named(&serde_json::json!({ "txt": body })).unwrap(),
        )
        .unwrap();
}

/// Seeds `record -FacetOf-> facet` in `node`'s LMDB and mirrors it into the
/// live doc through recovery, returning the CRDT edge key the stamp occupies.
/// A TURN source keeps this suite on the PROPAGATION question — the disclosure
/// semantics of a stamped CLAIM are pinned in `disclosure::tests`, and both
/// types sit on the same `FacetOf` table.
fn seed_stamped_record(node: &Node, record: &EntityId, facet: &EntityId) -> String {
    seed(&node.vault, facet, ENTITY_TYPE_FACET, "facet");
    seed(&node.vault, record, ENTITY_TYPE_TURN, "turn");
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

// ─── fix-13 P1-2: the production op emits the doc removal ───────────────────

/// THE P1-2 REGRESSION — PRODUCTION ONLY.
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

// ─── fix-13 P1-1: the relaxed door needs device-import provenance ───────────

/// THE P1-1 REGRESSION — a RAW local edge deletion must not tear the stamp.
///
/// The removal is authored directly on the observed live doc (the public
/// `LoadedWindow.doc` seam a host holds) with no `unstamp_facet_of` call
/// anywhere. Observer B classifies the commit as LOCAL provenance, so the
/// absolute gate refuses it: the LMDB stamp survives, the consent ledger stays
/// empty, a typed `FacetUnstampWithoutConsent` quarantine record is written,
/// and an unrelated sibling op in the SAME commit still applies (H2 — one
/// refused row must never wedge the batch).
///
/// MUTATION PROBE: drop the `!removal_provenance.replicated_door()` guard on
/// the removal arm (i.e. restore fix-12's unconditional relaxation) and the
/// LMDB assertion fails — the raw deletion tears the stamp consent-free.
#[test]
fn a_raw_local_edge_deletion_cannot_tear_the_stamp() {
    let a = node("node-a");
    let record = id(0xD1);
    let facet = id(0xD2);
    let sibling = id(0xD3);
    let edge_key = seed_stamped_record(&a, &record, &facet);
    seed(&a.vault, &sibling, ENTITY_TYPE_TURN, "sibling");
    let a = publish_seed(a);
    assert!(
        a.doc_edges_contains(&edge_key),
        "fixture: doc holds a stamp"
    );

    // ONE commit: the bare removal plus an unrelated edge upsert.
    let window = a.manager.window(&WindowKey::new(WINDOW)).unwrap();
    let edges = window.doc.get_map("edges");
    edges.delete(edge_key.as_str()).unwrap();
    let sibling_key = format_edge_key(&sibling, EdgeKind::Mentions, &record);
    edges
        .insert(
            sibling_key.as_str(),
            oneiron::sync::bridge::encode_edge_value_for_crdt(
                EdgeKind::Mentions,
                0.4,
                T0 + 2,
                None,
                None,
            )
            .unwrap()
            .as_slice(),
        )
        .unwrap();
    window.doc.commit();

    assert!(
        a.lmdb_stamp(&record, &facet),
        "a raw edges-map removal must NOT tear the LMDB stamp"
    );
    assert!(
        a.vault
            .facet_reclassification_ledger(&record, &facet)
            .unwrap()
            .is_empty(),
        "and must append no consent event"
    );
    assert!(
        a.vault
            .edge_exists(&sibling, EdgeKind::Mentions, &record)
            .unwrap(),
        "one refused row must not deny the rest of the commit (H2)"
    );

    let records = quarantined_records(&a.vault).unwrap();
    let refusals: Vec<_> = records
        .iter()
        .filter(|(_, r)| r.reason_code == format!("{:?}", ErrorKind::FacetUnstampWithoutConsent))
        .collect();
    assert_eq!(
        refusals.len(),
        1,
        "the refusal must leave typed durable evidence, got {records:?}"
    );
    assert_eq!(refusals[0].1.container, QuarantineContainer::Edges);
}

/// Same refusal through `SyncClient::import_queued_update` — a `pub` seam that
/// takes CALLER-SUPPLIED raw bytes and therefore proves nothing about their
/// origin. Replaying a queued frame must not be a way to launder a removal.
#[test]
fn a_queued_update_replay_cannot_tear_the_stamp() {
    let a = node("node-a");
    let record = id(0xD4);
    let facet = id(0xD5);
    let edge_key = seed_stamped_record(&a, &record, &facet);
    let mut a = publish_seed(a);

    // A hostile/queued frame authored elsewhere that removes the stamp.
    let forger = oneiron::sync::schema::create_window_doc("forger", &WindowKey::new(WINDOW));
    forger.import(&a.export()).unwrap();
    forger.get_map("edges").delete(edge_key.as_str()).unwrap();
    forger.commit();
    let removal = forger.export(ExportMode::all_updates()).unwrap();

    a.client.import_queued_update(WINDOW, &removal).unwrap();

    assert!(
        a.lmdb_stamp(&record, &facet),
        "a queued-replay removal must NOT tear the LMDB stamp"
    );
    assert!(
        a.vault
            .facet_reclassification_ledger(&record, &facet)
            .unwrap()
            .is_empty(),
        "and must append no consent event"
    );
    assert!(
        quarantined_records(&a.vault)
            .unwrap()
            .iter()
            .any(|(_, r)| r.reason_code == format!("{:?}", ErrorKind::FacetUnstampWithoutConsent)),
        "the refusal must leave typed durable evidence"
    );

    // And the dedicated door still works on the same pair — the refusal is
    // about PROVENANCE, not a wall in front of the operation.
    assert!(a.vault.unstamp_facet_of(&record, &facet, T0 + 9).unwrap());
    assert!(!a.lmdb_stamp(&record, &facet));
}

/// The LOCAL doors are untouched by the provenance work: all three generic
/// removals still refuse on a fully sync-attached node, and the dedicated op
/// still works. This is the pin that would fail if the fix had been
/// implemented as "relax the gate" rather than "bind the relaxation".
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
