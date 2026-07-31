// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
//! ONE-1645 — the `FacetOf` type table at the FEDERATION ADMISSION BOUNDARY.
//!
//! The replay chokepoint (`sync_facet_of_replay_gating`) stops an off-table
//! stamp from reaching LMDB. That is not the whole exposure, because the
//! federation SELECTOR does not read LMDB — `facet_scope_by_source` walks the
//! RAW Loro edges map. A forged `PERSON -> <selected FACET>` row that merely
//! SITS in the admitted / live document is therefore visible to the export
//! path, quarantined or not.
//!
//! So the table also runs at the trust boundary, with a deliberately
//! ASYMMETRIC invariant:
//!
//! * PROVABLY off-table — on ANY SUFFICIENT FACT, from the local vault or from
//!   the admitted update itself: a KNOWN off-table source alone, or a KNOWN
//!   non-FACET target alone — is DROPPED with a typed `InvalidFacetOfEdge`
//!   quarantine record. It never enters the doc. Waiting for BOTH endpoints
//!   would let a forger buy a pass by withholding the endpoint that is not the
//!   incriminating one.
//! * UNKNOWABLE deciding endpoint — it has not arrived yet — PASSES THROUGH to
//!   the remat gate's defer-then-validate. A hard verdict here would burn
//!   legitimate out-of-order delivery permanently (H2). That residue is inert
//!   on the export path regardless: the selector mirrors the same table on its
//!   read side, so an unadmitted source's stamps carry no facet scope even
//!   after the missing endpoint lands off-table.
//!
//! And it runs on the OBSERVER-B door, which a member/guest import into a
//! LOADED window takes synchronously through the ungated
//! `BatchOp::EdgeWithCreatedAt` arm — never crossing forward remat at all.
//!
//! The end-to-end residue pin — forge, admit, remat, then FILTER the same
//! document and prove the forged seed moved nothing across the disclosure
//! boundary — lives in `sync::selector::tests` beside the facet-scope pin it
//! guards (`selector_denies_event_scoped_to_unselected_facet`), where the
//! grant fixture needs no extra crate feature.

#![cfg(feature = "sync")]

mod sync_harness;

use std::sync::Arc;

use loro::ExportMode;
use oneiron::edge::EdgeKind;
use oneiron::registry::{
    ENTITY_TYPE_EVENT, ENTITY_TYPE_FACET, ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN,
};
use oneiron::sync::bridge::{Materializer, encode_edge_value_for_crdt, format_edge_key};
use oneiron::sync::client::{SyncClient, SyncClientConfig};
use oneiron::sync::manager::WindowManager;
use oneiron::sync::quarantine::{QuarantineContainer, quarantined_records};
use oneiron::sync::schema::create_window_doc;
use oneiron::sync::transport::{self, TAG_WINDOW_SYNC, window_sub_tags};
use oneiron::sync::types::WindowKey;
use oneiron::sync::window::forward_rematerialize;
use oneiron::sync::{FederationAdmissionRole, admit_federated_window_update};
use oneiron::temporal::TimeRange;
use oneiron::{EntityId, Vault};

use sync_harness::{T0, WINDOW, clear_policy_manifests, map_insert_bytes, test_config};

fn test_vault() -> (tempfile::TempDir, Arc<Vault>) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), test_config()).unwrap());
    clear_policy_manifests(&vault);
    (dir, vault)
}

fn seed(vault: &Vault, id: &EntityId, entity_type: u8) {
    vault
        .put_entity(
            id,
            entity_type,
            TimeRange { start: T0, end: T0 },
            T0,
            b"admission fixture",
        )
        .unwrap();
}

/// The pinned 25-byte entity envelope (contracts.ts `entityValueEnvelope`)
/// built from LITERAL parts, so a CRDT-side expectation never rides an engine
/// encode path.
fn entity_blob(entity_type: u8, body: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(25 + body.len());
    blob.push(entity_type);
    for _ in 0..3 {
        blob.extend_from_slice(&T0.to_be_bytes());
    }
    blob.extend_from_slice(body);
    blob
}

fn facet_of_value(created_at: u64) -> Vec<u8> {
    encode_edge_value_for_crdt(EdgeKind::FacetOf, 0.7, created_at, None, None).unwrap()
}

/// Imports `update` into the admitted doc and returns the edge keys the
/// admission door let through.
fn admitted_edge_keys(
    vault: &Vault,
    key: &WindowKey,
    update: &[u8],
    role: FederationAdmissionRole,
) -> Vec<String> {
    let admitted = admit_federated_window_update(vault, key, update, role)
        .unwrap_or_else(|e| panic!("{role:?}: admission must not fail closed: {e}"));
    let receiver = create_window_doc("receiver", key);
    receiver.import(&admitted).unwrap();
    let mut keys = Vec::new();
    receiver
        .get_map("edges")
        .for_each(|k, _| keys.push(k.to_string()));
    keys.sort();
    keys
}

/// P1/P2 ROOT FIX: a provably off-table `PERSON -> FACET` row never enters the
/// admitted document, so the selector — which reads the raw Loro map — cannot
/// read it as a facet seed. Both endpoint types are knowable from the local
/// vault here, the easiest case; the one-sided cases below are the load-bearing
/// ones.
///
/// Run once per role: a table enforced for members but not guests (or the
/// reverse) is worse than no table, because it reads as protection.
#[test]
fn admission_drops_provably_off_table_facet_of_for_member_and_guest() {
    for role in [
        FederationAdmissionRole::Member,
        FederationAdmissionRole::Guest,
    ] {
        let (_dir, vault) = test_vault();
        let window_key = WindowKey::new(WINDOW);
        let person = EntityId::from_bytes([0x71; 16]).unwrap();
        let event = EntityId::from_bytes([0x72; 16]).unwrap();
        let facet = EntityId::from_bytes([0x73; 16]).unwrap();
        let turn = EntityId::from_bytes([0x74; 16]).unwrap();
        for (id, entity_type) in [
            (&person, ENTITY_TYPE_PERSON),
            (&event, ENTITY_TYPE_EVENT),
            (&facet, ENTITY_TYPE_FACET),
            (&turn, ENTITY_TYPE_TURN),
        ] {
            seed(&vault, id, entity_type);
        }

        let remote = create_window_doc("federation-peer", &window_key);
        let edges = remote.get_map("edges");
        let forged_key = format_edge_key(&person, EdgeKind::FacetOf, &facet);
        let forged_value = facet_of_value(T0);
        map_insert_bytes(&edges, &forged_key, &forged_value);
        let control_key = format_edge_key(&event, EdgeKind::FacetOf, &facet);
        map_insert_bytes(&edges, &control_key, &facet_of_value(T0 + 1));
        let ordinary_key = format_edge_key(&turn, EdgeKind::Mentions, &facet);
        map_insert_bytes(
            &edges,
            &ordinary_key,
            &encode_edge_value_for_crdt(EdgeKind::Mentions, 0.4, T0 + 2, None, None).unwrap(),
        );
        remote.commit();
        let update = remote.export(ExportMode::all_updates()).unwrap();

        let keys = admitted_edge_keys(&vault, &window_key, &update, role);
        assert!(
            !keys.contains(&forged_key),
            "{role:?}: a provably off-table PERSON stamp must never enter the \
             admitted document — the selector reads the RAW map, so a merely \
             quarantined row still scopes exports"
        );
        assert!(
            keys.contains(&control_key),
            "{role:?}: the on-table EVENT stamp must admit normally"
        );
        assert!(
            keys.contains(&ordinary_key),
            "{role:?}: one forged row must not starve the other N-1 rows"
        );

        let records = quarantined_records(&vault).unwrap();
        assert_eq!(
            records.len(),
            1,
            "{role:?}: exactly the forged row carries durable evidence"
        );
        assert_eq!(records[0].1.container, QuarantineContainer::Edges);
        assert_eq!(
            records[0].1.reason_code, "InvalidFacetOfEdge",
            "{role:?}: the dropped row must carry the typed table reason"
        );
    }
}

/// The endpoint types may be knowable from the ADMITTED UPDATE ITSELF, not
/// only from the local vault — the endpoint arriving in the same frame as its
/// stamp is the common legitimate delivery. The boundary must read that map
/// too, or a hostile peer bundles the forged endpoint with the forged stamp
/// and walks straight through.
#[test]
fn admission_drops_off_table_row_whose_endpoints_arrive_in_the_same_frame() {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new(WINDOW);
    let person = EntityId::from_bytes([0xB1; 16]).unwrap();
    let facet = EntityId::from_bytes([0xB2; 16]).unwrap();

    // Nothing is seeded locally: BOTH endpoint types are knowable only from
    // this update's own entities map.
    let remote = create_window_doc("federation-peer", &window_key);
    let entities = remote.get_map("entities");
    map_insert_bytes(
        &entities,
        &person.to_hex(),
        &entity_blob(ENTITY_TYPE_PERSON, b"person"),
    );
    map_insert_bytes(
        &entities,
        &facet.to_hex(),
        &entity_blob(ENTITY_TYPE_FACET, b"facet"),
    );
    let forged_key = format_edge_key(&person, EdgeKind::FacetOf, &facet);
    map_insert_bytes(&remote.get_map("edges"), &forged_key, &facet_of_value(T0));
    remote.commit();
    let update = remote.export(ExportMode::all_updates()).unwrap();

    let keys = admitted_edge_keys(
        &vault,
        &window_key,
        &update,
        FederationAdmissionRole::Member,
    );
    assert!(
        !keys.contains(&forged_key),
        "an endpoint bundled with its own forged stamp is still PROVABLY \
         off-table — the admitted update's entities map is a type source"
    );
}

/// ONE-SIDED SOURCE. The table is a conjunction, so a KNOWN off-table source
/// falsifies it alone: `PERSON -> <target absent everywhere>` is proven bad
/// with the target's type still unknown, because NO target type could rescue a
/// PERSON stamp.
///
/// A "both endpoints known" reading would copy this row through, and the
/// bypass is trivial to drive: the forger simply withholds the endpoint that
/// is not the incriminating one, then delivers it in a later update.
///
/// Both roles: a table enforced for one and not the other reads as protection
/// while being none.
#[test]
fn admission_drops_one_sided_off_table_source_with_unknown_target() {
    for role in [
        FederationAdmissionRole::Member,
        FederationAdmissionRole::Guest,
    ] {
        let (_dir, vault) = test_vault();
        let window_key = WindowKey::new(WINDOW);
        let person = EntityId::from_bytes([0xE1; 16]).unwrap();
        // Target is seeded NOWHERE — not the vault, not the update.
        let unknown_target = EntityId::from_bytes([0xE2; 16]).unwrap();
        seed(&vault, &person, ENTITY_TYPE_PERSON);

        let remote = create_window_doc("federation-peer", &window_key);
        let forged_key = format_edge_key(&person, EdgeKind::FacetOf, &unknown_target);
        map_insert_bytes(&remote.get_map("edges"), &forged_key, &facet_of_value(T0));
        remote.commit();
        let update = remote.export(ExportMode::all_updates()).unwrap();

        let keys = admitted_edge_keys(&vault, &window_key, &update, role);
        assert!(
            !keys.contains(&forged_key),
            "{role:?}: a KNOWN off-table source proves the row bad on its own — \
             no target type could make PERSON -> anything a legal facet stamp, \
             so waiting for the target hands the forger a free pass"
        );

        let records = quarantined_records(&vault).unwrap();
        assert_eq!(records.len(), 1, "{role:?}: exactly the forged row");
        assert_eq!(
            records[0].1.reason_code, "InvalidFacetOfEdge",
            "{role:?}: the one-sided drop carries the typed table reason"
        );
    }
}

/// ONE-SIDED TARGET, the mirror image: a KNOWN non-FACET target falsifies the
/// table alone. `<source absent everywhere> -> PERSON` is proven bad with the
/// source's type still unknown, because NO source type may stamp a non-FACET.
#[test]
fn admission_drops_one_sided_non_facet_target_with_unknown_source() {
    for role in [
        FederationAdmissionRole::Member,
        FederationAdmissionRole::Guest,
    ] {
        let (_dir, vault) = test_vault();
        let window_key = WindowKey::new(WINDOW);
        // Source is seeded NOWHERE — not the vault, not the update.
        let unknown_source = EntityId::from_bytes([0xE3; 16]).unwrap();
        let person_target = EntityId::from_bytes([0xE4; 16]).unwrap();
        seed(&vault, &person_target, ENTITY_TYPE_PERSON);

        let remote = create_window_doc("federation-peer", &window_key);
        let forged_key = format_edge_key(&unknown_source, EdgeKind::FacetOf, &person_target);
        map_insert_bytes(&remote.get_map("edges"), &forged_key, &facet_of_value(T0));
        remote.commit();
        let update = remote.export(ExportMode::all_updates()).unwrap();

        let keys = admitted_edge_keys(&vault, &window_key, &update, role);
        assert!(
            !keys.contains(&forged_key),
            "{role:?}: a KNOWN non-FACET target proves the row bad on its own — \
             CLAIM, TURN and EVENT alike may only stamp a FACET"
        );

        let records = quarantined_records(&vault).unwrap();
        assert_eq!(records.len(), 1, "{role:?}: exactly the forged row");
        assert_eq!(
            records[0].1.reason_code, "InvalidFacetOfEdge",
            "{role:?}: the one-sided drop carries the typed table reason"
        );
    }
}

/// H2 line: a row whose endpoint types are UNKNOWABLE — absent from the vault
/// and from the update — passes THROUGH admission. The remat gate's
/// defer-then-validate owns it.
///
/// Rejecting here would make first-delivery-out-of-order a permanent drop with
/// no CRDT row left to retry from, which is exactly the wedge the ungated
/// batch arm exists to avoid, relocated to the boundary. The full lifecycle is
/// pinned: passes admission → defers at remat (no `x:` row, no edge) → heals
/// once the endpoints land.
#[test]
fn admission_passes_through_unknowable_endpoint_types_for_the_remat_gate() {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new(WINDOW);
    let turn = EntityId::from_bytes([0xC1; 16]).unwrap();
    let facet = EntityId::from_bytes([0xC2; 16]).unwrap();

    let remote = create_window_doc("federation-peer", &window_key);
    let stamp_key = format_edge_key(&turn, EdgeKind::FacetOf, &facet);
    map_insert_bytes(&remote.get_map("edges"), &stamp_key, &facet_of_value(T0));
    remote.commit();
    let update = remote.export(ExportMode::all_updates()).unwrap();

    let admitted = admit_federated_window_update(
        &vault,
        &window_key,
        &update,
        FederationAdmissionRole::Member,
    )
    .expect("an unknowable-type row must not fail the admission door");
    let local = create_window_doc("receiver", &window_key);
    local.import(&admitted).unwrap();
    let mut keys = Vec::new();
    local
        .get_map("edges")
        .for_each(|k, _| keys.push(k.to_string()));
    assert!(
        keys.contains(&stamp_key),
        "an unknowable endpoint type is not evidence of forgery — the row \
         passes through for the remat gate's defer-then-validate"
    );
    assert!(
        quarantined_records(&vault).unwrap().is_empty(),
        "a deferred legitimate row must leave no false evidence at admission"
    );

    forward_rematerialize(&vault, &local, &Materializer::new(), &window_key).unwrap();
    assert!(
        !vault.edge_exists(&turn, EdgeKind::FacetOf, &facet).unwrap(),
        "remat defers while the endpoints are absent"
    );
    assert!(
        quarantined_records(&vault).unwrap().is_empty(),
        "deferral is not rejection: still no x: row"
    );

    // The endpoints arrive later; the SAME retained CRDT row now materializes.
    seed(&vault, &turn, ENTITY_TYPE_TURN);
    seed(&vault, &facet, ENTITY_TYPE_FACET);
    forward_rematerialize(&vault, &local, &Materializer::new(), &window_key).unwrap();
    assert!(
        vault.edge_exists(&turn, EdgeKind::FacetOf, &facet).unwrap(),
        "the on-table stamp must heal once its endpoints exist — dropping it \
         at admission would have destroyed the only retry source"
    );
}

/// OBSERVER-B door (P2). A member/guest import into a LOADED window
/// materializes SYNCHRONOUSLY through Observer B and the ungated
/// `BatchOp::EdgeWithCreatedAt` arm — it never crosses forward remat, where
/// the replay gate lives. Driven through the PRODUCTION entry
/// `SyncClient::import_federated_window_update` on an already-open window, per
/// role, so the pin fails if that routing changes.
#[test]
fn observer_b_blocks_off_table_facet_of_on_a_loaded_window_for_both_roles() {
    for role in [
        FederationAdmissionRole::Member,
        FederationAdmissionRole::Guest,
    ] {
        let (_dir, vault) = test_vault();
        let manager = Arc::new(WindowManager::new(
            Arc::clone(&vault),
            Arc::new(Materializer::new()),
            "test-user",
        ));
        let (mut client, _rx) = SyncClient::new(manager, SyncClientConfig::default()).unwrap();

        let person = EntityId::from_bytes([0xD1; 16]).unwrap();
        let event = EntityId::from_bytes([0xD2; 16]).unwrap();
        let facet = EntityId::from_bytes([0xD3; 16]).unwrap();
        let turn = EntityId::from_bytes([0xD4; 16]).unwrap();
        for (id, entity_type) in [
            (&person, ENTITY_TYPE_PERSON),
            (&event, ENTITY_TYPE_EVENT),
            (&facet, ENTITY_TYPE_FACET),
            (&turn, ENTITY_TYPE_TURN),
        ] {
            seed(&vault, id, entity_type);
        }
        // LOADED, not cold: this is the arm that materializes synchronously.
        client.ensure_window(WINDOW).unwrap();

        let remote = create_window_doc("federation-peer", &WindowKey::new(WINDOW));
        let edges = remote.get_map("edges");
        map_insert_bytes(
            &edges,
            &format_edge_key(&person, EdgeKind::FacetOf, &facet),
            &facet_of_value(T0),
        );
        map_insert_bytes(
            &edges,
            &format_edge_key(&event, EdgeKind::FacetOf, &facet),
            &facet_of_value(T0 + 1),
        );
        map_insert_bytes(
            &edges,
            &format_edge_key(&turn, EdgeKind::Mentions, &facet),
            &encode_edge_value_for_crdt(EdgeKind::Mentions, 0.4, T0 + 2, None, None).unwrap(),
        );
        remote.commit();
        let update = remote.export(ExportMode::all_updates()).unwrap();

        client
            .import_federated_window_update(WINDOW, &update, role)
            .unwrap_or_else(|e| panic!("{role:?}: federated import must not fail closed: {e:?}"));

        assert!(
            !vault
                .edge_exists(&person, EdgeKind::FacetOf, &facet)
                .unwrap(),
            "{role:?}: the forged stamp must not land through the synchronous \
             Observer-B path — it never reaches the remat gate"
        );
        assert!(
            vault
                .edge_exists(&event, EdgeKind::FacetOf, &facet)
                .unwrap(),
            "{role:?}: the on-table EVENT control must materialize"
        );
        assert!(
            vault
                .edge_exists(&turn, EdgeKind::Mentions, &facet)
                .unwrap(),
            "{role:?}: unrelated rows in the same import must still commit"
        );

        let records = quarantined_records(&vault).unwrap();
        assert!(
            records
                .iter()
                .any(|(_, r)| r.container == QuarantineContainer::Edges
                    && r.reason_code == "InvalidFacetOfEdge"),
            "{role:?}: the rejection must carry the typed table reason, not a \
             generic one — got {:?}",
            records
                .iter()
                .map(|(_, r)| &r.reason_code)
                .collect::<Vec<_>>()
        );
    }
}

/// The Observer-B gate ISOLATED: the ordinary full-window `UPDATE` arm.
///
/// The test above drives the federated entry, which is the production shape
/// worth pinning — but admission now drops the forged row first, so that test
/// alone cannot prove the Observer-B gate exists. This one can: the plain
/// `WindowSync UPDATE` wire frame never touches `admit_federated_window_update`
/// at all. It imports straight into the LOADED doc, Observer B fires inline,
/// and the edge would land through the ungated `BatchOp::EdgeWithCreatedAt`
/// arm. Nothing else is between the peer's bytes and LMDB here, so removing
/// the Observer-B call makes exactly this assertion fail.
#[test]
fn observer_b_is_the_only_gate_on_the_plain_window_update_arm() {
    let (_dir, vault) = test_vault();
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&vault),
        Arc::new(Materializer::new()),
        "test-user",
    ));
    let (mut client, _rx) = SyncClient::new(manager, SyncClientConfig::default()).unwrap();

    let person = EntityId::from_bytes([0x75; 16]).unwrap();
    let event = EntityId::from_bytes([0x76; 16]).unwrap();
    let facet = EntityId::from_bytes([0x77; 16]).unwrap();
    for (id, entity_type) in [
        (&person, ENTITY_TYPE_PERSON),
        (&event, ENTITY_TYPE_EVENT),
        (&facet, ENTITY_TYPE_FACET),
    ] {
        seed(&vault, id, entity_type);
    }
    client.ensure_window(WINDOW).unwrap();

    let remote = create_window_doc("peer", &WindowKey::new(WINDOW));
    let edges = remote.get_map("edges");
    map_insert_bytes(
        &edges,
        &format_edge_key(&person, EdgeKind::FacetOf, &facet),
        &facet_of_value(T0),
    );
    map_insert_bytes(
        &edges,
        &format_edge_key(&event, EdgeKind::FacetOf, &facet),
        &facet_of_value(T0 + 1),
    );
    remote.commit();
    let update = remote.export(ExportMode::all_updates()).unwrap();

    let frame = transport::encode_window_sync(WINDOW, window_sub_tags::UPDATE, &update)
        .into_result()
        .unwrap();
    let mut message = vec![TAG_WINDOW_SYNC];
    message.extend_from_slice(&frame[1..]);
    client
        .handle_server_message(&message)
        .expect("a forged row must not fail the window-sync arm closed");

    assert!(
        !vault
            .edge_exists(&person, EdgeKind::FacetOf, &facet)
            .unwrap(),
        "on this arm Observer B is the ONLY door: without its table call the \
         forged PERSON stamp lands in LMDB"
    );
    assert!(
        vault
            .edge_exists(&event, EdgeKind::FacetOf, &facet)
            .unwrap(),
        "the on-table EVENT control must materialize"
    );
    assert!(
        quarantined_records(&vault)
            .unwrap()
            .iter()
            .any(|(_, r)| r.reason_code == "InvalidFacetOfEdge"),
        "the rejection must leave typed durable evidence"
    );
}
