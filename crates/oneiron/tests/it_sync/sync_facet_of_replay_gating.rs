// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
//! ONE-1645 — the `FacetOf` type table on the FEDERATED REPLAY door.
//!
//! The write-time table (`CLAIM | TURN | EVENT -> FACET`) is enforced on the
//! local batch door, which aborts atomically. Replay cannot abort: a hard
//! failure on a replicated shape wedges sync permanently (H2), so
//! `BatchOp::EdgeWithCreatedAt` is deliberately ungated and forward
//! rematerialization runs the table at the write chokepoint, QUARANTINING an
//! off-table row and continuing the window.
//!
//! Why this is an authorization boundary and not schema hygiene: an off-table
//! stamp injected by a member/guest peer — say `PERSON -> FACET`, a shape no
//! local public writer can produce — would otherwise land in LMDB, the
//! retrieval truth every local disclosure surface reads. The grant-backed
//! federation selector mirrors this same table on its read side
//! (`sync::selector::facet_scope_by_source`) and so will not honor such a
//! source as a facet seed; keeping the unwritable shape out of storage in the
//! first place is THIS door's job.
//!
//! This suite drives the REAL member/guest entry point
//! (`admit_federated_window_update` → forward rematerialization) rather than
//! hand-built docs, so it fails if the admission door stops routing through
//! the chokepoint.

#![cfg(feature = "sync")]

use std::sync::Arc;

use loro::ExportMode;
use oneiron::edge::EdgeKind;
use oneiron::registry::{
    ENTITY_TYPE_EVENT, ENTITY_TYPE_FACET, ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN,
};
use oneiron::sync::bridge::{Materializer, encode_edge_value_for_crdt, format_edge_key};
use oneiron::sync::quarantine::{QuarantineContainer, quarantined_records};
use oneiron::sync::schema::create_window_doc;
use oneiron::sync::types::WindowKey;
use oneiron::sync::window::forward_rematerialize;
use oneiron::sync::{FederationAdmissionRole, admit_federated_window_update};
use oneiron::temporal::TimeRange;
use oneiron::{EntityId, Vault};

use crate::sync_harness::{
    T0, WINDOW, clear_policy_manifests, make_entity_blob, map_insert_bytes, test_config,
};

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
            b"replay fixture",
        )
        .unwrap();
}

/// A member/guest peer injecting an off-table `PERSON -> FACET` stamp is
/// quarantined at the replay chokepoint, while the on-table `EVENT -> FACET`
/// stamp and an unrelated ordinary edge in the SAME admitted window still
/// materialize.
///
/// Run once per role: the admission door is role-parameterized, and a table
/// enforced for members but not guests (or the reverse) would be worse than
/// no table at all.
#[test]
fn federated_replay_quarantines_off_table_facet_of_for_member_and_guest() {
    for role in [
        FederationAdmissionRole::Member,
        FederationAdmissionRole::Guest,
    ] {
        let (_dir, vault) = test_vault();
        let window_key = WindowKey::new(WINDOW);

        let person = EntityId::from_bytes([0xC1; 16]).unwrap();
        let event = EntityId::from_bytes([0xC2; 16]).unwrap();
        let facet = EntityId::from_bytes([0xC3; 16]).unwrap();
        let ordinary = EntityId::from_bytes([0xC4; 16]).unwrap();
        for (id, entity_type) in [
            (&person, ENTITY_TYPE_PERSON),
            (&event, ENTITY_TYPE_EVENT),
            (&facet, ENTITY_TYPE_FACET),
            (&ordinary, ENTITY_TYPE_TURN),
        ] {
            seed(&vault, id, entity_type);
        }

        // The hostile peer's window: an off-table facet stamp plus two rows
        // that must be unaffected by its rejection.
        let remote = create_window_doc("federation-peer", &window_key);
        let edges = remote.get_map("edges");
        let forged_key = format_edge_key(&person, EdgeKind::FacetOf, &facet);
        let forged_value =
            encode_edge_value_for_crdt(EdgeKind::FacetOf, 0.7, T0, None, None).unwrap();
        map_insert_bytes(&edges, &forged_key, &forged_value);
        map_insert_bytes(
            &edges,
            &format_edge_key(&event, EdgeKind::FacetOf, &facet),
            &encode_edge_value_for_crdt(EdgeKind::FacetOf, 0.7, T0 + 1, None, None).unwrap(),
        );
        map_insert_bytes(
            &edges,
            &format_edge_key(&ordinary, EdgeKind::Mentions, &facet),
            &encode_edge_value_for_crdt(EdgeKind::Mentions, 0.4, T0 + 2, None, None).unwrap(),
        );
        remote.commit();
        let update = remote.export(ExportMode::all_updates()).unwrap();

        // The real member/guest entry point, then the shared replay path.
        let admitted = admit_federated_window_update(&vault, &window_key, &update, role)
            .unwrap_or_else(|e| panic!("{role:?}: federated admission must not fail closed: {e}"));
        let local = create_window_doc("receiver", &window_key);
        local.import(&admitted).unwrap();
        forward_rematerialize(&vault, &local, &Materializer::new(), &window_key).unwrap();

        assert!(
            !vault
                .edge_exists(&person, EdgeKind::FacetOf, &facet)
                .unwrap(),
            "{role:?}: an off-table PERSON-sourced facet stamp must never land \
             through federated replay — the selector would read it as a facet seed"
        );
        assert!(
            vault
                .edge_exists(&event, EdgeKind::FacetOf, &facet)
                .unwrap(),
            "{role:?}: the on-table EVENT stamp must replicate normally"
        );
        assert!(
            vault
                .edge_exists(&ordinary, EdgeKind::Mentions, &facet)
                .unwrap(),
            "{role:?}: one forged row must not starve the other N-1 rows in the window"
        );

        let records = quarantined_records(&vault).unwrap();
        assert_eq!(
            records.len(),
            1,
            "{role:?}: exactly the forged row carries quarantine evidence"
        );
        let record = &records[0].1;
        assert_eq!(record.container, QuarantineContainer::Edges);
        assert_eq!(
            record.reason_code, "InvalidFacetOfEdge",
            "{role:?}: the peer's row must carry the typed table reason"
        );
    }
}

/// The chokepoint quarantines; it must never ABORT (H2). A window whose ONLY
/// edge row is off-table still returns Ok and leaves the rest of the window's
/// entity work committed — the failure mode the ungated batch arm exists to
/// prevent must not reappear one layer up.
#[test]
fn federated_replay_off_table_facet_of_never_aborts_the_window() {
    let (_dir, vault) = test_vault();
    let window_key = WindowKey::new(WINDOW);
    let person = EntityId::from_bytes([0xC5; 16]).unwrap();
    let facet = EntityId::from_bytes([0xC6; 16]).unwrap();
    seed(&vault, &person, ENTITY_TYPE_PERSON);
    seed(&vault, &facet, ENTITY_TYPE_FACET);

    // A fresh entity arrives in the same window as the forged edge.
    let bystander = EntityId::from_bytes([0xC7; 16]).unwrap();
    let remote = create_window_doc("federation-peer", &window_key);
    map_insert_bytes(
        &remote.get_map("entities"),
        &bystander.to_hex(),
        &make_entity_blob(ENTITY_TYPE_TURN, T0, b"bystander body"),
    );
    map_insert_bytes(
        &remote.get_map("edges"),
        &format_edge_key(&person, EdgeKind::FacetOf, &facet),
        &encode_edge_value_for_crdt(EdgeKind::FacetOf, 0.7, T0, None, None).unwrap(),
    );
    remote.commit();
    let update = remote.export(ExportMode::all_updates()).unwrap();

    let admitted = admit_federated_window_update(
        &vault,
        &window_key,
        &update,
        FederationAdmissionRole::Member,
    )
    .expect("an off-table edge must not fail the admission door");
    let local = create_window_doc("receiver", &window_key);
    local.import(&admitted).unwrap();

    let materialized = forward_rematerialize(&vault, &local, &Materializer::new(), &window_key)
        .expect("an off-table facet stamp must quarantine, never abort the window (H2)");

    assert_eq!(
        materialized, 1,
        "the bystander entity materializes; only the forged edge is dropped"
    );
    assert!(
        vault.get(&bystander).unwrap().is_some(),
        "an unrelated entity in the same window must survive the edge rejection"
    );
    assert!(
        !vault
            .edge_exists(&person, EdgeKind::FacetOf, &facet)
            .unwrap()
    );
}
