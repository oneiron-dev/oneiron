// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
//! ONE-1646 fix-12 — a CONSENTED `FacetOf` unstamp must PROPAGATE.
//!
//! `disclosure::gate_facet_of_unstamp` refuses every GENERIC removal of a
//! `FacetOf` stamp, because removing one reclassifies a SURVIVING record into
//! the unfaceted class the P7 conjunct admits as invariant. That rule is
//! LOCAL: the only local removal is `Vault::unstamp_facet_of`, which consents
//! and acts in one commit.
//!
//! The REPLICATED door is a different question, and this suite is its
//! contract. When device A's owner unstamps, the removal replicates to B as a
//! bare `edges`-map removal — the only shape the CRDT has. Running the
//! absolute refusal there had two teeth:
//!
//! * the consented unstamp could not propagate. B kept the stamp, so the two
//!   devices disagreed FOREVER about which clamp class a surviving record was
//!   in — the exact divergence the gate exists to prevent, now permanent and
//!   owner-invisible;
//! * worse, LMDB and the doc DIVERGED on B, and reverse remat re-mirrors a
//!   surviving in-range LMDB edge back into the CRDT (LMDB wins for records
//!   absent from the doc). The refusal therefore RESURRECTED the stamp and
//!   pushed it back out to every peer, including A.
//!
//! Fix-12's ruling: the replicated door APPLIES the removal. Every plane that
//! can EXPRESS one is in-domain in v1's topology — the member/guest plane is
//! structurally removal-free (pinned by
//! `sync::selector::tests::federated_admission_cannot_express_a_removal`) and
//! the device plane is vault-credential-gated. Consent is enforced ONCE, at
//! the origin device's local gate, which stays exactly as it was.

#![cfg(feature = "sync")]

mod sync_harness;

use oneiron::edge::EdgeKind;
use oneiron::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_TURN};
use oneiron::sync::bridge::format_edge_key;
use oneiron::temporal::TimeRange;
use oneiron::{EntityId, ErrorKind, Vault};

use sync_harness::{T0, TestNode, WINDOW, assert_converged, exchange, map_get_bytes, vault_pair};

fn id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).unwrap()
}

fn window_range() -> TimeRange {
    TimeRange { start: T0, end: T0 }
}

fn seed(vault: &Vault, id: &EntityId, entity_type: u8, body: serde_json::Value) {
    vault
        .put_entity(
            id,
            entity_type,
            window_range(),
            T0,
            &rmp_serde::to_vec_named(&body).unwrap(),
        )
        .unwrap();
}

/// Seeds `record -FacetOf-> facet` on `node` and returns the CRDT edge key
/// the stamp occupies. A TURN source keeps this suite on the PROPAGATION
/// question — the disclosure semantics of a stamped CLAIM are pinned in
/// `disclosure::tests`, and both types sit on the same `FacetOf` table.
fn seed_stamped_record(node: &TestNode, record: &EntityId, facet: &EntityId) -> String {
    seed(
        &node.vault,
        facet,
        ENTITY_TYPE_FACET,
        serde_json::json!({ "name": "facet" }),
    );
    seed(
        &node.vault,
        record,
        ENTITY_TYPE_TURN,
        serde_json::json!({ "txt": "turn" }),
    );
    node.vault
        .batch()
        .edge(record, EdgeKind::FacetOf, facet, 1.0)
        .commit()
        .unwrap();
    format_edge_key(record, EdgeKind::FacetOf, facet)
}

fn stamp_in_doc(node: &TestNode, edge_key: &str) -> bool {
    map_get_bytes(&node.doc(WINDOW).get_map("edges"), edge_key).is_some()
}

fn stamp_in_lmdb(node: &TestNode, record: &EntityId, facet: &EntityId) -> bool {
    node.vault
        .edge_exists(record, EdgeKind::FacetOf, facet)
        .unwrap()
}

/// THE P1 REGRESSION — a consented unstamp on device A propagates to B, and
/// stays gone across a full re-sync and a restart replay.
///
/// The mutation probe for this test is the refusal itself: restore
/// `gate_facet_of_unstamp` on the replicated door (or reinstate a
/// classifier that defers/quarantines the removal) and the final
/// convergence assertion fails — B keeps the stamp while A does not.
#[test]
fn consented_unstamp_propagates_and_does_not_resurrect() {
    let (mut a, mut b) = vault_pair();
    let record = id(0xC1);
    let facet = id(0xC2);
    let edge_key = seed_stamped_record(&a, &record, &facet);

    // Mirror A's LMDB into its doc, then converge: B learns the stamp.
    a.recover(WINDOW);
    exchange(&a, &b, WINDOW);
    assert!(stamp_in_doc(&b, &edge_key), "B must learn the stamp first");
    assert!(
        stamp_in_lmdb(&b, &record, &facet),
        "and materialize it into LMDB"
    );

    // THE ACT: the owner unstamps on A through the DEDICATED door, which
    // consents and removes in one commit.
    assert!(a.vault.unstamp_facet_of(&record, &facet, T0 + 1).unwrap());
    assert_eq!(
        a.vault
            .facet_reclassification_ledger(&record, &facet)
            .unwrap()
            .len(),
        1,
        "the consent event is appended in the same commit"
    );

    // A's doc drops the stamp (the removal is authored locally), and the
    // delta carries a bare `edges`-map removal to B.
    a.doc(WINDOW)
        .get_map("edges")
        .delete(edge_key.as_str())
        .unwrap();
    a.doc(WINDOW).commit();
    assert!(!stamp_in_doc(&a, &edge_key));

    exchange(&a, &b, WINDOW);

    // B APPLIES it. Pre-fix this was refused forever: the stamp survived in
    // B's LMDB and the devices disagreed about the claim's clamp class.
    assert!(!stamp_in_doc(&b, &edge_key), "the removal reaches B's doc");
    assert!(
        !stamp_in_lmdb(&b, &record, &facet),
        "and B's LMDB — a consented unstamp must PROPAGATE"
    );

    // NO RESURRECTION. Reverse remat re-mirrors surviving in-range LMDB
    // edges back into the doc, so a stamp left alive in B's LMDB would be
    // pushed back out to A. Restart replay on BOTH nodes, then re-converge.
    a.recover(WINDOW);
    b.recover(WINDOW);
    exchange(&a, &b, WINDOW);

    for node in [&a, &b] {
        assert!(
            !stamp_in_doc(node, &edge_key),
            "{}: the stamp must not resurrect into the doc",
            node.name
        );
        assert!(
            !stamp_in_lmdb(node, &record, &facet),
            "{}: nor into LMDB",
            node.name
        );
    }
    assert_converged(&a, &b, WINDOW);
}

/// The LOCAL door is untouched by fix-12 — the replicated relaxation must not
/// leak onto the local plane.
///
/// Both generic local doors still refuse on a node that is fully sync-attached
/// (the same node whose replicated door just applied a removal), and the
/// dedicated op still works. This is the pin that would fail if the fix had
/// been implemented as "relax the gate" rather than "relax it for the
/// replicated door only".
#[test]
fn the_local_door_still_refuses_on_a_sync_attached_node() {
    let (a, _b) = vault_pair();
    let record = id(0xD1);
    let facet = id(0xD2);
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
        stamp_in_lmdb(&a, &record, &facet),
        "a refused local unstamp writes nothing"
    );
    assert!(
        a.vault
            .facet_reclassification_ledger(&record, &facet)
            .unwrap()
            .is_empty(),
        "and appends no ledger event"
    );

    // The dedicated door — the ONLY local removal — is unchanged.
    assert!(a.vault.unstamp_facet_of(&record, &facet, T0 + 1).unwrap());
    assert!(!stamp_in_lmdb(&a, &record, &facet));
    assert_eq!(
        a.vault
            .facet_reclassification_ledger(&record, &facet)
            .unwrap()
            .len(),
        1
    );
}
