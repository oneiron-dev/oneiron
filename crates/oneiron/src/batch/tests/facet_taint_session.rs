//! Facet-of validation, taint guard, session apply and live-overlay exclusion.

use super::*;

/// The gate preflight runs the entity write door's verdict in its OWN
/// transaction, so a standalone claim preflight cannot leave a decision receipt
/// behind for a write `apply_put` is going to refuse.
#[test]
fn standalone_claim_write_does_not_record_gate_decision_before_taint_rejection() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let claim = EntityId::now();
    let (envelope, candidate) = claim_candidate_fixture(&vault, "overlay-member candidate")?;
    let session = vault
        .off_record_session_vault()
        .enter("sess-claim-preflight", OffRecordBackendClass::Local)?;
    stage_live_overlay_entity(&session, &claim)?;
    assert!(vault.gate_decisions(10)?.is_empty());

    let err = vault
        .batch()
        .claim_candidate(&claim, candidate, &envelope, test_time_range(10, 10), 11)
        .commit()
        .expect_err("a live overlay member must reject before the gate decision persists");
    assert_eq!(err.kind(), ErrorKind::OffRecordTaintedBaseWrite);
    assert!(vault.gate_decisions(10)?.is_empty());
    assert!(vault.get_claim(&claim)?.is_none());
    session.close()?;
    Ok(())
}

/// The materialization door is the WIDER one: replicated replay reaches
/// `apply_put` without passing the decode-point taint pass, so a remote payload
/// naming a live overlay member must be refused there, with the same typed
/// identity `sync/quarantine.rs` classifies on.
#[cfg(feature = "sync")]
#[test]
fn replicated_put_is_rejected_at_a_live_overlay_member_id() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let turn = EntityId::now();
    let session = vault
        .off_record_session_vault()
        .enter("sess-replicated-overlay", OffRecordBackendClass::Local)?;
    stage_live_overlay_entity(&session, &turn)?;

    let err = vault
        .batch()
        .put_replicated(
            &turn,
            crate::registry::ENTITY_TYPE_TURN,
            test_time_range(10, 10),
            10,
            b"stale remote off-record turn",
        )
        .commit()
        .expect_err("a remote payload must not materialize at a live overlay id");

    assert_eq!(err.kind(), ErrorKind::OffRecordTaintedBaseWrite);
    assert!(vault.get(&turn)?.is_none());

    // Once the room is gone the id is ordinary: the door is keyed to LIVE
    // membership, not to a durable marker that outlives the session.
    session.close()?;
    vault
        .batch()
        .put_replicated(
            &turn,
            crate::registry::ENTITY_TYPE_TURN,
            test_time_range(10, 10),
            10,
            b"post-close remote turn",
        )
        .commit()?;
    assert!(vault.get(&turn)?.is_some());
    Ok(())
}

fn child_of_edge(child: EntityId, parent: EntityId) -> BatchOp {
    BatchOp::Edge {
        src: child,
        kind: EdgeKind::ChildOf,
        tgt: parent,
        weight: 1.0,
        vad: Vad::NEUTRAL,
    }
}

#[test]
fn child_of_overlay_orders_entity_clear_against_same_pair_edge() {
    let child = entity(0x41);
    let parent = entity(0x62);

    let edge_after_clear = ChildOfBatchOverlay::from_ops(&[
        BatchOp::Delete { id: child },
        child_of_edge(child, parent),
    ]);
    assert_eq!(
        edge_after_clear.final_edge_override(&child, &parent),
        Some(true),
        "a ChildOf edge re-added after clearing the child must win"
    );

    let clear_after_edge = ChildOfBatchOverlay::from_ops(&[
        child_of_edge(child, parent),
        BatchOp::Delete { id: child },
    ]);
    assert_eq!(
        clear_after_edge.final_edge_override(&child, &parent),
        Some(false),
        "clearing the child after touching the ChildOf pair must win"
    );
}

/// Writes a minimal entity row of the given type. CLAIM rows carry a real
/// encoded claim body so they survive the write-door body validation; every
/// other type takes an opaque payload.
fn put_typed(vault: &Vault, id: &EntityId, entity_type: u8) -> Result<()> {
    let payload = if entity_type == ENTITY_TYPE_CLAIM {
        let body = ClaimBody::new(
            "facet.type_table_probe",
            ClaimSubject::Entity(*id),
            Value::from("v"),
            0.9,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        crate::claim::encode_claim_body(&body)?
    } else {
        b"payload".to_vec()
    };
    vault.put_entity(id, entity_type, test_time_range(1, 1), 1, &payload)
}

fn facet_of_edge_stored(vault: &Vault, src: &EntityId, tgt: &EntityId) -> Result<bool> {
    let rtxn = vault.store.env.read_txn()?;
    let key = Store::encode_edge_key(src, EdgeKind::FacetOf, tgt);
    Ok(vault.store.edges_out.get(&rtxn, &key)?.is_some())
}

fn assert_invalid_facet_of_edge(
    err: &Error,
    expected_src_type: Option<u8>,
    expected_tgt_type: Option<u8>,
    context: &str,
) {
    match err {
        Error::InvalidFacetOfEdge {
            src_type, tgt_type, ..
        } => {
            assert_eq!(*src_type, expected_src_type, "{context}: src type");
            assert_eq!(*tgt_type, expected_tgt_type, "{context}: tgt type");
        }
        other => panic!("{context}: expected InvalidFacetOfEdge, got {other:?}"),
    }
}

/// The admitted table: CLAIM → FACET, TURN → FACET, EVENT → FACET.
///
/// Two semantics ride one edge kind. CLAIM|TURN-sourced stamps are
/// DISCLOSURE-SCOPING — CLAIM adjacency is what `claim_facet_scope`
/// prefix-scans and what strict-mode filtering acts on; TURN is admitted
/// alongside CLAIM because per-turn facet stamps are what transcript filtering
/// rides. EVENT-sourced stamps are WORLD-MODEL: they exist for ARCH-0039 PPR
/// traversal (`facet_of` λ 0.05), and rejecting EVENT would make a ratified
/// traversal contract unwritable.
///
/// "World-model" is scoped to the LOCAL QUERY door, not to disclosure at
/// large. `apply_facet_filter` keeps every non-CLAIM entity unconditionally,
/// so an EVENT-sourced stamp is inert THERE — but the federation selector
/// scopes by every source type THIS table admits, EVENT included, so the same
/// stamp is disclosure-EFFECTIVE on that door (pinned by
/// `sync::selector::tests::selector_denies_event_scoped_to_unselected_facet`).
#[test]
fn facet_of_edge_valid_source_types_accepted() -> Result<()> {
    for (label, src_type) in [
        ("claim source", ENTITY_TYPE_CLAIM),
        ("turn source", ENTITY_TYPE_TURN),
        (
            "event source (world-model; federation-door effective)",
            ENTITY_TYPE_EVENT,
        ),
    ] {
        let (_dir, vault) = open_test_vault();
        let src = EntityId::now();
        let facet = EntityId::now();
        put_typed(&vault, &src, src_type)?;
        put_typed(&vault, &facet, ENTITY_TYPE_FACET)?;

        vault
            .batch()
            .edge(&src, EdgeKind::FacetOf, &facet, 0.7)
            .commit()?;
        assert!(
            facet_of_edge_stored(&vault, &src, &facet)?,
            "{label} must be admitted"
        );
    }
    Ok(())
}

/// The rejected table. Every row aborts the batch atomically and reports the
/// types actually found — including `None` for an endpoint with no entity
/// row, whose type is unknowable rather than merely wrong.
///
/// Admitting EVENT widened the source set to {CLAIM, TURN, EVENT}; it did not
/// soften the teeth. Sources OUTSIDE that set are still rejected (the SESSION
/// and PERSON rows pin this), the target must still be a FACET, and a missing
/// endpoint row still fails closed.
#[test]
fn facet_of_edge_type_table_rejects_off_table_endpoints() -> Result<()> {
    // (label, src type, tgt type) — `None` means "write no entity row".
    let table: [(&str, Option<u8>, Option<u8>); 5] = [
        (
            "wrong target type",
            Some(ENTITY_TYPE_CLAIM),
            Some(ENTITY_TYPE_PERSON),
        ),
        (
            "wrong source type",
            Some(ENTITY_TYPE_PERSON),
            Some(ENTITY_TYPE_FACET),
        ),
        (
            "off-table source stays rejected after the EVENT widening",
            Some(crate::registry::ENTITY_TYPE_SESSION),
            Some(ENTITY_TYPE_FACET),
        ),
        ("missing source row", None, Some(ENTITY_TYPE_FACET)),
        ("missing target row", Some(ENTITY_TYPE_CLAIM), None),
    ];
    for (label, src_type, tgt_type) in table {
        let (_dir, vault) = open_test_vault();
        let src = EntityId::now();
        let tgt = EntityId::now();
        if let Some(t) = src_type {
            put_typed(&vault, &src, t)?;
        }
        if let Some(t) = tgt_type {
            put_typed(&vault, &tgt, t)?;
        }

        let err = vault
            .batch()
            .edge(&src, EdgeKind::FacetOf, &tgt, 0.7)
            .commit()
            .expect_err(label);
        assert_invalid_facet_of_edge(&err, src_type, tgt_type, label);
        assert_eq!(err.kind(), ErrorKind::InvalidFacetOfEdge, "{label}");
        assert!(
            !facet_of_edge_stored(&vault, &src, &tgt)?,
            "{label}: the rejected edge must not be stored"
        );
    }
    Ok(())
}

/// Ops apply in order inside one write txn, so an entity put and the edge
/// that stamps it commit together in a single batch.
#[test]
fn facet_of_edge_same_batch_entity_then_edge_accepted() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();
    let facet = EntityId::now();
    let claim_body = crate::claim::encode_claim_body(&ClaimBody::new(
        "facet.type_table_probe",
        ClaimSubject::Entity(claim),
        Value::from("v"),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    ))?;

    vault
        .batch()
        .put(
            &claim,
            ENTITY_TYPE_CLAIM,
            test_time_range(1, 1),
            1,
            &claim_body,
        )
        .put(&facet, ENTITY_TYPE_FACET, test_time_range(1, 1), 1, b"f")
        .edge(&claim, EdgeKind::FacetOf, &facet, 0.7)
        .commit()?;

    assert!(facet_of_edge_stored(&vault, &claim, &facet)?);
    Ok(())
}

/// The gate covers the public timestamped builder arm too, with the same
/// table — the public write door is one boundary, not two.
#[test]
fn facet_of_edge_via_public_created_at_builder_rejected_same_table() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();
    let person = EntityId::now();
    put_typed(&vault, &claim, ENTITY_TYPE_CLAIM)?;
    put_typed(&vault, &person, ENTITY_TYPE_PERSON)?;

    let err = vault
        .batch()
        .edge_with_created_at(&claim, EdgeKind::FacetOf, &person, 0.7, 5)
        .commit()
        .expect_err("public timestamped arm must run the same type table");
    assert_invalid_facet_of_edge(
        &err,
        Some(ENTITY_TYPE_CLAIM),
        Some(ENTITY_TYPE_PERSON),
        "public created_at arm",
    );
    assert!(!facet_of_edge_stored(&vault, &claim, &person)?);

    // Control: the same builder admits a well-typed stamp.
    let facet = EntityId::now();
    put_typed(&vault, &facet, ENTITY_TYPE_FACET)?;
    vault
        .batch()
        .edge_with_created_at(&claim, EdgeKind::FacetOf, &facet, 0.7, 5)
        .commit()?;
    assert!(facet_of_edge_stored(&vault, &claim, &facet)?);
    Ok(())
}

/// Collateral check: the gate keys on `FacetOf` alone. Any other edge kind
/// between arbitrary typed entities commits exactly as it did before.
#[test]
fn non_facet_of_edges_unaffected() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let person_a = EntityId::now();
    let person_b = EntityId::now();
    put_typed(&vault, &person_a, ENTITY_TYPE_PERSON)?;
    put_typed(&vault, &person_b, ENTITY_TYPE_PERSON)?;

    vault
        .batch()
        .edge(&person_a, EdgeKind::Mentions, &person_b, 0.7)
        .commit()?;
    assert!(vault.edge_exists(&person_a, EdgeKind::Mentions, &person_b)?);

    // Even an edge whose endpoints do not exist at all stays ungated when the
    // kind is not FacetOf.
    let ghost_a = EntityId::now();
    let ghost_b = EntityId::now();
    vault
        .batch()
        .edge(&ghost_a, EdgeKind::Mentions, &ghost_b, 0.7)
        .commit()?;
    assert!(vault.edge_exists(&ghost_a, EdgeKind::Mentions, &ghost_b)?);
    Ok(())
}

/// The sync-replay arm stays UNGATED by design (H2). A replicated LWW winner
/// must never wedge local sync into a permanent abort, so the type table is
/// enforced one layer up, at the REPLAY chokepoint, where an off-table row
/// can be quarantined instead of aborting the window: see
/// `sync::window::tests::forward_remat_quarantines_off_table_facet_of_and_admits_the_on_table_row`.
/// Pinned deliberately: an ill-typed FacetOf edge still applies at THIS arm,
/// and the internal builder is `pub(crate)` — no local actor reaches it
/// without sync replay, and no replay reaches it without passing the
/// chokepoint's table.
#[test]
fn facet_of_edge_sync_replay_arm_ungated() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = EntityId::now();
    let person = EntityId::now();
    put_typed(&vault, &claim, ENTITY_TYPE_CLAIM)?;
    put_typed(&vault, &person, ENTITY_TYPE_PERSON)?;

    vault
        .batch()
        .edge_with_value_fields(
            &claim,
            EdgeKind::FacetOf,
            &person,
            EdgeValueFields {
                weight: 0.7,
                created_at: 1,
                vad: Vad::NEUTRAL,
                provenance: None,
            },
        )
        .commit()?;

    assert!(
        facet_of_edge_stored(&vault, &claim, &person)?,
        "the replay arm must apply a wrong-typed FacetOf edge unchanged"
    );
    Ok(())
}

/// Stages one live overlay entity for `id` on `session`, so the K4 guard sees
/// a genuine live-overlay member — the same shape `off_record/tests.rs` uses.
fn stage_live_overlay_entity(
    session: &crate::off_record::OffRecordSession<'_>,
    id: &EntityId,
) -> Result<()> {
    let overlay = session.overlay();
    let segment = overlay.install_txn_segment()?;
    overlay.put(
        crate::session_overlay::OverlayKeyspace::Entities,
        id.as_bytes(),
        b"live session overlay entity",
    )?;
    segment.commit()
}

/// An `Ordinary` base write naming a live-overlay id in an op ref OTHER than
/// the written entity itself — here an edge TARGET — is rejected. This is the
/// case the entity-materialization door cannot catch: it only sees ids that
/// materialize, and an edge target materializes nothing.
#[test]
fn taint_guard_rejects_edge_targeting_a_live_overlay_id() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let source = EntityId::now();
    let overlay_id = EntityId::now();
    put_typed(&vault, &source, ENTITY_TYPE_PERSON)?;
    let session = vault
        .off_record_session_vault()
        .enter("sess-taint-edge", OffRecordBackendClass::Local)?;
    stage_live_overlay_entity(&session, &overlay_id)?;

    let err = vault
        .batch()
        .edge(&source, EdgeKind::Mentions, &overlay_id, 1.0)
        .commit()
        .expect_err("an edge into a live overlay id must be refused");
    assert_eq!(err.kind(), ErrorKind::OffRecordTaintedBaseWrite);
    assert_matches!(
        err,
        Error::OffRecordTaintedBaseWrite { entity_ref } if entity_ref == overlay_id.to_hex()
    );
    assert!(!vault.edge_exists(&source, EdgeKind::Mentions, &overlay_id)?);
    session.close()?;
    Ok(())
}

/// A raw base CLAIM put whose BODY names a live-overlay id as its subject is
/// rejected: the guard decodes the opaque body through the same decoder the
/// apply path uses, so the subject ref joins the referenced-id set even though
/// the claim's own id is untainted.
#[test]
fn taint_guard_decodes_raw_claim_body_subject_refs() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let claim = EntityId::now();
    let overlay_id = EntityId::now();
    let session = vault
        .off_record_session_vault()
        .enter("sess-taint-claim", OffRecordBackendClass::Local)?;
    stage_live_overlay_entity(&session, &overlay_id)?;

    let body = ClaimBody::new(
        "profile.name",
        ClaimSubject::Entity(overlay_id),
        Value::from("subject rides in the opaque body"),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    let err = vault
        .put_entity(
            &claim,
            ENTITY_TYPE_CLAIM,
            test_time_range(1, 1),
            1,
            &crate::claim::encode_claim_body(&body)?,
        )
        .expect_err("a claim body naming a live overlay subject must be refused");
    assert_eq!(err.kind(), ErrorKind::OffRecordTaintedBaseWrite);
    assert!(vault.get_raw(&claim)?.is_none());
    session.close()?;
    Ok(())
}

/// Commits one raw CLAIM-prefixed put through the reserved-claim door, which
/// (unlike the public `put`) carries the body to the op loop unvalidated — the
/// only way an undecodable body can reach the decode point at all.
fn commit_raw_claim_put(vault: &Vault, claim: &EntityId, data: &[u8]) -> Result<()> {
    vault.with_write_txn(|wtxn| {
        vault
            .batch_in()
            .put_reserved_claim(claim, test_time_range(1, 1), 1, data)
            .apply(wtxn)
    })
}

/// An UNDECODABLE CLAIM-prefixed body fails closed with the taint error while a
/// live overlay holds entities: its refs cannot be enumerated, so membership
/// cannot be disproved, and deciding it untainted is exactly the open-by-default
/// shape the guard forbids.
#[test]
fn taint_guard_fails_closed_on_undecodable_claim_body() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let claim = EntityId::now();
    let overlay_id = EntityId::now();
    let session = vault
        .off_record_session_vault()
        .enter("sess-taint-undecodable", OffRecordBackendClass::Local)?;
    stage_live_overlay_entity(&session, &overlay_id)?;

    let err = commit_raw_claim_put(&vault, &claim, b"not a decodable claim body")
        .expect_err("an undecodable claim body must fail closed");
    assert_eq!(err.kind(), ErrorKind::OffRecordTaintedBaseWrite);
    assert!(vault.get_raw(&claim)?.is_none());
    session.close()?;
    Ok(())
}

/// With no live overlay entity the guard is inert: the same undecodable body
/// reaches its precise `InvalidClaimBody` verdict. The taint error names a real
/// membership fact, never a decode failure on its own.
#[test]
fn taint_guard_is_inert_without_live_overlay_entities() {
    let (_dir, vault) = open_raw_test_vault();
    let claim = EntityId::now();
    let err = commit_raw_claim_put(&vault, &claim, b"not a decodable claim body")
        .expect_err("an undecodable claim body is still rejected");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
}

/// The guard runs INSIDE the applying transaction, so a batch it refuses is
/// atomic: the earlier ops of the same batch leave no base row behind. There is
/// no preflight pass whose verdict could be published before the transaction.
#[test]
fn taint_guard_rejection_rolls_back_the_whole_batch() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let clean = EntityId::now();
    let source = EntityId::now();
    let overlay_id = EntityId::now();
    put_typed(&vault, &source, ENTITY_TYPE_PERSON)?;
    let session = vault
        .off_record_session_vault()
        .enter("sess-taint-atomic", OffRecordBackendClass::Local)?;
    stage_live_overlay_entity(&session, &overlay_id)?;

    let err = vault
        .batch()
        .put(
            &clean,
            ENTITY_TYPE_PERSON,
            test_time_range(1, 1),
            1,
            b"untainted op ordered before the tainted one",
        )
        .edge(&source, EdgeKind::Mentions, &overlay_id, 1.0)
        .commit()
        .expect_err("the tainted op must refuse the batch");
    assert_eq!(err.kind(), ErrorKind::OffRecordTaintedBaseWrite);
    assert!(
        vault.get_raw(&clean)?.is_none(),
        "the untainted op that preceded the refusal must roll back with it"
    );
    session.close()?;
    Ok(())
}

/// Closing the session drops the membership, and the identical write then
/// succeeds — the refusal tracks LIVE overlay state read inside the applying
/// transaction, not a durable mark on the id.
#[test]
fn taint_guard_releases_after_session_close() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let source = EntityId::now();
    let overlay_id = EntityId::now();
    put_typed(&vault, &source, ENTITY_TYPE_PERSON)?;
    let session = vault
        .off_record_session_vault()
        .enter("sess-taint-release", OffRecordBackendClass::Local)?;
    stage_live_overlay_entity(&session, &overlay_id)?;
    let refused = vault
        .batch()
        .edge(&source, EdgeKind::Mentions, &overlay_id, 1.0)
        .commit()
        .expect_err("a live overlay member must refuse an ordinary base edge write");
    assert_matches!(refused.kind(), ErrorKind::OffRecordTaintedBaseWrite);
    session.close()?;

    vault
        .batch()
        .edge(&source, EdgeKind::Mentions, &overlay_id, 1.0)
        .commit()?;
    assert!(vault.edge_exists(&source, EdgeKind::Mentions, &overlay_id)?);
    Ok(())
}

/// The session apply entry refuses a STALE route before staging anything.
///
/// `SessionWriteRoute::revalidate` being correct in isolation is not enough:
/// what matters is that `apply_ops_session` actually CALLS it. A mode flip
/// landing between mint and apply must abort the write whole — half a turn
/// staged into a room the caller no longer believes it is in would be worse
/// than either outcome.
#[test]
fn session_apply_refuses_a_route_minted_before_a_mode_flip() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let session = vault
        .off_record_session_vault()
        .enter("sess-apply-stale-route", OffRecordBackendClass::Local)?;
    let route = session.write_route()?;
    // The flip republishes the mode generation, stranding the route above.
    session.flip_on_record()?;
    session.flip_off_record()?;

    let turn = EntityId::now();
    let entry = crate::session_overlay::JournalEntry {
        scope: crate::session_overlay::JournalScope::new(EntityId::now(), turn),
        role: crate::session_overlay::JournalRole::TurnPut,
        learned_at: 10,
        occurred: TimeRange { start: 10, end: 10 },
        op: BatchOp::Put {
            id: turn,
            entity_type: crate::registry::ENTITY_TYPE_TURN,
            occurred: TimeRange { start: 10, end: 10 },
            learned_at: 10,
            data: b"stale-route turn".to_vec(),
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        },
    };

    let overlay = session.overlay();
    let mut wtxn = vault.store.env.write_txn()?;
    let segment = overlay.install_txn_segment()?;
    let view = session.read_view()?;
    let refused = crate::batch::apply_ops_session(
        &view,
        &route,
        &vault.config,
        &vault.analyzer,
        &mut wtxn,
        vec![entry],
    )
    .expect_err("a route minted before the flip must be refused");
    assert_eq!(
        refused.kind(),
        crate::error::ErrorKind::OffRecordOverlayLeaseClosed
    );
    drop(view);
    drop(segment);
    drop(wtxn);

    // Nothing staged: the refusal happens before the first row. The snapshot
    // holds a read lease and close DRAINS leases, so it is scoped tightly —
    // holding one across close deadlocks the closing thread.
    {
        let snapshot = overlay.snapshot()?;
        assert_eq!(
            snapshot.row_count(crate::session_overlay::OverlayKeyspace::Entities),
            0,
            "a refused session apply stages no rows"
        );
        assert_eq!(
            snapshot.journal_entries().len(),
            0,
            "a refused session apply journals nothing"
        );
    }
    session.close()?;
    Ok(())
}

/// The session apply door validates CLAIM BODIES, not just the type byte.
///
/// `apply_ops_session` ran `validate_public_entity_type` and went straight to
/// staging, so a malformed CLAIM body landed in the overlay, was journaled,
/// and read back through the room's composed view. Promote replays that very
/// op through `apply_put`, whose D18 arm rejects it — so the room showed its
/// caller a claim that could never land, and the refusal arrived a whole
/// session later attached to promote rather than to the write that was wrong.
/// Fail-closed at promote is not enough: the wrongness has to be
/// unrepresentable IN the room, not merely unpromotable out of it.
///
/// Both halves of the validator chain are covered, because either alone leaves
/// a door open: a body the DECODER rejects, and well-formed bodies a family's
/// STRUCTURAL arm rejects (wrong subject kind, wrong value shape).
#[test]
fn session_apply_validates_claim_bodies_before_staging() -> Result<()> {
    let (_dir, vault) = open_raw_test_vault();
    let session = vault
        .off_record_session_vault()
        .enter("sess-claim-body-door", OffRecordBackendClass::Local)?;

    let encode = |predicate: &str, subject: ClaimSubject, value: Value| -> Result<Vec<u8>> {
        crate::claim::encode_claim_body(&ClaimBody::new(
            predicate,
            subject,
            value,
            0.9,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        ))
    };

    let mut undecodable = encode(
        "dream.symbol",
        ClaimSubject::Entity(EntityId::now()),
        Value::from("a blue door"),
    )?;
    undecodable.push(0x00);

    let cases: [(&str, Vec<u8>); 3] = [
        ("trailing bytes after the body map", undecodable),
        (
            "a calendar claim whose subject is an EDGE, not an entity",
            encode(
                crate::calendar::claims::PREDICATE_CALENDAR_TZ,
                ClaimSubject::Edge {
                    source: EntityId::now(),
                    kind: EdgeKind::Mentions,
                    target: EntityId::now(),
                },
                Value::from("Europe/Berlin"),
            )?,
        ),
        (
            "a calendar claim whose tz value is an integer, not a string",
            encode(
                crate::calendar::claims::PREDICATE_CALENDAR_TZ,
                ClaimSubject::Entity(EntityId::now()),
                Value::from(7),
            )?,
        ),
    ];

    for (case, data) in cases {
        let claim_id = EntityId::now();
        let occurred = TimeRange { start: 5, end: 5 };
        let entry = crate::session_overlay::JournalEntry {
            scope: crate::session_overlay::JournalScope::new(EntityId::now(), claim_id),
            role: crate::session_overlay::JournalRole::TurnOwnedArtifact,
            learned_at: 5,
            occurred,
            op: BatchOp::Put {
                id: claim_id,
                entity_type: ENTITY_TYPE_CLAIM,
                occurred,
                learned_at: 5,
                data,
                allow_maintenance: false,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            },
        };

        let route = session.write_route()?;
        let overlay = session.overlay();
        let mut wtxn = vault.store.env.write_txn()?;
        let segment = overlay.install_txn_segment()?;
        let view = session.read_view()?;
        let refused = crate::batch::apply_ops_session(
            &view,
            &route,
            &vault.config,
            &vault.analyzer,
            &mut wtxn,
            vec![entry],
        )
        .expect_err(case);
        assert_eq!(refused.kind(), ErrorKind::InvalidClaimBody, "{case}");
        drop(view);
        drop(segment);
        drop(wtxn);

        // The refusal must precede the first staged byte, exactly as the base
        // door's does: a half-written turn in a room is the outcome both doors
        // exist to prevent.
        {
            let snapshot = overlay.snapshot()?;
            assert_eq!(
                snapshot.row_count(crate::session_overlay::OverlayKeyspace::Entities),
                0,
                "{case}: no row may stage"
            );
            assert_eq!(
                snapshot.journal_entries().len(),
                0,
                "{case}: nothing may be journaled"
            );
        }
    }

    session.close()?;
    Ok(())
}
