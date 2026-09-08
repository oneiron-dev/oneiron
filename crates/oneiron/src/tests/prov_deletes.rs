//! Provenance-claim deletes (downgrade/restamp) plus model substrate and actor class.

use super::*;

#[test]
fn hard_delete_of_sole_provenance_claim_downgrades_edge_to_bare() -> Result<()> {
    // AC1, "any hard reason": user_hard_delete purges directly;
    // gdpr/policy SoftErase first and then purge — all three must land on
    // the same D16 end state.
    for reason in [
        DeleteReason::UserHardDelete,
        DeleteReason::GdprDelete,
        DeleteReason::PolicyDelete,
    ] {
        let fx = lifecycle_fixture()?;
        let vault = &fx.vault;
        let subject = fx.subject;

        let (bare_out, _) = raw_edge_values(vault, &subject)?;
        let bare_out = bare_out.expect("pre-provenance edge");
        assert_eq!(bare_out.len(), EDGE_VALUE_SEMANTIC_LEN, "{reason:?}");

        let claim_id = EntityId::now();
        let mut body = EdgeProvenanceClaimBody::new(fx.person, 0.8, SupersessionStatus::Confirmed);
        body.source_revision_ref = Some([0x61; 16]);
        body.body_snapshot_ref = Some([0x62; 16]);
        vault.put_edge_provenance(&claim_id, &subject, &body, EdgeActorClass::Human, 1_000)?;
        let (stamped, _) = raw_edge_values(vault, &subject)?;
        let stamped = stamped.expect("stamped edge");
        assert_eq!(
            stamped.len(),
            EDGE_VALUE_SEMANTIC_PROVENANCED_LEN,
            "{reason:?}: the claim must stamp 26 B before the delete"
        );

        let outcome = vault.delete_entity_with_reason(&claim_id, reason)?;
        assert!(outcome.existed, "{reason:?}");
        assert!(
            vault.get(&claim_id)?.is_none(),
            "{reason:?}: the claim entity must be hard-purged"
        );

        // D16: the LAST live Claim is gone, so the cached flag may not
        // outlive its truth — the edge value downgrades 26 B → 24 B bare
        // with the first 24 bytes (weight + created_at + VAD) preserved
        // verbatim, IDENTICAL in BOTH directions.
        let (out, inn) = raw_edge_values(vault, &subject)?;
        let out = out.expect("edges_out row must survive the claim delete");
        let inn = inn.expect("edges_in row must survive the claim delete");
        assert_eq!(
            out.len(),
            EDGE_VALUE_SEMANTIC_LEN,
            "{reason:?}: 26 B must downgrade to 24 B"
        );
        assert_eq!(
            out.as_slice(),
            &stamped[..24],
            "{reason:?}: first 24 bytes preserved verbatim"
        );
        assert_eq!(
            out, bare_out,
            "{reason:?}: the downgrade restores the pre-provenance bytes"
        );
        assert_eq!(inn, out, "{reason:?}: edges_in must mirror edges_out");

        // Decoded reads agree: no cached flags remain.
        let info = vault
            .edges_out(&subject.source)?
            .into_iter()
            .find(|info| info.kind == EdgeKind::Mentions && info.target == subject.target)
            .expect("edge still listed after the claim delete");
        assert_eq!(info.provenance, None, "{reason:?}");
    }
    Ok(())
}

#[test]
fn soft_erase_of_provenance_claim_downgrades_edge_and_skips_dead_shell() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;
    let subject = fx.subject;

    let claim_id = EntityId::now();
    vault.put_edge_provenance(
        &claim_id,
        &subject,
        &EdgeProvenanceClaimBody::new(fx.person, 0.8, SupersessionStatus::Disputed),
        EdgeActorClass::Human,
        1_000,
    )?;
    let (stamped, _) = raw_edge_values(vault, &subject)?;
    let stamped = stamped.expect("stamped edge");
    assert_eq!(
        (stamped[24], stamped[25]),
        (2, 0),
        "disputed/human before the SoftErase"
    );

    // user_delete = local SoftErase: no receipt, no sweep row.
    let outcome = vault.delete_entity_with_reason(&claim_id, DeleteReason::UserDelete)?;
    assert!(outcome.existed);
    assert!(outcome.receipt_id.is_none());
    assert!(outcome.sweep_key.is_none());
    assert!(hard_erase_sweep_rows(vault)?.is_empty());

    // The Claim shell survives (25 B header, empty payload) per SoftErase
    // semantics, but the edge downgrades 26 B → 24 B in BOTH directions:
    // the truth-Claim's body is scrubbed, so the cached flag goes with it.
    assert_eq!(vault.get(&claim_id)?.as_deref(), Some([].as_slice()));
    let (out, inn) = raw_edge_values(vault, &subject)?;
    let out = out.expect("edges_out row must survive the SoftErase");
    assert_eq!(out.len(), EDGE_VALUE_SEMANTIC_LEN, "26 B → 24 B");
    assert_eq!(out.as_slice(), &stamped[..24], "first 24 bytes preserved");
    assert_eq!(inn.as_deref(), Some(out.as_slice()));

    // The bodiless shell is NOT live: a fresh provenance Claim for the same
    // edge must succeed — the live scan skips the tombstoned shell instead
    // of failing closed on its empty body — and may even carry an OLDER
    // learned_at, because the live frontier is empty again.
    let fresh = EntityId::now();
    vault.put_edge_provenance(
        &fresh,
        &subject,
        &EdgeProvenanceClaimBody::new(fx.machine, 0.3, SupersessionStatus::Confirmed),
        EdgeActorClass::System,
        500,
    )?;
    let (out, _) = raw_edge_values(vault, &subject)?;
    let out = out.expect("restamped edge");
    assert_eq!(out.len(), EDGE_VALUE_SEMANTIC_PROVENANCED_LEN);
    assert_eq!(
        (out[24], out[25]),
        (1, 2),
        "the fresh claim stamps confirmed/system"
    );
    Ok(())
}

#[test]
fn delete_of_provenance_claim_with_survivors_restamps_from_winner() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;
    let subject = fx.subject;
    let person2 = EntityId::now();
    vault.put_entity(&person2, 4, test_time_range(1, 1), 1, b"person2")?;

    // A live learned_at-tie cohort (t = 2000) so survivors exist after the
    // delete: `winner` (conf 0.6, confirmed/system) outranks `runner_up`
    // (conf 0.4, disputed/agent) under D14.
    let winner = EntityId::now();
    vault.put_edge_provenance(
        &winner,
        &subject,
        &EdgeProvenanceClaimBody::new(fx.machine, 0.6, SupersessionStatus::Confirmed),
        EdgeActorClass::System,
        2_000,
    )?;
    let runner_up = EntityId::now();
    vault.put_edge_provenance(
        &runner_up,
        &subject,
        &EdgeProvenanceClaimBody::new(person2, 0.4, SupersessionStatus::Disputed),
        EdgeActorClass::Agent,
        2_000,
    )?;
    let (before, _) = raw_edge_values(vault, &subject)?;
    let before = before.expect("stamped edge");
    assert_eq!(
        (before[24], before[25]),
        (1, 2),
        "the winner (confirmed/system) stamps while both claims are live"
    );

    // Hard-delete the WINNER: a live Claim remains, so the edge restamps
    // from the D14 winner among the SURVIVORS (disputed = 2, agent = 1) —
    // NOT a downgrade and NOT a stale stamp. A keep-the-old-flags
    // implementation FAILS here.
    let outcome = vault.delete_entity_with_reason(&winner, DeleteReason::UserHardDelete)?;
    assert!(outcome.existed);
    let (out, inn) = raw_edge_values(vault, &subject)?;
    let out = out.expect("edges_out row");
    assert_eq!(
        out.len(),
        EDGE_VALUE_SEMANTIC_PROVENANCED_LEN,
        "a surviving live claim keeps the edge 26 B"
    );
    assert_eq!(
        (out[24], out[25]),
        (2, 1),
        "restamped from the surviving runner-up"
    );
    assert_eq!(&out[..24], &before[..24], "first 24 bytes preserved");
    assert_eq!(inn.as_deref(), Some(out.as_slice()));

    // SoftErase the survivor: NO live Claim remains → D16 downgrade, both
    // directions.
    let outcome = vault.delete_entity_with_reason(&runner_up, DeleteReason::UserDelete)?;
    assert!(outcome.existed);
    let (out, inn) = raw_edge_values(vault, &subject)?;
    let out = out.expect("edges_out row");
    assert_eq!(out.len(), EDGE_VALUE_SEMANTIC_LEN);
    assert_eq!(out.as_slice(), &before[..24]);
    assert_eq!(inn.as_deref(), Some(out.as_slice()));
    Ok(())
}

#[test]
fn deleting_the_retracted_truth_claim_downgrades_the_retracted_stamp() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;
    let subject = fx.subject;

    let claim_id = EntityId::now();
    vault.put_edge_provenance(
        &claim_id,
        &subject,
        &EdgeProvenanceClaimBody::new(fx.person, 0.9, SupersessionStatus::Confirmed),
        EdgeActorClass::Human,
        1_000,
    )?;
    vault.retract_edge_provenance(&claim_id, 2_000)?;
    let (retracted, _) = raw_edge_values(vault, &subject)?;
    let retracted = retracted.expect("retracted edge");
    assert_eq!(
        (retracted.len(), retracted[24]),
        (EDGE_VALUE_SEMANTIC_PROVENANCED_LEN, 3),
        "RETRACT keeps the 26 B retracted stamp — the Claim is still readable truth"
    );

    // DELETE removes the truth-Claim entirely: with NO provenance Claim of
    // any lifecycle left for this EdgeRef the retracted stamp would be
    // unauditable, so it must NOT survive — D16 downgrade to 24 B bare.
    let outcome = vault.delete_entity_with_reason(&claim_id, DeleteReason::GdprDelete)?;
    assert!(outcome.existed);
    let (out, inn) = raw_edge_values(vault, &subject)?;
    let out = out.expect("edges_out row");
    assert_eq!(out.len(), EDGE_VALUE_SEMANTIC_LEN, "26 B → 24 B");
    assert_eq!(out.as_slice(), &retracted[..24]);
    assert_eq!(inn.as_deref(), Some(out.as_slice()));
    Ok(())
}

#[test]
fn deleting_a_superseded_claim_keeps_the_surviving_retracted_dampening_stamp() -> Result<()> {
    // ONE-1107 blocker: deleting a SUPERSEDED/closed `edge.provenance` Claim
    // while a RETRACTED Claim for the SAME EdgeRef still survives must KEEP
    // the 26 B retracted dampening stamp — NOT downgrade to 24 B bare, which
    // would silently drop the contract-mandated retracted flag and re-enable
    // PPR propagation of withdrawn provenance (retractionRules RETRACT). This
    // matches `retract_edge_provenance`'s own None-branch. The pre-fix code
    // scans only ACTIVE survivors, sees none, and downgrades to bare — so it
    // FAILS the `EDGE_VALUE_SEMANTIC_PROVENANCED_LEN` / byte-24 == 3
    // assertions below.
    for reason in [DeleteReason::UserHardDelete, DeleteReason::GdprDelete] {
        let fx = lifecycle_fixture()?;
        let vault = &fx.vault;
        let subject = fx.subject;

        // A: PERSON / human (actor_class = 0) @ t = 1000, confirmed.
        let claim_a = EntityId::now();
        vault.put_edge_provenance(
            &claim_a,
            &subject,
            &EdgeProvenanceClaimBody::new(fx.person, 0.9, SupersessionStatus::Confirmed),
            EdgeActorClass::Human,
            1_000,
        )?;

        // B supersedes A: MACHINE / system (actor_class = 2) @ t = 2000.
        // Distinct class from A so byte 25 proves which truth-Claim the edge
        // follows after the delete.
        let claim_b = EntityId::now();
        vault.supersede_edge_provenance(
            &claim_a,
            &claim_b,
            &subject,
            &EdgeProvenanceClaimBody::new(fx.machine, 0.8, SupersessionStatus::Confirmed),
            EdgeActorClass::System,
            2_000,
        )?;
        // A is now closed (superseded); B is the live winner.
        assert_eq!(
            vault.get_claim(&claim_a)?.expect("a").lifecycle,
            ClaimLifecycleStatus::Superseded,
            "{reason:?}"
        );

        // Retract B → the edge carries the 26 B RETRACTED dampening stamp
        // (confirmation_status = retracted = 3, actor_class = system = 2).
        vault.retract_edge_provenance(&claim_b, 3_000)?;
        let (retracted, _) = raw_edge_values(vault, &subject)?;
        let retracted = retracted.expect("retracted edge");
        assert_eq!(
            (retracted.len(), retracted[24], retracted[25]),
            (EDGE_VALUE_SEMANTIC_PROVENANCED_LEN, 3, 2),
            "{reason:?}: B's retraction stamps 26 B retracted/system before the delete"
        );

        // DELETE the SUPERSEDED A while the RETRACTED B survives as readable
        // truth. The derived edge flag follows the surviving (retracted)
        // Claim: the edge STAYS 26 B with confirmation_status = retracted (3)
        // and B's persisted actor_class = system (2) — it must NOT downgrade
        // to 24 B bare, and it must NOT fall back to A's human (0) class.
        let outcome = vault.delete_entity_with_reason(&claim_a, reason)?;
        assert!(outcome.existed, "{reason:?}");
        assert!(
            vault.get(&claim_a)?.is_none(),
            "{reason:?}: the superseded claim A must be purged"
        );
        assert_eq!(
            vault.get_claim(&claim_b)?.expect("b").lifecycle,
            ClaimLifecycleStatus::Retracted,
            "{reason:?}: the retracted truth-Claim B survives the delete of A"
        );

        let (out, inn) = raw_edge_values(vault, &subject)?;
        let out = out.expect("edges_out row");
        assert_eq!(
            out.len(),
            EDGE_VALUE_SEMANTIC_PROVENANCED_LEN,
            "{reason:?}: a surviving retracted Claim KEEPS the 26 B stamp — must NOT downgrade to 24 B bare"
        );
        assert_eq!(
            out[24], 3,
            "{reason:?}: confirmation_status stays retracted = 3 (the dampening flag)"
        );
        assert_eq!(
            out[25], 2,
            "{reason:?}: actor_class follows the surviving retracted B (system = 2), not deleted A's human = 0"
        );
        assert_eq!(
            &out[..24],
            &retracted[..24],
            "{reason:?}: weight/created_at/VAD bytes preserved verbatim"
        );
        assert_eq!(
            inn.as_deref(),
            Some(out.as_slice()),
            "{reason:?}: edges_in must mirror edges_out byte-for-byte"
        );

        // Decoded read agrees: the cached dampening flag survives.
        let info = vault
            .edges_out(&subject.source)?
            .into_iter()
            .find(|info| info.kind == EdgeKind::Mentions && info.target == subject.target)
            .expect("edge still listed after the superseded-claim delete");
        assert_eq!(
            info.provenance,
            Some(EdgeProvenanceFlags {
                confirmation_status: EdgeConfirmationStatus::Retracted,
                actor_class: EdgeActorClass::System,
            }),
            "{reason:?}: decoded flags must be retracted/system, never None"
        );
    }
    Ok(())
}

#[test]
fn delete_hook_discriminates_by_type_byte_and_predicate() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;
    let subject = fx.subject;

    // A provenanced 26 B edge that must NOT be touched by unrelated deletes.
    let anchor = EntityId::now();
    vault.put_edge_provenance(
        &anchor,
        &subject,
        &EdgeProvenanceClaimBody::new(fx.person, 0.9, SupersessionStatus::Confirmed),
        EdgeActorClass::Human,
        1_000,
    )?;
    let (before_out, before_in) = raw_edge_values(vault, &subject)?;

    // (a) an ORDINARY Claim (type 0, non-provenance predicate) about the
    // SAME source entity — the hook must discriminate on the PREDICATE.
    let ordinary = EntityId::now();
    let ordinary_body = ClaimBody::new(
        "hobby.collects",
        ClaimSubject::Entity(subject.source),
        rmpv::Value::from("stamps"),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    vault.put_claim(&ordinary, &ordinary_body, test_time_range(5, 5), 5)?;
    let outcome = vault.delete_entity_with_reason(&ordinary, DeleteReason::UserHardDelete)?;
    assert!(outcome.existed);

    // (b) a NON-Claim entity (TURN, type byte 1) — the hook must
    // discriminate on the TYPE BYTE.
    let turn = EntityId::now();
    vault.put_entity(&turn, 1, test_time_range(7, 7), 7, b"turn-payload")?;
    let outcome = vault.delete_entity_with_reason(&turn, DeleteReason::GdprDelete)?;
    assert!(outcome.existed);

    // Zero new behavior: the provenanced edge bytes never moved…
    let (after_out, after_in) = raw_edge_values(vault, &subject)?;
    assert_eq!(
        after_out, before_out,
        "unrelated deletes must not touch the edge"
    );
    assert_eq!(after_in, before_in);

    // …and neither queued sweep row carries provenance refs (empty slots,
    // not missing — the seam shape is uniform).
    let rows = hard_erase_sweep_rows(vault)?;
    assert_eq!(rows.len(), 2, "both receipt-writing deletes queue a sweep");
    for (_key, value) in &rows {
        let job: serde_json::Value = rmp_serde::from_slice(value).expect("decode sweep job");
        assert_eq!(
            job["scope"]["body_snapshot_refs"],
            serde_json::json!([]),
            "non-provenance deletes must queue an EMPTY body_snapshot_refs slot"
        );
        assert_eq!(job["scope"]["revision_ids"], serde_json::json!([]));
    }
    Ok(())
}

#[test]
fn corrupt_type_0_body_fails_the_delete_closed_with_zero_residue() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;
    let subject = fx.subject;

    // A pre-existing provenanced 26 B edge that the aborted deletes must
    // never touch.
    let anchor = EntityId::now();
    vault.put_edge_provenance(
        &anchor,
        &subject,
        &EdgeProvenanceClaimBody::new(fx.person, 0.9, SupersessionStatus::Confirmed),
        EdgeActorClass::Human,
        1_000,
    )?;
    let (edge_before_out, edge_before_in) = raw_edge_values(vault, &subject)?;
    let receipts_before = redaction_audit_receipts(vault)?;

    // Raw-write a type-0 (CLAIM) record with a valid 25 B header and a
    // NON-empty garbage body (32 × 0xC1 — a reserved MessagePack byte that
    // can never decode). ONE-1104 pins that every type-0 write is
    // validated, so this record can only exist through corruption.
    let corrupt = EntityId::now();
    let mut raw = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + 32);
    raw.push(0); // type byte 0 = CLAIM
    raw.extend_from_slice(&5_u64.to_be_bytes()); // occurred_start
    raw.extend_from_slice(&5_u64.to_be_bytes()); // occurred_end
    raw.extend_from_slice(&5_u64.to_be_bytes()); // learned_at
    raw.extend_from_slice(&[0xC1; 32]);
    assert!(raw.len() >= ENTITY_METADATA_HEADER_LEN + 26);
    vault.with_write_txn(|wtxn| {
        vault.store.entities.put(wtxn, corrupt.as_bytes(), &raw)?;
        Ok(())
    })?;

    // The capture hook runs on EVERY delete reason BEFORE any mutation; an
    // undecodable non-empty type-0 body must abort the delete CLOSED with
    // the decoder's typed error on a hard reason AND on the local SoftErase
    // path. A warn-and-proceed or skip-on-decode-failure capture FAILS the
    // expect_err (the delete would go through and leave residue below).
    for reason in [DeleteReason::GdprDelete, DeleteReason::UserDelete] {
        let err = vault
            .delete_entity_with_reason(&corrupt, reason)
            .expect_err("undecodable non-empty type-0 body must fail the delete closed");
        assert_eq!(err.kind(), ErrorKind::InvalidClaimBody, "{reason:?}");

        // Zero residue: the corrupt record's stored bytes are untouched…
        let rtxn = vault.store.env.read_txn()?;
        assert_eq!(
            vault
                .store
                .entities
                .get(&rtxn, corrupt.as_bytes())?
                .as_deref(),
            Some(raw.as_slice()),
            "{reason:?}: the aborted delete must leave the record byte-identical"
        );
        drop(rtxn);
        // …no receipt was written and no sweep row was queued…
        assert_eq!(
            redaction_audit_receipts(vault)?,
            receipts_before,
            "{reason:?}: receipts must be unchanged by the aborted delete"
        );
        assert!(
            hard_erase_sweep_rows(vault)?.is_empty(),
            "{reason:?}: no sweep row may be queued by the aborted delete"
        );
        // …and the pre-existing provenanced edge's raw bytes never moved.
        let (out, inn) = raw_edge_values(vault, &subject)?;
        assert_eq!(out, edge_before_out, "{reason:?}");
        assert_eq!(inn, edge_before_in, "{reason:?}");
    }
    Ok(())
}

#[test]
fn deleting_a_provenance_claim_whose_subject_edge_is_gone_refreshes_nothing() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;
    let subject = fx.subject;

    let claim_id = EntityId::now();
    vault.put_edge_provenance(
        &claim_id,
        &subject,
        &EdgeProvenanceClaimBody::new(fx.person, 0.7, SupersessionStatus::Confirmed),
        EdgeActorClass::Human,
        1_000,
    )?;
    assert!(vault.delete_edge(&subject.source, EdgeKind::Mentions, &subject.target)?);

    // The orphaned Claim still deletes cleanly: nothing is left to refresh,
    // and the missing subject edge is NOT an error.
    let outcome = vault.delete_entity_with_reason(&claim_id, DeleteReason::UserHardDelete)?;
    assert!(outcome.existed);
    assert!(vault.get(&claim_id)?.is_none());
    let (out, inn) = raw_edge_values(vault, &subject)?;
    assert_eq!(out, None, "the delete must not resurrect the edge");
    assert_eq!(inn, None);
    Ok(())
}

#[test]
fn provenance_claim_delete_invalidates_ppr_cache_for_subject_endpoints() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;
    let subject = fx.subject;

    let claim_id = EntityId::now();
    vault.put_edge_provenance(
        &claim_id,
        &subject,
        &EdgeProvenanceClaimBody::new(fx.person, 0.8, SupersessionStatus::Confirmed),
        EdgeActorClass::Human,
        1_000,
    )?;

    // Plant malformed PPR cache rows keyed to both subject-edge endpoints
    // (mirrors the ONE-1105 restamp test): invalidation DELETES dependent
    // cache rows. The TARGET endpoint is the discriminating probe — the
    // purge's own invalidate_ppr_for_delete only reaches the claim's
    // claim_of neighbor (the SOURCE); only the D16 edge refresh touches the
    // target.
    let src_hash = [0xBD_u8; 16];
    let tgt_hash = [0xBE_u8; 16];
    {
        let mut wtxn = vault.store.env.write_txn()?;
        let mut src_dep = [0_u8; 32];
        src_dep[..16].copy_from_slice(subject.source.as_bytes());
        src_dep[16..].copy_from_slice(&src_hash);
        let mut tgt_dep = [0_u8; 32];
        tgt_dep[..16].copy_from_slice(subject.target.as_bytes());
        tgt_dep[16..].copy_from_slice(&tgt_hash);
        vault
            .store
            .ppr_cache
            .put(&mut wtxn, &src_hash, &[1, 2, 3])?;
        vault
            .store
            .ppr_cache
            .put(&mut wtxn, &tgt_hash, &[1, 2, 3])?;
        vault.store.ppr_cache_deps.put(&mut wtxn, &src_dep, &[])?;
        vault.store.ppr_cache_deps.put(&mut wtxn, &tgt_dep, &[])?;
        wtxn.commit()?;
    }

    vault.delete_entity_with_reason(&claim_id, DeleteReason::UserHardDelete)?;

    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault.store.ppr_cache.get(&rtxn, &src_hash)?.is_none(),
        "source-endpoint PPR cache must be invalidated by the downgrade"
    );
    assert!(
        vault.store.ppr_cache.get(&rtxn, &tgt_hash)?.is_none(),
        "target-endpoint PPR cache must be invalidated by the downgrade"
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn hard_delete_of_provenance_claim_carries_snapshot_ref_in_sweep_scope() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;
    let subject = fx.subject;

    let claim_id = EntityId::now();
    let mut body = EdgeProvenanceClaimBody::new(fx.person, 0.8, SupersessionStatus::Confirmed);
    body.source_revision_ref = Some([0x5A; 16]);
    body.body_snapshot_ref = Some([0x5B; 16]);
    vault.put_edge_provenance(&claim_id, &subject, &body, EdgeActorClass::Human, 1_000)?;

    let outcome = vault.delete_entity_with_reason(&claim_id, DeleteReason::GdprDelete)?;
    assert!(outcome.existed);
    let sweep_key = outcome.sweep_key.expect("gdpr_delete must queue the sweep");
    assert!(sweep_key.starts_with(b"h:"));

    let rows = hard_erase_sweep_rows(vault)?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, sweep_key);
    let raw_job = rows[0].1.as_slice();
    let job: serde_json::Value = rmp_serde::from_slice(raw_job).expect("decode sweep job");

    // hardEraseSweepQueue: value = "scope + retry state"; scope = opaque IDs
    // + carrier classes, no content. The captured body_snapshot_ref MUST
    // ride the queued row's scope — "body_snapshot_ref lets the queued
    // historical-carrier sweep locate residual snapshot/update bytes" — as
    // an opaque lowercase-hex id. The executor consuming it is ONE-1091
    // (deferred); only the seam is asserted here.
    let mut scope_fields: Vec<&str> = job["scope"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    scope_fields.sort_unstable();
    assert_eq!(
        scope_fields,
        vec![
            "body_snapshot_refs",
            "carrier_classes",
            "entity_ids",
            "revision_ids"
        ]
    );
    let snapshot_hex = "5b".repeat(16);
    let revision_hex = "5a".repeat(16);
    assert_eq!(
        job["scope"]["body_snapshot_refs"],
        serde_json::json!([snapshot_hex.as_str()])
    );
    // The captured source_revision_ref rides the scope's pinned
    // "revision UUIDs" slot.
    assert_eq!(
        job["scope"]["revision_ids"],
        serde_json::json!([revision_hex])
    );
    assert_eq!(job["scope"]["entity_ids"][0], claim_id.to_hex());
    assert_eq!(
        job["scope"]["carrier_classes"],
        serde_json::json!([
            "historical_loro_updates",
            "historical_loro_snapshots",
            "derived_carriers",
            "redirect_table"
        ])
    );

    // Minimization: no content or predicate strings in the queued row.
    assert_no_receipt_payload_leak(
        raw_job,
        &[
            b"edge.provenance",
            b"actor_entity_ref",
            b"supersession_status",
        ],
    );

    // The RECEIPT is unchanged (AC3): pinned top-level fields, pinned scope
    // shape (entity UUIDs / revision UUIDs only — the captured sweep refs do
    // NOT enter the receipt), and no content/predicate/ref leak.
    let receipt_raw = vault
        .get_raw(&outcome.receipt_id.expect("receipt id"))?
        .expect("receipt persisted");
    assert_no_receipt_payload_leak(
        &receipt_raw,
        &[
            b"edge.provenance",
            b"actor_entity_ref",
            snapshot_hex.as_bytes(),
        ],
    );
    let receipt = receipt_body(&receipt_raw);
    assert_receipt_fields(&receipt);
    let mut receipt_scope_fields: Vec<&str> = receipt["scope"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    receipt_scope_fields.sort_unstable();
    assert_eq!(receipt_scope_fields, vec!["entity_ids", "revision_ids"]);
    assert_eq!(receipt["scope"]["entity_ids"][0], claim_id.to_hex());
    assert_eq!(
        receipt["scope"]["revision_ids"].as_array().unwrap().len(),
        0
    );
    Ok(())
}

/// ONE-1138 MODEL kind + get-or-create door: `ensure_model_substrate` is the
/// ONLY public way to mint a MODEL entity ("written when a substrate
/// first appears in a write path"), keyed by `(name, version)`, idempotent,
/// with the reserved `mo` short-id prefix actually allocated; descriptor
/// validation is typed (`InvalidModelSubstrate`).
#[test]
fn ensure_model_substrate_get_or_create_pins_model_kind() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    // CREATE on first appearance: engine-authored MODEL entity, type 65.
    let kimi = vault.ensure_model_substrate("kimi-k2.6", "2026-05", 1_000)?;
    assert_eq!(vault.get_entity_type(&kimi)?, Some(ENTITY_TYPE_MODEL));
    assert_eq!(ENTITY_TYPE_MODEL, 65, "ratified type byte");

    // The body dedups name + version ON the entity (never inline in
    // provenance records).
    let raw = vault.get_raw(&kimi)?.expect("model entity stored");
    let (name, version) =
        crate::provenance::decode_model_entity_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
    assert_eq!(name, "kimi-k2.6");
    assert_eq!(version, "2026-05");

    // GET: the same (name, version) returns the SAME id — idempotent, no
    // duplicate substrate row even at a different `now`.
    assert_eq!(
        vault.ensure_model_substrate("kimi-k2.6", "2026-05", 2_000)?,
        kimi
    );
    assert_eq!(vault.entities_by_type(ENTITY_TYPE_MODEL)?.len(), 1);

    // A different version IS a different substrate (selective
    // re-extraction needs per-version identity).
    let kimi_next = vault.ensure_model_substrate("kimi-k2.6", "2026-06", 3_000)?;
    assert_ne!(kimi_next, kimi);
    assert_eq!(vault.entities_by_type(ENTITY_TYPE_MODEL)?.len(), 2);

    // The reserved `mo` short-id prefix is allocated for engine-authored
    // rows (registry short_id_prefix = Some("mo"), unlike REDACTION_AUDIT).
    let rtxn = vault.store.env.read_txn()?;
    let reverse = vault
        .store
        .short_ids_reverse
        .get(&rtxn, kimi.as_bytes())?
        .expect("model entity must carry a short id");
    assert!(
        reverse.starts_with(b"mo"),
        "short id must use the reserved mo prefix, got {reverse:?}"
    );
    drop(rtxn);

    // Descriptor validation: empty or oversized name/version → typed
    // InvalidModelSubstrate, nothing written.
    let before = vault.entities_by_type(ENTITY_TYPE_MODEL)?.len();
    let oversized = "x".repeat(257);
    for (bad_name, bad_version) in [
        ("", "v1"),
        ("m", ""),
        (oversized.as_str(), "v1"),
        ("m", oversized.as_str()),
    ] {
        let err = vault
            .ensure_model_substrate(bad_name, bad_version, 1)
            .expect_err("invalid model descriptor must fail typed");
        assert_eq!(err.kind(), ErrorKind::InvalidModelSubstrate);
    }
    assert_eq!(vault.entities_by_type(ENTITY_TYPE_MODEL)?.len(), before);
    Ok(())
}

/// ONE-1138 write path: `substrate_ref` + `reasoning_effort` persist on the
/// stored 10-key record; the validated caller-supplied `actor_class` rides
/// the BODY key and the wrapper `evid` stays empty; lifecycle restamps
/// resolve the class from the body; the substrate gate rejects non-MODEL
/// refs (MACHINE-82 reuse REJECTED — kind = shape, DEC-0005 §7) and
/// dangling refs; a conflicting caller-set body class fails closed.
#[test]
fn put_edge_provenance_substrate_and_effort_round_trip_with_model_gate() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;
    let model = vault.ensure_model_substrate("oneironer-tiny", "0.3", 500)?;

    let claim_id = EntityId::now();
    let mut body = EdgeProvenanceClaimBody::new(fx.person, 0.9, SupersessionStatus::Confirmed);
    body.substrate_ref = Some(model);
    body.reasoning_effort = Some("high".to_owned());
    vault.put_edge_provenance(&claim_id, &fx.subject, &body, EdgeActorClass::Agent, 1_000)?;

    let claim = vault.get_claim(&claim_id)?.expect("claim body");
    assert!(
        claim.evidence.is_none(),
        "post-bump writers leave evid empty (evidence purity)"
    );
    let record = decode_edge_provenance_body(&claim.value)?;
    assert_eq!(record.substrate_ref, Some(model));
    assert_eq!(record.reasoning_effort.as_deref(), Some("high"));
    assert_eq!(record.actor_class, Some(EdgeActorClass::Agent));

    // Lifecycle on a NEW-shape claim: retraction resolves the persisted
    // class from the BODY key and restamps retracted (3) + agent (1).
    vault.retract_edge_provenance(&claim_id, 2_000)?;
    let (out, _) = raw_edge_values(vault, &fx.subject)?;
    let out = out.expect("edge survives retraction");
    assert_eq!(out[24], 3, "retracted = 3");
    assert_eq!(out[25], 1, "agent = 1 resolved from the BODY actor_class");

    // Substrate gate: a MACHINE (82) entity is NOT a substrate.
    let bad_id = EntityId::now();
    let mut machine_substrate =
        EdgeProvenanceClaimBody::new(fx.person, 0.5, SupersessionStatus::Proposed);
    machine_substrate.substrate_ref = Some(fx.machine);
    let err = vault
        .put_edge_provenance(
            &bad_id,
            &fx.subject,
            &machine_substrate,
            EdgeActorClass::Human,
            3_000,
        )
        .expect_err("MACHINE substrate_ref must be rejected");
    assert_eq!(err.kind(), ErrorKind::InvalidModelSubstrate);
    assert!(vault.get(&bad_id)?.is_none(), "nothing written on reject");

    // Substrate gate: a ref that names no stored entity.
    let mut dangling = EdgeProvenanceClaimBody::new(fx.person, 0.5, SupersessionStatus::Proposed);
    dangling.substrate_ref = Some(EntityId::now());
    let err = vault
        .put_edge_provenance(
            &EntityId::now(),
            &fx.subject,
            &dangling,
            EdgeActorClass::Human,
            3_000,
        )
        .expect_err("dangling substrate_ref must be rejected");
    assert_eq!(err.kind(), ErrorKind::InvalidModelSubstrate);

    // Substrate gate: a REAL, indexed MODEL row whose MessagePack
    // body is MALFORMED (not the engine `{name, version}` shape). The remote
    // replay door admits the maintenance type byte (allow_maintenance) WITHOUT
    // body-shape validation, so a forged/corrupt body can physically land in
    // the entities table. The substrate gate runs the SAME strict decoder as
    // the get-or-create scan, so a type-byte-only gate would wrongly ACCEPT
    // this. It must fail closed as `CorruptedIndex` — distinct from the
    // `InvalidModelSubstrate` referential rejections (wrong kind / dangling) —
    // and stage NO provenance Claim.
    let forged_model = EntityId::now();
    {
        let mut wtxn = vault.store.env.write_txn()?;
        crate::batch::apply_ops(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            &mut wtxn,
            vec![crate::batch::BatchOp::Put {
                id: forged_model,
                entity_type: ENTITY_TYPE_MODEL,
                occurred: TimeRange {
                    start: 400,
                    end: 400,
                },
                learned_at: 400,
                // Not a `{name, version}` MessagePack map → decode_model_entity_body fails.
                data: b"forged-model".to_vec(),
                allow_maintenance: true,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            true,
            false,
            false,
        )?;
        wtxn.commit()?;
    }
    // It really is an indexed MODEL row, so the gate reaches the body
    // decode rather than tripping on a missing / wrong-type entity.
    assert_eq!(
        vault.get_entity_type(&forged_model)?,
        Some(ENTITY_TYPE_MODEL),
        "forged substrate must be a real indexed MODEL row"
    );
    let corrupt_claim_id = EntityId::now();
    let mut malformed_substrate =
        EdgeProvenanceClaimBody::new(fx.person, 0.5, SupersessionStatus::Proposed);
    malformed_substrate.substrate_ref = Some(forged_model);
    let err = vault
        .put_edge_provenance(
            &corrupt_claim_id,
            &fx.subject,
            &malformed_substrate,
            EdgeActorClass::Human,
            3_000,
        )
        .expect_err("malformed MODEL substrate body must be rejected");
    assert_eq!(
        err.kind(),
        ErrorKind::CorruptedIndex,
        "body-malformed MODEL substrate row is ambiguous on-disk corruption \
         (CorruptedIndex), NOT a clean referential rejection (InvalidModelSubstrate)"
    );
    assert!(
        vault.get(&corrupt_claim_id)?.is_none(),
        "fail-closed: no provenance Claim staged on body-corruption reject"
    );

    // Conflict gate: a caller-set body actor_class that disagrees with the
    // actor_class parameter is ambiguous → typed reject; an AGREEING body
    // class is accepted (idempotent injection).
    let mut conflicted = EdgeProvenanceClaimBody::new(fx.person, 0.5, SupersessionStatus::Proposed);
    conflicted.actor_class = Some(EdgeActorClass::Human);
    let err = vault
        .put_edge_provenance(
            &EntityId::now(),
            &fx.subject,
            &conflicted,
            EdgeActorClass::Agent,
            3_000,
        )
        .expect_err("conflicting body actor_class must be rejected");
    assert_eq!(err.kind(), ErrorKind::InvalidProvenanceBody);
    let mut agreeing = EdgeProvenanceClaimBody::new(fx.person, 0.5, SupersessionStatus::Proposed);
    agreeing.actor_class = Some(EdgeActorClass::Human);
    vault.put_edge_provenance(
        &EntityId::now(),
        &fx.subject,
        &agreeing,
        EdgeActorClass::Human,
        3_000,
    )?;
    Ok(())
}

/// ONE-1138 transition semantics, LEGACY side: a pre-bump claim — 7-key
/// value record (no `actor_class` body key) + the engine-owned
/// `{"actor_class": u8}` map on the wrapper's `evid` — still decodes and
/// participates in lifecycle operations; old claims are NEVER invalidated.
#[test]
fn legacy_evid_actor_class_claim_decodes_and_lifecycle_restamps() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;

    // Fabricate the pre-bump shape byte-exactly through the reserved door
    // (the encoder elides the absent actor_class key, so this is the exact
    // legacy 7-key wire shape).
    let claim_id = EntityId::now();
    let record = EdgeProvenanceClaimBody::new(fx.person, 0.75, SupersessionStatus::Confirmed);
    let mut wrapper = ClaimBody::new(
        PREDICATE_EDGE_PROVENANCE,
        ClaimSubject::from(fx.subject),
        crate::provenance::encode_edge_provenance_value(&record),
        0.75,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    wrapper.evidence = Some(crate::provenance::encode_actor_class_evidence(
        EdgeActorClass::Human,
    ));
    let bytes = crate::claim::encode_claim_body(&wrapper)?;
    vault.with_write_txn(|wtxn| {
        vault
            .batch_in()
            .put_reserved_claim(&claim_id, test_time_range(1_000, u64::MAX), 1_000, &bytes)
            .edge(&claim_id, EdgeKind::ClaimOf, &fx.subject.source, 1.0)
            .apply(wtxn)
    })?;

    // The legacy claim drives the lifecycle: retraction resolves the class
    // from the LEGACY evid map and restamps retracted (3) + human (0).
    vault.retract_edge_provenance(&claim_id, 2_000)?;
    let (out, inn) = raw_edge_values(vault, &fx.subject)?;
    let out = out.expect("edges_out row survives");
    assert_eq!(inn.as_deref(), Some(out.as_slice()));
    assert_eq!(out.len(), EDGE_VALUE_SEMANTIC_PROVENANCED_LEN);
    assert_eq!(out[24], 3, "retracted = 3");
    assert_eq!(out[25], 0, "human = 0 resolved from the LEGACY evid map");
    Ok(())
}

/// ONE-1138 transition semantics, ambiguity side: a claim carrying
/// `actor_class` in BOTH the value-record body AND the wrapper's legacy
/// `evid` map fails closed on every lifecycle read — typed
/// `InvalidProvenanceBody`, never silently reconciled, and the stored claim
/// is left untouched.
#[test]
fn provenance_actor_class_in_both_body_and_evid_fails_closed() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;

    let claim_id = EntityId::now();
    let mut record = EdgeProvenanceClaimBody::new(fx.person, 0.75, SupersessionStatus::Confirmed);
    record.actor_class = Some(EdgeActorClass::Human);
    let mut wrapper = ClaimBody::new(
        PREDICATE_EDGE_PROVENANCE,
        ClaimSubject::from(fx.subject),
        crate::provenance::encode_edge_provenance_value(&record),
        0.75,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    // Even an AGREEING duplicate is ambiguous — fail closed.
    wrapper.evidence = Some(crate::provenance::encode_actor_class_evidence(
        EdgeActorClass::Human,
    ));
    let bytes = crate::claim::encode_claim_body(&wrapper)?;
    // The structural write-door (ONE-1159) rejects the ambiguous body at WRITE
    // time — the claim never reaches the store, so the whole batch is rejected
    // atomically. The resolve-time check in `resolve_persisted_actor_class` is
    // the defence-in-depth backstop, pinned separately by
    // `resolve_persisted_actor_class_pins_transition_matrix`.
    let err = vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .put_reserved_claim(&claim_id, test_time_range(1_000, u64::MAX), 1_000, &bytes)
                .edge(&claim_id, EdgeKind::ClaimOf, &fx.subject.source, 1.0)
                .apply(wtxn)
        })
        .expect_err("both-places actor_class must fail closed at write");
    assert_eq!(err.kind(), ErrorKind::InvalidProvenanceBody);

    // Fail-closed wrote nothing: the ambiguous claim was never stored and the
    // subject edge still carries no provenance stamp (24 B bare).
    assert!(
        vault.get_claim(&claim_id)?.is_none(),
        "rejected ambiguous claim must not be stored"
    );
    let (out, _) = raw_edge_values(vault, &fx.subject)?;
    assert_eq!(out.expect("edge row").len(), EDGE_VALUE_SEMANTIC_LEN);
    Ok(())
}
