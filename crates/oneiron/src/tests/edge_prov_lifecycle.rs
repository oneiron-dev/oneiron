//! Edge-provenance lifecycle: winner election, surgical weight/VAD rewrites, write-once IDs.

use super::*;

#[test]
fn retract_edge_provenance_keeps_edge_and_closes_claim() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;
    let subject = fx.subject;

    let claim_id = EntityId::now();
    let body = EdgeProvenanceClaimBody::new(fx.person, 0.75, SupersessionStatus::Confirmed);
    vault.put_edge_provenance(&claim_id, &subject, &body, EdgeActorClass::Human, 1_000)?;
    let (stamped, _) = raw_edge_values(vault, &subject)?;
    let stamped = stamped.expect("stamped edge");
    assert_eq!(stamped[24], 1, "confirmed = 1 before the retract");

    vault.retract_edge_provenance(&claim_id, 2_000)?;

    // AC1: the edge row SURVIVES — edges_out AND edges_in still return it,
    // 26 B, status byte 3. A delete-the-edge implementation FAILS here.
    let out_infos = vault.edges_out(&subject.source)?;
    let edge_out = out_infos
        .iter()
        .find(|info| info.kind == EdgeKind::Mentions && info.target == subject.target)
        .expect("edges_out must still return the retracted edge");
    let in_infos = vault.edges_in(&subject.target)?;
    let edge_in = in_infos
        .iter()
        .find(|info| info.kind == EdgeKind::Mentions && info.target == subject.source)
        .expect("edges_in must still return the retracted edge");
    let expected_flags = EdgeProvenanceFlags {
        confirmation_status: EdgeConfirmationStatus::Retracted,
        actor_class: EdgeActorClass::Human,
    };
    assert_eq!(edge_out.provenance, Some(expected_flags));
    assert_eq!(edge_in.provenance, Some(expected_flags));

    let (out, inn) = raw_edge_values(vault, &subject)?;
    let out = out.expect("edges_out row must survive retraction");
    let inn = inn.expect("edges_in row must survive retraction");
    assert_eq!(out.len(), EDGE_VALUE_SEMANTIC_PROVENANCED_LEN, "26 B kept");
    assert_eq!(out[24], 3, "retracted = 3 at offset 24");
    assert_eq!(out[25], 0, "actor_class stays the claim's own human = 0");
    assert_eq!(
        &out[..24],
        &stamped[..24],
        "weight/created_at/VAD bytes preserved verbatim"
    );
    assert_eq!(inn, out, "edges_in must mirror edges_out byte-for-byte");

    // The Claim was re-put CLOSED, not deleted: supersession_status =
    // retracted + valid_to = now in the value record, mirrored on the
    // wrapper; confidence untouched.
    let wrapper = vault
        .get_claim(&claim_id)?
        .expect("retracted claim stays readable");
    assert_eq!(wrapper.lifecycle, ClaimLifecycleStatus::Retracted);
    assert_eq!(wrapper.valid_to, Some(2_000));
    let record = decode_edge_provenance_body(&wrapper.value)?;
    assert_eq!(record.supersession_status, SupersessionStatus::Retracted);
    assert_eq!(record.valid_to, Some(2_000));
    assert_eq!(record.confidence.to_bits(), 0.75_f32.to_bits());

    // D15: envelope occurred_end refreshed u64::MAX → now; occurred_start
    // and learned_at (the D14 precedence key) never move on a lifecycle
    // re-put.
    let raw = vault.get_raw(&claim_id)?.expect("claim entity");
    assert_eq!(raw[0], 0, "claim type byte must stay 0");
    assert_eq!(
        u64::from_be_bytes(raw[1..9].try_into().expect("occurred_start")),
        1_000
    );
    assert_eq!(
        u64::from_be_bytes(raw[9..17].try_into().expect("occurred_end")),
        2_000
    );
    assert_eq!(
        u64::from_be_bytes(raw[17..25].try_into().expect("learned_at")),
        1_000
    );

    // Temporal rows follow the refreshed envelope: the u64::MAX open-end
    // sentinel row and its long-interval row are gone; the closed end
    // indexes at now.
    let rtxn = vault.store.env.read_txn()?;
    let old_end_key = Store::encode_temporal_key(u64::MAX, &claim_id);
    let new_end_key = Store::encode_temporal_key(2_000, &claim_id);
    assert!(
        vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &old_end_key)?
            .is_none(),
        "open-end sentinel row must be replaced"
    );
    assert!(
        vault
            .store
            .temporal_long_intervals
            .get(&rtxn, &old_end_key)?
            .is_none(),
        "long-interval row must be dropped with the closed window"
    );
    assert!(
        vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &new_end_key)?
            .is_some()
    );
    drop(rtxn);
    Ok(())
}

#[test]
fn supersede_edge_provenance_closes_prior_and_restamps_winner() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;
    let subject = fx.subject;

    let prior = EntityId::now();
    let prior_body = EdgeProvenanceClaimBody::new(fx.person, 0.9, SupersessionStatus::Proposed);
    vault.put_edge_provenance(&prior, &subject, &prior_body, EdgeActorClass::Human, 1_000)?;
    let (before, _) = raw_edge_values(vault, &subject)?;
    let before = before.expect("stamped edge");
    assert_eq!(
        (before[24], before[25]),
        (0, 0),
        "proposed/human before the supersede"
    );

    // D14: the newer claim wins on envelope learned_at even with LOWER
    // confidence (0.2 < 0.9) — a confidence-first implementation FAILS this
    // restamp.
    let newer = EntityId::now();
    let newer_body = EdgeProvenanceClaimBody::new(fx.machine, 0.2, SupersessionStatus::Disputed);
    vault.supersede_edge_provenance(
        &prior,
        &newer,
        &subject,
        &newer_body,
        EdgeActorClass::System,
        2_000,
    )?;

    let (out, inn) = raw_edge_values(vault, &subject)?;
    let out = out.expect("edges_out row");
    assert_eq!(out.len(), EDGE_VALUE_SEMANTIC_PROVENANCED_LEN);
    assert_eq!(out[24], 2, "disputed = 2 from the newer (winner) claim");
    assert_eq!(out[25], 2, "system = 2 from the newer (winner) claim");
    assert_eq!(&out[..24], &before[..24]);
    assert_eq!(inn.as_deref(), Some(out.as_slice()));

    // The prior is CLOSED, not deleted: still readable, life = superseded,
    // valid_to = the new claim's learned_at; its supersession_status is
    // untouched (closure lives in life + the validity window — only RETRACT
    // rewrites the status).
    let closed = vault.get_claim(&prior)?.expect("prior claim readable");
    assert_eq!(closed.lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(closed.valid_to, Some(2_000));
    let closed_record = decode_edge_provenance_body(&closed.value)?;
    assert_eq!(closed_record.valid_to, Some(2_000));
    assert_eq!(
        closed_record.supersession_status,
        SupersessionStatus::Proposed
    );
    // Prior envelope end refreshed per D15 (was the u64::MAX sentinel).
    let raw = vault.get_raw(&prior)?.expect("prior entity");
    assert_eq!(
        u64::from_be_bytes(raw[9..17].try_into().expect("occurred_end")),
        2_000
    );

    let new_claim = vault.get_claim(&newer)?.expect("new claim");
    assert_eq!(new_claim.lifecycle, ClaimLifecycleStatus::Active);
    Ok(())
}

#[test]
fn put_edge_provenance_implicitly_closes_strictly_older_live_claims() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;
    let subject = fx.subject;

    let older = EntityId::now();
    vault.put_edge_provenance(
        &older,
        &subject,
        &EdgeProvenanceClaimBody::new(fx.person, 0.9, SupersessionStatus::Confirmed),
        EdgeActorClass::Human,
        1_000,
    )?;

    // AC2: writing a NEWER provenance Claim for the same EdgeRef closes the
    // prior live Claim — even through the plain put API.
    let newer = EntityId::now();
    vault.put_edge_provenance(
        &newer,
        &subject,
        &EdgeProvenanceClaimBody::new(fx.person, 0.1, SupersessionStatus::Proposed),
        EdgeActorClass::Agent,
        2_000,
    )?;

    let closed = vault.get_claim(&older)?.expect("prior claim readable");
    assert_eq!(closed.lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(
        closed.valid_to,
        Some(2_000),
        "absent valid_to closes at the incoming learned_at"
    );

    let (out, _) = raw_edge_values(vault, &subject)?;
    let out = out.expect("edge");
    assert_eq!(
        (out[24], out[25]),
        (0, 1),
        "flags restamp from the newer claim (proposed/agent)"
    );

    // Both claims remain attached to the source entity — history is kept.
    let ids: HashSet<EntityId> = vault
        .claims_for_subject(&subject.source)?
        .into_iter()
        .collect();
    assert_eq!(ids, HashSet::from([older, newer]));
    Ok(())
}

/// THE regression for the pinned hole (M2 adversarial verify, PR #81):
/// before ONE-1113, every plain edge put re-encoded an already-provenanced
/// edge with `provenance: None`, silently dropping the 26-byte value to
/// 24 bytes in BOTH directions while the truth Claim stayed live. Ruling
/// pt 2: typed reject, routed; both directions byte-identical; the live
/// Claim untouched. A fix that strips, preserves-silently, or rejects only
/// `put_edge` (not the batch builders) FAILS here.
#[test]
fn plain_edge_reput_on_provenanced_edge_rejects_and_routes() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;
    let subject = fx.subject;
    let (a, b) = (subject.source, subject.target);

    let claim_id = EntityId::now();
    vault.put_edge_provenance(
        &claim_id,
        &subject,
        &EdgeProvenanceClaimBody::new(fx.person, 0.75, SupersessionStatus::Confirmed),
        EdgeActorClass::Human,
        1_000,
    )?;
    let (before_out, before_in) = raw_edge_values(vault, &subject)?;
    let before_out = before_out.expect("provenanced edge");
    assert_eq!(before_out.len(), EDGE_VALUE_SEMANTIC_PROVENANCED_LEN);
    assert_eq!(before_in.as_deref(), Some(before_out.as_slice()));

    let vad = Vad {
        valence: 0.1,
        arousal: 0.2,
        dominance: 0.3,
    };
    // Every public plain-put surface the ruling names: the typed vault API,
    // both batch-builder flavors, and the txn-builder flavor.
    let attempts: Vec<(&str, Error)> = vec![
        (
            "put_edge",
            vault
                .put_edge(&a, EdgeKind::Mentions, &b, 0.5)
                .expect_err("put_edge must reject"),
        ),
        (
            "put_edge_with_vad",
            vault
                .put_edge_with_vad(&a, EdgeKind::Mentions, &b, 0.5, vad)
                .expect_err("put_edge_with_vad must reject"),
        ),
        (
            "batch().edge()",
            vault
                .batch()
                .edge(&a, EdgeKind::Mentions, &b, 0.5)
                .commit()
                .expect_err("batch edge must reject"),
        ),
        (
            "batch().edge_with_vad()",
            vault
                .batch()
                .edge_with_vad(&a, EdgeKind::Mentions, &b, 0.5, vad)
                .commit()
                .expect_err("batch edge_with_vad must reject"),
        ),
        (
            "batch_in().edge()",
            vault
                .with_write_txn(|wtxn| {
                    vault
                        .batch_in()
                        .edge(&a, EdgeKind::Mentions, &b, 0.5)
                        .apply(wtxn)
                })
                .expect_err("txn-builder edge must reject"),
        ),
    ];
    for (context, err) in &attempts {
        assert_edge_is_provenanced_reject(err, EdgeKind::Mentions, context);
    }

    // Atomicity: a batch mixing a VALID entity put with the offending edge
    // op aborts wholesale — the put must not survive the rejected commit.
    let orphan = EntityId::now();
    let err = vault
        .batch()
        .put(&orphan, 4, test_time_range(1, 1), 1, b"rider")
        .edge(&a, EdgeKind::Mentions, &b, 0.5)
        .commit()
        .expect_err("mixed batch must reject");
    assert_edge_is_provenanced_reject(&err, EdgeKind::Mentions, "mixed batch");
    assert!(
        vault.get_raw(&orphan)?.is_none(),
        "a rejected batch must not leak its rider put"
    );

    // Both directions byte-identical to the pre-attempt 26-byte value.
    let (after_out, after_in) = raw_edge_values(vault, &subject)?;
    assert_eq!(
        after_out.as_deref(),
        Some(before_out.as_slice()),
        "edges_out must stay byte-identical after every rejected put"
    );
    assert_eq!(
        after_in.as_deref(),
        Some(before_out.as_slice()),
        "edges_in must stay byte-identical after every rejected put"
    );

    // The live Claim is untouched truth.
    let claim = vault.get_claim(&claim_id)?.expect("claim readable");
    assert_eq!(claim.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(
        decode_edge_provenance_body(&claim.value)?.supersession_status,
        SupersessionStatus::Confirmed
    );

    // Ruling pt 1 (positive control): a plain put on a NON-provenanced edge
    // is unchanged — absence of provenance is itself the anonymous
    // representation. Re-put a bare edge and a structural edge freely.
    let c = EntityId::now();
    vault.put_entity(&c, 4, test_time_range(1, 1), 1, b"c")?;
    vault.put_edge(&a, EdgeKind::About, &c, 0.25)?;
    vault.put_edge(&a, EdgeKind::About, &c, 0.75)?;
    let bare = EdgeRef::new(a, EdgeKind::About, c);
    let (out, inn) = raw_edge_values(vault, &bare)?;
    let out = out.expect("bare edge");
    assert_eq!(out.len(), EDGE_VALUE_SEMANTIC_LEN, "bare re-put stays 24 B");
    assert_eq!(&out[0..4], &0.75_f32.to_le_bytes(), "re-put weight applied");
    assert_eq!(inn.as_deref(), Some(out.as_slice()));
    vault.put_edge(&a, EdgeKind::BelongsTo, &c, 0.5)?;
    vault.put_edge(&a, EdgeKind::BelongsTo, &c, 0.9)?;
    Ok(())
}

/// ONE-1113 operational weight setter (ruling pt 5, M3 weight pin): the
/// carve-out rewrites ONLY bytes 0..4, preserves `created_at` + VAD + the
/// two hot-flag bytes verbatim on a 26-byte value, mirrors both directions,
/// never touches the Claim, and invalidates the endpoint PPR caches like
/// any edge write. An implementation that re-encodes the value (dropping
/// flags) or skips the reverse row FAILS here.
#[test]
fn set_edge_weight_rewrites_only_weight_bytes_and_preserves_provenance() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;
    let subject = fx.subject;
    let (a, b) = (subject.source, subject.target);

    let claim_id = EntityId::now();
    vault.put_edge_provenance(
        &claim_id,
        &subject,
        &EdgeProvenanceClaimBody::new(fx.person, 0.75, SupersessionStatus::Confirmed),
        EdgeActorClass::Human,
        1_000,
    )?;
    let (before, _) = raw_edge_values(vault, &subject)?;
    let before = before.expect("provenanced edge");
    assert_eq!(before.len(), EDGE_VALUE_SEMANTIC_PROVENANCED_LEN);

    // Plant malformed PPR cache rows keyed to both endpoints so the
    // invalidation is observable (the same oracle as the ONE-1105 test).
    let src_hash = [0xB1_u8; 16];
    let tgt_hash = [0xB2_u8; 16];
    {
        let mut wtxn = vault.store.env.write_txn()?;
        let mut src_dep = [0_u8; 32];
        src_dep[..16].copy_from_slice(a.as_bytes());
        src_dep[16..].copy_from_slice(&src_hash);
        let mut tgt_dep = [0_u8; 32];
        tgt_dep[..16].copy_from_slice(b.as_bytes());
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

    vault.set_edge_weight(&a, EdgeKind::Mentions, &b, 0.42)?;

    let (out, inn) = raw_edge_values(vault, &subject)?;
    let out = out.expect("edge survives");
    assert_eq!(out.len(), EDGE_VALUE_SEMANTIC_PROVENANCED_LEN);
    assert_eq!(
        &out[0..4],
        &0.42_f32.to_le_bytes(),
        "weight bytes rewritten"
    );
    assert_eq!(
        &out[4..],
        &before[4..],
        "created_at + VAD + hot-flag bytes (incl. 24/25) preserved verbatim"
    );
    assert_eq!(inn.as_deref(), Some(out.as_slice()), "both directions");
    {
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault.store.ppr_cache.get(&rtxn, &src_hash)?.is_none(),
            "source-endpoint PPR cache must be invalidated"
        );
        assert!(
            vault.store.ppr_cache.get(&rtxn, &tgt_hash)?.is_none(),
            "target-endpoint PPR cache must be invalidated"
        );
    }
    // The truth Claim is untouched by the operational setter.
    let claim = vault.get_claim(&claim_id)?.expect("claim readable");
    assert_eq!(claim.lifecycle, ClaimLifecycleStatus::Active);

    // Contract [0, 1] + finiteness — typed reject, value unchanged.
    for bad in [1.5_f32, -0.1, f32::NAN] {
        let err = vault
            .set_edge_weight(&a, EdgeKind::Mentions, &b, bad)
            .expect_err("out-of-contract weight must reject");
        assert_eq!(err.kind(), ErrorKind::InvalidEdgeWeight, "weight {bad}");
    }
    let (unchanged, _) = raw_edge_values(vault, &subject)?;
    assert_eq!(unchanged.as_deref(), Some(out.as_slice()));

    // Never an upsert: a missing edge is the typed EdgeNotFound.
    let ghost = EntityId::now();
    let err = vault
        .set_edge_weight(&a, EdgeKind::Mentions, &ghost, 0.5)
        .expect_err("missing edge must reject");
    assert_eq!(err.kind(), ErrorKind::EdgeNotFound);

    // Weight lives at offset 0 on ALL layouts: a structural 12-byte edge is
    // settable and KEEPS its 12-byte layout.
    vault.put_edge(&a, EdgeKind::BelongsTo, &b, 0.5)?;
    vault.set_edge_weight(&a, EdgeKind::BelongsTo, &b, 0.125)?;
    let structural = EdgeRef::new(a, EdgeKind::BelongsTo, b);
    let (out, inn) = raw_edge_values(vault, &structural)?;
    let out = out.expect("structural edge");
    assert_eq!(out.len(), EDGE_VALUE_STRUCTURAL_LEN);
    assert_eq!(&out[0..4], &0.125_f32.to_le_bytes());
    assert_eq!(inn.as_deref(), Some(out.as_slice()));
    Ok(())
}

/// ONE-1113 operational VAD setter: rewrites ONLY bytes 12..24, preserves
/// weight/`created_at`/length (24 B stays 24 B; a 26-byte value keeps its
/// hot-flag bytes), mirrors both directions, and rejects structural
/// 12-byte kinds typed — the contract layout table gives them no VAD.
#[test]
fn set_edge_vad_rewrites_only_vad_bytes_and_preserves_layout() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;
    let subject = fx.subject;
    let (a, b) = (subject.source, subject.target);

    // Component ranges are the pinned VAD contract: valence ∈ [-1, 1],
    // arousal/dominance ∈ [0, 1].
    let new_vad = Vad {
        valence: -0.5,
        arousal: 0.25,
        dominance: 0.875,
    };

    // 24-byte bare edge: VAD bytes rewritten in place, length preserved.
    let (before, _) = raw_edge_values(vault, &subject)?;
    let before = before.expect("bare fixture edge");
    assert_eq!(before.len(), EDGE_VALUE_SEMANTIC_LEN);
    vault.set_edge_vad(&a, EdgeKind::Mentions, &b, new_vad)?;
    let (out, inn) = raw_edge_values(vault, &subject)?;
    let out = out.expect("edge survives");
    assert_eq!(out.len(), EDGE_VALUE_SEMANTIC_LEN, "24 B stays 24 B");
    assert_eq!(&out[0..12], &before[0..12], "weight + created_at preserved");
    assert_eq!(&out[12..16], &(-0.5_f32).to_le_bytes());
    assert_eq!(&out[16..20], &0.25_f32.to_le_bytes());
    assert_eq!(&out[20..24], &0.875_f32.to_le_bytes());
    assert_eq!(inn.as_deref(), Some(out.as_slice()), "both directions");

    // 26-byte provenanced edge: hot-flag bytes 24/25 preserved verbatim.
    let claim_id = EntityId::now();
    vault.put_edge_provenance(
        &claim_id,
        &subject,
        &EdgeProvenanceClaimBody::new(fx.person, 0.75, SupersessionStatus::Disputed),
        EdgeActorClass::Agent,
        1_000,
    )?;
    let (stamped, _) = raw_edge_values(vault, &subject)?;
    let stamped = stamped.expect("stamped edge");
    assert_eq!(stamped.len(), EDGE_VALUE_SEMANTIC_PROVENANCED_LEN);
    vault.set_edge_vad(&a, EdgeKind::Mentions, &b, Vad::NEUTRAL)?;
    let (out, inn) = raw_edge_values(vault, &subject)?;
    let out = out.expect("edge survives");
    assert_eq!(out.len(), EDGE_VALUE_SEMANTIC_PROVENANCED_LEN);
    assert_eq!(&out[0..12], &stamped[0..12]);
    assert_eq!(&out[12..24], &[0_u8; 12][..], "VAD reset to NEUTRAL");
    assert_eq!(
        &out[24..26],
        &stamped[24..26],
        "hot-flag bytes (disputed=2, agent=1) must survive the VAD rewrite"
    );
    assert_eq!(inn.as_deref(), Some(out.as_slice()));
    assert_eq!(
        vault.get_claim(&claim_id)?.expect("claim").lifecycle,
        ClaimLifecycleStatus::Active,
        "the operational setter never touches the Claim"
    );

    // Structural kinds carry no VAD — typed reject, nothing written.
    vault.put_edge(&a, EdgeKind::BelongsTo, &b, 0.5)?;
    let err = vault
        .set_edge_vad(&a, EdgeKind::BelongsTo, &b, new_vad)
        .expect_err("structural VAD set must reject");
    assert_eq!(err.kind(), ErrorKind::InvariantViolation);
    assert!(
        err.to_string()
            .contains("structural edges do not carry VAD"),
        "got {err:?}"
    );
    let structural = EdgeRef::new(a, EdgeKind::BelongsTo, b);
    let (out, _) = raw_edge_values(vault, &structural)?;
    assert_eq!(
        out.expect("structural edge").len(),
        EDGE_VALUE_STRUCTURAL_LEN
    );

    // Component validation + never-upsert. NaN and the asymmetric range
    // pins (valence [-1, 1] admits -1; arousal [0, 1] rejects it).
    let err = vault
        .set_edge_vad(
            &a,
            EdgeKind::Mentions,
            &b,
            Vad {
                valence: f32::NAN,
                arousal: 0.0,
                dominance: 0.0,
            },
        )
        .expect_err("NaN VAD must reject");
    assert_eq!(err.kind(), ErrorKind::InvalidVad);
    let err = vault
        .set_edge_vad(
            &a,
            EdgeKind::Mentions,
            &b,
            Vad {
                valence: -1.0,
                arousal: -0.25,
                dominance: 0.0,
            },
        )
        .expect_err("arousal below [0, 1] must reject");
    assert!(
        matches!(
            err,
            Error::InvalidVad {
                component: VadComponent::Arousal,
                ..
            }
        ),
        "got {err:?}"
    );
    let ghost = EntityId::now();
    let err = vault
        .set_edge_vad(&a, EdgeKind::Mentions, &ghost, new_vad)
        .expect_err("missing edge must reject");
    assert_eq!(err.kind(), ErrorKind::EdgeNotFound);
    Ok(())
}

/// ONE-1113 batch forms (the decay / retrieval-feedback loop idiom): both
/// setters compose in one atomic batch, and one failing op aborts the WHOLE
/// transaction — staged sibling rewrites must not survive a rejected
/// commit.
#[test]
fn batch_set_edge_weight_and_vad_forms_apply_atomically() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let a = EntityId::now();
    let b = EntityId::now();
    let c = EntityId::now();
    vault.put_entity(&a, 4, test_time_range(1, 1), 1, b"a")?;
    vault.put_entity(&b, 4, test_time_range(1, 1), 1, b"b")?;
    vault.put_entity(&c, 4, test_time_range(1, 1), 1, b"c")?;
    vault.put_edge(&a, EdgeKind::Mentions, &b, 0.875)?;
    vault.put_edge(&a, EdgeKind::About, &c, 0.5)?;

    let vad = Vad {
        valence: 0.5,
        arousal: 0.25,
        dominance: 0.75,
    };
    vault
        .batch()
        .set_edge_weight(&a, EdgeKind::Mentions, &b, 0.4375)
        .set_edge_vad(&a, EdgeKind::About, &c, vad)
        .commit()?;
    let (mentions, _) = raw_edge_values(&vault, &EdgeRef::new(a, EdgeKind::Mentions, b))?;
    let mentions = mentions.expect("mentions edge");
    assert_eq!(&mentions[0..4], &0.4375_f32.to_le_bytes());
    let (about, _) = raw_edge_values(&vault, &EdgeRef::new(a, EdgeKind::About, c))?;
    let about = about.expect("about edge");
    assert_eq!(&about[12..16], &0.5_f32.to_le_bytes());
    assert_eq!(&about[16..20], &0.25_f32.to_le_bytes());

    // Atomicity: the second op targets a missing edge — the whole batch
    // aborts and the FIRST op's staged rewrite is discarded.
    let ghost = EntityId::now();
    let err = vault
        .batch()
        .set_edge_weight(&a, EdgeKind::Mentions, &b, 0.9)
        .set_edge_weight(&a, EdgeKind::Mentions, &ghost, 0.5)
        .commit()
        .expect_err("batch with a missing-edge op must reject");
    assert_eq!(err.kind(), ErrorKind::EdgeNotFound);
    let (mentions, _) = raw_edge_values(&vault, &EdgeRef::new(a, EdgeKind::Mentions, b))?;
    assert_eq!(
        &mentions.expect("mentions edge")[0..4],
        &0.4375_f32.to_le_bytes(),
        "a rejected batch must not leak its sibling weight rewrite"
    );
    Ok(())
}

/// ONE-1113 session-bound actor handle (ruling pt 4): bind the actor once,
/// write normally — the handle injects `actor_entity_ref` + `actor_class`
/// into the provenance path; a conflicting body actor is rejected typed
/// (never silently rewritten); the full gate chain (D13 class validation,
/// implicit supersession, winner restamp) still runs underneath.
#[test]
fn as_actor_bound_write_carries_bound_actor_and_rejects_conflicts() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;
    let subject = fx.subject;

    let bound = vault.as_actor(fx.person, EdgeActorClass::Human);
    assert_eq!(bound.actor(), fx.person);
    assert_eq!(bound.actor_class(), EdgeActorClass::Human);

    // Bound write: the Claim carries the BOUND actor and the edge restamps
    // (confirmed = 1, human = 0) — composed with main's current actor shape
    // (the caller-supplied class parameter, persisted by the engine).
    let claim_id = EntityId::now();
    let body = bound.provenance_body(0.8, SupersessionStatus::Confirmed);
    bound.put_edge_provenance(&claim_id, &subject, &body, 1_000)?;
    let claim = vault.get_claim(&claim_id)?.expect("bound claim");
    assert_eq!(claim.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(
        decode_edge_provenance_body(&claim.value)?.actor_entity_ref,
        fx.person,
        "the bound write must carry the bound actor_entity_ref"
    );
    let (out, inn) = raw_edge_values(vault, &subject)?;
    let out = out.expect("stamped edge");
    assert_eq!(out.len(), EDGE_VALUE_SEMANTIC_PROVENANCED_LEN);
    assert_eq!((out[24], out[25]), (1, 0), "confirmed/human stamp");
    assert_eq!(inn.as_deref(), Some(out.as_slice()));

    // Ruling pt 3 through the handle: a NEWER bound write modifies via the
    // supersession chain — the prior closes, history kept, flags restamp.
    let claim2 = EntityId::now();
    let body2 = bound.provenance_body(0.6, SupersessionStatus::Disputed);
    bound.put_edge_provenance(&claim2, &subject, &body2, 2_000)?;
    assert_eq!(
        vault.get_claim(&claim_id)?.expect("prior").lifecycle,
        ClaimLifecycleStatus::Superseded,
        "modification flows as a supersession chain (retraction is not excision)"
    );
    let (out, _) = raw_edge_values(vault, &subject)?;
    let out = out.expect("edge");
    assert_eq!(
        (out[24], out[25]),
        (2, 0),
        "flags restamp from the newer bound claim (disputed/human)"
    );

    // Fail-closed binding: a body naming a DIFFERENT actor is rejected
    // typed — the handle injects, it never silently rewrites.
    let conflicting = EdgeProvenanceClaimBody::new(fx.machine, 0.9, SupersessionStatus::Confirmed);
    let stray = EntityId::now();
    let err = bound
        .put_edge_provenance(&stray, &subject, &conflicting, 3_000)
        .expect_err("conflicting body actor must reject");
    assert!(
        matches!(
            &err,
            Error::InvalidProvenanceBody(msg)
                if msg.contains("session-bound actor")
        ),
        "got {err:?}"
    );
    assert!(
        vault.get_raw(&stray)?.is_none(),
        "a rejected bound write must store nothing"
    );

    // The handle is ergonomics, NOT authorization: D13 still validates the
    // bound class against the actor entity's kind underneath.
    let mismatched = vault.as_actor(fx.machine, EdgeActorClass::Human);
    let stray2 = EntityId::now();
    let body3 = mismatched.provenance_body(0.9, SupersessionStatus::Confirmed);
    let err = mismatched
        .put_edge_provenance(&stray2, &subject, &body3, 3_000)
        .expect_err("MACHINE+human must fail D13 through the handle");
    assert_eq!(err.kind(), ErrorKind::ActorClassMismatch);
    Ok(())
}

#[test]
fn multi_claim_winner_and_retract_refresh_to_runner_up() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;
    let subject = fx.subject;
    // Distinct actor entity (PERSON) for the runner-up so the actor_class
    // refresh is observable on byte 25.
    let person2 = EntityId::now();
    vault.put_entity(&person2, 4, test_time_range(1, 1), 1, b"person2")?;

    // c1 @ t1 — auto-superseded once the t2 cohort lands.
    let c1 = EntityId::now();
    vault.put_edge_provenance(
        &c1,
        &subject,
        &EdgeProvenanceClaimBody::new(fx.person, 0.9, SupersessionStatus::Proposed),
        EdgeActorClass::Human,
        1_000,
    )?;
    // c2 @ t2, conf 0.6 — the winner.
    let c2 = EntityId::now();
    vault.put_edge_provenance(
        &c2,
        &subject,
        &EdgeProvenanceClaimBody::new(fx.machine, 0.6, SupersessionStatus::Confirmed),
        EdgeActorClass::System,
        2_000,
    )?;
    // c3 @ t2, conf 0.4 — learned_at TIE with c2, broken by confidence: c3
    // coexists live but the stamp stays c2's. A stamp-the-newest-write
    // implementation FAILS these assertions.
    let c3 = EntityId::now();
    vault.put_edge_provenance(
        &c3,
        &subject,
        &EdgeProvenanceClaimBody::new(person2, 0.4, SupersessionStatus::Disputed),
        EdgeActorClass::Agent,
        2_000,
    )?;

    let (out, _) = raw_edge_values(vault, &subject)?;
    let out = out.expect("edge");
    assert_eq!(
        (out[24], out[25]),
        (1, 2),
        "winner = c2 (confirmed/system): the t2 tie is broken by confidence 0.6 > 0.4"
    );

    // Lifecycles: c1 superseded by the t2 cohort; c2 and c3 BOTH live.
    assert_eq!(
        vault.get_claim(&c1)?.expect("c1").lifecycle,
        ClaimLifecycleStatus::Superseded
    );
    assert_eq!(
        vault.get_claim(&c2)?.expect("c2").lifecycle,
        ClaimLifecycleStatus::Active
    );
    assert_eq!(
        vault.get_claim(&c3)?.expect("c3").lifecycle,
        ClaimLifecycleStatus::Active
    );

    // AC4: retract the WINNER → flags refresh to the RUNNER-UP c3
    // (disputed = 2, agent = 1) — and NOT to the closed c1 even though its
    // confidence (0.9) is the highest on record: closed claims never win.
    vault.retract_edge_provenance(&c2, 3_000)?;
    let (out, inn) = raw_edge_values(vault, &subject)?;
    let out = out.expect("edge survives");
    assert_eq!(out.len(), EDGE_VALUE_SEMANTIC_PROVENANCED_LEN);
    assert_eq!(
        (out[24], out[25]),
        (2, 1),
        "runner-up c3 (disputed/agent) must stamp after the winner's retraction"
    );
    assert_eq!(inn.as_deref(), Some(out.as_slice()));

    // Retract the last live claim → zero live: the contract's retracted
    // stamp (3) with the retracted claim's own persisted actor class.
    vault.retract_edge_provenance(&c3, 4_000)?;
    let (out, inn) = raw_edge_values(vault, &subject)?;
    let out = out.expect("edge survives full retraction");
    assert_eq!(out.len(), EDGE_VALUE_SEMANTIC_PROVENANCED_LEN);
    assert_eq!(
        (out[24], out[25]),
        (3, 1),
        "no live claims: retracted = 3 with c3's agent class"
    );
    assert_eq!(inn.as_deref(), Some(out.as_slice()));

    // History: all three claims remain readable — never deleted.
    let ids: HashSet<EntityId> = vault
        .claims_for_subject(&subject.source)?
        .into_iter()
        .collect();
    assert_eq!(ids, HashSet::from([c1, c2, c3]));
    Ok(())
}

#[test]
fn provenance_lifecycle_negative_paths_fail_closed() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;
    let subject = fx.subject;

    // A live claim to act against.
    let live = EntityId::now();
    vault.put_edge_provenance(
        &live,
        &subject,
        &EdgeProvenanceClaimBody::new(fx.person, 0.8, SupersessionStatus::Confirmed),
        EdgeActorClass::Human,
        2_000,
    )?;
    let (stamped, _) = raw_edge_values(vault, &subject)?;
    let stamped = stamped.expect("stamped edge");
    let live_before = vault.get_claim(&live)?.expect("live claim");
    let fresh_body = EdgeProvenanceClaimBody::new(fx.person, 0.5, SupersessionStatus::Proposed);

    // Retract: missing claim id → EntityNotFound.
    let err = vault
        .retract_edge_provenance(&seeded_entity_id(0xF00D), 3_000)
        .expect_err("missing claim must be rejected");
    assert_eq!(err.kind(), ErrorKind::EntityNotFound);

    // Retract on a non-claim entity (PERSON, type 4) → NotAProvenanceClaim.
    let err = vault
        .retract_edge_provenance(&fx.person, 3_000)
        .expect_err("a PERSON entity is not a provenance claim");
    assert_eq!(err.kind(), ErrorKind::NotAProvenanceClaim);

    // Retract on an ORDINARY claim (wrong predicate) → NotAProvenanceClaim;
    // the claim body is untouched.
    let ordinary = EntityId::now();
    let ordinary_body = ClaimBody::new(
        "hobby.collects",
        ClaimSubject::Entity(fx.person),
        rmpv::Value::from("stamps"),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    vault.put_claim(&ordinary, &ordinary_body, test_time_range(5, 5), 5)?;
    let err = vault
        .retract_edge_provenance(&ordinary, 3_000)
        .expect_err("ordinary claims must be rejected");
    assert_eq!(err.kind(), ErrorKind::NotAProvenanceClaim);
    assert_eq!(
        vault.get_claim(&ordinary)?.expect("ordinary claim intact"),
        ordinary_body
    );

    // Supersede with an ordinary-claim prior → NotAProvenanceClaim; the new
    // claim must not exist afterwards.
    let new_id = EntityId::now();
    let err = vault
        .supersede_edge_provenance(
            &ordinary,
            &new_id,
            &subject,
            &fresh_body,
            EdgeActorClass::Human,
            3_000,
        )
        .expect_err("ordinary prior must be rejected");
    assert_eq!(err.kind(), ErrorKind::NotAProvenanceClaim);
    assert_no_entity_state(vault, &new_id)?;

    // SUBJECT MISMATCH (AC3): the prior names a DIFFERENT EdgeRef than the
    // supersede call → typed; nothing written, prior untouched.
    let c = EntityId::now();
    vault.put_entity(&c, 4, test_time_range(1, 1), 1, b"c")?;
    vault.put_edge(&subject.source, EdgeKind::About, &c, 0.5)?;
    let other_subject = EdgeRef::new(subject.source, EdgeKind::About, c);
    let (other_before, _) = raw_edge_values(vault, &other_subject)?;
    let new_id = EntityId::now();
    let err = vault
        .supersede_edge_provenance(
            &live,
            &new_id,
            &other_subject,
            &fresh_body,
            EdgeActorClass::Human,
            3_000,
        )
        .expect_err("prior addressing a different EdgeRef must be rejected");
    assert_eq!(err.kind(), ErrorKind::ProvenanceSubjectMismatch);
    assert_no_entity_state(vault, &new_id)?;
    assert_eq!(
        vault.get_claim(&live)?.expect("live untouched"),
        live_before
    );
    let (other_after, _) = raw_edge_values(vault, &other_subject)?;
    assert_eq!(
        other_after, other_before,
        "the mismatched-subject edge must be untouched"
    );

    // Double-retract → ProvenanceClaimAlreadyClosed; the FIRST close wins.
    vault.retract_edge_provenance(&live, 3_000)?;
    let err = vault
        .retract_edge_provenance(&live, 4_000)
        .expect_err("double retract must be rejected");
    assert_eq!(err.kind(), ErrorKind::ProvenanceClaimAlreadyClosed);
    let after = vault.get_claim(&live)?.expect("claim");
    assert_eq!(
        after.valid_to,
        Some(3_000),
        "a rejected second retract must not move the close instant"
    );
    assert_eq!(after.lifecycle, ClaimLifecycleStatus::Retracted);

    // Supersede a CLOSED prior → ProvenanceClaimAlreadyClosed; nothing
    // written.
    let new_id = EntityId::now();
    let err = vault
        .supersede_edge_provenance(
            &live,
            &new_id,
            &subject,
            &fresh_body,
            EdgeActorClass::Human,
            5_000,
        )
        .expect_err("closed prior must be rejected");
    assert_eq!(err.kind(), ErrorKind::ProvenanceClaimAlreadyClosed);
    assert_no_entity_state(vault, &new_id)?;

    // D14 precedence: an incoming claim OLDER than the live frontier is
    // rejected with the exact typed payload, on BOTH the implicit put path
    // and the explicit supersede path.
    let c4 = EntityId::now();
    vault.put_edge_provenance(
        &c4,
        &subject,
        &EdgeProvenanceClaimBody::new(fx.person, 0.7, SupersessionStatus::Confirmed),
        EdgeActorClass::Human,
        6_000,
    )?;
    let new_id = EntityId::now();
    let err = vault
        .put_edge_provenance(&new_id, &subject, &fresh_body, EdgeActorClass::Human, 5_000)
        .expect_err("older-than-frontier put must be rejected");
    let Error::ProvenancePrecedenceViolation {
        incoming_learned_at,
        frontier_learned_at,
    } = err
    else {
        panic!("expected ProvenancePrecedenceViolation, got {err:?}");
    };
    assert_eq!(incoming_learned_at, 5_000);
    assert_eq!(frontier_learned_at, 6_000);
    assert_no_entity_state(vault, &new_id)?;
    let err = vault
        .supersede_edge_provenance(
            &c4,
            &new_id,
            &subject,
            &fresh_body,
            EdgeActorClass::Human,
            5_000,
        )
        .expect_err("older-than-prior explicit supersede must be rejected");
    assert_eq!(err.kind(), ErrorKind::ProvenancePrecedenceViolation);
    assert_no_entity_state(vault, &new_id)?;

    // Self-supersession → typed; the claim stays live.
    let err = vault
        .supersede_edge_provenance(
            &c4,
            &c4,
            &subject,
            &fresh_body,
            EdgeActorClass::Human,
            7_000,
        )
        .expect_err("self supersession must be rejected");
    assert_eq!(err.kind(), ErrorKind::ProvenanceSelfSupersession);
    assert_eq!(
        vault.get_claim(&c4)?.expect("c4").lifecycle,
        ClaimLifecycleStatus::Active
    );

    // Retract BEFORE valid_from would invert the validity window → typed
    // InvalidProvenanceBody, never silently reordered; claim untouched.
    let future = EntityId::now();
    let mut future_body =
        EdgeProvenanceClaimBody::new(fx.person, 0.6, SupersessionStatus::Proposed);
    future_body.valid_from = Some(9_000);
    vault.put_edge_provenance(
        &future,
        &subject,
        &future_body,
        EdgeActorClass::Human,
        6_000,
    )?;
    let err = vault
        .retract_edge_provenance(&future, 8_000)
        .expect_err("retract before valid_from must be rejected");
    assert_eq!(err.kind(), ErrorKind::InvalidProvenanceBody);
    let intact = vault.get_claim(&future)?.expect("future claim intact");
    assert_eq!(intact.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(
        decode_edge_provenance_body(&intact.value)?.supersession_status,
        SupersessionStatus::Proposed
    );

    // Through every rejection above, the subject edge bytes never moved
    // from the last successful stamp (c4: confirmed/human) and the first 24
    // bytes never changed at all.
    let (out, _) = raw_edge_values(vault, &subject)?;
    let out = out.expect("edge");
    assert_eq!((out[24], out[25]), (1, 0));
    assert_eq!(&out[..24], &stamped[..24]);
    Ok(())
}

#[test]
fn provenance_claim_ids_are_write_once_no_closed_claim_resurrection() -> Result<()> {
    let fx = lifecycle_fixture()?;
    let vault = &fx.vault;
    let subject = fx.subject;

    // One claim, then retract it: a CLOSED wrapper is now persisted under
    // claim_id and the edge carries the retracted stamp (3, human = 0).
    let claim_id = EntityId::now();
    vault.put_edge_provenance(
        &claim_id,
        &subject,
        &EdgeProvenanceClaimBody::new(fx.person, 0.75, SupersessionStatus::Confirmed),
        EdgeActorClass::Human,
        1_000,
    )?;
    vault.retract_edge_provenance(&claim_id, 2_000)?;
    let closed_raw = vault.get_raw(&claim_id)?.expect("closed claim raw bytes");
    let (edge_before, edge_before_in) = raw_edge_values(vault, &subject)?;
    let edge_before = edge_before.expect("stamped edge");
    assert_eq!(
        (edge_before[24], edge_before[25]),
        (3, 0),
        "retracted/human stamp before the resurrection attempt"
    );

    // RESURRECTION ATTEMPT (the verifier's shipped-bug repro): re-put the
    // SAME id with a LATER learned_at. Without a write-once gate this
    // overwrites the closed wrapper with a fresh life=active body —
    // bypassing ProvenanceClaimAlreadyClosed and violating ARCH-0003
    // ("claims are never silently deleted"). An implementation that
    // tolerates the overwrite FAILS the expect_err below.
    let err = vault
        .put_edge_provenance(
            &claim_id,
            &subject,
            &EdgeProvenanceClaimBody::new(fx.person, 0.9, SupersessionStatus::Confirmed),
            EdgeActorClass::Human,
            3_000,
        )
        .expect_err("re-putting a retracted claim's id must be rejected");
    assert_eq!(err.kind(), ErrorKind::ProvenanceClaimIdInUse);

    // The closed claim's RAW bytes are untouched (envelope + wrapper +
    // record byte-for-byte) and its lifecycle is still retracted.
    assert_eq!(
        vault.get_raw(&claim_id)?.expect("closed claim survives"),
        closed_raw,
        "a rejected re-put must not touch the closed claim's stored bytes"
    );
    assert_eq!(
        vault.get_claim(&claim_id)?.expect("closed claim").lifecycle,
        ClaimLifecycleStatus::Retracted,
        "the closed claim must NOT come back life=active"
    );

    // The subject edge flags never moved, in BOTH directions.
    let (out, inn) = raw_edge_values(vault, &subject)?;
    assert_eq!(
        out.as_deref(),
        Some(edge_before.as_slice()),
        "edge bytes must be unchanged after the rejected re-put"
    );
    assert_eq!(inn, edge_before_in);

    // supersede_edge_provenance reusing an EXISTING id for its NEW claim is
    // rejected by the same write-once gate — and writes nothing: the live
    // prior stays open.
    let live_prior = EntityId::now();
    vault.put_edge_provenance(
        &live_prior,
        &subject,
        &EdgeProvenanceClaimBody::new(fx.machine, 0.6, SupersessionStatus::Disputed),
        EdgeActorClass::System,
        3_000,
    )?;
    let live_prior_raw = vault.get_raw(&live_prior)?.expect("live prior raw");
    let (edge_live, _) = raw_edge_values(vault, &subject)?;
    let edge_live = edge_live.expect("stamped edge");
    assert_eq!((edge_live[24], edge_live[25]), (2, 2), "disputed/system");
    let err = vault
        .supersede_edge_provenance(
            &live_prior,
            &claim_id,
            &subject,
            &EdgeProvenanceClaimBody::new(fx.person, 0.9, SupersessionStatus::Confirmed),
            EdgeActorClass::Human,
            4_000,
        )
        .expect_err("supersede must not reuse an existing id for its new claim");
    assert_eq!(err.kind(), ErrorKind::ProvenanceClaimIdInUse);
    assert_eq!(
        vault.get_raw(&claim_id)?.expect("closed claim survives"),
        closed_raw
    );
    assert_eq!(
        vault.get_claim(&live_prior)?.expect("prior").lifecycle,
        ClaimLifecycleStatus::Active,
        "a rejected supersede must NOT close the named prior"
    );

    // Write-once also covers a LIVE claim's id: re-putting it (which the
    // live-scan exclusion would otherwise tolerate as an in-place overwrite)
    // is rejected and the stored bytes stay put.
    let err = vault
        .put_edge_provenance(
            &live_prior,
            &subject,
            &EdgeProvenanceClaimBody::new(fx.person, 0.9, SupersessionStatus::Confirmed),
            EdgeActorClass::Human,
            5_000,
        )
        .expect_err("re-putting a LIVE claim's id must be rejected");
    assert_eq!(err.kind(), ErrorKind::ProvenanceClaimIdInUse);
    assert_eq!(
        vault.get_raw(&live_prior)?.expect("live prior survives"),
        live_prior_raw
    );

    // Edge flags through all three rejections: still the live prior's
    // disputed/system stamp, identical bytes both directions.
    let (out, inn) = raw_edge_values(vault, &subject)?;
    let out = out.expect("edge");
    assert_eq!((out[24], out[25]), (2, 2));
    assert_eq!(inn.as_deref(), Some(out.as_slice()));
    Ok(())
}
