//! Claim lifecycle: supersede/retract, temporal rehoming, origin-truth guards.

use super::*;

#[test]
fn put_edge_provenance_atomic_write_restamps_and_indexes() -> Result<()> {
    let (dir, vault) = open_test_vault();
    let actor = EntityId::now();
    let source = EntityId::now();
    let target = EntityId::now();
    vault.put_entity(&actor, 4, test_time_range(1, 1), 1, b"person-actor")?;
    vault.put_entity(&source, 4, test_time_range(1, 1), 1, b"src")?;
    vault.put_entity(&target, 4, test_time_range(1, 1), 1, b"tgt")?;

    let vad = Vad {
        valence: 0.25,
        arousal: 0.5,
        dominance: 0.75,
    };
    vault.put_edge_with_vad(&source, EdgeKind::Mentions, &target, 0.875, vad)?;
    let subject = EdgeRef::new(source, EdgeKind::Mentions, target);

    let (before_out, before_in) = raw_edge_values(&vault, &subject)?;
    let before_out = before_out.expect("subject edge missing");
    assert_eq!(
        before_out.len(),
        EDGE_VALUE_SEMANTIC_LEN,
        "pre-provenance edge must be 24 B"
    );
    assert_eq!(before_in.as_deref(), Some(before_out.as_slice()));

    // Plant malformed PPR cache rows (3 B < header length) keyed to both
    // endpoints so the AC5e invalidation is observable: invalidation
    // DELETES sub-header cache rows.
    let src_hash = [0xAB_u8; 16];
    let tgt_hash = [0xAC_u8; 16];
    {
        let mut wtxn = vault.store.env.write_txn()?;
        let mut src_dep = [0_u8; 32];
        src_dep[..16].copy_from_slice(source.as_bytes());
        src_dep[16..].copy_from_slice(&src_hash);
        let mut tgt_dep = [0_u8; 32];
        tgt_dep[..16].copy_from_slice(target.as_bytes());
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

    let claim_id = EntityId::now();
    let mut body = EdgeProvenanceClaimBody::new(actor, 0.75, SupersessionStatus::Confirmed);
    body.source_revision_ref = Some([0x51; 16]);
    body.body_snapshot_ref = Some([0x52; 16]);
    let learned_at = 1_000_000_u64;
    vault.put_edge_provenance(
        &claim_id,
        &subject,
        &body,
        EdgeActorClass::Human,
        learned_at,
    )?;

    // 26-byte restamp at the pinned offsets, first 24 bytes preserved
    // verbatim, IDENTICAL bytes in BOTH directions (read raw).
    let (after_out, after_in) = raw_edge_values(&vault, &subject)?;
    let after_out = after_out.expect("edges_out row");
    let after_in = after_in.expect("edges_in row");
    assert_eq!(after_out.len(), EDGE_VALUE_SEMANTIC_PROVENANCED_LEN);
    assert_eq!(
        &after_out[..24],
        before_out.as_slice(),
        "weight/created_at/VAD bytes must survive the restamp"
    );
    assert_eq!(after_out[24], 1, "confirmed = 1 at offset 24");
    assert_eq!(after_out[25], 0, "human = 0 at offset 25");
    assert_eq!(
        after_in, after_out,
        "edges_in must mirror edges_out byte-for-byte"
    );

    // PPR caches for both subject-edge endpoints invalidated (AC5e).
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

    // The Claim entity is a type-0 record whose envelope carries the D15
    // open-window sentinels: start = learned_at, end = u64::MAX.
    let raw = vault.get_raw(&claim_id)?.expect("claim entity");
    assert_eq!(raw[0], 0, "claim type byte must be 0");
    assert_eq!(
        u64::from_be_bytes(raw[1..9].try_into().expect("occurred_start")),
        learned_at,
        "absent valid_from must derive occurred.start = learned_at (D15)"
    );
    assert_eq!(
        u64::from_be_bytes(raw[9..17].try_into().expect("occurred_end")),
        u64::MAX,
        "absent valid_to must derive occurred.end = u64::MAX (D15)"
    );

    // claim_of (u8 = 5, structural 12 B) Claim → SOURCE entity (D12), and
    // NOT to the target.
    let rtxn = vault.store.env.read_txn()?;
    let claim_of_src = Store::encode_edge_key(&claim_id, EdgeKind::ClaimOf, &source);
    let claim_of_tgt = Store::encode_edge_key(&claim_id, EdgeKind::ClaimOf, &target);
    let link = vault
        .store
        .edges_out
        .get(&rtxn, &claim_of_src)?
        .expect("claim_of edge to the subject edge's source");
    assert_eq!(link.len(), EDGE_VALUE_STRUCTURAL_LEN);
    // Weight f32 LE @0 = the contract's pinned claim_of pprWeight 1.0
    // (contracts.ts edgeKinds u8 = 5).
    assert_eq!(&link[0..4], &1.0_f32.to_le_bytes());
    assert!(
        vault.store.edges_out.get(&rtxn, &claim_of_tgt)?.is_none(),
        "claim_of must target the SOURCE entity only (D12)"
    );
    drop(rtxn);
    assert_eq!(vault.claims_for_subject(&source)?, vec![claim_id]);

    // The wrapping claim decodes: pinned predicate, EdgeRef subject, the
    // 10-key value record, and the conf mirror. NEW behavior pinned by the
    // ONE-1138 ruling (ONE-1112 C2 relocation): the persisted record carries
    // the validated caller-supplied actor_class as a BODY key, and the
    // wrapper's `evid` stays empty (evidence purity — no legacy map).
    let claim = vault.get_claim(&claim_id)?.expect("claim body");
    assert_eq!(claim.predicate, PREDICATE_EDGE_PROVENANCE);
    assert_eq!(claim.subject, ClaimSubject::from(subject));
    assert_eq!(claim.confidence.to_bits(), 0.75_f32.to_bits());
    assert!(
        claim.evidence.is_none(),
        "post-ONE-1138 writers must leave the wrapper evid empty"
    );
    let value = decode_edge_provenance_body(&claim.value)?;
    let mut expected = body;
    expected.actor_class = Some(EdgeActorClass::Human);
    assert_eq!(value, expected);

    // D15 temporal interplay: the open window indexes occurred_start at
    // learned_at and occurred_end + long_intervals at u64::MAX.
    let rtxn = vault.store.env.read_txn()?;
    let start_key = Store::encode_temporal_key(learned_at, &claim_id);
    let end_key = Store::encode_temporal_key(u64::MAX, &claim_id);
    assert!(
        vault
            .store
            .temporal_occurred_start
            .get(&rtxn, &start_key)?
            .is_some()
    );
    assert!(
        vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &end_key)?
            .is_some()
    );
    let long_row = vault
        .store
        .temporal_long_intervals
        .get(&rtxn, &end_key)?
        .expect("open validity window must index as a long interval");
    assert_eq!(*long_row, learned_at.to_be_bytes());
    drop(rtxn);

    // A SECOND provenance claim restamps only the two flag bytes
    // (disputed = 2, agent = 1); the value stays 26 B with the original
    // 24-byte prefix.
    let claim2 = EntityId::now();
    let body2 = EdgeProvenanceClaimBody::new(actor, 0.5, SupersessionStatus::Disputed);
    vault.put_edge_provenance(
        &claim2,
        &subject,
        &body2,
        EdgeActorClass::Agent,
        learned_at + 1,
    )?;
    let (out2, in2) = raw_edge_values(&vault, &subject)?;
    let out2 = out2.expect("edges_out row");
    assert_eq!(out2.len(), EDGE_VALUE_SEMANTIC_PROVENANCED_LEN);
    assert_eq!(&out2[..24], before_out.as_slice());
    assert_eq!(out2[24], 2, "disputed = 2");
    assert_eq!(out2[25], 1, "agent = 1");
    assert_eq!(in2.as_deref(), Some(out2.as_slice()));

    // The u64::MAX envelope sentinel must not trip the long-interval
    // migration guard at open (store.rs open-gate step 7) — D15's pinned
    // verification.
    drop(vault);
    let reopened = Vault::open(dir.path(), test_config())?;
    assert!(reopened.get_claim(&claim_id)?.is_some());
    Ok(())
}

#[test]
fn put_edge_provenance_explicit_validity_window_maps_envelope() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let actor = EntityId::now();
    let a = EntityId::now();
    let b = EntityId::now();
    vault.put_entity(&actor, 4, test_time_range(1, 1), 1, b"person")?;
    vault.put_entity(&a, 4, test_time_range(1, 1), 1, b"a")?;
    vault.put_entity(&b, 4, test_time_range(1, 1), 1, b"b")?;
    vault.put_edge(&a, EdgeKind::About, &b, 0.5)?;
    let subject = EdgeRef::new(a, EdgeKind::About, b);

    let claim_id = EntityId::now();
    let mut body = EdgeProvenanceClaimBody::new(actor, 0.9, SupersessionStatus::Proposed);
    body.valid_from = Some(100);
    body.valid_to = Some(200);
    vault.put_edge_provenance(&claim_id, &subject, &body, EdgeActorClass::Human, 300)?;

    // Explicit window → envelope copies it verbatim (no sentinels).
    let raw = vault.get_raw(&claim_id)?.expect("claim entity");
    assert_eq!(
        u64::from_be_bytes(raw[1..9].try_into().expect("occurred_start")),
        100
    );
    assert_eq!(
        u64::from_be_bytes(raw[9..17].try_into().expect("occurred_end")),
        200
    );

    // 100-second span: NOT a long interval; closed end indexes normally.
    let rtxn = vault.store.env.read_txn()?;
    let end_key = Store::encode_temporal_key(200, &claim_id);
    assert!(
        vault
            .store
            .temporal_long_intervals
            .get(&rtxn, &end_key)?
            .is_none(),
        "a 100 s window must not index as a long interval"
    );
    assert!(
        vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &end_key)?
            .is_some()
    );
    drop(rtxn);

    // The claim-layer from/to mirrors carry the same window; the 7-field
    // record stays authoritative.
    let claim = vault.get_claim(&claim_id)?.expect("claim body");
    assert_eq!(claim.valid_from, Some(100));
    assert_eq!(claim.valid_to, Some(200));
    let value = decode_edge_provenance_body(&claim.value)?;
    assert_eq!(value.valid_from, Some(100));
    assert_eq!(value.valid_to, Some(200));

    // valid_to earlier than learned_at with absent valid_from would derive
    // an inverted envelope — typed reject, nothing written, never silently
    // reordered.
    let bad_id = EntityId::now();
    let mut bad_body = EdgeProvenanceClaimBody::new(actor, 0.5, SupersessionStatus::Proposed);
    bad_body.valid_to = Some(50);
    let err = vault
        .put_edge_provenance(&bad_id, &subject, &bad_body, EdgeActorClass::Human, 100)
        .expect_err("inverted derived envelope must be rejected");
    assert_eq!(err.kind(), ErrorKind::InvalidProvenanceBody);
    assert_no_entity_state(&vault, &bad_id)?;
    Ok(())
}

#[test]
fn put_edge_provenance_negative_paths_write_nothing() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let person = EntityId::now();
    let machine = EntityId::now();
    let a = EntityId::now();
    let b = EntityId::now();
    vault.put_entity(&person, 4, test_time_range(1, 1), 1, b"person")?;
    vault.put_entity(
        &machine,
        ENTITY_TYPE_MACHINE,
        test_time_range(1, 1),
        1,
        b"machine",
    )?;
    vault.put_entity(&a, 4, test_time_range(1, 1), 1, b"a")?;
    vault.put_entity(&b, 4, test_time_range(1, 1), 1, b"b")?;

    // Structural-kind subject edge (part_of u8 = 2, 12 B) → typed reject
    // even though the edge EXISTS; the edge value is untouched.
    vault.put_edge(&a, EdgeKind::PartOf, &b, 1.0)?;
    let structural = EdgeRef::new(a, EdgeKind::PartOf, b);
    let claim_id = EntityId::now();
    let body = EdgeProvenanceClaimBody::new(person, 0.9, SupersessionStatus::Confirmed);
    let err = vault
        .put_edge_provenance(&claim_id, &structural, &body, EdgeActorClass::Human, 10)
        .expect_err("structural subject kind must be rejected");
    assert_eq!(err.kind(), ErrorKind::ProvenanceOnStructuralEdge);
    assert_no_entity_state(&vault, &claim_id)?;
    let (out, _) = raw_edge_values(&vault, &structural)?;
    assert_eq!(
        out.expect("structural edge").len(),
        EDGE_VALUE_STRUCTURAL_LEN,
        "structural edge must keep its 12 B value"
    );

    // Nonexistent semantic subject edge → EdgeNotFound (NO upsert — the
    // path must never invent weight/created_at).
    let missing = EdgeRef::new(a, EdgeKind::Mentions, b);
    let claim_id = EntityId::now();
    let err = vault
        .put_edge_provenance(&claim_id, &missing, &body, EdgeActorClass::Human, 10)
        .expect_err("missing subject edge must be rejected");
    assert_eq!(err.kind(), ErrorKind::EdgeNotFound);
    assert_no_entity_state(&vault, &claim_id)?;
    let (out, inn) = raw_edge_values(&vault, &missing)?;
    assert_eq!(out, None, "rejection must not upsert the edge");
    assert_eq!(inn, None);

    // From here on the subject edge exists as semantic-bare 24 B.
    vault.put_edge(&a, EdgeKind::Mentions, &b, 0.5)?;
    let subject = EdgeRef::new(a, EdgeKind::Mentions, b);
    let (before, _) = raw_edge_values(&vault, &subject)?;
    let before = before.expect("subject edge");
    assert_eq!(before.len(), EDGE_VALUE_SEMANTIC_LEN);

    // Nonexistent actor entity → typed EntityNotFound; edge untouched.
    let claim_id = EntityId::now();
    let ghost_body =
        EdgeProvenanceClaimBody::new(seeded_entity_id(0xD00D), 0.9, SupersessionStatus::Confirmed);
    let err = vault
        .put_edge_provenance(&claim_id, &subject, &ghost_body, EdgeActorClass::Human, 10)
        .expect_err("missing actor entity must be rejected");
    assert_eq!(err.kind(), ErrorKind::EntityNotFound);
    assert_no_entity_state(&vault, &claim_id)?;
    let (out, _) = raw_edge_values(&vault, &subject)?;
    assert_eq!(out.as_deref(), Some(before.as_slice()));

    // D13 mismatches: PERSON+system, MACHINE+human, MACHINE+agent — each a
    // typed ActorClassMismatch, nothing written, edge untouched in BOTH
    // directions.
    for (actor, class) in [
        (person, EdgeActorClass::System),
        (machine, EdgeActorClass::Human),
        (machine, EdgeActorClass::Agent),
    ] {
        let claim_id = EntityId::now();
        let body = EdgeProvenanceClaimBody::new(actor, 0.9, SupersessionStatus::Confirmed);
        let err = vault
            .put_edge_provenance(&claim_id, &subject, &body, class, 10)
            .expect_err("actor kind/class mismatch must be rejected");
        assert_eq!(err.kind(), ErrorKind::ActorClassMismatch, "class {class:?}");
        assert_no_entity_state(&vault, &claim_id)?;
        let (out, inn) = raw_edge_values(&vault, &subject)?;
        assert_eq!(
            out.as_deref(),
            Some(before.as_slice()),
            "subject edge must be untouched after a rejected write"
        );
        assert_eq!(inn.as_deref(), Some(before.as_slice()));
    }

    // Sanity: the SAME setup succeeds with a compatible pair — proving the
    // rejections above came from the stated violations.
    let ok_id = EntityId::now();
    let ok_body = EdgeProvenanceClaimBody::new(person, 0.9, SupersessionStatus::Confirmed);
    vault.put_edge_provenance(&ok_id, &subject, &ok_body, EdgeActorClass::Human, 10)?;
    Ok(())
}

#[test]
fn decode_edge_value_rejects_out_of_range_flag_bytes() {
    let flags = EdgeProvenanceFlags {
        confirmation_status: EdgeConfirmationStatus::Proposed,
        actor_class: EdgeActorClass::Human,
    };
    let valid = encode_edge_value(EdgeKind::Mentions, 0.5, 1_000, Vad::NEUTRAL, Some(flags))
        .expect("valid 26 B value");
    assert_eq!(valid.len(), EDGE_VALUE_SEMANTIC_PROVENANCED_LEN);

    // confirmation_status admits exactly {0, 1, 2, 3}: 4 is the first
    // invalid byte.
    for bad in [4_u8, 0x7F, 255] {
        let mut value = valid.clone();
        value[24] = bad;
        let err = decode_edge_value(&value).expect_err("confirmation byte > 3 must be rejected");
        assert!(
            matches!(err, Error::CorruptedIndex("edge value")),
            "byte {bad} returned wrong error: {err:?}"
        );
    }
    // actor_class admits exactly {0, 1, 2}: 3 is the first invalid byte.
    for bad in [3_u8, 0x7F, 255] {
        let mut value = valid.clone();
        value[25] = bad;
        let err = decode_edge_value(&value).expect_err("actor byte > 2 must be rejected");
        assert!(
            matches!(err, Error::CorruptedIndex("edge value")),
            "byte {bad} returned wrong error: {err:?}"
        );
    }
}

#[test]
fn supersede_claim_closes_old_writes_edge_and_keeps_history() -> Result<()> {
    const NOW: u64 = 777;

    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    vault.put_entity(&subject, 4, test_time_range(1, 1), 1, b"person")?;
    let old = put_active_claim(&vault, &subject, "profile.lives_in", "osaka", 11)?;
    let new = put_active_claim(&vault, &subject, "profile.lives_in", "tokyo", 22)?;

    vault.supersede_claim(&new, &old, NOW)?;

    // Old body closed: life = superseded, to = now — and the old claim is
    // STILL readable. A purge implementation fails right here.
    let old_read = vault
        .get_claim(&old)?
        .expect("superseded claim must stay readable");
    assert_eq!(old_read.lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(old_read.valid_to, Some(NOW));
    assert!(
        vault.get(&old)?.is_some(),
        "superseded claim record must persist"
    );

    // Envelope occurred_end refreshed to now. Offsets are the pinned
    // 25-byte envelope LITERALS: type u8 @0, occurred_start u64 BE @1..9,
    // occurred_end u64 BE @9..17, learned_at u64 BE @17..25.
    let raw = vault.get_raw(&old)?.ok_or(Error::EntityNotFound)?;
    assert_eq!(raw[0], 0, "type byte must stay CLAIM (0)");
    assert_eq!(
        &raw[1..9],
        &11_u64.to_be_bytes(),
        "occurred_start untouched"
    );
    assert_eq!(&raw[9..17], &NOW.to_be_bytes(), "occurred_end refreshed");
    assert_eq!(&raw[17..25], &11_u64.to_be_bytes(), "learned_at untouched");

    // supersedes edge new → old: discriminant 3, structural 12 B (weight
    // f32 LE @0 = the contract's pinned pprWeight 0.3, created_at u64 LE
    // @4 = now), identical bytes in BOTH directions.
    let key_out = raw_edge_key(&new, 3, &old);
    let key_in = raw_edge_key(&old, 3, &new);
    let rtxn = vault.store.env.read_txn()?;
    let out_value = vault
        .store
        .edges_out
        .get(&rtxn, &key_out)?
        .expect("supersedes edge missing from edges_out")
        .to_vec();
    let in_value = vault
        .store
        .edges_in
        .get(&rtxn, &key_in)?
        .expect("supersedes edge missing from edges_in")
        .to_vec();
    drop(rtxn);
    assert_eq!(out_value.len(), 12, "supersedes must be structural 12 B");
    assert_eq!(out_value, in_value);
    assert_eq!(&out_value[0..4], &0.3_f32.to_le_bytes());
    assert_eq!(&out_value[4..12], &NOW.to_le_bytes());
    assert_eq!(
        vault.targets(&new, EdgeKind::Supersedes, Some(0))?,
        vec![old]
    );

    // The temporal index follows the refreshed envelope end.
    let rtxn = vault.store.env.read_txn()?;
    let end_key = Store::encode_temporal_key(NOW, &old);
    assert!(
        vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &end_key)?
            .is_some(),
        "refreshed occurred_end must be indexed"
    );
    drop(rtxn);

    // The NEW claim is untouched — supersession closes only the old side.
    let new_read = vault.get_claim(&new)?.expect("new claim");
    assert_eq!(new_read.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(new_read.valid_to, None);

    // History stays attached to the subject: BOTH claims remain linked.
    let mut linked = vault.claims_for_subject(&subject)?;
    linked.sort();
    let mut expected = vec![old, new];
    expected.sort();
    assert_eq!(linked, expected, "superseded claim must stay in the graph");
    Ok(())
}

#[test]
fn retract_claim_marks_retracted_and_preserves_record() -> Result<()> {
    const NOW: u64 = 555;

    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    vault.put_entity(&subject, 4, test_time_range(1, 1), 1, b"person")?;
    let claim = put_active_claim(&vault, &subject, "profile.lives_in", "osaka", 11)?;

    vault.retract_claim(&claim, NOW)?;

    let read = vault
        .get_claim(&claim)?
        .expect("retracted claim must stay readable");
    assert_eq!(read.lifecycle, ClaimLifecycleStatus::Retracted);
    assert_eq!(read.valid_to, Some(NOW));

    // Pin the EXACT closed on-disk body: pinned D11 short keys in
    // canonical order with the lifecycle fields stamped — to = now,
    // life = "retracted". A long-key / reordered / purging implementation
    // fails byte equality.
    let raw = vault.get_raw(&claim)?.ok_or(Error::EntityNotFound)?;
    let expected = rmpv_map_bytes(&[
        ("pred".into(), "profile.lives_in".into()),
        ("val".into(), "osaka".into()),
        ("conf".into(), rmpv::Value::F32(0.9)),
        ("to".into(), rmpv::Value::from(NOW)),
        (
            "subj".into(),
            rmpv::Value::Binary(subject.as_bytes().to_vec()),
        ),
        ("appr".into(), "auto".into()),
        ("life".into(), "retracted".into()),
    ]);
    assert_eq!(
        &raw[ENTITY_METADATA_HEADER_LEN..],
        expected.as_slice(),
        "retracted on-disk body drifted from the pinned D11 ABI"
    );

    // Envelope occurred_end refreshed to now; record + index preserved.
    assert_eq!(&raw[9..17], &NOW.to_be_bytes());
    assert!(
        vault.entities_by_type(0)?.contains(&claim),
        "retracted claim must remain type-indexed"
    );
    assert_eq!(vault.claims_for_subject(&subject)?, vec![claim]);
    Ok(())
}

#[test]
fn supersede_claim_moves_temporal_occurred_end_row() -> Result<()> {
    const NOW: u64 = 777;

    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    vault.put_entity(&subject, 4, test_time_range(1, 1), 1, b"person")?;
    let old = put_active_interval_claim(
        &vault,
        &subject,
        "profile.lives_in",
        "osaka",
        test_time_range(11, 50),
        11,
    )?;
    let new = put_active_claim(&vault, &subject, "profile.lives_in", "tokyo", 22)?;

    // Fixture sanity: the interval claim pre-indexes occurred_end at
    // ts = 50, so the absence assertion after the supersede is
    // non-vacuous.
    let stale_end_key = Store::encode_temporal_key(50, &old);
    {
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .temporal_occurred_end
                .get(&rtxn, &stale_end_key)?
                .is_some(),
            "fixture must pre-index occurred_end at ts = 50"
        );
    }

    vault.supersede_claim(&new, &old, NOW)?;

    // The envelope refresh must MOVE the temporal_occurred_end row: the
    // stale ts = 50 row is deleted and the refreshed ts = 777 row is
    // written. An implementation that only hand-adds the new row (never
    // deleting the prior one) fails the first assertion.
    let refreshed_end_key = Store::encode_temporal_key(NOW, &old);
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &stale_end_key)?
            .is_none(),
        "stale occurred_end row at ts = 50 must be deleted by the refresh"
    );
    assert!(
        vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &refreshed_end_key)?
            .is_some(),
        "refreshed occurred_end row at ts = 777 must be indexed"
    );
    drop(rtxn);

    // The transition itself completed (close semantics are pinned in
    // depth by supersede_claim_closes_old_writes_edge_and_keeps_history).
    let old_read = vault.get_claim(&old)?.expect("superseded claim");
    assert_eq!(old_read.lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(old_read.valid_to, Some(NOW));
    Ok(())
}

#[test]
fn retract_claim_moves_temporal_occurred_end_row() -> Result<()> {
    const NOW: u64 = 555;

    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    vault.put_entity(&subject, 4, test_time_range(1, 1), 1, b"person")?;
    let claim = put_active_interval_claim(
        &vault,
        &subject,
        "profile.lives_in",
        "osaka",
        test_time_range(11, 50),
        11,
    )?;

    let stale_end_key = Store::encode_temporal_key(50, &claim);
    {
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault
                .store
                .temporal_occurred_end
                .get(&rtxn, &stale_end_key)?
                .is_some(),
            "fixture must pre-index occurred_end at ts = 50"
        );
    }

    vault.retract_claim(&claim, NOW)?;

    let refreshed_end_key = Store::encode_temporal_key(NOW, &claim);
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &stale_end_key)?
            .is_none(),
        "stale occurred_end row at ts = 50 must be deleted by the refresh"
    );
    assert!(
        vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &refreshed_end_key)?
            .is_some(),
        "refreshed occurred_end row at ts = 555 must be indexed"
    );
    drop(rtxn);

    let read = vault.get_claim(&claim)?.expect("retracted claim");
    assert_eq!(read.lifecycle, ClaimLifecycleStatus::Retracted);
    assert_eq!(read.valid_to, Some(NOW));
    Ok(())
}

#[test]
fn supersede_claim_rehomes_temporal_long_interval_row() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    vault.put_entity(&subject, 4, test_time_range(1, 1), 1, b"person")?;

    // Span > LONG_INTERVAL_THRESHOLD_SECS: the old claim owns a
    // temporal_long_intervals row keyed by occurred_end, value =
    // occurred_start u64 BE.
    let old_end = 1_000 + crate::batch::LONG_INTERVAL_THRESHOLD_SECS + 10;
    let old = put_active_interval_claim(
        &vault,
        &subject,
        "profile.lives_in",
        "osaka",
        test_time_range(1_000, old_end),
        1_000,
    )?;
    let new = put_active_claim(&vault, &subject, "profile.lives_in", "tokyo", 22)?;

    let stale_key = Store::encode_temporal_key(old_end, &old);
    {
        let rtxn = vault.store.env.read_txn()?;
        let value = vault
            .store
            .temporal_long_intervals
            .get(&rtxn, &stale_key)?
            .ok_or(Error::EntityNotFound)?;
        assert_eq!(
            u64::from_be_bytes(value.as_ref().try_into().map_err(|_| Error::InvalidKey)?),
            1_000,
            "fixture must pre-index the long interval (value = occurred_start BE)"
        );
    }

    // `now` keeps the refreshed window long (now − 1 000 > threshold), so
    // the long-interval row must be RE-HOMED: deleted at the stale end
    // key, re-written keyed by the refreshed occurred_end with the same
    // occurred_start value. A refresh that never touches
    // temporal_long_intervals fails both assertions.
    let now = 1_000 + 2 * crate::batch::LONG_INTERVAL_THRESHOLD_SECS;
    vault.supersede_claim(&new, &old, now)?;

    let rehomed_key = Store::encode_temporal_key(now, &old);
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .temporal_long_intervals
            .get(&rtxn, &stale_key)?
            .is_none(),
        "stale long-interval row must be deleted by the refresh"
    );
    let value = vault
        .store
        .temporal_long_intervals
        .get(&rtxn, &rehomed_key)?
        .expect("long-interval row must be re-homed to the refreshed occurred_end");
    assert_eq!(
        u64::from_be_bytes(value.as_ref().try_into().map_err(|_| Error::InvalidKey)?),
        1_000,
        "re-homed long-interval value must keep occurred_start"
    );
    // The occurred_end row moves with it.
    assert!(
        vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &stale_key)?
            .is_none(),
        "stale occurred_end row must be deleted by the refresh"
    );
    assert!(
        vault
            .store
            .temporal_occurred_end
            .get(&rtxn, &rehomed_key)?
            .is_some(),
        "refreshed occurred_end row must be indexed"
    );
    Ok(())
}

#[test]
fn supersede_claim_rejects_self_supersession() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    vault.put_entity(&subject, 4, test_time_range(1, 1), 1, b"person")?;
    let claim = put_active_claim(&vault, &subject, "profile.name", "Alice", 2)?;
    let before = vault.get_raw(&claim)?.expect("claim stored");

    let err = vault
        .supersede_claim(&claim, &claim, 9)
        .expect_err("self-supersession must fail");
    assert_eq!(err.kind(), ErrorKind::ClaimSelfSupersession);

    // Nothing written: body + envelope byte-identical, still active, no
    // supersedes edge (a self-loop edge would betray a partial write).
    assert_eq!(vault.get_raw(&claim)?.expect("still stored"), before);
    assert_eq!(
        vault.get_claim(&claim)?.expect("claim").lifecycle,
        ClaimLifecycleStatus::Active
    );
    assert!(
        vault
            .targets(&claim, EdgeKind::Supersedes, None)?
            .is_empty()
    );
    Ok(())
}

#[test]
fn generated_claim_cannot_supersede_user_stated_non_code_truth() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    vault.put_entity(&subject, 4, test_time_range(1, 1), 1, b"person")?;
    let old = put_active_claim_with_source(
        &vault,
        &subject,
        "profile.lives_in",
        "osaka",
        Some(ClaimSource::UserStated),
        11,
    )?;
    let new = put_active_claim_with_source_and_approval(
        &vault,
        &subject,
        "profile.lives_in",
        "tokyo",
        Some(ClaimSource::Generated),
        ClaimApprovalStatus::Proposed,
        22,
    )?;
    let old_before = vault.get_raw(&old)?.expect("old claim stored");

    let err = vault
        .supersede_claim(&new, &old, 777)
        .expect_err("generated non-code truth must not supersede user-stated truth");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    assert_eq!(
        vault.get_raw(&old)?.expect("old claim still stored"),
        old_before
    );
    assert_eq!(
        vault.get_claim(&old)?.expect("old claim").lifecycle,
        ClaimLifecycleStatus::Active
    );
    assert!(vault.targets(&new, EdgeKind::Supersedes, None)?.is_empty());
    Ok(())
}

#[test]
fn restamped_generated_origin_claim_cannot_supersede_user_stated_truth() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    vault.put_entity(&subject, 4, test_time_range(1, 1), 1, b"person")?;
    let old = put_active_claim_with_source(
        &vault,
        &subject,
        "profile.lives_in",
        "osaka",
        Some(ClaimSource::UserStated),
        11,
    )?;

    let new = EntityId::now();
    let mut new_body = ClaimBody::new(
        "profile.lives_in",
        ClaimSubject::Entity(subject),
        rmpv::Value::from("tokyo"),
        0.9,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    );
    new_body.source = Some(ClaimSource::Imported);
    new_body.scope = Some(rmpv::Value::Map(vec![(
        rmpv::Value::from("federated_original_source"),
        rmpv::Value::from(ClaimSource::Generated.as_str()),
    )]));
    vault.put_claim(&new, &new_body, test_time_range(22, 22), 22)?;
    let old_before = vault.get_raw(&old)?.expect("old claim stored");

    let err = vault
        .supersede_claim(&new, &old, 777)
        .expect_err("restamped generated-origin claim must not supersede user-stated truth");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    assert_eq!(
        vault.get_raw(&old)?.expect("old claim still stored"),
        old_before
    );
    assert_eq!(
        vault.get_claim(&old)?.expect("old claim").lifecycle,
        ClaimLifecycleStatus::Active
    );
    assert!(vault.targets(&new, EdgeKind::Supersedes, None)?.is_empty());
    Ok(())
}

#[test]
fn restamped_generated_origin_claim_cannot_supersede_legacy_unstamped_truth() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    vault.put_entity(&subject, 4, test_time_range(1, 1), 1, b"person")?;
    let old = put_active_claim(&vault, &subject, "profile.lives_in", "osaka", 11)?;
    assert_eq!(
        vault.get_claim(&old)?.expect("old claim").source,
        None,
        "fixture must preserve the legacy missing-src shape"
    );

    let new = EntityId::now();
    let mut new_body = ClaimBody::new(
        "profile.lives_in",
        ClaimSubject::Entity(subject),
        rmpv::Value::from("tokyo"),
        0.9,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    );
    new_body.source = Some(ClaimSource::Imported);
    new_body.scope = Some(rmpv::Value::Map(vec![(
        rmpv::Value::from("federated_original_source"),
        rmpv::Value::from(ClaimSource::Generated.as_str()),
    )]));
    vault.put_claim(&new, &new_body, test_time_range(22, 22), 22)?;
    let old_before = vault.get_raw(&old)?.expect("old claim stored");

    let err = vault
        .supersede_claim(&new, &old, 777)
        .expect_err("restamped generated-origin claim must not supersede legacy missing-src truth");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    assert_eq!(
        vault.get_raw(&old)?.expect("old claim still stored"),
        old_before
    );
    assert_eq!(
        vault.get_claim(&old)?.expect("old claim").lifecycle,
        ClaimLifecycleStatus::Active
    );
    assert!(vault.targets(&new, EdgeKind::Supersedes, None)?.is_empty());
    Ok(())
}

#[test]
fn claim_lifecycle_ops_reject_non_claims_and_missing_ids() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    vault.put_entity(&subject, 4, test_time_range(1, 1), 1, b"person")?;
    let claim = put_active_claim(&vault, &subject, "profile.name", "Alice", 2)?;
    let before = vault.get_raw(&claim)?.expect("claim stored");

    // Non-claim id in either position → typed InvalidClaimBody.
    let err = vault
        .supersede_claim(&claim, &subject, 9)
        .expect_err("old = PERSON must fail typed");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    let err = vault
        .supersede_claim(&subject, &claim, 9)
        .expect_err("new = PERSON must fail typed");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    let err = vault
        .retract_claim(&subject, 9)
        .expect_err("retracting a PERSON must fail typed");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);

    // Missing id in either position → typed EntityNotFound.
    let ghost = seeded_entity_id(0x1108);
    let err = vault
        .supersede_claim(&ghost, &claim, 9)
        .expect_err("missing new id must fail typed");
    assert_eq!(err.kind(), ErrorKind::EntityNotFound);
    let err = vault
        .supersede_claim(&claim, &ghost, 9)
        .expect_err("missing old id must fail typed");
    assert_eq!(err.kind(), ErrorKind::EntityNotFound);
    let err = vault
        .retract_claim(&ghost, 9)
        .expect_err("retracting a missing id must fail typed");
    assert_eq!(err.kind(), ErrorKind::EntityNotFound);

    // Nothing was written by any failed attempt.
    assert_eq!(vault.get_raw(&claim)?.expect("still stored"), before);
    assert_eq!(
        vault.get_claim(&claim)?.expect("claim").lifecycle,
        ClaimLifecycleStatus::Active
    );
    assert!(
        vault
            .targets(&claim, EdgeKind::Supersedes, None)?
            .is_empty()
    );
    assert!(
        vault
            .targets(&subject, EdgeKind::Supersedes, None)?
            .is_empty()
    );
    assert_no_entity_state(&vault, &ghost)?;
    Ok(())
}

#[test]
fn claim_lifecycle_ops_reject_already_closed_claims() -> Result<()> {
    const T1: u64 = 100;
    const T2: u64 = 200;

    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    vault.put_entity(&subject, 4, test_time_range(1, 1), 1, b"person")?;
    let a = put_active_claim(&vault, &subject, "profile.lives_in", "osaka", 2)?;
    let b = put_active_claim(&vault, &subject, "profile.lives_in", "tokyo", 3)?;
    let c = put_active_claim(&vault, &subject, "profile.lives_in", "kyoto", 4)?;

    vault.supersede_claim(&b, &a, T1)?;

    // Superseding an already-superseded claim → the NAMED-TARGET refusal
    // (ONE-1936): closed history still never transitions again, but a caller
    // who named a replaced head gets the concurrency answer — the current
    // head's public ref — rather than the bare mechanical rejection. The
    // FIRST close timestamp must survive (T1, not T2).
    let err = vault
        .supersede_claim(&c, &a, T2)
        .expect_err("a is closed history");
    assert_eq!(err.kind(), ErrorKind::WriteVerbTargetStale);
    assert_matches!(
        err,
        Error::WriteVerbTargetStale {
            lifecycle: ClaimLifecycleStatus::Superseded,
            ..
        }
    );
    let a_read = vault.get_claim(&a)?.expect("a");
    assert_eq!(
        a_read.valid_to,
        Some(T1),
        "failed supersede must not restamp `to`"
    );
    // …and the failed attempt wrote no c → a edge.
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .edges_out
            .get(&rtxn, &raw_edge_key(&c, 3, &a))?
            .is_none(),
        "failed supersede must not write a supersedes edge"
    );
    drop(rtxn);

    // Retracting a superseded claim → the same named-target refusal.
    let err = vault
        .retract_claim(&a, T2)
        .expect_err("retracting superseded must fail typed");
    assert_eq!(err.kind(), ErrorKind::WriteVerbTargetStale);

    // Double retract → named-target refusal; the first timestamp survives.
    vault.retract_claim(&c, T1)?;
    let err = vault
        .retract_claim(&c, T2)
        .expect_err("double retract must fail typed");
    assert_eq!(err.kind(), ErrorKind::WriteVerbTargetStale);
    assert_matches!(
        err,
        Error::WriteVerbTargetStale {
            lifecycle: ClaimLifecycleStatus::Retracted,
            ..
        }
    );
    assert_eq!(vault.get_claim(&c)?.expect("c").valid_to, Some(T1));

    // Superseding a retracted claim → named-target refusal.
    let err = vault
        .supersede_claim(&b, &c, T2)
        .expect_err("superseding retracted must fail typed");
    assert_eq!(err.kind(), ErrorKind::WriteVerbTargetStale);

    // A closed claim cannot be the SUPERSEDING side either (fail-closed): the
    // new claim must itself be active. This side is NOT a named lifecycle
    // target — it is the replacement the caller is offering — so it keeps the
    // mechanical already-closed rejection.
    let d = put_active_claim(&vault, &subject, "profile.lives_in", "nara", 5)?;
    let err = vault
        .supersede_claim(&a, &d, T2)
        .expect_err("closed new side must fail typed");
    assert_eq!(err.kind(), ErrorKind::ClaimAlreadyClosed);
    assert_eq!(
        vault.get_claim(&d)?.expect("d").lifecycle,
        ClaimLifecycleStatus::Active
    );
    Ok(())
}

#[test]
fn claim_lifecycle_ops_reject_provenance_claims_toward_provenance_api() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let a = EntityId::now();
    let b = EntityId::now();
    vault.put_entity(&a, 4, test_time_range(1, 1), 1, b"a")?;
    vault.put_entity(&b, 4, test_time_range(1, 1), 1, b"b")?;

    // An edge.provenance Claim written through the pub(crate) reserved-
    // namespace door (the provenance unit's path).
    let prov = EntityId::now();
    // Structurally valid since ONE-1159 (the reserved door validates the
    // provenance value record + actor-class evidence).
    let prov_body = valid_provenance_claim_body(a, a, b);
    let prov_bytes = crate::claim::encode_claim_body(&prov_body)?;
    vault.with_write_txn(|wtxn| {
        vault
            .batch_in()
            .put_reserved_claim(&prov, test_time_range(1, 1), 2, &prov_bytes)
            .apply(wtxn)
    })?;
    let normal = put_active_claim(&vault, &a, "profile.name", "Alice", 2)?;
    let prov_before = vault.get_raw(&prov)?.expect("prov stored");
    let normal_before = vault.get_raw(&normal)?.expect("normal stored");

    // The generic ops must NOT bypass the edge-restamp lifecycle (M2-9):
    // provenance-predicate claims are rejected typed in EVERY position.
    let err = vault
        .retract_claim(&prov, 9)
        .expect_err("retracting an edge.provenance claim must fail typed");
    assert_eq!(err.kind(), ErrorKind::ProvenanceClaimLifecycle);

    let err = vault
        .supersede_claim(&normal, &prov, 9)
        .expect_err("old = provenance claim must fail typed");
    assert_eq!(err.kind(), ErrorKind::ProvenanceClaimLifecycle);
    let err = vault
        .supersede_claim(&prov, &normal, 9)
        .expect_err("new = provenance claim must fail typed");
    assert_eq!(err.kind(), ErrorKind::ProvenanceClaimLifecycle);

    // Nothing was written: bodies + envelopes byte-identical, lifecycle
    // untouched, no supersedes edges anywhere.
    assert_eq!(vault.get_raw(&prov)?.expect("prov"), prov_before);
    assert_eq!(vault.get_raw(&normal)?.expect("normal"), normal_before);
    assert_eq!(
        vault.get_claim(&prov)?.expect("prov").lifecycle,
        ClaimLifecycleStatus::Active
    );
    assert!(vault.targets(&prov, EdgeKind::Supersedes, None)?.is_empty());
    assert!(
        vault
            .targets(&normal, EdgeKind::Supersedes, None)?
            .is_empty()
    );
    Ok(())
}
