//! Claim bodies, roles, typed validation matrix, public vs replicated doors.

use super::*;
use crate::error::RecordError;

#[test]
fn context_pack_run_serialized_toon_end_to_end() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let a = EntityId::now();
    let b = EntityId::now();
    let claim_subject = seeded_entity_id(0xC1A1);

    let payload_a = valid_claim_body_bytes("goal.learning", "Learn Japanese by June");
    let payload_b = rmp_serde::to_vec_named(&serde_json::json!({ "name": "Alice" }))
        .map_err(|_| Error::InvalidKey)?;

    vault
        .batch()
        .put(&claim_subject, 4, test_time_range(99, 99), 100, b"subject")
        .put(&a, 0, test_time_range(100, 100), 101, &payload_a)
        .text(&a, &[("body", "learn japanese")])
        .put(&b, 4, test_time_range(102, 102), 103, &payload_b)
        .edge(&a, EdgeKind::Mentions, &b, 1.0)
        .commit()?;

    let output = vault
        .context_pack()
        .search_text("japanese", 10)
        .edge_hop(1)
        .format(PackFormat::Toon)
        .run_serialized()?;
    assert!(!output.is_empty());

    let text = String::from_utf8(output).map_err(|_| Error::InvalidKey)?;
    assert!(text.contains("claims"));
    Ok(())
}

#[test]
fn claim_body_keys_pin_d11_vocabulary() {
    // The pinned ON-DISK key set, literal (D11). A renamed, reordered, or
    // re-cased vocabulary must fail here.
    assert_eq!(
        CLAIM_BODY_KEYS,
        [
            "pred", "val", "conf", "sal", "evid", "from", "to", "src", "world", "rel", "subj",
            "scope", "appr", "life", "stale", "sess",
        ]
    );
    // fusion.rs consumes the SAME constants — pinned to the short keys.
    assert_eq!(crate::claim::KEY_SAL, "sal");
    assert_eq!(crate::claim::KEY_CONF, "conf");
    // Context-pack profiles are prefixes of the pinned set.
    assert_eq!(crate::claim::CLAIM_FIELDS_MINIMAL, ["pred", "val"]);
    assert_eq!(
        crate::claim::CLAIM_FIELDS_STANDARD,
        ["pred", "val", "conf", "sal", "evid"]
    );
    assert_eq!(
        crate::claim::CLAIM_FIELDS_FULL,
        [
            "pred", "val", "conf", "sal", "evid", "from", "to", "src", "world", "rel", "subj",
            "scope"
        ]
    );
}

#[test]
fn stored_claim_body_serves_fusion_signals_and_context_pack_profiles() -> Result<()> {
    // The `learned_at` every claim below is written at, and the frozen run
    // clock every scoring query below reads under.
    //
    // ONE-1402 multiplies a read-side decay factor onto the fused score, so
    // on an unpinned wall clock these epoch-second claims would age by
    // decades and each exact expectation here would silently become
    // `blend * ACCESS_FACTOR_FLOOR`. Freezing the clock at the fixture's own
    // `learned_at` gives age `0` and factor `2^0 = 1.0` exactly, keeping the
    // assertions below a pure `sal`/`conf` KEY contract instead of a decay
    // one (decay's own arithmetic is pinned in `claim::tests` and
    // `pipeline::decay_tests`).
    const CLAIM_LEARNED_AT: u64 = 11;
    fn z_score(value: f32, values: &[f32]) -> f32 {
        let mean = values.iter().map(|value| f64::from(*value)).sum::<f64>() / values.len() as f64;
        let variance = values
            .iter()
            .map(|candidate| {
                let delta = f64::from(*candidate) - mean;
                delta * delta
            })
            .sum::<f64>()
            / values.len() as f64;
        ((f64::from(value) - mean) / variance.sqrt()) as f32
    }

    fn score_for(scores: &[ScoredEntity], id: EntityId) -> f32 {
        scores
            .iter()
            .find(|scored| scored.id == id)
            .expect("expected scored entity")
            .score
    }

    // ONE body written through put_claim must BOTH feed the retrieval blend
    // signals (sal/conf short keys) AND project through the context-pack CLAIM
    // field profiles — the pre-fix engine read "salience"/"confidence" in
    // fusion and "sal"/"conf" in profiles, so no single body could do both.
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    vault.put_entity(&subject, 4, test_time_range(1, 1), 1, b"person")?;

    let claim = EntityId::now();
    let mut body = ClaimBody::new(
        "preference.food",
        ClaimSubject::Entity(subject),
        rmpv::Value::from("matcha"),
        0.1,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.salience = Some(0.9);
    vault.put_claim(&claim, &body, test_time_range(10, 10), CLAIM_LEARNED_AT)?;

    let other_claim = EntityId::now();
    let mut other_body = ClaimBody::new(
        "preference.food",
        ClaimSubject::Entity(subject),
        rmpv::Value::from("matcha"),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    other_body.salience = Some(0.3);
    vault.put_claim(
        &other_claim,
        &other_body,
        test_time_range(10, 10),
        CLAIM_LEARNED_AT,
    )?;

    let third_claim = EntityId::now();
    let mut third_body = ClaimBody::new(
        "preference.food",
        ClaimSubject::Entity(subject),
        rmpv::Value::from("matcha"),
        0.4,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    third_body.salience = Some(0.0);
    vault.put_claim(
        &third_claim,
        &third_body,
        test_time_range(10, 10),
        CLAIM_LEARNED_AT,
    )?;
    vault
        .batch()
        .text(&claim, &[("body", "matcha preference")])
        .text(&other_claim, &[("body", "matcha preference")])
        .text(&third_claim, &[("body", "matcha preference")])
        .commit()?;

    let baseline = vault
        .query()
        .search_text("matcha", 10)
        .with_temporal_now(CLAIM_LEARNED_AT)
        .run()?;
    assert_eq!(baseline.len(), 3);

    let sal_boosted = vault
        .query()
        .search_text("matcha", 10)
        .with_temporal_now(CLAIM_LEARNED_AT)
        .boost_salience()
        .run()?;
    assert_eq!(sal_boosted.len(), 3);
    assert_eq!(sal_boosted[0].id, claim);
    let expected_salience_score = (0.30_f32 * z_score(0.9, &[0.9, 0.3, 0.0])).exp();
    assert!(
        (score_for(&sal_boosted, claim) - expected_salience_score).abs() < 1e-6,
        "salience blend must read the pinned `sal` key"
    );

    let conf_boosted = vault
        .query()
        .search_text("matcha", 10)
        .with_temporal_now(CLAIM_LEARNED_AT)
        .boost_confidence()
        .run()?;
    assert_eq!(conf_boosted.len(), 3);
    assert_eq!(conf_boosted[0].id, other_claim);
    let expected_confidence_score = (0.20_f32 * z_score(0.9, &[0.1, 0.9, 0.4])).exp();
    assert!(
        (score_for(&conf_boosted, other_claim) - expected_confidence_score).abs() < 1e-6,
        "confidence blend must read the pinned `conf` key"
    );

    // The SAME stored body projects through the CLAIM Full profile.
    let full = vault
        .context_pack()
        .search_text("matcha", 10)
        .field_profile(FieldProfile::Full)
        .format(PackFormat::Json)
        .run_serialized()?;
    let full = String::from_utf8(full).map_err(|_| Error::InvalidKey)?;
    assert!(full.contains("\"pred\""), "Full profile must surface pred");
    assert!(full.contains("preference.food"));
    assert!(full.contains("\"conf\""), "Full profile must surface conf");
    assert!(full.contains("\"sal\""), "Full profile must surface sal");

    // Minimal profile allowlists pred/val only.
    let minimal = vault
        .context_pack()
        .search_text("matcha", 10)
        .field_profile(FieldProfile::Minimal)
        .format(PackFormat::Json)
        .run_serialized()?;
    let minimal = String::from_utf8(minimal).map_err(|_| Error::InvalidKey)?;
    assert!(minimal.contains("\"pred\""));
    assert!(!minimal.contains("\"sal\""), "Minimal must not surface sal");
    assert!(
        !minimal.contains("\"conf\""),
        "Minimal must not surface conf"
    );
    Ok(())
}

#[test]
fn put_claim_round_trip_and_pinned_on_disk_bytes() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    vault.put_entity(&subject, 4, test_time_range(1, 1), 1, b"person")?;

    let claim = EntityId::now();
    let mut body = ClaimBody::new(
        "profile.lives_in",
        ClaimSubject::Entity(subject),
        rmpv::Value::from("tokyo"),
        0.75,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    );
    body.salience = Some(0.25);
    body.evidence = Some(rmpv::Value::Array(vec!["tn1".into()]));
    body.valid_from = Some(100);
    body.valid_to = Some(200);
    body.source = Some(ClaimSource::UserStated);
    let world_id = EntityId::from_bytes([0x5A; 16])?;
    body.world = Some(world_id);
    body.scope = Some("rel1".into());
    body.stale = true;
    vault.put_claim(&claim, &body, test_time_range(100, 200), 300)?;

    // Pin the EXACT on-disk bytes: pinned short keys, canonical order. The
    // expected map is built with LITERAL key strings so an encoder writing
    // camelCase keys, long names, or a different order fails byte equality.
    let raw = vault.get_raw(&claim)?.ok_or(Error::EntityNotFound)?;
    let expected = rmpv_map_bytes(&[
        ("pred".into(), "profile.lives_in".into()),
        ("val".into(), "tokyo".into()),
        ("conf".into(), rmpv::Value::F32(0.75)),
        ("sal".into(), rmpv::Value::F32(0.25)),
        ("evid".into(), rmpv::Value::Array(vec!["tn1".into()])),
        ("from".into(), rmpv::Value::from(100_u64)),
        ("to".into(), rmpv::Value::from(200_u64)),
        ("src".into(), "user_stated".into()),
        (
            "world".into(),
            rmpv::Value::Binary(world_id.as_bytes().to_vec()),
        ),
        (
            "subj".into(),
            rmpv::Value::Binary(subject.as_bytes().to_vec()),
        ),
        ("scope".into(), "rel1".into()),
        ("appr".into(), "proposed".into()),
        ("life".into(), "active".into()),
        ("stale".into(), rmpv::Value::Boolean(true)),
    ]);
    assert_eq!(
        &raw[ENTITY_METADATA_HEADER_LEN..],
        expected.as_slice(),
        "on-disk claim body bytes drifted from the pinned D11 ABI"
    );

    let read = vault.get_claim(&claim)?.expect("claim must decode");
    assert_eq!(read, body);

    // Minimal claim: optionals absent, stale defaults to false on decode.
    let minimal_id = EntityId::now();
    let minimal = ClaimBody::new(
        "profile.name",
        ClaimSubject::Entity(subject),
        rmpv::Value::from("Alice"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    vault.put_claim(&minimal_id, &minimal, test_time_range(1, 1), 2)?;
    let read = vault.get_claim(&minimal_id)?.expect("minimal claim");
    assert!(!read.stale, "absent stale must decode to false");
    assert_eq!(read.salience, None);
    assert_eq!(read.source, None);
    assert_eq!(read.valid_from, None);
    assert_eq!(read.valid_to, None);

    // The minimal body must NOT contain a stale key on disk (default elided).
    let raw = vault.get_raw(&minimal_id)?.ok_or(Error::EntityNotFound)?;
    assert!(
        !slice_contains(&raw[ENTITY_METADATA_HEADER_LEN..], b"stale"),
        "stale=false must be elided from the stored body"
    );

    // Claims carry the pinned 'cl' short-id prefix. The lookup is
    // intentionally schema-agnostic (see find_short_id_any_schema): the
    // parallel ONE-1102 branch flips the short_ids key direction per the
    // pinned manifest, and this assertion must hold on this branch
    // standalone AND after ONE-1102 merges.
    let short_id = find_short_id_any_schema(&vault, &claim)?
        .expect("claim short id missing from both short-id DBs");
    assert!(
        short_id.starts_with("cl"),
        "CLAIM short-id prefix must be 'cl', got {short_id}"
    );
    let counter = &short_id[2..];
    assert!(
        !counter.is_empty() && counter.bytes().all(|b| b.is_ascii_digit()),
        "CLAIM short id must be 'cl' + decimal counter, got {short_id}"
    );
    Ok(())
}

#[test]
fn put_claim_writes_claim_of_edge_atomically() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    vault.put_entity(&subject, 4, test_time_range(1, 1), 1, b"person")?;

    let claim = EntityId::now();
    let body = ClaimBody::new(
        "profile.name",
        ClaimSubject::Entity(subject),
        rmpv::Value::from("Alice"),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    vault.put_claim(&claim, &body, test_time_range(1, 1), 2)?;

    // claim_of (u8 = 5) Claim → subject, structural 12-byte value, present
    // in BOTH edge directions with identical bytes.
    let key_out = Store::encode_edge_key(&claim, EdgeKind::ClaimOf, &subject);
    let key_in = Store::encode_edge_key(&subject, EdgeKind::ClaimOf, &claim);
    assert_eq!(key_out[16], 5, "claim_of discriminant must be 5");
    let rtxn = vault.store.env.read_txn()?;
    let out_value = vault
        .store
        .edges_out
        .get(&rtxn, &key_out)?
        .expect("claim_of edge missing from edges_out");
    let in_value = vault
        .store
        .edges_in
        .get(&rtxn, &key_in)?
        .expect("claim_of edge missing from edges_in");
    assert_eq!(out_value.len(), 12, "claim_of must be structural 12 B");
    assert_eq!(out_value, in_value);
    // Weight f32 LE @0 = the contract's pinned claim_of pprWeight 1.0
    // (contracts.ts edgeKinds u8 = 5).
    assert_eq!(&out_value[0..4], &1.0_f32.to_le_bytes());
    drop(rtxn);

    // claims_for_subject = sources(ClaimOf, Some(0)).
    assert_eq!(vault.claims_for_subject(&subject)?, vec![claim]);

    // Nonexistent subject → typed reject, NOTHING written (no entity, no
    // claim_of rows, no index rows).
    let ghost = seeded_entity_id(0xDEAD);
    let orphan = EntityId::now();
    let body = ClaimBody::new(
        "profile.name",
        ClaimSubject::Entity(ghost),
        rmpv::Value::from("Bob"),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    let err = vault
        .put_claim(&orphan, &body, test_time_range(1, 1), 2)
        .expect_err("nonexistent subject must be rejected");
    assert_eq!(err.kind(), ErrorKind::EntityNotFound);
    assert_no_entity_state(&vault, &orphan)?;
    assert!(vault.claims_for_subject(&ghost)?.is_empty());
    Ok(())
}

#[test]
fn put_claim_edge_ref_subject_validates_shape_without_claim_of() -> Result<()> {
    // An EdgeRef subject is shape-validated and stored, but claim_of wiring
    // for edge subjects belongs to the provenance path — no edge is written.
    let (_dir, vault) = open_test_vault();
    let a = EntityId::now();
    let b = EntityId::now();
    vault.put_entity(&a, 4, test_time_range(1, 1), 1, b"a")?;
    vault.put_entity(&b, 4, test_time_range(1, 1), 1, b"b")?;

    let claim = EntityId::now();
    let body = ClaimBody::new(
        "graph.observation",
        ClaimSubject::Edge {
            source: a,
            kind: EdgeKind::Supports,
            target: b,
        },
        rmpv::Value::from("noted"),
        0.5,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    vault.put_claim(&claim, &body, test_time_range(1, 1), 2)?;

    let read = vault.get_claim(&claim)?.expect("edge-subject claim");
    assert_eq!(
        read.subject,
        ClaimSubject::Edge {
            source: a,
            kind: EdgeKind::Supports,
            target: b,
        }
    );
    assert!(
        vault.edges_out(&claim)?.is_empty(),
        "EdgeRef-subject put_claim must not write claim_of edges"
    );
    Ok(())
}

#[test]
fn type0_validation_guards_every_write_path() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let garbage: &[u8] = b"definitely not msgpack";

    // Path 1: Vault::put_entity.
    let id = EntityId::now();
    let err = vault
        .put_entity(&id, 0, test_time_range(1, 1), 1, garbage)
        .expect_err("raw put_entity must validate type-0 bodies");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    assert_no_entity_state(&vault, &id)?;

    // Path 2: BatchBuilder::put → commit.
    let id = EntityId::now();
    let err = vault
        .batch()
        .put(&id, 0, test_time_range(1, 1), 1, garbage)
        .commit()
        .expect_err("BatchBuilder must validate type-0 bodies");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    assert_no_entity_state(&vault, &id)?;

    // Path 3: TxnBatchBuilder::apply (the sync-replay path) — the failed
    // transaction is dropped without commit, so nothing lands.
    let id = EntityId::now();
    let err = vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .put(&id, 0, test_time_range(1, 1), 1, garbage)
                .apply(wtxn)
        })
        .expect_err("TxnBatchBuilder must validate type-0 bodies");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    assert_no_entity_state(&vault, &id)?;

    // A structurally VALID legacy claim body with no caller-supplied source
    // remains a raw compatibility case.
    let id = EntityId::now();
    vault.put_entity(
        &id,
        0,
        test_time_range(1, 1),
        1,
        &valid_claim_body_bytes("profile.name", "Alice"),
    )?;
    assert!(vault.get_claim(&id)?.is_some());

    // Bodies of non-schema-bearing types stay OPAQUE: the same garbage commits
    // fine and round-trips byte-for-byte.
    let id = EntityId::now();
    vault.put_entity(&id, 1, test_time_range(1, 1), 1, garbage)?;
    assert_eq!(vault.get(&id)?.as_deref(), Some(garbage));
    Ok(())
}

#[test]
fn each_role_validates() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    for role in TaskRole::ALL {
        let id = EntityId::now();
        let body = task_body(role);
        vault.put_entity(
            &id,
            ENTITY_TYPE_TASK,
            test_time_range(u64::from(role.role_byte()), u64::from(role.role_byte())),
            u64::from(role.role_byte()),
            &body,
        )?;
        // STO-03: a Habit row carries the two DERIVED counters, appended by
        // the recompute tail out of its (here empty) check-in child set. Every
        // other role round-trips byte-exact and never gains a streak key.
        let expected = if role == TaskRole::Habit {
            rmpv_map_bytes(&[
                ("role".into(), role.role_byte().into()),
                ("currentStreak".into(), 0_u32.into()),
                ("longestStreak".into(), 0_u32.into()),
            ])
        } else {
            body
        };
        assert_eq!(vault.get(&id)?, Some(expected));
        assert_eq!(TaskRole::from_role_byte(role.role_byte()), Some(role));
    }

    Ok(())
}

#[test]
fn unset_or_unknown_role_rejected_typed() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let trailing = {
        let mut bytes = task_body(TaskRole::Task);
        bytes.push(0xC0);
        bytes
    };
    let cases = [
        (
            "absent",
            rmpv_map_bytes(&[("title".into(), "no-role".into())]),
        ),
        ("zero", rmpv_map_bytes(&[("role".into(), 0_u8.into())])),
        ("unknown", rmpv_map_bytes(&[("role".into(), 6_u8.into())])),
        (
            "not a byte",
            rmpv_map_bytes(&[("role".into(), 256_u64.into())]),
        ),
        ("trailing", trailing),
    ];

    for (name, body) in cases {
        let id = EntityId::now();
        let err = vault
            .put_entity(&id, ENTITY_TYPE_TASK, test_time_range(1, 1), 1, &body)
            .expect_err(name);
        assert_eq!(err.kind(), ErrorKind::InvalidTaskBody, "{name}");
        assert_matches!(err, Error::Record(RecordError::InvalidTaskBody(_)));
        assert_no_entity_state(&vault, &id)?;
    }

    Ok(())
}

#[test]
fn claim_negative_matrix_rejects_typed_and_writes_nothing() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subj_bytes = seeded_entity_id(0xAA01).as_bytes().to_vec();
    let base = base_claim_entries("profile.name", subj_bytes.clone());

    let valid_map_plus_trailing = {
        let mut bytes = rmpv_map_bytes(&base);
        bytes.push(0xC0);
        bytes
    };

    let cases: Vec<(&str, Vec<u8>, ErrorKind)> = vec![
        (
            "garbage bytes",
            b"\xFF\xFF\xFF garbage".to_vec(),
            ErrorKind::InvalidClaimBody,
        ),
        ("empty body", Vec::new(), ErrorKind::InvalidClaimBody),
        (
            "non-map body",
            {
                let mut out = Vec::new();
                rmpv::encode::write_value(&mut out, &rmpv::Value::from("just a string"))
                    .expect("encode");
                out
            },
            ErrorKind::InvalidClaimBody,
        ),
        (
            "trailing bytes",
            valid_map_plus_trailing,
            ErrorKind::InvalidClaimBody,
        ),
        (
            "missing pred",
            rmpv_map_bytes(&entries_without(&base, "pred")),
            ErrorKind::InvalidClaimBody,
        ),
        (
            "missing subj",
            rmpv_map_bytes(&entries_without(&base, "subj")),
            ErrorKind::InvalidClaimBody,
        ),
        (
            "missing val",
            rmpv_map_bytes(&entries_without(&base, "val")),
            ErrorKind::InvalidClaimBody,
        ),
        (
            "missing conf",
            rmpv_map_bytes(&entries_without(&base, "conf")),
            ErrorKind::InvalidClaimBody,
        ),
        (
            "missing appr",
            rmpv_map_bytes(&entries_without(&base, "appr")),
            ErrorKind::InvalidClaimBody,
        ),
        (
            "missing life",
            rmpv_map_bytes(&entries_without(&base, "life")),
            ErrorKind::InvalidClaimBody,
        ),
        (
            "conf NaN",
            rmpv_map_bytes(&entries_replacing(
                &base,
                "conf",
                rmpv::Value::F32(f32::NAN),
            )),
            ErrorKind::InvalidClaimBody,
        ),
        (
            "conf -0.1",
            rmpv_map_bytes(&entries_replacing(&base, "conf", rmpv::Value::F64(-0.1))),
            ErrorKind::InvalidClaimBody,
        ),
        (
            "conf 1.1",
            rmpv_map_bytes(&entries_replacing(&base, "conf", rmpv::Value::F64(1.1))),
            ErrorKind::InvalidClaimBody,
        ),
        (
            "appr unknown enum",
            rmpv_map_bytes(&entries_replacing(&base, "appr", "maybe".into())),
            ErrorKind::InvalidClaimBody,
        ),
        (
            "life unknown enum",
            rmpv_map_bytes(&entries_replacing(&base, "life", "zombie".into())),
            ErrorKind::InvalidClaimBody,
        ),
        (
            "src unknown enum",
            {
                let mut entries = base.clone();
                entries.push(("src".into(), "psychic".into()));
                rmpv_map_bytes(&entries)
            },
            ErrorKind::InvalidClaimBody,
        ),
        (
            "sal out of range",
            {
                let mut entries = base.clone();
                entries.push(("sal".into(), rmpv::Value::F64(1.5)));
                rmpv_map_bytes(&entries)
            },
            ErrorKind::InvalidClaimBody,
        ),
        (
            "subj 17 bytes",
            rmpv_map_bytes(&entries_replacing(
                &base,
                "subj",
                rmpv::Value::Binary(vec![0x44; 17]),
            )),
            ErrorKind::InvalidClaimBody,
        ),
        (
            "subj not binary",
            rmpv_map_bytes(&entries_replacing(&base, "subj", "stringy".into())),
            ErrorKind::InvalidClaimBody,
        ),
        (
            "stale not boolean",
            {
                let mut entries = base.clone();
                entries.push(("stale".into(), rmpv::Value::from(1_u64)));
                rmpv_map_bytes(&entries)
            },
            ErrorKind::InvalidClaimBody,
        ),
        (
            "unknown camelCase key",
            {
                let mut entries = base.clone();
                entries.push(("valueKey".into(), "s:x".into()));
                rmpv_map_bytes(&entries)
            },
            ErrorKind::InvalidClaimBody,
        ),
        (
            "duplicate key",
            {
                let mut entries = base.clone();
                entries.push(("pred".into(), "profile.other".into()));
                rmpv_map_bytes(&entries)
            },
            ErrorKind::InvalidClaimBody,
        ),
        (
            "uppercase predicate Edge.Provenance",
            rmpv_map_bytes(&base_claim_entries("Edge.Provenance", subj_bytes.clone())),
            ErrorKind::InvalidPredicate,
        ),
        (
            "single-segment predicate profile",
            rmpv_map_bytes(&base_claim_entries("profile", subj_bytes.clone())),
            ErrorKind::InvalidPredicate,
        ),
        (
            "reserved edge.provenance via public path",
            rmpv_map_bytes(&base_claim_entries("edge.provenance", subj_bytes)),
            ErrorKind::ReservedPredicate,
        ),
    ];

    for (name, bytes, expected_kind) in cases {
        let id = EntityId::now();
        let err = match vault.put_entity(&id, 0, test_time_range(1, 1), 1, &bytes) {
            Ok(()) => panic!("case {name}: write must be rejected"),
            Err(err) => err,
        };
        assert_eq!(err.kind(), expected_kind, "case {name}: got {err:?}");
        assert_no_entity_state(&vault, &id)?;
    }
    Ok(())
}

#[test]
fn put_claim_typed_api_rejects_invalid_confidence() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let subject = EntityId::now();
    vault.put_entity(&subject, 4, test_time_range(1, 1), 1, b"person")?;

    for bad_conf in [f32::NAN, -0.1, 1.1, f32::INFINITY] {
        let id = EntityId::now();
        let body = ClaimBody::new(
            "profile.name",
            ClaimSubject::Entity(subject),
            rmpv::Value::from("Alice"),
            bad_conf,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        let err = vault
            .put_claim(&id, &body, test_time_range(1, 1), 2)
            .expect_err("invalid conf must be rejected");
        assert_eq!(err.kind(), ErrorKind::InvalidClaimBody, "conf {bad_conf}");
        assert_no_entity_state(&vault, &id)?;
    }
    Ok(())
}

#[test]
fn reserved_predicate_rejected_publicly_but_door_writes_and_reads_back() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let a = EntityId::now();
    let b = EntityId::now();
    vault.put_entity(&a, 4, test_time_range(1, 1), 1, b"a")?;
    vault.put_entity(&b, 4, test_time_range(1, 1), 1, b"b")?;

    // Structurally valid since ONE-1159: the door validates the provenance
    // value record + actor-class evidence, not just the D18 wrapper.
    let body = valid_provenance_claim_body(a, a, b);
    let bytes = crate::claim::encode_claim_body(&body)?;

    // Public typed API → ReservedPredicate, nothing written.
    let id = EntityId::now();
    let err = vault
        .put_claim(&id, &body, test_time_range(1, 1), 2)
        .expect_err("public put_claim must reject edge.*");
    assert_eq!(err.kind(), ErrorKind::ReservedPredicate);
    assert_no_entity_state(&vault, &id)?;

    // Public raw path → ReservedPredicate, nothing written.
    let err = vault
        .put_entity(&id, 0, test_time_range(1, 1), 2, &bytes)
        .expect_err("public put_entity must reject edge.*");
    assert_eq!(err.kind(), ErrorKind::ReservedPredicate);
    assert_no_entity_state(&vault, &id)?;

    // The pub(crate) reserved-namespace door (provenance unit) succeeds and
    // the stored claim reads back through get_claim.
    vault.with_write_txn(|wtxn| {
        vault
            .batch_in()
            .put_reserved_claim(&id, test_time_range(1, 1), 2, &bytes)
            .apply(wtxn)
    })?;
    let read = vault.get_claim(&id)?.expect("door-written claim");
    assert_eq!(read.predicate, "edge.provenance");
    assert_eq!(
        read.subject,
        ClaimSubject::Edge {
            source: a,
            kind: EdgeKind::Mentions,
            target: b,
        }
    );

    // The door still enforces grammar + structural validation.
    let ungrammatical = rmpv_map_bytes(&base_claim_entries(
        "Edge.Provenance",
        a.as_bytes().to_vec(),
    ));
    let bad_id = EntityId::now();
    let err = vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .put_reserved_claim(&bad_id, test_time_range(1, 1), 2, &ungrammatical)
                .apply(wtxn)
        })
        .expect_err("door must still enforce the predicate grammar");
    assert_eq!(err.kind(), ErrorKind::InvalidPredicate);
    assert_no_entity_state(&vault, &bad_id)?;
    Ok(())
}

/// ONE-1123: the sync-replay door (`put_replicated`) admits a reserved
/// `edge.provenance` Claim on BOTH builder flavors — the truth-Claim behind
/// the 26 B edge flag cache (contracts.ts edgeProvenanceClaim: "the edge
/// flags are a DERIVED CACHE of that Claim, and the Claim is truth";
/// storedAs "Normal CLAIM entity") — while every public path keeps
/// rejecting the reserved namespace (covered by the neighboring tests and
/// the claim.rs grammar tests).
#[cfg(feature = "sync")]
#[test]
fn replicated_door_admits_reserved_claim_on_both_builders() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let a = EntityId::now();
    let b = EntityId::now();
    vault.put_entity(&a, 4, test_time_range(1, 1), 1, b"a")?;
    vault.put_entity(&b, 4, test_time_range(1, 1), 1, b"b")?;

    // Structurally valid since ONE-1159: the replicated door validates the
    // provenance value record + actor-class evidence, not just D18.
    let body = valid_provenance_claim_body(a, a, b);
    let bytes = crate::claim::encode_claim_body(&body)?;

    // TxnBatchBuilder flavor (Observer B's replay door).
    let txn_id = EntityId::now();
    vault.with_write_txn(|wtxn| {
        vault
            .batch_in()
            .put_replicated(
                &txn_id,
                crate::registry::ENTITY_TYPE_CLAIM,
                test_time_range(1, 1),
                2,
                &bytes,
            )
            .apply(wtxn)
    })?;
    let read = vault.get_claim(&txn_id)?.expect("txn-door claim stored");
    assert_eq!(read.predicate, "edge.provenance");

    // BatchBuilder flavor (forward_rematerialize's replay door).
    let batch_id = EntityId::now();
    vault
        .batch()
        .put_replicated(
            &batch_id,
            crate::registry::ENTITY_TYPE_CLAIM,
            test_time_range(1, 1),
            2,
            &bytes,
        )
        .commit()?;
    let read = vault
        .get_claim(&batch_id)?
        .expect("batch-door claim stored");
    assert_eq!(read.predicate, "edge.provenance");
    assert_eq!(
        read.subject,
        ClaimSubject::Edge {
            source: a,
            kind: EdgeKind::Mentions,
            target: b,
        }
    );
    Ok(())
}

/// ONE-1123: a trusted door still validates structure. `put_replicated`
/// opens ONLY the two engine-authored band rejections; the D17 grammar, the
/// D18 body validation, and the type registry all still fail typed, and
/// nothing is written on failure.
#[cfg(feature = "sync")]
#[test]
fn replicated_door_still_fails_typed_on_structural_violations() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let a = EntityId::now();
    vault.put_entity(&a, 4, test_time_range(1, 1), 1, b"a")?;

    // Ungrammatical reserved predicate: "Edge.Provenance" violates the D17
    // segment grammar `[a-z][a-z0-9_]*`, so it fails InvalidPredicate even
    // through the door — `allow_reserved` skips ONLY the ReservedPredicate
    // arm, never the grammar.
    let ungrammatical = rmpv_map_bytes(&base_claim_entries(
        "Edge.Provenance",
        a.as_bytes().to_vec(),
    ));
    let bad_txn = EntityId::now();
    let err = vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .put_replicated(
                    &bad_txn,
                    crate::registry::ENTITY_TYPE_CLAIM,
                    test_time_range(1, 1),
                    2,
                    &ungrammatical,
                )
                .apply(wtxn)
        })
        .expect_err("txn replay door must still enforce the D17 grammar");
    assert_eq!(err.kind(), ErrorKind::InvalidPredicate);
    assert_no_entity_state(&vault, &bad_txn)?;

    let bad_batch = EntityId::now();
    let err = vault
        .batch()
        .put_replicated(
            &bad_batch,
            crate::registry::ENTITY_TYPE_CLAIM,
            test_time_range(1, 1),
            2,
            &ungrammatical,
        )
        .commit()
        .expect_err("batch replay door must still enforce the D17 grammar");
    assert_eq!(err.kind(), ErrorKind::InvalidPredicate);
    assert_no_entity_state(&vault, &bad_batch)?;

    // Malformed type-0 body (not a MessagePack map) → InvalidClaimBody.
    let bad_body = EntityId::now();
    let err = vault
        .batch()
        .put_replicated(
            &bad_body,
            crate::registry::ENTITY_TYPE_CLAIM,
            test_time_range(1, 1),
            2,
            b"not a msgpack map",
        )
        .commit()
        .expect_err("replay door must still enforce D18 body validation");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    assert_no_entity_state(&vault, &bad_body)?;

    // Genuinely unknown type byte → InvalidEntityType (registry gate; the
    // door admits the REGISTERED maintenance band, not arbitrary bytes).
    let bad_type = EntityId::now();
    let err = vault
        .batch()
        .put_replicated(&bad_type, 200, test_time_range(1, 1), 2, b"")
        .commit()
        .expect_err("replay door must still reject unregistered type bytes");
    assert_eq!(err.kind(), ErrorKind::InvalidEntityType);
    assert_no_entity_state(&vault, &bad_type)?;
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn replicated_door_fails_closed_on_malformed_federation_grant_body() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let malformed = b"not a federation grant body";

    let bad_txn = EntityId::now();
    let err = vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .put_replicated(
                    &bad_txn,
                    ENTITY_TYPE_FEDERATION_GRANT,
                    test_time_range(1, 1),
                    2,
                    malformed,
                )
                .apply(wtxn)
        })
        .expect_err("txn replay door must reject malformed federation grants");
    assert_eq!(err.kind(), ErrorKind::InvalidFederationGrantBody);
    assert_no_entity_state(&vault, &bad_txn)?;

    let bad_batch = EntityId::now();
    let err = vault
        .batch()
        .put_replicated(
            &bad_batch,
            ENTITY_TYPE_FEDERATION_GRANT,
            test_time_range(1, 1),
            2,
            malformed,
        )
        .commit()
        .expect_err("batch replay door must reject malformed federation grants");
    assert_eq!(err.kind(), ErrorKind::InvalidFederationGrantBody);
    assert_no_entity_state(&vault, &bad_batch)?;
    Ok(())
}

/// FED-001: syntactically valid FEDERATION_GRANT bodies still fail closed at
/// the replicated write chokepoint when role/preset policy is invalid.
#[cfg(feature = "sync")]
#[test]
fn replicated_door_fails_closed_on_invalid_federation_grant_policy() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let invalid_policy = federation_grant_body_with_role_and_preset("admin", "read_only");

    let bad_txn = EntityId::now();
    let err = vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .put_replicated(
                    &bad_txn,
                    ENTITY_TYPE_FEDERATION_GRANT,
                    test_time_range(1, 1),
                    2,
                    &invalid_policy,
                )
                .apply(wtxn)
        })
        .expect_err("txn replay door must reject role/preset mismatches");
    assert_eq!(err.kind(), ErrorKind::InvalidFederationGrantBody);
    assert_no_entity_state(&vault, &bad_txn)?;

    let bad_batch = EntityId::now();
    let err = vault
        .batch()
        .put_replicated(
            &bad_batch,
            ENTITY_TYPE_FEDERATION_GRANT,
            test_time_range(1, 1),
            2,
            &invalid_policy,
        )
        .commit()
        .expect_err("batch replay door must reject role/preset mismatches");
    assert_eq!(err.kind(), ErrorKind::InvalidFederationGrantBody);
    assert_no_entity_state(&vault, &bad_batch)?;
    Ok(())
}

/// FED-001: COMM_RECORD (type 136) is a registered maintenance kind, so the
/// replicated doors admit it — malformed bodies must fail typed at the
/// boundary instead of persisting bytes the comm projector silently skips.
#[cfg(feature = "sync")]
#[test]
fn replicated_door_fails_closed_on_malformed_comm_record_body() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let malformed = b"not a comm record body";

    let bad_txn = EntityId::now();
    let err = vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .put_replicated(
                    &bad_txn,
                    crate::registry::ENTITY_TYPE_COMM_RECORD,
                    test_time_range(1, 1),
                    2,
                    malformed,
                )
                .apply(wtxn)
        })
        .expect_err("txn replay door must reject malformed comm records");
    assert_eq!(err.kind(), ErrorKind::InvalidCommRecordBody);
    assert_no_entity_state(&vault, &bad_txn)?;

    let bad_batch = EntityId::now();
    let err = vault
        .batch()
        .put_replicated(
            &bad_batch,
            crate::registry::ENTITY_TYPE_COMM_RECORD,
            test_time_range(1, 1),
            2,
            malformed,
        )
        .commit()
        .expect_err("batch replay door must reject malformed comm records");
    assert_eq!(err.kind(), ErrorKind::InvalidCommRecordBody);
    assert_no_entity_state(&vault, &bad_batch)?;
    Ok(())
}

#[test]
fn get_claim_rejects_non_claim_types_and_handles_missing() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    // Missing entity → Ok(None).
    assert!(vault.get_claim(&seeded_entity_id(0xBEEF))?.is_none());

    // Non-claim type byte → typed InvalidClaimBody, not a silent decode.
    let person = EntityId::now();
    vault.put_entity(&person, 4, test_time_range(1, 1), 1, b"person")?;
    let err = vault
        .get_claim(&person)
        .expect_err("get_claim on a PERSON must fail typed");
    assert_eq!(err.kind(), ErrorKind::InvalidClaimBody);
    Ok(())
}
