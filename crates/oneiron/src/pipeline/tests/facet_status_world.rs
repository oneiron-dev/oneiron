//! Facet filter, claim-status gate, and world-scope visibility pins.

use super::*;

use crate::registry::{ENTITY_TYPE_EVENT, ENTITY_TYPE_FACET, ENTITY_TYPE_TURN};

use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};

/// AC 3 — *(no facet)* mode regression pin: a query that never calls
/// `.facet()` returns every candidate, other-facet claims included,
/// with the exact unfiltered/unboosted blend scores in the exact
/// pre-feature order. Any accidental default-on filtering or rescoring
/// fails this literal pin.
#[test]
fn facet_absent_is_a_no_op_regression_pin() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let fixture = setup_facet_fixture(&vault)?;

    let results = vault
        .query()
        .search_vector(&FACET_QUERY, 10)
        .with_temporal_now(FACET_NOW)
        .run()?;
    assert_eq!(
        ordered_results(&results),
        vec![
            (fixture.claim_other, FACET_R0),
            (fixture.claim_active, FACET_R1),
            (fixture.claim_core, FACET_R2),
            (fixture.event_faceted, FACET_R3),
        ],
        "no-facet mode must be identical to the pre-feature pipeline"
    );
    Ok(())
}

/// AC 1 — strict mode: the claim whose `FacetOf` edge targets a
/// different facet is removed; the active-facet claim and the
/// core/unfaceted claim pass with their scores UNTOUCHED (strict never
/// boosts); the non-claim entity passes even though it carries a
/// `FacetOf` edge to the other facet.
#[test]
fn facet_strict_removes_other_facet_claims_only() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let fixture = setup_facet_fixture(&vault)?;

    let results = vault
        .query()
        .search_vector(&FACET_QUERY, 10)
        .with_temporal_now(FACET_NOW)
        .facet(&fixture.facet_a, FacetMode::Strict)
        .run()?;
    assert_eq!(
        ordered_results(&results),
        vec![
            (fixture.claim_active, FACET_R1),
            (fixture.claim_core, FACET_R2),
            (fixture.event_faceted, FACET_R3),
        ],
        "strict must drop claim_other, keep core + active claims and \
             non-claim entities at unchanged scores"
    );
    Ok(())
}

/// AC 2 — prefer mode: nothing is removed; the active-facet claim's
/// score is multiplied by the caller-supplied boost EXACTLY
/// (`R1 * 3.0`), which reorders it above the baseline rank-0 entity;
/// every other score is byte-identical to the baseline.
#[test]
fn facet_prefer_boosts_active_facet_with_exact_derived_values() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let fixture = setup_facet_fixture(&vault)?;

    let results = vault
        .query()
        .search_vector(&FACET_QUERY, 10)
        .with_temporal_now(FACET_NOW)
        .facet(&fixture.facet_a, FacetMode::Prefer { boost: 3.0 })
        .run()?;
    assert_eq!(
        ordered_results(&results),
        vec![
            (fixture.claim_active, FACET_R1 * 3.0),
            (fixture.claim_other, FACET_R0),
            (fixture.claim_core, FACET_R2),
            (fixture.event_faceted, FACET_R3),
        ],
        "prefer must keep all candidates, boost only the active-facet \
             claim, and reorder it by the exact derived score"
    );
    Ok(())
}

/// AC 4 — strict-excluded claims do not consume `result_limit` slots:
/// with `limit(2)` and the top-ranked candidate excluded, BOTH
/// remaining passing candidates fill the page. A filter applied after
/// truncation would return a single result here.
#[test]
fn facet_strict_excluded_claims_free_result_limit_slots() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let fixture = setup_facet_fixture(&vault)?;

    let results = vault
        .query()
        .search_vector(&FACET_QUERY, 10)
        .with_temporal_now(FACET_NOW)
        .limit(2)
        .facet(&fixture.facet_a, FacetMode::Strict)
        .run()?;
    assert_eq!(
        ordered_results(&results),
        vec![
            (fixture.claim_active, FACET_R1),
            (fixture.claim_core, FACET_R2),
        ],
        "the excluded rank-0 claim must free its slot for claim_core"
    );
    Ok(())
}

/// ONE-1645 seam contract: "kept by relevance" is NOT "publicly disclosable".
/// One unfaceted claim, two axes asserted together — it survives STRICT-mode
/// relevance filtering, and its unstamped body simultaneously reads the
/// band-2 disclosure floor. The pair is the contract that forbids ONE-1646
/// from ever reading `ClaimFacetScope::Unfaceted` as invariant evidence:
/// invariant admission needs positive public-provenance, never stamp-absence.
#[test]
fn unfaceted_scope_is_not_invariant_evidence_contract() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let fixture = setup_facet_fixture(&vault)?;

    // Axis 1 — relevance: the unfaceted claim passes the strict-mode filter.
    let strict = vault
        .query()
        .search_vector(&FACET_QUERY, 10)
        .with_temporal_now(FACET_NOW)
        .facet(&fixture.facet_a, FacetMode::Strict)
        .run()?;
    assert!(
        to_score_map(&strict).contains_key(&fixture.claim_core),
        "the unfaceted claim must survive strict-mode relevance"
    );

    // Axis 2 — disclosure: the very same claim's body is unstamped, so it
    // reads the floor band and fails closed at every disclosure surface.
    let body = crate::claim::decode_claim_body(&facet_claim_body(), false)?;
    assert_eq!(
        crate::claim::claim_sensitivity_band(&body),
        Some(crate::claim::UNSTAMPED_CLAIM_SENSITIVITY_BAND),
        "the fixture claim body must be unstamped, so relevance-kept != disclosable"
    );
    Ok(())
}

/// Multi-facet claims: a claim with `FacetOf` edges to BOTH facets is
/// scoped to each of them — strict keeps it for either active facet,
/// removes it for a third facet, and prefer boosts it exactly ONCE.
#[test]
fn facet_multi_scoped_claim_matches_any_of_its_facets() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let facet_a = entity_id(0x91);
    let facet_b = entity_id(0xB1);
    let facet_c = entity_id(0xC1);
    put_entity(&vault, facet_a, ENTITY_TYPE_FACET, 1, 1, 1)?;
    put_entity(&vault, facet_b, ENTITY_TYPE_FACET, 1, 1, 1)?;
    put_entity(&vault, facet_c, ENTITY_TYPE_FACET, 1, 1, 1)?;

    let claim_multi = entity_id(0x31);
    put_claim_with_vector(&vault, claim_multi, [1.0, 0.0, 0.0, 0.0])?;
    vault
        .batch()
        .edge(&claim_multi, EdgeKind::FacetOf, &facet_a, 0.7)
        .edge(&claim_multi, EdgeKind::FacetOf, &facet_b, 0.7)
        .commit()?;

    for facet in [facet_a, facet_b] {
        let results = vault
            .query()
            .search_vector(&FACET_QUERY, 10)
            .with_temporal_now(FACET_NOW)
            .facet(&facet, FacetMode::Strict)
            .run()?;
        assert_eq!(
            ordered_results(&results),
            vec![(claim_multi, FACET_R0)],
            "strict must keep a claim scoped to the active facet"
        );
    }

    let strict_c = vault
        .query()
        .search_vector(&FACET_QUERY, 10)
        .with_temporal_now(FACET_NOW)
        .facet(&facet_c, FacetMode::Strict)
        .run()?;
    assert!(
        strict_c.is_empty(),
        "strict must remove a claim scoped only to other facets, got {strict_c:?}"
    );

    // Two FacetOf edges, one matching: the boost applies exactly once.
    let prefer = vault
        .query()
        .search_vector(&FACET_QUERY, 10)
        .with_temporal_now(FACET_NOW)
        .facet(&facet_a, FacetMode::Prefer { boost: 2.0 })
        .run()?;
    assert_eq!(
        ordered_results(&prefer),
        vec![(claim_multi, FACET_R0 * 2.0)],
        "prefer must apply the boost exactly once per claim"
    );
    Ok(())
}

/// Only the `FacetOf` kind (u8 17) carries claim facet scope: a
/// `HasFacet` (u8 16) edge neither scopes a claim (strict treats it as
/// unfaceted) nor rescues one scoped elsewhere via `FacetOf`.
#[test]
fn facet_filter_reads_only_facet_of_edges() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let facet_a = entity_id(0x91);
    let facet_b = entity_id(0xB1);
    put_entity(&vault, facet_a, ENTITY_TYPE_FACET, 1, 1, 1)?;
    put_entity(&vault, facet_b, ENTITY_TYPE_FACET, 1, 1, 1)?;

    // `HasFacet → facet_b` only: NOT facet scope — unfaceted.
    let claim_has_facet = entity_id(0x41);
    // `FacetOf → facet_b` + `HasFacet → facet_a`: scoped to facet_b;
    // the HasFacet edge to the active facet must not rescue it.
    let claim_scoped_b = entity_id(0x66);
    put_claim_with_vector(&vault, claim_has_facet, [1.0, 0.0, 0.0, 0.0])?;
    put_claim_with_vector(&vault, claim_scoped_b, [0.8, 0.6, 0.0, 0.0])?;
    vault
        .batch()
        .edge(&claim_has_facet, EdgeKind::HasFacet, &facet_b, 0.7)
        .edge(&claim_scoped_b, EdgeKind::FacetOf, &facet_b, 0.7)
        .edge(&claim_scoped_b, EdgeKind::HasFacet, &facet_a, 0.7)
        .commit()?;

    let strict = vault
        .query()
        .search_vector(&FACET_QUERY, 10)
        .with_temporal_now(FACET_NOW)
        .facet(&facet_a, FacetMode::Strict)
        .run()?;
    assert_eq!(
        ordered_results(&strict),
        vec![(claim_has_facet, FACET_R0)],
        "HasFacet must not scope a claim, and must not rescue a \
             FacetOf-scoped one"
    );

    let prefer = vault
        .query()
        .search_vector(&FACET_QUERY, 10)
        .with_temporal_now(FACET_NOW)
        .facet(&facet_b, FacetMode::Prefer { boost: 4.0 })
        .run()?;
    assert_eq!(
        ordered_results(&prefer),
        vec![
            (claim_scoped_b, FACET_R1 * 4.0),
            (claim_has_facet, FACET_R0),
        ],
        "prefer must boost via FacetOf only — a HasFacet edge to the \
             active facet earns no boost"
    );
    Ok(())
}

/// Non-claim entities are never boosted nor removed, whatever edges
/// they carry — the filter discriminates on the type byte first.
#[test]
fn facet_filter_never_rescores_non_claim_entities() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let facet_a = entity_id(0x91);
    put_entity(&vault, facet_a, ENTITY_TYPE_FACET, 1, 1, 1)?;

    let event_active = entity_id(0x51);
    vault
        .batch()
        .put(
            &event_active,
            ENTITY_TYPE_EVENT,
            TimeRange { start: 1, end: 1 },
            1,
            b"payload",
        )
        .vector(&event_active, &[1.0, 0.0, 0.0, 0.0])
        .edge(&event_active, EdgeKind::FacetOf, &facet_a, 0.7)
        .commit()?;

    for mode in [FacetMode::Strict, FacetMode::Prefer { boost: 5.0 }] {
        let results = vault
            .query()
            .search_vector(&FACET_QUERY, 10)
            .with_temporal_now(FACET_NOW)
            .facet(&facet_a, mode)
            .run()?;
        assert_eq!(
            ordered_results(&results),
            vec![(event_active, FACET_R0)],
            "non-claim entity must pass unchanged under {mode:?}"
        );
    }
    Ok(())
}

/// Fail-closed: a non-finite or non-positive prefer boost is a typed
/// [`Error::InvalidConfig`] from `run()`, never a silent skip or a
/// poisoned score.
#[test]
fn facet_prefer_rejects_invalid_boost_typed() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let fixture = setup_facet_fixture(&vault)?;

    for bad_boost in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, 0.0, -1.0] {
        let err = vault
            .query()
            .search_vector(&FACET_QUERY, 10)
            .facet(&fixture.facet_a, FacetMode::Prefer { boost: bad_boost })
            .run()
            .expect_err("invalid prefer boost must be rejected");
        assert!(
            matches!(err, Error::InvalidConfig(_)),
            "expected InvalidConfig for boost {bad_boost}, got {err:?}"
        );
    }
    Ok(())
}

#[test]
fn pipeline_reports_pending_vector_state_for_retrieved_claim() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let claim = entity_id(0x71);
    put_status_claim(
        &vault,
        claim,
        "pendingvectorneedle",
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
        false,
    )?;

    let pending = vault
        .query()
        .search_text("pendingvectorneedle", 10)
        .run_with_pending_vectors()?;
    assert!(
        pending.value.iter().any(|scored| scored.id == claim),
        "claim should be retrievable through text before embedding fill"
    );
    assert_eq!(pending.pending_vector_ids, vec![claim]);
    let token = pending
        .pending_vectors
        .iter()
        .find(|pending| pending.id == claim)
        .expect("pending marker token for claim")
        .token
        .clone();

    vault
        .batch()
        .vector_for_pending_embedding(&claim, &[1.0, 0.0, 0.0, 0.0], &token)
        .commit()?;

    let filled = vault
        .query()
        .search_text("pendingvectorneedle", 10)
        .run_with_pending_vectors()?;
    assert!(
        filled.value.iter().any(|scored| scored.id == claim),
        "claim should remain retrievable after embedding fill"
    );
    assert!(
        filled.pending_vector_ids.is_empty(),
        "embedding fill should clear pending vector state"
    );
    Ok(())
}

/// AC 1 / AC 3 / AC 4 — the literal status table through the text
/// channel: ONLY `appr ∈ {auto, approved}` ∧ `life = active` ∧
/// `stale ∈ {absent, false}` surfaces. The surfaceable rows are written
/// through `ClaimBody::new` (stale ABSENT on disk), so their presence
/// also pins "absence alone must NOT exclude".
#[test]
fn claim_status_gate_pins_the_literal_status_table() -> Result<()> {
    use ClaimApprovalStatus as A;
    use ClaimLifecycleStatus as L;

    let (_dir, vault) = open_test_vault();

    let cases: &[(u8, A, L, bool, bool)] = &[
        // (id byte, appr, life, stale, must_surface)
        (10, A::Auto, L::Active, false, true),
        (11, A::Approved, L::Active, false, true),
        (12, A::Proposed, L::Active, false, false),
        (13, A::Rejected, L::Active, false, false),
        (14, A::Auto, L::Superseded, false, false),
        (15, A::Auto, L::Retracted, false, false),
        (16, A::Auto, L::Active, true, false),
    ];

    for (byte, appr, life, stale, _) in cases {
        put_status_claim(
            &vault,
            entity_id(*byte),
            "statusneedle",
            *appr,
            *life,
            *stale,
        )?;
    }

    let results = vault.query().search_text("statusneedle", 20).run()?;
    let surfaced = to_score_map(&results);

    for (byte, appr, life, stale, must_surface) in cases {
        assert_eq!(
            surfaced.contains_key(&entity_id(*byte)),
            *must_surface,
            "appr={appr:?} life={life:?} stale={stale} must_surface={must_surface}"
        );
    }
    assert_eq!(results.len(), 2, "exactly the two surfaceable claims");
    Ok(())
}

/// AC 2 — the gate covers all five channels: one claim is reachable via
/// text, vector, phonetic, temporal, and PPR; after `retract_claim`
/// (which re-puts the body ONLY — every index row survives) it must be
/// absent from every channel.
#[test]
fn claim_status_gate_covers_all_five_channels() -> Result<()> {
    type ChannelQuery = Box<dyn Fn(&Vault) -> Result<Vec<ScoredEntity>>>;

    let (_dir, vault) = open_test_vault();

    let anchor = 1_000_000_u64;
    let claim = entity_id(20);
    let seed = entity_id(21);

    vault
        .batch()
        .put(
            &claim,
            ENTITY_TYPE_CLAIM,
            TimeRange {
                start: anchor,
                end: anchor,
            },
            anchor,
            &claim_body_bytes(
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Active,
                false,
            ),
        )
        .text(&claim, &[("body", "gateneedle")])
        .vector(&claim, &[0.9, 0.1, 0.0, 0.0])
        .phonetic(&claim, &["KTNTL"])
        .commit()?;

    // PPR channel: a TURN seed with a semantic edge onto the claim.
    vault.put_entity(
        &seed,
        1,
        TimeRange {
            start: anchor,
            end: anchor,
        },
        anchor,
        b"payload",
    )?;
    vault.put_edge(&seed, EdgeKind::Supports, &claim, 0.9)?;

    let channels: Vec<(&str, ChannelQuery)> = vec![
        (
            "text",
            Box::new(|v: &Vault| v.query().search_text("gateneedle", 10).run()),
        ),
        (
            "vector",
            Box::new(|v: &Vault| v.query().search_vector(&[0.9, 0.1, 0.0, 0.0], 10).run()),
        ),
        (
            "phonetic",
            Box::new(|v: &Vault| v.query().search_phonetic(&["KTNTL"]).run()),
        ),
        (
            "temporal",
            Box::new(move |v: &Vault| {
                v.query()
                    .search_temporal(anchor - 100, anchor + 100, 10)
                    .run()
            }),
        ),
        (
            "ppr",
            Box::new(move |v: &Vault| v.query().search_ppr(&[seed], 2).run()),
        ),
    ];

    for (name, query) in &channels {
        assert!(
            to_score_map(&query(&vault)?).contains_key(&claim),
            "channel `{name}` must surface the active claim"
        );
    }

    vault.retract_claim(&claim, anchor + 500)?;

    for (name, query) in &channels {
        assert!(
            !to_score_map(&query(&vault)?).contains_key(&claim),
            "channel `{name}` must NOT surface the retracted claim"
        );
    }
    Ok(())
}

/// Blocker 1 fail-closed: the active facet must resolve to an EXISTING
/// FACET entity. A bogus id and a wrong-type (TURN) id both reject with
/// the typed [`Error::InvalidFacet`] carrying what was actually found; a
/// real FACET passes. A wrong impl that stores arbitrary facet bytes and
/// strict-drops every scoped claim fails the wrong-type leg.
#[test]
fn facet_query_rejects_invalid_active_facet_typed() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let fixture = setup_facet_fixture(&vault)?;

    // Bogus id: no such entity → InvalidFacet { found: None }.
    let bogus = entity_id(0xEE);
    let err = vault
        .query()
        .search_vector(&FACET_QUERY, 10)
        .facet(&bogus, FacetMode::Strict)
        .run()
        .expect_err("a bogus active facet must be rejected");
    assert!(
        matches!(err, Error::InvalidFacet { found: None, .. }),
        "expected InvalidFacet {{ found: None }}, got {err:?}"
    );

    // Wrong type: an existing TURN is not a FACET → found = Some(TURN).
    let turn = entity_id(0xDD);
    put_entity(&vault, turn, ENTITY_TYPE_TURN, 1, 1, 1)?;
    let err = vault
        .query()
        .search_vector(&FACET_QUERY, 10)
        .facet(&turn, FacetMode::Strict)
        .run()
        .expect_err("a non-FACET active facet must be rejected");
    assert!(
        matches!(err, Error::InvalidFacet { found: Some(t), .. } if t == ENTITY_TYPE_TURN),
        "expected InvalidFacet {{ found: Some(TURN) }}, got {err:?}"
    );

    // A real FACET entity (the fixture's facet_a) passes.
    let ok = vault
        .query()
        .search_vector(&FACET_QUERY, 10)
        .with_temporal_now(FACET_NOW)
        .facet(&fixture.facet_a, FacetMode::Strict)
        .run()?;
    assert!(!ok.is_empty(), "a valid FACET must not be rejected");
    Ok(())
}

/// Blocker 2 world filter visibility matrix: an absent-world (base) claim
/// surfaces under ALL three scopes; a world=W claim surfaces under All and
/// World(W) but NOT under Base nor World(V). Pins the exact membership a
/// wrong (or absent) world filter would violate.
#[test]
fn world_scope_filter_visibility_matrix() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let world_w = entity_id(0x5E);
    let world_v = entity_id(0xE2);

    let claim_base = entity_id(0x61); // no `world` key — base reality
    let claim_w = entity_id(0x62); // `world` = W
    put_claim_with_vector_world(&vault, claim_base, [1.0, 0.0, 0.0, 0.0], None)?;
    put_claim_with_vector_world(&vault, claim_w, [0.8, 0.6, 0.0, 0.0], Some(world_w))?;

    let ids =
        |scores: &[ScoredEntity]| -> HashSet<EntityId> { scores.iter().map(|s| s.id).collect() };

    // All (default): both worlds span.
    let all = ids(&vault.query().search_vector(&FACET_QUERY, 10).run()?);
    assert!(
        all.contains(&claim_base) && all.contains(&claim_w),
        "All scope must span base + world claims, got {all:?}"
    );

    // Base: only the absent-world claim; the W-scoped claim is removed.
    let base = ids(&vault
        .query()
        .search_vector(&FACET_QUERY, 10)
        .world(WorldScope::Base)
        .run()?);
    assert!(
        base.contains(&claim_base),
        "base claim must surface in Base"
    );
    assert!(
        !base.contains(&claim_w),
        "W-scoped claim must NOT surface in Base"
    );

    // World(W): the W-scoped claim plus base claims.
    let in_w = ids(&vault
        .query()
        .search_vector(&FACET_QUERY, 10)
        .world(WorldScope::World(world_w))
        .run()?);
    assert!(
        in_w.contains(&claim_base) && in_w.contains(&claim_w),
        "World(W) must surface the W claim + base claim, got {in_w:?}"
    );

    // World(V): base claim only — the W claim belongs to another world.
    let in_v = ids(&vault
        .query()
        .search_vector(&FACET_QUERY, 10)
        .world(WorldScope::World(world_v))
        .run()?);
    assert!(
        in_v.contains(&claim_base),
        "base claim must surface in World(V)"
    );
    assert!(
        !in_v.contains(&claim_w),
        "W-scoped claim must NOT surface in World(V)"
    );
    Ok(())
}

/// AC 1 — `supersede_claim` closes the OLD claim only: the new claim
/// keeps surfacing, the superseded one disappears (indexes untouched).
#[test]
fn superseded_claim_stops_surfacing_but_successor_does_not() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let old = entity_id(30);
    let new = entity_id(31);
    put_status_claim(
        &vault,
        old,
        "supersedeneedle",
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
        false,
    )?;
    put_status_claim(
        &vault,
        new,
        "supersedeneedle",
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
        false,
    )?;

    vault.supersede_claim(&new, &old, 2_000)?;

    let surfaced = to_score_map(&vault.query().search_text("supersedeneedle", 10).run()?);
    assert!(!surfaced.contains_key(&old), "superseded claim must hide");
    assert!(surfaced.contains_key(&new), "successor must keep surfacing");
    Ok(())
}

/// AC 5 — non-type-0 entities are NEVER status-gated: their bodies are
/// opaque, even when they happen to spell poisonous claim-status keys
/// or are not MessagePack at all.
#[test]
fn non_claim_entities_are_never_status_gated() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    // TURN (type 1) whose body SAYS rejected/retracted/stale.
    let poison = entity_id(40);
    let mut poison_body = Vec::new();
    rmpv::encode::write_value(
        &mut poison_body,
        &rmpv::Value::Map(vec![
            (rmpv::Value::from("appr"), rmpv::Value::from("rejected")),
            (rmpv::Value::from("life"), rmpv::Value::from("retracted")),
            (rmpv::Value::from("stale"), rmpv::Value::Boolean(true)),
        ]),
    )
    .expect("msgpack encode");
    vault
        .batch()
        .put(&poison, 1, TimeRange { start: 1, end: 1 }, 1, &poison_body)
        .text(&poison, &[("body", "opaqueneedle")])
        .commit()?;

    // PERSON-band entity (type 4) whose body is not MessagePack at all.
    let opaque = entity_id(41);
    vault
        .batch()
        .put(&opaque, 4, TimeRange { start: 1, end: 1 }, 1, b"payload")
        .text(&opaque, &[("body", "opaqueneedle")])
        .commit()?;

    let surfaced = to_score_map(&vault.query().search_text("opaqueneedle", 10).run()?);
    assert!(surfaced.contains_key(&poison));
    assert!(surfaced.contains_key(&opaque));
    Ok(())
}

/// AC 7 — fail-closed hydration on the pipeline: raw-written type-0
/// records whose bodies are not the pinned CLAIM ABI never surface
/// (silent exclusion, not an error).
#[test]
fn claim_status_gate_fails_closed_on_undecodable_bodies() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let control = entity_id(50);
    put_status_claim(
        &vault,
        control,
        "rawneedle",
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
        false,
    )?;

    // Three corrupt type-0 records, each text-indexed before the raw
    // overwrite (retraction-style: indexes survive, body goes bad).
    let non_map = entity_id(51);
    let missing_appr = entity_id(52);
    let empty_body = entity_id(53);
    for id in [non_map, missing_appr, empty_body] {
        put_status_claim(
            &vault,
            id,
            "rawneedle",
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
            false,
        )?;
    }

    // (a) body is MessagePack but not a map;
    let mut junk = Vec::new();
    rmpv::encode::write_value(&mut junk, &rmpv::Value::from("junk")).expect("msgpack encode");
    overwrite_entity_record(&vault, &non_map, ENTITY_TYPE_CLAIM, &junk)?;

    // (b) body is a map but missing required `appr`;
    let mut no_appr = Vec::new();
    rmpv::encode::write_value(
        &mut no_appr,
        &rmpv::Value::Map(vec![
            (rmpv::Value::from("pred"), rmpv::Value::from("test.bad")),
            (rmpv::Value::from("val"), rmpv::Value::from("v")),
            (rmpv::Value::from("conf"), rmpv::Value::F32(0.5)),
            (
                rmpv::Value::from("subj"),
                rmpv::Value::Binary(vec![0x7C; 16]),
            ),
            (rmpv::Value::from("life"), rmpv::Value::from("active")),
        ]),
    )
    .expect("msgpack encode");
    overwrite_entity_record(&vault, &missing_appr, ENTITY_TYPE_CLAIM, &no_appr)?;

    // (c) body missing entirely (bare 25-byte envelope).
    overwrite_entity_record(&vault, &empty_body, ENTITY_TYPE_CLAIM, &[])?;

    let results = vault.query().search_text("rawneedle", 10).run()?;
    let surfaced = to_score_map(&results);
    assert!(surfaced.contains_key(&control), "control claim surfaces");
    assert_eq!(results.len(), 1, "all three corrupt records suppressed");
    Ok(())
}

/// AC 8 — excluded claims never consume `result_limit` slots: the gate
/// runs before sort/truncate, so retracting the TOP-ranked claim frees
/// its slot for the next survivor.
#[test]
fn excluded_claims_do_not_consume_result_limit_slots() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let c1 = entity_id(60);
    let c2 = entity_id(61);
    let c3 = entity_id(62);
    for (id, text) in [
        (c1, "alpha alpha alpha"),
        (c2, "alpha alpha"),
        (c3, "alpha"),
    ] {
        put_status_claim(
            &vault,
            id,
            text,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
            false,
        )?;
    }

    // Establish the BM25 rank order this test relies on.
    let before = vault.query().search_text("alpha", 10).run()?;
    let before_ids: Vec<EntityId> = before.iter().map(|s| s.id).collect();
    assert_eq!(before_ids, vec![c1, c2, c3], "expected rank order");

    vault.retract_claim(&c1, 2_000)?;

    let after = vault.query().search_text("alpha", 10).limit(2).run()?;
    let after_ids: Vec<EntityId> = after.iter().map(|s| s.id).collect();
    assert_eq!(
        after_ids,
        vec![c2, c3],
        "retracted top claim must not consume a result_limit slot"
    );
    Ok(())
}

/// Pinned decision — the gate runs BEFORE expand_ppr implicit seed
/// selection: a retracted claim never seeds the expansion, so nothing
/// reachable only through its seeding can surface.
#[test]
fn dead_claim_never_seeds_ppr_expansion() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let r = entity_id(70);
    let x = entity_id(0x67);
    put_status_claim(
        &vault,
        r,
        "seedneedle",
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
        false,
    )?;
    vault.put_entity(&x, 4, TimeRange { start: 1, end: 1 }, 1, b"payload")?;
    vault.put_edge(&r, EdgeKind::Supports, &x, 0.9)?;

    // Control: while active, the claim seeds the expansion and pulls in
    // its neighborhood.
    let before = to_score_map(
        &vault
            .query()
            .search_text("seedneedle", 10)
            .expand_ppr(&[], 2)
            .run()?,
    );
    assert!(before.contains_key(&r));
    assert!(
        before.contains_key(&x),
        "active claim must seed expansion and surface its neighbor"
    );

    vault.retract_claim(&r, 2_000)?;

    let after = vault
        .query()
        .search_text("seedneedle", 10)
        .expand_ppr(&[], 2)
        .run()?;
    assert!(
        after.is_empty(),
        "retracted claim must not seed expansion; got {after:?}"
    );
    Ok(())
}

/// Pinned decision — claims PULLED IN by expand_ppr are gated too: the
/// expansion list is status-gated before fusion, so a dead claim found
/// through the graph walk cannot surface.
#[test]
fn expansion_results_are_status_gated() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let a = entity_id(80);
    let dead = entity_id(81);
    let live = entity_id(82);
    vault
        .batch()
        .put(&a, 1, TimeRange { start: 1, end: 1 }, 1, b"payload")
        .text(&a, &[("body", "expneedle")])
        .commit()?;
    put_status_claim(
        &vault,
        dead,
        "deadclaim",
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Retracted,
        false,
    )?;
    put_status_claim(
        &vault,
        live,
        "liveclaim",
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
        false,
    )?;
    vault.put_edge(&a, EdgeKind::Supports, &dead, 0.9)?;
    vault.put_edge(&a, EdgeKind::Supports, &live, 0.9)?;

    let surfaced = to_score_map(
        &vault
            .query()
            .search_text("expneedle", 10)
            .expand_ppr(&[], 2)
            .run()?,
    );
    assert!(surfaced.contains_key(&a), "seed turn surfaces");
    assert!(
        surfaced.contains_key(&live),
        "expansion must surface the ACTIVE claim (control: expansion can surface claims)"
    );
    assert!(
        !surfaced.contains_key(&dead),
        "expansion-introduced retracted claim must be gated"
    );
    Ok(())
}

#[test]
fn ppr_reblend_keeps_original_dead_claims_filtered() -> Result<()> {
    let (_dir, vault) = open_test_vault();

    let live_seed = entity_id(83);
    let dead_indexed = entity_id(84);
    let expanded = entity_id(85);
    put_status_claim(
        &vault,
        live_seed,
        "reblendneedle",
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
        false,
    )?;
    put_status_claim(
        &vault,
        dead_indexed,
        "reblendneedle",
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Retracted,
        false,
    )?;
    put_status_claim(
        &vault,
        expanded,
        "expandedclaim",
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
        false,
    )?;
    vault.put_edge(&live_seed, EdgeKind::Supports, &expanded, 0.9)?;

    let surfaced = to_score_map(
        &vault
            .query()
            .search_text("reblendneedle", 10)
            .expand_ppr(&[], 2)
            .run()?,
    );

    assert!(surfaced.contains_key(&live_seed), "live seed surfaces");
    assert!(
        surfaced.contains_key(&expanded),
        "gated PPR expansion result surfaces"
    );
    assert!(
        !surfaced.contains_key(&dead_indexed),
        "dead claim from the original ranked lists must not re-enter after PPR reblend"
    );
    Ok(())
}
