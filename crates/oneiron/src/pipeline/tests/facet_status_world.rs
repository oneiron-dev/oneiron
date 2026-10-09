//! Facet filter, claim-status gate, and world-scope visibility pins.

use super::*;

use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};

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

    let owner = crate::federation::derivation::DerivationOwner([7; 32]);
    vault.bind_derivation_owner(owner)?;
    let resealed = vault
        .query()
        .search_text("pendingvectorneedle", 10)
        .run_with_pending_vectors()?;
    assert_eq!(resealed.pending_vector_ids, vec![claim]);
    let sealed_token = resealed.pending_vectors[0].token.clone();
    assert_ne!(sealed_token, token);
    // Work dispatched before the owner binding cannot complete under that owner.
    vault
        .batch()
        .vector_for_pending_embedding(&claim, &[1.0, 0.0, 0.0, 0.0], &token)
        .commit()?;
    assert!(vault.get_vector(&claim)?.is_none());
    vault.bind_derivation_owner(owner)?;
    let repeated = vault
        .query()
        .search_text("pendingvectorneedle", 10)
        .run_with_pending_vectors()?;
    assert_eq!(repeated.pending_vectors[0].token, sealed_token);
    let token = sealed_token;

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
    vault.put_entity(
        &x,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"payload",
    )?;
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
