//! Relationship-scope filter, demotion, and facet/world conjunction.

use super::*;
use crate::error::RegistryError;

/// The frozen run clock every relationship-scope test queries under,
/// equal to the `learned_at` of every fixture row in this module.
///
/// Same reason as `FACET_NOW`: ONE-1402 read-side decay ages claims
/// against the run's resolved clock, so left unpinned these
/// epoch-second fixture claims floor at `ACCESS_FACTOR_FLOOR` and sort
/// below the neutral non-claim row, turning these relationship
/// visibility contracts into decay arithmetic. At the fixture's own
/// epoch every claim's age — and therefore its decay — is exactly zero.
const RELATIONSHIP_NOW: u64 = 1;

fn relationship_body(rel: Option<EntityId>) -> ClaimBody {
    let mut body = ClaimBody::new(
        "test.relationship_scope",
        crate::claim::ClaimSubject::Entity(crate::test_util::entity(0xD1)),
        rmpv::Value::from("value"),
        0.9,
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Active,
    );
    body.rel = rel;
    body
}

struct RelationshipFixture {
    active_relationship: EntityId,
    claim_other: EntityId,
    claim_active: EntityId,
    claim_core: EntityId,
    event: EntityId,
}

fn setup_relationship_fixture(vault: &Vault) -> Result<RelationshipFixture> {
    let fixture = RelationshipFixture {
        active_relationship: entity_id(0xE0),
        claim_other: entity_id(0xE7),
        claim_active: entity_id(0xE2),
        claim_core: entity_id(0xE3),
        event: entity_id(0xE4),
    };
    let other_relationship = entity_id(0xE5);
    put_entity(
        vault,
        fixture.active_relationship,
        ENTITY_TYPE_RELATIONSHIP,
        1,
        1,
        1,
    )?;
    put_entity(vault, other_relationship, ENTITY_TYPE_RELATIONSHIP, 1, 1, 1)?;

    for (id, vector, relationship) in [
        (
            fixture.claim_other,
            [1.0, 0.0, 0.0, 0.0],
            Some(other_relationship),
        ),
        (
            fixture.claim_active,
            [0.9, 0.1, 0.0, 0.0],
            Some(fixture.active_relationship),
        ),
        (fixture.claim_core, [0.8, 0.2, 0.0, 0.0], None),
    ] {
        let encoded = crate::claim::encode_claim_body(&relationship_body(relationship))?;
        vault
            .batch()
            .put(
                &id,
                ENTITY_TYPE_CLAIM,
                TimeRange { start: 1, end: 1 },
                1,
                &encoded,
            )
            .vector(&id, &vector)
            .commit()?;
    }
    vault
        .batch()
        .put(
            &fixture.event,
            ENTITY_TYPE_EVENT,
            TimeRange { start: 1, end: 1 },
            1,
            b"relationship non-claim",
        )
        .vector(&fixture.event, &[0.7, 0.3, 0.0, 0.0])
        .commit()?;
    Ok(fixture)
}

fn relationship_results(scores: &[ScoredEntity]) -> Vec<(EntityId, f32)> {
    scores.iter().map(|score| (score.id, score.score)).collect()
}

#[derive(Default)]
struct RelationshipRecordingReranker {
    seen: std::sync::Mutex<Vec<(EntityId, Option<EntityId>)>>,
}

impl Reranker for RelationshipRecordingReranker {
    fn id(&self) -> &str {
        "test/relationship-scope-recording@v1"
    }

    fn rerank(&self, _query: &str, candidates: &[RerankCandidate<'_>]) -> Result<Vec<f32>> {
        self.seen.lock().unwrap().extend(
            candidates
                .iter()
                .map(|candidate| (candidate.id, candidate.claim.and_then(|claim| claim.rel))),
        );
        Ok(vec![0.0; candidates.len()])
    }
}

fn put_relationship(vault: &Vault, id: EntityId) -> Result<()> {
    vault.put_entity(
        &id,
        crate::registry::ENTITY_TYPE_RELATIONSHIP,
        TimeRange { start: 1, end: 1 },
        1,
        b"relationship",
    )
}

fn put_relationship_claim(
    vault: &Vault,
    id: EntityId,
    rel: Option<EntityId>,
    vector: [f32; 4],
) -> Result<()> {
    let encoded = crate::claim::encode_claim_body(&relationship_body(rel))?;
    vault
        .batch()
        .put(
            &id,
            ENTITY_TYPE_CLAIM,
            TimeRange { start: 1, end: 1 },
            1,
            &encoded,
        )
        .vector(&id, &vector)
        .commit()
}

fn put_relationship_event(vault: &Vault, id: EntityId, vector: [f32; 4]) -> Result<()> {
    vault
        .batch()
        .put(
            &id,
            ENTITY_TYPE_EVENT,
            TimeRange { start: 1, end: 1 },
            1,
            b"event",
        )
        .vector(&id, &vector)
        .commit()
}

fn setup_relationship_rows(
    vault: &Vault,
) -> Result<(EntityId, EntityId, EntityId, EntityId, EntityId, EntityId)> {
    let active_relationship = crate::test_util::entity(0xE7);
    let other_relationship = crate::test_util::entity(0xE2);
    let other_claim = crate::test_util::entity(0xE3);
    let active_claim = crate::test_util::entity(0xE4);
    let core_claim = crate::test_util::entity(0xE5);
    let event = crate::test_util::entity(0xE6);
    put_relationship(vault, active_relationship)?;
    put_relationship(vault, other_relationship)?;
    put_relationship_claim(
        vault,
        other_claim,
        Some(other_relationship),
        [1.0, 0.0, 0.0, 0.0],
    )?;
    put_relationship_claim(
        vault,
        active_claim,
        Some(active_relationship),
        [0.8, 0.6, 0.0, 0.0],
    )?;
    put_relationship_claim(vault, core_claim, None, [0.6, 0.8, 0.0, 0.0])?;
    put_relationship_event(vault, event, [0.0, 1.0, 0.0, 0.0])?;
    Ok((
        active_relationship,
        other_claim,
        active_claim,
        core_claim,
        event,
        other_relationship,
    ))
}

#[test]
fn relationship_claim_body_key_is_strict_16_byte_binary() -> Result<()> {
    let subject = entity_id(0xD6);
    let body_with_relationship = |relationship: Option<rmpv::Value>| -> Vec<u8> {
        let mut fields = vec![
            (
                rmpv::Value::from("pred"),
                rmpv::Value::from("test.relationship_scope"),
            ),
            (rmpv::Value::from("val"), rmpv::Value::from("value")),
            (rmpv::Value::from("conf"), rmpv::Value::F32(0.9)),
        ];
        if let Some(relationship) = relationship {
            fields.push((rmpv::Value::from("rel"), relationship));
        }
        fields.extend([
            (
                rmpv::Value::from("subj"),
                rmpv::Value::Binary(subject.as_bytes().to_vec()),
            ),
            (rmpv::Value::from("appr"), rmpv::Value::from("auto")),
            (rmpv::Value::from("life"), rmpv::Value::from("active")),
        ]);
        let mut encoded = Vec::new();
        rmpv::encode::write_value(&mut encoded, &rmpv::Value::Map(fields))
            .expect("encode relationship claim body");
        encoded
    };

    let absent = crate::claim::encode_claim_body(&relationship_body(None))?;
    let decoded_absent = crate::claim::decode_claim_body(&absent, true)?;
    assert_eq!(decoded_absent.rel, None);
    let encoded_value = rmpv::decode::read_value(&mut std::io::Cursor::new(&absent))
        .expect("decode encoded relationship claim body");
    assert!(matches!(
        encoded_value,
        rmpv::Value::Map(entries) if entries.iter().all(|(key, _)| key.as_str() != Some("rel"))
    ));

    let relationship = entity_id(0xD8);
    let hand_built =
        body_with_relationship(Some(rmpv::Value::Binary(relationship.as_bytes().to_vec())));
    assert_eq!(
        crate::claim::decode_claim_body(&hand_built, true)?.rel,
        Some(relationship)
    );
    let round_trip = crate::claim::encode_claim_body(&relationship_body(Some(relationship)))?;
    assert_eq!(
        crate::claim::decode_claim_body(&round_trip, true)?.rel,
        Some(relationship)
    );
    for invalid in [
        body_with_relationship(Some(rmpv::Value::Binary(vec![0xD8; 15]))),
        body_with_relationship(Some(rmpv::Value::from("relationship"))),
        body_with_relationship(Some(rmpv::Value::Binary(vec![0; 16]))),
    ] {
        assert_matches!(
            crate::claim::decode_claim_body(&invalid, true),
            Err(Error::InvalidClaimBody(_))
        );
    }
    Ok(())
}

#[test]
fn relationship_absent_is_exact_no_op() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let fixture = setup_relationship_fixture(&vault)?;
    let results = vault
        .query()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
        .with_temporal_now(RELATIONSHIP_NOW)
        .run()?;
    assert_eq!(
        relationship_results(&results),
        vec![
            (fixture.claim_active, 1.0),
            (fixture.claim_core, 1.0),
            (fixture.event, 1.0),
            (fixture.claim_other, 1.0),
        ],
        "an unscoped query must retain the deterministic pre-relationship tie order and scores"
    );
    Ok(())
}

#[test]
fn relationship_filter_matches_facet_visibility_matrix() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let fixture = setup_relationship_fixture(&vault)?;
    let reranker = RelationshipRecordingReranker::default();
    let results = vault
        .query()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
        .with_temporal_now(RELATIONSHIP_NOW)
        .relationship(&fixture.active_relationship, RelMode::Filter)
        .rerank(
            &reranker,
            RerankOptions {
                top_n: 4,
                query: Some("relationship visibility".to_owned()),
            },
        )
        .run()?;
    assert_eq!(
        relationship_results(&results),
        vec![
            (fixture.claim_active, 1.0),
            (fixture.claim_core, 1.0),
            (fixture.event, 1.0),
        ],
        "filter must remove only another-relationship claim without changing retained scores"
    );
    assert_eq!(
        *reranker.seen.lock().unwrap(),
        vec![
            (fixture.claim_active, Some(fixture.active_relationship)),
            (fixture.claim_core, None),
            (fixture.event, None),
        ],
        "reranking must not receive another-relationship claims, while active, core, and non-claim rows remain eligible"
    );
    Ok(())
}

#[test]
fn relationship_filter_excluded_claims_free_result_slots() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let (active_relationship, other_claim, active_claim, core_claim, _event, _other_relationship) =
        setup_relationship_rows(&vault)?;

    let rows = vault
        .query()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
        .with_temporal_now(RELATIONSHIP_NOW)
        .limit(2)
        .relationship(&active_relationship, RelMode::Filter)
        .run()?;

    assert_eq!(
        rows.iter().map(|row| row.id).collect::<Vec<_>>(),
        vec![active_claim, core_claim],
        "the excluded rank-zero relationship claim must not consume a result slot"
    );
    assert!(!rows.iter().any(|row| row.id == other_claim));
    Ok(())
}

#[test]
fn relationship_demote_is_stable_partition() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let active_relationship = crate::test_util::entity(0xE7);
    let other_relationship = crate::test_util::entity(0xE8);
    let other_first = crate::test_util::entity(0xE9);
    let active = crate::test_util::entity(0xEA);
    let other_second = crate::test_util::entity(0xEB);
    let core = crate::test_util::entity(0xEC);
    let event = crate::test_util::entity(0xED);
    put_relationship(&vault, active_relationship)?;
    put_relationship(&vault, other_relationship)?;
    put_relationship_claim(
        &vault,
        other_first,
        Some(other_relationship),
        [1.0, 0.0, 0.0, 0.0],
    )?;
    put_relationship_claim(
        &vault,
        active,
        Some(active_relationship),
        [0.8, 0.6, 0.0, 0.0],
    )?;
    put_relationship_claim(
        &vault,
        other_second,
        Some(other_relationship),
        [0.6, 0.8, 0.0, 0.0],
    )?;
    put_relationship_claim(&vault, core, None, [0.4, 0.916_515_1, 0.0, 0.0])?;
    put_relationship_event(&vault, event, [0.2, 0.979_795_9, 0.0, 0.0])?;

    let baseline = vault
        .query()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
        .with_temporal_now(RELATIONSHIP_NOW)
        .run()?;
    assert_eq!(
        baseline.iter().map(|row| row.id).collect::<Vec<_>>(),
        vec![other_first, active, other_second, core, event],
        "the fixture must begin with interleaved other-relationship and in-scope rows"
    );
    let demoted = vault
        .query()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
        .with_temporal_now(RELATIONSHIP_NOW)
        .relationship(&active_relationship, RelMode::Demote)
        .run()?;
    let baseline_scores = baseline
        .iter()
        .map(|row| (row.id, row.score))
        .collect::<std::collections::HashMap<_, _>>();

    assert_eq!(
        demoted.iter().map(|row| row.id).collect::<Vec<_>>(),
        vec![active, core, event, other_first, other_second],
        "Demote must stably partition the final relevance order"
    );
    for row in &demoted {
        assert_eq!(baseline_scores.get(&row.id), Some(&row.score));
    }
    Ok(())
}

#[test]
fn relationship_demoted_rows_only_fill_remaining_slots() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let (active_relationship, other_claim, active_claim, core_claim, event, _other_relationship) =
        setup_relationship_rows(&vault)?;

    let no_demoted_slot = vault
        .query()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
        .with_temporal_now(RELATIONSHIP_NOW)
        .limit(2)
        .relationship(&active_relationship, RelMode::Demote)
        .run()?;
    assert_eq!(
        no_demoted_slot.iter().map(|row| row.id).collect::<Vec<_>>(),
        vec![active_claim, core_claim],
        "demoted rows cannot displace available in-scope rows"
    );

    let one_demoted_slot = vault
        .query()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
        .with_temporal_now(RELATIONSHIP_NOW)
        .limit(4)
        .relationship(&active_relationship, RelMode::Demote)
        .run()?;
    assert_eq!(
        one_demoted_slot
            .iter()
            .map(|row| row.id)
            .collect::<Vec<_>>(),
        vec![active_claim, core_claim, event, other_claim],
        "the first demoted row fills only the slot after every in-scope row"
    );
    Ok(())
}

#[test]
fn relationship_query_rejects_invalid_active_relationship_typed() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let candidate = crate::test_util::entity(0xE7);
    put_entity(&vault, candidate, ENTITY_TYPE_EVENT, 1, 1, 1)?;
    vault
        .batch()
        .vector(&candidate, &[1.0, 0.0, 0.0, 0.0])
        .commit()?;

    let missing = crate::test_util::entity(0xE2);
    let err = vault
        .query()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 4)
        .relationship(&missing, RelMode::Filter)
        .run()
        .expect_err("a missing active relationship must fail closed");
    assert!(
        matches!(
            err,
            Error::Registry(RegistryError::InvalidRelationship { found: None, .. })
        ),
        "expected InvalidRelationship {{ found: None }}, got {err:?}"
    );

    let turn = crate::test_util::entity(0xE3);
    put_entity(&vault, turn, ENTITY_TYPE_TURN, 1, 1, 1)?;
    let err = vault
        .query()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 4)
        .relationship(&turn, RelMode::Filter)
        .run()
        .expect_err("a TURN cannot be the active relationship");
    assert!(
        matches!(err, Error::Registry(RegistryError::InvalidRelationship { found: Some(t), .. }) if t == ENTITY_TYPE_TURN),
        "expected InvalidRelationship {{ found: Some(TURN) }}, got {err:?}"
    );

    let relationship = crate::test_util::entity(0xE4);
    put_entity(&vault, relationship, ENTITY_TYPE_RELATIONSHIP, 1, 1, 1)?;
    let results = vault
        .query()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 4)
        .relationship(&relationship, RelMode::Filter)
        .run()?;
    assert_eq!(
        results.iter().map(|row| row.id).collect::<Vec<_>>(),
        vec![candidate]
    );
    Ok(())
}

#[test]
fn relationship_facet_world_four_quadrants_compose_conjunctively() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let active_facet = crate::test_util::entity(0xE5);
    let other_facet = crate::test_util::entity(0xE6);
    let active_relationship = crate::test_util::entity(0xE7);
    let other_relationship = crate::test_util::entity(0xE8);
    let active_world = crate::test_util::entity(0xE9);
    let other_world = crate::test_util::entity(0xEA);
    put_entity(&vault, active_facet, ENTITY_TYPE_FACET, 1, 1, 1)?;
    put_entity(&vault, other_facet, ENTITY_TYPE_FACET, 1, 1, 1)?;
    put_entity(
        &vault,
        active_relationship,
        ENTITY_TYPE_RELATIONSHIP,
        1,
        1,
        1,
    )?;
    put_entity(
        &vault,
        other_relationship,
        ENTITY_TYPE_RELATIONSHIP,
        1,
        1,
        1,
    )?;

    let core = crate::test_util::entity(0xEB);
    let facet_only = crate::test_util::entity(0xEC);
    let relationship_only = crate::test_util::entity(0xED);
    let both = crate::test_util::entity(0xEE);
    let wrong_facet = crate::test_util::entity(0xEF);
    let wrong_relationship = crate::test_util::entity(0xF0);
    let wrong_world = crate::test_util::entity(0xF1);
    let cases = [
        (core, None, None, None),
        (facet_only, Some(active_facet), None, Some(active_world)),
        (
            relationship_only,
            None,
            Some(active_relationship),
            Some(active_world),
        ),
        (
            both,
            Some(active_facet),
            Some(active_relationship),
            Some(active_world),
        ),
        (
            wrong_facet,
            Some(other_facet),
            Some(active_relationship),
            Some(active_world),
        ),
        (
            wrong_relationship,
            Some(active_facet),
            Some(other_relationship),
            Some(active_world),
        ),
        (
            wrong_world,
            Some(active_facet),
            Some(active_relationship),
            Some(other_world),
        ),
    ];
    for (index, (id, facet, relationship, world)) in cases.into_iter().enumerate() {
        let mut body = relationship_body(relationship);
        body.world = world;
        let encoded = crate::claim::encode_claim_body(&body)?;
        vault
            .batch()
            .put(
                &id,
                ENTITY_TYPE_CLAIM,
                TimeRange { start: 1, end: 1 },
                1,
                &encoded,
            )
            .vector(
                &id,
                &[1.0 - index as f32 * 0.05, index as f32 * 0.05, 0.0, 0.0],
            )
            .commit()?;
        if let Some(facet) = facet {
            vault.put_edge(&id, EdgeKind::FacetOf, &facet, 0.7)?;
        }
    }

    for (use_facet, use_relationship, expected) in [
        (
            false,
            false,
            vec![
                core,
                facet_only,
                relationship_only,
                both,
                wrong_facet,
                wrong_relationship,
            ],
        ),
        (
            true,
            false,
            vec![
                core,
                facet_only,
                relationship_only,
                both,
                wrong_relationship,
            ],
        ),
        (
            false,
            true,
            vec![core, facet_only, relationship_only, both, wrong_facet],
        ),
        (true, true, vec![core, facet_only, relationship_only, both]),
    ] {
        let mut query = vault
            .query()
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 16)
            .world(WorldScope::World(active_world));
        if use_facet {
            query = query.facet(&active_facet, FacetMode::Strict);
        }
        if use_relationship {
            query = query.relationship(&active_relationship, RelMode::Filter);
        }
        let visible: std::collections::HashSet<_> = query.run()?.iter().map(|row| row.id).collect();
        assert_eq!(
            visible,
            expected
                .into_iter()
                .collect::<std::collections::HashSet<_>>(),
            "facet={use_facet}, relationship={use_relationship} must have its exact membership matrix"
        );
    }
    Ok(())
}

#[test]
fn relationship_filter_covers_candidate_and_post_fusion_paths() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let active = crate::test_util::entity(0xF2);
    let other = crate::test_util::entity(0xF3);
    put_entity(&vault, active, ENTITY_TYPE_RELATIONSHIP, 1, 1, 1)?;
    put_entity(&vault, other, ENTITY_TYPE_RELATIONSHIP, 1, 1, 1)?;
    let malformed_probe_only = crate::test_util::entity(0xF4);
    let mut pairs = Vec::new();

    put_relationship_claim(
        &vault,
        malformed_probe_only,
        Some(other),
        [0.0, 0.0, 0.0, 0.0],
    )?;
    let mut junk = Vec::new();
    rmpv::encode::write_value(&mut junk, &rmpv::Value::from("junk")).expect("msgpack encode");
    overwrite_entity_record(&vault, &malformed_probe_only, ENTITY_TYPE_CLAIM, &junk)?;
    vault
        .batch()
        .text(
            &malformed_probe_only,
            &[("body", "relationshipgateprefixdead")],
        )
        .commit()?;

    // Each prefix expansion has a high-frequency out-of-scope row and a
    // lower-frequency active row. Candidate filtering must remove the former before
    // the widened channel is truncated to eight entries.
    for (index, (other_claim, active_claim)) in (0xB0..=0xB8)
        .map(crate::test_util::entity)
        .zip((0xC0..=0xC8).map(crate::test_util::entity))
        .enumerate()
    {
        let token = format!("relationshipgateprefix{index:02}");
        let repeated = vec![token.as_str(); 16].join(" ");
        put_relationship_claim(&vault, other_claim, Some(other), [0.0, 0.0, 0.0, 0.0])?;
        vault
            .batch()
            .text(&other_claim, &[("body", &repeated)])
            .commit()?;
        put_relationship_claim(&vault, active_claim, Some(active), [0.0, 0.0, 0.0, 0.0])?;
        vault
            .batch()
            .text(&active_claim, &[("body", &token)])
            .commit()?;
        pairs.push((other_claim, active_claim));
    }
    let (other_claim, active_claim) = pairs[0];
    let active_claims: std::collections::HashSet<_> = pairs
        .iter()
        .map(|(_, active_claim)| *active_claim)
        .collect();

    // A prefix-only probe makes BM25 widen from the requested eight slots to every
    // indexed document. The malformed first expansion must be rejected by the claim
    // gate, and the candidate truncation must reject every other-relationship row.
    let filter_probe = ClaimProbeReranker::default();
    let filter_trace = captured_retrieval_trace(
        &vault,
        vault
            .query()
            .search_text("relationshipgateprefix", 8)
            .relationship(&active, RelMode::Filter)
            .rerank(&filter_probe, RerankOptions::default()),
    )?;
    let text_channel = filter_trace
        .per_channel
        .iter()
        .find(|channel| channel.signal == RetrievalSignal::Text)
        .expect("captured text channel");
    let candidate_ids: std::collections::HashSet<_> = text_channel
        .candidates
        .iter()
        .map(|candidate| EntityId::from_bytes(candidate.result_id).expect("trace entity id"))
        .collect();
    assert_eq!(
        candidate_ids.len(),
        8,
        "candidate truncation must fill its requested slots"
    );
    assert!(
        candidate_ids.is_subset(&active_claims),
        "candidate truncation must retain only active-relationship prefix expansions"
    );
    let reranked_ids: std::collections::HashSet<_> = filter_probe
        .seen
        .lock()
        .unwrap()
        .iter()
        .map(|(id, has_claim)| {
            assert!(*has_claim, "candidate claims must decode before rerank");
            *id
        })
        .collect();
    assert_eq!(reranked_ids, candidate_ids);
    assert!(
        reranked_ids.is_subset(&active_claims),
        "the candidate door must exclude other relationships before rerank"
    );

    // Exact postings do not take the widened-truncation path, so this separately
    // demonstrates that the pre-rerank Filter backstop removes the other row.
    vault
        .batch()
        .text(&other_claim, &[("backstop", "relationshipbackstop")])
        .text(&active_claim, &[("backstop", "relationshipbackstop")])
        .commit()?;
    let backstop_probe = ClaimProbeReranker::default();
    let backstop = vault
        .query()
        .search_text("relationshipbackstop", 20)
        .relationship(&active, RelMode::Filter)
        .rerank(&backstop_probe, RerankOptions::default())
        .run()?;
    assert_eq!(
        backstop.iter().map(|row| row.id).collect::<Vec<_>>(),
        vec![active_claim]
    );
    assert_eq!(
        backstop_probe.seen.lock().unwrap().clone(),
        vec![(active_claim, true)]
    );

    let demote_probe = ClaimProbeReranker::default();
    let demoted = vault
        .query()
        .search_text("relationshipbackstop", 20)
        .relationship(&active, RelMode::Demote)
        .rerank(&demote_probe, RerankOptions::default())
        .run()?;
    let demote_seen: std::collections::HashSet<_> =
        demote_probe.seen.lock().unwrap().iter().copied().collect();
    assert_eq!(
        demote_seen,
        [(other_claim, true), (active_claim, true)]
            .into_iter()
            .collect::<std::collections::HashSet<_>>(),
        "Demote must retain other-relationship bodies through rerank"
    );
    assert_eq!(
        demoted.iter().map(|row| row.id).collect::<Vec<_>>(),
        vec![active_claim, other_claim]
    );
    Ok(())
}

#[test]
fn relationship_scope_changes_retrieval_fork_hash() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let active = crate::test_util::entity(0xE7);
    let alternate = crate::test_util::entity(0xE2);
    let candidate = crate::test_util::entity(0xE3);
    put_entity(&vault, active, ENTITY_TYPE_RELATIONSHIP, 1, 1, 1)?;
    put_entity(&vault, alternate, ENTITY_TYPE_RELATIONSHIP, 1, 1, 1)?;
    put_text(&vault, candidate, "relationship fork hash needle")?;

    let same_query = || {
        vault
            .query()
            .search_text("relationship fork hash needle", 10)
            .relationship(&active, RelMode::Filter)
    };
    let first = captured_retrieval_trace(&vault, same_query())?;
    let repeat = captured_retrieval_trace(&vault, same_query())?;
    let changed_relationship = captured_retrieval_trace(
        &vault,
        vault
            .query()
            .search_text("relationship fork hash needle", 10)
            .relationship(&alternate, RelMode::Filter),
    )?;
    let changed_mode = captured_retrieval_trace(
        &vault,
        vault
            .query()
            .search_text("relationship fork hash needle", 10)
            .relationship(&active, RelMode::Demote),
    )?;

    assert_eq!(first.fork_hash, repeat.fork_hash);
    assert_ne!(first.fork_hash, changed_relationship.fork_hash);
    assert_ne!(first.fork_hash, changed_mode.fork_hash);
    Ok(())
}

#[test]
fn relationship_filter_wipe_reports_filter_matched_none() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let active = crate::test_util::entity(0xE4);
    let other = crate::test_util::entity(0xE5);
    let excluded_claim = crate::test_util::entity(0xE6);
    put_entity(&vault, active, ENTITY_TYPE_RELATIONSHIP, 1, 1, 1)?;
    put_entity(&vault, other, ENTITY_TYPE_RELATIONSHIP, 1, 1, 1)?;
    vault
        .batch()
        .put(
            &excluded_claim,
            ENTITY_TYPE_CLAIM,
            TimeRange { start: 1, end: 1 },
            1,
            &crate::claim::encode_claim_body(&relationship_body(Some(other)))?,
        )
        .text(
            &excluded_claim,
            &[("body", "relationship filter wipe needle")],
        )
        .commit()?;

    let output = vault
        .query()
        .search_text("relationship filter wipe needle", 10)
        .relationship(&active, RelMode::Filter)
        .capture_retrieval_trace(true)
        .run_with_telemetry()?;
    assert!(output.value.is_empty());
    let run_id = output.run_id.expect("candidate query records telemetry");
    let run = vault
        .retrieval_run(run_id)?
        .expect("telemetry row remains available");
    assert_eq!(run.empty_reason.as_deref(), Some("FilterMatchedNone"));
    assert_ne!(run.empty_reason.as_deref(), Some("BelowThreshold"));
    assert!(
        run.trace
            .as_ref()
            .expect("telemetry trace is captured for a filter wipe")
            .final_stage
            .candidates
            .is_empty(),
        "the pre-limit candidate count is zero after the destructive filter"
    );
    Ok(())
}

#[test]
fn relationship_filter_widens_strict_text_channel() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let active = crate::test_util::entity(0xE7);
    let other = crate::test_util::entity(0xE8);
    let other_claim = crate::test_util::entity(0xE9);
    let matching_claim = crate::test_util::entity(0xEA);
    put_entity(&vault, active, ENTITY_TYPE_RELATIONSHIP, 1, 1, 1)?;
    put_entity(&vault, other, ENTITY_TYPE_RELATIONSHIP, 1, 1, 1)?;
    for (id, rel, text) in [
        (
            other_claim,
            other,
            "scopewidenneedle scopewidenneedle scopewidenneedle",
        ),
        (matching_claim, active, "scopewidenneedle"),
    ] {
        vault
            .batch()
            .put(
                &id,
                ENTITY_TYPE_CLAIM,
                TimeRange { start: 1, end: 1 },
                1,
                &crate::claim::encode_claim_body(&relationship_body(Some(rel)))?,
            )
            .text(&id, &[("body", text)])
            .commit()?;
    }

    let results = vault
        .query()
        .search_text("scopewidenneedle", 1)
        .relationship(&active, RelMode::Filter)
        .run()?;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, matching_claim);
    Ok(())
}
