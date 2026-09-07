//! ONE-1388 adapter tests. Existing scope and ranking suites stay separate.

#[path = "authority_corpus_tests.rs"]
mod authority_corpus_tests;

use std::collections::BTreeSet;

use rmpv::Value;

use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, ScopedReadActorKey,
};
use crate::gate::{RetrievalFilter, narrow_retrieval_filter, resolve_policy_manifest};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_TURN};
use crate::{EntityId, Result, Vault};

use super::tests::{entity_id, open_test_vault};

fn map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(key, value)| (Value::from(key), value))
            .collect(),
    )
}

fn read_grant(actor_ref: &str, scope: Value) -> Value {
    map(vec![
        ("actor_ref", Value::from(actor_ref)),
        ("effector", Value::from("core:read")),
        ("receipt_required", Value::Boolean(false)),
        ("scope", scope),
    ])
}

fn install_grant(vault: &Vault, scope: Value) -> Result<()> {
    install_grants(vault, vec![read_grant("authority-reader", scope)])
}

fn install_grants(vault: &Vault, grants: Vec<Value>) -> Result<()> {
    let bytes = crate::gate::default_policy_manifest();
    let Value::Map(mut entries) = rmpv::decode::read_value(&mut bytes.as_slice()).unwrap() else {
        panic!("manifest map");
    };
    entries.retain(|(key, _)| key.as_str() != Some("scoped_grants"));
    entries.push((Value::from("scoped_grants"), Value::Array(grants)));
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &Value::Map(entries)).unwrap();
    crate::test_util::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id()?,
        &bytes,
    )
}

fn claim() -> ClaimBody {
    let mut body = ClaimBody::new(
        "test.authority",
        ClaimSubject::Entity(entity_id(0xF0)),
        Value::from("v"),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    body.salience = Some(0.9);
    body.scope = Some(map(vec![("sensitivity", Value::from(1))]));
    body
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(super) fn put_claim(vault: &Vault, id: EntityId, body: &ClaimBody) -> Result<()> {
        vault
            .batch()
            .put_replicated(
                &id,
                ENTITY_TYPE_CLAIM,
                crate::temporal::TimeRange { start: 1, end: 1 },
                1,
                &crate::claim::encode_claim_body(body)?,
            )
            .text(&id, &[("body", "authorityneedle")])
            .vector(&id, &[1.0, 0.0, 0.0, 0.0])
            .commit()
    }
}
use tests::put_claim;

fn reader(vault: &Vault) -> crate::claim::ScopedRead<'_> {
    vault.scoped_read(ScopedReadActorKey::new("authority-reader").unwrap())
}

fn resolve_reader_filter(
    vault: &Vault,
    requested: Option<&RetrievalFilter>,
) -> Result<crate::gate::ResolvedRetrievalFilter> {
    let txn = vault.store.env.read_txn()?;
    let policy = resolve_policy_manifest(&vault.store, &txn)?;
    narrow_retrieval_filter(
        &policy.retrieval_floor_for_actor(Some(reader(vault).actor_key())),
        requested,
    )
}

fn assert_search_ids(
    read: &crate::claim::ScopedRead<'_>,
    requested: Option<&RetrievalFilter>,
    expected: &[EntityId],
) -> Result<()> {
    for hits in [
        read.search_text("authorityneedle", 64, requested)?,
        read.search_vector(&[1.0, 0.0, 0.0, 0.0], 64, requested)?,
        read.search("authorityneedle", &[1.0, 0.0, 0.0, 0.0], 64, requested)?,
    ] {
        assert_eq!(hits.len(), expected.len());
        assert_eq!(
            hits.iter().map(|hit| hit.id).collect::<BTreeSet<_>>(),
            expected.iter().copied().collect::<BTreeSet<_>>()
        );
    }
    Ok(())
}

#[test]
fn authority_enforcement_before_final_limit() -> Result<()> {
    let (_tmp, vault) = open_test_vault();
    let mut rejected = Vec::new();
    let mut high_sensitivity = claim();
    high_sensitivity.scope = Some(map(vec![("sensitivity", Value::from(3))]));
    rejected.push(high_sensitivity);
    let mut low_confidence = claim();
    low_confidence.confidence = 0.1;
    rejected.push(low_confidence);
    let mut low_salience = claim();
    low_salience.salience = Some(0.1);
    rejected.push(low_salience);
    let mut no_salience = claim();
    no_salience.salience = None;
    rejected.push(no_salience);
    let mut stale = claim();
    stale.stale = true;
    rejected.push(stale);
    for (index, body) in rejected.iter().enumerate() {
        put_claim(&vault, entity_id(0x20 + index as u8), body)?;
    }
    let allowed = entity_id(0x40);
    put_claim(&vault, allowed, &claim())?;
    vault
        .batch()
        .vector(&allowed, &[0.8, 0.6, 0.0, 0.0])
        .commit()?;
    let baseline = vault
        .query()
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 32)
        .limit(1)
        .run()?;
    assert_eq!(baseline.len(), 1);
    assert_ne!(
        baseline[0].id, allowed,
        "excluded rows must outrank the allowed row"
    );
    let request = RetrievalFilter {
        entity_types: Some(BTreeSet::from([ENTITY_TYPE_CLAIM])),
        max_sensitivity_band: Some(1),
        min_confidence: Some(0.8),
        min_salience: Some(0.8),
        ..RetrievalFilter::default()
    };
    let txn = vault.store.env.read_txn()?;
    let policy = resolve_policy_manifest(&vault.store, &txn)?;
    let filter = narrow_retrieval_filter(&policy.retrieval_floor_for_actor(None), Some(&request))?;
    drop(txn);
    let hits = vault
        .query()
        .authority_filter(filter)
        .search_vector(&[1.0, 0.0, 0.0, 0.0], 32)
        .limit(1)
        .run()?;
    assert_eq!(
        hits.iter().map(|hit| hit.id).collect::<Vec<_>>(),
        vec![allowed]
    );
    Ok(())
}

#[test]
fn authority_unset_and_overask_return_only_floor_rows() -> Result<()> {
    let (_tmp, vault) = open_test_vault();
    install_grant(
        &vault,
        map(vec![
            (
                "entity_types",
                Value::Array(vec![Value::from(ENTITY_TYPE_CLAIM)]),
            ),
            ("max_sensitivity_band", Value::from(1)),
            ("include_stale", Value::Boolean(false)),
            ("min_confidence", Value::F32(0.8)),
            ("min_salience", Value::F32(0.8)),
            ("world_ref", Value::from("base")),
        ]),
    )?;
    let allowed = entity_id(0x50);
    put_claim(&vault, allowed, &claim())?;
    let mut denied = claim();
    denied.confidence = 0.1;
    put_claim(&vault, entity_id(0x51), &denied)?;
    let mut wrong_world = claim();
    wrong_world.world = Some(entity_id(0xF1));
    put_claim(&vault, entity_id(0x52), &wrong_world)?;
    let overask = RetrievalFilter {
        entity_types: Some(BTreeSet::from([ENTITY_TYPE_CLAIM, ENTITY_TYPE_TURN])),
        max_sensitivity_band: Some(3),
        include_stale: Some(true),
        min_confidence: Some(0.0),
        min_salience: Some(0.0),
    };
    for request in [None, Some(&overask)] {
        let read = reader(&vault);
        for hits in [
            read.search_text("authorityneedle", 1, request)?,
            read.search_vector(&[1.0, 0.0, 0.0, 0.0], 1, request)?,
            read.search("authorityneedle", &[1.0, 0.0, 0.0, 0.0], 1, request)?,
        ] {
            assert_eq!(
                hits.iter().map(|hit| hit.id).collect::<Vec<_>>(),
                vec![allowed]
            );
        }
    }
    Ok(())
}

#[test]
fn authority_empty_read_plane_preserves_default_but_present_unmatched_grants_deny() -> Result<()> {
    let (_tmp, vault) = open_test_vault();
    let allowed = entity_id(0x60);
    put_claim(&vault, allowed, &claim())?;
    let mut stale = claim();
    stale.stale = true;
    put_claim(&vault, entity_id(0x61), &stale)?;
    let overask = RetrievalFilter {
        include_stale: Some(true),
        ..RetrievalFilter::default()
    };
    let stricter = RetrievalFilter {
        min_confidence: Some(1.0),
        ..RetrievalFilter::default()
    };
    assert_search_ids(&reader(&vault), None, &[allowed])?;
    for grants in [
        Vec::new(),
        vec![map(vec![("effector", Value::from("core:*"))])],
        vec![map(vec![("effector", Value::from("oneiron:read"))])],
        vec![map(vec![("effector", Value::from("core:write"))])],
    ] {
        install_grants(&vault, grants)?;
        let read = reader(&vault);
        assert_search_ids(&read, None, &[allowed])?;
        assert_search_ids(&read, Some(&overask), &[allowed])?;
        assert_search_ids(&read, Some(&stricter), &[])?;
    }
    install_grants(&vault, vec![read_grant("other-reader", Value::Nil)])?;
    assert_search_ids(&reader(&vault), None, &[])?;
    let other = vault.scoped_read(ScopedReadActorKey::new("other-reader").unwrap());
    assert_search_ids(&other, None, &[allowed])?;
    Ok(())
}

#[test]
fn authority_malformed_grants_and_invalid_requests_fail_closed() -> Result<()> {
    let (_tmp, vault) = open_test_vault();
    put_claim(&vault, entity_id(0x60), &claim())?;
    let invalid = RetrievalFilter {
        min_salience: Some(f32::NAN),
        ..RetrievalFilter::default()
    };
    for scope in [
        map(vec![("min_confidence", Value::from("bad"))]),
        Value::Nil,
    ] {
        let malformed = scope != Value::Nil;
        install_grant(&vault, scope)?;
        let read = reader(&vault);
        if malformed {
            assert_search_ids(&read, None, &[])?;
        }
        assert!(
            read.search_text("authorityneedle", 0, Some(&invalid))
                .is_err()
        );
        assert!(read.search_vector(&[], 0, Some(&invalid)).is_err());
        assert!(
            read.search("authorityneedle", &[], 0, Some(&invalid))
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn authority_stale_is_explicit_and_nonclaims_only_obey_type() -> Result<()> {
    let (_tmp, vault) = open_test_vault();
    install_grant(&vault, map(vec![("include_stale", Value::Boolean(true))]))?;
    let stale_id = entity_id(0x70);
    let mut body = claim();
    body.stale = true;
    put_claim(&vault, stale_id, &body)?;
    let nonclaim = entity_id(0x71);
    vault
        .batch()
        .put(
            &nonclaim,
            ENTITY_TYPE_TURN,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"opaque non-claim body",
        )
        .text(&nonclaim, &[("body", "authorityneedle")])
        .commit()?;
    let owner_hits = vault.query().search_text("authorityneedle", 10).run()?;
    assert!(!owner_hits.iter().any(|hit| hit.id == stale_id));
    let hits = reader(&vault).search_text("authorityneedle", 10, None)?;
    assert!(hits.iter().any(|hit| hit.id == stale_id));
    let request = RetrievalFilter {
        max_sensitivity_band: Some(0),
        include_stale: Some(false),
        min_confidence: Some(1.0),
        min_salience: Some(1.0),
        ..RetrievalFilter::default()
    };
    let hits = reader(&vault).search_text("authorityneedle", 1, Some(&request))?;
    assert_eq!(
        hits.iter().map(|hit| hit.id).collect::<Vec<_>>(),
        vec![nonclaim]
    );
    let no_types = RetrievalFilter {
        entity_types: Some(BTreeSet::new()),
        ..RetrievalFilter::default()
    };
    assert!(
        reader(&vault)
            .search_text("authorityneedle", 1, Some(&no_types))?
            .is_empty()
    );
    Ok(())
}

#[test]
fn authority_disjoint_type_grants_are_alternatives_not_global_restrictions() -> Result<()> {
    let (_tmp, vault) = open_test_vault();
    let claim_id = entity_id(0x80);
    let turn_id = entity_id(0x81);
    put_claim(&vault, claim_id, &claim())?;
    vault
        .batch()
        .put(
            &turn_id,
            ENTITY_TYPE_TURN,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"opaque non-claim body",
        )
        .text(&turn_id, &[("body", "authorityneedle")])
        .vector(&turn_id, &[1.0, 0.0, 0.0, 0.0])
        .commit()?;
    let claim_grant = read_grant(
        "authority-reader",
        map(vec![(
            "entity_types",
            Value::Array(vec![Value::from(ENTITY_TYPE_CLAIM)]),
        )]),
    );
    let turn_grant = read_grant(
        "authority-reader",
        map(vec![
            (
                "entity_types",
                Value::Array(vec![Value::from(ENTITY_TYPE_TURN)]),
            ),
            ("max_sensitivity_band", Value::from(0)),
            ("min_confidence", Value::F32(1.0)),
            ("min_salience", Value::F32(1.0)),
        ]),
    );
    let only_claims = RetrievalFilter {
        entity_types: Some(BTreeSet::from([ENTITY_TYPE_CLAIM])),
        ..RetrievalFilter::default()
    };
    for rows in [
        vec![claim_grant.clone(), turn_grant.clone()],
        vec![turn_grant.clone(), claim_grant],
    ] {
        install_grants(&vault, rows)?;
        assert_search_ids(&reader(&vault), None, &[claim_id, turn_id])?;
        assert_search_ids(&reader(&vault), Some(&only_claims), &[claim_id])?;
    }
    // An unrestricted type alternative is the union identity for all types,
    // not an intersection that inherits the TURN-only row's numeric limits.
    install_grants(
        &vault,
        vec![turn_grant, read_grant("authority-reader", Value::Nil)],
    )?;
    assert_search_ids(&reader(&vault), None, &[claim_id, turn_id])?;
    Ok(())
}

#[test]
fn authority_numeric_alternatives_keep_complete_scope_and_request_conjuncts() -> Result<()> {
    let (_tmp, vault) = open_test_vault();
    let world_a = entity_id(0xE3);
    let world_b = entity_id(0xE2);
    let corpus_a = crate::corpus::CorpusId::from_entity_id(entity_id(0xE4));
    let corpus_b = crate::corpus::CorpusId::from_entity_id(entity_id(0xE5));
    let scope_a = map(vec![
        ("relationship", Value::from("alpha")),
        ("facet", Value::from("facet-a")),
        ("sensitivity", Value::from(1)),
    ]);
    let scope_b = map(vec![
        ("relationship", Value::from("beta")),
        ("facet", Value::from("facet-b")),
        ("sensitivity", Value::from(3)),
    ]);
    let scope_a = crate::corpus::scope_with_corpus_id(Some(scope_a), corpus_a)?;
    let scope_b = crate::corpus::scope_with_corpus_id(Some(scope_b), corpus_b)?;
    let first = read_grant(
        "authority-reader",
        map(vec![
            ("world_ref", Value::from(world_a.to_hex())),
            ("claim_scope", scope_a.clone()),
            ("facet", Value::from("facet-a")),
            ("max_sensitivity_band", Value::from(1)),
            ("include_stale", Value::Boolean(false)),
            ("min_confidence", Value::F32(0.8)),
            ("min_salience", Value::F32(0.2)),
        ]),
    );
    let second = read_grant(
        "authority-reader",
        map(vec![
            ("world_ref", Value::from(world_b.to_hex())),
            ("claim_scope", scope_b.clone()),
            ("facet", Value::from("facet-b")),
            ("max_sensitivity_band", Value::from(3)),
            ("include_stale", Value::Boolean(true)),
            ("min_confidence", Value::F32(0.2)),
            ("min_salience", Value::F32(0.8)),
        ]),
    );
    let mut a = claim();
    a.world = Some(world_a);
    a.scope = Some(scope_a);
    a.salience = Some(0.25);
    let mut b = claim();
    b.world = Some(world_b);
    b.scope = Some(scope_b);
    b.confidence = 0.25;
    b.stale = true;
    let a_id = entity_id(0x90);
    let b_id = entity_id(0x91);
    put_claim(&vault, a_id, &a)?;
    put_claim(&vault, b_id, &b)?;

    // Each decoy passes the union envelope but no complete grant. In
    // particular, B's weaker confidence/stale limits cannot widen A's scope.
    let mut low_confidence_a = a.clone();
    low_confidence_a.confidence = b.confidence;
    let mut low_salience_b = b.clone();
    low_salience_b.salience = a.salience;
    let mut stale_a = a.clone();
    stale_a.stale = true;
    let mut wrong_world_a = a.clone();
    wrong_world_a.world = b.world;
    let mut wrong_facet_a = a.clone();
    wrong_facet_a.scope = Some(map(vec![
        ("relationship", Value::from("alpha")),
        ("facet", Value::from("facet-b")),
        ("sensitivity", Value::from(1)),
    ]));
    wrong_facet_a.scope = Some(crate::corpus::scope_with_corpus_id(
        wrong_facet_a.scope,
        corpus_a,
    )?);
    let mut wrong_corpus_a = a.clone();
    wrong_corpus_a.scope = Some(crate::corpus::scope_with_corpus_id(
        wrong_corpus_a.scope,
        corpus_b,
    )?);
    let mut wrong_relationship_a = a;
    wrong_relationship_a.scope = Some(map(vec![
        ("relationship", Value::from("beta")),
        ("facet", Value::from("facet-a")),
        ("sensitivity", Value::from(1)),
    ]));
    wrong_relationship_a.scope = Some(crate::corpus::scope_with_corpus_id(
        wrong_relationship_a.scope,
        corpus_a,
    )?);
    for (index, body) in [
        low_confidence_a,
        low_salience_b,
        stale_a,
        wrong_world_a,
        wrong_facet_a,
        wrong_relationship_a,
        wrong_corpus_a,
    ]
    .iter()
    .enumerate()
    {
        put_claim(&vault, entity_id(0x92 + index as u8), body)?;
    }
    let overask = RetrievalFilter {
        max_sensitivity_band: Some(3),
        include_stale: Some(true),
        min_confidence: Some(0.0),
        min_salience: Some(0.0),
        ..RetrievalFilter::default()
    };
    let confident = RetrievalFilter {
        min_confidence: Some(0.8),
        ..RetrievalFilter::default()
    };
    let salient = RetrievalFilter {
        min_salience: Some(0.8),
        ..RetrievalFilter::default()
    };
    let both = RetrievalFilter {
        min_confidence: Some(0.8),
        min_salience: Some(0.8),
        ..RetrievalFilter::default()
    };
    let fresh = RetrievalFilter {
        include_stale: Some(false),
        ..RetrievalFilter::default()
    };
    let low_sensitivity = RetrievalFilter {
        max_sensitivity_band: Some(1),
        ..RetrievalFilter::default()
    };
    for rows in [vec![first.clone(), second.clone()], vec![second, first]] {
        install_grants(&vault, rows)?;
        let read = reader(&vault);
        assert_search_ids(&read, None, &[a_id, b_id])?;
        assert_search_ids(&read, Some(&overask), &[a_id, b_id])?;
        assert_search_ids(&read, Some(&confident), &[a_id])?;
        assert_search_ids(&read, Some(&salient), &[b_id])?;
        assert_search_ids(&read, Some(&both), &[])?;
        assert_search_ids(&read, Some(&fresh), &[a_id])?;
        assert_search_ids(&read, Some(&low_sensitivity), &[a_id])?;
    }
    Ok(())
}

#[test]
fn authority_malformed_matching_grant_does_not_veto_or_widen_valid_alternatives() -> Result<()> {
    let (_tmp, vault) = open_test_vault();
    let allowed = entity_id(0xA0);
    let low_confidence = entity_id(0xA7);
    let wrong_world = entity_id(0xA8);
    put_claim(&vault, allowed, &claim())?;
    let mut low = claim();
    low.confidence = 0.1;
    put_claim(&vault, low_confidence, &low)?;
    let mut world = claim();
    world.world = Some(entity_id(0xE3));
    put_claim(&vault, wrong_world, &world)?;
    let valid = read_grant(
        "authority-reader",
        map(vec![
            ("world_ref", Value::from("base")),
            ("min_confidence", Value::F32(0.8)),
        ]),
    );
    let other = read_grant("other-reader", Value::Nil);
    for malformed_scope in [
        map(vec![("min_confidence", Value::F64(f64::NAN))]),
        map(vec![("min_salience", Value::from("bad"))]),
        map(vec![
            ("include_stale", Value::Boolean(true)),
            ("include_stale", Value::Boolean(false)),
        ]),
        Value::from("not a scope map"),
    ] {
        let bad = read_grant("authority-reader", malformed_scope);
        for rows in [
            vec![bad.clone(), valid.clone(), other.clone()],
            vec![other.clone(), valid.clone(), bad],
        ] {
            install_grants(&vault, rows)?;
            assert_search_ids(&reader(&vault), None, &[allowed])?;
            let other_read = vault.scoped_read(ScopedReadActorKey::new("other-reader").unwrap());
            assert_search_ids(&other_read, None, &[allowed, low_confidence, wrong_world])?;
        }
    }
    Ok(())
}

#[test]
fn authority_bounded_candidates_inherit_resolved_stale_and_keep_filters() -> Result<()> {
    use super::filters::pipeline_candidate_matches_filters_and_gate;
    use super::types::{
        ClaimStatusGateCache, EntityMetadataCache, PipelineFilterConfig, WorldScope,
    };

    let (_tmp, vault) = open_test_vault();
    install_grant(
        &vault,
        map(vec![
            (
                "entity_types",
                Value::Array(vec![Value::from(ENTITY_TYPE_CLAIM)]),
            ),
            ("include_stale", Value::Boolean(true)),
        ]),
    )?;
    let stale_id = entity_id(0xB1);
    let excluded_id = entity_id(0xB2);
    let turn_id = entity_id(0xB3);
    let mut stale = claim();
    stale.stale = true;
    put_claim(&vault, stale_id, &stale)?;
    put_claim(&vault, excluded_id, &stale)?;
    vault
        .batch()
        .put(
            &turn_id,
            ENTITY_TYPE_TURN,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"opaque non-claim body",
        )
        .text(&turn_id, &[("body", "authorityneedle")])
        .commit()?;
    let candidate = |_store: &crate::store::Store, _txn: &heed::RoTxn<'_>, id: &EntityId| {
        Ok(*id != excluded_id)
    };
    let fresh = RetrievalFilter {
        include_stale: Some(false),
        ..RetrievalFilter::default()
    };
    for requested in [None, Some(&fresh)] {
        let filter = resolve_reader_filter(&vault, requested)?;
        assert_eq!(filter.include_stale, requested.is_none());
        for types in [&[ENTITY_TYPE_CLAIM][..], &[ENTITY_TYPE_TURN][..]] {
            let expected = filter.include_stale && types.contains(&ENTITY_TYPE_CLAIM);
            let txn = vault.store.env.read_txn()?;
            let config = PipelineFilterConfig {
                authority_filter: &filter,
                candidate_filter: Some(&candidate),
                type_filter: Some(types),
                since_filter: None,
                occurred_range: None,
                learned_range: None,
                repo_ref_filter: None,
                project_id_filter: None,
                facet_filter: None,
                relationship_filter: None,
                world_scope: WorldScope::All,
                world_active_set: None,
                corpus_scope: &crate::corpus::CorpusScope::All,
            };
            let mut metadata = EntityMetadataCache::default();
            // Bounded scans must use local decisions and resolved authority,
            // not the caller cache's stale flag or a corpus-sized shared memo.
            let mut gate = ClaimStatusGateCache {
                include_stale: !filter.include_stale,
                ..ClaimStatusGateCache::default()
            };
            for (id, allowed) in [(stale_id, expected), (excluded_id, false), (turn_id, false)] {
                assert_eq!(
                    pipeline_candidate_matches_filters_and_gate(
                        &vault.store,
                        &txn,
                        &id,
                        config,
                        &mut metadata,
                        &mut gate,
                    )?,
                    allowed
                );
            }
            assert!(gate.decisions.is_empty());
            drop(txn);

            // Exercise the same predicate through bounded text scoring too.
            let hits = vault
                .query()
                .authority_filter(filter.clone())
                .filter_candidates(&candidate)
                .filter_types(types)
                .search_text("authorityneedle", 1)
                .limit(1)
                .run()?;
            assert_eq!(
                hits.iter().map(|hit| hit.id).collect::<Vec<_>>(),
                if expected { vec![stale_id] } else { Vec::new() }
            );
        }
    }
    Ok(())
}

#[test]
fn authority_deny_all_returns_before_counting_or_querying_either_index() -> Result<()> {
    let disjoint = RetrievalFilter {
        entity_types: Some(BTreeSet::from([ENTITY_TYPE_TURN])),
        ..RetrievalFilter::default()
    };
    for (grant, requested) in [
        (read_grant("other-reader", Value::Nil), None),
        (
            read_grant(
                "authority-reader",
                map(vec![("min_confidence", Value::from("bad"))]),
            ),
            None,
        ),
        (
            read_grant(
                "authority-reader",
                map(vec![("entity_types", Value::Array(Vec::new()))]),
            ),
            None,
        ),
        (
            read_grant(
                "authority-reader",
                map(vec![(
                    "entity_types",
                    Value::Array(vec![Value::from(ENTITY_TYPE_CLAIM)]),
                )]),
            ),
            Some(&disjoint),
        ),
    ] {
        let (_tmp, vault) = open_test_vault();
        put_claim(&vault, entity_id(0xB0), &claim())?;
        install_grants(&vault, vec![grant])?;
        let mut txn = vault.store.env.write_txn()?;
        // Deliberately poison both counts. Any candidate-limit or search
        // access must fail, so Ok([]) proves denial happened before either.
        vault.store.text_meta.put(&mut txn, &[0_u8; 16], &[0])?;
        vault
            .store
            .hnsw_meta
            .put(&mut txn, crate::hnsw::COUNT_KEY, &[0])?;
        txn.commit()?;
        assert!(
            vault
                .scoped_read_search_candidate_limit(1, true, false)
                .is_err()
        );
        assert!(
            vault
                .scoped_read_search_candidate_limit(1, false, true)
                .is_err()
        );
        assert_search_ids(&reader(&vault), requested, &[])?;

        // Bypass ScopedRead's shortcut: the builder must honor resolved denial
        // before touching either poisoned index, with nonzero channel limits.
        let filter = resolve_reader_filter(&vault, requested)?;
        assert!(filter.deny_all);
        for query in [
            vault.query().search_text("authorityneedle", 1),
            vault.query().search_vector(&[1.0, 0.0, 0.0, 0.0], 1),
            vault
                .query()
                .search("authorityneedle", &[1.0, 0.0, 0.0, 0.0], None, 1),
        ] {
            assert!(query.authority_filter(filter.clone()).run()?.is_empty());
        }

        // This is a deny-only shortcut, not blanket suppression of index errors.
        install_grant(&vault, Value::Nil)?;
        let read = reader(&vault);
        assert!(read.search_text("authorityneedle", 1, None).is_err());
        assert!(read.search_vector(&[1.0, 0.0, 0.0, 0.0], 1, None).is_err());
        assert!(
            read.search("authorityneedle", &[1.0, 0.0, 0.0, 0.0], 1, None)
                .is_err()
        );
        let filter = resolve_reader_filter(&vault, None)?;
        assert!(!filter.deny_all);
        for query in [
            vault.query().search_text("authorityneedle", 1),
            vault.query().search_vector(&[1.0, 0.0, 0.0, 0.0], 1),
            vault
                .query()
                .search("authorityneedle", &[1.0, 0.0, 0.0, 0.0], None, 1),
        ] {
            assert!(query.authority_filter(filter.clone()).run().is_err());
        }
    }
    Ok(())
}
