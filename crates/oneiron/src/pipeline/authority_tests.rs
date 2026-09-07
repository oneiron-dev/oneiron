//! ONE-1388 adapter tests. Existing scope and ranking suites stay separate.

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

fn install_grant(vault: &Vault, scope: Value) -> Result<()> {
    let bytes = crate::gate::default_policy_manifest();
    let Value::Map(mut entries) = rmpv::decode::read_value(&mut bytes.as_slice()).unwrap() else {
        panic!("manifest map");
    };
    entries.retain(|(key, _)| key.as_str() != Some("scoped_grants"));
    entries.push((
        Value::from("scoped_grants"),
        Value::Array(vec![map(vec![
            ("actor_ref", Value::from("authority-reader")),
            ("effector", Value::from("core:read")),
            ("receipt_required", Value::Boolean(false)),
            ("scope", scope),
        ])]),
    ));
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

fn put_claim(vault: &Vault, id: EntityId, body: &ClaimBody) -> Result<()> {
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

fn reader(vault: &Vault) -> crate::claim::ScopedRead<'_> {
    vault.scoped_read(ScopedReadActorKey::new("authority-reader").unwrap())
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
fn authority_scoped_absence_malformed_grants_and_invalid_requests_fail_closed() -> Result<()> {
    let (_tmp, vault) = open_test_vault();
    put_claim(&vault, entity_id(0x60), &claim())?;
    assert!(
        reader(&vault)
            .search_text("authorityneedle", 1, None)?
            .is_empty()
    );
    install_grant(&vault, map(vec![("min_confidence", Value::from("bad"))]))?;
    assert!(
        reader(&vault)
            .search_text("authorityneedle", 1, None)?
            .is_empty()
    );
    install_grant(&vault, Value::Nil)?;
    let invalid = RetrievalFilter {
        min_salience: Some(f32::NAN),
        ..RetrievalFilter::default()
    };
    let read = reader(&vault);
    assert!(
        read.search_text("authorityneedle", 0, Some(&invalid))
            .is_err()
    );
    assert!(read.search_vector(&[], 0, Some(&invalid)).is_err());
    assert!(
        read.search("authorityneedle", &[], 0, Some(&invalid))
            .is_err()
    );
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
