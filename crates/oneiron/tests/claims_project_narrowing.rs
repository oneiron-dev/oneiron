//! L1-12 PR O-1 (OPUS-FIX-E): `vault.claims.list_filtered` and
//! `vault.claims.read_filtered` take `project_refs` and narrow to them, as
//! `vault.recall`'s scope does. A memory provider that keeps each memory's
//! records under one anchor id on the claim's project axis lists and reads
//! one memory at a time. The anchors here are bare 32-hex ids that name no
//! row: the claim door and both reads take them as they are.
//!
//! `cargo test --locked -p oneiron --all-features --test claims_project_narrowing`
//! (the lane's runner also sets `RUSTFLAGS="--cfg oneiron_test_support"`).
#![cfg(feature = "test-support")]

use std::sync::Arc;

use oneiron::claim::base_world_id;
use oneiron::memory::{
    AllRelationships, ClaimFilteredListRequest, ClaimFilteredReadRequest, ClaimRelationships,
    ClaimScope, ScopedClaimInput,
};
use oneiron::registry::ENTITY_TYPE_FACET;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Maps any error into the test's error with the step that failed.
fn at<E: std::fmt::Debug>(step: &'static str) -> impl FnOnce(E) -> Box<dyn std::error::Error> {
    move |error| format!("{step}: {error:?}").into()
}

/// Two memory anchors: ids on the project axis that name no row.
const ANCHOR_A: &str = "5b0e3f9c2d4a4e1f8a7c6b5d4e3f2a1b";
const ANCHOR_B: &str = "c4d3e2f1a0b94c8d9e7f6a5b4c3d2e1f";

/// An owned vault with a device keystore and install signing and its
/// embedded owner PERSON, as `tests/gate_pins_put_pipeline.rs` opens one,
/// holding one claim in each anchor.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    actor: EntityId,
    in_a: String,
    in_b: String,
}

fn fixture() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), VaultConfig::device()).map_err(at("open owned"))?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault
        .prepare_install_signing()
        .map_err(at("install signing"))?;
    let actor = vault
        .ensure_embedded_owner_actor()
        .map_err(at("embedded owner"))?;
    let facet = EntityId::now();
    let facet_body = rmp_serde::to_vec_named(&json!({ "name": "narrowing facet" }))?;
    vault
        .put_entity(
            &facet,
            ENTITY_TYPE_FACET,
            TimeRange { start: 1, end: 1 },
            1,
            &facet_body,
        )
        .map_err(at("put the facet row"))?;
    // Two predicates, so neither claim corrects the other.
    let in_a = remember(&vault, actor, facet, ANCHOR_A, "profile.hobby", "gardening")?;
    let in_b = remember(
        &vault,
        actor,
        facet,
        ANCHOR_B,
        "profile.occupation",
        "baker",
    )?;
    Ok(Fixture {
        _dir: dir,
        vault,
        actor,
        in_a,
        in_b,
    })
}

/// The owner's scoped claim about themself in `anchor`; its 32-hex id.
fn remember(
    vault: &Vault,
    actor: EntityId,
    facet: EntityId,
    anchor: &str,
    predicate: &str,
    value: &str,
) -> TestResult<String> {
    let id = EntityId::now();
    vault
        .memory(actor, EdgeActorClass::Human)
        .claim_upsert_scoped(&ScopedClaimInput {
            id: Some(id.to_hex()),
            predicate: predicate.to_owned(),
            subject_ref: actor.to_hex(),
            value: json!(value),
            confidence: 1.0,
            source: "user_stated".to_owned(),
            scope: ClaimScope {
                world_id: base_world_id().to_hex(),
                scope_facet_id: facet.to_hex(),
                scope_relationship_id: ClaimRelationships::All(AllRelationships::All),
                scope_project_id: anchor.to_owned(),
            },
            sensitivity: None,
            evidence_turn_refs: Vec::new(),
            valid_from: None,
            valid_to: None,
            occurred_at: Some(1),
            learned_at: Some(1),
            salience: None,
        })
        .map_err(at("FIXTURE: the owner's claim in an anchor"))?;
    Ok(id.to_hex())
}

/// Each claim `vault.claims.list_filtered` serves for `request` (the JSON
/// a client sends), as its id and its project stamp.
fn listed(fixture: &Fixture, request: serde_json::Value) -> TestResult<Vec<(String, String)>> {
    let request: ClaimFilteredListRequest =
        serde_json::from_value(request).map_err(at("the list request"))?;
    let served = fixture
        .vault
        .memory(fixture.actor, EdgeActorClass::Human)
        .claim_list_filtered(&request)
        .map_err(at("vault.claims.list_filtered"))?;
    Ok(served
        .value
        .into_iter()
        .map(|view| (view.claim_ref, view.claim_scope.scope_project_id))
        .collect())
}

fn ids(listed: &[(String, String)]) -> Vec<&str> {
    listed.iter().map(|(id, _)| id.as_str()).collect()
}

/// The claim id `vault.claims.read_filtered` serves for `request`, or
/// `None` when it answers missing.
fn read(fixture: &Fixture, request: serde_json::Value) -> TestResult<Option<String>> {
    let request: ClaimFilteredReadRequest =
        serde_json::from_value(request).map_err(at("the read request"))?;
    let served = fixture
        .vault
        .memory(fixture.actor, EdgeActorClass::Human)
        .claim_read_filtered(&request)
        .map_err(at("vault.claims.read_filtered"))?;
    Ok(served.value.map(|view| view.claim_ref))
}

#[test]
fn a_list_narrowed_to_one_anchor_returns_none_of_another_anchors_claims() -> TestResult {
    let fixture = fixture()?;
    let everything = listed(&fixture, json!({ "limit": 100_000 }))?;
    assert!(
        ids(&everything).contains(&fixture.in_a.as_str())
            && ids(&everything).contains(&fixture.in_b.as_str()),
        "FIXTURE: an unnarrowed list serves both anchors' claims: {everything:?}"
    );

    let in_a = listed(
        &fixture,
        json!({ "limit": 1000, "project_refs": [ANCHOR_A] }),
    )?;
    assert!(
        ids(&in_a).contains(&fixture.in_a.as_str()),
        "a list narrowed to anchor A serves A's claim: {in_a:?}"
    );
    assert!(
        !ids(&in_a).contains(&fixture.in_b.as_str()),
        "a list narrowed to anchor A serves none of B's claims: {in_a:?}"
    );
    assert!(
        in_a.iter().all(|(_, project)| project == ANCHOR_A),
        "every claim a list narrowed to anchor A serves is stamped A: {in_a:?}"
    );
    let both = listed(
        &fixture,
        json!({ "limit": 1000, "project_refs": [ANCHOR_A, ANCHOR_B] }),
    )?;
    assert!(
        ids(&both).contains(&fixture.in_a.as_str()) && ids(&both).contains(&fixture.in_b.as_str()),
        "a list narrowed to both anchors serves both claims: {both:?}"
    );
    assert!(
        both.iter()
            .all(|(_, project)| project == ANCHOR_A || project == ANCHOR_B),
        "a list narrowed to both anchors serves no other project's claim: {both:?}"
    );
    Ok(())
}

#[test]
fn a_read_of_another_anchors_claim_narrowed_to_one_anchor_answers_missing() -> TestResult {
    let fixture = fixture()?;
    assert_eq!(
        read(&fixture, json!({ "claim_ref": fixture.in_b }))?,
        Some(fixture.in_b.clone()),
        "FIXTURE: an unnarrowed read serves B's claim"
    );

    assert_eq!(
        read(
            &fixture,
            json!({ "claim_ref": fixture.in_b, "project_refs": [ANCHOR_A] })
        )?,
        None,
        "a read of B's claim narrowed to anchor A answers missing"
    );
    assert_eq!(
        read(
            &fixture,
            json!({ "claim_ref": fixture.in_b, "project_refs": [ANCHOR_B] })
        )?,
        Some(fixture.in_b.clone()),
        "a read of B's claim narrowed to anchor B serves it"
    );
    Ok(())
}
