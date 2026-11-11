//! The stewardship reach-out keeps the audience of the record it cites
//! (OPUS-LEAKS, lead call G "leaks today").
//!
//! The owner keeps in touch with two people. The newest record about Pia is
//! an open claim; the newest record about Rob is a claim scoped to a
//! relationship R, which the Dreamer reads on its own live grant, as an
//! owner grants it today. The nightly stewardship pass lands one reach-out
//! per person, naming the record it last saw and when (`last_record`,
//! `quiet_since`). A member outside R reads both people and Pia's reach-out,
//! never the R claim; the test asserts it reads no reach-out that names the
//! R claim or its time.
//!
//! A second test checks the place a reach-out copies: its record's canonical
//! facet and project stamps win over a selector nested in the opaque scope
//! map (review round 2 of #6972).
//!
//! Each `FIXTURE:` assertion checks the setup, never the leak. The last
//! assertion of each test is the leak check.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test stewardship_source_label`.
#![cfg(oneiron_test_support)]

use oneiron::dreamer_runner::maintenance::stewardship::{STEWARDSHIP_PREDICATE, StewardshipRule};
use oneiron::edge::EdgeActorClass;
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_RELATIONSHIP};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::label_writers::{
    embedded_owner, grant_dreamer_relationship_claims, open_member_vault, run_stewardship_once,
};
use oneiron::write_envelope::ClaimCandidate;
use oneiron::write_envelope::claim_body::relationship_scope_of;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    Vault, VaultConfig, WriteActor, WriteEnvelope, WriteProvenance,
};
use rmpv::Value;

/// When each record about a person happened.
const RECORD_AT: u64 = 10;
/// When the owner sets the rules.
const RULES_AT: u64 = 20;
/// The rules' quiet stretch.
const EVERY_SECS: u64 = 60;
/// When the nightly pass runs: both people are due.
const PASS_AT: u64 = 100;

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

fn person(vault: &Vault, name: &str) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            at(1),
            1,
            &rmp_serde::to_vec_named(&serde_json::json!({ "name": name })).expect("body"),
        )
        .expect("a person");
    id
}

/// A stated record about `person`, scoped to `relationship` when one is
/// named.
fn record(
    vault: &Vault,
    person: EntityId,
    words: &str,
    relationship: Option<EntityId>,
) -> EntityId {
    let id = EntityId::now();
    let mut body = ClaimBody::new(
        "profile.name",
        ClaimSubject::Entity(person),
        rmpv::Value::from(words),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("claim body");
    body.source = Some(ClaimSource::UserStated);
    body.rel = relationship_scope_of(relationship);
    vault
        .put_claim(&id, &body, at(RECORD_AT), RECORD_AT)
        .expect("a record");
    id
}

/// The reach-out landed about `person`, with its value.
fn reach_out(vault: &Vault, person: EntityId) -> (EntityId, serde_json::Value) {
    let found: Vec<_> = vault
        .claims_for_subject(&person)
        .expect("claims read")
        .into_iter()
        .filter_map(|id| {
            let body = vault.get_claim(&id).expect("claim read")?;
            (body.predicate == STEWARDSHIP_PREDICATE).then(|| {
                let value = body.value.as_str().expect("a JSON string value");
                (
                    id,
                    serde_json::from_str::<serde_json::Value>(value).expect("a JSON value"),
                )
            })
        })
        .collect();
    let [one] = found.as_slice() else {
        panic!("FIXTURE: one reach-out about the person, found {found:?}");
    };
    one.clone()
}

#[test]
fn a_reach_out_never_names_a_relationship_record_to_a_member_outside_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outsider = EntityId::now();
    let vault = open_member_vault(dir.path(), VaultConfig::device(), &[outsider.to_hex()])
        .expect("fixture vault");
    let relationship = EntityId::now();
    vault
        .put_entity(
            &relationship,
            ENTITY_TYPE_RELATIONSHIP,
            at(1),
            1,
            b"relationship",
        )
        .expect("a relationship");
    vault
        .put_entity(&outsider, ENTITY_TYPE_PERSON, at(1), 1, b"outsider")
        .expect("a member outside the relationship");
    let (_owner, proof) = embedded_owner(&vault).expect("the owner");
    let pia = person(&vault, "Pia");
    let rob = person(&vault, "Rob");
    let open_record = record(&vault, pia, "Pia", None);
    let hidden_record = record(&vault, rob, "Rob", Some(relationship));
    grant_dreamer_relationship_claims(&vault, relationship).expect("the Dreamer's grant");
    vault
        .set_stewardship_rules(
            &proof,
            [("pia", pia), ("rob", rob)]
                .into_iter()
                .map(|(id, person)| StewardshipRule {
                    id: id.to_owned(),
                    person,
                    every_secs: EVERY_SECS,
                    since: 0,
                    draft: None,
                })
                .collect(),
            RULES_AT,
        )
        .expect("the owner's rules");

    run_stewardship_once(&vault, PASS_AT).expect("one nightly stewardship pass");

    let (pia_reach_out, pia_value) = reach_out(&vault, pia);
    assert_eq!(
        (&pia_value["last_record"], &pia_value["quiet_since"]),
        (
            &serde_json::json!(open_record.to_hex()),
            &serde_json::json!(RECORD_AT)
        ),
        "FIXTURE: Pia's reach-out names her open record"
    );
    let (rob_reach_out, rob_value) = reach_out(&vault, rob);
    assert_eq!(
        (&rob_value["last_record"], &rob_value["quiet_since"]),
        (
            &serde_json::json!(hidden_record.to_hex()),
            &serde_json::json!(RECORD_AT)
        ),
        "FIXTURE: the Dreamer read the R record on its grant"
    );

    let reads = |id: &EntityId| {
        vault
            .memory(outsider, EdgeActorClass::Human)
            .get_entity(&id.to_hex())
            .expect("outsider read")
            .value
            .is_some()
    };
    assert!(
        reads(&pia) && reads(&rob),
        "FIXTURE: the outsider reads both people"
    );
    assert!(
        reads(&open_record) && reads(&pia_reach_out),
        "FIXTURE: the outsider reads the open record and the reach-out naming it"
    );
    assert!(
        !reads(&hidden_record),
        "FIXTURE: the outsider does not read the R record"
    );

    assert!(
        !reads(&rob_reach_out),
        "LEAK: a member outside R reads a reach-out naming the R record {} and its time {}",
        rob_value["last_record"],
        rob_value["quiet_since"]
    );
}

/// Review round 2 of #6972: a reach-out copies its record's opaque scope map
/// and its canonical facet and project stamps (`FindingPlace`) onto one
/// candidate. A selector nested in that map must not override the stamps:
/// a record stamped project P whose map names project Q would land its
/// reach-out in Q, where a reader of Q but not of P learns of the P record.
#[test]
fn a_copied_place_keeps_its_canonical_stamps_over_a_nested_selector() {
    let (facet, project) = (EntityId::now(), EntityId::now());
    let (selector_facet, selector_project) = (EntityId::now(), EntityId::now());
    let scope = Value::Map(vec![
        (Value::from("facet"), Value::from(selector_facet.to_hex())),
        (
            Value::from("scopeProjectId"),
            Value::from(selector_project.to_hex()),
        ),
    ]);
    let envelope = WriteEnvelope::new(
        WriteActor::new(EntityId::now(), EdgeActorClass::Agent),
        ClaimSource::Generated,
        WriteProvenance::new(Value::Map(vec![(
            Value::from("surface"),
            Value::from("dreamer.finding"),
        )]))
        .expect("provenance"),
        ClaimApprovalStatus::Auto,
    );
    let body = ClaimCandidate::new(
        STEWARDSHIP_PREDICATE,
        ClaimSubject::Entity(EntityId::now()),
        Value::from("reach out"),
        1.0,
    )
    .with_scope(scope.clone())
    .with_scope_stamps(facet, project)
    .into_claim_body(&envelope, EntityId::now())
    .expect("FIXTURE: the claim body");
    assert_eq!(
        body.scope,
        Some(scope),
        "FIXTURE: the opaque scope map is kept as written"
    );
    assert_eq!(
        (body.scope_facet, body.scope_project),
        (facet, project),
        "LEAK: a nested selector overrode the copied record's canonical facet and project stamps"
    );
}
