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
//! Each `FIXTURE:` assertion checks the setup, never the leak. The last
//! assertion is the leak check.
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
use oneiron::write_envelope::claim_body::relationship_scope_of;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    Vault, VaultConfig,
};

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
fn record(vault: &Vault, person: EntityId, words: &str, relationship: Option<EntityId>) -> EntityId {
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
