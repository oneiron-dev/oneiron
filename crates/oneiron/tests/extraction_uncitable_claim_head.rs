//! A listed Dreamer-extracted head is marked uncitable, the prompt no longer
//! asks the model to cite one, and a reply that cites one anyway is refused
//! at the checked step: the attempt parks for a retry instead of failing the
//! pass in verification ("generated claim cannot corroborate").
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test extraction_uncitable_claim_head`.
#![cfg(oneiron_test_support)]

use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::extraction_probe::probe_unbound_turn;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    DreamerAttemptExecution, DreamerParkCause, EntityId, TimeRange, Vault,
};
use rmpv::Value;

const READER: &str = "reader";

/// A PERSON body carrying `name`, so the listing shows it and the passage
/// names it by its identity hint.
fn person_body(name: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(
        &mut bytes,
        &Value::Map(vec![(Value::from("name"), Value::from(name))]),
    )
    .expect("encode person body");
    bytes
}

/// A head about `subject` with `source`: public, active, never stale, so the
/// Dreamer's listing shows it.
fn put_head(
    vault: &Vault,
    subject: EntityId,
    predicate: &str,
    value: &str,
    source: ClaimSource,
) -> EntityId {
    let mut body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(subject),
        Value::from(value),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("claim body");
    body.source = Some(source);
    body.scope = Some(Value::Map(vec![(
        Value::from("sensitivity"),
        Value::from(0u64),
    )]));
    let head = EntityId::now();
    vault
        .put_claim(&head, &body, TimeRange { start: 2, end: 2 }, 2)
        .expect("put head");
    head
}

/// A person named `name` holding one head with `source`.
fn person_with_head(
    vault: &Vault,
    name: &str,
    predicate: &str,
    value: &str,
    source: ClaimSource,
) -> (EntityId, EntityId) {
    let person = EntityId::now();
    vault
        .put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            &person_body(name),
        )
        .expect("put person");
    let head = put_head(vault, person, predicate, value, source);
    (person, head)
}

/// The listing's claim lines for `predicate` across the recorded calls.
fn claim_lines<'a>(requests: &'a [String], predicate: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    for request in requests {
        for line in request.lines() {
            if line.starts_with("  claim ") && line.contains(predicate) {
                out.push(line);
            }
        }
    }
    out
}

/// A reply that cites a generated head as evidence is refused at the checked
/// step: the attempt parks for a retry instead of failing the pass with
/// "generated claim cannot corroborate".
#[test]
fn a_reply_citing_a_generated_head_parks_for_retry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("vault");
    let (_owen, head) = person_with_head(
        &vault,
        "Owen",
        "profile.nickname",
        "Ollie",
        ClaimSource::Generated,
    );
    assert_eq!(
        vault.get_claim(&head).expect("read").expect("head").source,
        Some(ClaimSource::Generated),
        "the listed head is generated"
    );

    let template = serde_json::json!({
        "candidates": [{
            "subject": "{{entity:Owen}}",
            "predicate": "profile.nickname",
            "value": "Ollie",
            "confidence": 0.9,
            "evidence_refs": [
                {"source": "T1", "quote": "Owen"},
                {"claim": "{{claim:profile.nickname}}"},
            ],
        }],
    })
    .to_string();
    let pass = probe_unbound_turn(&vault, "Owen still goes by Ollie", &template).expect("pass ran");
    assert!(
        !claim_lines(&pass.requests, "profile.nickname").is_empty(),
        "the extraction call listed the head"
    );
    match pass.outcome {
        Err(error) => panic!("the pass failed instead of parking the refused reply: {error:?}"),
        Ok(DreamerAttemptExecution::ParkWithSpend { reason, cause, .. }) => {
            assert_eq!(
                cause,
                DreamerParkCause::Retry,
                "a refused reply parks for a retry: {reason}"
            );
            assert!(
                reason.contains("cites outside its source"),
                "the park names the citation refusal: {reason}"
            );
            assert!(
                reason.contains("cannot corroborate"),
                "the park names the generated head: {reason}"
            );
        }
        Ok(outcome) => panic!("a reply citing a generated head parks; got: {outcome:?}"),
    }
    assert!(
        pass.landed.is_empty(),
        "a refused reply lands nothing: {:?}",
        pass.landed
    );
}

/// The extraction call's listing marks a generated head ` (uncitable)` and
/// leaves a stated head unmarked.
#[test]
fn the_listing_marks_only_the_generated_head_uncitable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("vault");
    let (_owen, _generated) = person_with_head(
        &vault,
        "Owen",
        "profile.nickname",
        "Ollie",
        ClaimSource::Generated,
    );
    let (_mara, _stated) = person_with_head(
        &vault,
        "Mara",
        "profile.city",
        "Paris",
        ClaimSource::UserStated,
    );

    let pass = probe_unbound_turn(
        &vault,
        "Owen still goes by Ollie, and Mara still lives in Paris",
        "{\"candidates\": []}",
    )
    .expect("pass ran");
    assert!(!pass.requests.is_empty(), "the model was called");
    let generated = claim_lines(&pass.requests, "profile.nickname");
    let stated = claim_lines(&pass.requests, "profile.city");
    assert!(
        !generated.is_empty(),
        "the extraction call listed the generated head"
    );
    assert!(
        !stated.is_empty(),
        "the extraction call listed the stated head"
    );
    assert!(
        generated.iter().all(|line| line.ends_with(" (uncitable)")),
        "the generated head is marked: {generated:?}"
    );
    assert!(
        stated.iter().all(|line| !line.contains("(uncitable)")),
        "the stated head is not marked: {stated:?}"
    );
    assert!(
        matches!(&pass.outcome, Ok(DreamerAttemptExecution::Completed { .. })),
        "a pass with nothing stated completes: {:?}",
        pass.outcome
    );
}

/// Control: a reply citing a stated head as corroboration still verifies and
/// lands, as before.
#[test]
fn a_reply_citing_a_stated_head_still_lands() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("vault");
    let (mara, head) = person_with_head(
        &vault,
        "Mara",
        "profile.city",
        "Paris",
        ClaimSource::UserStated,
    );

    let template = serde_json::json!({
        "persons": [{"id": "new:P1", "name": "Theo", "evidence_turn_refs": ["T1"]}],
        "candidates": [{
            "subject": "new:P1",
            "predicate": "profile.city",
            "value": "Paris",
            "confidence": 0.85,
            "evidence_refs": [
                {"source": "T1", "quote": "lives in Paris with Theo"},
                {"claim": "{{claim:profile.city}}"},
            ],
        }],
    })
    .to_string();
    let pass = probe_unbound_turn(&vault, "Mara still lives in Paris with Theo", &template)
        .expect("pass ran");
    assert!(
        !claim_lines(&pass.requests, "profile.city").is_empty(),
        "the extraction call listed the head"
    );
    assert!(
        matches!(&pass.outcome, Ok(DreamerAttemptExecution::Completed { .. })),
        "the pass completes: {:?}",
        pass.outcome
    );
    assert_eq!(
        pass.landed.len(),
        1,
        "the corroborated claim lands: {:?}",
        pass.landed
    );
    assert_ne!(pass.landed[0], head, "a new claim lands beside the head");
    let body = vault
        .get_claim(&pass.landed[0])
        .expect("read")
        .expect("landed claim");
    assert_eq!(body.predicate, "profile.city");
    assert_eq!(body.value, Value::from("Paris"));
    let ClaimSubject::Entity(subject) = body.subject else {
        panic!("the claim is about the new person: {:?}", body.subject);
    };
    assert_ne!(subject, mara, "the claim is about the new person");
    assert_eq!(
        vault.get_entity_type(&subject).expect("read"),
        Some(ENTITY_TYPE_PERSON),
        "the claim is about a person"
    );
}
