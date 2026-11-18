//! WAVE11-REPO-REGISTRANT-UNRECORDED: a registered repository's retained
//! configuration names the agent that registered it as the owner's
//! delegate. Stored change: keep. A registration stored before the key
//! existed (the two keys `source` and `editable`) decodes as before, with no
//! registrant, and one with no registrant encodes to those same two keys.
//!
//! Red at main: the registrant accessors do not exist there, so this file
//! does not compile. Fleet command: `cargo test --locked -p oneiron-store
//! --test code_repo_registration_registrant`.

use oneiron_base::error::ErrorKind;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::code_artifact_body::{
    CodeArtifactBody, decode_code_artifact_body, encode_code_artifact_body,
};
use oneiron_store::code_repo_registration::{CodeRepoRegistration, CodeRepoSource};
use oneiron_store::code_snapshot::repo_ref::RepoRef;
use rmpv::Value;

const FOLDER: &str = "/srv/repos/math";

fn source() -> CodeRepoSource {
    CodeRepoSource::LocalFolder {
        path: FOLDER.to_owned(),
    }
}

/// The map every registration was stored as before the registrant.
fn two_key_map() -> Value {
    Value::Map(vec![
        (
            Value::from("source"),
            Value::from(format!("local:{FOLDER}")),
        ),
        (
            Value::from("editable"),
            Value::Array(vec![Value::from("math.rs")]),
        ),
    ])
}

/// The two-key map with a `registrant` entry holding `registrant`.
fn with_registrant_entry(registrant: Value) -> Value {
    let Value::Map(mut entries) = two_key_map() else {
        unreachable!("a registration is a map");
    };
    entries.push((Value::from("registrant"), registrant));
    Value::Map(entries)
}

#[test]
fn a_stored_two_key_registration_reads_with_no_registrant() {
    let decoded =
        CodeRepoRegistration::from_value(&two_key_map()).expect("a two-key registration decodes");
    assert_eq!(decoded.registrant(), None);
    assert_eq!(decoded.source(), &source());
    assert_eq!(decoded.editable(), ["math.rs".to_owned()]);
    assert_eq!(
        decoded.to_value(),
        two_key_map(),
        "a registration with no registrant encodes as before"
    );
}

#[test]
fn a_registration_round_trips_its_registrant() {
    let agent = EntityId::now();
    let registration = CodeRepoRegistration::new(source(), ["math.rs"])
        .expect("registration")
        .with_registrant(Some(agent));
    let value = registration.to_value();
    assert_eq!(
        value,
        with_registrant_entry(Value::Binary(agent.as_bytes().to_vec())),
        "the registrant is the third key, as 16 bytes"
    );
    let decoded = CodeRepoRegistration::from_value(&value).expect("decodes");
    assert_eq!(decoded.registrant(), Some(agent));
    assert_eq!(decoded, registration);

    let repo_ref = RepoRef::LocalFolder {
        path: FOLDER.to_owned(),
        commit: "0".repeat(40),
    }
    .canonical();
    let body = CodeArtifactBody::new(
        format!("The registered local repository at {FOLDER}."),
        [7; 32],
        repo_ref,
    )
    .with_registration(Some(registration.clone()));
    let stored = encode_code_artifact_body(&body).expect("encode the CODE body");
    let read = decode_code_artifact_body(&stored).expect("decode the CODE body");
    assert_eq!(
        read.registration.and_then(|held| held.registrant()),
        Some(agent),
        "the CODE body keeps the registrant"
    );
}

#[test]
fn a_registrant_of_another_shape_is_refused() {
    for registrant in [
        Value::Binary(vec![0x42; 15]),
        Value::from(EntityId::now().to_hex()),
        Value::Binary(vec![0; 16]),
    ] {
        let error = CodeRepoRegistration::from_value(&with_registrant_entry(registrant.clone()))
            .expect_err("a registrant is 16 bytes of a live entity id");
        assert_eq!(
            error.kind(),
            ErrorKind::InvalidCodeArtifactBody,
            "{registrant:?}"
        );
    }
    let Value::Map(mut entries) =
        with_registrant_entry(Value::Binary(EntityId::now().as_bytes().to_vec()))
    else {
        unreachable!("a registration is a map");
    };
    entries.push((
        Value::from("registrant"),
        Value::Binary(EntityId::now().as_bytes().to_vec()),
    ));
    let error = CodeRepoRegistration::from_value(&Value::Map(entries))
        .expect_err("a registrant is named once");
    assert_eq!(error.kind(), ErrorKind::InvalidCodeArtifactBody);
}
