//! CLAIM-REDACTION-SKIPS-DERIVED-COPIES: a value redaction withdraws the
//! CLAIMs derived from the redacted one; the redacted CLAIM stays, redacted.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test redaction_withdraws_dependents`.
#![cfg(oneiron_test_support)]

use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::test_doors::claim_value_redaction::redact_claim_value_fields;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeKind, EntityId,
    TimeRange, Vault, VaultConfig,
};
use rmpv::Value;

struct Fixture {
    vault: Vault,
    owner: EntityId,
    source: EntityId,
    dependent: EntityId,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("FIXTURE: a temporary vault dir");
        let vault =
            Vault::open(dir.path(), VaultConfig::default()).expect("FIXTURE: open the vault");
        let owner = vault
            .ensure_embedded_owner_actor()
            .expect("FIXTURE: the owner");
        let subject = EntityId::now();
        let at = TimeRange {
            start: 100,
            end: 100,
        };
        vault
            .put_entity(&subject, ENTITY_TYPE_PERSON, at, 100, b"person")
            .expect("FIXTURE: put the subject");
        let source = EntityId::now();
        let dependent = EntityId::now();
        for (id, predicate, value) in [
            (
                source,
                "profile.note",
                Value::Map(vec![
                    (Value::from("secret_note"), Value::from("the door code")),
                    (Value::from("public_note"), Value::from("likes tea")),
                ]),
            ),
            (dependent, "profile.summary", Value::from("the door code")),
        ] {
            let body = ClaimBody::new(
                predicate,
                ClaimSubject::Entity(subject),
                value,
                0.9,
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Active,
            )
            .expect("FIXTURE: a CLAIM body");
            vault
                .put_claim(&id, &body, at, 100)
                .expect("FIXTURE: put the CLAIM");
        }
        vault
            .put_edge(&dependent, EdgeKind::DerivedFrom, &source, 1.0)
            .expect("FIXTURE: the dependent derives from the source");
        assert!(
            vault
                .get_claim(&source)
                .expect("FIXTURE: read the source")
                .is_some(),
            "FIXTURE: the source reads before redaction"
        );
        assert!(
            vault
                .get_claim(&dependent)
                .expect("FIXTURE: read the dependent")
                .is_some(),
            "FIXTURE: the dependent reads before redaction"
        );
        Self {
            vault,
            owner,
            source,
            dependent,
            _dir: dir,
        }
    }
}

#[test]
fn a_claim_derived_from_a_redacted_claim_reads_withdrawn() {
    let fixture = Fixture::new();
    redact_claim_value_fields(
        &fixture.vault,
        fixture.source,
        &["secret_note".to_owned()],
        fixture.owner,
    )
    .expect("redact the source CLAIM's value field");

    let body = fixture
        .vault
        .get_claim(&fixture.source)
        .expect("read the redacted CLAIM")
        .expect("the redacted CLAIM no longer reads");
    let Value::Map(entries) = body.value else {
        panic!("the redacted CLAIM's value is no longer a map");
    };
    assert!(
        !entries
            .iter()
            .any(|(key, _)| key.as_str() == Some("secret_note")),
        "the redacted CLAIM kept the field"
    );
    assert!(
        entries.iter().any(|(key, value)| {
            key.as_str() == Some("public_note") && value.as_str() == Some("likes tea")
        }),
        "the redacted CLAIM lost the public field or its value"
    );
    assert!(
        fixture
            .vault
            .get_claim(&fixture.dependent)
            .expect("read the dependent CLAIM")
            .is_none(),
        "the CLAIM derived from the redacted CLAIM still reads"
    );
    assert!(
        fixture
            .vault
            .entity_exists(&fixture.dependent)
            .expect("check the dependent's row"),
        "withdrawal leaves the dependent stored"
    );
}

#[test]
fn a_redaction_that_removes_nothing_withdraws_nothing() {
    let fixture = Fixture::new();
    redact_claim_value_fields(
        &fixture.vault,
        fixture.source,
        &["absent_note".to_owned()],
        fixture.owner,
    )
    .expect("redact a field the source CLAIM does not hold");

    assert!(
        fixture
            .vault
            .get_claim(&fixture.dependent)
            .expect("read the dependent CLAIM")
            .is_some(),
        "a redaction that removed no words withdrew the dependent"
    );
}
