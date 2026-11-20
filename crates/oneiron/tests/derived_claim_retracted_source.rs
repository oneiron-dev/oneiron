//! A derived claim stands on the rows its consolidation envelope cites, and
//! a cited CLAIM the owner retracted supports nothing: a retraction says the
//! claim was wrong, so a claim derived only from it is not served, and stays
//! in history (FIX DERIVED-CLAIM-SUPPORT-COUNTS-RETRACTED-CITED-CLAIM; Engine
//! ANSWER DERIVED-CLAIM-RETRACTED-SOURCE-SUPPORT = A, by canon ARCH-0004
//! hydration: "one whose cited sources are gone is not served"). A
//! superseded cited claim still supports it: a newer version replaced it, no
//! one refuted it. Any other live cited row keeps it served, as before.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test derived_claim_retracted_source`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::dreamer_consolidation::{
    ConsolidationEvidenceEnvelope, encode_consolidation_evidence,
};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::derive::claim_has_live_support;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    TimeRange, Vault,
};
use rmpv::Value;

const READER: &str = "reader";

fn put(vault: &Vault, entity_type: u8, body: &[u8]) -> EntityId {
    let id = EntityId::now();
    let at = vault.now_recorded_at();
    vault
        .put_entity(&id, entity_type, TimeRange { start: at, end: at }, at, body)
        .expect("a row");
    id
}

fn turn(vault: &Vault) -> EntityId {
    let body = rmp_serde::to_vec_named(&std::collections::BTreeMap::from([("role", "user")]))
        .expect("a TURN body");
    put(vault, ENTITY_TYPE_TURN, &body)
}

/// A claim about `person` through the owner's raw claim door; with `cites`,
/// its evidence is a consolidation envelope naming those rows.
fn claim(vault: &Vault, person: EntityId, value: &str, cites: Option<Vec<EntityId>>) -> EntityId {
    let mut body = ClaimBody::new(
        "profile.nickname",
        ClaimSubject::Entity(person),
        Value::from(value),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("claim body");
    body.source = Some(ClaimSource::UserStated);
    if let Some(refs) = cites {
        body.evidence = Some(encode_consolidation_evidence(
            &ConsolidationEvidenceEnvelope {
                refs,
                chain: Vec::new(),
                source_meet: ClaimSource::UserStated,
            },
        ));
    }
    let id = EntityId::now();
    let at = vault.now_recorded_at();
    vault
        .put_claim(&id, &body, TimeRange { start: at, end: at }, at)
        .expect("put claim");
    id
}

/// Whether the read doors serve `claim`.
fn served(vault: &Vault, claim: &EntityId) -> bool {
    claim_has_live_support(vault, claim)
        .expect("read")
        .expect("the claim is stored")
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    person: EntityId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("vault");
    let person = put(&vault, ENTITY_TYPE_PERSON, b"someone");
    Fixture {
        _dir: dir,
        vault,
        person,
    }
}

/// A derived claim citing only one claim is served; once the owner retracts
/// that claim, it is not, and it stays in history.
/// Red on main 0aedc807c526: live support reads only that the cited row
/// exists, and a retracted claim's row does.
#[test]
fn a_derived_claim_whose_only_cited_claim_is_retracted_is_not_served() {
    let Fixture {
        _dir,
        vault,
        person,
    } = fixture();
    let source = claim(&vault, person, "o", None);
    let derived = claim(&vault, person, "goes by o", Some(vec![source]));
    assert!(served(&vault, &derived), "the derived claim is served");

    vault
        .retract_claim(&source, vault.now_recorded_at())
        .expect("the owner retracts the cited claim");

    assert!(
        !served(&vault, &derived),
        "FAILBEFORE DERIVED-CLAIM-SUPPORT-COUNTS-RETRACTED-CITED-CLAIM: a claim derived only from \
         a retracted claim is served"
    );
    assert!(
        vault.get_claim(&derived).expect("read").is_some(),
        "the derived claim stays in history"
    );
}

/// A derived claim whose one cited claim is superseded stays served: the
/// supersession replaced the claim with a newer version.
#[test]
fn a_derived_claim_whose_cited_claim_is_superseded_stays_served() {
    let Fixture {
        _dir,
        vault,
        person,
    } = fixture();
    let source = claim(&vault, person, "o", None);
    let derived = claim(&vault, person, "goes by o", Some(vec![source]));
    let newer = claim(&vault, person, "oh", None);

    vault
        .supersede_claim(&newer, &source, vault.now_recorded_at())
        .expect("the newer claim supersedes the cited one");

    assert_eq!(
        vault
            .get_claim(&source)
            .expect("read")
            .expect("stored")
            .lifecycle,
        ClaimLifecycleStatus::Superseded,
        "the cited claim is superseded"
    );
    assert!(
        served(&vault, &derived),
        "a claim derived from a superseded claim stays served"
    );
}

/// A derived claim citing a retracted claim and a live TURN stays served:
/// one live cited row keeps it readable.
#[test]
fn a_live_turn_beside_a_retracted_cited_claim_keeps_a_derived_claim_served() {
    let Fixture {
        _dir,
        vault,
        person,
    } = fixture();
    let source = claim(&vault, person, "o", None);
    let said = turn(&vault);
    let derived = claim(&vault, person, "goes by o", Some(vec![source, said]));

    vault
        .retract_claim(&source, vault.now_recorded_at())
        .expect("the owner retracts the cited claim");

    assert!(
        served(&vault, &derived),
        "a live cited TURN keeps the derived claim served"
    );
}
