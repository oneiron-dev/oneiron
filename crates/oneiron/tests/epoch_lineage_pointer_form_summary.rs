//! The lineage census reads a pointer-form epoch SUMMARY by the keyframe keys
//! it keeps beside its pointer ([EPOCH-LINEAGE-POINTER-FORM-SUMMARY]).
//!
//! `prior_epoch_in_txn` decoded only inline or withdrawn epoch bodies. An epoch
//! SUMMARY whose text `Vault::migrate_entity_text` moved to the document plane
//! keeps every keyframe key but `text`, so `is_epoch_candidate_for_scope`
//! (one missing key) held and the census returned `Err`: the next compact of
//! that scope failed. The census now reads the pointer form the same way
//! `stored_epoch_in` does and keeps the `Err` for truly malformed rows.
//!
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test epoch_lineage_pointer_form_summary`.
#![cfg(oneiron_test_support)]

use oneiron::consent::AuthenticatedOwner;
use oneiron::entity_doc::{DocAuthorization, TextField};
use oneiron::registry::ENTITY_TYPE_SUMMARY;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::epoch_lineage_pointer::{prior_epoch_matches, put_inline_epoch};
use oneiron::{EdgeActorClass, EntityId, ErrorKind, TimeRange, Vault, VaultConfig, WriteActor};

fn fresh_vault() -> (tempfile::TempDir, Vault) {
    let directory = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(directory.path(), VaultConfig::device()).expect("fresh vault");
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    let owner = vault.ensure_embedded_owner_actor().expect("owner PERSON");
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("owner host binding");
    (directory, vault)
}

fn authenticated_owner(vault: &Vault) -> (WriteActor, AuthenticatedOwner) {
    let owner = vault.ensure_embedded_owner_actor().expect("owner PERSON");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    (WriteActor::new(owner, EdgeActorClass::Human), proof)
}

#[test]
fn a_pointer_form_epoch_counts_as_the_lineage_prior() {
    let (_directory, vault) = fresh_vault();
    let session = EntityId::now();
    let actor = EntityId::now();
    let summary = put_inline_epoch(
        &vault,
        &session,
        None,
        1,
        1,
        3,
        "the sitting's first epoch, compacted",
        &actor,
    )
    .expect("inline epoch row");
    let (owner, proof) = authenticated_owner(&vault);
    vault
        .migrate_entity_text(
            &summary,
            &TextField::MapField("text".to_owned()),
            owner,
            &DocAuthorization::Owner(&proof),
        )
        .expect("the owner migrates the epoch text to a document");
    assert!(
        prior_epoch_matches(&vault, &session, None, 1, 3)
            .expect("the census reads the pointer-form epoch"),
        "a pointer-form epoch is its lineage's prior",
    );
}

#[test]
fn an_inline_epoch_counts_as_the_lineage_prior() {
    let (_directory, vault) = fresh_vault();
    let session = EntityId::now();
    let actor = EntityId::now();
    put_inline_epoch(
        &vault,
        &session,
        None,
        1,
        1,
        3,
        "the sitting's first epoch, compacted",
        &actor,
    )
    .expect("inline epoch row");
    assert!(
        prior_epoch_matches(&vault, &session, None, 1, 3)
            .expect("the census reads the inline epoch"),
        "an inline epoch is its lineage's prior",
    );
}

#[test]
fn a_withdrawn_epoch_counts_as_the_lineage_prior() {
    let (_directory, vault) = fresh_vault();
    let session = EntityId::now();
    let actor = EntityId::now();
    let body = rmpv::Value::Map(vec![
        (
            rmpv::Value::from("v"),
            rmpv::Value::from(oneiron::compaction::EPOCH_SUMMARY_BODY_VERSION),
        ),
        (
            rmpv::Value::from("session"),
            rmpv::Value::from(session.to_hex()),
        ),
        (rmpv::Value::from("conversation"), rmpv::Value::Nil),
        (rmpv::Value::from("epoch"), rmpv::Value::from(1u64)),
        (rmpv::Value::from("turn_start"), rmpv::Value::from(1u64)),
        (rmpv::Value::from("turn_end"), rmpv::Value::from(3u64)),
        (
            rmpv::Value::from("level"),
            rmpv::Value::from(oneiron::compaction::EPOCH_SUMMARY_LEVEL),
        ),
        (
            rmpv::Value::from("actor"),
            rmpv::Value::from(actor.to_hex()),
        ),
    ]);
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &body).expect("encode the withdrawn keyframe");
    vault
        .put_entity(
            &EntityId::now(),
            ENTITY_TYPE_SUMMARY,
            TimeRange { start: 1, end: 1 },
            1,
            &encoded,
        )
        .expect("withdrawn epoch row");
    assert!(
        prior_epoch_matches(&vault, &session, None, 1, 3)
            .expect("the census reads the withdrawn epoch"),
        "a withdrawn epoch is its lineage's prior",
    );
}

#[test]
fn a_malformed_epoch_candidate_still_refuses_the_census() {
    let (_directory, vault) = fresh_vault();
    let session = EntityId::now();
    let actor = EntityId::now();
    // Every pinned key but `text`, with a non-integer `epoch`: no epoch form
    // decodes it, but it names this lineage with one key missing.
    let body = rmpv::Value::Map(vec![
        (
            rmpv::Value::from("v"),
            rmpv::Value::from(oneiron::compaction::EPOCH_SUMMARY_BODY_VERSION),
        ),
        (
            rmpv::Value::from("session"),
            rmpv::Value::from(session.to_hex()),
        ),
        (rmpv::Value::from("conversation"), rmpv::Value::Nil),
        (rmpv::Value::from("epoch"), rmpv::Value::from("three")),
        (rmpv::Value::from("turn_start"), rmpv::Value::from(1u64)),
        (rmpv::Value::from("turn_end"), rmpv::Value::from(3u64)),
        (
            rmpv::Value::from("level"),
            rmpv::Value::from(oneiron::compaction::EPOCH_SUMMARY_LEVEL),
        ),
        (
            rmpv::Value::from("actor"),
            rmpv::Value::from(actor.to_hex()),
        ),
    ]);
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &body).expect("encode the malformed row");
    vault
        .put_entity(
            &EntityId::now(),
            ENTITY_TYPE_SUMMARY,
            TimeRange { start: 1, end: 1 },
            1,
            &encoded,
        )
        .expect("malformed epoch row");
    let error = prior_epoch_matches(&vault, &session, None, 1, 3)
        .expect_err("a malformed candidate refuses");
    assert_eq!(error.kind(), ErrorKind::InvariantViolation);
}
