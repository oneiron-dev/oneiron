//! FIX [NATIVE-CLAIM-LANDS-ON-ARCHIVED-PERSON]: the Dreamer's extraction
//! derives a person's id from the extraction it belongs to (its queued
//! parent, else the first try of its retry lineage), the person's name and
//! the mention. A later try of that lineage, or another child of that
//! parent, derives the same id for the same mention. When the vault cleanup
//! archived that PERSON in between (an extraction mint with no live claim
//! and no pending try of its lineage), the mint restores her: the same
//! record, never a second one (ARCH-0073 §6, ARCH-0055 §10). And a claim
//! the Dreamer's promotion writer lands about a PERSON the cleanup archived
//! restores her in the claim's own transaction, whether or not a mint came
//! before it.
//!
//! The extractions here are ids the fixture supplies to the mint door: no
//! attempt of theirs is queued, so no try of a minting lineage is pending,
//! and a retry's resolution to its lineage's first try is not exercised. The
//! one queued attempt is the promotion run of the third test.
//!
//! Red without the fix (the first three tests): the mint door writes
//! nothing for an id whose row stands, and the promotion asks only that its
//! subject's row is stored, so the PERSON stays archived.
//!
//! Guards that hold with and without the fix (the last two tests): a
//! mention under another extraction id derives another id and leaves the
//! archived PERSON archived, and a mention of a PERSON the owner deleted
//! while she was archived restores nothing and does not fail the mint.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test native_re_mention_restores_archived_person`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::attempt_queue::AttemptId;
use oneiron::dreamer_promotion::promote_consolidated_claims;
use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::derive::row_live;
use oneiron::test_doors::derive_person::{cleanup_lists, person_body};
use oneiron::test_doors::dreamer_promotion_seconds::{
    candidate, open_auto_promotion_vault, promotion_run,
};
use oneiron::test_doors::native_person_mint::mint_named_person;
use oneiron::vault_cleanup::run_vault_cleanup;
use oneiron::{EntityId, Vault};

const READER: &str = "reader";

/// What the user said: the one mention of Ann.
const SAID: &str = "I had lunch with Ann today.";

fn open() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("vault");
    (dir, vault)
}

/// A TURN holding [`SAID`], spoken by the user.
fn turn(vault: &Vault) -> EntityId {
    let body = rmp_serde::to_vec_named(&std::collections::BTreeMap::from([
        ("speaker", "user"),
        ("text", SAID),
    ]))
    .expect("a TURN body");
    let id = EntityId::now();
    let at = vault.now_recorded_at();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_TURN,
            TimeRange { start: at, end: at },
            at,
            &body,
        )
        .expect("a TURN");
    id
}

/// The name the stored PERSON `person` bears.
fn name(vault: &Vault, person: EntityId) -> Option<String> {
    person_body(vault, person)
        .expect("read")
        .and_then(|body| body.name)
}

/// The mint door mints Ann from `said` under the extraction ids `attempt`
/// and `parent`; her id.
fn mint_ann(
    vault: &Vault,
    attempt: AttemptId,
    parent: Option<AttemptId>,
    said: EntityId,
) -> EntityId {
    mint_named_person(vault, attempt, parent, said, "Ann").expect("the mint runs")
}

/// A cleanup run archives `person`, an extraction mint with no live claim
/// and no pending try of its lineage.
fn archive_by_cleanup(vault: &Vault, person: EntityId) {
    assert!(
        cleanup_lists(vault, person).expect("read"),
        "no try of her lineage is pending and no claim names her: the cleanup lists her"
    );
    let report = run_vault_cleanup(vault, &AttemptId::now()).expect("a cleanup run");
    assert!(
        report.archived.contains(&Some(person)),
        "the run archives her: {report:?}"
    );
    assert!(
        vault.archived_entity(&person).expect("read").is_some(),
        "she is archived"
    );
}

/// `person` is the owner's to read again: no archive marker, the row live
/// under `minted_as`, the name it was minted with, and not the cleanup's to
/// archive.
fn assert_restored(vault: &Vault, person: EntityId, minted_as: &str) {
    assert!(
        vault.archived_entity(&person).expect("read").is_none(),
        "the new mention restored her: she bears no archive marker"
    );
    assert!(row_live(vault, person).expect("read"), "her row is live");
    assert_eq!(
        name(vault, person).as_deref(),
        Some(minted_as),
        "the restored row is the row the first mint wrote"
    );
    assert!(
        !cleanup_lists(vault, person).expect("read"),
        "a restored PERSON is not an empty mint the cleanup lists"
    );
}

#[test]
fn the_same_mention_under_the_same_first_try_restores_the_person_the_cleanup_archived() {
    let (_dir, vault) = open();
    let said = turn(&vault);
    let first_try = AttemptId::now();
    let ann = mint_ann(&vault, first_try, None, said);
    assert!(row_live(&vault, ann).expect("read"), "the mint wrote her");
    assert_eq!(name(&vault, ann).as_deref(), Some("Ann"));
    archive_by_cleanup(&vault, ann);

    // The same TURN names her again under the same first try, as a later
    // try of that lineage would after its origin resolved to it.
    let again = mint_ann(&vault, first_try, None, said);
    assert_eq!(again, ann, "the same mention derives the same id");
    assert_restored(&vault, ann, "Ann");
}

#[test]
fn the_same_mention_under_the_same_parent_restores_the_person_the_cleanup_archived() {
    let (_dir, vault) = open();
    let said = turn(&vault);
    let parent = AttemptId::now();
    let ann = mint_ann(&vault, AttemptId::now(), Some(parent), said);
    assert!(row_live(&vault, ann).expect("read"), "the mint wrote her");
    archive_by_cleanup(&vault, ann);

    // Another attempt id under the same parent id names her from the same
    // TURN, as another child of one parent would.
    let again = mint_ann(&vault, AttemptId::now(), Some(parent), said);
    assert_eq!(again, ann, "two attempts under one parent derive one id");
    assert_restored(&vault, ann, "Ann");
}

#[test]
fn a_claim_the_promotion_lands_about_an_archived_person_restores_her() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_auto_promotion_vault(dir.path()).expect("vault");
    let mut run = promotion_run(&vault).expect("a queued Dreamer run");
    // The run's TURN reads "my name is Ada". The mint door minted Ada from
    // it under an attempt id that is not queued, and no claim names her.
    let ada =
        mint_named_person(&vault, AttemptId::now(), None, run.turn, "Ada").expect("the mint runs");
    assert!(row_live(&vault, ada).expect("read"), "the mint wrote her");
    archive_by_cleanup(&vault, ada);

    // The Dreamer's promotion lands a claim about her, with no mint of this
    // run before it.
    run.subject = ada;
    let claim = candidate(&run, "profile.name", "Ada", None);
    let id = claim.claim_id;
    let outcome =
        promote_consolidated_claims(&vault, &run.run, vec![claim]).expect("a promotion pass");
    assert_eq!(outcome.landed, vec![id], "the claim lands: {outcome:?}");
    assert_restored(&vault, ada, "Ada");
}

#[test]
fn a_mention_under_another_extraction_leaves_the_archived_person_archived() {
    let (_dir, vault) = open();
    let said = turn(&vault);
    let ann = mint_ann(&vault, AttemptId::now(), None, said);
    archive_by_cleanup(&vault, ann);

    // Another extraction id names an Ann in the same TURN: no two mentions
    // merge by name alone, so it mints its own PERSON.
    let other = mint_ann(&vault, AttemptId::now(), None, said);
    assert_ne!(other, ann, "another extraction id derives another id");
    assert!(
        row_live(&vault, other).expect("read"),
        "its own mint landed"
    );
    assert!(
        vault.archived_entity(&ann).expect("read").is_some(),
        "the archived PERSON is not this extraction's: she stays archived"
    );
}

#[test]
fn a_mention_of_a_person_the_owner_deleted_restores_nothing() {
    // A delete signs with this install's key: the vault needs a keystore.
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_auto_promotion_vault(dir.path()).expect("vault");
    let said = turn(&vault);
    let first_try = AttemptId::now();
    let ann = mint_ann(&vault, first_try, None, said);
    archive_by_cleanup(&vault, ann);
    assert!(
        vault.delete_entity(&ann).expect("the owner's delete"),
        "the delete found her row"
    );
    assert!(
        vault.archived_entity(&ann).expect("read").is_some(),
        "a delete keeps the archive marker of the row it scrubs"
    );

    // The same mention again: the mint neither fails nor brings her back.
    let again = mint_ann(&vault, first_try, None, said);
    assert_eq!(again, ann, "the same mention derives the same id");
    assert!(
        vault.archived_entity(&ann).expect("read").is_some(),
        "the mention cleared no marker of a deleted PERSON"
    );
    assert!(
        !row_live(&vault, ann).expect("read"),
        "a deletion stands: no mention restores a deleted PERSON"
    );
    assert_eq!(
        name(&vault, ann),
        None,
        "the words the delete scrubbed stay gone"
    );
}
