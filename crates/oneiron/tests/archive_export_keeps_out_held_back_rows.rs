#![cfg(oneiron_test_support)]
//! The whole-vault export keeps out a row this vault holds back, and every row whose words came
//! from one (FIX WHOLE-VAULT-EXPORT-CARRIES-HELD-BACK-ROWS). A held-back row reads to no one
//! here and never leaves while held; the archive carries no hold, so a restore would read it
//! openly.
//!
//! Public doors plus the source-audience hold door; neutral fixtures; vaults in tempdirs.
//!
//! * `a_whole_vault_export_keeps_out_a_row_held_back_here`: two PERSONs travel; once the vault
//!   holds one back (the vault it came from withheld it after it travelled), the export carries
//!   the other and not the held one.
//! * `a_row_whose_words_came_from_a_held_row_stays_out`: a CLAIM derived from a held CLAIM stays
//!   out with it; the PERSONs they are about, and a CLAIM with no held source, still travel.
//!
//! Both run red at main 5a4ffa6a1ca, whose export door asks only the off-record overlay and the
//! use limit, and green at the fix.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test archive_export_keeps_out_held_back_rows`.

use std::collections::BTreeSet;

use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::test_doors::turn_programs::withhold_turn;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeKind, EntityId,
    TimeRange, Vault, VaultConfig,
};
use rmpv::Value;

const AT: u64 = 100;

fn range() -> TimeRange {
    TimeRange { start: AT, end: AT }
}

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir for the vault");
    let vault = Vault::open_owned(dir.path(), VaultConfig::default()).expect("open the vault");
    (dir, vault)
}

fn put_person(vault: &Vault, name: &[u8]) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(&id, ENTITY_TYPE_PERSON, range(), AT, name)
        .expect("FIXTURE: put the PERSON");
    id
}

fn put_claim(vault: &Vault, predicate: &str, subject: EntityId, value: &str) -> EntityId {
    let id = EntityId::now();
    let body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(subject),
        Value::from(value),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("FIXTURE: claim body");
    vault
        .put_claim(&id, &body, range(), AT)
        .expect("FIXTURE: put the claim");
    id
}

/// Holds `row` back here, as a sync import does when the vault it came from withheld it after
/// it travelled.
fn hold_back(vault: &Vault, row: EntityId) {
    assert!(
        withhold_turn(vault, row).expect("FIXTURE: hold the row back"),
        "FIXTURE: the hold is new"
    );
}

/// The ids of every entity and claim a whole-vault export of `vault` carries.
fn carried_ids(vault: &Vault) -> BTreeSet<String> {
    let archive = vault
        .export_whole_vault(true)
        .expect("whole-vault export")
        .bytes()
        .to_vec();
    let document = vault
        .read_whole_vault_archive(&archive)
        .expect("the archive reads back");
    document
        .evidence_ledger
        .entities
        .iter()
        .chain(document.claims.iter())
        .map(|row| row.id.clone())
        .collect()
}

#[test]
fn a_whole_vault_export_keeps_out_a_row_held_back_here() {
    let (_dir, vault) = open_vault();
    let held = put_person(&vault, b"held-person");
    let kept = put_person(&vault, b"kept-person");
    let before = carried_ids(&vault);
    assert!(
        before.contains(&held.to_hex()) && before.contains(&kept.to_hex()),
        "FIXTURE: before the hold the export carries both PERSONs"
    );

    hold_back(&vault, held);

    let after = carried_ids(&vault);
    assert!(
        !after.contains(&held.to_hex()),
        "the export keeps out a row this vault holds back"
    );
    assert!(
        after.contains(&kept.to_hex()),
        "the export still carries a row it does not hold back"
    );
}

#[test]
fn a_row_whose_words_came_from_a_held_row_stays_out() {
    let (_dir, vault) = open_vault();
    let first = put_person(&vault, b"first-person");
    let second = put_person(&vault, b"second-person");
    let source = put_claim(&vault, "test.role", first, "source-words");
    let derived = put_claim(&vault, "test.role", second, "derived-words");
    vault
        .put_edge(&derived, EdgeKind::DerivedFrom, &source, 1.0)
        .expect("FIXTURE: the derived claim names its source");
    let unrelated = put_claim(&vault, "test.city", second, "unrelated-words");
    let before = carried_ids(&vault);
    for (kind, id) in [
        ("source claim", source),
        ("derived claim", derived),
        ("unrelated claim", unrelated),
    ] {
        assert!(
            before.contains(&id.to_hex()),
            "FIXTURE: before the hold the export carries the {kind}"
        );
    }

    hold_back(&vault, source);

    let after = carried_ids(&vault);
    assert!(
        !after.contains(&source.to_hex()),
        "the export keeps out the held claim"
    );
    assert!(
        !after.contains(&derived.to_hex()),
        "the export keeps out a claim whose words came from a held claim"
    );
    for (kind, id) in [
        ("first PERSON", first),
        ("second PERSON", second),
        ("unrelated claim", unrelated),
    ] {
        assert!(
            after.contains(&id.to_hex()),
            "the export still carries the {kind}, whose words came from no held row"
        );
    }
}
