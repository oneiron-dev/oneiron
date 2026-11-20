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
//! * `a_profile_built_from_a_held_claim_stays_out`: a PSYCH_PROFILE names the CLAIM it read as a
//!   typed source in its body, never as an edge (REVIEW-9874 round 2); once that CLAIM is held,
//!   the profile stays out with it, while the PERSON it describes still travels.
//!
//! The first two run red at main 5a4ffa6a1ca, whose export door asks only the off-record overlay
//! and the use limit, and green at the fix; the third runs red at e95173f3140, whose hold walk
//! reads no profile source, and green at the round-2 fix.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test archive_export_keeps_out_held_back_rows`.

use std::collections::BTreeSet;

use oneiron::psych_profile::{
    PsychProfile, PsychProfileConfidence, PsychProfileSource, PsychProfileSourceWords,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::revision_ref::RevisionRef;
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

/// Lands a PSYCH_PROFILE about `person` whose one typed source is `claim`, as profile landing
/// records it: in the body, with no edge to the claim.
fn put_profile_from(vault: &Vault, person: EntityId, claim: EntityId) -> EntityId {
    let profile = PsychProfile::new(
        person,
        "compact",
        "Copied prose from the source claim.",
        "Narrative about the person.",
        vec![claim],
        PsychProfileConfidence::new(0.9, 0.8, 0.7).expect("FIXTURE: confidence"),
    )
    .expect("FIXTURE: profile")
    .with_sources(vec![PsychProfileSource {
        revision_ref: claim,
        document_ref: claim,
        world_ref: None,
        document_revision: RevisionRef(*claim.as_bytes()),
        words: PsychProfileSourceWords::Record {
            content: [0x5C; 32],
        },
    }])
    .expect("FIXTURE: profile sources");
    let id = EntityId::now();
    vault
        .put_psych_profile(&id, &profile)
        .expect("FIXTURE: put the profile");
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

#[test]
fn a_profile_built_from_a_held_claim_stays_out() {
    let (_dir, vault) = open_vault();
    let person = put_person(&vault, b"profiled-person");
    let claim = put_claim(&vault, "test.role", person, "source-words");
    let profile = put_profile_from(&vault, person, claim);
    let before = carried_ids(&vault);
    for (kind, id) in [("PERSON", person), ("claim", claim), ("profile", profile)] {
        assert!(
            before.contains(&id.to_hex()),
            "FIXTURE: before the hold the export carries the {kind}"
        );
    }

    hold_back(&vault, claim);

    let after = carried_ids(&vault);
    assert!(
        !after.contains(&claim.to_hex()),
        "the export keeps out the held claim"
    );
    assert!(
        !after.contains(&profile.to_hex()),
        "the export keeps out a profile built from a held claim"
    );
    assert!(
        after.contains(&person.to_hex()),
        "the export still carries the PERSON the profile describes"
    );
}
