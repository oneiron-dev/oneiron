//! FIX SOURCE-AUDIENCE-WALK-MISSES-PSYCH-PROFILE-SOURCES: a PSYCH_PROFILE's words are the CLAIMs
//! it cites, which profile landing names only as typed sources in the body (and in the dependency
//! index), never as an edge. The source-audience walk the read judge (`readable_with_read_in`)
//! and the replication judge share read no such source, so a profile copying a claim learned
//! from a private mailbox read to a person outside that mailbox's policy, and a profile built
//! from a held claim still read while the claim read to no one.
//!
//! * `a_profile_reads_only_to_the_readers_of_each_claim_it_copies`: a profile of a claim a
//!   mailbox source supports reads to that mailbox's reader and not to a person outside its
//!   policy; a profile of a free claim reads to both.
//! * `a_profile_built_from_a_held_claim_reads_to_no_one_and_stays_home`: once its claim is held
//!   back here, the profile reads to no one and does not travel, while the PERSON it describes
//!   still does both.
//! * `a_companion_read_withholds_a_profile_of_a_mailbox_claim` (REVIEW-9906 round 1): the
//!   companion profile read (`companion_profile_snapshot_admitted`) reads the sealed profile past
//!   the scoped row gate, so it asks the source audience itself: under a companion grant, a read
//!   that authenticates no reader of the mailbox gets the profile of its claim withheld, while the
//!   profile of a free claim is still admitted.
//!
//! The first two run red at #9874's head c351d3d0d6a, whose walk adds the profile's sources to
//! the hold walk alone, and green at the fix; the third runs red at the first fix eb92b8d5fea,
//! whose companion read asks no source audience, and green at the round-1 fix.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test source_audience_psych_profile_sources`
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::companion::CompanionProfileAdmission;
use oneiron::psych_profile::{
    PsychProfile, PsychProfileConfidence, PsychProfileKey, PsychProfileSource,
    PsychProfileSourceWords, psych_profile_entity_id,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::settings::ReadDestination;
use oneiron::store::revision_ref::RevisionRef;
use oneiron::test_doors::source_audience::land_source_bound_artifact;
use oneiron::test_doors::source_audience_binding::{reads, travels};
use oneiron::test_doors::turn_programs::withhold_turn;
use oneiron::{
    AccessGrant, ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeKind,
    EntityId, TimeRange, Vault, VaultConfig,
};
use rmpv::Value;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const AT: u64 = 100;

fn range() -> TimeRange {
    TimeRange { start: AT, end: AT }
}

fn put_person(vault: &Vault) -> Result<EntityId, Box<dyn std::error::Error>> {
    let id = EntityId::now();
    vault.put_entity(&id, ENTITY_TYPE_PERSON, range(), AT, b"profiled-person")?;
    Ok(id)
}

fn put_claim(
    vault: &Vault,
    predicate: &str,
    subject: EntityId,
    value: &str,
) -> Result<EntityId, Box<dyn std::error::Error>> {
    let id = EntityId::now();
    let body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(subject),
        Value::from(value),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    vault.put_claim(&id, &body, range(), AT)?;
    Ok(id)
}

/// Lands a PSYCH_PROFILE about `person` whose one typed source is `claim`, as profile landing
/// records it (`psych_profile::sources::profile_source_in`): in the body, with no edge to the
/// claim.
fn put_profile_from(
    vault: &Vault,
    person: EntityId,
    claim: EntityId,
) -> Result<EntityId, Box<dyn std::error::Error>> {
    let id = EntityId::now();
    put_profile_at(vault, id, person, claim)?;
    Ok(id)
}

/// [`put_profile_from`] at the row `id`.
fn put_profile_at(
    vault: &Vault,
    id: EntityId,
    person: EntityId,
    claim: EntityId,
) -> Result<(), Box<dyn std::error::Error>> {
    let profile = PsychProfile::new(
        person,
        "compact",
        "Copied prose from the source claim.",
        "Narrative about the person.",
        vec![claim],
        PsychProfileConfidence::new(0.9, 0.8, 0.7)?,
    )?
    .with_sources(vec![PsychProfileSource {
        revision_ref: claim,
        document_ref: claim,
        world_ref: None,
        document_revision: RevisionRef(*claim.as_bytes()),
        words: PsychProfileSourceWords::Record {
            content: [0x5C; 32],
        },
    }])?;
    vault.put_psych_profile(&id, &profile)?;
    Ok(())
}

#[test]
fn a_profile_reads_only_to_the_readers_of_each_claim_it_copies() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner_actor = vault.ensure_embedded_owner_actor()?;
    let insider = EntityId::now();
    let outsider = EntityId::now();
    let person = put_person(&vault)?;

    // A mailbox's row under a policy one person reads, and a claim learned from it alone.
    let mailbox =
        land_source_bound_artifact(&vault, BTreeSet::from([insider]), false, owner_actor, 1)?;
    let mailbox_claim = put_claim(&vault, "test.mailbox", person, "words from the mailbox")?;
    vault.put_edge(&mailbox.row, EdgeKind::Supports, &mailbox_claim, 1.0)?;
    // A claim nothing binds.
    let free_claim = put_claim(&vault, "test.free", person, "open words")?;
    let mailbox_profile = put_profile_from(&vault, person, mailbox_claim)?;
    let free_profile = put_profile_from(&vault, person, free_claim)?;

    assert!(
        reads(&vault, mailbox_claim, &[insider])?,
        "FIXTURE: the mailbox's reader reads the claim learned from it"
    );
    assert!(
        !reads(&vault, mailbox_claim, &[outsider])?,
        "FIXTURE: a person outside the mailbox's policy does not read the claim"
    );

    assert!(
        !reads(&vault, mailbox_profile, &[outsider])?,
        "a profile copying a mailbox claim read to a person outside the mailbox's policy"
    );
    assert!(
        reads(&vault, mailbox_profile, &[insider])?,
        "the mailbox's reader reads the profile of its claim"
    );
    assert!(
        reads(&vault, free_profile, &[outsider])?,
        "a profile of a free claim still reads to a person outside the mailbox's policy"
    );
    assert!(
        reads(&vault, free_profile, &[insider])?,
        "a profile of a free claim still reads to the mailbox's reader"
    );
    Ok(())
}

#[test]
fn a_profile_built_from_a_held_claim_reads_to_no_one_and_stays_home() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let viewer = vault.ensure_embedded_owner_actor()?;
    let person = put_person(&vault)?;
    let claim = put_claim(&vault, "test.role", person, "source-words")?;
    let profile = put_profile_from(&vault, person, claim)?;
    assert!(
        reads(&vault, profile, &[viewer])?,
        "FIXTURE: before the hold the profile reads"
    );
    assert!(
        travels(&vault, profile)?,
        "FIXTURE: before the hold the profile travels"
    );

    // Held back here, as a sync import does when the vault it came from withheld the claim
    // after it travelled.
    assert!(withhold_turn(&vault, claim)?, "FIXTURE: the hold is new");
    assert!(
        !reads(&vault, claim, &[viewer])?,
        "FIXTURE: the held claim reads to no one"
    );

    assert!(
        !reads(&vault, profile, &[viewer])?,
        "a profile built from a held claim still read"
    );
    assert!(
        !travels(&vault, profile)?,
        "a profile built from a held claim travels"
    );
    assert!(
        reads(&vault, person, &[viewer])?,
        "the PERSON the profile describes still reads"
    );
    assert!(
        travels(&vault, person)?,
        "the PERSON the profile describes still travels"
    );
    Ok(())
}

#[test]
fn a_companion_read_withholds_a_profile_of_a_mailbox_claim() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner_actor = vault.ensure_embedded_owner_actor()?;
    let insider = EntityId::now();
    let principal = EntityId::now();

    // Two PERSONs, each with one profile from one claim: one claim learned from a mailbox alone,
    // one nothing binds. The companion principal holds a profile grant for each.
    let mailbox =
        land_source_bound_artifact(&vault, BTreeSet::from([insider]), false, owner_actor, 1)?;
    let mailbox_person = put_person(&vault)?;
    let mailbox_claim = put_claim(
        &vault,
        "test.mailbox",
        mailbox_person,
        "words from the mailbox",
    )?;
    vault.put_edge(&mailbox.row, EdgeKind::Supports, &mailbox_claim, 1.0)?;
    let free_person = put_person(&vault)?;
    let free_claim = put_claim(&vault, "test.free", free_person, "open words")?;
    let key = |person: EntityId| PsychProfileKey {
        person,
        facet: None,
        world: None,
    };
    for (person, claim) in [(mailbox_person, mailbox_claim), (free_person, free_claim)] {
        put_profile_at(&vault, psych_profile_entity_id(&key(person)), person, claim)?;
        vault.create_access_grant(
            &EntityId::now(),
            &AccessGrant::companion_profile_read(principal, person, None, 1),
        )?;
    }
    // A companion read whose caller has no read lane: it authenticates no reader of the mailbox.
    let admitted = |person: EntityId| {
        vault.companion_profile_snapshot_admitted(
            &principal,
            &key(person),
            &ReadDestination::on_device(),
            None,
            None,
        )
    };

    let free = admitted(free_person)?;
    assert!(
        matches!(free, CompanionProfileAdmission::Admitted { .. }),
        "FIXTURE: the grant admits the profile of a free claim: {free:?}"
    );
    let copied = admitted(mailbox_person)?;
    assert!(
        matches!(copied, CompanionProfileAdmission::Withheld { .. }),
        "a companion read with no reader of the mailbox returned a profile copying its claim: \
         {copied:?}"
    );
    Ok(())
}
