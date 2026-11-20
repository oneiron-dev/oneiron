//! A PSYCH_PROFILE's words are those of the CLAIMs it cites, which profile landing names only as
//! typed sources in the body (FIX 11766), never as an edge. The derived-source conjunct of a
//! scoped read and the owner's C6 use-limit check take a row's sources from
//! `scope_summary::word_sources_in`, which named none for a profile, so neither judged a cited
//! claim (FIX PSYCH-PROFILE-DERIVED-SOURCE-CONJUNCT-MISSES-CITED-CLAIMS).
//!
//! Public doors only; neutral fixtures; vaults in tempdirs.
//!
//! * `a_reader_missing_a_cited_claim_is_withheld_the_profile`: the readers are credentials of
//!   the vault owner narrowed by a records caveat, as a transport verifies a request's slip
//!   (`summary_read_withholds_unreadable_sources.rs`). R1 names the profile, its PERSON and the
//!   claim it cites, and reads the profile; R2 names the profile and its PERSON alone, does not
//!   read the claim, and is withheld the profile on `vault.get`, as an absent row is.
//! * `a_use_limited_cited_claim_withholds_the_profile_from_the_owner`: on a hosted vault a
//!   customer hold refuses the privacy erase of the cited claim, which keeps it stored and
//!   use-limited (C6 storage-only). The owner's `vault.get` of the profile served it before and
//!   answers it as absent after (FIX 1496 S8); a profile of another claim still reads.
//!
//! Both run red at main 0aedc807c52, whose `word_sources_in` reads a PSYCH_PROFILE as its own,
//! and green at the fix.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test psych_profile_read_judges_cited_claims`
#![cfg(oneiron_test_support)]

use std::sync::atomic::{AtomicU8, Ordering};

use oneiron::authority::{HostSlipIssuer, VerifiedSlip};
use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::LegalHoldTarget;
use oneiron::memory::{EraseOptions, EraseReason, Memory};
use oneiron::psych_profile::{
    PsychProfile, PsychProfileConfidence, PsychProfileSource, PsychProfileSourceWords,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::store::revision_ref::RevisionRef;
use oneiron::test_support::{bind_host_owner, provision_engine_machines};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeActorClass, EntityId,
    HostingPrivacyPosture, TimeRange, Vault, VaultConfig,
};
use oneiron_testkit::door;
use rmpv::Value as MsgValue;
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const AT: u64 = 100;

const CHALLENGE: &[u8] = b"oneiron-request:psych-profile-read-judges-cited-claims";

/// The profile's text tier, copied from the claim it cites.
const PROFILE_TEXT: &str = "Copied prose from the cited claim.";

fn range() -> TimeRange {
    TimeRange { start: AT, end: AT }
}

fn put_person(vault: &Vault) -> TestResult<EntityId> {
    let id = EntityId::now();
    vault.put_entity(&id, ENTITY_TYPE_PERSON, range(), AT, b"profiled person")?;
    Ok(id)
}

fn put_claim(vault: &Vault, subject: EntityId, value: &str) -> TestResult<EntityId> {
    let id = EntityId::now();
    let mut body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        MsgValue::from(value),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )?;
    body.salience = Some(0.9);
    body.source = Some(oneiron::claim::ClaimSource::UserStated);
    vault.put_claim(&id, &body, range(), AT)?;
    Ok(id)
}

/// Lands a PSYCH_PROFILE about `person` whose one typed source is `claim`, as profile landing
/// records it (`psych_profile::sources::profile_source_in`): in the body, with no edge to the
/// claim.
fn put_profile_from(vault: &Vault, person: EntityId, claim: EntityId) -> TestResult<EntityId> {
    let profile = PsychProfile::new(
        person,
        "compact",
        PROFILE_TEXT,
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
    let id = EntityId::now();
    vault.put_psych_profile(&id, &profile)?;
    Ok(id)
}

/// `reader`'s `vault.get` of `id`.
fn get(reader: &Memory<'_>, id: &EntityId) -> Value {
    door::invoke(reader, "vault.get", json!({ "entity_ref": id.to_hex() }))
        .unwrap_or_else(|error| panic!("vault.get answers an error: {error:?}"))
}

/// A served `vault.get` names the row.
fn assert_served(read: &Value, id: &EntityId, what: &str) {
    assert_eq!(
        read.pointer("/value/id_hex"),
        Some(&json!(id.to_hex())),
        "{what}: {read}"
    );
}

/// A withheld read answers its receipt and no value, as an absent row does.
fn assert_withheld(read: &Value, what: &str) {
    assert!(
        read.get("narrowing").is_some(),
        "{what} answers no read receipt: {read}"
    );
    assert!(read["value"].is_null(), "{what} is served: {read}");
}

/// A rooted vault whose host mints the owner's credentials, a PERSON, a claim about it and a
/// profile citing that claim. The vault closes before its directory goes.
struct Fixture {
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    person: EntityId,
    claim: EntityId,
    profile: EntityId,
    _dir: tempfile::TempDir,
}

fn open() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let issuer = provision_engine_machines(&vault);
    bind_host_owner(&vault, &issuer, owner)?;
    let person = put_person(&vault)?;
    let claim = put_claim(&vault, person, "prefers quiet mornings")?;
    let profile = put_profile_from(&vault, person, claim)?;
    Ok(Fixture {
        vault,
        issuer,
        owner,
        person,
        claim,
        profile,
        _dir: dir,
    })
}

fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// The owner's handle bound to a live `human` credential the host mints from its root claims,
/// held by a records caveat to `records`, verified as a transport verifies the slip a request
/// presents.
fn narrowed_owner<'v>(fixture: &'v Fixture, records: &[EntityId]) -> Memory<'v> {
    let mut claims = fixture
        .vault
        .ensure_host_root_slip(&fixture.issuer)
        .expect("the host root slip")
        .claims;
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = fixture.owner.to_hex();
    claims.actor_class = Some("human".to_owned());
    claims.records = records.iter().map(EntityId::to_hex).collect();
    let slip = fixture
        .vault
        .mint_capability_slip(&fixture.issuer, claims)
        .expect("mint the credential");
    let binding = fixture
        .issuer
        .binding_proof(&slip, CHALLENGE)
        .expect("the binding proof");
    let proof: VerifiedSlip = fixture
        .vault
        .verify_capability_slip(&fixture.issuer.public_key(), &slip, CHALLENGE, &binding)
        .expect("verify the credential");
    fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .with_read_proof(&proof)
}

#[test]
fn a_reader_missing_a_cited_claim_is_withheld_the_profile() -> TestResult {
    let fixture = open()?;
    let r1 = narrowed_owner(
        &fixture,
        &[
            fixture.owner,
            fixture.person,
            fixture.profile,
            fixture.claim,
        ],
    );
    let r2 = narrowed_owner(&fixture, &[fixture.owner, fixture.person, fixture.profile]);
    // The setup: R1 reads the claim and the profile; R2 reads the PERSON but not the claim.
    assert_served(
        &get(&r1, &fixture.claim),
        &fixture.claim,
        "FIXTURE: R1 reads the cited claim",
    );
    assert_served(
        &get(&r1, &fixture.profile),
        &fixture.profile,
        "FIXTURE: R1, a reader of the cited claim, reads the profile",
    );
    assert_served(
        &get(&r2, &fixture.person),
        &fixture.person,
        "FIXTURE: R2 reads the PERSON its caveat names",
    );
    assert_withheld(
        &get(&r2, &fixture.claim),
        "FIXTURE: R2's read of the claim its caveat leaves out",
    );
    // The promise.
    let read = get(&r2, &fixture.profile);
    assert_withheld(
        &read,
        "R2, who does not read the cited claim, reading the profile",
    );
    assert!(
        !read.to_string().contains(PROFILE_TEXT),
        "the withheld read carries none of the profile's words: {read}"
    );
    Ok(())
}

fn owner_proof(vault: &Vault) -> TestResult<AuthenticatedOwner> {
    let owner = vault.ensure_embedded_owner_actor()?;
    Ok(vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?)
}

/// Places a customer hold on `record` and runs its privacy erase, which the hold refuses: the
/// record stays stored and use-limited.
fn keep_use_limited(vault: &Vault, record: EntityId) -> TestResult {
    let hold = vault.place_legal_hold(
        &owner_proof(vault)?,
        vec![LegalHoldTarget::Record(record)],
        Some("matter-profile-cited-claim".to_owned()),
    )?;
    assert!(hold.stands(), "FIXTURE: the customer hold stands: {hold:?}");
    let memory = door::owner(vault)?;
    let preview = memory.preview_entity_delete(&record)?;
    let outcome = memory.confirm_entity_erase(
        &preview,
        EraseOptions {
            reason: EraseReason::GdprDelete,
            also_same_bytes: false,
            veto_starter: None,
        },
    )?;
    assert_eq!(
        outcome.first.reason.as_str(),
        "privacy_erase_kept",
        "FIXTURE: the held privacy erase is kept: {outcome:?}"
    );
    assert!(
        vault.legal_hold_use_limit(&record)?.is_some(),
        "FIXTURE: the kept erase use-limits the record"
    );
    Ok(())
}

#[test]
fn a_use_limited_cited_claim_withholds_the_profile_from_the_owner() -> TestResult {
    let dir = tempfile::tempdir()?;
    let mut config = VaultConfig::default();
    config.privacy.posture = HostingPrivacyPosture::Hosted;
    let vault = Vault::open_owned(dir.path(), config)?;
    vault.install_device_keystore(std::sync::Arc::new(
        oneiron_keystore::MemoryKeystore::default(),
    ));
    let person = put_person(&vault)?;
    let held = put_claim(&vault, person, "prefers quiet mornings")?;
    let kept = put_claim(&vault, person, "likes long walks")?;
    let held_profile = put_profile_from(&vault, person, held)?;
    let kept_profile = put_profile_from(&vault, person, kept)?;
    let owner = door::owner(&vault)?;
    assert_served(
        &get(&owner, &held_profile),
        &held_profile,
        "FIXTURE: the owner reads the profile before its claim is kept",
    );

    keep_use_limited(&vault, held)?;

    assert_served(
        &get(&owner, &kept_profile),
        &kept_profile,
        "the owner still reads the profile of a claim with no use limit",
    );
    let read = get(&owner, &held_profile);
    assert_withheld(
        &read,
        "the owner's read of a profile citing a use-limited claim",
    );
    assert!(
        !read.to_string().contains(PROFILE_TEXT),
        "the withheld read carries none of the profile's words: {read}"
    );
    Ok(())
}
