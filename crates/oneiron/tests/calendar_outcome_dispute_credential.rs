//! CAL-07 review P1 (#8202, blind review round 1): `vault.calendar.event_outcome`
//! names the machine outcomes that dispute the owner's answer, and most of them
//! are claims the answer superseded. The verb's surfaceable lane admits the
//! EVENT and its active claims only, so each disputing claim is admitted through
//! the caller's own lane at the record verbs' status before its outcome is
//! returned. A credential whose records caveat leaves that claim out never sees
//! the outcome it holds; the owner's unheld credential still does.
//!
//! Public paths only. A device vault with its host root and embedded owner;
//! each credential is minted from the host root's claims and verified with the
//! host's binding proof, as a transport verifies the slip a request presents
//! (the fixture of `tests/receipts_credential_pin.rs`).
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test calendar_outcome_dispute_credential`

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU8, Ordering};

use oneiron::authority::{HostSlipIssuer, VerifiedSlip};
use oneiron::calendar::meeting::CalendarMeetingRequest;
use oneiron::calendar::outcome::{
    EventOutcome, EventOutcomeBasis, EventOutcomeClaimValue, record_event_outcome,
};
use oneiron::memory::Memory;
use oneiron::registry::ENTITY_TYPE_EVENT;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig,
};
use rmpv::Value;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const CHALLENGE: &[u8] = b"oneiron-request:calendar-outcome-dispute-credential";
const EVENT_START: u64 = 1_754_400_000;
const EVENT_END: u64 = EVENT_START + 3_600;
/// A transcript's machine outcome, before the owner answers.
const MACHINE_AT: u64 = EVENT_END + 600;
const ANSWERED_AT: u64 = EVENT_END + 1_800;

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    event: EntityId,
    origin: EntityId,
    answer: EntityId,
    machine_outcome: EventOutcomeClaimValue,
}

/// A native meeting EVENT whose machine outcome (`no_show`) the owner's answer
/// (`held`) superseded: the answer is the current outcome and the machine
/// claim disputes it.
fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    let issuer = HostSlipIssuer::from_secret(b"oneiron-test-calendar-outcome-dispute-credential")?;
    vault.ensure_host_root_slip(&issuer)?;
    let owner = vault.ensure_embedded_owner_actor()?;

    let event = EntityId::now();
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &Value::Map(vec![(Value::from("name"), Value::from("intro call"))]),
    )?;
    vault.put_entity(
        &event,
        ENTITY_TYPE_EVENT,
        TimeRange {
            start: EVENT_START,
            end: EVENT_END,
        },
        EVENT_START,
        &body,
    )?;
    let origin = EntityId::now();
    let mut origin_claim = ClaimBody::new(
        "calendar.origin",
        ClaimSubject::Entity(event),
        Value::from("native"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )?;
    origin_claim.scope_facet = vault.default_facet()?;
    vault.put_claim(
        &origin,
        &origin_claim,
        TimeRange {
            start: EVENT_START,
            end: EVENT_START,
        },
        EVENT_START,
    )?;

    let machine_outcome = EventOutcomeClaimValue {
        outcome: EventOutcome::NoShow,
        basis: EventOutcomeBasis::Machine,
        recorded_at: MACHINE_AT,
    };
    record_event_outcome(&vault, event, &machine_outcome, ClaimSource::Observed)?;
    let answer = record_event_outcome(
        &vault,
        event,
        &EventOutcomeClaimValue {
            outcome: EventOutcome::Held,
            basis: EventOutcomeBasis::OwnerAttested,
            recorded_at: ANSWERED_AT,
        },
        ClaimSource::UserStated,
    )?;
    Ok(Fixture {
        _dir: dir,
        vault,
        issuer,
        owner,
        event,
        origin,
        answer,
        machine_outcome,
    })
}

fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// The owner's live `human` credential this host mints, held to `records`
/// (empty: no records caveat), verified as a transport verifies it.
fn owner_credential(
    fixture: &Fixture,
    records: BTreeSet<String>,
) -> Result<VerifiedSlip, Box<dyn std::error::Error>> {
    let root = fixture.vault.ensure_host_root_slip(&fixture.issuer)?;
    let mut claims = root.claims;
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = fixture.owner.to_hex();
    claims.actor_class = Some("human".to_owned());
    claims.records = records;
    let slip = fixture
        .vault
        .mint_capability_slip(&fixture.issuer, claims)?;
    let binding = fixture.issuer.binding_proof(&slip, CHALLENGE)?;
    Ok(fixture.vault.verify_capability_slip(
        &fixture.issuer.public_key(),
        &slip,
        CHALLENGE,
        &binding,
    )?)
}

/// The verb's answer for the fixture's EVENT as `reader` reads it: the current
/// outcome and the disputing machine outcomes, or `None` when the EVENT is not
/// readable.
fn event_outcome_seen(
    fixture: &Fixture,
    reader: &Memory<'_>,
) -> Result<Option<(EventOutcome, Vec<EventOutcomeClaimValue>)>, Box<dyn std::error::Error>> {
    let read = reader.calendar_event_outcome(&CalendarMeetingRequest {
        event_ref: fixture.event.to_hex(),
    })?;
    Ok(read
        .value
        .map(|outcome| (outcome.outcome, outcome.disputing_machine_outcomes)))
}

#[test]
fn the_owners_unheld_credential_sees_the_machine_outcome_its_answer_superseded() -> TestResult {
    let fixture = fixture()?;
    let proof = owner_credential(&fixture, BTreeSet::new())?;
    let reader = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .with_read_proof(&proof);
    let seen = event_outcome_seen(&fixture, &reader)?;
    assert_eq!(
        seen,
        Some((EventOutcome::Held, vec![fixture.machine_outcome])),
        "the owner's answer is the current outcome, and the machine outcome it \
         superseded disputes it"
    );
    Ok(())
}

#[test]
fn a_credential_that_cannot_read_the_superseded_machine_claim_sees_no_dispute() -> TestResult {
    let fixture = fixture()?;
    // Held by a records caveat to the EVENT, its active claims (the origin and
    // the owner's answer) and the owner's own row: everything but the machine
    // claim the answer superseded.
    let proof = owner_credential(
        &fixture,
        BTreeSet::from([
            fixture.event.to_hex(),
            fixture.origin.to_hex(),
            fixture.answer.to_hex(),
            fixture.owner.to_hex(),
        ]),
    )?;
    let reader = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .with_read_proof(&proof);
    let seen = event_outcome_seen(&fixture, &reader)?;
    assert_eq!(
        seen,
        Some((EventOutcome::Held, Vec::new())),
        "the held credential reads the EVENT and the answer, and no outcome of the \
         machine claim it may not read"
    );
    Ok(())
}
