//! A calendar invite the hygiene wall refuses answers `BAD_REQUEST` and
//! names the law that refused it (ARCH-0060 #invites, #invite-binding-closed;
//! the engine's contract in `memory/outbound/errors.rs`: "A refusal is a
//! `bad_request`, not an internal fault"). FIX
//! CALENDAR-COLD-INVITE-INVALID-STATE.
//!
//! On main the outbound chokepoint turned every calendar admission refusal
//! into `INVALID_STATE` "calendar.invite failed calendar admission", "Refresh
//! the current effect state before retrying": a send that can never pass
//! read as a stale one, and the law was lost. Each test prints the answer
//! it got when it fails.
//!
//! The fixture is the CAL-09 surface oracle's (`tests/it/calendar_surface_oracle.rs`),
//! whose `oneiron_calendar_invite_still_refuses_a_cold_invite` turns green
//! with this fix too.
//!
//! Run: `cargo test --locked -p oneiron --all-features --test calendar_invite_refusal_code`.
#![cfg(feature = "test-support")]

mod common;

use common::entity as test_id;
use oneiron::calendar::transcript::{
    permit_calendar_read_for_test, permit_imported_calendar_source_for_test,
};
use oneiron::registry::{ENTITY_TYPE_EVENT, ENTITY_TYPE_PERSON};
use oneiron::{
    CalendarInviteMethod, CalendarInviteSurfaceInput, CalendarInviteSurfaceMethod,
    ClaimApprovalStatus, ClaimCandidate, ClaimSource, ClaimSubject, EdgeActorClass, EntityId,
    MEMORY_CODE_BAD_REQUEST, Memory, MemoryError, TimeRange, Vault, VaultConfig, WriteActor,
    WriteEnvelope, WriteProvenance,
};
use rmpv::Value;

const ACTOR_SEED: u8 = 0x81;
const EVENT_SEED: u8 = 0x82;
const INVITE_UID: &str = "one-1786@oneiron.test";
const INVITE_RECIPIENT: &str = "guest@example.test";
const INVITE_ARTIFACT_SEED: u8 = 0x8A;
const IDENTITY_SEED: u8 = 0x8B;

fn temp_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    vault.install_device_keystore(std::sync::Arc::new(
        oneiron_keystore::MemoryKeystore::default(),
    ));
    vault
        .prepare_install_signing()
        .expect("load this install's signing keys");
    (dir, vault)
}

fn at(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

/// A Human actor with calendar read scope and its Imported source permit.
fn actor_facade(vault: &Vault) -> (EntityId, Memory<'_>) {
    let actor = test_id(ACTOR_SEED);
    vault
        .put_entity(&actor, ENTITY_TYPE_PERSON, at(1), 1, b"calendar actor")
        .expect("put actor");
    permit_calendar_read_for_test(vault, actor).expect("grant actor read scope");
    permit_imported_calendar_source_for_test(vault, actor)
        .expect("permit this fixture actor's Imported calendar claims");
    (actor, vault.memory(actor, EdgeActorClass::Human))
}

/// The confirmed booking EVENT the invite is for, with the `calendar.*`
/// family the oracle's imported EVENT carries and its UID indexed: every
/// fact a lawful invite needs except a consent basis.
fn store_booked_event(vault: &Vault, actor: EntityId) {
    let event = test_id(EVENT_SEED);
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &Value::Map(vec![(
            Value::from("name"),
            Value::from("Confirmed booking"),
        )]),
    )
    .expect("encode event body");
    vault
        .put_entity(
            &event,
            ENTITY_TYPE_EVENT,
            TimeRange {
                start: 100,
                end: 200,
            },
            1,
            &body,
        )
        .expect("put event");
    let envelope = WriteEnvelope::new(
        WriteActor::new(actor, EdgeActorClass::Human),
        ClaimSource::Imported,
        WriteProvenance::new(Value::from("calendar-refusal-code")).expect("provenance"),
        ClaimApprovalStatus::Approved,
    );
    let family = [
        ("calendar.origin", Value::from("imported")),
        (
            "calendar.time_kind",
            Value::Map(vec![
                (Value::from("kind"), Value::from("absolute")),
                (Value::from("busy_transparency"), Value::from("busy")),
            ]),
        ),
        (
            "calendar.attendee",
            Value::Map(vec![
                (Value::from("who"), Value::from("cfo@acme.example")),
                (Value::from("role"), Value::from("REQ-PARTICIPANT")),
                (Value::from("partstat"), Value::from("ACCEPTED")),
            ]),
        ),
        (
            "calendar.meeting_link",
            Value::from("https://meet.example/calendar-refusal-code"),
        ),
    ];
    for (index, (predicate, value)) in family.into_iter().enumerate() {
        let mut claim = [0xB0_u8; 16];
        claim[1] = EVENT_SEED;
        claim[2] = u8::try_from(index).expect("family fits a byte");
        vault
            .batch()
            .claim_candidate(
                &EntityId::from_bytes(claim).expect("fixture claim id"),
                ClaimCandidate::new(predicate, ClaimSubject::Entity(event), value, 1.0),
                &envelope,
                at(1),
                1,
            )
            .commit()
            .expect("claim candidate commits");
    }
    oneiron::calendar::index_passport_uid(vault, INVITE_UID, &event).expect("index invite uid");
}

/// The actor's active dedicated sending identity on the primary domain.
fn store_sending_identity(vault: &Vault, actor: EntityId) {
    let identity = common::self_held_identity_in_state(
        "email",
        "me@primary.test",
        oneiron::channel_identity::SelfHeldShape::DedicatedAddress,
        oneiron::channel_identity::ChannelIdentityBinding::agent(actor),
        oneiron::channel_identity::ChannelIdentityState::Active,
        100,
    );
    vault
        .create_channel_identity(&test_id(IDENTITY_SEED), &identity)
        .expect("create sending identity");
}

/// Renders and stores the invitation the frozen payload references.
fn store_invite_blob(vault: &Vault, actor: EntityId) -> String {
    let ics = oneiron::emit_imip_ics(&oneiron::ImipEmitRequest {
        method: CalendarInviteMethod::Request,
        uid: INVITE_UID.to_owned(),
        sequence: 0,
        organizer: "me@primary.test".to_owned(),
        attendees: vec![INVITE_RECIPIENT.to_owned()],
        summary: "Confirmed booking".to_owned(),
        starts_at_utc: 1_800_003_600,
        ends_at_utc: 1_800_007_200,
        tz_label: "Europe/Warsaw".to_owned(),
        dtstamp_utc: 1_800_000_000,
    })
    .expect("emit invitation");
    oneiron::persist_imip_blob(
        vault,
        &test_id(INVITE_ARTIFACT_SEED),
        "calendar refusal code invitation",
        &ics,
        &oneiron::blob_artifact::BlobVersionProvenance::AgentRun {
            run_ref: "calendar-refusal-code".to_owned(),
        },
        WriteActor::new(actor, EdgeActorClass::Human),
        100,
    )
    .expect("persist invitation blob")
}

/// The actor's REQUEST invite of the stored invitation to the guest.
fn send_invite(facade: &Memory<'_>, blob_ref: String) -> MemoryError {
    facade
        .calendar_invite(&CalendarInviteSurfaceInput {
            method: CalendarInviteSurfaceMethod::Request,
            uid: INVITE_UID.to_owned(),
            sequence: 0,
            ics_blob_ref: blob_ref,
            recipient: INVITE_RECIPIENT.to_owned(),
            mention: None,
        })
        .expect_err("the hygiene wall refuses this invite")
}

/// Checks a refusal: `BAD_REQUEST`, naming `law`, and no send scheduled.
fn assert_names_the_law(vault: &Vault, error: &MemoryError, law: &str) {
    assert_eq!(
        error.code, MEMORY_CODE_BAD_REQUEST,
        "a refused invite is a bad request, not a stale state; got {error}"
    );
    assert!(
        error.message.contains("calendar invite refused") && error.message.contains(law),
        "the refusal names the law ({law}); got {error}"
    );
    assert!(
        vault.connector_send_tasks().expect("tasks").is_empty(),
        "a refused invite schedules nothing"
    );
}

/// Cold outreach never attaches an .ics (ARCH-0060 #invites): with no prior
/// thread and no booking grant the invite is refused, and the answer says so.
#[test]
fn a_cold_invite_names_the_consent_law() {
    let (_dir, vault) = temp_vault();
    let (actor, facade) = actor_facade(&vault);
    store_booked_event(&vault, actor);
    store_sending_identity(&vault, actor);
    let blob_ref = store_invite_blob(&vault, actor);

    let error = send_invite(&facade, blob_ref);

    assert_names_the_law(&vault, &error, "cold invite");
}

/// A real invite leaves only from the primary calendar domain, never from
/// sequencer-class infrastructure (ARCH-0060 #invites): with no active
/// dedicated sending identity the invite is refused, and the answer says so.
#[test]
fn an_invite_with_no_sending_identity_names_the_sender_law() {
    let (_dir, vault) = temp_vault();
    let (actor, facade) = actor_facade(&vault);
    store_booked_event(&vault, actor);
    let blob_ref = store_invite_blob(&vault, actor);

    let error = send_invite(&facade, blob_ref);

    assert_names_the_law(&vault, &error, "no active dedicated sending identity");
}
