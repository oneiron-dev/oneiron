//! CAL-09 surface oracle (ONE-1791).
//!
//! Pins the properties the calendar surface exists to guarantee, at the public
//! boundary and against the REAL write gate rather than a gate-free fixture
//! vault:
//!
//! 1. **One admission rule, three verbs.** `read`, `search`, and `freebusy` all
//!    project from the same admitted claims, so a claim that did not clear
//!    write admission is invisible on every verb — no verb is a side door, and
//!    the actor lane is always a subset of the internal one.
//! 2. **Freebusy is occupancy and nothing else.** The external DTO carries two
//!    integers; names, descriptions, attendees, meeting links, and the internal
//!    representative `source` ref cannot cross it, while the internal
//!    `BusyInterval` keeps `source` for engine consumers like BK-00.
//! 3. **Invites route through the gate.** The typed invite surface reaches a
//!    connector only via `schedule_outbound`, so before CAL-04 registers the
//!    capability it returns the ordinary unsupported-capability error and
//!    schedules nothing.
//!
//! ## The surface is live on a default vault
//!
//! `gate::default_policy_manifest()` resolves criticality from an allow-list of
//! predicate prefixes and defaults everything else to `critical`. `calendar.`
//! carries its own prefix rule (`criticality: normal`, `sensitivity: normal`),
//! so an approved calendar write clears the criticality floor and the read
//! surface projects it on a stock vault — no manifest edit required.
//!
//! [`calendar_claims_resolve_normal_criticality_under_the_default_policy_manifest`]
//! pins that: it drives an approved `calendar.*` write through the real gate and
//! then reads it back through the public surface. The tier-scoping property —
//! that a claim which did NOT clear admission stays invisible on every verb —
//! is what [`calendar_surface_scopes_read_search_and_freebusy`] pins, using a
//! deliberately `proposed` fixture rather than a manifest hole.

use crate::common::entity as test_id;
use oneiron::registry::{ENTITY_TYPE_EVENT, ENTITY_TYPE_PERSON};
use oneiron::{
    BusyInterval, CALENDAR_INVITE_OUTBOUND_CHANNEL, CALENDAR_INVITE_OUTBOUND_VERB,
    CalendarFreebusyIntervalDto, CalendarInviteSurfaceInput, CalendarInviteSurfaceMethod,
    CalendarRangeDto, CalendarReadRequest, CalendarSearchRequest, CalendarSel, ClaimApprovalStatus,
    ClaimCandidate, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EdgeActorClass, EntityId,
    MEMORY_CODE_BAD_REQUEST, Memory, TimeRange, Vault, VaultConfig, WriteActor, WriteEnvelope,
    WriteProvenance,
};
use rmpv::Value;

const ACTOR_SEED: u8 = 0x81;
const BUSY_SEED: u8 = 0x82;
const FREE_SEED: u8 = 0x83;

const SECRET_NAME: &str = "Board offsite with Acme";
const SECRET_DESCRIPTION: &str = "Term sheet walkthrough, do not forward";
const SECRET_ATTENDEE: &str = "cfo@acme.example";
const SECRET_MEETING_LINK: &str = "https://meet.example/one-1791-board";

fn temp_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    (dir, vault)
}

fn at(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

fn event_body(name: &str, description: &str) -> Vec<u8> {
    let mut out = Vec::new();
    rmpv::encode::write_value(
        &mut out,
        &Value::Map(vec![
            (Value::from("name"), Value::from(name)),
            (Value::from("desc"), Value::from(description)),
        ]),
    )
    .expect("encode event body");
    out
}

/// Claim ids are keyed `(0xB0, event seed, claim index)` so no fixture claim
/// can alias a generic `entity(seed)` id.
fn claim_id(event_seed: u8, index: u8) -> EntityId {
    let mut bytes = [0xB0_u8; 16];
    bytes[1] = event_seed;
    bytes[2] = index;
    EntityId::from_bytes(bytes).expect("fixture claim id")
}

/// The `calendar.*` family one imported EVENT carries, as the ingest path
/// would write it.
fn calendar_family(transparency: &str) -> [(&'static str, Value); 4] {
    [
        ("calendar.origin", Value::from("imported")),
        (
            "calendar.time_kind",
            Value::Map(vec![
                (Value::from("kind"), Value::from("absolute")),
                (Value::from("busy_transparency"), Value::from(transparency)),
            ]),
        ),
        (
            "calendar.attendee",
            Value::Map(vec![
                (Value::from("who"), Value::from(SECRET_ATTENDEE)),
                (Value::from("role"), Value::from("REQ-PARTICIPANT")),
                (Value::from("partstat"), Value::from("ACCEPTED")),
            ]),
        ),
        ("calendar.meeting_link", Value::from(SECRET_MEETING_LINK)),
    ]
}

fn envelope(actor: EntityId, approval: ClaimApprovalStatus) -> WriteEnvelope {
    WriteEnvelope::new(
        WriteActor::new(actor, EdgeActorClass::Human),
        ClaimSource::Imported,
        WriteProvenance::new(Value::from("one-1791-oracle")).expect("provenance"),
        approval,
    )
}

/// Stores one calendar EVENT and its family through the ordinary claim
/// candidate door at `approval`, against the REAL default policy manifest.
fn store_calendar_event(
    vault: &Vault,
    actor: EntityId,
    seed: u8,
    name: &str,
    occurred: TimeRange,
    transparency: &str,
    approval: ClaimApprovalStatus,
) -> EntityId {
    let id = test_id(seed);
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_EVENT,
            occurred,
            1,
            &event_body(name, SECRET_DESCRIPTION),
        )
        .expect("put event");

    let envelope = envelope(actor, approval);
    for (index, (predicate, value)) in calendar_family(transparency).into_iter().enumerate() {
        vault
            .batch()
            .claim_candidate(
                &claim_id(seed, u8::try_from(index).expect("family fits a byte")),
                ClaimCandidate::new(predicate, ClaimSubject::Entity(id), value, 1.0),
                &envelope,
                at(1),
                1,
            )
            .commit()
            .expect("claim candidate commits");
    }
    id
}

fn actor_facade(vault: &Vault) -> (EntityId, Memory<'_>) {
    let actor = test_id(ACTOR_SEED);
    vault
        .put_entity(&actor, ENTITY_TYPE_PERSON, at(1), 1, b"calendar actor")
        .expect("put actor");
    (actor, vault.memory(actor, EdgeActorClass::Human))
}

fn window() -> TimeRange {
    TimeRange {
        start: 0,
        end: 10_000,
    }
}

#[test]
fn calendar_claims_resolve_normal_criticality_under_the_default_policy_manifest() {
    let (_dir, vault) = temp_vault();
    let (actor, facade) = actor_facade(&vault);

    // The `calendar.` prefix rule resolves criticality `normal`, so the
    // criticality floor does not pend an approved calendar write: the claim is
    // admitted at the tier the writer asked for, on a stock vault with no
    // manifest edit.
    let busy = store_calendar_event(
        &vault,
        actor,
        BUSY_SEED,
        SECRET_NAME,
        TimeRange {
            start: 1_000,
            end: 1_099,
        },
        "busy",
        ClaimApprovalStatus::Approved,
    );
    let stored = vault
        .get_claim(&claim_id(BUSY_SEED, 1))
        .expect("claim row")
        .expect("the claim-candidate door stored a row");
    assert_eq!(stored.predicate, "calendar.time_kind");
    assert_eq!(stored.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(stored.approval, ClaimApprovalStatus::Approved);

    // …and admitted claims project: the read surface is live on a default
    // vault, not inert. `blocks_time` comes from the admitted
    // `calendar.time_kind` claim rather than the EVENT header, so a true here
    // proves the gate let the claim through to the projector.
    let view = facade
        .calendar_read(&CalendarReadRequest {
            event_ref: busy.to_hex(),
        })
        .expect("read")
        .expect("an admitted calendar claim projects on a default vault");
    assert_eq!(view.event_ref, busy.to_hex());
    assert!(view.blocks_time);
    assert_eq!(view.start_utc, Some(1_000));
    assert_eq!(view.end_utc, Some(1_099));
}

#[test]
fn calendar_surface_scopes_read_search_and_freebusy() {
    let (_dir, vault) = temp_vault();
    let (actor, facade) = actor_facade(&vault);

    // Written `proposed` on purpose: this oracle scopes the verbs against a
    // claim that did not clear admission, and `proposed` is the tier that says
    // so at the door itself rather than through a manifest gap.
    let busy = store_calendar_event(
        &vault,
        actor,
        BUSY_SEED,
        SECRET_NAME,
        TimeRange {
            start: 1_000,
            end: 1_099,
        },
        "busy",
        ClaimApprovalStatus::Proposed,
    );
    store_calendar_event(
        &vault,
        actor,
        FREE_SEED,
        "Travel buffer",
        TimeRange {
            start: 2_000,
            end: 2_099,
        },
        "free",
        ClaimApprovalStatus::Proposed,
    );

    // One admission rule, three verbs: the claims exist but did not clear write
    // admission, so no verb surfaces them — not the cheapest one either.
    assert!(
        vault
            .get_claim(&claim_id(BUSY_SEED, 1))
            .expect("claim row")
            .is_some(),
        "this oracle observes admission, not deletion"
    );
    assert!(
        facade
            .calendar_read(&CalendarReadRequest {
                event_ref: busy.to_hex(),
            })
            .expect("read")
            .is_none()
    );
    assert!(
        facade
            .calendar_search(&CalendarSearchRequest {
                calendars: Vec::new(),
                range: Some(CalendarRangeDto {
                    start: window().start,
                    end: window().end,
                }),
                text: None,
                limit: 50,
            })
            .expect("search")
            .is_empty()
    );
    let external = facade
        .calendar_freebusy(&[], window())
        .expect("freebusy projects");
    assert!(external.is_empty());

    // The internal lane BK-00 consumes agrees, so the actor lane can only ever
    // be a subset of it — never a wider view reached through a different door.
    assert!(
        oneiron::freebusy(&vault, &[], window())
            .expect("internal freebusy")
            .is_empty()
    );

    // Freebusy is occupancy and nothing else: the external interval type has
    // exactly two integer fields, so no calendar detail can ride it.
    let interval = CalendarFreebusyIntervalDto {
        start_utc: 1_000,
        end_utc: 1_100,
    };
    let wire = serde_json::to_value(vec![interval]).expect("freebusy DTO serializes");
    assert_eq!(
        wire[0]
            .as_object()
            .expect("interval object")
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec!["start_utc", "end_utc"]
    );
    let rendered = wire.to_string();
    for secret in [
        SECRET_NAME,
        SECRET_DESCRIPTION,
        SECRET_ATTENDEE,
        SECRET_MEETING_LINK,
        busy.to_hex().as_str(),
    ] {
        assert!(
            !rendered.contains(secret),
            "freebusy must not be able to carry {secret:?}; got {rendered}"
        );
    }

    // The internal projection is where provenance lives, and it is a distinct
    // type — the redaction is a boundary property, not a lossy conversion.
    let internal = BusyInterval {
        start_utc: 1_000,
        end_utc: 1_100,
        source: busy,
    };
    assert_eq!(internal.source, busy);
}

#[test]
fn calendar_surface_rejects_invalid_ranges_with_the_typed_facade_error() {
    let (_dir, vault) = temp_vault();
    let (_actor, facade) = actor_facade(&vault);

    let inverted = facade
        .calendar_search(&CalendarSearchRequest {
            calendars: Vec::new(),
            range: Some(CalendarRangeDto {
                start: 900,
                end: 100,
            }),
            text: None,
            limit: 10,
        })
        .expect_err("an inverted search window is a typed rejection");
    assert_eq!(inverted.code, MEMORY_CODE_BAD_REQUEST);

    let inverted = facade
        .calendar_freebusy(
            &[],
            TimeRange {
                start: 900,
                end: 100,
            },
        )
        .expect_err("an inverted freebusy window is a typed rejection");
    assert_eq!(inverted.code, MEMORY_CODE_BAD_REQUEST);

    let blank_selector = facade
        .calendar_freebusy(
            &[CalendarSel {
                system: Some("   ".to_owned()),
            }],
            TimeRange { start: 0, end: 100 },
        )
        .expect_err("a blank selector token is malformed input");
    assert_eq!(blank_selector.code, MEMORY_CODE_BAD_REQUEST);
}

#[test]
fn calendar_invite_draft_is_cal_04s_verb_and_typed_five_field_payload() {
    let input = CalendarInviteSurfaceInput {
        method: CalendarInviteSurfaceMethod::Request,
        uid: "uid-one-1791".to_owned(),
        sequence: 3,
        ics_blob_ref: "blob:one-1791".to_owned(),
        recipient: "guest@example.test".to_owned(),
    };

    // CAL-04 (ONE-1786) branches its dispatch chokepoint on
    // `draft.verb == CALENDAR_INVITE_VERB` ("calendar.invite") before it
    // exact-decodes the payload. A shorter local verb leaves that branch dead
    // on arrival: the invite would schedule as a generic draft and never reach
    // the iMIP codec.
    assert_eq!(CALENDAR_INVITE_OUTBOUND_VERB, "calendar.invite");

    let draft = input.outbound_draft();
    assert_eq!(draft.verb, CALENDAR_INVITE_OUTBOUND_VERB);
    assert_eq!(draft.channel, CALENDAR_INVITE_OUTBOUND_CHANNEL);
    assert_eq!(draft.target, input.recipient);
    assert_eq!(
        draft.content_ref.as_deref(),
        Some(input.ics_blob_ref.as_str())
    );

    // The other three fields stay typed on the payload CAL-04 decodes: exactly
    // C7's five keys, in order, with the uppercase iMIP method and a numeric
    // sequence — never re-parsed out of the derived idempotency/trigger keys.
    let wire = serde_json::to_value(&input).expect("invite payload serializes");
    let payload = wire.as_object().expect("invite payload object");
    assert_eq!(
        payload.keys().map(String::as_str).collect::<Vec<_>>(),
        vec!["method", "uid", "sequence", "ics_blob_ref", "recipient"]
    );
    assert_eq!(payload["method"], serde_json::json!("REQUEST"));
    assert_eq!(payload["uid"], serde_json::json!("uid-one-1791"));
    assert_eq!(payload["sequence"], serde_json::json!(3));
}

#[test]
fn oneiron_calendar_invite_routes_only_through_schedule_outbound() {
    let (_dir, vault) = temp_vault();
    let (_actor, facade) = actor_facade(&vault);

    let error = facade
        .calendar_invite(&CalendarInviteSurfaceInput {
            method: CalendarInviteSurfaceMethod::Request,
            uid: "uid-one-1791".to_owned(),
            sequence: 0,
            ics_blob_ref: "blob:one-1791".to_owned(),
            recipient: "guest@example.test".to_owned(),
        })
        .expect_err("calendar.invite is unregistered until CAL-04");

    // This message is produced only by `schedule_outbound`'s capability
    // preflight, so reaching it proves the invite took the ordinary outbound
    // path rather than a direct connector call.
    assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST);
    assert!(
        error.message.contains("unsupported outbound capability"),
        "invite must fail at the outbound capability preflight; got {error}"
    );
    // The preflight echoes the verb it could not resolve, so this also proves
    // CAL-04's pinned verb — not a local shorthand — is what reaches the door.
    // Spelled literally on purpose: asserting against the constant would pass
    // for whatever the constant happens to say.
    assert!(
        error.message.contains("\"calendar.invite\""),
        "the pinned calendar.invite verb must reach the outbound door; got {error}"
    );

    // Nothing was scheduled: no receipt exists for this actor.
    assert!(
        facade.receipts(32).expect("receipts").is_empty(),
        "an unregistered invite schedules nothing"
    );

    // Blank required fields fail before any scheduling work.
    let blank = facade
        .calendar_invite(&CalendarInviteSurfaceInput {
            method: CalendarInviteSurfaceMethod::Cancel,
            uid: String::new(),
            sequence: 1,
            ics_blob_ref: "blob:one-1791".to_owned(),
            recipient: "guest@example.test".to_owned(),
        })
        .expect_err("a blank uid is a typed rejection");
    assert_eq!(blank.code, MEMORY_CODE_BAD_REQUEST);
    assert!(blank.message.contains("uid"));
}
