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
//! ## Known hole pinned here (NOT owned by CAL-09)
//!
//! `gate::default_policy_manifest()` resolves criticality from an allow-list of
//! predicate prefixes (`profile.`, `affect.vad`, `skill.*`, …) and defaults
//! everything else to `critical`. `calendar.*` is absent, so under the shipped
//! default policy every calendar claim is gate-pending and lands `proposed` —
//! which means the read surface is correctly, but completely, empty on a
//! default vault. CAL-09 cannot fix that: `crates/oneiron/src/gate.rs` is a
//! lane-wide CAL non-claim. The fix is one `calendar.` rule
//! (`criticality: normal`, `sensitivity: normal`) in the default manifest,
//! owned by the GATE lane or by CAL-02 (ONE-1784) when it wires ICS ingest.
//!
//! [`calendar_claims_are_gate_pending_under_the_default_policy_manifest`] pins
//! that state deliberately: when the rule lands, this oracle fails loudly and
//! its positive-projection arm can be enabled. The projection itself is covered
//! by the `calendar::query` / `calendar::freebusy` unit tests, which run on a
//! manifest-cleared vault.

mod common;

use common::entity as test_id;
use oneiron::registry::{ENTITY_TYPE_EVENT, ENTITY_TYPE_PERSON};
use oneiron::{
    BusyInterval, CALENDAR_INVITE_OUTBOUND_CHANNEL, CALENDAR_INVITE_OUTBOUND_VERB,
    CalendarFreebusyIntervalDto, CalendarInviteSurfaceInput, CalendarInviteSurfaceMethod,
    CalendarRangeDto, CalendarReadRequest, CalendarSearchRequest, CalendarSel, ClaimApprovalStatus,
    ClaimCandidate, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EdgeActorClass, EntityId,
    FACADE_CODE_BAD_REQUEST, MemoryFacade, TimeRange, Vault, VaultConfig, WriteActor,
    WriteEnvelope, WriteProvenance,
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
/// candidate door at the admission tier the default policy manifest actually
/// permits (`proposed`).
fn store_calendar_event(
    vault: &Vault,
    actor: EntityId,
    seed: u8,
    name: &str,
    occurred: TimeRange,
    transparency: &str,
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

    let envelope = envelope(actor, ClaimApprovalStatus::Proposed);
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

fn actor_facade(vault: &Vault) -> (EntityId, MemoryFacade<'_>) {
    let actor = test_id(ACTOR_SEED);
    vault
        .put_entity(&actor, ENTITY_TYPE_PERSON, at(1), 1, b"calendar actor")
        .expect("put actor");
    (actor, vault.memory_facade(actor, EdgeActorClass::Human))
}

fn window() -> TimeRange {
    TimeRange {
        start: 0,
        end: 10_000,
    }
}

#[test]
fn calendar_claims_are_gate_pending_under_the_default_policy_manifest() {
    let (_dir, vault) = temp_vault();
    let (actor, _facade) = actor_facade(&vault);
    let id = test_id(BUSY_SEED);
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_EVENT,
            TimeRange {
                start: 1_000,
                end: 1_099,
            },
            1,
            &event_body(SECRET_NAME, SECRET_DESCRIPTION),
        )
        .expect("put event");

    let (predicate, value) = calendar_family("busy")
        .into_iter()
        .nth(1)
        .expect("time kind");
    let rejected = vault
        .batch()
        .claim_candidate(
            &claim_id(BUSY_SEED, 1),
            ClaimCandidate::new(predicate, ClaimSubject::Entity(id), value, 1.0),
            &envelope(actor, ClaimApprovalStatus::Approved),
            at(1),
            1,
        )
        .commit()
        .expect_err("no `calendar.` rule exists in the default policy manifest");

    // The default manifest resolves criticality from a prefix allow-list and
    // defaults the rest to `critical`; `calendar.*` is absent, so an approved
    // calendar write cannot clear the floor and the read surface is correctly
    // — but completely — empty on a default vault. gate.rs is a lane-wide CAL
    // non-claim, so the fix (one `calendar.` rule, criticality/sensitivity
    // `normal`) belongs to the GATE lane or CAL-02 (ONE-1784). When it lands,
    // this assertion fails loudly and the positive projection arm can be
    // enabled here.
    match rejected {
        oneiron::Error::GateWriteRejected {
            outcome,
            reason_codes,
        } => {
            assert_eq!(outcome, "pending");
            assert_eq!(reason_codes.as_slice(), &["gate.pending.criticality_floor"]);
        }
        other => panic!("expected a gate criticality-floor pending, got {other:?}"),
    }

    // The tier the door does admit is `proposed`, which is not surfaceable.
    store_calendar_event(
        &vault,
        actor,
        FREE_SEED,
        "Travel buffer",
        TimeRange {
            start: 2_000,
            end: 2_099,
        },
        "busy",
    );
    let stored = vault
        .get_claim(&claim_id(FREE_SEED, 1))
        .expect("claim row")
        .expect("the claim-candidate door stored a row");
    assert_eq!(stored.predicate, "calendar.time_kind");
    assert_eq!(stored.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(stored.approval, ClaimApprovalStatus::Proposed);
}

#[test]
fn calendar_surface_scopes_read_search_and_freebusy() {
    let (_dir, vault) = temp_vault();
    let (actor, facade) = actor_facade(&vault);

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
    assert_eq!(inverted.code, FACADE_CODE_BAD_REQUEST);

    let inverted = facade
        .calendar_freebusy(
            &[],
            TimeRange {
                start: 900,
                end: 100,
            },
        )
        .expect_err("an inverted freebusy window is a typed rejection");
    assert_eq!(inverted.code, FACADE_CODE_BAD_REQUEST);

    let blank_selector = facade
        .calendar_freebusy(
            &[CalendarSel {
                system: Some("   ".to_owned()),
            }],
            TimeRange { start: 0, end: 100 },
        )
        .expect_err("a blank selector token is malformed input");
    assert_eq!(blank_selector.code, FACADE_CODE_BAD_REQUEST);
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
    assert_eq!(error.code, FACADE_CODE_BAD_REQUEST);
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
    assert_eq!(blank.code, FACADE_CODE_BAD_REQUEST);
    assert!(blank.message.contains("uid"));
}
