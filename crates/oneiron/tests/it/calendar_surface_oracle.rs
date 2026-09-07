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
//!    connector only via `schedule_outbound`. CAL-04 (ONE-1786) registered the
//!    `calendar`/`calendar.invite` capability, so that route now completes:
//!    exactly one gate-decided connector-send TASK carrying CAL-04's frozen
//!    five-field body. The property this file pins did not change with that
//!    landing — the route did not become a side door, it just stopped ending in
//!    an unsupported-capability error — and the hygiene wall still refuses a
//!    cold invite at the same door.
//!
//! ## Normal criticality is not source permission
//!
//! `gate::default_policy_manifest()` gives `calendar.` normal criticality and
//! sensitivity. It does not grant Imported source trust. A Human actor's
//! Approved request still needs an explicit, actor-bound source permit.
//!
//! [`calendar_claims_resolve_normal_criticality_under_the_default_policy_manifest`]
//! pins the distinction on an unchanged default vault: Imported + Approved
//! pends only on source trust and writes no EVENT or claims. The tier-scoping
//! property — claims stored as Proposed stay invisible on every read verb —
//! remains pinned by [`calendar_surface_scopes_read_search_and_freebusy`].

use crate::common::entity as test_id;
use oneiron::registry::{ENTITY_TYPE_EVENT, ENTITY_TYPE_PERSON};
use oneiron::{
    CalendarInviteMethod, CalendarInviteSurfaceInput, CalendarInviteSurfaceMethod,
    CalendarRangeDto, CalendarReadRequest, CalendarSearchRequest, CalendarSel, ClaimApprovalStatus,
    ClaimCandidate, ClaimSource, ClaimSubject, EdgeActorClass, EntityId, MEMORY_CODE_BAD_REQUEST,
    Memory, TimeRange, Vault, VaultConfig, WriteActor, WriteEnvelope, WriteProvenance,
    calendar::BusyInterval, memory::CALENDAR_INVITE_OUTBOUND_CHANNEL,
    memory::CALENDAR_INVITE_OUTBOUND_VERB, memory::CalendarFreebusyIntervalDto,
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
/// candidate door at `approval`. Approved fixtures explicitly install their
/// actor's Imported source permit; Proposed claims keep their review status.
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
    let busy = test_id(BUSY_SEED);
    let envelope = envelope(actor, ClaimApprovalStatus::Approved);

    // Normal criticality clears only that axis. Neither Human nor Approved
    // supplies the missing Imported source permit. Exercise each family member
    // separately so an earlier rejection cannot hide a later predicate's gate.
    for (index, (predicate, value)) in calendar_family("busy").into_iter().enumerate() {
        let claim = claim_id(BUSY_SEED, u8::try_from(index).expect("family fits a byte"));
        let error = vault
            .batch()
            .put(
                &busy,
                ENTITY_TYPE_EVENT,
                TimeRange {
                    start: 1_000,
                    end: 1_099,
                },
                1,
                &event_body(SECRET_NAME, SECRET_DESCRIPTION),
            )
            .claim_candidate(
                &claim,
                ClaimCandidate::new(predicate, ClaimSubject::Entity(busy), value, 1.0),
                &envelope,
                at(1),
                1,
            )
            .commit()
            .expect_err("Imported + Approved needs source permission on a default vault");
        match error {
            oneiron::Error::GateWriteRejected {
                outcome,
                reason_codes,
            } => {
                assert_eq!(outcome, "pending", "{predicate}");
                assert_eq!(
                    reason_codes.as_slice(),
                    ["gate.pending.source_trust"],
                    "{predicate}: normal criticality is not a source permit"
                );
            }
            other => panic!("expected source-trust pending for {predicate}, got {other:?}"),
        }
        assert!(vault.get_claim(&claim).expect("claim row").is_none());
        assert!(
            vault.get_raw(&busy).expect("event row").is_none(),
            "source rejection rolls back the earlier EVENT put"
        );
        assert!(
            vault
                .claims_for_subject(&busy)
                .expect("claim index")
                .is_empty()
        );
    }

    // No read verb or outbound queue acquires data from a rejected write.
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
    assert!(
        facade
            .calendar_freebusy(&[], window())
            .expect("freebusy")
            .is_empty()
    );
    assert!(
        oneiron::calendar::freebusy(&vault, &[], window())
            .expect("internal freebusy")
            .is_empty()
    );
    assert!(vault.connector_send_tasks().expect("tasks").is_empty());
}

/// Missing and wrong-actor permits reject the same atomic batch that a
/// matching permit admits. No raw claim injection participates in this oracle.
#[test]
fn calendar_imported_source_permit_is_actor_bound() {
    for (label, permit_seed) in [
        ("missing permit", None),
        ("wrong actor permit", Some(0x84)),
        ("matching actor permit", Some(ACTOR_SEED)),
    ] {
        let (_dir, vault) = temp_vault();
        let (actor, facade) = actor_facade(&vault);
        if let Some(seed) = permit_seed {
            let permitted_actor = test_id(seed);
            if permitted_actor != actor {
                vault
                    .put_entity(
                        &permitted_actor,
                        ENTITY_TYPE_PERSON,
                        at(1),
                        1,
                        b"other actor",
                    )
                    .expect("put the other permit holder");
            }
            vault
                .install_imported_source_permit_for_test(permitted_actor)
                .expect("install the explicit actor-bound Imported permit");
        }
        let busy = test_id(BUSY_SEED);
        let claim = claim_id(BUSY_SEED, 1);
        let [_, (predicate, value), _, _] = calendar_family("busy");
        let result = vault
            .batch()
            .put(
                &busy,
                ENTITY_TYPE_EVENT,
                TimeRange {
                    start: 1_000,
                    end: 1_099,
                },
                1,
                &event_body(SECRET_NAME, SECRET_DESCRIPTION),
            )
            .claim_candidate(
                &claim,
                ClaimCandidate::new(predicate, ClaimSubject::Entity(busy), value, 1.0),
                &envelope(actor, ClaimApprovalStatus::Approved),
                at(1),
                1,
            )
            .commit();
        let allowed = permit_seed == Some(ACTOR_SEED);
        if allowed {
            result.expect("the matching actor permit admits Imported + Approved");
        } else {
            match result.expect_err(label) {
                oneiron::Error::GateWriteRejected {
                    outcome,
                    reason_codes,
                } => {
                    assert_eq!(outcome, "pending", "{label}");
                    assert_eq!(
                        reason_codes.as_slice(),
                        ["gate.pending.source_trust"],
                        "{label}"
                    );
                }
                other => panic!("expected source-trust pending for {label}, got {other:?}"),
            }
        }
        // Rejection rolls back the earlier EVENT and the claim/index write.
        let event = vault.get_raw(&busy).expect("event row");
        let body = vault.get_claim(&claim).expect("claim row");
        assert_eq!(event.is_some(), allowed, "{label}");
        assert_eq!(body.is_some(), allowed, "{label}");
        if let Some(body) = body {
            assert_eq!(body.source, Some(ClaimSource::Imported));
            assert_eq!(body.approval, ClaimApprovalStatus::Approved);
        }
        assert_eq!(
            vault.claims_for_subject(&busy).expect("claim index").len(),
            usize::from(allowed),
            "{label}"
        );
        let read = facade
            .calendar_read(&CalendarReadRequest {
                event_ref: busy.to_hex(),
            })
            .expect("read");
        assert_eq!(read.is_some(), allowed, "{label}");
        let external = facade.calendar_freebusy(&[], window()).expect("freebusy");
        let internal =
            oneiron::calendar::freebusy(&vault, &[], window()).expect("internal freebusy");
        assert_eq!(external.len(), usize::from(allowed), "{label}");
        assert_eq!(internal.len(), usize::from(allowed), "{label}");
        assert!(
            vault.connector_send_tasks().expect("tasks").is_empty(),
            "{label}"
        );
    }
}

#[test]
fn calendar_surface_scopes_read_search_and_freebusy() {
    let (_dir, vault) = temp_vault();
    let (actor, facade) = actor_facade(&vault);
    vault
        .install_imported_source_permit_for_test(actor)
        .expect("source permission must not promote Proposed claims");

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
        oneiron::calendar::freebusy(&vault, &[], window())
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

/// CAL-04's arrival contract, as this file promised it.
///
/// Before ONE-1786 this test pinned the UNREGISTERED failure: the invite
/// reached `schedule_outbound`'s capability preflight and stopped there. CAL-04
/// registered `calendar.invite` and the `calendar` connector manifest, so the
/// same call now travels the whole ordinary rail. What is pinned here is that
/// it is still the ORDINARY rail — one connector-send TASK, gate-decided,
/// carrying CAL-04's frozen five-field body — and never a direct connector
/// call. The `schedule_outbound` route is unchanged; only the door at the end
/// of it opened.
#[test]
fn oneiron_calendar_invite_routes_only_through_schedule_outbound() {
    let (_dir, vault) = temp_vault();
    let (actor, facade) = actor_facade(&vault);
    vault
        .install_imported_source_permit_for_test(actor)
        .expect("permit this fixture actor's Imported calendar claims");

    // The pair the preflight used to refuse now resolves in the manifest, and
    // the verb is in the common vocabulary exactly once. Spelled literally on
    // purpose: asserting against the constant alone would pass for whatever the
    // constant happens to say.
    let contract = oneiron::outbound_verb_contract("calendar", "calendar.invite")
        .expect("CAL-04 registers the calendar/calendar.invite pair");
    assert_eq!(contract.kind, "calendar.invite");
    assert_eq!(
        oneiron::COMMON_OUTBOUND_VERB_KINDS
            .iter()
            .filter(|verb| **verb == "calendar.invite")
            .count(),
        1,
        "calendar.invite is registered exactly once, by CAL-04"
    );

    seed_invite_preconditions(&vault, actor);
    let blob_ref = store_invite_blob(&vault, actor);

    let receipt = facade
        .calendar_invite(&CalendarInviteSurfaceInput {
            method: CalendarInviteSurfaceMethod::Request,
            uid: INVITE_UID.to_owned(),
            sequence: 0,
            ics_blob_ref: blob_ref.clone(),
            recipient: INVITE_RECIPIENT.to_owned(),
        })
        .expect("a registered invite schedules through the ordinary gate");

    // The schedule-only Hold window is what admits the durable TASK, exactly as
    // it does for every other verb: the bridge never delivers.
    assert_eq!(receipt.outcome, "held");
    assert_eq!(receipt.gate_outcome.as_deref(), Some("allow"));
    assert!(receipt.gate_decision_ref.is_some(), "the gate ruled on it");
    assert!(!receipt.deduped);

    // ONE connector-send TASK, on the calendar connector, carrying the frozen
    // five-field body — not a second queue and not a bespoke payload.
    let tasks = vault.connector_send_tasks().expect("connector tasks");
    assert_eq!(tasks.len(), 1);
    let task = &tasks[0];
    assert_eq!(task.intent.verb, CALENDAR_INVITE_OUTBOUND_VERB);
    assert_eq!(task.intent.channel, CALENDAR_INVITE_OUTBOUND_CHANNEL);
    assert_eq!(task.intent.target, INVITE_RECIPIENT);
    let payload = task
        .calendar_invite
        .as_ref()
        .expect("CAL-04's typed payload rides the TASK");
    assert_eq!(payload.method, CalendarInviteMethod::Request);
    assert_eq!(payload.uid, INVITE_UID);
    assert_eq!(payload.sequence, 0);
    assert_eq!(payload.ics_blob_ref, blob_ref);
    assert_eq!(payload.recipient, INVITE_RECIPIENT);

    // Scheduling the same revision again coalesces on the idempotency key
    // rather than minting a second invite or bumping a sequence.
    let again = facade
        .calendar_invite(&CalendarInviteSurfaceInput {
            method: CalendarInviteSurfaceMethod::Request,
            uid: INVITE_UID.to_owned(),
            sequence: 0,
            ics_blob_ref: blob_ref.clone(),
            recipient: INVITE_RECIPIENT.to_owned(),
        })
        .expect("a re-schedule of the same revision coalesces");
    assert!(again.deduped);
    assert_eq!(again.outcome, "already_scheduled");
    assert_eq!(
        vault.connector_send_tasks().expect("tasks").len(),
        1,
        "a coalesced re-schedule mints no second TASK"
    );

    // Blank required fields still fail before any scheduling work.
    let blank = facade
        .calendar_invite(&CalendarInviteSurfaceInput {
            method: CalendarInviteSurfaceMethod::Cancel,
            uid: String::new(),
            sequence: 1,
            ics_blob_ref: blob_ref,
            recipient: INVITE_RECIPIENT.to_owned(),
        })
        .expect_err("a blank uid is a typed rejection");
    assert_eq!(blank.code, MEMORY_CODE_BAD_REQUEST);
    assert!(blank.message.contains("uid"));
}

/// A cold invite is still refused at the same door, with a typed error — the
/// registration opened the capability, not the hygiene wall.
#[test]
fn oneiron_calendar_invite_still_refuses_a_cold_invite() {
    let (_dir, vault) = temp_vault();
    let (actor, facade) = actor_facade(&vault);
    vault
        .install_imported_source_permit_for_test(actor)
        .expect("permit this fixture actor's Imported calendar claims");
    // Everything a lawful invite needs EXCEPT a consent basis.
    let event_ref = store_calendar_event(
        &vault,
        actor,
        BUSY_SEED,
        "Confirmed booking",
        TimeRange {
            start: 100,
            end: 200,
        },
        "busy",
        ClaimApprovalStatus::Approved,
    );
    oneiron::calendar::index_passport_uid(&vault, INVITE_UID, &event_ref)
        .expect("index invite uid");
    store_sending_identity(&vault, actor);
    let blob_ref = store_invite_blob(&vault, actor);

    let error = facade
        .calendar_invite(&CalendarInviteSurfaceInput {
            method: CalendarInviteSurfaceMethod::Request,
            uid: INVITE_UID.to_owned(),
            sequence: 0,
            ics_blob_ref: blob_ref,
            recipient: INVITE_RECIPIENT.to_owned(),
        })
        .expect_err("cold outreach never attaches an .ics");
    assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST);
    assert!(
        error.message.contains("cold invite"),
        "the refusal must name the hygiene row; got {error}"
    );
    assert!(
        vault.connector_send_tasks().expect("tasks").is_empty(),
        "a refused invite schedules nothing"
    );
}

const INVITE_UID: &str = "one-1786@oneiron.test";
const INVITE_RECIPIENT: &str = "guest@example.test";
const INVITE_ARTIFACT_SEED: u8 = 0x8A;
const IDENTITY_SEED: u8 = 0x8B;
const GRANT_SEED: u8 = 0x8C;

/// The vault evidence a lawful REQUEST stands on: an EVENT whose UID is
/// indexed, an active dedicated sending identity, and a prior thread.
fn seed_invite_preconditions(vault: &Vault, actor: EntityId) {
    let event_ref = store_calendar_event(
        vault,
        actor,
        BUSY_SEED,
        "Confirmed booking",
        TimeRange {
            start: 100,
            end: 200,
        },
        "busy",
        ClaimApprovalStatus::Approved,
    );
    oneiron::calendar::index_passport_uid(vault, INVITE_UID, &event_ref).expect("index invite uid");
    store_sending_identity(vault, actor);

    // R7: publishing the booking page IS the consent. BK-03 (ONE-1814) owns
    // minting this grant; CAL-04 only ever verifies it, so the oracle drives
    // the existing mint door here to prove the verification leg works.
    vault
        .mint_standing_outbound_grant(
            &test_id(GRANT_SEED),
            &oneiron::genui::GrantMintIntent {
                principal_ref: actor.to_hex(),
                origin_component_id: "one_1786_oracle".to_owned(),
                origin_action_id: "confirm_booking".to_owned(),
                origin_receipt_ref: None,
                scope: oneiron::genui::GrantMintIntentScope::Contact {
                    contact_ref: INVITE_RECIPIENT.to_owned(),
                },
            },
            100,
        )
        .expect("mint the booking-page standing grant");
}

fn store_sending_identity(vault: &Vault, actor: EntityId) {
    let mut identity = oneiron::channel_identity::ChannelIdentity::requested(
        "email",
        "me@primary.test",
        oneiron::channel_identity::SelfHeldShape::DedicatedAddress,
        oneiron::channel_identity::ChannelIdentityBinding::agent(actor),
        100,
    );
    identity.state = oneiron::channel_identity::ChannelIdentityState::Active;
    vault
        .create_channel_identity(&test_id(IDENTITY_SEED), &identity)
        .expect("create sending identity");
}

/// Renders and stores the invitation the frozen payload will reference. The
/// bytes live in the blob store; only the ref ever travels.
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
        "one-1786 invitation",
        &ics,
        &oneiron::blob_artifact::BlobVersionProvenance::AgentRun {
            run_ref: "one-1786-oracle".to_owned(),
        },
        oneiron::WriteActor::new(actor, EdgeActorClass::Human),
        100,
    )
    .expect("persist invitation blob")
}
