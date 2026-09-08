//! Scoped-lane, search, and surfaceability suite.

use super::*;

use crate::calendar::claims::PREDICATE_CALENDAR_ORIGIN;

use crate::calendar::freebusy::{freebusy, freebusy_scoped};

use crate::calendar::test_support::{CalendarEventFixture, event_name_body, open_calendar_vault};

use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, ScopedReadActorKey,
};

use crate::test_util::{entity, put_policy_manifest_bytes};

/// Actor ref the scoped-read grant below is written for.
const SCOPED_READER: &str = "cal-09-scoped-reader";

fn at(start: u64, end: u64) -> TimeRange {
    TimeRange { start, end }
}

fn time_kind_value(transparency: &str) -> Value {
    Value::Map(vec![
        (Value::from("kind"), Value::from("absolute")),
        (Value::from("busy_transparency"), Value::from(transparency)),
    ])
}

fn cancelled_status_value() -> Value {
    Value::Map(vec![
        (Value::from("status"), Value::from("cancelled")),
        (Value::from("basis"), Value::from("imported_cancel")),
        (Value::from("recorded_at"), Value::from(1_754_400_000_u64)),
    ])
}

/// Writes one live, surfaceable `calendar.*` claim, optionally scoped to a
/// world. Claim ids are keyed `(0xD1, event seed, claim index)` so no
/// fixture claim can alias a generic `entity(seed)` id.
fn put_family_claim(
    vault: &Vault,
    seed: u8,
    index: u8,
    subject: EntityId,
    predicate: &str,
    value: Value,
    world: Option<EntityId>,
) {
    let mut bytes = [0xD1_u8; 16];
    bytes[1] = seed;
    bytes[2] = index;
    let claim_id = EntityId::from_bytes(bytes).expect("claim fixture id");
    let mut body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(subject),
        value,
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    body.world = world;
    vault
        .put_claim(&claim_id, &body, at(1, 1), 1)
        .expect("put calendar claim");
}

/// One calendar EVENT carrying a world-less family claim plus one decisive
/// single-cardinality claim. Placing the decisive claim in `decisive_world`
/// puts it OUTSIDE the scoped grant below while leaving it live and
/// surfaceable — so the two lanes legitimately see different facts about
/// the same EVENT.
fn store_split_grant_event(
    vault: &Vault,
    seed: u8,
    occurred: TimeRange,
    decisive: (&str, Value),
    decisive_world: Option<EntityId>,
) -> EntityId {
    let id = entity(seed);
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_EVENT,
            occurred,
            1,
            &event_name_body("Split grant"),
        )
        .expect("put calendar event");
    put_family_claim(
        vault,
        seed,
        0,
        id,
        PREDICATE_CALENDAR_ORIGIN,
        Value::from("imported"),
        None,
    );
    put_family_claim(vault, seed, 1, id, decisive.0, decisive.1, decisive_world);
    id
}

/// A policy manifest whose only scoped grant is `core:read` over `world`.
///
/// Under `gate::scoped_read_claim_allowed` a world grant also admits every
/// world-less claim, so this is the smallest manifest that splits one
/// EVENT's family across the grant boundary.
fn scoped_read_world_manifest(actor_ref: &str, world: EntityId) -> Vec<u8> {
    let grant = Value::Map(vec![
        (Value::from("actor_ref"), Value::from(actor_ref)),
        (Value::from("effector"), Value::from("core:read")),
        (
            Value::from("scope"),
            Value::Map(vec![(
                Value::from("world_ref"),
                Value::from(world.to_hex()),
            )]),
        ),
        (Value::from("receipt_required"), Value::Boolean(false)),
    ]);
    let manifest = Value::Map(vec![
        (Value::from("schema_version"), Value::from("1.1")),
        (Value::from("pack_id"), Value::from("cal-09-scoped-read")),
        (Value::from("pack_version"), Value::from("1")),
        (Value::from("min_engine_version"), Value::from("0.0.0")),
        (Value::from("defaults"), Value::Map(Vec::new())),
        (Value::from("rules"), Value::Array(Vec::new())),
        (Value::from("actor_ceilings"), Value::Array(Vec::new())),
        (Value::from("scoped_grants"), Value::Array(vec![grant])),
    ]);
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &manifest).expect("policy manifest encodes");
    data
}

#[test]
fn scoped_lane_fails_closed_on_a_decisive_claim_it_may_not_read() {
    let (_dir, vault) = open_calendar_vault();
    let granted_world = entity(0x91);
    let hidden_world = entity(0x92);

    // Free — but only the claim outside the grant says so.
    let free = store_split_grant_event(
        &vault,
        0x93,
        at(1_000, 1_099),
        (PREDICATE_CALENDAR_TIME_KIND, time_kind_value("free")),
        Some(hidden_world),
    );
    // Cancelled — but only the claim outside the grant says so.
    let cancelled = store_split_grant_event(
        &vault,
        0x94,
        at(2_000, 2_099),
        (PREDICATE_CALENDAR_STATUS, cancelled_status_value()),
        Some(hidden_world),
    );
    // Control: the whole family is inside the grant, and it really is busy.
    let busy = store_split_grant_event(
        &vault,
        0x96,
        at(3_000, 3_099),
        (PREDICATE_CALENDAR_TIME_KIND, time_kind_value("busy")),
        None,
    );

    // Written after the claims so the write door stays gate-free; only the
    // read lane is under test.
    put_policy_manifest_bytes(
        &vault,
        entity(0x95),
        &scoped_read_world_manifest(SCOPED_READER, granted_world),
    )
    .expect("policy manifest stores");

    let lane = vault.scoped_read(ScopedReadActorKey::new(SCOPED_READER).expect("actor key"));
    let window = at(0, 10_000);
    let internal = freebusy(&vault, &[], window).expect("internal freebusy");
    let scoped = freebusy_scoped(&lane, &[], window).expect("scoped freebusy");

    assert_eq!(
        internal.len(),
        1,
        "internally the free and cancelled EVENTs occupy nothing"
    );
    assert_eq!(internal[0].source, busy);
    assert_eq!(
        scoped, internal,
        "an actor's union is a subset of the internal one; a claim the \
             actor cannot read must never ADD an interval"
    );

    // The same rule at the projection: a decisive claim this lane cannot
    // read defaults toward non-busy, never toward the CAL-00 busy default.
    let scoped_free = read_event_scoped(
        &lane,
        &CalendarReadRequest {
            event_ref: free.to_hex(),
        },
    )
    .expect("scoped read")
    .expect("the readable family claim still projects the EVENT");
    assert!(
        !scoped_free.blocks_time,
        "a withheld calendar.time_kind cannot resolve to the busy default"
    );

    assert!(
        !freebusy_scoped(&lane, &[], at(2_000, 2_099))
            .expect("scoped freebusy")
            .iter()
            .any(|interval| interval.source == cancelled),
        "a withheld calendar.status cannot resolve to non-cancelled"
    );
}

#[test]
fn calendar_search_filters_calendar_range_and_text() {
    let (_dir, vault) = open_calendar_vault();
    CalendarEventFixture::new(0x21, "Design review", 1_000, 2_000).store(&vault);
    CalendarEventFixture::new(0x22, "Dentist", 10_000, 11_000).store(&vault);

    let all = search_events(
        &vault,
        &CalendarSearchRequest {
            calendars: Vec::new(),
            range: None,
            text: None,
            limit: 10,
        },
    )
    .expect("search");
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].name.as_deref(), Some("Design review"));

    let windowed = search_events(
        &vault,
        &CalendarSearchRequest {
            calendars: Vec::new(),
            range: Some(CalendarRangeDto {
                start: 9_000,
                end: 12_000,
            }),
            text: None,
            limit: 10,
        },
    )
    .expect("search");
    assert_eq!(windowed.len(), 1);
    assert_eq!(windowed[0].name.as_deref(), Some("Dentist"));

    let texted = search_events(
        &vault,
        &CalendarSearchRequest {
            calendars: Vec::new(),
            range: None,
            text: Some("DESIGN".to_owned()),
            limit: 10,
        },
    )
    .expect("search");
    assert_eq!(texted.len(), 1);
    assert_eq!(texted[0].name.as_deref(), Some("Design review"));
}

#[test]
fn calendar_search_bounds_limit() {
    let (_dir, vault) = open_calendar_vault();
    for (index, seed) in [0x31_u8, 0x32, 0x33, 0x34].into_iter().enumerate() {
        let start = 1_000 + index as u64 * 100;
        CalendarEventFixture::new(seed, "Standup", start, start + 10).store(&vault);
    }

    let request = |limit| CalendarSearchRequest {
        calendars: Vec::new(),
        range: None,
        text: None,
        limit,
    };
    assert_eq!(search_events(&vault, &request(2)).expect("search").len(), 2);
    assert_eq!(search_events(&vault, &request(0)).expect("search").len(), 0);
    assert_eq!(
        search_events(&vault, &request(u32::MAX))
            .expect("search")
            .len(),
        4
    );
}

#[test]
fn calendar_selector_is_ignored_until_passport_index_lands() {
    let (_dir, vault) = open_calendar_vault();
    CalendarEventFixture::new(0x41, "Offsite", 1_000, 2_000).store(&vault);

    // No passport index exists on the 1791 baseline, so a selector must not
    // empty the result set (CAL-02 / ONE-1784 activates real filtering).
    let selected = search_events(
        &vault,
        &CalendarSearchRequest {
            calendars: vec![CalendarSel {
                system: Some("google".to_owned()),
            }],
            range: None,
            text: None,
            limit: 10,
        },
    )
    .expect("search");
    assert_eq!(selected.len(), 1);

    assert!(
        validate_selectors(&[CalendarSel {
            system: Some("   ".to_owned()),
        }])
        .is_err(),
        "a blank selector token is malformed in every baseline"
    );
}

#[test]
fn calendar_read_projects_only_family_events() {
    let (_dir, vault) = open_calendar_vault();
    let calendar = CalendarEventFixture::new(0x51, "Sync", 1_000, 2_000).store(&vault);
    let plain = crate::test_util::entity(0x52);
    vault
        .put_entity(
            &plain,
            ENTITY_TYPE_EVENT,
            TimeRange {
                start: 1_000,
                end: 2_000,
            },
            1,
            &event_name_body("Not a calendar event"),
        )
        .expect("put plain event");

    let view = read_event(
        &vault,
        &CalendarReadRequest {
            event_ref: calendar.to_hex(),
        },
    )
    .expect("read")
    .expect("calendar event is projected");
    assert_eq!(view.name.as_deref(), Some("Sync"));
    assert_eq!(view.start_utc, Some(1_000));
    assert_eq!(view.end_utc, Some(2_000));
    assert!(view.blocks_time);

    assert!(
        read_event(
            &vault,
            &CalendarReadRequest {
                event_ref: plain.to_hex(),
            },
        )
        .expect("read")
        .is_none(),
        "family membership is CAL-00's exact table, never a bare EVENT"
    );
}

#[test]
fn calendar_search_never_anchors_an_undated_event_at_the_epoch() {
    let (_dir, vault) = open_calendar_vault();
    let undated = CalendarEventFixture::new(0x97, "Undated", 0, 0).store(&vault);

    let view = read_event(
        &vault,
        &CalendarReadRequest {
            event_ref: undated.to_hex(),
        },
    )
    .expect("read")
    .expect("an undated calendar EVENT still projects");
    assert_eq!(view.start_utc, None);
    assert_eq!(view.end_utc, None);

    let request = |range| CalendarSearchRequest {
        calendars: Vec::new(),
        range,
        text: None,
        limit: 10,
    };
    assert!(
        search_events(
            &vault,
            &request(Some(CalendarRangeDto { start: 0, end: 100 })),
        )
        .expect("search")
        .is_empty(),
        "an undated EVENT has no instant to compare, so no window selects it"
    );
    assert_eq!(
        search_events(&vault, &request(None)).expect("search").len(),
        1,
        "only temporal filtering excludes it; an unbounded search still lists it"
    );
}

#[test]
fn calendar_surface_admits_only_surfaceable_claims() {
    let (_dir, vault) = open_calendar_vault();
    let proposed = CalendarEventFixture::new(0x53, "Pending import", 1_000, 2_000)
        .proposed()
        .store(&vault);

    assert!(
        read_event(
            &vault,
            &CalendarReadRequest {
                event_ref: proposed.to_hex(),
            },
        )
        .expect("read")
        .is_none(),
        "an unapproved calendar claim is not calendar truth on any lane"
    );
}
