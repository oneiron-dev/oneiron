use super::*;
use crate::calendar::test_support::open_calendar_vault;

/// A one-body fetcher: every fetch returns a complete feed.
struct BodyFetcher {
    body: Vec<u8>,
}

impl IcsFeedFetcher for BodyFetcher {
    fn fetch(
        &self,
        _secret_ref: &str,
        _if_none_match: Option<&str>,
    ) -> Result<IcsFetchResponse, CalendarError> {
        Ok(IcsFetchResponse::Complete {
            etag: None,
            body: self.body.clone(),
        })
    }
}

fn one_event_feed(dtstart: &str, dtend: &str) -> Vec<u8> {
    format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//oneiron//test//EN\r\n\
         BEGIN:VEVENT\r\nUID:uid-oc@x\r\nDTSTAMP:20260805T100000Z\r\n\
         DTSTART:{dtstart}\r\nDTEND:{dtend}\r\nSEQUENCE:1\r\nSUMMARY:standup\r\n\
         END:VEVENT\r\nEND:VCALENDAR\r\n"
    )
    .into_bytes()
}

fn test_config() -> IcsFeedPollConfig {
    IcsFeedPollConfig {
        secret_ref: "ics-feed:work".to_owned(),
        system: "work".to_owned(),
        cadence_min_seconds: 300,
        cadence_max_seconds: 900,
    }
}

/// VERDICT-FIX (semantic-update-not-applied): a same-SEQUENCE content
/// drift moves the EVENT's stored occurrence, not just the passport head.
/// The header read is crate-internal, so this half of the oracle lives
/// here; the name/transparency half lives in the adapter oracle.
#[test]
fn update_existing_rewrites_the_event_occurrence() {
    let (_dir, vault) = open_calendar_vault();
    let config = test_config();
    let first = BodyFetcher {
        body: one_event_feed("20260806T140000Z", "20260806T150000Z"),
    };
    run_ics_feed_poll(&vault, &first, &config, 1_800_000_000, 7).expect("create poll");
    let event = crate::calendar::passport::resolve_event_by_uid(&vault, "uid-oc@x")
        .expect("resolve")
        .expect("event minted");
    let before = vault
        .read_entity_header(&event)
        .expect("header")
        .expect("event exists");
    assert_eq!(before.occurred_start, 1_786_024_800);
    assert_eq!(before.occurred_end, 1_786_028_400);

    let drifted = BodyFetcher {
        body: one_event_feed("20260807T090000Z", "20260807T093000Z"),
    };
    run_ics_feed_poll(&vault, &drifted, &config, 1_800_000_100, 7).expect("drift poll");
    let after = vault
        .read_entity_header(&event)
        .expect("header")
        .expect("event exists");
    assert_eq!(
        (after.occurred_start, after.occurred_end),
        (1_786_093_200, 1_786_095_000),
        "a drifted DTSTART/DTEND re-mints the EVENT occurrence"
    );
}
#[test]
fn poll_retains_calendar_properties_and_retracts_removed_fields() {
    use crate::calendar::claims::*;
    let (_dir, vault) = open_calendar_vault();
    let config = test_config();
    let feed=String::from_utf8(one_event_feed("20260806T140000Z","20260806T150000Z")).unwrap()
        .replace("SUMMARY:standup", "SUMMARY:standup\r\nRRULE:FREQ=DAILY;COUNT=2\r\nATTENDEE;ROLE=CHAIR;PARTSTAT=ACCEPTED:mailto:host@example.org\r\nURL:https://meet.example.org/room");
    let first = BodyFetcher {
        body: feed.into_bytes(),
    };
    run_ics_feed_poll(&vault, &first, &config, 1_800_000_000, 7).unwrap();
    let event = crate::calendar::passport::resolve_event_by_uid(&vault, "uid-oc@x")
        .unwrap()
        .unwrap();
    let live = || {
        vault
            .claims_for_subject(&event)
            .unwrap()
            .into_iter()
            .filter_map(|id| vault.get_claim(&id).unwrap())
            .filter(|claim| claim.lifecycle == ClaimLifecycleStatus::Active)
            .collect::<Vec<_>>()
    };
    let rows = live();
    assert!(
        rows.iter()
            .any(|claim| claim.predicate == PREDICATE_CALENDAR_SERIES_MASTER)
    );
    let attendee = rows
        .iter()
        .find(|claim| claim.predicate == PREDICATE_CALENDAR_ATTENDEE)
        .unwrap();
    assert_eq!(
        decode_attendee_value(&attendee.value).unwrap().who,
        "mailto:host@example.org"
    );
    assert!(
        rows.iter()
            .any(|claim| claim.predicate == PREDICATE_CALENDAR_MEETING_LINK
                && claim.value.as_str() == Some("https://meet.example.org/room"))
    );
    run_ics_feed_poll(&vault, &first, &config, 1_800_000_001, 7).unwrap();
    assert_eq!(live().len(), rows.len());
    let next = BodyFetcher {
        body: one_event_feed("20260806T140000Z", "20260806T150000Z"),
    };
    run_ics_feed_poll(&vault, &next, &config, 1_800_000_002, 7).unwrap();
    assert!(!live().iter().any(|claim| matches!(
        claim.predicate.as_str(),
        PREDICATE_CALENDAR_ATTENDEE
            | PREDICATE_CALENDAR_MEETING_LINK
            | PREDICATE_CALENDAR_SERIES_MASTER
            | PREDICATE_CALENDAR_RRULE
    )));
}

#[test]
fn floating_and_all_day_events_do_not_acquire_an_absolute_time_kind() {
    use crate::calendar::claims::*;
    for (start, end, kind) in [
        (
            "20260806T140000",
            "20260806T150000",
            CalendarTimeKind::Floating,
        ),
        ("20260806", "20260807", CalendarTimeKind::AllDay),
    ] {
        let (_dir, vault) = open_calendar_vault();
        let config = test_config();
        run_ics_feed_poll(
            &vault,
            &BodyFetcher {
                body: one_event_feed(start, end),
            },
            &config,
            1_800_000_000,
            7,
        )
        .unwrap();
        let event = crate::calendar::passport::resolve_event_by_uid(&vault, "uid-oc@x")
            .unwrap()
            .unwrap();
        let rows: Vec<_> = vault
            .claims_for_subject(&event)
            .unwrap()
            .into_iter()
            .filter_map(|id| vault.get_claim(&id).unwrap())
            .collect();
        let time = rows
            .iter()
            .find(|claim| claim.predicate == PREDICATE_CALENDAR_TIME_KIND)
            .unwrap();
        assert_eq!(decode_time_kind_value(&time.value).unwrap().kind, kind);
        assert!(
            rows.iter()
                .any(|claim| claim.predicate == PREDICATE_CALENDAR_WALL_TIME)
        );
        assert!(
            !rows
                .iter()
                .any(|claim| claim.predicate == PREDICATE_CALENDAR_TZ)
        );
    }
}

#[test]
fn detached_exception_preserves_uid_master_and_absence_restores_the_series_mask() {
    use crate::calendar::claims::{
        PREDICATE_CALENDAR_SERIES_EXCEPTION, decode_series_exception_value,
    };
    let (_dir, vault) = open_calendar_vault();
    let config = test_config();
    let master = String::from_utf8(one_event_feed("20260806T140000Z", "20260806T150000Z"))
        .unwrap()
        .replace(
            "SUMMARY:standup",
            "RRULE:FREQ=DAILY;COUNT=3\r\nSUMMARY:standup",
        );
    let exception = String::from_utf8(one_event_feed("20260806T160000Z", "20260806T170000Z"))
        .unwrap()
        .replace("SEQUENCE:1", "SEQUENCE:2\r\nRECURRENCE-ID:20260806T140000Z");
    let component = exception
        .split_once("BEGIN:VEVENT")
        .unwrap()
        .1
        .split_once("END:VEVENT")
        .unwrap()
        .0;
    let full = master.replace(
        "BEGIN:VEVENT",
        &format!("BEGIN:VEVENT{component}END:VEVENT\r\nBEGIN:VEVENT"),
    );
    run_ics_feed_poll(
        &vault,
        &BodyFetcher {
            body: full.clone().into_bytes(),
        },
        &config,
        1_800_000_000,
        7,
    )
    .unwrap();
    let master_ref = crate::calendar::passport::resolve_event_by_uid(&vault, "uid-oc@x")
        .unwrap()
        .unwrap();
    let events = vault.entities_by_type(ENTITY_TYPE_EVENT).unwrap();
    assert_eq!(events.len(), 2);
    let child = *events.iter().find(|id| **id != master_ref).unwrap();
    let masks = || {
        vault
            .claims_for_subject(&child)
            .unwrap()
            .into_iter()
            .filter_map(|id| vault.get_claim(&id).unwrap())
            .filter(|body| {
                body.predicate == PREDICATE_CALENDAR_SERIES_EXCEPTION
                    && body.lifecycle == ClaimLifecycleStatus::Active
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        decode_series_exception_value(&masks()[0].value)
            .unwrap()
            .master_ref,
        master_ref
    );
    assert_eq!(
        vault
            .read_entity_header(&master_ref)
            .unwrap()
            .unwrap()
            .occurred_start,
        1_786_024_800
    );
    // A stale node-local index must not let an exception steal its master's UID.
    index_passport_uid(&vault, "uid-oc@x", &child).unwrap();
    assert_eq!(
        crate::calendar::passport::resolve_event_by_uid(&vault, "uid-oc@x").unwrap(),
        Some(master_ref)
    );
    run_ics_feed_poll(
        &vault,
        &BodyFetcher {
            body: master.into_bytes(),
        },
        &config,
        1_800_000_010,
        7,
    )
    .unwrap();
    assert!(masks().is_empty());
    run_ics_feed_poll(
        &vault,
        &BodyFetcher {
            body: full.into_bytes(),
        },
        &config,
        1_800_000_020,
        7,
    )
    .unwrap();
    assert_eq!(masks().len(), 1);
}

#[test]
fn connector_resource_routes_exceptions_separately_and_scopes_absence() {
    use crate::calendar::claims::{CalendarPassportDirection, CalendarPassportPresence};
    use crate::calendar::ingest::{
        admit_connector_event, connector_event_ref, sweep_connector_resource,
    };
    let (_dir, vault) = open_calendar_vault();
    let master = String::from_utf8(one_event_feed("20260806T140000Z", "20260806T150000Z"))
        .unwrap()
        .replace(
            "SUMMARY:standup",
            "RRULE:FREQ=DAILY;COUNT=3\r\nSUMMARY:standup",
        );
    let exception = String::from_utf8(one_event_feed("20260806T160000Z", "20260806T170000Z"))
        .unwrap()
        .replace("SEQUENCE:1", "SEQUENCE:2\r\nRECURRENCE-ID:20260806T140000Z");
    let component = exception
        .split_once("BEGIN:VEVENT")
        .unwrap()
        .1
        .split_once("END:VEVENT")
        .unwrap()
        .0;
    let full = master.replace(
        "BEGIN:VEVENT",
        &format!("BEGIN:VEVENT{component}END:VEVENT\r\nBEGIN:VEVENT"),
    );
    let feed = crate::calendar::ics::parse_ics_feed(full.as_bytes()).unwrap();
    for event in &feed.events {
        admit_connector_event(&vault, "caldav", "fixture://resource", event, 1_800_000_000)
            .unwrap();
    }
    let master_id = connector_event_ref(&vault, &feed.events[0])
        .unwrap()
        .unwrap();
    let child = connector_event_ref(&vault, &feed.events[1])
        .unwrap()
        .unwrap();
    assert_ne!(master_id, child);
    let unrelated =
        crate::calendar::ics::parse_ics_feed(master.replace("uid-oc@x", "unrelated@x").as_bytes())
            .unwrap();
    admit_connector_event(
        &vault,
        "caldav",
        "fixture://other",
        &unrelated.events[0],
        1_800_000_000,
    )
    .unwrap();
    let other_id = connector_event_ref(&vault, &unrelated.events[0])
        .unwrap()
        .unwrap();
    let only_master = crate::calendar::ics::parse_ics_feed(master.as_bytes()).unwrap();
    sweep_connector_resource(
        &vault,
        "caldav",
        "fixture://resource",
        &only_master,
        "uid-oc@x",
        1_800_000_001,
    )
    .unwrap();
    let passport = |id| {
        crate::calendar::passport::live_passport_for(
            &vault,
            &id,
            "caldav",
            if id == other_id {
                "unrelated@x"
            } else {
                "uid-oc@x"
            },
        )
        .unwrap()
        .unwrap()
        .1
    };
    assert_eq!(passport(child).presence, CalendarPassportPresence::Absent);
    assert_eq!(passport(other_id).presence, CalendarPassportPresence::Live);
    assert_eq!(
        passport(master_id).direction,
        CalendarPassportDirection::Inbound
    );
}

#[test]
fn impossible_utc_civil_date_refuses_before_calendar_admission() {
    let (_dir, vault) = open_calendar_vault();
    let error = run_ics_feed_poll(
        &vault,
        &BodyFetcher {
            body: one_event_feed("20260230T140000Z", "20260230T150000Z"),
        },
        &test_config(),
        1_800_000_000,
        7,
    )
    .unwrap_err();
    assert!(matches!(error, CalendarError::IcsParse { .. }));
    assert!(
        vault
            .entities_by_type(ENTITY_TYPE_EVENT)
            .unwrap()
            .is_empty()
    );
}
