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

#[test]
fn calendar_property_replacement_preserves_other_sources() {
    use crate::calendar::claims::*;
    let (_dir, vault) = open_calendar_vault();
    let a = test_config();
    let mut b = test_config();
    b.system = "personal".into();
    b.secret_ref = "ics-feed:personal".into();
    let base = String::from_utf8(one_event_feed("20260806T140000Z", "20260806T150000Z")).unwrap();
    let feed = |who: &str| {
        BodyFetcher { body: base.replace("SUMMARY:standup", &format!(
        "SUMMARY:standup\r\nATTENDEE:mailto:{who}@example.org\r\nURL:https://meet.example.org/shared"
    )).into_bytes() }
    };
    run_ics_feed_poll(&vault, &feed("work"), &a, 1_800_000_000, 7).unwrap();
    run_ics_feed_poll(&vault, &feed("personal"), &b, 1_800_000_100, 7).unwrap();
    let event = crate::calendar::passport::resolve_event_by_uid(&vault, "uid-oc@x")
        .unwrap()
        .unwrap();
    let live = || {
        vault
            .claims_for_subject(&event)
            .unwrap()
            .into_iter()
            .filter_map(|id| vault.get_claim(&id).unwrap())
            .filter(|body| body.lifecycle == ClaimLifecycleStatus::Active)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        live()
            .iter()
            .filter(|row| row.predicate == PREDICATE_CALENDAR_MEETING_LINK)
            .count(),
        2
    );
    run_ics_feed_poll(
        &vault,
        &BodyFetcher {
            body: base.into_bytes(),
        },
        &a,
        1_800_000_200,
        7,
    )
    .unwrap();
    let rows = live();
    let attendees: Vec<_> = rows
        .iter()
        .filter(|row| row.predicate == PREDICATE_CALENDAR_ATTENDEE)
        .map(|row| decode_attendee_value(&row.value).unwrap().who)
        .collect();
    assert_eq!(attendees, ["mailto:personal@example.org"]);
    assert_eq!(
        rows.iter()
            .filter(|row| row.predicate == PREDICATE_CALENDAR_MEETING_LINK)
            .count(),
        1
    );
}

#[test]
fn missing_dtstart_retracts_time_metadata_and_never_bills_the_poll_instant() {
    use crate::calendar::claims::PREDICATE_CALENDAR_TIME_KIND;
    let (_dir, vault) = open_calendar_vault();
    let config = test_config();
    let dated = String::from_utf8(one_event_feed("20260806T140000Z", "20260806T150000Z")).unwrap();
    let now = 1_800_000_000;
    run_ics_feed_poll(
        &vault,
        &BodyFetcher {
            body: dated.clone().into_bytes(),
        },
        &config,
        now,
        7,
    )
    .unwrap();
    let event = crate::calendar::passport::resolve_event_by_uid(&vault, "uid-oc@x")
        .unwrap()
        .unwrap();
    // Imports remain proposed until reviewed. Approve the initial facts through
    // the public write door so this oracle tests time semantics, not filtering.
    for id in vault.claims_for_subject(&event).unwrap() {
        let mut claim = vault.get_claim(&id).unwrap().unwrap();
        claim.approval = crate::ClaimApprovalStatus::Approved;
        vault
            .put_claim(
                &id,
                &claim,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
            )
            .unwrap();
    }
    let window = TimeRange {
        start: 0,
        end: now + 100,
    };
    assert_eq!(
        crate::calendar::freebusy::freebusy(&vault, &[], window)
            .unwrap()
            .len(),
        1
    );
    let undated = dated
        .replace("DTSTART:20260806T140000Z\r\n", "")
        .replace("DTEND:20260806T150000Z\r\n", "");
    run_ics_feed_poll(
        &vault,
        &BodyFetcher {
            body: undated.into_bytes(),
        },
        &config,
        now + 1,
        7,
    )
    .unwrap();
    assert_eq!(
        crate::calendar::passport::resolve_event_by_uid(&vault, "uid-oc@x").unwrap(),
        Some(event)
    );
    assert!(
        !vault
            .claims_for_subject(&event)
            .unwrap()
            .into_iter()
            .any(|id| {
                vault.get_claim(&id).unwrap().is_some_and(|claim| {
                    claim.lifecycle == ClaimLifecycleStatus::Active
                        && claim.predicate == PREDICATE_CALENDAR_TIME_KIND
                })
            })
    );
    assert!(
        crate::calendar::freebusy::freebusy(&vault, &[], window)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn connector_missing_dtstart_preserves_other_sources_time_metadata() {
    use crate::calendar::claims::PREDICATE_CALENDAR_TIME_KIND;
    let (_dir, vault) = open_calendar_vault();
    let dated = one_event_feed("20260806T140000Z", "20260806T150000Z");
    let feed = crate::calendar::ics::parse_ics_feed(&dated).unwrap();
    admit_connector_event(
        &vault,
        "work",
        "fixture://dated",
        &feed.events[0],
        1_800_000_000,
    )
    .unwrap();
    let event = connector_event_ref(&vault, &feed.events[0])
        .unwrap()
        .unwrap();
    let time_claims = || {
        vault
            .claims_for_subject(&event)
            .unwrap()
            .into_iter()
            .filter(|id| {
                vault.get_claim(id).unwrap().is_some_and(|claim| {
                    claim.lifecycle == ClaimLifecycleStatus::Active
                        && claim.predicate == PREDICATE_CALENDAR_TIME_KIND
                })
            })
            .collect::<Vec<_>>()
    };
    let work = time_claims();
    assert_eq!(work.len(), 1);
    admit_connector_event(
        &vault,
        "personal",
        "fixture://dated",
        &feed.events[0],
        1_800_000_000,
    )
    .unwrap();
    let before = time_claims();
    assert_eq!(before.len(), 2);
    let personal = *before.iter().find(|id| !work.contains(id)).unwrap();
    let undated = String::from_utf8(dated)
        .unwrap()
        .replace("DTSTART:20260806T140000Z\r\n", "")
        .replace("DTEND:20260806T150000Z\r\n", "");
    let feed = crate::calendar::ics::parse_ics_feed(undated.as_bytes()).unwrap();
    admit_connector_event(
        &vault,
        "work",
        "fixture://undated",
        &feed.events[0],
        1_800_000_001,
    )
    .unwrap();
    assert_eq!(time_claims(), vec![personal]);
    admit_connector_event(
        &vault,
        "personal",
        "fixture://undated",
        &feed.events[0],
        1_800_000_002,
    )
    .unwrap();
    assert!(time_claims().is_empty());
}

#[test]
fn invalid_derived_claim_values_leave_no_event_uid_or_claims_on_repeated_polls() {
    let base = String::from_utf8(one_event_feed("20260806T140000Z", "20260806T150000Z")).unwrap();
    for property in [
        format!("URL:https://meet.example.org/{}", "x".repeat(513)),
        format!("ATTENDEE;ROLE={}:mailto:host@example.org", "x".repeat(513)),
    ] {
        let (_dir, vault) = open_calendar_vault();
        let invalid = base.replace("SUMMARY:standup", &format!("SUMMARY:standup\r\n{property}"));
        assert!(crate::calendar::ics::parse_ics_feed(invalid.as_bytes()).is_ok());
        let fetcher = BodyFetcher {
            body: invalid.into_bytes(),
        };
        for now in [1_800_000_000, 1_800_000_001] {
            assert!(matches!(
                run_ics_feed_poll(&vault, &fetcher, &test_config(), now, 7),
                Err(CalendarError::IcsIngest { .. })
            ));
            assert!(
                vault
                    .entities_by_type(ENTITY_TYPE_EVENT)
                    .unwrap()
                    .is_empty()
            );
            assert!(
                vault
                    .entities_by_type(crate::registry::ENTITY_TYPE_CLAIM)
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(
                crate::calendar::passport::resolve_event_by_uid(&vault, "uid-oc@x").unwrap(),
                None
            );
        }
    }
}

#[test]
fn invalid_connector_update_preserves_event_properties_and_passport() {
    let (_dir, vault) = open_calendar_vault();
    let base = String::from_utf8(one_event_feed("20260806T140000Z", "20260806T150000Z")).unwrap();
    let first = crate::calendar::ics::parse_ics_feed(base.as_bytes()).unwrap();
    admit_connector_event(
        &vault,
        "work",
        "fixture://first",
        &first.events[0],
        1_800_000_000,
    )
    .unwrap();
    let event = connector_event_ref(&vault, &first.events[0])
        .unwrap()
        .unwrap();
    let before = vault.get(&event).unwrap();
    let header = vault.read_entity_header(&event).unwrap().unwrap();
    let claims = vault.claims_for_subject(&event).unwrap();
    let invalid = base
        .replace("SEQUENCE:1", "SEQUENCE:2")
        .replace("DTSTART:20260806T140000Z", "DTSTART:20260807T140000Z")
        .replace(
            "SUMMARY:standup",
            &format!(
                "SUMMARY:changed\r\nURL:https://meet.example.org/{}",
                "x".repeat(513)
            ),
        );
    let next = crate::calendar::ics::parse_ics_feed(invalid.as_bytes()).unwrap();
    assert!(matches!(
        admit_connector_event(
            &vault,
            "work",
            "fixture://invalid",
            &next.events[0],
            1_800_000_001
        ),
        Err(CalendarError::IcsIngest { .. })
    ));
    assert_eq!(vault.get(&event).unwrap(), before);
    let after = vault.read_entity_header(&event).unwrap().unwrap();
    assert_eq!(
        (after.occurred_start, after.occurred_end),
        (header.occurred_start, header.occurred_end)
    );
    assert_eq!(vault.claims_for_subject(&event).unwrap(), claims);
    assert!(
        claims
            .iter()
            .all(|id| vault.get_claim(id).unwrap().unwrap().lifecycle
                == ClaimLifecycleStatus::Active)
    );
    assert_eq!(
        crate::calendar::passport::live_passport_for(&vault, &event, "work", "uid-oc@x")
            .unwrap()
            .unwrap()
            .1
            .last_sequence,
        1
    );
}

#[test]
fn invalid_detached_claim_value_preflights_before_the_feed_master_is_created() {
    let (_dir, vault) = open_calendar_vault();
    let base = String::from_utf8(one_event_feed("20260806T140000Z", "20260806T150000Z")).unwrap();
    let exception = format!(
        "BEGIN:VEVENT\r\nUID:uid-oc@x\r\nRECURRENCE-ID:20260806T140000Z\r\nDTSTART:20260806T160000Z\r\nURL:https://meet.example.org/{}\r\nEND:VEVENT\r\n",
        "x".repeat(513)
    );
    let invalid = base.replace("END:VCALENDAR", &format!("{exception}END:VCALENDAR"));
    assert_eq!(
        crate::calendar::ics::parse_ics_feed(invalid.as_bytes())
            .unwrap()
            .events
            .len(),
        2
    );
    assert!(matches!(
        run_ics_feed_poll(
            &vault,
            &BodyFetcher {
                body: invalid.into_bytes()
            },
            &test_config(),
            1_800_000_000,
            7
        ),
        Err(CalendarError::IcsIngest { .. })
    ));
    assert!(
        vault
            .entities_by_type(ENTITY_TYPE_EVENT)
            .unwrap()
            .is_empty()
    );
    assert!(
        vault
            .entities_by_type(crate::registry::ENTITY_TYPE_CLAIM)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        crate::calendar::passport::resolve_event_by_uid(&vault, "uid-oc@x").unwrap(),
        None
    );
}
