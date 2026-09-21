use super::*;
use crate::calendar::connectors::{
    CalendarConnectorSeatConfig, CalendarSyncOutcome, RemoteCalendarChange, RemoteCalendarObject,
    RemoteSyncBatch, calendar_write_outbox_rows, run_calendar_connector_sync,
};
use crate::calendar::ics::parse_ics_feed;
use crate::calendar::test_support::{CalendarEventFixture, event_name_body, open_calendar_vault};
use std::cell::RefCell;

const NOW: u64 = 1_800_000_000;

struct ChangeDuringUpsert<'a> {
    on_first: RefCell<Option<Box<dyn FnOnce() + 'a>>>,
    requests: RefCell<Vec<RemoteWriteRequest>>,
}

impl CalendarRemoteTransport for ChangeDuringUpsert<'_> {
    fn provider_key(&self) -> &'static str {
        crate::calendar::caldav::CALDAV_PROVIDER_KEY
    }

    fn pull(
        &self,
        _secret_ref: &str,
        _calendar_ref: &str,
        _cursor: Option<&str>,
    ) -> Result<RemoteSyncBatch, CalendarConnectorError> {
        let requests = self.requests.borrow();
        let request = requests.last().expect("a write precedes its echo");
        Ok(RemoteSyncBatch {
            next_cursor: None,
            changes: vec![RemoteCalendarChange::Upsert(RemoteCalendarObject {
                href: "/work/event.ics".into(),
                etag: Some(format!("write-{}", requests.len())),
                uid: request.uid.clone(),
                sequence: request.sequence,
                content_hash: ics_content_hash(&request.ics, &request.uid)?,
                ics: request.ics.clone(),
            })],
        })
    }

    fn upsert(
        &self,
        _secret_ref: &str,
        _calendar_ref: &str,
        request: &RemoteWriteRequest,
    ) -> Result<RemoteWriteReceipt, CalendarConnectorError> {
        self.requests.borrow_mut().push(request.clone());
        if let Some(change) = self.on_first.borrow_mut().take() {
            change();
        }
        Ok(RemoteWriteReceipt {
            href: "/work/event.ics".into(),
            etag: Some(format!("write-{}", self.requests.borrow().len())),
            uid: request.uid.clone(),
            sequence: request.sequence,
            content_hash: ics_content_hash(&request.ics, &request.uid)?,
        })
    }

    fn delete(
        &self,
        _secret_ref: &str,
        _calendar_ref: &str,
        _href: &str,
        _expected_etag: Option<&str>,
        _uid: &str,
        _sequence: u32,
    ) -> Result<RemoteWriteReceipt, CalendarConnectorError> {
        panic!("receipt settlement must not delete remotely")
    }
}

fn seat() -> CalendarConnectorSeatState {
    CalendarConnectorSeatState::new(CalendarConnectorSeatConfig {
        seat_ref: "work-seat".into(),
        secret_ref: "caldav:work".into(),
        system: "work".into(),
        calendar_ref: "work".into(),
        cadence_jitter_min_seconds: 300,
        cadence_jitter_max_seconds: 900,
    })
}

fn rename(vault: &Vault, event: EntityId, name: &str) {
    let header = vault.read_entity_header(&event).unwrap().unwrap();
    vault
        .put_entity(
            &event,
            ENTITY_TYPE_EVENT,
            crate::TimeRange {
                start: header.occurred_start,
                end: header.occurred_end,
            },
            NOW + 1,
            &event_name_body(name),
        )
        .unwrap();
}

#[test]
fn remote_applied_snapshot_settles_without_overwriting_an_inflight_local_edit() {
    let (_dir, vault) = open_calendar_vault();
    let event = CalendarEventFixture::new(0x81, "staged", NOW, NOW + 60).store(&vault);
    let transport = ChangeDuringUpsert {
        on_first: RefCell::new(Some(Box::new(|| rename(&vault, event, "newer local edit")))),
        requests: RefCell::default(),
    };
    let first = write_calendar_event(&vault, &seat(), &transport, event, NOW).unwrap();
    assert_eq!(
        calendar_write_outbox_rows(&vault).unwrap()[0].state,
        CalendarWriteOutboxState::Committed
    );
    assert_eq!(
        vault.get(&event).unwrap(),
        Some(event_name_body("newer local edit"))
    );
    let passport = live_passport_for(&vault, &event, "work", &first.uid)
        .unwrap()
        .unwrap()
        .1;
    assert_eq!(passport.content_hash, first.content_hash);
    assert_eq!(passport.last_sequence, first.sequence);
    let echo = run_calendar_connector_sync(&vault, &seat(), &transport, NOW + 2, 7).unwrap();
    assert!(matches!(
        echo,
        CalendarSyncOutcome::Reenqueued {
            applied: 0,
            acknowledged: 1,
            ..
        }
    ));
    assert_eq!(
        vault.get(&event).unwrap(),
        Some(event_name_body("newer local edit"))
    );
    let second = write_calendar_event(&vault, &seat(), &transport, event, NOW + 3).unwrap();
    assert_eq!(second.sequence, first.sequence + 1);
    let requests = transport.requests.borrow();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[1].expected_etag, first.etag);
    assert_eq!(
        parse_ics_feed(&requests[0].ics).unwrap().events[0]
            .summary
            .as_deref(),
        Some("staged")
    );
    assert_eq!(
        parse_ics_feed(&requests[1].ics).unwrap().events[0]
            .summary
            .as_deref(),
        Some("newer local edit")
    );
}

#[test]
fn remote_applied_resume_uses_stored_snapshot_after_a_newer_local_restore() {
    let (_dir, vault) = open_calendar_vault();
    let event = CalendarEventFixture::new(0x82, "staged", NOW, NOW + 60).store(&vault);
    let transport = ChangeDuringUpsert {
        on_first: RefCell::new(Some(Box::new(|| {
            vault.delete_entity(&event).unwrap();
        }))),
        requests: RefCell::default(),
    };
    assert!(write_calendar_event(&vault, &seat(), &transport, event, NOW).is_err());
    let row = calendar_write_outbox_rows(&vault).unwrap().remove(0);
    assert_eq!(row.state, CalendarWriteOutboxState::RemoteApplied);
    vault
        .put_entity(
            &event,
            ENTITY_TYPE_EVENT,
            crate::TimeRange {
                start: NOW,
                end: NOW + 60,
            },
            NOW + 1,
            &event_name_body("restored newer edit"),
        )
        .unwrap();
    let resumed = write_calendar_event(&vault, &seat(), &transport, event, NOW + 2).unwrap();
    assert_eq!(Some(resumed.clone()), row.receipt);
    assert_eq!(transport.requests.borrow().len(), 1);
    assert_eq!(
        calendar_write_outbox_rows(&vault).unwrap()[0].state,
        CalendarWriteOutboxState::Committed
    );
    assert_eq!(
        vault.get(&event).unwrap(),
        Some(event_name_body("restored newer edit"))
    );
    let next = write_calendar_event(&vault, &seat(), &transport, event, NOW + 3).unwrap();
    assert_eq!(next.sequence, resumed.sequence + 1);
    assert_eq!(transport.requests.borrow()[1].expected_etag, resumed.etag);
}

#[test]
fn applied_series_snapshot_keeps_new_members_and_child_edits_for_the_next_sequence() {
    use crate::calendar::claims::PREDICATE_CALENDAR_SERIES_EXCEPTION;
    use crate::calendar::ingest::{admit_connector_event, connector_event_ref};
    let (_dir, vault) = open_calendar_vault();
    let feed = parse_ics_feed(b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:series@test\r\nSEQUENCE:1\r\nDTSTART:20260806T140000Z\r\nDTEND:20260806T150000Z\r\nRRULE:FREQ=DAILY;COUNT=3\r\nSUMMARY:master\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nUID:series@test\r\nSEQUENCE:1\r\nRECURRENCE-ID:20260806T140000Z\r\nDTSTART:20260806T160000Z\r\nDTEND:20260806T170000Z\r\nSUMMARY:staged child\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n").unwrap();
    for parsed in &feed.events {
        admit_connector_event(&vault, "work", "fixture://series", parsed, NOW).unwrap();
    }
    let master = connector_event_ref(&vault, &feed.events[0])
        .unwrap()
        .unwrap();
    let child = connector_event_ref(&vault, &feed.events[1])
        .unwrap()
        .unwrap();
    let added = crate::test_util::entity(0x83);
    let transport = ChangeDuringUpsert {
        on_first: RefCell::new(Some(Box::new(|| {
            rename(&vault, child, "newer child edit");
            assert_eq!(
                CalendarEventFixture::new(
                    0x83,
                    "new local exception",
                    1_786_118_400,
                    1_786_122_000
                )
                .store(&vault),
                added
            );
            vault
                .put_claim(
                    &EntityId::now(),
                    &crate::ClaimBody::new(
                        PREDICATE_CALENDAR_SERIES_EXCEPTION,
                        crate::ClaimSubject::Entity(added),
                        rmpv::Value::Map(vec![
                            ("master_ref".into(), master.to_hex().into()),
                            ("uid".into(), "series@test".into()),
                            ("original_start_utc".into(), 1_786_111_200_u64.into()),
                        ]),
                        1.0,
                        crate::ClaimApprovalStatus::Approved,
                        crate::ClaimLifecycleStatus::Active,
                    ),
                    crate::TimeRange {
                        start: NOW,
                        end: NOW,
                    },
                    NOW,
                )
                .unwrap();
        }))),
        requests: RefCell::default(),
    };
    let first = write_calendar_event(&vault, &seat(), &transport, child, NOW).unwrap();
    let staged = parse_ics_feed(&transport.requests.borrow()[0].ics).unwrap();
    assert_eq!(staged.events.len(), 2);
    for (member, component) in [master, child].into_iter().zip(&staged.events) {
        let passport = live_passport_for(&vault, &member, "work", "series@test")
            .unwrap()
            .unwrap()
            .1;
        assert_eq!(passport.content_hash, component.content_hash);
        assert_eq!(passport.last_sequence, first.sequence);
        assert_eq!(passport.direction, CalendarPassportDirection::TwoWay);
    }
    assert!(
        live_passport_for(&vault, &added, "work", "series@test")
            .unwrap()
            .is_none()
    );
    let echo = run_calendar_connector_sync(&vault, &seat(), &transport, NOW + 2, 7).unwrap();
    assert!(matches!(
        echo,
        CalendarSyncOutcome::Reenqueued {
            applied: 0,
            acknowledged: 2,
            source_absences: 0,
            ..
        }
    ));
    assert_eq!(
        vault.get(&child).unwrap(),
        Some(event_name_body("newer child edit"))
    );
    let next = write_calendar_event(&vault, &seat(), &transport, master, NOW + 3).unwrap();
    assert_eq!(next.sequence, first.sequence + 1);
    let requests = transport.requests.borrow();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[1].expected_etag, first.etag);
    let rendered = parse_ics_feed(&requests[1].ics).unwrap();
    assert_eq!(rendered.events.len(), 3);
    assert_eq!(
        rendered.events[1].summary.as_deref(),
        Some("newer child edit")
    );
    assert_eq!(
        rendered.events[2].summary.as_deref(),
        Some("new local exception")
    );
}
