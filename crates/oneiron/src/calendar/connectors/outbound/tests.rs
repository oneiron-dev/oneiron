use super::*;
use crate::calendar::connectors::{
    CalendarConnectorSeatConfig, CalendarSyncOutcome, RemoteCalendarChange, RemoteCalendarObject,
    RemoteSyncBatch, calendar_write_outbox_rows, run_calendar_connector_sync,
};
use crate::calendar::ics::parse_ics_feed;
use crate::calendar::test_support::{CalendarEventFixture, open_calendar_vault};
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

/// `event`'s stored body with only `name` replaced. A local EVENT write must
/// carry the EVENT's live origin union, so every other field is kept.
fn renamed_body(vault: &Vault, event: EntityId, name: &str) -> Vec<u8> {
    let body = vault.get(&event).unwrap().unwrap();
    let rmpv::Value::Map(mut fields) = rmpv::decode::read_value(&mut body.as_slice()).unwrap()
    else {
        panic!("calendar EVENT body is a map");
    };
    fields.retain(|(key, _)| key.as_str() != Some("name"));
    fields.push(("name".into(), name.into()));
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &rmpv::Value::Map(fields)).unwrap();
    out
}

fn put_local_edit(vault: &Vault, event: EntityId, body: &[u8]) {
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
            body,
        )
        .unwrap();
}

#[test]
fn remote_applied_snapshot_settles_without_overwriting_an_inflight_local_edit() {
    let (_dir, vault) = open_calendar_vault();
    let owner = crate::WriteActor::new(
        vault.ensure_embedded_owner_actor().unwrap(),
        crate::EdgeActorClass::Human,
    );
    let event = vault
        .create_native_calendar_event(
            &crate::calendar::origin::CalendarEventInput {
                name: "staged".into(),
                ..Default::default()
            },
            crate::TimeRange {
                start: NOW,
                end: NOW + 60,
            },
            owner,
        )
        .unwrap();
    let edited = renamed_body(&vault, event, "newer local edit");
    let transport = ChangeDuringUpsert {
        on_first: RefCell::new(Some(Box::new(|| put_local_edit(&vault, event, &edited)))),
        requests: RefCell::default(),
    };
    let first = write_calendar_event(&vault, &seat(), &transport, event, NOW).unwrap();
    assert_eq!(
        calendar_write_outbox_rows(&vault).unwrap()[0].state,
        CalendarWriteOutboxState::Committed
    );
    assert_eq!(vault.get(&event).unwrap(), Some(edited.clone()));
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
    assert_eq!(vault.get(&event).unwrap(), Some(edited.clone()));
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
    let child_edit = renamed_body(&vault, child, "newer child edit");
    let transport = ChangeDuringUpsert {
        on_first: RefCell::new(Some(Box::new(|| {
            put_local_edit(&vault, child, &child_edit);
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
                    )
                    .unwrap(),
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
    assert_eq!(vault.get(&child).unwrap(), Some(child_edit.clone()));
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

#[test]
fn remote_applied_resume_uses_stored_snapshot_after_a_newer_local_edit() {
    struct Unreachable;
    impl CalendarRemoteTransport for Unreachable {
        fn provider_key(&self) -> &'static str {
            crate::calendar::caldav::CALDAV_PROVIDER_KEY
        }
        fn pull(
            &self,
            _secret_ref: &str,
            _calendar_ref: &str,
            _cursor: Option<&str>,
        ) -> Result<RemoteSyncBatch, CalendarConnectorError> {
            panic!("the failing write never pulls")
        }
        fn upsert(
            &self,
            _secret_ref: &str,
            _calendar_ref: &str,
            _request: &RemoteWriteRequest,
        ) -> Result<RemoteWriteReceipt, CalendarConnectorError> {
            Err(CalendarConnectorError::Transport {
                provider: crate::calendar::caldav::CALDAV_PROVIDER_KEY,
                operation: "upsert",
                detail: "provider unreachable".into(),
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
            panic!("the failing write never deletes")
        }
    }
    let (_dir, vault) = open_calendar_vault();
    let owner = crate::WriteActor::new(
        vault.ensure_embedded_owner_actor().unwrap(),
        crate::EdgeActorClass::Human,
    );
    // A local edit carries the EVENT's live origin, so the EVENT is native.
    let event = vault
        .create_native_calendar_event(
            &crate::calendar::origin::CalendarEventInput {
                name: "staged".into(),
                ..Default::default()
            },
            crate::TimeRange {
                start: NOW,
                end: NOW + 60,
            },
            owner,
        )
        .unwrap();
    // An ordinary transport failure leaves the row prepared. The provider then
    // applies the prepared request, and a crash before the local settle leaves
    // it remote-applied.
    assert!(write_calendar_event(&vault, &seat(), &Unreachable, event, NOW).is_err());
    let mut row = calendar_write_outbox_rows(&vault).unwrap().remove(0);
    let transport = ChangeDuringUpsert {
        on_first: RefCell::new(None),
        requests: RefCell::default(),
    };
    let uid = row.uid.clone();
    let request = RemoteWriteRequest {
        href: row.href.clone(),
        expected_etag: row.expected_etag.clone(),
        uid: uid.clone(),
        sequence: row.sequence,
        ics: render_owner_vevent(&vault, &event, &uid, row.sequence, NOW)
            .unwrap()
            .ics,
    };
    issue_prepared_upsert(&vault, &seat(), &transport, &uid, NOW, &mut row, &request).unwrap();
    let row = calendar_write_outbox_rows(&vault).unwrap().remove(0);
    assert_eq!(row.state, CalendarWriteOutboxState::RemoteApplied);
    let edited = renamed_body(&vault, event, "newer local edit");
    put_local_edit(&vault, event, &edited);
    let resumed = write_calendar_event(&vault, &seat(), &transport, event, NOW + 2).unwrap();
    assert_eq!(Some(resumed.clone()), row.receipt);
    assert_eq!(transport.requests.borrow().len(), 1);
    assert_eq!(
        calendar_write_outbox_rows(&vault).unwrap()[0].state,
        CalendarWriteOutboxState::Committed
    );
    assert_eq!(vault.get(&event).unwrap(), Some(edited));
    let next = write_calendar_event(&vault, &seat(), &transport, event, NOW + 3).unwrap();
    assert_eq!(next.sequence, resumed.sequence + 1);
    assert_eq!(transport.requests.borrow()[1].expected_etag, resumed.etag);
}
