use super::*;
use crate::calendar::connectors::*;

struct PullOne(RemoteCalendarObject);
impl CalendarRemoteTransport for PullOne {
    fn provider_key(&self) -> &'static str {
        "caldav"
    }
    fn pull(
        &self,
        _: &str,
        _: &str,
        _: Option<&str>,
    ) -> Result<RemoteSyncBatch, CalendarConnectorError> {
        Ok(RemoteSyncBatch {
            next_cursor: Some("next".to_owned()),
            changes: vec![RemoteCalendarChange::Upsert(self.0.clone())],
        })
    }
    fn upsert(
        &self,
        _: &str,
        _: &str,
        _: &RemoteWriteRequest,
    ) -> Result<RemoteWriteReceipt, CalendarConnectorError> {
        unreachable!("an inbound sync must not write remotely")
    }
    fn delete(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: Option<&str>,
        _: &str,
        _: u32,
    ) -> Result<RemoteWriteReceipt, CalendarConnectorError> {
        unreachable!("an inbound sync must not delete remotely")
    }
}

#[test]
fn normal_connector_upsert_rewrites_event_without_erasing_confirmation_context() {
    let (_dir, vault, receipt, plan) = executable(EmergencyActionPolicy::Cancel);
    let context = crate::booking::lifecycle::booking_confirmation_context(
        &vault,
        &receipt.calendar.event_ref,
    )
    .unwrap()
    .unwrap();
    let ics = crate::calendar::emit_imip_ics(&crate::calendar::ImipEmitRequest {
        method: crate::calendar::CalendarInviteMethod::Request,
        uid: receipt.calendar.uid.clone(),
        sequence: 0,
        organizer: "host@example.test".to_owned(),
        attendees: vec!["booker@example.test".to_owned()],
        summary: "provider title".to_owned(),
        starts_at_utc: plan.booking.occurrence.start,
        ends_at_utc: plan.booking.occurrence.end,
        tz_label: "UTC".to_owned(),
        dtstamp_utc: NOW,
    })
    .unwrap();
    let transport = PullOne(RemoteCalendarObject {
        href: "/booking.ics".to_owned(),
        etag: Some("v1".to_owned()),
        uid: receipt.calendar.uid.clone(),
        sequence: 0,
        content_hash: [0; 32],
        ics,
    });
    let seat = CalendarConnectorSeatState::new(CalendarConnectorSeatConfig {
        seat_ref: "booking-sync".to_owned(),
        secret_ref: "booking-calendar".to_owned(),
        system: "provider-calendar".to_owned(),
        calendar_ref: "calendar".to_owned(),
        cadence_jitter_min_seconds: 30,
        cadence_jitter_max_seconds: 60,
    });
    run_calendar_connector_sync(&vault, &seat, &transport, NOW + 1, 7).unwrap();
    let raw = vault.get_raw(&receipt.calendar.event_ref).unwrap().unwrap();
    assert!(
        !raw.windows(b"booking_context".len())
            .any(|bytes| bytes == b"booking_context")
    );
    assert_eq!(
        crate::booking::lifecycle::booking_confirmation_context(
            &vault,
            &receipt.calendar.event_ref
        )
        .unwrap(),
        Some(context)
    );
    let rows = enumerate_affected_bookings(&vault, &plan.request, NOW + 1).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].calendar.event_ref, receipt.calendar.event_ref);
}
