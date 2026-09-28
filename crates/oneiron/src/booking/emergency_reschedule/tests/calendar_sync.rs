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
    let clock = crate::ports::ManualClock::new(NOW);
    let config = crate::VaultConfig {
        store_clock: clock.bundle(),
        ..crate::VaultConfig::default()
    };
    let (_dir, vault, receipt, plan) =
        executable_with_invite_config(EmergencyActionPolicy::Cancel, true, config);
    crate::calendar::test_support::provision_test_calendar_importer(&vault);
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

#[test]
fn provider_cancelled_booking_cannot_pass_a_due_reminder_wake() {
    use crate::booking::{booking_due_reminder, booking_reminder_wakes};
    use crate::calendar::claims::{CalendarStatus, PREDICATE_CALENDAR_STATUS, decode_status_value};
    use crate::claim::claim_surfaceable;

    let (_dir, vault, receipt, plan) = executable(EmergencyActionPolicy::Cancel);
    crate::calendar::test_support::provision_test_calendar_importer(&vault);
    let event_ref = receipt.calendar.event_ref;
    let policy = crate::booking::BookingConversionPolicy {
        reminder_leads_secs: vec![1_800, 600],
        ..vault.booking_conversion_policy(None).unwrap()
    };
    let wakes = booking_reminder_wakes(event_ref, plan.booking.occurrence.start, NOW, &policy)
        .expect("two reminder wakes");
    assert_eq!(wakes.len(), 2);
    assert!(
        booking_due_reminder(&vault, &wakes[0], wakes[0].due_utc, &policy)
            .unwrap()
            .is_some()
    );

    let ics = crate::calendar::emit_imip_ics(&crate::calendar::ImipEmitRequest {
        method: crate::calendar::CalendarInviteMethod::Cancel,
        uid: receipt.calendar.uid.clone(),
        sequence: 1,
        organizer: "host@example.test".to_owned(),
        attendees: vec!["booker@example.test".to_owned()],
        summary: "provider cancelled".to_owned(),
        starts_at_utc: plan.booking.occurrence.start,
        ends_at_utc: plan.booking.occurrence.end,
        tz_label: "UTC".to_owned(),
        dtstamp_utc: NOW + 1,
    })
    .unwrap();
    let transport = PullOne(RemoteCalendarObject {
        href: "/booking.ics".to_owned(),
        etag: Some("cancelled".to_owned()),
        uid: receipt.calendar.uid,
        sequence: 1,
        content_hash: [0; 32],
        ics,
    });
    let seat = CalendarConnectorSeatState::new(CalendarConnectorSeatConfig {
        seat_ref: "booking-sync-cancel".to_owned(),
        secret_ref: "booking-calendar".to_owned(),
        system: "provider-calendar".to_owned(),
        calendar_ref: "calendar".to_owned(),
        cadence_jitter_min_seconds: 30,
        cadence_jitter_max_seconds: 60,
    });
    run_calendar_connector_sync(&vault, &seat, &transport, NOW + 1, 7).unwrap();
    let status_id = vault
        .claims_for_subject(&event_ref)
        .unwrap()
        .into_iter()
        .find(|id| {
            vault.get_claim(id).unwrap().is_some_and(|body| {
                body.predicate == PREDICATE_CALENDAR_STATUS
                    && decode_status_value(&body.value).unwrap().status == CalendarStatus::Cancelled
            })
        })
        .expect("provider ingestion records a cancellation claim");
    let status = vault.get_claim(&status_id).unwrap().unwrap();
    if !claim_surfaceable(&status) {
        // Imported evidence is proposed without an actor-bound source permit.
        // A pending row must not suppress the reminder; owner approval makes
        // this an effective provider cancellation on the existing EVENT.
        assert!(
            booking_due_reminder(&vault, &wakes[0], wakes[0].due_utc, &policy)
                .unwrap()
                .is_some()
        );
        // The import is a signed MACHINE claim: the owner approves it with a
        // signed transition, not a raw re-put.
        let owner = vault.ensure_embedded_owner_actor().unwrap();
        crate::test_util::bind_test_owner(&vault, owner);
        vault
            .approve_machine_claim_as(
                status_id,
                crate::WriteActor::new(owner, crate::EdgeActorClass::Human),
            )
            .unwrap();
    }
    assert!(claim_surfaceable(
        &vault.get_claim(&status_id).unwrap().unwrap()
    ));
    assert_eq!(
        booking_due_reminder(&vault, &wakes[0], wakes[0].due_utc, &policy).unwrap(),
        None
    );
}
