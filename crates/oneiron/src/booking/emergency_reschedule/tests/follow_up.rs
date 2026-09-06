use super::*;

fn pick(
    vault: &Vault,
    item: &EmergencyItem,
    index: usize,
    sink: &mut EffectSpy<'_>,
    now: u64,
) -> Result<CalendarRevision, BookingError> {
    counterparty_pick(
        vault,
        &item.actions[index],
        &calendars(),
        &consumer(vault, now),
        sink,
    )
}

#[test]
fn successful_pick_delivers_blob_backed_request_after_both_passports_and_intent() {
    let (_dir, vault, _, plan) = executable(EmergencyActionPolicy::Cancel);
    let item = execute(&vault, &plan, &mut spy(&vault, &plan), NOW).unwrap();
    let mut sink = spy(&vault, &plan);
    let revision = pick(&vault, &item, 1, &mut sink, NOW + 1).unwrap();
    let saved = checkpoint(&vault, &plan).unwrap().picked.unwrap();
    assert!(saved.calendar_delivered);
    assert_eq!(revision, saved.calendar);
    assert_eq!(revision.sequence, 2);
    assert_eq!(revision.uid, item.calendar.uid);
    assert_eq!(sink.calls.len(), 1);
    assert_eq!(sink.calls[0].0, "calendar");
    let frozen = crate::calendar::decode_frozen_calendar_invite(&sink.calls[0].1).unwrap();
    assert_eq!(frozen, saved.payload);
    assert_eq!(
        frozen.method,
        crate::calendar::CalendarInviteMethod::Request
    );
    let expected = crate::calendar::ics::emit_imip_ics(&crate::calendar::ics::ImipEmitRequest {
        method: crate::calendar::CalendarInviteMethod::Request,
        uid: revision.uid.clone(),
        sequence: revision.sequence,
        organizer: "host@example.test".to_owned(),
        attendees: vec!["booker@example.test".to_owned()],
        summary: "intro".to_owned(),
        starts_at_utc: plan.proposals[1].start_utc,
        ends_at_utc: plan.proposals[1].end_utc,
        tz_label: plan.booking.context.visitor_tz.clone(),
        dtstamp_utc: NOW + 1,
    })
    .unwrap();
    assert_eq!(
        crate::calendar::read_calendar_invite_ics(&vault, &frozen).unwrap(),
        expected
    );
    assert!(
        !String::from_utf8(sink.calls[0].1.clone())
            .unwrap()
            .contains("BEGIN:VCALENDAR")
    );
    assert_eq!(
        project_event_outcome(read_event_outcome(&vault, revision.event_ref).unwrap()),
        EventOutcome::Unknown
    );
    assert_eq!(
        pick(&vault, &item, 1, &mut sink, NOW + 2).unwrap(),
        revision
    );
    assert_eq!(sink.calls.len(), 1);
    assert!(
        execute(&vault, &plan, &mut sink, NOW + 2).is_err(),
        "the old CANCEL cannot follow the picked REQUEST"
    );
    assert_eq!(sink.calls.len(), 1);
}

#[test]
fn picking_the_already_updated_slot_still_sends_one_follow_up_request() {
    let (_dir, vault, _, plan) = executable(EmergencyActionPolicy::RequestUpdate);
    let item = execute(&vault, &plan, &mut spy(&vault, &plan), NOW).unwrap();
    let mut sink = spy(&vault, &plan);
    let revision = pick(&vault, &item, 0, &mut sink, NOW + 1).unwrap();
    assert_eq!(revision.sequence, 2);
    assert_eq!(sink.calls.len(), 1);
    assert_eq!(
        crate::calendar::decode_frozen_calendar_invite(&sink.calls[0].1)
            .unwrap()
            .method,
        crate::calendar::CalendarInviteMethod::Request
    );
    assert!(
        read_event_outcome(&vault, revision.event_ref)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        pick(&vault, &item, 0, &mut sink, NOW + 2).unwrap(),
        revision
    );
    assert_eq!(sink.calls.len(), 1);
}

#[test]
fn failed_pick_delivery_reuses_committed_sequence_blob_and_frozen_intent() {
    let (_dir, vault, _, plan) = executable(EmergencyActionPolicy::Cancel);
    let item = execute(&vault, &plan, &mut spy(&vault, &plan), NOW).unwrap();
    let mut sink = spy(&vault, &plan);
    sink.fail_channel = Some("calendar");
    assert!(pick(&vault, &item, 0, &mut sink, NOW + 1).is_err());
    let pending = checkpoint(&vault, &plan).unwrap().picked.unwrap();
    assert!(!pending.calendar_delivered);
    assert_eq!(pending.calendar.sequence, 2);
    let bytes = crate::calendar::read_calendar_invite_ics(&vault, &pending.payload).unwrap();
    let frozen = sink.calls[0].1.clone();
    assert!(
        pick(&vault, &item, 1, &mut sink, NOW + 2).is_err(),
        "a different action cannot replace a pending pick"
    );
    assert_eq!(sink.calls.len(), 1);
    let revision = pick(&vault, &item, 0, &mut sink, NOW + 60).unwrap();
    let done = checkpoint(&vault, &plan).unwrap().picked.unwrap();
    assert_eq!(revision, pending.calendar);
    assert_eq!(done.content_hash, pending.content_hash);
    assert_eq!(done.payload, pending.payload);
    assert_eq!(done.committed_at, NOW + 1);
    assert!(done.calendar_delivered);
    assert_eq!(
        crate::calendar::read_calendar_invite_ics(&vault, &done.payload).unwrap(),
        bytes
    );
    assert_eq!(sink.calls.len(), 2);
    assert_eq!(sink.calls[1].1, frozen);
    assert_eq!(
        pick(&vault, &item, 0, &mut sink, NOW + 61).unwrap(),
        revision
    );
    assert_eq!(sink.calls.len(), 2);
}

#[test]
fn acknowledged_pick_with_missing_delivery_mark_does_not_repeat_effect() {
    let (_dir, vault, _, plan) = executable(EmergencyActionPolicy::Cancel);
    let item = execute(&vault, &plan, &mut spy(&vault, &plan), NOW).unwrap();
    let mut sink = spy(&vault, &plan);
    let revision = pick(&vault, &item, 0, &mut sink, NOW + 1).unwrap();
    // Model the crash gap after the chokepoint ACK and before our local mark.
    booking_writer(&vault, |txn| {
        let mut saved = read_item_in(
            &vault,
            &*txn,
            &item_key(&plan.request, item.calendar.event_ref)?,
        )?
        .unwrap();
        saved.picked.as_mut().unwrap().calendar_delivered = false;
        write_item_in(&vault, txn, &saved)
    })
    .unwrap();
    assert_eq!(
        pick(&vault, &item, 0, &mut sink, NOW + 2).unwrap(),
        revision
    );
    assert_eq!(
        sink.calls.len(),
        1,
        "the existing chokepoint ACK owns deduplication"
    );
    assert!(
        checkpoint(&vault, &plan)
            .unwrap()
            .picked
            .unwrap()
            .calendar_delivered
    );
    assert!(
        passports(&vault, revision.event_ref)
            .iter()
            .all(|head| head.last_sequence == 2)
    );
}

#[test]
fn follow_up_request_gate_refusal_is_not_reported_as_pick_success() {
    use crate::campaign::claims::{
        CommDoNotContactValue, DO_NOT_CONTACT_SCOPE_ALL, PREDICATE_COMM_DO_NOT_CONTACT,
        encode_do_not_contact_value,
    };
    let (_dir, vault, _, plan) = executable(EmergencyActionPolicy::Cancel);
    let item = execute(&vault, &plan, &mut spy(&vault, &plan), NOW).unwrap();
    let party = crate::comm::resolve_or_create_comm_party(&vault, "booker@example.test").unwrap();
    let denial = ClaimBody::new(
        PREDICATE_COMM_DO_NOT_CONTACT,
        ClaimSubject::Entity(party),
        encode_do_not_contact_value(&CommDoNotContactValue {
            scope: DO_NOT_CONTACT_SCOPE_ALL.to_owned(),
            channel: Some("calendar".to_owned()),
        }),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    vault
        .put_claim(
            &id(0x7c),
            &denial,
            TimeRange {
                start: NOW + 1,
                end: NOW + 1,
            },
            NOW + 1,
        )
        .unwrap();
    let mut sink = spy(&vault, &plan);
    assert!(pick(&vault, &item, 0, &mut sink, NOW + 1).is_err());
    let pending = checkpoint(&vault, &plan).unwrap().picked.unwrap();
    assert_eq!(pending.calendar.sequence, 2);
    assert!(!pending.calendar_delivered);
    assert!(sink.calls.is_empty());
    assert!(pick(&vault, &item, 0, &mut sink, NOW + 2).is_err());
    assert_eq!(checkpoint(&vault, &plan).unwrap().picked.unwrap(), pending);
    assert!(sink.calls.is_empty());
}

#[test]
fn picked_request_admission_failure_resumes_saved_content_after_identity_returns() {
    use crate::channel_identity::ChannelIdentityState;
    let (_dir, vault, _, plan) = executable(EmergencyActionPolicy::Cancel);
    let item = execute(&vault, &plan, &mut spy(&vault, &plan), NOW).unwrap();
    let (snapshot, index) = crate::booking::lifecycle::read_emergency_pick(
        &vault,
        &item.actions[0],
        &consumer(&vault, NOW + 1),
    )
    .unwrap();
    let prepared = super::super::pick::prepare_pick(&vault, &snapshot, index, NOW + 1).unwrap();
    crate::booking::lifecycle::pick_emergency_item(
        &vault,
        &item.actions[0],
        &calendars(),
        &consumer(&vault, NOW + 1),
        &prepared,
    )
    .unwrap();
    vault
        .transition_channel_identity(
            &id(0x79),
            ChannelIdentityState::Rotating,
            None,
            NOW + 2,
            None,
        )
        .unwrap();
    let mut sink = spy(&vault, &plan);
    assert!(pick(&vault, &item, 0, &mut sink, NOW + 2).is_err());
    assert!(sink.calls.is_empty());
    assert_eq!(checkpoint(&vault, &plan).unwrap().picked.unwrap(), prepared);
    vault
        .transition_channel_identity(&id(0x79), ChannelIdentityState::Active, None, NOW + 3, None)
        .unwrap();
    assert_eq!(
        pick(&vault, &item, 0, &mut sink, NOW + 3).unwrap(),
        prepared.calendar
    );
    assert_eq!(sink.calls.len(), 1);
    assert_eq!(
        crate::calendar::decode_frozen_calendar_invite(&sink.calls[0].1).unwrap(),
        prepared.payload
    );
}

#[test]
fn pick_busy_race_after_request_preparation_does_not_advance_sequence() {
    let (_dir, vault, _, plan) = executable(EmergencyActionPolicy::Cancel);
    let item = execute(&vault, &plan, &mut spy(&vault, &plan), NOW).unwrap();
    let (snapshot, index) = crate::booking::lifecycle::read_emergency_pick(
        &vault,
        &item.actions[0],
        &consumer(&vault, NOW + 1),
    )
    .unwrap();
    let prepared = super::super::pick::prepare_pick(&vault, &snapshot, index, NOW + 1).unwrap();
    book(&vault, PAGE, plan.proposals[0].start_utc);
    let before = (meta(&vault), entities(&vault));
    let error = crate::booking::lifecycle::pick_emergency_item(
        &vault,
        &item.actions[0],
        &calendars(),
        &consumer(&vault, NOW + 1),
        &prepared,
    )
    .unwrap_err();
    assert!(error.to_string().contains("busy"));
    assert_eq!((meta(&vault), entities(&vault)), before);
    assert!(checkpoint(&vault, &plan).unwrap().picked.is_none());
    assert!(
        passports(&vault, item.calendar.event_ref)
            .iter()
            .all(|head| head.last_sequence == 1)
    );
    let mut sink = spy(&vault, &plan);
    assert_eq!(
        pick(&vault, &item, 1, &mut sink, NOW + 1).unwrap().sequence,
        2
    );
    assert_eq!(sink.calls.len(), 1);
}

#[test]
fn changed_pick_blob_head_refuses_retry_without_another_sequence_or_effect() {
    let (_dir, vault, _, plan) = executable(EmergencyActionPolicy::Cancel);
    let item = execute(&vault, &plan, &mut spy(&vault, &plan), NOW).unwrap();
    let mut sink = spy(&vault, &plan);
    sink.fail_channel = Some("calendar");
    assert!(pick(&vault, &item, 0, &mut sink, NOW + 1).is_err());
    let pending = checkpoint(&vault, &plan).unwrap().picked.unwrap();
    let artifact =
        EntityId::from_hex(pending.payload.ics_blob_ref.strip_prefix("blob:").unwrap()).unwrap();
    vault
        .append_blob_artifact_version(
            &artifact,
            b"different picked content",
            &crate::blob_artifact::BlobVersionProvenance::UserUpload,
            crate::write_envelope::WriteActor::new(id(OWNER), crate::edge::EdgeActorClass::Human),
            TimeRange {
                start: NOW + 2,
                end: NOW + 2,
            },
            NOW + 2,
        )
        .unwrap();
    assert!(pick(&vault, &item, 0, &mut sink, NOW + 3).is_err());
    assert_eq!(sink.calls.len(), 1);
    assert_eq!(checkpoint(&vault, &plan).unwrap().picked.unwrap(), pending);
    assert!(
        passports(&vault, item.calendar.event_ref)
            .iter()
            .all(|head| head.last_sequence == 2)
    );
}

#[test]
fn competing_same_pick_preparations_reuse_the_winning_checkpoint() {
    let (_dir, vault, _, plan) = executable(EmergencyActionPolicy::Cancel);
    let item = execute(&vault, &plan, &mut spy(&vault, &plan), NOW).unwrap();
    let (snapshot, index) = crate::booking::lifecycle::read_emergency_pick(
        &vault,
        &item.actions[0],
        &consumer(&vault, NOW + 1),
    )
    .unwrap();
    let first = super::super::pick::prepare_pick(&vault, &snapshot, index, NOW + 1).unwrap();
    let second = super::super::pick::prepare_pick(&vault, &snapshot, index, NOW + 2).unwrap();
    assert_ne!(first.content_hash, second.content_hash);
    let winner = crate::booking::lifecycle::pick_emergency_item(
        &vault,
        &item.actions[0],
        &calendars(),
        &consumer(&vault, NOW + 1),
        &first,
    )
    .unwrap();
    let replay = crate::booking::lifecycle::pick_emergency_item(
        &vault,
        &item.actions[0],
        &calendars(),
        &consumer(&vault, NOW + 2),
        &second,
    )
    .unwrap();
    assert_eq!(winner, replay);
    assert_eq!(replay.picked.as_ref().unwrap(), &first);
    let mut sink = spy(&vault, &plan);
    assert_eq!(
        pick(&vault, &item, 0, &mut sink, NOW + 3).unwrap(),
        first.calendar
    );
    assert_eq!(
        pick(&vault, &item, 0, &mut sink, NOW + 4).unwrap(),
        first.calendar
    );
    assert_eq!(sink.calls.len(), 1);
    assert_eq!(
        crate::calendar::decode_frozen_calendar_invite(&sink.calls[0].1).unwrap(),
        first.payload
    );
}

#[test]
fn pending_pick_survives_vault_reopen_with_the_same_request_content() {
    let (dir, vault, _, plan) = executable(EmergencyActionPolicy::Cancel);
    let item = execute(&vault, &plan, &mut spy(&vault, &plan), NOW).unwrap();
    let mut sink = spy(&vault, &plan);
    sink.fail_channel = Some("calendar");
    assert!(pick(&vault, &item, 0, &mut sink, NOW + 1).is_err());
    let frozen = sink.calls[0].1.clone();
    let pending = checkpoint(&vault, &plan).unwrap().picked.unwrap();
    drop(sink);
    drop(vault);
    let reopened = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    let mut sink = spy(&reopened, &plan);
    assert_eq!(
        pick(&reopened, &item, 0, &mut sink, NOW + 2).unwrap(),
        pending.calendar
    );
    assert_eq!(sink.calls.len(), 1);
    assert_eq!(sink.calls[0].1, frozen);
    assert_eq!(
        checkpoint(&reopened, &plan)
            .unwrap()
            .picked
            .unwrap()
            .content_hash,
        pending.content_hash
    );
}
