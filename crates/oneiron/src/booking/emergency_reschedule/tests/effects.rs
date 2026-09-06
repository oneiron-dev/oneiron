use super::*;

#[test]
fn each_item_has_two_or_three_live_solver_proposals() {
    let (_dir, vault, _, plan) = executable(EmergencyActionPolicy::Cancel);
    assert!((2..=3).contains(&plan.proposals.len()));
    let distinct: std::collections::BTreeSet<_> = plan
        .proposals
        .iter()
        .map(|slot| (slot.start_utc, slot.end_utc))
        .collect();
    assert_eq!(distinct.len(), plan.proposals.len());
    for slot in &plan.proposals {
        let solved = solve_live(
            &vault,
            &plan.booking,
            &calendars(),
            TimeRange {
                start: slot.start_utc,
                end: slot.end_utc - 1,
            },
            NOW,
        )
        .unwrap();
        assert!(
            solved
                .slots
                .iter()
                .any(|live| live.start_utc == slot.start_utc && live.end_utc == slot.end_utc)
        );
    }
}
#[test]
fn plan_and_execute_thread_the_same_now_utc() {
    let (_dir, vault, _, plan) = executable(EmergencyActionPolicy::Cancel);
    let mut sink = spy(&vault, &plan);
    let item = execute(&vault, &plan, &mut sink, NOW).unwrap();
    assert_eq!(plan.planned_at, NOW);
    assert_eq!(item.committed_at, NOW);
    assert!(plan.proposals.iter().all(|slot| slot.start_utc > NOW));
}
#[test]
fn cancel_keeps_uid_and_increments_sequence_once() {
    let (_dir, vault, receipt, plan) = executable(EmergencyActionPolicy::Cancel);
    let mut sink = spy(&vault, &plan);
    let first = execute(&vault, &plan, &mut sink, NOW).unwrap();
    let replay = execute(&vault, &plan, &mut sink, NOW + 1).unwrap();
    assert_eq!(first, replay);
    assert_eq!(first.calendar.uid, receipt.calendar.uid);
    assert_eq!(first.calendar.sequence, 1);
    assert_eq!(sink.calls.len(), 2);
    assert_eq!(
        plan.payload.as_ref().unwrap().method,
        crate::calendar::CalendarInviteMethod::Cancel
    );
    // Existing ordinary cancel token returns the same cancellation receipt.
    let ordinary = run(
        &vault,
        BookingVerbRequest::Cancel(CancelSpec {
            token: receipt.cancel_token,
            idempotency_key: None,
        }),
        plan.booking.occurrence,
    );
    assert!(
        matches!(ordinary, BookingVerbReceipt::Cancelled(value) if value.calendar == first.calendar)
    );
}
#[test]
fn update_uses_request_same_uid_and_increments_sequence_once() {
    let (_dir, vault, receipt, plan) = executable(EmergencyActionPolicy::RequestUpdate);
    let mut sink = spy(&vault, &plan);
    let item = execute(&vault, &plan, &mut sink, NOW).unwrap();
    assert_eq!(item.calendar.uid, receipt.calendar.uid);
    assert_eq!(item.calendar.sequence, 1);
    assert_eq!(
        plan.payload.as_ref().unwrap().method,
        crate::calendar::CalendarInviteMethod::Request
    );
    assert_eq!(
        read_fact::<BookingStatusValue>(
            &vault,
            receipt.calendar.event_ref,
            BOOKING_STATUS_PREDICATE
        )
        .unwrap()
        .unwrap()
        .status,
        BookingStatus::Confirmed
    );
    assert_eq!(execute(&vault, &plan, &mut sink, NOW + 1).unwrap(), item);
}
#[test]
fn local_lifecycle_passport_and_item_state_commit_before_intent_freeze() {
    let (_dir, vault, _, plan) = executable(EmergencyActionPolicy::Cancel);
    assert!(emergency_records(&vault).is_empty());
    let item = crate::booking::lifecycle::commit_emergency_item(
        &vault,
        &plan,
        &calendars(),
        &consumer(&vault, NOW),
    )
    .unwrap();
    assert_eq!(checkpoint(&vault, &plan), Some(item));
    assert!(
        passports(&vault, plan.booking.calendar.event_ref)
            .iter()
            .all(|p| p.last_sequence == 1)
    );
    assert!(emergency_records(&vault).is_empty());
    execute(&vault, &plan, &mut spy(&vault, &plan), NOW).unwrap();
}
#[test]
fn raw_ics_is_blob_backed_and_mime_is_connector_owned() {
    let (_dir, vault, _, plan) = executable(EmergencyActionPolicy::Cancel);
    let raw =
        crate::calendar::read_calendar_invite_ics(&vault, plan.payload.as_ref().unwrap()).unwrap();
    assert!(String::from_utf8(raw).unwrap().contains("METHOD:CANCEL"));
    let mut sink = spy(&vault, &plan);
    execute(&vault, &plan, &mut sink, NOW).unwrap();
    assert!(
        !String::from_utf8(sink.calls[0].1.clone())
            .unwrap()
            .contains("BEGIN:VCALENDAR")
    );
    assert!(
        plan.payload
            .as_ref()
            .unwrap()
            .ics_blob_ref
            .starts_with("blob:")
    );
}
#[test]
fn intent_is_logged_before_each_external_effect() {
    let (_dir, vault, _, plan) = executable(EmergencyActionPolicy::Cancel);
    let mut sink = spy(&vault, &plan);
    execute(&vault, &plan, &mut sink, NOW).unwrap();
    assert_eq!(
        sink.calls
            .iter()
            .map(|(channel, _)| channel.as_str())
            .collect::<Vec<_>>(),
        ["calendar", "email"]
    );
}
#[test]
fn retry_after_partial_failure_reuses_same_sequence_and_content() {
    for failed in ["calendar", "email"] {
        let (_dir, vault, _, plan) = executable(EmergencyActionPolicy::Cancel);
        let mut sink = spy(&vault, &plan);
        sink.fail_channel = Some(failed);
        assert!(execute(&vault, &plan, &mut sink, NOW).is_err());
        let prior = checkpoint(&vault, &plan).unwrap();
        let failed_payload = sink.calls.last().unwrap().1.clone();
        let resumed_plan =
            plan_emergency_reschedule(&vault, &plan.request, &calendars(), NOW + 1).unwrap();
        assert_eq!(resumed_plan.plans, vec![plan.clone()]);
        let item = execute(&vault, &plan, &mut sink, NOW + 1).unwrap();
        assert_eq!(item.calendar, prior.calendar);
        assert_eq!(item.actions, prior.actions);
        assert!(item.calendar_delivered && item.apology_delivered);
        assert_eq!(
            sink.calls
                .iter()
                .filter(|(_, bytes)| bytes == &failed_payload)
                .count(),
            2
        );
        let count = sink.calls.len();
        execute(&vault, &plan, &mut sink, NOW + 2).unwrap();
        assert_eq!(sink.calls.len(), count);
    }
}
#[test]
fn calendar_send_still_passes_gate_hygiene() {
    use crate::campaign::claims::{
        CommDoNotContactValue, DO_NOT_CONTACT_SCOPE_ALL, PREDICATE_COMM_DO_NOT_CONTACT,
        encode_do_not_contact_value,
    };
    let (_dir, vault, _, plan) = executable(EmergencyActionPolicy::Cancel);
    let party = crate::comm::resolve_or_create_comm_party(&vault, "booker@example.test").unwrap();
    vault
        .put_claim(
            &id(0x7c),
            &ClaimBody::new(
                PREDICATE_COMM_DO_NOT_CONTACT,
                ClaimSubject::Entity(party),
                encode_do_not_contact_value(&CommDoNotContactValue {
                    channel: Some("calendar".to_owned()),
                    scope: DO_NOT_CONTACT_SCOPE_ALL.to_owned(),
                }),
                1.0,
                ClaimApprovalStatus::Approved,
                ClaimLifecycleStatus::Active,
            ),
            TimeRange {
                start: NOW,
                end: NOW,
            },
            NOW,
        )
        .unwrap();
    let mut sink = spy(&vault, &plan);
    assert!(execute(&vault, &plan, &mut sink, NOW).is_err());
    assert!(sink.calls.is_empty());
    assert!(emergency_records(&vault).is_empty());
}
#[test]
fn apology_contains_two_or_three_opaque_rebook_actions() {
    let (_dir, vault, _, plan) = executable(EmergencyActionPolicy::Cancel);
    let mut sink = spy(&vault, &plan);
    let item = execute(&vault, &plan, &mut sink, NOW).unwrap();
    assert_eq!(item.actions.len(), plan.proposals.len());
    for token in &item.actions {
        assert_eq!(token.0.len(), 64);
        assert!(!token.0.contains(&item.calendar.event_ref.to_hex()));
    }
    let frozen: serde_json::Value = serde_json::from_slice(&sink.calls[1].1).unwrap();
    let id = EntityId::from_hex(
        frozen["content_ref"]
            .as_str()
            .unwrap()
            .strip_prefix("blob:")
            .unwrap(),
    )
    .unwrap();
    let head = vault.blob_artifact_head(&id).unwrap().unwrap();
    let bytes = vault
        .read_blob_artifact_version(&id, head.version)
        .unwrap()
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        body["actions"].as_array().unwrap().len(),
        item.actions.len()
    );
    for (index, token) in item.actions.iter().enumerate() {
        assert_eq!(
            body["actions"][index]["action"],
            format!("booking:emergency-pick:{}", token.0)
        );
    }
}
#[test]
fn counterparty_pick_delegates_to_lifecycle_home_node_writer() {
    let (_dir, vault, receipt, plan) = executable(EmergencyActionPolicy::Cancel);
    let item = execute(&vault, &plan, &mut spy(&vault, &plan), NOW).unwrap();
    let mut sink = spy(&vault, &plan);
    let token = &item.actions[0];
    let mut remote = consumer(&vault, NOW);
    remote.local_node_id = 10;
    let before = (meta(&vault), entities(&vault));
    assert!(counterparty_pick(&vault, token, &calendars(), &remote, &mut sink).is_err());
    assert_eq!((meta(&vault), entities(&vault)), before);
    // Ordinary tokens still cannot revive the cancelled booking.
    assert!(
        crate::booking::lifecycle::execute_reschedule(
            &vault,
            &Offered(plan.booking.occurrence, OWNER),
            &crate::booking::RescheduleSpec {
                token: receipt.reschedule_token,
                new_slot: plan.booking.occurrence,
                visitor_tz: "UTC".to_owned(),
                constraint: None,
                idempotency_key: None,
            },
            NOW
        )
        .is_err()
    );
    // A competing home-node confirm wins the first offered slot.
    book(&vault, PAGE, plan.proposals[0].start_utc);
    assert!(
        counterparty_pick(
            &vault,
            token,
            &calendars(),
            &consumer(&vault, NOW),
            &mut sink
        )
        .is_err()
    );
    let picked = counterparty_pick(
        &vault,
        &item.actions[1],
        &calendars(),
        &consumer(&vault, NOW),
        &mut sink,
    )
    .unwrap();
    assert_eq!(picked.uid, item.calendar.uid);
    assert_eq!(picked.sequence, 2);
    assert_eq!(
        counterparty_pick(
            &vault,
            &item.actions[1],
            &calendars(),
            &consumer(&vault, NOW),
            &mut sink
        )
        .unwrap(),
        picked
    );
    assert!(
        counterparty_pick(
            &vault,
            token,
            &calendars(),
            &consumer(&vault, NOW),
            &mut sink
        )
        .is_err()
    );
}
#[test]
fn pre_start_cancel_writes_owner_attested_cancelled_pre_start() {
    let (_dir, vault, _, plan) = executable(EmergencyActionPolicy::Cancel);
    execute(&vault, &plan, &mut spy(&vault, &plan), NOW).unwrap();
    let outcome = read_event_outcome(&vault, plan.booking.calendar.event_ref)
        .unwrap()
        .unwrap();
    assert_eq!(outcome.outcome, EventOutcome::CancelledPreStart);
    assert_eq!(
        outcome.basis,
        crate::calendar::EventOutcomeBasis::OwnerAttested
    );
    assert_eq!(outcome.recorded_at, NOW);
}
#[test]
fn at_or_after_start_cancel_uses_distinct_local_basis() {
    for now in [NOW + 3_600, NOW + 5_400] {
        let (_dir, vault, _, plan) = executable(EmergencyActionPolicy::Cancel);
        let item = execute(&vault, &plan, &mut spy(&vault, &plan), now).unwrap();
        assert_eq!(item.basis, EmergencyLocalBasis::EmergencyAtOrAfterStart);
        assert_eq!(
            project_event_outcome(read_event_outcome(&vault, item.calendar.event_ref).unwrap()),
            EventOutcome::Unknown
        );
    }
}
#[test]
fn update_does_not_write_cancelled_outcome() {
    let (_dir, vault, _, plan) = executable(EmergencyActionPolicy::RequestUpdate);
    let item = execute(&vault, &plan, &mut spy(&vault, &plan), NOW).unwrap();
    assert_eq!(item.basis, EmergencyLocalBasis::RequestUpdate);
    assert!(
        read_event_outcome(&vault, item.calendar.event_ref)
            .unwrap()
            .is_none()
    );
}
#[test]
fn facade_entrypoints_extend_memory_facade_only() {
    let (_dir, vault) = open_test_vault_with(VaultConfig::default());
    page(&vault, PAGE, OWNER);
    let input = crate::memory::EmergencyInstructionInput {
        affected_window: crate::calendar::query::CalendarRangeDto {
            start: NOW + 3_600,
            end: NOW + 10_799,
        },
        reason: "unavailable".to_owned(),
        action_policy: EmergencyActionPolicy::Cancel,
        recorded_at: NOW,
    };
    let before = meta(&vault);
    assert!(
        vault
            .memory(id(OWNER), crate::edge::EdgeActorClass::Agent)
            .record_emergency_instruction(&input)
            .is_err()
    );
    assert_eq!(meta(&vault), before);
    let memory: crate::memory::Memory<'_> =
        vault.memory(id(OWNER), crate::edge::EdgeActorClass::Human);
    let record = memory.record_emergency_instruction(&input).unwrap();
    let mut req = request();
    req.authority = record;
    assert!(
        memory
            .plan_emergency_reschedule(&req, &calendars(), NOW)
            .unwrap()
            .plans
            .is_empty()
    );
    req.owner_ref = id(0x61);
    assert!(
        memory
            .plan_emergency_reschedule(&req, &calendars(), NOW)
            .is_err()
    );
}
#[test]
fn sequence_overflow_and_same_sequence_content_conflict_refuse_without_effects() {
    let (_dir, vault, _, plan) = executable(EmergencyActionPolicy::Cancel);
    let mut forged = plan.clone();
    forged.payload.as_mut().unwrap().ics_blob_ref = "blob:changed".to_owned();
    forged.content_hash = forged.hash().unwrap();
    let before = (meta(&vault), entities(&vault));
    let mut sink = spy(&vault, &plan);
    assert!(
        execute_emergency_plan(
            &vault,
            &plan.request,
            &forged,
            &calendars(),
            &consumer(&vault, NOW),
            &mut sink
        )
        .is_err()
    );
    assert_eq!((meta(&vault), entities(&vault)), before);
    assert!(sink.calls.is_empty());
    let mut exhausted = plan.booking.clone();
    exhausted.calendar.sequence = u32::MAX;
    assert!(
        plan_item(&vault, &plan.request, exhausted, &calendars(), NOW)
            .unwrap_err()
            .to_string()
            .contains("exhausted")
    );
    assert_eq!((meta(&vault), entities(&vault)), before);
}

#[test]
fn changed_blob_head_refuses_before_lifecycle_or_intent_writes() {
    let (_dir, vault, _, plan) = executable(EmergencyActionPolicy::Cancel);
    let artifact = EntityId::from_hex(
        plan.payload
            .as_ref()
            .unwrap()
            .ics_blob_ref
            .strip_prefix("blob:")
            .unwrap(),
    )
    .unwrap();
    vault
        .append_blob_artifact_version(
            &artifact,
            b"different content",
            &crate::blob_artifact::BlobVersionProvenance::UserUpload,
            crate::write_envelope::WriteActor::new(id(OWNER), crate::edge::EdgeActorClass::Human),
            TimeRange {
                start: NOW,
                end: NOW,
            },
            NOW,
        )
        .unwrap();
    let before = (meta(&vault), entities(&vault));
    let mut sink = spy(&vault, &plan);
    assert!(execute(&vault, &plan, &mut sink, NOW).is_err());
    assert_eq!((meta(&vault), entities(&vault)), before);
    assert!(checkpoint(&vault, &plan).is_none());
    assert!(sink.calls.is_empty());
    assert!(emergency_records(&vault).is_empty());
}

#[test]
fn original_host_context_is_not_replaced_by_mutable_routing_membership() {
    let (_dir, vault) = open_test_vault_with(VaultConfig::default());
    page(&vault, PAGE, OWNER);
    let receipt = book(&vault, PAGE, NOW + 3_600);
    let req = logged(&vault);
    let original = enumerate_affected_bookings(&vault, &req, NOW).unwrap();
    assert_eq!(original.len(), 1);
    // A second live config is ambiguous, so consulting today's routing
    // would either fail or adopt the stranger. Enumeration uses neither.
    page(&vault, PAGE, 0x61);
    let rows = enumerate_affected_bookings(&vault, &req, NOW).unwrap();
    assert_eq!(rows, original);
    assert_eq!(rows[0].calendar.event_ref, receipt.calendar.event_ref);
    let other = append_owner_instruction(
        &vault,
        id(0x61),
        req.affected_window,
        &req.reason,
        req.action_policy,
        NOW,
    )
    .unwrap();
    let mut stranger = req;
    stranger.owner_ref = id(0x61);
    stranger.authority = other;
    assert!(
        enumerate_affected_bookings(&vault, &stranger, NOW)
            .unwrap()
            .is_empty()
    );
}
