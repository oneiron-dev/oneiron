use super::*;

#[test]
fn normal_unsent_confirmation_uses_no_fake_cancel_and_first_pick_request_zero() {
    for policy in [
        EmergencyActionPolicy::Cancel,
        EmergencyActionPolicy::RequestUpdate,
    ] {
        let (_dir, vault, receipt, plan) = executable_with_invite(policy, false);
        assert!(
            passports(&vault, receipt.calendar.event_ref)
                .iter()
                .all(|head| head.system != crate::calendar::CALENDAR_INVITE_PASSPORT_SYSTEM)
        );
        assert!(
            vault
                .claims_for_subject(&receipt.calendar.event_ref)
                .unwrap()
                .iter()
                .all(|id| {
                    vault.get_claim(id).unwrap().unwrap().predicate
                        != crate::calendar::claims::PREDICATE_CALENDAR_ATTENDEE
                })
        );
        if policy == EmergencyActionPolicy::Cancel {
            assert!(plan.payload().is_none());
        } else {
            assert_eq!(plan.payload().unwrap().sequence, 0);
        }
        let memory = vault.memory(id(OWNER), crate::edge::EdgeActorClass::Human);
        let mut sink = spy(&vault, &plan);
        let item = memory
            .execute_emergency_reschedule(
                &plan.request,
                &plan,
                &calendars(),
                &consumer(&vault, NOW),
                &mut sink,
            )
            .unwrap();
        assert_eq!(
            sink.calls.len(),
            if policy == EmergencyActionPolicy::Cancel {
                1
            } else {
                2
            }
        );
        let picked = memory
            .pick_emergency_reschedule(
                &item.actions[1],
                &calendars(),
                &consumer(&vault, NOW + 1),
                &mut sink,
            )
            .unwrap();
        assert_eq!(
            picked.sequence, 2,
            "booking revision is independent of the CAL invite clock"
        );
        let payload =
            crate::calendar::decode_frozen_calendar_invite(&sink.calls.last().unwrap().1).unwrap();
        assert_eq!(
            payload.sequence,
            if policy == EmergencyActionPolicy::Cancel {
                0
            } else {
                1
            }
        );
        assert!(
            memory
                .plan_emergency_reschedule(&plan.request, &calendars(), NOW + 2)
                .unwrap()
                .plans
                .is_empty()
        );
    }
}

#[test]
fn pending_delivery_fences_ordinary_revision_and_completed_plans_do_not_reappear() {
    let (_dir, vault, receipt, plan) = executable(EmergencyActionPolicy::RequestUpdate);
    let mut sink = spy(&vault, &plan);
    sink.fail_channel = Some("email");
    assert!(execute(&vault, &plan, &mut sink, NOW).is_err());
    assert!(
        crate::booking::lifecycle::execute_cancel(
            &vault,
            &CancelSpec {
                token: receipt.cancel_token.clone(),
                idempotency_key: None,
            },
            NOW + 1
        )
        .is_err()
    );
    let pending = plan_emergency_reschedule(&vault, &plan.request, &calendars(), NOW + 1).unwrap();
    assert_eq!(pending.plans, vec![plan.clone()]);
    execute(&vault, &plan, &mut sink, NOW + 2).unwrap();
    assert!(
        plan_emergency_reschedule(&vault, &plan.request, &calendars(), NOW + 3)
            .unwrap()
            .plans
            .is_empty()
    );
    crate::booking::lifecycle::execute_cancel(
        &vault,
        &CancelSpec {
            token: receipt.cancel_token,
            idempotency_key: None,
        },
        NOW + 3,
    )
    .unwrap();
}

#[test]
fn saved_unapplied_plan_superseded_by_ordinary_cancel_is_not_executable_work() {
    let (_dir, vault, receipt, plan) = executable(EmergencyActionPolicy::Cancel);
    crate::booking::lifecycle::execute_cancel(
        &vault,
        &CancelSpec {
            token: receipt.cancel_token,
            idempotency_key: None,
        },
        NOW,
    )
    .unwrap();
    let batch = plan_emergency_reschedule(&vault, &plan.request, &calendars(), NOW + 1).unwrap();
    assert!(batch.plans.is_empty());
    assert_eq!(batch.refusals.len(), 1);
}

#[test]
fn non_home_instruction_and_lower_planning_doors_leave_all_bytes_unchanged() {
    let (_dir, vault, _, plan) = executable(EmergencyActionPolicy::Cancel);
    let local = consumer(&vault, NOW).local_node_id;
    DreamerRunnerStore::new(&vault)
        .elect_home_node(
            &[crate::DreamerHomeNodeCandidate::always_on_local(
                local.wrapping_add(1).max(1),
            )],
            NOW,
        )
        .unwrap();
    let before = (meta(&vault), entities(&vault));
    let memory = vault.memory(id(OWNER), crate::edge::EdgeActorClass::Human);
    let error = memory
        .record_emergency_instruction(&crate::memory::EmergencyInstructionInput {
            affected_window: crate::calendar::query::CalendarRangeDto {
                start: NOW + 1,
                end: NOW + 2,
            },
            reason: "another instruction".to_owned(),
            action_policy: EmergencyActionPolicy::Cancel,
            recorded_at: NOW,
        })
        .unwrap_err();
    assert_eq!(error.code, crate::memory::MEMORY_CODE_INVALID_STATE);
    assert!(plan_emergency_reschedule(&vault, &plan.request, &calendars(), NOW).is_err());
    assert!(
        plan_item(
            &vault,
            &plan.request,
            plan.booking.clone(),
            &calendars(),
            NOW
        )
        .is_err()
    );
    assert_eq!((meta(&vault), entities(&vault)), before);
}

#[test]
fn exact_booker_not_live_attendee_receives_actions() {
    let (_dir, vault, _, plan) = executable_with_invite(EmergencyActionPolicy::Cancel, false);
    let event = plan.booking.calendar.event_ref;
    vault
        .put_claim(
            &EntityId::now(),
            &ClaimBody::new(
                crate::calendar::claims::PREDICATE_CALENDAR_ATTENDEE,
                ClaimSubject::Entity(event),
                rmpv::Value::Map(vec![
                    ("who".into(), "stranger@example.test".into()),
                    ("role".into(), "REQ-PARTICIPANT".into()),
                    ("partstat".into(), "ACCEPTED".into()),
                ]),
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
    execute(&vault, &plan, &mut sink, NOW).unwrap();
    for (_, bytes) in &sink.calls {
        let frozen: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        assert_eq!(frozen["target"], "booker@example.test");
    }
}

#[test]
fn newer_held_and_no_show_survive_cancel_and_pick_in_the_lifecycle_transaction() {
    use crate::calendar::outcome::{
        EventOutcomeBasis, EventOutcomeClaimValue, record_event_outcome,
    };
    for outcome in [EventOutcome::Held, EventOutcome::NoShow] {
        let (_dir, vault, _, plan) = executable(EmergencyActionPolicy::Cancel);
        let event = plan.booking.calendar.event_ref;
        let value = EventOutcomeClaimValue {
            outcome,
            basis: EventOutcomeBasis::OwnerAttested,
            recorded_at: NOW + 10,
        };
        record_event_outcome(&vault, event, &value, crate::claim::ClaimSource::UserStated).unwrap();
        let item = execute(&vault, &plan, &mut spy(&vault, &plan), NOW).unwrap();
        assert_eq!(read_event_outcome(&vault, event).unwrap(), Some(value));
        counterparty_pick(
            &vault,
            &item.actions[1],
            &calendars(),
            &consumer(&vault, NOW + 1),
            &mut spy(&vault, &plan),
        )
        .unwrap();
        assert_eq!(read_event_outcome(&vault, event).unwrap(), Some(value));
    }
}

#[test]
fn owner_first_enumeration_and_per_item_fact_refusals_do_not_poison_the_batch() {
    let (_dir, vault, _, plan) = executable_with_invite(EmergencyActionPolicy::Cancel, false);
    page(&vault, 0x65, 0x66);
    let other = book_as(&vault, 0x65, NOW + 7_200, 0x66);
    let malformed = book(&vault, PAGE, NOW + 8_000);
    for event in [other.calendar.event_ref, malformed.calendar.event_ref] {
        let value =
            rmp_serde::to_vec_named(&BookingSourcePageValue { page_ref: id(PAGE) }).unwrap();
        let value = rmpv::decode::read_value(&mut std::io::Cursor::new(value)).unwrap();
        vault
            .put_claim(
                &EntityId::now(),
                &ClaimBody::new(
                    BOOKING_SOURCE_PAGE_PREDICATE,
                    ClaimSubject::Entity(event),
                    value,
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
    }
    let mut refusals = Vec::new();
    let rows = enumerate_with_refusals(&vault, &plan.request, NOW, &mut refusals).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].calendar.event_ref, plan.booking.calendar.event_ref);
    assert_eq!(refusals.len(), 1);
    assert_eq!(refusals[0].0, malformed.calendar.event_ref);
}

#[test]
fn memory_error_taxonomy_preserves_storage_state_and_typed_boundary_errors() {
    assert_eq!(
        crate::memory::booking_error(BookingError::SlotOracle("store unavailable".to_owned())).code,
        crate::memory::MEMORY_CODE_INTERNAL
    );
    assert_eq!(
        crate::memory::booking_error(BookingError::InvalidConfig("wrong home".to_owned())).code,
        crate::memory::MEMORY_CODE_INVALID_STATE
    );
    assert_eq!(
        crate::memory::booking_error(BookingError::InvalidConstraint("bad window".to_owned())).code,
        crate::memory::MEMORY_CODE_BAD_REQUEST
    );
    let (_dir, vault, _, _) = executable_with_invite(EmergencyActionPolicy::Cancel, false);
    let denied = vault
        .memory(id(OWNER), crate::edge::EdgeActorClass::Agent)
        .record_emergency_instruction(&crate::memory::EmergencyInstructionInput {
            affected_window: crate::calendar::query::CalendarRangeDto {
                start: NOW,
                end: NOW + 1,
            },
            reason: "unavailable".to_owned(),
            action_policy: EmergencyActionPolicy::Cancel,
            recorded_at: NOW,
        })
        .unwrap_err();
    assert_eq!(
        crate::memory::booking_error(BookingError::Boundary(Box::new(denied.clone()))),
        denied
    );
}

#[test]
fn verified_effect_chokepoint_rejects_deleted_owner_even_on_frozen_pick_retry() {
    for picked in [false, true] {
        let (_dir, vault, _, plan) = executable(EmergencyActionPolicy::Cancel);
        let mut sink = spy(&vault, &plan);
        let item = if picked {
            let item = execute(&vault, &plan, &mut sink, NOW).unwrap();
            sink.fail_channel = Some("calendar");
            assert!(
                counterparty_pick(
                    &vault,
                    &item.actions[1],
                    &calendars(),
                    &consumer(&vault, NOW + 1),
                    &mut sink
                )
                .is_err()
            );
            checkpoint(&vault, &plan).unwrap()
        } else {
            sink.fail_channel = Some("calendar");
            assert!(execute(&vault, &plan, &mut sink, NOW).is_err());
            checkpoint(&vault, &plan).unwrap()
        };
        let frozen = sink.calls.last().unwrap().1.clone();
        assert!(vault.delete_entity(&id(OWNER)).unwrap());
        let txn = vault.store.env.read_txn().unwrap();
        assert!(verify_frozen_effect_in(&vault, &txn, &frozen).is_err());
        drop(txn);
        let count = sink.calls.len();
        let effect = if picked {
            super::super::execution::EmergencyEffect::Pick
        } else {
            super::super::execution::EmergencyEffect::Calendar
        };
        assert!(
            super::super::execution::dispatch_item_effect(
                &vault,
                &item,
                effect,
                &mut sink,
                NOW + 2
            )
            .is_err()
        );
        assert_eq!(sink.calls.len(), count);
    }
}
