use super::*;

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
    assert_eq!(item.calendar.event_ref, plan.booking().calendar.event_ref);
    assert_eq!(item.calendar.sequence, 1);
    assert!(!item.calendar_delivered);
    assert!(!item.apology_delivered);
    let committed_passports = passports(&vault, item.calendar.event_ref);
    assert!(!committed_passports.is_empty());
    assert!(
        committed_passports
            .iter()
            .all(|p| p.last_sequence == item.calendar.sequence)
    );
    assert!(emergency_records(&vault).is_empty());

    let recovered = execute(&vault, &plan, &mut spy(&vault, &plan), NOW).unwrap();
    assert_eq!(recovered.calendar.event_ref, item.calendar.event_ref);
    assert_eq!(recovered.calendar.sequence, item.calendar.sequence);
    assert!(recovered.calendar_delivered);
    assert!(recovered.apology_delivered);
    let recovered_passports = passports(&vault, recovered.calendar.event_ref);
    assert!(!recovered_passports.is_empty());
    assert!(
        recovered_passports
            .iter()
            .all(|p| p.last_sequence == item.calendar.sequence)
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
            NOW,
            None
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
