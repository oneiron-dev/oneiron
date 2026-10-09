use super::*;
use crate::booking::{BookingSolver, SlotHostBinding, VaultActiveHoldSource};

const OTHER: u8 = 0x61;

fn replace_config(vault: &Vault, config: EventTypeConfig) {
    let old: Vec<_> = vault
        .claims_for_subject(&id(PAGE))
        .unwrap()
        .into_iter()
        .filter(|claim| {
            vault.get_claim(claim).unwrap().is_some_and(|body| {
                body.predicate == BOOKING_EVENT_TYPE_PREDICATE && claim_surfaceable(&body)
            })
        })
        .collect();
    let next = EntityId::now();
    let body = ClaimBody::new(
        BOOKING_EVENT_TYPE_PREDICATE,
        ClaimSubject::Entity(id(PAGE)),
        encode_event_type_claim_value(&BookingEventTypeClaimValue {
            schema_version: BOOKING_EVENT_TYPE_SCHEMA_VERSION,
            page_ref: id(PAGE),
            config,
        })
        .unwrap(),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )
    .unwrap();
    vault
        .put_claim(
            &next,
            &body,
            TimeRange {
                start: NOW,
                end: NOW,
            },
            NOW,
        )
        .unwrap();
    for prior in old {
        vault.supersede_claim(&next, &prior, NOW).unwrap();
    }
}

fn host_calendars() -> Vec<(EntityId, Vec<crate::calendar::query::CalendarSel>)> {
    [OWNER, OTHER]
        .into_iter()
        .map(|host| {
            (
                id(host),
                vec![crate::calendar::query::CalendarSel { system: None }],
            )
        })
        .collect()
}

fn two_host_page(vault: &Vault, routing: RoutingMode, first_available: bool) -> EventTypeConfig {
    page(vault, PAGE, OWNER);
    vault
        .put_entity(
            &id(OTHER),
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"other host",
        )
        .unwrap();
    let mut config = crate::booking::config::load_event_type_config(
        vault,
        id(PAGE),
        &EventTypeKey("intro".to_owned()),
    )
    .unwrap();
    let mut second = config.hosts[0].clone();
    second.host_ref = id(OTHER);
    second.calendar_refs = vec![id(OTHER)];
    if !first_available {
        config.hosts[0].working_hours[0].end_minute = 30;
    }
    config.hosts.push(second);
    config.routing = routing;
    replace_config(vault, config.clone());
    config
}

fn confirm_with_real_solver(vault: &Vault) -> (ConfirmReceipt, SolveResult) {
    confirm_with_real_solver_in_zone(vault, "UTC")
}

fn confirm_with_real_solver_in_zone(
    vault: &Vault,
    visitor_zone: &str,
) -> (ConfirmReceipt, SolveResult) {
    vault
        .put_entity(
            &id(0x53),
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"booker@example.test",
        )
        .unwrap();
    let session = SessionKey::derive(EntityId::now().as_bytes());
    let slot = TimeRange {
        start: NOW + 3_600,
        end: NOW + 5_400,
    };
    let held = run(
        vault,
        BookingVerbRequest::Hold(HoldSpec {
            page_ref: id(PAGE),
            event_type: EventTypeKey("intro".to_owned()),
            slot,
            session_key: session,
            visitor_tz: visitor_zone.to_owned(),
            constraint: None,
            lease: HoldLeaseSpec::Ordinary,
            idempotency_key: None,
        }),
        slot,
    );
    let BookingVerbReceipt::Held(held) = held else {
        panic!("not held")
    };
    let calendars = host_calendars();
    let holds = VaultActiveHoldSource::excluding(vault, session);
    let solver = BookingSolver {
        vault,
        page_ref: id(PAGE),
        calendars_by_host: &calendars,
        holds: &holds,
        now_utc: NOW,
        synthetic_config: None,
    };
    let solved = solver
        .solve(&SolveRequest {
            event_type: EventTypeKey("intro".to_owned()),
            window: TimeRange {
                start: slot.start,
                end: slot.end - 1,
            },
            constraint: None,
            visitor_tz: visitor_zone.to_owned(),
        })
        .unwrap();
    assert!(
        solved
            .slots
            .iter()
            .any(|value| value.start_utc == slot.start && value.end_utc == slot.end)
    );
    enqueue_booking_verb(
        vault,
        BookingVerbRequest::Confirm(ConfirmSpec {
            hold_token: held.token,
            session_key: session,
            booker_contact: id(0x53),
            intake: Vec::new(),
            idempotency_key: None,
        }),
        NOW,
    )
    .unwrap();
    let turn = run_booking_lifecycle_once(
        vault,
        |_| {
            Ok(BookingSolver {
                vault,
                page_ref: id(PAGE),
                calendars_by_host: &calendars,
                holds: &holds,
                now_utc: NOW,
                synthetic_config: None,
            })
        },
        &consumer(vault, NOW),
    )
    .unwrap();
    let BookingLifecycleTurn::Executed(BookingVerbReceipt::Confirmed(receipt)) = turn else {
        panic!("not confirmed: {turn:?}")
    };
    (receipt, solved)
}

fn request_as(vault: &Vault, owner: u8) -> EmergencyRescheduleRequest {
    let mut req = request();
    req.owner_ref = id(owner);
    req.authority = append_owner_instruction(
        vault,
        req.owner_ref,
        req.affected_window,
        &req.reason,
        req.action_policy,
        NOW,
    )
    .unwrap();
    req
}

fn bind_delivery(vault: &Vault, _event: EntityId, owner: u8) {
    use crate::channel_identity::{ChannelIdentityBinding, ChannelIdentityState, SelfHeldShape};
    let identity = crate::test_util::self_held_identity_in_state(
        "email",
        "host@example.test",
        SelfHeldShape::DedicatedAddress,
        ChannelIdentityBinding::agent(id(owner)),
        ChannelIdentityState::Active,
        NOW,
    );
    vault.create_channel_identity(&id(0x79), &identity).unwrap();
}

#[test]
fn either_confirmation_persists_the_host_that_actually_offered_the_slot() {
    let (_dir, vault) = open_test_vault_with(VaultConfig::default());
    let mut config = two_host_page(&vault, RoutingMode::Either, false);
    let (receipt, solved) = confirm_with_real_solver(&vault);
    assert_eq!(
        solved.host_bindings,
        vec![SlotHostBinding {
            start_utc: NOW + 3_600,
            end_utc: NOW + 5_400,
            host_refs: vec![id(OTHER).to_hex()],
            host_zones: vec!["UTC".to_owned()],
        }]
    );
    let context = crate::booking::lifecycle::booking_confirmation_context(
        &vault,
        &receipt.calendar.event_ref,
    )
    .unwrap()
    .unwrap();
    assert_eq!(context.owner_refs, vec![id(OTHER).to_hex()]);
    let owner = request_as(&vault, OTHER);
    let before = enumerate_affected_bookings(&vault, &owner, NOW).unwrap();
    assert_eq!(before.len(), 1);
    // Both hosts are now available and the routing mode/order also changes.
    // None of those changes may transfer this already-confirmed booking.
    config.hosts[0].working_hours[0].end_minute = 1440;
    config.hosts.reverse();
    config.routing = RoutingMode::Both;
    replace_config(&vault, config);
    assert_eq!(
        enumerate_affected_bookings(&vault, &owner, NOW).unwrap(),
        before
    );
    bind_delivery(&vault, receipt.calendar.event_ref, OTHER);
    let batch = plan_emergency_reschedule(&vault, &owner, &host_calendars(), NOW).unwrap();
    assert!(batch.refusals.is_empty(), "{:?}", batch.refusals);
    assert_eq!(batch.plans.len(), 1);
    assert_eq!(
        batch.plans[0].booking.context.owner_refs,
        vec![id(OTHER).to_hex()]
    );
    for proposal in &batch.plans[0].proposals {
        let result = solve_live(
            &vault,
            &before[0],
            &host_calendars(),
            TimeRange {
                start: proposal.start_utc,
                end: proposal.end_utc - 1,
            },
            NOW,
        )
        .unwrap();
        assert!(
            result
                .host_bindings
                .iter()
                .all(|binding| binding.host_refs == vec![id(OTHER).to_hex()])
        );
        assert!(!result.host_bindings.is_empty());
    }
    let non_owner = request_as(&vault, OWNER);
    assert!(
        enumerate_affected_bookings(&vault, &non_owner, NOW)
            .unwrap()
            .is_empty()
    );
    assert!(
        plan_emergency_reschedule(&vault, &non_owner, &host_calendars(), NOW)
            .unwrap()
            .plans
            .is_empty()
    );
    let mut sink = spy(&vault, &batch.plans[0]);
    let unchanged = (meta(&vault), entities(&vault));
    assert!(
        execute_emergency_plan(
            &vault,
            &non_owner,
            &batch.plans[0],
            &host_calendars(),
            &consumer(&vault, NOW),
            &mut sink
        )
        .is_err()
    );
    assert!(sink.calls.is_empty());
    assert_eq!((meta(&vault), entities(&vault)), unchanged);
}

#[test]
fn removing_selected_host_refuses_planning_instead_of_assigning_another_owner() {
    let (_dir, vault) = open_test_vault_with(VaultConfig::default());
    let mut config = two_host_page(&vault, RoutingMode::Either, false);
    let (receipt, _) = confirm_with_real_solver(&vault);
    config.hosts.retain(|host| host.host_ref == id(OWNER));
    config.hosts[0].working_hours[0].end_minute = 1440;
    replace_config(&vault, config);
    let owner = request_as(&vault, OTHER);
    let batch = plan_emergency_reschedule(&vault, &owner, &host_calendars(), NOW).unwrap();
    assert!(batch.plans.is_empty());
    assert_eq!(batch.refusals.len(), 1);
    assert_eq!(batch.refusals[0].0, receipt.calendar.event_ref);
    assert!(
        batch.refusals[0]
            .1
            .contains("original hosts are unavailable")
    );
    assert!(
        enumerate_affected_bookings(&vault, &request_as(&vault, OWNER), NOW)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn confirmation_refuses_missing_or_competing_host_bindings_without_guessing_config() {
    struct InvalidBindingOracle(bool);
    impl SlotOracle for InvalidBindingOracle {
        fn solve(&self, request: &SolveRequest) -> Result<SolveResult, BookingError> {
            let mut solved = Offered(
                TimeRange {
                    start: NOW + 3_600,
                    end: NOW + 5_400,
                },
                OWNER,
            )
            .solve(request)?;
            if self.0 {
                solved.host_bindings.push(solved.host_bindings[0].clone());
            } else {
                solved.host_bindings.clear();
            }
            Ok(solved)
        }
    }
    for duplicate in [false, true] {
        let (_dir, vault) = open_test_vault_with(VaultConfig::default());
        page(&vault, PAGE, OWNER);
        vault
            .put_entity(
                &id(0x53),
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"booker@example.test",
            )
            .unwrap();
        let slot = TimeRange {
            start: NOW + 3_600,
            end: NOW + 5_400,
        };
        let session = SessionKey::derive(EntityId::now().as_bytes());
        let held = run(
            &vault,
            BookingVerbRequest::Hold(HoldSpec {
                page_ref: id(PAGE),
                event_type: EventTypeKey("intro".to_owned()),
                slot,
                session_key: session,
                visitor_tz: "UTC".to_owned(),
                constraint: None,
                lease: HoldLeaseSpec::Ordinary,
                idempotency_key: None,
            }),
            slot,
        );
        let BookingVerbReceipt::Held(held) = held else {
            panic!("not held")
        };
        enqueue_booking_verb(
            &vault,
            BookingVerbRequest::Confirm(ConfirmSpec {
                hold_token: held.token,
                session_key: session,
                booker_contact: id(0x53),
                intake: Vec::new(),
                idempotency_key: None,
            }),
            NOW,
        )
        .unwrap();
        let error = run_booking_lifecycle_once(
            &vault,
            |_| Ok(InvalidBindingOracle(duplicate)),
            &consumer(&vault, NOW),
        )
        .unwrap_err();
        assert!(error.to_string().contains("bind"));
        assert!(
            vault
                .entities_by_type(crate::registry::ENTITY_TYPE_EVENT)
                .unwrap()
                .is_empty()
        );
    }
}

#[test]
fn ordinary_reschedule_rechecks_only_confirmation_bound_hosts() {
    for routing in [RoutingMode::Either, RoutingMode::Both] {
        let (_dir, vault) = open_test_vault_with(VaultConfig::default());
        let mut config = two_host_page(&vault, routing, true);
        let (receipt, _) = confirm_with_real_solver(&vault);
        let original = crate::booking::lifecycle::booking_confirmation_context(
            &vault,
            &receipt.calendar.event_ref,
        )
        .unwrap();
        config.hosts[0].working_hours[0].end_minute = 30;
        replace_config(&vault, config);
        let calendars = host_calendars();
        let holds = VaultActiveHoldSource::new(&vault);
        let solver = BookingSolver {
            vault: &vault,
            page_ref: id(PAGE),
            calendars_by_host: &calendars,
            holds: &holds,
            now_utc: NOW,
            synthetic_config: None,
        };
        let target = TimeRange {
            start: NOW + 7_200,
            end: NOW + 9_000,
        };
        assert!(
            crate::booking::lifecycle::execute_reschedule(
                &vault,
                &solver,
                &crate::booking::RescheduleSpec {
                    token: receipt.reschedule_token,
                    new_slot: target,
                    visitor_tz: "UTC".to_owned(),
                    constraint: None,
                    idempotency_key: None
                },
                NOW,
                None
            )
            .is_err()
        );
        assert_eq!(
            crate::booking::lifecycle::booking_confirmation_context(
                &vault,
                &receipt.calendar.event_ref
            )
            .unwrap(),
            original
        );
    }
}

#[test]
fn both_secondary_owner_and_rotated_sender_keep_the_actual_initial_organizer() {
    use crate::channel_identity::{
        ChannelIdentityBinding, ChannelIdentityState, ChannelIdentityStep, SelfHeldShape,
    };
    let (_dir, vault) = open_test_vault_with(VaultConfig::default());
    two_host_page(&vault, RoutingMode::Both, true);
    let (receipt, _) = confirm_with_real_solver(&vault);
    bind_delivery(&vault, receipt.calendar.event_ref, OWNER);
    policy(&vault);
    crate::booking::mint_publish_page_invite_grant(
        &vault,
        &crate::booking::PublishBookingPageGrantRequest {
            page_ref: id(PAGE),
            publisher_principal: id(OWNER),
            issued_at: NOW,
        },
    )
    .unwrap();
    crate::booking::invite_grant::dispatch_confirm_booking_invite(
        &vault,
        id(OWNER),
        &receipt,
        &mut Delivered,
        NOW,
    )
    .unwrap();
    vault
        .step_channel_identity(&id(0x79), ChannelIdentityStep::Rotate, NOW + 1)
        .unwrap();
    let rotated = crate::test_util::self_held_identity_in_state(
        "email",
        "rotated@example.test",
        SelfHeldShape::DedicatedAddress,
        ChannelIdentityBinding::agent(id(OWNER)),
        ChannelIdentityState::Active,
        NOW + 1,
    );
    vault.create_channel_identity(&id(0x7d), &rotated).unwrap();
    let batch = plan_emergency_reschedule(
        &vault,
        &request_as(&vault, OTHER),
        &host_calendars(),
        NOW + 1,
    )
    .unwrap();
    assert!(batch.refusals.is_empty(), "{:?}", batch.refusals);
    let plan = &batch.plans[0];
    let ics = crate::calendar::read_calendar_invite_ics(&vault, plan.payload().unwrap()).unwrap();
    assert_eq!(
        crate::calendar::ics::invite_organizer(&ics).unwrap(),
        "host@example.test"
    );
    assert_eq!(plan.organizer, "host@example.test");
}

#[test]
fn confirmation_freezes_both_party_zones_and_emits_them_after_config_changes() {
    let (_dir, vault) = open_test_vault_with(VaultConfig::default());
    let mut config = two_host_page(&vault, RoutingMode::Either, false);
    config.hosts[0].host_tz = "America/New_York".to_owned();
    config.hosts[1].host_tz = "Europe/London".to_owned();
    replace_config(&vault, config.clone());
    let (receipt, solved) = confirm_with_real_solver_in_zone(&vault, "Asia/Tokyo");
    assert_eq!(solved.host_bindings[0].host_zones, vec!["Europe/London"]);
    let context = crate::booking::lifecycle::booking_confirmation_context(
        &vault,
        &receipt.calendar.event_ref,
    )
    .unwrap()
    .unwrap();
    assert_eq!(context.owner_refs, vec![id(OTHER).to_hex()]);
    assert_eq!(context.host_zones, vec!["Europe/London"]);
    assert_eq!(context.visitor_tz, "Asia/Tokyo");

    // The page has changed, but this booking's invite still uses the zones
    // selected by the confirmation's solver, not current config or UTC.
    config.hosts[1].host_tz = "America/Los_Angeles".to_owned();
    replace_config(&vault, config);
    bind_delivery(&vault, receipt.calendar.event_ref, OWNER);
    policy(&vault);
    crate::booking::mint_publish_page_invite_grant(
        &vault,
        &crate::booking::PublishBookingPageGrantRequest {
            page_ref: id(PAGE),
            publisher_principal: id(OWNER),
            issued_at: NOW,
        },
    )
    .unwrap();
    let intent = crate::booking::invite_grant::dispatch_confirm_booking_invite(
        &vault,
        id(OWNER),
        &receipt,
        &mut Delivered,
        NOW,
    )
    .unwrap();
    assert_eq!(
        crate::booking::invite_grant::dispatch_confirm_booking_invite(
            &vault,
            id(OWNER),
            &receipt,
            &mut Delivered,
            NOW,
        )
        .unwrap(),
        intent,
        "a retry keeps the one frozen invite and its original party zones"
    );
    let listing = crate::outbound_intent_ledger::intent_ledger_records(&vault).unwrap();
    let row = listing.records.iter().find(|row| row.id == intent).unwrap();
    let frozen = crate::calendar::decode_frozen_calendar_invite(row.payload()).unwrap();
    let blob = EntityId::from_hex(frozen.ics_blob_ref.strip_prefix("blob:").unwrap()).unwrap();
    let head = vault.blob_artifact_head(&blob).unwrap().unwrap();
    let ics = String::from_utf8(
        vault
            .read_blob_artifact_version(&blob, head.version)
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert!(ics.contains("X-WR-TIMEZONE:Asia/Tokyo\r\n"));
    assert!(ics.contains("X-ONEIRON-TZID:Asia/Tokyo\r\n"));
    assert!(ics.contains("X-ONEIRON-ORGANIZER-TZID:Europe/London\r\n"));
    assert!(!ics.contains("X-ONEIRON-ORGANIZER-TZID:America/Los_Angeles"));
    assert!(ics.contains("DTSTART:") && ics.contains("Z\r\n"));
}
