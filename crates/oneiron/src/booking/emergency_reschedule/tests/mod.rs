use super::*;
use crate::booking::{
    BOOKING_EVENT_TYPE_PREDICATE, BOOKING_EVENT_TYPE_SCHEMA_VERSION, BookingEventTypeClaimValue,
    BookingLifecycleConsumerInput, BookingLifecycleTurn, BookingVerbReceipt, BookingVerbRequest,
    CancelSpec, ConfirmReceipt, ConfirmSpec, EventTypeConfig, HoldLeaseSpec, HoldSpec,
    HostAvailabilityConfig, RankedSlot, RoutingMode, SessionKey, SlotOracle, SolveRequest,
    SolveResult, WeeklyWallWindow, encode_event_type_claim_value, enqueue_booking_verb,
    run_booking_lifecycle_once,
};
use crate::calendar::outcome::{EventOutcome, project_event_outcome, read_event_outcome};
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus};
use crate::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_PERSON};
use crate::test_util::{entity as id, open_test_vault_with};
use crate::{DreamerRunnerStore, VaultConfig};

const NOW: u64 = 1_772_409_600;
const OWNER: u8 = 0x51;
const PAGE: u8 = 0x52;

fn request() -> EmergencyRescheduleRequest {
    let window = TimeRange {
        start: NOW + 3_600,
        end: NOW + 10_799,
    };
    EmergencyRescheduleRequest {
        owner_ref: id(OWNER),
        affected_window: window,
        reason: "unavailable".to_owned(),
        action_policy: EmergencyActionPolicy::Cancel,
        authority: OwnerInstructionRecord {
            owner_ref: id(OWNER),
            request_hash: canonical_emergency_request_hash(
                window,
                "unavailable",
                EmergencyActionPolicy::Cancel,
            )
            .unwrap(),
            recorded_at: NOW,
        },
    }
}

fn logged(vault: &Vault) -> EmergencyRescheduleRequest {
    let mut req = request();
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

fn meta(vault: &Vault) -> Vec<(Vec<u8>, Vec<u8>)> {
    let rtxn = vault.store.env.read_txn().unwrap();
    vault
        .store
        .vault_meta
        .iter(&rtxn)
        .unwrap()
        .map(|row| {
            let (key, value) = row.unwrap();
            (key.to_vec(), value.to_vec())
        })
        .collect()
}

fn entities(vault: &Vault) -> Vec<(Vec<u8>, Vec<u8>)> {
    let rtxn = vault.store.env.read_txn().unwrap();
    vault
        .store
        .entities
        .iter(&rtxn)
        .unwrap()
        .map(|row| {
            let (key, value) = row.unwrap();
            (key.to_vec(), value.to_vec())
        })
        .collect()
}

// Only the availability answer is a fixture. EVENT, lifecycle status,
// tokens, passport, receipts, and home-node attempts use the real writer.
struct Offered(TimeRange, u8);
impl SlotOracle for Offered {
    fn solve(&self, _: &SolveRequest) -> Result<SolveResult, BookingError> {
        Ok(SolveResult {
            slots: vec![RankedSlot {
                start_utc: self.0.start,
                end_utc: self.0.end,
                rank: 1.0,
            }],
            flex_used: false,
            host_bindings: vec![crate::booking::SlotHostBinding {
                start_utc: self.0.start,
                end_utc: self.0.end,
                host_refs: vec![id(self.1).to_hex()],
            }],
        })
    }
}

fn run(vault: &Vault, request: BookingVerbRequest, slot: TimeRange) -> BookingVerbReceipt {
    run_as(vault, request, slot, OWNER)
}

fn run_as(
    vault: &Vault,
    request: BookingVerbRequest,
    slot: TimeRange,
    host: u8,
) -> BookingVerbReceipt {
    enqueue_booking_verb(vault, request, NOW).unwrap();
    match run_booking_lifecycle_once(vault, |_| Ok(Offered(slot, host)), &consumer(vault, NOW))
        .unwrap()
    {
        BookingLifecycleTurn::Executed(receipt) => receipt,
        other => panic!("home node did not execute: {other:?}"),
    }
}

fn page(vault: &Vault, page_seed: u8, host_seed: u8) {
    for (entity, kind) in [
        (id(page_seed), ENTITY_TYPE_ASSET),
        (id(host_seed), ENTITY_TYPE_PERSON),
    ] {
        vault
            .put_entity(&entity, kind, TimeRange { start: 1, end: 1 }, 1, b"fixture")
            .unwrap();
    }
    let config = EventTypeConfig {
        key: EventTypeKey("intro".to_owned()),
        duration_min: 30,
        slot_step_min: 30,
        pre_buffer_min: 0,
        post_buffer_min: 0,
        min_notice_secs: 0,
        booking_window_secs: 86_400,
        daily_cap: None,
        weekly_cap: None,
        routing: RoutingMode::Either,
        hosts: vec![HostAvailabilityConfig {
            host_ref: id(host_seed),
            calendar_refs: vec![id(host_seed)],
            host_tz: "UTC".to_owned(),
            working_hours: vec![WeeklyWallWindow {
                weekday: 0,
                start_minute: 0,
                end_minute: 1440,
            }],
            preferred_hours: Vec::new(),
        }],
        flex_windows: Vec::new(),
    };
    let body = ClaimBody::new(
        BOOKING_EVENT_TYPE_PREDICATE,
        ClaimSubject::Entity(id(page_seed)),
        encode_event_type_claim_value(&BookingEventTypeClaimValue {
            schema_version: BOOKING_EVENT_TYPE_SCHEMA_VERSION,
            page_ref: id(page_seed),
            config,
        })
        .unwrap(),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    vault
        .put_claim(&EntityId::now(), &body, TimeRange { start: 1, end: 1 }, 1)
        .unwrap();
    DreamerRunnerStore::new(vault)
        .elect_home_node(
            &[DreamerRunnerStore::new(vault)
                .local_home_node_candidate(true, true, true)
                .unwrap()],
            1,
        )
        .unwrap();
}

fn book(vault: &Vault, page_seed: u8, start: u64) -> ConfirmReceipt {
    book_as(vault, page_seed, start, OWNER)
}

fn book_as(vault: &Vault, page_seed: u8, start: u64, host: u8) -> ConfirmReceipt {
    if vault.get_entity_type(&id(0x53)).unwrap().is_none() {
        vault
            .put_entity(
                &id(0x53),
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"booker@example.test",
            )
            .unwrap();
    }
    let slot = TimeRange {
        start,
        end: start + 1_800,
    };
    let session = SessionKey::derive(EntityId::now().as_bytes());
    let held = run(
        vault,
        BookingVerbRequest::Hold(HoldSpec {
            page_ref: id(page_seed),
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
    let confirmed = run_as(
        vault,
        BookingVerbRequest::Confirm(ConfirmSpec {
            hold_token: held.token,
            session_key: session,
            booker_contact: id(0x53),
            idempotency_key: None,
        }),
        slot,
        host,
    );
    let BookingVerbReceipt::Confirmed(confirmed) = confirmed else {
        panic!("not confirmed")
    };
    confirmed
}

fn policy(vault: &Vault) {
    let bytes = rmp_serde::to_vec_named(&serde_json::json!({
        "schema_version": "1.1", "pack_id": "emergency-tests", "pack_version": "v1",
        "min_engine_version": env!("CARGO_PKG_VERSION"),
        "defaults": { "criticality": "normal", "sensitivity": "normal" }, "rules": [],
        "actor_ceilings": [ { "actor_class": "agent", "actor_ref": id(OWNER).to_hex(), "ceiling": "auto" },
            { "actor_class": "first_party", "ceiling": "auto" }, { "actor_class": "human", "ceiling": "auto" } ],
        "scoped_grants": [ { "actor_ref": id(OWNER).to_hex(), "effector": "external:calendar.invite", "scope": { "channel": "calendar" } },
            { "actor_ref": id(OWNER).to_hex(), "effector": "external:send", "scope": { "channel": "email" } } ]
    })).unwrap();
    crate::test_util::put_policy_manifest_bytes(vault, id(0x7a), &bytes).unwrap();
}

fn consumer(vault: &Vault, now_utc: u64) -> BookingLifecycleConsumerInput {
    BookingLifecycleConsumerInput {
        local_node_id: crate::identity::load_or_mint_client_id(vault).unwrap(),
        lease_owner: "emergency-test".to_owned(),
        now_utc,
    }
}
fn calendars() -> Vec<(EntityId, Vec<crate::calendar::query::CalendarSel>)> {
    vec![(
        id(OWNER),
        vec![crate::calendar::query::CalendarSel { system: None }],
    )]
}
fn checkpoint(vault: &Vault, plan: &EmergencyPlan) -> Option<EmergencyItem> {
    let txn = vault.store.env.read_txn().unwrap();
    read_item_in(
        vault,
        &txn,
        &item_key(&plan.request, plan.booking.calendar.event_ref).unwrap(),
    )
    .unwrap()
}
fn passports(vault: &Vault, event: EntityId) -> Vec<crate::calendar::CalendarPassportValue> {
    live_passports_for_event(vault, &event)
        .unwrap()
        .into_iter()
        .map(|(_, value)| value)
        .collect()
}

fn executable(
    action_policy: EmergencyActionPolicy,
) -> (tempfile::TempDir, Vault, ConfirmReceipt, EmergencyPlan) {
    executable_with_invite(action_policy, true)
}

struct Delivered;
impl crate::outbound::OutboundExecutionSink for Delivered {
    fn execute(
        &mut self,
        _: &crate::outbound::OutboundExecutionRequest<'_>,
    ) -> crate::outbound::OutboundExecutionOutcome {
        crate::outbound::OutboundExecutionOutcome::delivered_to_channel("delivered")
    }
}

fn executable_with_invite(
    action_policy: EmergencyActionPolicy,
    send_initial: bool,
) -> (tempfile::TempDir, Vault, ConfirmReceipt, EmergencyPlan) {
    use crate::channel_identity::{
        ChannelIdentity, ChannelIdentityBinding, ChannelIdentityState, SelfHeldShape,
    };
    let (dir, vault) = open_test_vault_with(VaultConfig::default());
    page(&vault, PAGE, OWNER);
    let receipt = book(&vault, PAGE, NOW + 3_600);
    let mut identity = ChannelIdentity::requested(
        "email",
        "host@example.test",
        SelfHeldShape::DedicatedAddress,
        ChannelIdentityBinding::agent(id(OWNER)),
        NOW,
    );
    identity.state = ChannelIdentityState::Active;
    vault.create_channel_identity(&id(0x79), &identity).unwrap();
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
    if send_initial {
        crate::booking::invite_grant::dispatch_confirm_booking_invite(
            &vault,
            id(OWNER),
            &receipt,
            &mut Delivered,
            NOW,
        )
        .unwrap();
    }
    let mut req = request();
    req.action_policy = action_policy;
    let memory = vault.memory(id(OWNER), crate::edge::EdgeActorClass::Human);
    req.authority = memory
        .record_emergency_instruction(&crate::memory::EmergencyInstructionInput {
            affected_window: crate::calendar::query::CalendarRangeDto {
                start: req.affected_window.start,
                end: req.affected_window.end,
            },
            reason: req.reason.clone(),
            action_policy,
            recorded_at: NOW,
        })
        .unwrap();
    let batch = plan_emergency_reschedule(&vault, &req, &calendars(), NOW).unwrap();
    assert!(batch.refusals.is_empty(), "{:?}", batch.refusals);
    assert_eq!(batch.plans.len(), 1);
    (dir, vault, receipt, batch.plans.into_iter().next().unwrap())
}

struct EffectSpy<'a> {
    vault: &'a Vault,
    plan: &'a EmergencyPlan,
    fail_channel: Option<&'static str>,
    calls: Vec<(String, Vec<u8>)>,
}
impl crate::outbound::OutboundExecutionSink for EffectSpy<'_> {
    fn execute(
        &mut self,
        request: &crate::outbound::OutboundExecutionRequest<'_>,
    ) -> crate::outbound::OutboundExecutionOutcome {
        let item =
            checkpoint(self.vault, self.plan).expect("checkpoint is committed before any effect");
        assert_eq!(
            item.calendar.sequence,
            self.plan.booking.calendar.sequence + 1
        );
        let (revision, payload) = item
            .picked
            .as_ref()
            .map_or((&item.calendar, self.plan.payload.as_ref()), |picked| {
                (&picked.calendar, Some(&picked.payload))
            });
        let heads = passports(self.vault, item.calendar.event_ref);
        assert!(
            heads
                .iter()
                .any(|head| head.system == BOOKING_PASSPORT_SYSTEM
                    && head.last_sequence == revision.sequence)
        );
        if let Some(payload) = payload {
            assert!(heads.iter().any(|head| head.system
                == crate::calendar::CALENDAR_INVITE_PASSPORT_SYSTEM
                && head.last_sequence == payload.sequence));
        }
        let records = crate::outbound_intent_ledger::intent_ledger_records(self.vault).unwrap();
        let frozen = records
            .iter()
            .find(|record| {
                let value: serde_json::Value = serde_json::from_slice(record.payload()).unwrap();
                value["idempotency_key"].as_str() == Some(request.intent_ref)
            })
            .expect("intent is logged before this external effect");
        if let Some(part) = &request.calendar_invite {
            assert_eq!(
                part.ics,
                crate::calendar::read_calendar_invite_ics(self.vault, payload.unwrap()).unwrap()
            );
            assert!(part.content_type.starts_with("text/calendar; method="));
        }
        self.calls
            .push((request.intent.channel.clone(), frozen.payload().to_vec()));
        if self.fail_channel == Some(request.intent.channel.as_str()) {
            self.fail_channel = None;
            crate::outbound::OutboundExecutionOutcome::failed("definite fixture non-delivery")
        } else {
            crate::outbound::OutboundExecutionOutcome::delivered_to_channel("fixture-delivery")
        }
    }
}
fn spy<'a>(vault: &'a Vault, plan: &'a EmergencyPlan) -> EffectSpy<'a> {
    EffectSpy {
        vault,
        plan,
        fail_channel: None,
        calls: Vec::new(),
    }
}
fn execute(
    vault: &Vault,
    plan: &EmergencyPlan,
    spy: &mut EffectSpy<'_>,
    now: u64,
) -> Result<EmergencyItem, BookingError> {
    execute_emergency_plan(
        vault,
        &plan.request,
        plan,
        &calendars(),
        &consumer(vault, now),
        spy,
    )
}

fn emergency_records(vault: &Vault) -> Vec<crate::outbound_intent_ledger::IntentLedgerRecord> {
    crate::outbound_intent_ledger::intent_ledger_records(vault).unwrap().into_iter().filter(|record| {
        serde_json::from_slice::<serde_json::Value>(record.payload()).unwrap()["idempotency_key"]
            .as_str().is_some_and(|key| key.starts_with("intent:booking_emergency:"))
    }).collect()
}

mod calendar_sync;
mod corrections;
mod effects;
mod follow_up;
mod host_binding;
mod instruction;
mod owner_revocation;
