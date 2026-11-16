//! An emergency item's stored row keeps no usable pick token.
//!
//! Canon ARCH-0062:114: "A booking's stored metadata holds only digests of its
//! hold and checkout tokens, never their usable values". Engine RULING 16 Nov
//! 12:24: "store a digest and compare digests, with a red test (stored row
//! holds no usable token; a pick with the right token still works)". The
//! visitor's pick tokens reach them only inside the apology's blob; the
//! `EMERGENCY_ITEM` side-table row must spell none of them, before the pick
//! and after the pick rewrites that row. The pick with a token from the
//! delivery still moves the booking to that proposal's slot, while an
//! unminted well-formed token and the sibling token after the pick are
//! refused.
//!
//! The fixture is `tests/booking_feed_move_held.rs`'s, without its feed, ICS
//! and held move: the same page, host, booker, event type, lifecycle solver
//! and owner-logged `RequestUpdate` instruction, which owes no calendar
//! effect at commit, planned and executed with a sink that delivers every
//! request. Only public paths, so the base plus this file builds for the red
//! run. At the base the test fails at the first side-table scan, because the
//! item row stores each usable token; at the fixed head it passes.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron --all-features --test booking_emergency_action_digests`.
#![cfg(all(feature = "test-support", oneiron_test_support))]

mod common;

use oneiron::booking::{
    BOOKING_EVENT_TYPE_PREDICATE, BOOKING_EVENT_TYPE_SCHEMA_VERSION, BookingError,
    BookingEventTypeClaimValue, BookingLifecycleConsumerInput, BookingLifecycleTurn, BookingSolver,
    BookingVerbReceipt, BookingVerbRequest, ConfirmReceipt, ConfirmSpec,
    DEFAULT_INTRO_DURATION_MIN, EmergencyActionPolicy, EmergencyPlan, EmergencyRescheduleRequest,
    EventTypeConfig, EventTypeKey, HoldLeaseSpec, HoldReceipt, HoldSpec, HostAvailabilityConfig,
    OpaqueLifecycleToken, PublishBookingPageGrantRequest, RoutingMode, SessionKey, SlotOracle,
    SolveRequest, SolveResult, VaultActiveHoldSource, WeeklyWallWindow, counterparty_pick,
    encode_event_type_claim_value, enqueue_booking_verb, execute_emergency_plan,
    mint_publish_page_invite_grant, plan_emergency_reschedule, run_booking_lifecycle_once,
};
use oneiron::calendar::query::CalendarRangeDto;
use oneiron::channel_identity::{ChannelIdentityBinding, ChannelIdentityState, SelfHeldShape};
use oneiron::memory::EmergencyInstructionInput;
use oneiron::outbound::{
    OutboundExecutionOutcome, OutboundExecutionRequest, OutboundExecutionSink,
};
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_FACET, ENTITY_TYPE_PERSON};
use oneiron::test_doors::booking_side_table_rows::{
    BookingSideTableRow, booking_side_table_names, booking_side_table_rows,
};
use oneiron::{
    CalendarSel, ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject,
    DreamerRunnerStore, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig,
};

/// Monday 2 March 2026, 00:00 UTC.
const MONDAY: u64 = 1_772_409_600;
/// Request time: 08:00Z that Monday.
const NOW: u64 = MONDAY + 8 * 3_600;
/// Pick time: 08:02:30Z that Monday, after the execute, before every proposal.
const PICK_NOW: u64 = NOW + 150;

const PAGE_SEED: u8 = 0x51;
const HOST_SEED: u8 = 0x52;
const BOOKER_SEED: u8 = 0x57;
const BUSY_SEED: u8 = 0x61;
const IDENTITY_SEED: u8 = 0x79;
const POLICY_SEED: u8 = 0x7a;

/// `[seed; 16]`; every seed here is outside the production-pinned id bytes.
fn test_id(seed: u8) -> EntityId {
    common::entity(seed)
}

/// A point in time as an inclusive range.
const fn at(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

/// The engine's inclusive occurrence row for a half-open slot.
const fn inclusive(slot: TimeRange) -> TimeRange {
    TimeRange {
        start: slot.start,
        end: slot.end - 1,
    }
}

/// A slot of the intro call's length starting `hour` on the fixture Monday.
fn slot_at(hour: u64) -> TimeRange {
    let start = MONDAY + hour * 3_600;
    TimeRange {
        start,
        end: start + u64::from(DEFAULT_INTRO_DURATION_MIN) * 60,
    }
}

/// A vault with a booking page, a host, a booker and an elected home node.
struct Fixture {
    /// The temp dir that owns the vault's files.
    _dir: tempfile::TempDir,
    /// The vault under test.
    vault: Vault,
    /// The host issuer that rooted the vault.
    issuer: oneiron::authority::HostSlipIssuer,
    /// The booking page.
    page: EntityId,
    /// The host, who is also the emergency owner.
    host: EntityId,
    /// The booker.
    booker: EntityId,
    /// This install's client id, elected the lifecycle home node.
    node_id: u64,
}

impl Fixture {
    /// Opens a vault with the page, the host, the booker, the page's facet,
    /// the page's event type and an elected home node.
    fn open() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
        // Signing doors load this install's keys from a keystore (P6c).
        vault.install_device_keystore(std::sync::Arc::new(
            oneiron_keystore::MemoryKeystore::default(),
        ));
        let page = test_id(PAGE_SEED);
        let host = test_id(HOST_SEED);
        let booker = test_id(BOOKER_SEED);
        vault
            .put_entity(&page, ENTITY_TYPE_ASSET, at(1), 1, b"booking page")
            .expect("put booking page");
        vault
            .put_entity(&host, ENTITY_TYPE_PERSON, at(1), 1, b"host")
            .expect("put host");
        vault
            .put_entity(
                &booker,
                ENTITY_TYPE_PERSON,
                at(1),
                1,
                b"visitor@example.test",
            )
            .expect("put booker");
        // A raw claim put is born in its subject's substrate FACET, which
        // only a PERSON's put stores, so the birth gate refuses a claim about
        // the page ASSET (InvalidFacet, #4389) until that FACET is stored.
        vault
            .put_entity(
                &oneiron::claim::substrate_facet_id(page).expect("the page's facet id"),
                ENTITY_TYPE_FACET,
                at(1),
                1,
                &rmp_serde::to_vec_named(&serde_json::json!({"name": "booking page facet"}))
                    .expect("facet body"),
            )
            .expect("store the page's facet");
        // The page's event type, which the emergency planner solves its
        // proposals from.
        let event_type_claim = ClaimBody::new(
            BOOKING_EVENT_TYPE_PREDICATE,
            ClaimSubject::Entity(page),
            encode_event_type_claim_value(&BookingEventTypeClaimValue {
                schema_version: BOOKING_EVENT_TYPE_SCHEMA_VERSION,
                page_ref: page,
                config: fixture_config(),
            })
            .expect("encode the event type"),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )
        .expect("event type claim");
        vault
            .put_claim(&EntityId::now(), &event_type_claim, at(1), 1)
            .expect("put the page's event type");
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        let runner = DreamerRunnerStore::new(&vault);
        let local = runner
            .local_home_node_candidate(true, true, true)
            .expect("local home node candidate");
        let node_id = local.node_id;
        runner
            .elect_home_node(&[local], 1)
            .expect("elect home node");
        Self {
            _dir: dir,
            vault,
            issuer,
            page,
            host,
            booker,
            node_id,
        }
    }

    /// The consumer input for one turn at `now`.
    fn consumer(&self, now: u64) -> BookingLifecycleConsumerInput {
        BookingLifecycleConsumerInput {
            local_node_id: self.node_id,
            lease_owner: "booking-lifecycle-worker".to_owned(),
            now_utc: now,
        }
    }

    /// Enqueues a verb and runs exactly one home-node consumer turn.
    fn run(
        &self,
        request: BookingVerbRequest,
        now: u64,
    ) -> Result<BookingVerbReceipt, BookingError> {
        enqueue_booking_verb(&self.vault, request, now)?;
        let turn = run_booking_lifecycle_once(
            &self.vault,
            |oracle_request| {
                let page = oracle_request
                    .page_ref
                    .expect("the consumer only builds an oracle for a resolved page");
                Ok(LifecycleSolver {
                    page,
                    exclude: oracle_request.exclude_session_key,
                    vault: &self.vault,
                })
            },
            &self.consumer(now),
        )?;
        match turn {
            BookingLifecycleTurn::Executed(receipt) => Ok(receipt),
            other => panic!("the home node must execute the queued attempt, got {other:?}"),
        }
    }

    /// The calendars the emergency planner reads per host.
    fn calendars(&self) -> Vec<(EntityId, Vec<CalendarSel>)> {
        vec![(self.host, vec![CalendarSel { system: None }])]
    }
}

/// The production booking solver plus the vault-backed hold source.
struct LifecycleSolver<'a> {
    /// The page the solve is scoped to.
    page: EntityId,
    /// The session whose own hold the solve hides.
    exclude: Option<SessionKey>,
    /// The vault the solve reads.
    vault: &'a Vault,
}

impl SlotOracle for LifecycleSolver<'_> {
    /// Solves through the production solver with the vault's live holds.
    fn solve(&self, req: &SolveRequest) -> Result<SolveResult, BookingError> {
        let holds = match self.exclude {
            Some(key) => VaultActiveHoldSource::excluding(self.vault, key),
            None => VaultActiveHoldSource::new(self.vault),
        };
        let calendars = vec![(test_id(HOST_SEED), vec![CalendarSel { system: None }])];
        BookingSolver {
            vault: self.vault,
            page_ref: self.page,
            calendars_by_host: &calendars,
            holds: &holds,
            now_utc: NOW,
            synthetic_config: Some(fixture_config()),
        }
        .solve(req)
    }
}

/// The intro call event type.
fn event_type() -> EventTypeKey {
    EventTypeKey("intro-call".to_owned())
}

/// Monday 09:00-14:00 UTC, 30-minute slots, no notice.
fn fixture_config() -> EventTypeConfig {
    EventTypeConfig {
        key: event_type(),
        duration_min: DEFAULT_INTRO_DURATION_MIN,
        slot_step_min: 30,
        pre_buffer_min: 0,
        post_buffer_min: 0,
        min_notice_secs: 0,
        booking_window_secs: 7 * 24 * 3_600,
        daily_cap: None,
        weekly_cap: None,
        routing: RoutingMode::Either,
        hosts: vec![HostAvailabilityConfig {
            host_ref: test_id(HOST_SEED),
            calendar_refs: vec![test_id(BUSY_SEED)],
            host_tz: "UTC".to_owned(),
            working_hours: vec![WeeklyWallWindow {
                weekday: 0,
                start_minute: 9 * 60,
                end_minute: 14 * 60,
            }],
            preferred_hours: Vec::new(),
        }],
        flex_windows: Vec::new(),
    }
}

/// Holds `slot` and confirms it for the fixture booker.
fn book(fixture: &Fixture, session_key: SessionKey, slot: TimeRange) -> ConfirmReceipt {
    let hold: HoldReceipt = match fixture
        .run(
            BookingVerbRequest::Hold(HoldSpec {
                page_ref: fixture.page,
                event_type: event_type(),
                slot,
                session_key,
                visitor_tz: "UTC".to_owned(),
                constraint: None,
                lease: HoldLeaseSpec::Ordinary,
                idempotency_key: None,
            }),
            NOW,
        )
        .expect("hold")
    {
        BookingVerbReceipt::Held(hold) => hold,
        other => panic!("expected a hold receipt, got {other:?}"),
    };
    match fixture
        .run(
            BookingVerbRequest::Confirm(ConfirmSpec {
                hold_token: hold.token.clone(),
                session_key,
                booker_contact: fixture.booker,
                intake: Vec::new(),
                idempotency_key: None,
            }),
            NOW,
        )
        .expect("confirm")
    {
        BookingVerbReceipt::Confirmed(confirmed) => confirmed,
        other => panic!("expected a confirm receipt, got {other:?}"),
    }
}

/// One outbound request the sink delivered.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DeliveredRequest {
    /// The intent's channel.
    channel: String,
    /// The intent's verb.
    verb: String,
    /// The intent's content reference, when it carries one.
    content_ref: Option<String>,
}

/// A sink that delivers every request and keeps each intent's channel, verb
/// and content reference.
#[derive(Debug, Default)]
struct DeliveringSink {
    /// Every request this sink delivered, in order.
    deliveries: Vec<DeliveredRequest>,
}

impl OutboundExecutionSink for DeliveringSink {
    /// Records the intent and reports a delivery to the channel.
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        self.deliveries.push(DeliveredRequest {
            channel: request.intent.channel.clone(),
            verb: request.intent.verb.clone(),
            content_ref: request.intent.content_ref.clone(),
        });
        OutboundExecutionOutcome::delivered_to_channel("provider:message:fixture")
    }
}

/// Whether `bytes` spells `needle` in one run.
fn spells(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).any(|window| window == needle)
}

/// Asserts no row spells any token's usable text, and the rows include the
/// emergency item table, so the scan is not vacuous.
fn assert_rows_hold_no_token_text(rows: &[BookingSideTableRow], tokens: &[OpaqueLifecycleToken]) {
    for (index, token) in tokens.iter().enumerate() {
        let needle = token.0.as_bytes();
        for row in rows {
            assert!(
                !spells(&row.key, needle) && !spells(&row.value, needle),
                "a {} row spells the usable text of action {index}",
                row.table,
            );
        }
    }
    let seen = rows
        .iter()
        .filter(|row| row.table == "EMERGENCY_ITEM")
        .count();
    assert!(seen >= 1, "the scan saw the emergency item table: {seen}");
}

/// Reads the visitor's pick tokens from the apology blob `content_ref` names.
fn pick_tokens_from_apology(vault: &Vault, content_ref: &str) -> Vec<OpaqueLifecycleToken> {
    let hex = content_ref
        .strip_prefix("blob:")
        .expect("the apology names a blob");
    let id = EntityId::from_hex(hex).expect("the blob ref parses");
    let head = vault
        .blob_artifact_head(&id)
        .expect("the apology head reads")
        .expect("the apology head exists");
    let bytes = vault
        .read_blob_artifact_version(&id, head.version)
        .expect("the apology version reads")
        .expect("the apology version exists");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("the apology is JSON");
    body["actions"]
        .as_array()
        .expect("the apology lists actions")
        .iter()
        .map(|entry| {
            let action = entry["action"].as_str().expect("an action string");
            let token = action
                .strip_prefix("booking:emergency-pick:")
                .expect("a pick action");
            OpaqueLifecycleToken(token.to_owned())
        })
        .collect()
}

/// An emergency item row keeps no usable pick token, while the pick with a
/// token from the delivery still moves the booking.
#[test]
fn emergency_item_row_keeps_no_usable_pick_token() {
    let walked = booking_side_table_names();
    assert!(
        walked.contains(&"EMERGENCY_ITEM"),
        "the scan walks EMERGENCY_ITEM: {walked:?}",
    );
    let fixture = Fixture::open();
    let booked_slot = slot_at(9);
    let booked = book(
        &fixture,
        SessionKey::derive(b"emergency-action-digest"),
        booked_slot,
    );

    // The owner's delivery seat, policy and page grant, as the feed-move-held
    // fixture installs them.
    let identity = common::self_held_identity_in_state(
        "email",
        "host@example.test",
        SelfHeldShape::DedicatedAddress,
        ChannelIdentityBinding::agent(fixture.host),
        ChannelIdentityState::Active,
        NOW,
    );
    fixture
        .vault
        .create_channel_identity(&test_id(IDENTITY_SEED), &identity)
        .expect("the host's email identity");
    let effect_scope = oneiron::test_support::effect_preset();
    let policy = rmp_serde::to_vec_named(&serde_json::json!({
        "schema_version": "1.2", "pack_id": "emergency-action-digest-tests", "pack_version": "v1",
        "min_engine_version": env!("CARGO_PKG_VERSION"),
        "defaults": { "criticality": "normal", "sensitivity": "normal" }, "rules": [],
        "actor_ceilings": [
            { "actor_class": "agent", "actor_ref": fixture.host.to_hex(), "ceiling": "auto" },
            { "actor_class": "first_party", "ceiling": "auto" },
            { "actor_class": "human", "ceiling": "auto" }
        ],
        "scoped_grants": [
            { "actor_ref": fixture.host.to_hex(), "effector": "external:calendar.invite",
              "scope": effect_scope, "selectors": { "channel": "calendar" } },
            { "actor_ref": fixture.host.to_hex(), "effector": "external:send",
              "scope": effect_scope, "selectors": { "channel": "email" } }
        ]
    }))
    .expect("encode the policy manifest");
    oneiron::test_support::put_policy_manifest_bytes(&fixture.vault, test_id(POLICY_SEED), &policy)
        .expect("put the policy manifest");
    mint_publish_page_invite_grant(
        &fixture.vault,
        &PublishBookingPageGrantRequest {
            page_ref: fixture.page,
            publisher_principal: fixture.host,
            issued_at: NOW,
        },
    )
    .expect("the page's invite grant");
    oneiron::test_support::bind_host_owner(&fixture.vault, &fixture.issuer, fixture.host)
        .expect("bind the host as the owner");
    // The apology goes out on `email`, which a seeded vault refuses until its
    // built-in pack is installed and checked (OF-519): "the channel's
    // built-in pack is not installed". The pack is not what this test
    // covers, so the vault drops the seed marker, as an unseeded open has none.
    oneiron::test_doors::builtin_pack_seed::remove_builtin_pack_seed_marker(&fixture.vault)
        .expect("remove the built-in pack seed marker");

    // The owner's RequestUpdate instruction over the booked slot: it keeps
    // the booking confirmed at its slot and revision, and proposes others.
    let window = inclusive(booked_slot);
    let memory = fixture.vault.memory(fixture.host, EdgeActorClass::Human);
    let authority = memory
        .record_emergency_instruction(&EmergencyInstructionInput {
            affected_window: CalendarRangeDto {
                start: window.start,
                end: window.end,
            },
            reason: "unavailable".to_owned(),
            action_policy: EmergencyActionPolicy::RequestUpdate,
            recorded_at: NOW + 90,
        })
        .expect("the owner logs the emergency instruction");
    let request = EmergencyRescheduleRequest {
        owner_ref: fixture.host,
        affected_window: window,
        reason: "unavailable".to_owned(),
        action_policy: EmergencyActionPolicy::RequestUpdate,
        authority,
    };
    let batch = plan_emergency_reschedule(&fixture.vault, &request, &fixture.calendars(), NOW + 90)
        .expect("plan the emergency");
    assert!(batch.refusals.is_empty(), "{:?}", batch.refusals);
    let [plan] = <[EmergencyPlan; 1]>::try_from(batch.plans).expect("one plan, for the booking");
    assert_eq!(plan.booking().calendar.event_ref, booked.calendar.event_ref);

    // 1. Execute with the delivering sink. A RequestUpdate owes no calendar
    // effect, so the one delivery is the apology.
    let mut sink = DeliveringSink::default();
    let _item = execute_emergency_plan(
        &fixture.vault,
        &request,
        &plan,
        &fixture.calendars(),
        &fixture.consumer(NOW + 90),
        &mut sink,
    )
    .expect("the emergency delivery completes");
    let apologies: Vec<&DeliveredRequest> = sink
        .deliveries
        .iter()
        .filter(|delivery| {
            delivery.verb == "send"
                && delivery.channel == "email"
                && delivery
                    .content_ref
                    .as_deref()
                    .is_some_and(|reference| reference.starts_with("blob:"))
        })
        .collect();
    assert_eq!(apologies.len(), 1, "the apology is delivered exactly once");
    let content_ref = apologies[0]
        .content_ref
        .clone()
        .expect("the apology names its blob");

    // 2. The visitor's actions, read from the delivery, not from the item.
    let tokens = pick_tokens_from_apology(&fixture.vault, &content_ref);
    assert!(
        (2..=3).contains(&tokens.len()),
        "the apology carries two or three actions: {}",
        tokens.len(),
    );

    // 3. No stored row spells any token's usable text.
    let rows = booking_side_table_rows(&fixture.vault).expect("the booking side-table rows");
    assert_rows_hold_no_token_text(&rows, &tokens);

    // 4. A well-formed token nobody minted is refused.
    let unminted = OpaqueLifecycleToken("0".repeat(64));
    assert!(
        counterparty_pick(
            &fixture.vault,
            &unminted,
            &fixture.calendars(),
            &fixture.consumer(PICK_NOW),
            &mut sink,
        )
        .is_err(),
        "an unminted token is refused",
    );

    // 5. The pick with action 0's token moves the booking to proposal 0.
    let revision = counterparty_pick(
        &fixture.vault,
        &tokens[0],
        &fixture.calendars(),
        &fixture.consumer(PICK_NOW),
        &mut sink,
    )
    .expect("the pick with the delivery's token succeeds");
    assert_eq!(revision.event_ref, booked.calendar.event_ref);
    assert_eq!(revision.uid, booked.calendar.uid);
    assert_eq!(revision.sequence, booked.calendar.sequence + 1);
    let proposal = &plan.proposals()[0];
    let expected = inclusive(TimeRange {
        start: proposal.start_utc,
        end: proposal.end_utc,
    });
    assert_eq!(
        fixture
            .vault
            .get_occurred(&revision.event_ref)
            .expect("booking occurrence"),
        expected,
        "the booking sits at proposal 0's slot",
    );

    // 6. Action 1's token after the pick is refused as consumed.
    let consumed = counterparty_pick(
        &fixture.vault,
        &tokens[1],
        &fixture.calendars(),
        &fixture.consumer(PICK_NOW),
        &mut sink,
    );
    assert!(
        consumed.is_err(),
        "the sibling token after the pick is refused",
    );
    assert!(
        consumed
            .expect_err("the sibling pick is refused")
            .to_string()
            .contains("already been consumed"),
        "the sibling refusal says the action was consumed",
    );

    // 7. The pick rewrote the item row; still no row spells a token.
    let rows = booking_side_table_rows(&fixture.vault).expect("the booking side-table rows");
    assert_rows_hold_no_token_text(&rows, &tokens);
}
