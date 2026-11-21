//! A home move carries the emergency reschedule rows (FIX
//! [BK-EMERGENCY-ROWS-NOT-CARRIED-BY-HOME-MOVE]; Engine ANSWER
//! BK-EMERGENCY-ROWS-CARRY-SCOPE = B, 21 Nov 07:38; lead ruling
//! BK-HOME-MOVE-CARRIES-BOOKINGS = A, 06:2x: "a move must never silently
//! strand a visitor's link"). The emergency writers write on the home alone,
//! and a home move carried none of the owner's instructions, plans or
//! checkpoints: on the new home the counterparty's pick link from the apology
//! did not resolve, and an emergency whose delivery failed on the old home
//! could be finished nowhere. Now:
//! - the counterparty's pick on the new home moves the booking the old home
//!   planned, and the old home refuses it;
//! - the owner's instruction lands with the owner's part, and a checkpoint
//!   whose booker part does not open (an erased booker) lands nothing: its
//!   pick is refused loudly;
//! - the raw action tokens travel sealed under the booker's key, and the old
//!   home drops its copy once the new home acknowledged the move (lead ruling
//!   BK-EMERGENCY-RAW-TOKENS-SEALED = A);
//! - an emergency whose delivery failed on the old home travels owed, and the
//!   new home delivers it (ASK BK-EMERGENCY-PENDING-ITEM-MOVE); the old home
//!   can no longer resume it;
//! - a send that ended uncertain on the old home (the provider took it as a
//!   remote task) travels marked, and the owner's resume on the new home that
//!   sends it again answers "this send ended uncertain on the old home and
//!   may repeat" (FIX [BK-EMERGENCY-UNCERTAIN-SEND-NOT-SHOWN-TO-OWNER];
//!   Engine ANSWER BK-EMERGENCY-UNCERTAIN-SEND-RECEIPT = A, 21 Nov 09:14),
//!   and so does every later run over the checkpoint (review round 2 of
//!   #10166); a send that failed definitely there answers nothing;
//! - a mark travels with the next move, even once its send was delivered
//!   again: a home whose run sent it and then stopped on a later effect
//!   passes it on, and the next home's run answers it (review round 1 of
//!   #10125);
//! - an apology the provider took as a remote task on a home, which the move
//!   carried away owed and a later move carried back there, goes again from
//!   that former home under the key its first send reached the provider
//!   under (FIX [BK-EMERGENCY-DEFERRED-SEND-STRANDED-ON-FORMER-HOME]): its
//!   own ledger's deferred row, which its replay never sends again (FIX
//!   7960), no longer holds every resume there;
//! - an invite, whose provider-native key a fresh ledger row would change,
//!   keeps its row on that former home: its own remote task settles it, and
//!   it is never sent under a second key (review round 1 of #10220);
//! - once that apology's first send is delivered after all (its remote task
//!   completes), neither the former home's resume nor the next home's sends
//!   it again (review round 1 of #10220).
//!
//! The emergency fixture is `tests/booking_feed_move_held.rs`'s: an
//! owner-logged RequestUpdate instruction over a booked slot, planned and
//! executed on the lifecycle home node. The seed vault books and runs the
//! emergency, then closes, and the two machines are copies of its directory,
//! as `tests/booking_home_move_carries_deposit.rs` makes them. The door
//! `drop_node_local_booking_rows` empties the new home's node-local booking
//! and emergency rows, which no sync carries, `drop_node_local_outbound_rows`
//! its outbound send ledger (each node's names only the sends it made), and
//! `move_booking_home` freezes the old home and carries each section the build
//! registers.
//!
//! Red on main (the base #10060 head with these doors and the carrier's
//! scrub hook, and no emergency section registered): the new home refuses
//! the pick ("emergency action has no durable checkpoint") and the resume
//! ("owner instruction has not been logged"), holds no instruction, and the
//! old home keeps its raw tokens after the ack.
//!
//! The repeat answer is red on its base (#10109's head 02f5b7401a4e): the
//! resume answers the checkpoint alone, so this file does not compile there
//! (no `EmergencyRepeatNotice`, no `repeat_notices`). The mark carried past
//! a second move is red on #10125's first head 57571ff1ad64: the second home
//! drops the mark of an invite it delivered, so the third home's run answers
//! nothing. The answer over a picked checkpoint is red on #10166's head
//! 7cdc5c16ca1e: the owner's run refuses the picked checkpoint before it
//! answers, so a repeat its delivery left unanswered is never shown. The
//! answer's replay is red on #10166's head 91d09f814167: the first answer
//! dropped its mark, so a run that stopped after that writer, before the
//! owner read its answer, left the next run nothing to answer (review round
//! 2 of #10166). The send carried back to its former home is red on #10166's
//! head 6bf877252c85: the former home's resume replays its own deferred row
//! under the same attempt, never calls the sink, and refuses ("emergency
//! effect is not delivered; resume its existing intent"). The door
//! `record_booking_home_adoption` records on that former home the adoption a
//! move's target records, so it takes home writes again. The invite's own
//! remote task and the apology delivered by its first send are red on
//! #10220's head 091a2032bf6a: that head gives the deferred invite a fresh
//! ledger row, so the sink is handed it again under a new key, and it reads
//! only the apology's fresh attempt, so the former home and the next home
//! send it again. The door `emergency_effect_ledger_rows` names a node's
//! ledger rows of an effect under each of its ledger generations.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test booking_home_move_carries_emergency`.
#![cfg(all(oneiron_test_support, feature = "sync"))]

mod common;

use oneiron::booking::{
    BOOKING_EVENT_TYPE_PREDICATE, BOOKING_EVENT_TYPE_SCHEMA_VERSION, BookingError,
    BookingEventTypeClaimValue, BookingLifecycleConsumerInput, BookingLifecycleTurn, BookingSolver,
    BookingVerbReceipt, BookingVerbRequest, ConfirmReceipt, ConfirmSpec,
    DEFAULT_INTRO_DURATION_MIN, EMERGENCY_REPEAT_NOTICE, EmergencyActionPolicy, EmergencyItem,
    EmergencyPlan, EmergencyRepeatNotice, EmergencyRescheduleRequest, EventTypeConfig,
    EventTypeKey, HoldLeaseSpec, HoldReceipt, HoldSpec, HostAvailabilityConfig,
    PublishBookingPageGrantRequest, RoutingMode, SessionKey, SlotOracle, SolveRequest, SolveResult,
    VaultActiveHoldSource, WeeklyWallWindow, counterparty_pick, encode_event_type_claim_value,
    enqueue_booking_verb, execute_emergency_plan, mint_publish_page_invite_grant,
    plan_emergency_reschedule, run_booking_lifecycle_once, verify_logged_owner_instruction,
};
use oneiron::calendar::query::CalendarRangeDto;
use oneiron::channel_identity::{ChannelIdentityBinding, ChannelIdentityState, SelfHeldShape};
use oneiron::memory::EmergencyInstructionInput;
use oneiron::outbound::{
    OutboundExecutionOutcome, OutboundExecutionRequest, OutboundExecutionSink,
};
use oneiron::outbound_intent_ledger::{RemoteTaskHandle, RemoteTaskObservation};
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_PERSON};
use oneiron::test_doors::booking_home_move::{
    acknowledge_booking_home_move, booking_rows_hold, deliver_emergency_without_answer,
    drop_node_local_booking_rows, drop_node_local_outbound_rows, emergency_effect_ledger_rows,
    move_booking_home, record_booking_home_adoption,
};
use oneiron::{
    CalendarSel, ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject,
    DreamerRunnerStore, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig,
};

/// Monday 2 March 2026, 00:00 UTC.
const MONDAY: u64 = 1_772_409_600;
const NOW: u64 = MONDAY + 8 * 3_600;

const PAGE_SEED: u8 = 0x51;
const BOOKER_SEED: u8 = 0x57;
const BUSY_SEED: u8 = 0x61;
const IDENTITY_SEED: u8 = 0x79;
const POLICY_SEED: u8 = 0x7a;

/// The vault's directory inside a machine's directory.
const MACHINE_VAULT_DIR: &str = "vault";

const fn at(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

/// `[seed; 16]`; every seed here is outside the production-pinned id bytes.
fn test_id(seed: u8) -> EntityId {
    common::entity(seed)
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

fn event_type() -> EventTypeKey {
    EventTypeKey("intro-call".to_owned())
}

fn fixture_config(host: EntityId) -> EventTypeConfig {
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
        deposit: None,
        routing: RoutingMode::Either,
        hosts: vec![HostAvailabilityConfig {
            host_ref: host,
            calendar_refs: vec![test_id(BUSY_SEED)],
            host_tz: "UTC".to_owned(),
            working_hours: vec![WeeklyWallWindow {
                weekday: 0,
                start_minute: 9 * 60,
                end_minute: 14 * 60,
            }],
            preferred_hours: Vec::new(),
        }],
        flex_with_ordinary: false,
        flex_windows: Vec::new(),
        allowed_durations_min: Vec::new(),
    }
}

/// One machine: a vault in `dir/vault` with the booking page, its host (the
/// vault's embedded owner), a booker contact and an elected home node.
struct Machine {
    dir: tempfile::TempDir,
    vault: Vault,
    page: EntityId,
    host: EntityId,
    booker: EntityId,
    /// This install's client id, elected the lifecycle home node: the
    /// emergency writers run only there.
    node_id: u64,
}

impl Machine {
    fn seed() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(MACHINE_VAULT_DIR);
        std::fs::create_dir_all(&path).expect("vault dir");
        let vault = open_vault(&path);
        let page = test_id(PAGE_SEED);
        let host = vault.ensure_embedded_owner_actor().expect("host");
        let booker = test_id(BOOKER_SEED);
        vault
            .put_entity(&page, ENTITY_TYPE_ASSET, at(1), 1, b"booking page")
            .expect("put booking page");
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
        // only a PERSON's put stores, so the page's FACET is stored first.
        vault
            .put_entity(
                &oneiron::claim::substrate_facet_id(page).expect("the page's facet id"),
                oneiron::registry::ENTITY_TYPE_FACET,
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
                config: fixture_config(host),
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
        let machine = Self {
            dir,
            vault,
            page,
            host,
            booker,
            node_id,
        };
        machine.install_owner_delivery(&issuer);
        machine
    }

    /// The owner's delivery seat, policy and page grant, as the crate's own
    /// emergency fixture installs them (`tests/booking_feed_move_held.rs`).
    fn install_owner_delivery(&self, issuer: &oneiron::authority::HostSlipIssuer) {
        let identity = common::self_held_identity_in_state(
            "email",
            "host@example.test",
            SelfHeldShape::DedicatedAddress,
            ChannelIdentityBinding::agent(self.host),
            ChannelIdentityState::Active,
            NOW,
        );
        self.vault
            .create_channel_identity(&test_id(IDENTITY_SEED), &identity)
            .expect("the host's email identity");
        let effect_scope = oneiron::test_support::effect_preset();
        let policy = rmp_serde::to_vec_named(&serde_json::json!({
            "schema_version": "1.2", "pack_id": "home-move-emergency-tests", "pack_version": "v1",
            "min_engine_version": env!("CARGO_PKG_VERSION"),
            "defaults": { "criticality": "normal", "sensitivity": "normal" }, "rules": [],
            "actor_ceilings": [
                { "actor_class": "agent", "actor_ref": self.host.to_hex(), "ceiling": "auto" },
                { "actor_class": "first_party", "ceiling": "auto" },
                { "actor_class": "human", "ceiling": "auto" }
            ],
            "scoped_grants": [
                { "actor_ref": self.host.to_hex(), "effector": "external:calendar.invite",
                  "scope": effect_scope, "selectors": { "channel": "calendar" } },
                { "actor_ref": self.host.to_hex(), "effector": "external:send",
                  "scope": effect_scope, "selectors": { "channel": "email" } }
            ]
        }))
        .expect("encode the policy manifest");
        oneiron::test_support::put_policy_manifest_bytes(
            &self.vault,
            test_id(POLICY_SEED),
            &policy,
        )
        .expect("put the policy manifest");
        mint_publish_page_invite_grant(
            &self.vault,
            &PublishBookingPageGrantRequest {
                page_ref: self.page,
                publisher_principal: self.host,
                issued_at: NOW,
            },
        )
        .expect("the page's invite grant");
        oneiron::test_support::bind_host_owner(&self.vault, issuer, self.host)
            .expect("bind the host as the owner");
        // The apology goes out on `email`, which a seeded vault refuses until
        // its built-in pack is installed and checked (OF-519); the pack is
        // not what this test covers.
        oneiron::test_doors::builtin_pack_seed::remove_builtin_pack_seed_marker(&self.vault)
            .expect("remove the built-in pack seed marker");
    }

    /// Closes this machine and opens two on copies of its directory: the old
    /// home, with every row this one held, and the new home, with none of its
    /// node-local booking or emergency rows (sync leaves the EVENTs, claims
    /// and blobs on both).
    fn into_old_and_new_home(self) -> (Self, Self) {
        let Self {
            dir,
            vault,
            page,
            host,
            booker,
            node_id,
        } = self;
        drop(vault);
        let open = || {
            let copy = tempfile::tempdir().expect("temp dir");
            copy_dir(dir.path(), copy.path());
            let vault = open_vault(&copy.path().join(MACHINE_VAULT_DIR));
            Self {
                dir: copy,
                vault,
                page,
                host,
                booker,
                node_id,
            }
        };
        let (old_home, new_home) = (open(), open());
        drop_node_local_booking_rows(&new_home.vault).expect("FIXTURE: the new home's own rows");
        drop_node_local_outbound_rows(&new_home.vault)
            .expect("FIXTURE: the new home's own outbound ledger");
        (old_home, new_home)
    }

    fn consumer(&self, now: u64) -> BookingLifecycleConsumerInput {
        BookingLifecycleConsumerInput {
            local_node_id: self.node_id,
            lease_owner: "booking-lifecycle-worker".to_owned(),
            now_utc: now,
        }
    }

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

    /// The counterparty's pick of `item`'s first proposal on this machine.
    fn pick(
        &self,
        item: &EmergencyItem,
    ) -> Result<oneiron::booking::CalendarRevision, BookingError> {
        counterparty_pick(
            &self.vault,
            &item.actions[0],
            &self.calendars(),
            &self.consumer(NOW + 300),
            &mut DeliveringSink,
        )
    }
}

/// Opens the vault at `path` with an in-memory keystore: signing doors load
/// this install's keys from a keystore (P6c).
fn open_vault(path: &std::path::Path) -> Vault {
    let vault = Vault::open(path, VaultConfig::default()).expect("open vault");
    vault.install_device_keystore(std::sync::Arc::new(
        oneiron_keystore::MemoryKeystore::default(),
    ));
    vault
}

/// Copies the closed machine directory `from` into `to`, file by file, as
/// `tests/room_pins_concurrent_merge.rs` copies its seed vault.
fn copy_dir(from: &std::path::Path, to: &std::path::Path) {
    for entry in std::fs::read_dir(from).expect("read the machine dir") {
        let entry = entry.expect("machine dir entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("entry type").is_dir() {
            std::fs::create_dir_all(&target).expect("copy dir");
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).expect("copy file");
        }
    }
}

struct LifecycleSolver<'a> {
    page: EntityId,
    exclude: Option<SessionKey>,
    vault: &'a Vault,
}

impl SlotOracle for LifecycleSolver<'_> {
    fn solve(&self, req: &SolveRequest) -> Result<SolveResult, BookingError> {
        let holds = match self.exclude {
            Some(key) => VaultActiveHoldSource::excluding(self.vault, key),
            None => VaultActiveHoldSource::new(self.vault),
        };
        let host = self.vault.ensure_embedded_owner_actor().expect("host");
        let calendars = vec![(host, vec![CalendarSel { system: None }])];
        BookingSolver {
            vault: self.vault,
            page_ref: self.page,
            calendars_by_host: &calendars,
            holds: &holds,
            now_utc: NOW,
            synthetic_config: Some(fixture_config(host)),
        }
        .solve(req)
    }
}

/// A sink that delivers every effect.
struct DeliveringSink;

impl OutboundExecutionSink for DeliveringSink {
    fn execute(&mut self, _request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        OutboundExecutionOutcome::delivered_to_channel("provider:message:fixture")
    }
}

/// A sink whose every delivery fails definitely.
struct FailingSink;

impl OutboundExecutionSink for FailingSink {
    fn execute(&mut self, _request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        OutboundExecutionOutcome::failed("definite fixture non-delivery")
    }
}

/// A sink whose provider takes every send as a remote task: whether it
/// reached the booker is not known.
struct DeferringSink;

impl OutboundExecutionSink for DeferringSink {
    fn execute(&mut self, _request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        OutboundExecutionOutcome::deferred(RemoteTaskHandle {
            id: "provider:task:fixture".to_owned(),
            poll_after_secs: None,
            poll: None,
        })
    }
}

/// A sink that records the channel of each send it is handed and the key that send reaches its
/// provider under, then answers it as `inner` does. The key is the one the served email sink
/// drafts a send under (`email_send_key`, with no engine send id here): the transport's
/// provider-native key, else the intent's own.
struct RecordingSink<S> {
    inner: S,
    sends: Vec<(String, String)>,
}

impl<S> RecordingSink<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            sends: Vec::new(),
        }
    }

    /// The provider keys of the sends on `channel` this sink was handed, in order.
    fn keys(&self, channel: &str) -> Vec<&str> {
        self.sends
            .iter()
            .filter(|(sent, _)| sent == channel)
            .map(|(_, key)| key.as_str())
            .collect()
    }
}

impl<S: OutboundExecutionSink> OutboundExecutionSink for RecordingSink<S> {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        let key = request
            .idempotency_key
            .or(request.intent.idempotency_key.as_deref())
            .unwrap_or(request.intent_ref);
        self.sends
            .push((request.intent.channel.to_string(), key.to_owned()));
        self.inner.execute(request)
    }
}

/// A sink that delivers the calendar invite and whose provider takes every other send as a
/// remote task: the owner's run sends the invite, and whether the apology reached the booker is
/// not known.
struct ApologyDeferringSink;

impl OutboundExecutionSink for ApologyDeferringSink {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        if request.intent.channel == "calendar" {
            OutboundExecutionOutcome::delivered_to_channel("provider:message:fixture")
        } else {
            DeferringSink.execute(request)
        }
    }
}

/// A sink that delivers the calendar invite and fails every other send
/// definitely: the owner's run sends the invite, then stops on the apology.
struct InviteOnlySink;

impl OutboundExecutionSink for InviteOnlySink {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        if request.intent.channel == "calendar" {
            OutboundExecutionOutcome::delivered_to_channel("provider:message:fixture")
        } else {
            OutboundExecutionOutcome::failed("definite fixture non-delivery")
        }
    }
}

fn book(machine: &Machine, session_key: SessionKey, slot: TimeRange) -> ConfirmReceipt {
    let hold: HoldReceipt = match machine
        .run(
            BookingVerbRequest::Hold(HoldSpec {
                page_ref: machine.page,
                event_type: event_type(),
                slot,
                session_key,
                visitor_tz: "UTC".to_owned(),
                constraint: None,
                lease: HoldLeaseSpec::Ordinary,
                idempotency_key: None,
                cap_override: None,
            }),
            NOW,
        )
        .expect("FIXTURE: hold")
    {
        BookingVerbReceipt::Held(hold) => hold,
        other => panic!("expected a hold receipt, got {other:?}"),
    };
    match machine
        .run(
            BookingVerbRequest::Confirm(ConfirmSpec {
                hold_token: hold.token.clone(),
                session_key,
                booker_contact: machine.booker,
                intake: Vec::new(),
                idempotency_key: None,
            }),
            NOW,
        )
        .expect("FIXTURE: confirm")
    {
        BookingVerbReceipt::Confirmed(confirmed) => confirmed,
        other => panic!("expected a confirm receipt, got {other:?}"),
    }
}

/// The 09:00 booking with the owner's RequestUpdate emergency over it,
/// planned and executed on the seed through `sink`.
struct Emergency {
    booked: ConfirmReceipt,
    request: EmergencyRescheduleRequest,
    plan: EmergencyPlan,
    /// The executed checkpoint, `Err` when `sink` failed its delivery.
    item: Result<EmergencyItem, BookingError>,
}

fn emergency(seed: &Machine, sink: &mut impl OutboundExecutionSink) -> Emergency {
    let booked = book(seed, SessionKey::derive(b"home-move-emergency"), slot_at(9));
    let window = inclusive(slot_at(9));
    let authority = seed
        .vault
        .memory(seed.host, EdgeActorClass::Human)
        .record_emergency_instruction(&EmergencyInstructionInput {
            affected_window: CalendarRangeDto {
                start: window.start,
                end: window.end,
            },
            reason: "unavailable".to_owned(),
            action_policy: EmergencyActionPolicy::RequestUpdate,
            recorded_at: NOW + 90,
        })
        .expect("FIXTURE: the owner logs the emergency instruction");
    let request = EmergencyRescheduleRequest {
        owner_ref: seed.host,
        affected_window: window,
        reason: "unavailable".to_owned(),
        action_policy: EmergencyActionPolicy::RequestUpdate,
        authority,
    };
    let batch = plan_emergency_reschedule(&seed.vault, &request, &seed.calendars(), NOW + 90)
        .expect("FIXTURE: plan the emergency");
    assert!(batch.refusals.is_empty(), "{:?}", batch.refusals);
    let [plan] = <[EmergencyPlan; 1]>::try_from(batch.plans).expect("one plan, for the booking");
    let item = execute_emergency_plan(
        &seed.vault,
        &request,
        &plan,
        &seed.calendars(),
        &seed.consumer(NOW + 90),
        sink,
    )
    .map(|run| run.item);
    Emergency {
        booked,
        request,
        plan,
        item,
    }
}

/// A delivered emergency on the seed, then the old and new home.
fn delivered_emergency() -> (Machine, Machine, Emergency) {
    let seed = Machine::seed();
    let emergency = emergency(&seed, &mut DeliveringSink);
    let item = emergency
        .item
        .as_ref()
        .expect("FIXTURE: the emergency delivers on the seed");
    assert!(item.calendar_delivered && item.apology_delivered);
    assert!(!item.actions.is_empty(), "one pick action per proposal");
    let (old_home, new_home) = seed.into_old_and_new_home();
    (old_home, new_home, emergency)
}

fn delivered(emergency: &Emergency) -> &EmergencyItem {
    emergency.item.as_ref().expect("delivered on the seed")
}

#[test]
fn the_counterpartys_pick_on_the_new_home_moves_the_booking_the_old_home_planned() {
    let (old_home, new_home, emergency) = delivered_emergency();
    assert!(
        move_booking_home(&old_home.vault, &new_home.vault, &[]).expect("move the booking home"),
        "every section applies"
    );

    let refused = old_home
        .pick(delivered(&emergency))
        .expect_err("the old home holds history: it refuses the pick");
    assert!(
        refused
            .to_string()
            .contains("does not hold the booking rows"),
        "{refused}"
    );

    let event = emergency.booked.calendar.event_ref;
    let revision = new_home
        .pick(delivered(&emergency))
        .expect("the new home resolves the pick link (main: no durable checkpoint)");
    assert_eq!(revision.event_ref, event);
    assert!(
        revision.sequence > emergency.booked.calendar.sequence,
        "the pick takes the booking's next revision"
    );
    let picked = &emergency.plan.proposals()[0];
    assert_eq!(
        new_home
            .vault
            .get_occurred(&event)
            .expect("the booking's occurrence")
            .start,
        picked.start_utc,
        "the booking moves to the picked proposal on the new home"
    );
}

#[test]
fn a_checkpoint_whose_booker_part_does_not_open_lands_nothing_and_its_pick_is_refused() {
    let (old_home, new_home, emergency) = delivered_emergency();
    assert!(
        move_booking_home(&old_home.vault, &new_home.vault, &[old_home.booker])
            .expect("move the booking home"),
        "every section applies, the withheld parts' rows as their facts"
    );

    verify_logged_owner_instruction(&new_home.vault, &emergency.request)
        .expect("the instruction lands with the owner's part (main: not logged)");
    let refused = new_home
        .pick(delivered(&emergency))
        .expect_err("a checkpoint without its booker's content lands nothing");
    assert!(
        refused.to_string().contains("no durable checkpoint"),
        "the pick is refused loudly: {refused}"
    );
    let event = emergency.booked.calendar.event_ref;
    assert_eq!(
        new_home
            .vault
            .get_occurred(&event)
            .expect("the booking's occurrence"),
        inclusive(slot_at(9)),
        "the refused pick moves nothing"
    );
}

#[test]
fn the_old_home_holds_no_raw_action_token_once_the_new_home_acknowledged_the_move() {
    let (old_home, new_home, emergency) = delivered_emergency();
    let token = delivered(&emergency).actions[0].0.clone();
    assert!(
        booking_rows_hold(&old_home.vault, token.as_bytes()).expect("read the old home"),
        "FIXTURE: the old home's checkpoint holds the raw token"
    );
    assert!(
        move_booking_home(&old_home.vault, &new_home.vault, &[]).expect("move the booking home"),
        "every section applies"
    );
    assert!(
        booking_rows_hold(&new_home.vault, token.as_bytes()).expect("read the new home"),
        "the raw token travels sealed and lands on the new home (main: nothing carried)"
    );
    assert!(
        booking_rows_hold(&old_home.vault, token.as_bytes()).expect("read the old home"),
        "until the ack the move can be cancelled, so the old home keeps its copy"
    );

    acknowledge_booking_home_move(&old_home.vault).expect("the old home's writer on the ack");
    assert!(
        !booking_rows_hold(&old_home.vault, token.as_bytes()).expect("read the old home"),
        "once the new home acknowledged the move the old home holds no raw token \
         (main: it keeps its copy)"
    );
    new_home
        .pick(delivered(&emergency))
        .expect("the new home's copy still resolves the pick");
}

#[test]
fn an_emergency_whose_delivery_failed_on_the_old_home_is_delivered_by_the_new_home() {
    let seed = Machine::seed();
    let emergency = emergency(&seed, &mut FailingSink);
    assert!(
        emergency.item.is_err(),
        "FIXTURE: the delivery fails, so the emergency stays owed"
    );
    let (old_home, new_home) = seed.into_old_and_new_home();
    assert!(
        move_booking_home(&old_home.vault, &new_home.vault, &[]).expect("move the booking home"),
        "every section applies"
    );

    let resume = |machine: &Machine| {
        execute_emergency_plan(
            &machine.vault,
            &emergency.request,
            &emergency.plan,
            &machine.calendars(),
            &machine.consumer(NOW + 200),
            &mut DeliveringSink,
        )
    };
    assert!(
        resume(&old_home).is_err(),
        "the old home holds history: it resumes nothing"
    );
    let run = resume(&new_home)
        .expect("the new home resumes the owed delivery (main: the instruction is not there)");
    assert!(
        run.item.calendar_delivered && run.item.apology_delivered,
        "the new home delivers what the old home owed"
    );
    assert!(
        !run.item.actions.is_empty(),
        "its pick actions travelled with it"
    );
    assert!(
        run.repeat_notices.is_empty(),
        "a send that failed definitely on the old home never reached the booker: no repeat"
    );
}

#[test]
fn the_new_homes_resume_of_a_send_that_ended_uncertain_on_the_old_home_says_it_may_repeat() {
    let seed = Machine::seed();
    let emergency = emergency(&seed, &mut DeferringSink);
    assert!(
        emergency.item.is_err(),
        "FIXTURE: the provider took the invite as a remote task, so the emergency stays owed"
    );
    let (old_home, new_home) = seed.into_old_and_new_home();
    assert!(
        move_booking_home(&old_home.vault, &new_home.vault, &[]).expect("move the booking home"),
        "every section applies"
    );

    let resume = || {
        execute_emergency_plan(
            &new_home.vault,
            &emergency.request,
            &emergency.plan,
            &new_home.calendars(),
            &new_home.consumer(NOW + 200),
            &mut DeliveringSink,
        )
        .expect("the new home resumes the owed delivery")
    };
    let run = resume();
    assert!(
        run.item.calendar_delivered && run.item.apology_delivered,
        "the new home delivers what the old home owed"
    );
    assert_eq!(
        run.repeat_notices,
        vec![EmergencyRepeatNotice {
            effect: "calendar",
            message: EMERGENCY_REPEAT_NOTICE,
        }],
        "the invite the old home sent uncertain may reach the booker twice; the old home never \
         sent the apology"
    );
    assert_eq!(
        EMERGENCY_REPEAT_NOTICE,
        "this send ended uncertain on the old home and may repeat"
    );
    assert_eq!(
        resume().repeat_notices,
        run.repeat_notices,
        "every later run answers the repeat again, so an answer that never reached the owner is \
         given again (#10166's head 91d09f814167 dropped the mark with its first answer)"
    );
}

#[test]
fn a_repeat_the_owner_was_not_answered_for_travels_with_the_next_move() {
    let seed = Machine::seed();
    let emergency = emergency(&seed, &mut DeferringSink);
    assert!(
        emergency.item.is_err(),
        "FIXTURE: the provider took the invite as a remote task, so the emergency stays owed"
    );
    let (old_home, second_home) = seed.into_old_and_new_home();
    assert!(
        move_booking_home(&old_home.vault, &second_home.vault, &[]).expect("move the booking home"),
        "every section applies"
    );
    let stopped = execute_emergency_plan(
        &second_home.vault,
        &emergency.request,
        &emergency.plan,
        &second_home.calendars(),
        &second_home.consumer(NOW + 200),
        &mut InviteOnlySink,
    );
    assert!(
        stopped.is_err(),
        "FIXTURE: the second home sends the invite again, then its apology fails, so its run \
         answers the owner nothing"
    );

    let (second_home, third_home) = second_home.into_old_and_new_home();
    assert!(
        move_booking_home(&second_home.vault, &third_home.vault, &[])
            .expect("move the booking home again"),
        "every section applies"
    );
    let run = execute_emergency_plan(
        &third_home.vault,
        &emergency.request,
        &emergency.plan,
        &third_home.calendars(),
        &third_home.consumer(NOW + 300),
        &mut DeliveringSink,
    )
    .expect("the third home resumes the owed apology");
    assert!(
        run.item.calendar_delivered && run.item.apology_delivered,
        "the third home delivers what the second home owed"
    );
    assert_eq!(
        run.repeat_notices,
        vec![EmergencyRepeatNotice {
            effect: "calendar",
            message: EMERGENCY_REPEAT_NOTICE,
        }],
        "the second home sent the uncertain invite again and never answered the owner, so the \
         third home's run does (#10125's first head: the delivered invite's mark went at the \
         second move)"
    );
}

#[test]
fn a_repeat_delivered_before_the_bookers_pick_is_answered_by_the_owners_next_run() {
    let seed = Machine::seed();
    let emergency = emergency(&seed, &mut DeferringSink);
    assert!(
        emergency.item.is_err(),
        "FIXTURE: the provider took the invite as a remote task, so the emergency stays owed"
    );
    let (old_home, new_home) = seed.into_old_and_new_home();
    assert!(
        move_booking_home(&old_home.vault, &new_home.vault, &[]).expect("move the booking home"),
        "every section applies"
    );
    let delivered = deliver_emergency_without_answer(
        &new_home.vault,
        &emergency.request,
        &emergency.plan,
        &new_home.calendars(),
        &new_home.consumer(NOW + 200),
        &mut DeliveringSink,
    )
    .expect(
        "FIXTURE: the new home sends the invite again and the apology, and stops before it \
         answers the owner",
    );
    assert!(
        delivered.calendar_delivered && delivered.apology_delivered,
        "both deliveries are committed on the checkpoint"
    );
    new_home
        .pick(&delivered)
        .expect("both deliveries released the booker's pick");

    // A failing sink: the owner's run over the picked checkpoint sends nothing.
    let run = execute_emergency_plan(
        &new_home.vault,
        &emergency.request,
        &emergency.plan,
        &new_home.calendars(),
        &new_home.consumer(NOW + 400),
        &mut FailingSink,
    )
    .expect(
        "the owner's run over the picked checkpoint answers the repeat its delivery left \
         unanswered (#10166's head 7cdc5c16ca1e refuses it first)",
    );
    assert!(run.item.picked().is_some(), "the booker's pick stands");
    assert_eq!(
        run.repeat_notices,
        vec![EmergencyRepeatNotice {
            effect: "calendar",
            message: EMERGENCY_REPEAT_NOTICE,
        }],
        "the invite the old home sent uncertain may reach the booker twice"
    );
    let again = execute_emergency_plan(
        &new_home.vault,
        &emergency.request,
        &emergency.plan,
        &new_home.calendars(),
        &new_home.consumer(NOW + 500),
        &mut FailingSink,
    )
    .expect(
        "the owner's next run over the picked checkpoint answers the repeat again (#10166's head \
         91d09f814167 refuses it: its first answer dropped the mark)",
    );
    assert_eq!(
        again.repeat_notices, run.repeat_notices,
        "an answer that never reached the owner is given again"
    );
}

/// The emergency on a seed through `sink`, its home moved to a second machine and back to the
/// seed before the second machine resumed it, with the adoption recorded there: the former home,
/// the second machine and the emergency.
fn carried_back_to_former_home(
    sink: &mut impl OutboundExecutionSink,
) -> (Machine, Machine, Emergency) {
    let seed = Machine::seed();
    let emergency = emergency(&seed, sink);
    let (former_home, second_home) = seed.into_old_and_new_home();
    assert!(
        move_booking_home(&former_home.vault, &second_home.vault, &[])
            .expect("move the booking home"),
        "every section applies"
    );
    assert!(
        move_booking_home(&second_home.vault, &former_home.vault, &[])
            .expect("move the booking home back before the second home resumed it"),
        "every section applies on the former home"
    );
    record_booking_home_adoption(&former_home.vault)
        .expect("FIXTURE: the former home holds the state it adopted");
    (former_home, second_home, emergency)
}

/// The owner's resume of `emergency` on `machine` through `sink`: its checkpoint, and whether
/// each repeat was answered.
fn resume(
    machine: &Machine,
    emergency: &Emergency,
    sink: &mut impl OutboundExecutionSink,
) -> Result<(EmergencyItem, Vec<EmergencyRepeatNotice>), BookingError> {
    execute_emergency_plan(
        &machine.vault,
        &emergency.request,
        &emergency.plan,
        &machine.calendars(),
        &machine.consumer(NOW + 300),
        sink,
    )
    .map(|run| (run.item, run.repeat_notices))
}

/// The former home's own ledger row of the apology's first send, the one the seed's provider
/// took as a remote task, which the provider then reports completed: delivered after all.
fn first_apology_delivered_after_all(former_home: &Machine) {
    let rows = emergency_effect_ledger_rows(&former_home.vault, "apology")
        .expect("FIXTURE: read the former home's apology rows");
    let [first_send] = rows[..] else {
        panic!("FIXTURE: the former home holds the apology's first send alone: {rows:?}");
    };
    former_home
        .vault
        .settle_remote_outbound_task(&first_send, RemoteTaskObservation::Completed)
        .expect("FIXTURE: the provider reports the first apology's remote task completed");
}

#[test]
fn an_apology_deferred_on_a_former_home_goes_again_when_a_move_carries_it_back() {
    let mut seeding = RecordingSink::new(ApologyDeferringSink);
    let (former_home, _second_home, emergency) = carried_back_to_former_home(&mut seeding);
    assert!(
        emergency.item.is_err(),
        "FIXTURE: the provider took the apology as a remote task, so the emergency stays owed"
    );
    let apology_key = match seeding.keys("email")[..] {
        [key] => key.to_owned(),
        _ => panic!(
            "FIXTURE: the seed sends the apology once: {:?}",
            seeding.sends
        ),
    };

    let mut delivering = RecordingSink::new(DeliveringSink);
    let (item, repeat_notices) = resume(&former_home, &emergency, &mut delivering).expect(
        "the former home resumes the owed apology (#10166's head 6bf877252c85 replays its own \
         deferred apology under the same attempt and refuses every resume)",
    );
    assert!(
        item.calendar_delivered && item.apology_delivered,
        "the former home delivers the apology the second home carried back owed"
    );
    assert!(
        delivering.keys("calendar").is_empty(),
        "the invite the seed delivered is not sent again"
    );
    assert_eq!(
        delivering.keys("email"),
        vec![apology_key.as_str()],
        "the apology goes again once, under the key its first send reached the provider under, \
         so a provider that drops a repeated key can drop it"
    );
    assert_eq!(
        repeat_notices,
        vec![EmergencyRepeatNotice {
            effect: "apology",
            message: EMERGENCY_REPEAT_NOTICE,
        }],
        "the apology the former home sent uncertain may reach the booker twice"
    );
}

#[test]
fn an_invite_deferred_on_a_former_home_is_settled_by_its_own_remote_task() {
    let mut deferring = RecordingSink::new(DeferringSink);
    let (former_home, _second_home, emergency) = carried_back_to_former_home(&mut deferring);
    assert!(
        emergency.item.is_err(),
        "FIXTURE: the provider took the invite as a remote task, so the emergency stays owed"
    );
    let rows = emergency_effect_ledger_rows(&former_home.vault, "calendar")
        .expect("read the former home's invite rows");
    let [invite_send] = rows[..] else {
        panic!("the former home keeps the invite's one row and takes no fresh attempt: {rows:?}");
    };
    former_home
        .vault
        .settle_remote_outbound_task(&invite_send, RemoteTaskObservation::Completed)
        .expect("the provider reports the invite's remote task completed on the former home");

    let mut delivering = RecordingSink::new(DeliveringSink);
    let (item, _) = resume(&former_home, &emergency, &mut delivering)
        .expect("the former home resumes the owed apology once its invite's remote task completed");
    assert!(
        item.calendar_delivered && item.apology_delivered,
        "the invite its own remote task delivered and the apology are delivered"
    );
    assert!(
        delivering.keys("calendar").is_empty(),
        "the invite is never sent again, so no second provider key reaches the provider \
         (#10220's head 091a2032bf6a hands it to the sink again under a fresh ledger row's key)"
    );
    assert_eq!(
        delivering.keys("email").len(),
        1,
        "the former home sends the apology"
    );
}

#[test]
fn an_apology_its_first_send_delivered_after_all_is_not_sent_again_by_the_former_home() {
    let (former_home, _second_home, emergency) =
        carried_back_to_former_home(&mut ApologyDeferringSink);
    first_apology_delivered_after_all(&former_home);

    let mut delivering = RecordingSink::new(DeliveringSink);
    let (item, _) = resume(&former_home, &emergency, &mut delivering)
        .expect("the former home resumes the emergency");
    assert!(
        item.calendar_delivered && item.apology_delivered,
        "the apology its first send delivered is delivered"
    );
    assert!(
        delivering.keys("email").is_empty(),
        "its fresh attempt never goes (#10220's head 091a2032bf6a sends it under that attempt)"
    );
}

#[test]
fn an_apology_its_first_send_delivered_after_all_is_not_sent_by_the_next_home() {
    let (former_home, second_home, emergency) =
        carried_back_to_former_home(&mut ApologyDeferringSink);
    first_apology_delivered_after_all(&former_home);
    assert!(
        move_booking_home(&former_home.vault, &second_home.vault, &[])
            .expect("move the booking home to the second machine again"),
        "every section applies on the second machine"
    );
    record_booking_home_adoption(&second_home.vault)
        .expect("FIXTURE: the second machine holds the state it adopted again");

    let mut delivering = RecordingSink::new(DeliveringSink);
    let (item, _) = resume(&second_home, &emergency, &mut delivering)
        .expect("the second machine resumes the emergency");
    assert!(
        item.calendar_delivered && item.apology_delivered,
        "the move carried the apology delivered"
    );
    assert!(
        delivering.keys("email").is_empty(),
        "the next home never sends the apology the former home's first send delivered \
         (#10220's head 091a2032bf6a reads only the apology's fresh attempt and exports it owed)"
    );
}
