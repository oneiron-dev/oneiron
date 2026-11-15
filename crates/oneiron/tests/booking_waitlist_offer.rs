//! A waitlist offer's one email (census L3-13 PR 3; RULING
//! L3-13-OFFER-CHANNEL = A, Engine 15 Nov 13:42).
//!
//! When a cancel frees a slot, the first waiter whose window holds it is
//! offered the slot by one ordinary `(email, send)` from the page's verified
//! live publisher, through the outbound door, the gate and the intent ledger.
//! The page's standing invite grant covers exactly that send: to the contact
//! of an entry on that same page holding a standing offer, under that offer's
//! own intent. The body names the event type, the slot, the end of the offer
//! and a claim link whose offer token claims the slot as the entry token
//! does. The ruling's red cases: a send to a contact holding no offer, a send
//! to another page's waiter, and a second send of one offer are refused. The
//! send names its offer by the offer token's digest, so the intent the ledger
//! keeps holds no token a claim accepts (OPUS-SECREAD-A N1, 15 Nov).
//!
//! The lifecycle fixture is `tests/booking_waitlist.rs`'s; the publisher's
//! email identity, policy manifest and owner binding are
//! `tests/booking_feed_move_held.rs`'s, with no scoped grant for email, so
//! the page grant is the only authority an offer's send can run under. The
//! built-in pack seed marker goes through a test door, so run it with the
//! lane runner: `RUSTFLAGS="--cfg oneiron_test_support" cargo test -p oneiron
//! --all-features --test booking_waitlist_offer`.
#![cfg(feature = "test-support")]

mod common;

use std::cell::RefCell;

use oneiron::booking::{
    BOOKING_PUBLIC_PAGE_PREDICATE, BOOKING_PUBLIC_PAGE_SCHEMA_VERSION, BookingError,
    BookingLandingContent, BookingLifecycleConsumerInput, BookingLifecycleTurn,
    BookingPagePublication, BookingSolver, BookingVerbReceipt, BookingVerbRequest, CancelSpec,
    ConfirmReceipt, ConfirmSpec, ConstraintFieldConfig, DEFAULT_INTRO_DURATION_MIN, EventTypeCard,
    EventTypeConfig, EventTypeKey, HoldLeaseSpec, HoldSpec, HostAvailabilityConfig,
    OpaqueLifecycleToken, PublicBookingAvailability, PublicBookingPageToken, RoutingMode,
    SessionKey, SlotOracle, SolveRequest, SolveResult, ThemeTokens, VaultActiveHoldSource,
    WaitlistAction, WaitlistClaim, WaitlistJoin, WaitlistReceipt, WaitlistSpec, WeeklyWallWindow,
    booking_config_hash, enqueue_booking_verb, run_booking_lifecycle_attempt_with_invites,
};
use oneiron::channel_identity::{ChannelIdentityBinding, ChannelIdentityState, SelfHeldShape};
use oneiron::memory::ClaimInput;
use oneiron::outbound::{
    OutboundDeliveryWindowDecision, OutboundDispatchActor, OutboundDispatchGate,
    OutboundDispatchRequest, OutboundExecutionOutcome, OutboundExecutionRequest,
    OutboundExecutionSink, OutboundIntent, OutboundIntentDraft, OutboundIntentTrigger,
};
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_PERSON};
use oneiron::{
    CalendarSel, DreamerRunnerStore, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig,
};

/// Monday 2 March 2026, 00:00 UTC.
const MONDAY: u64 = 1_772_409_600;
const NOW: u64 = MONDAY + 8 * 3_600;
const HOUR: u64 = 3_600;

const PAGE_SEED: u8 = 0x51;
const HOST_SEED: u8 = 0x52;
const OTHER_PAGE_SEED: u8 = 0x53;
const OWEN_SEED: u8 = 0x57;
const YUKI_SEED: u8 = 0x58;
const MIKA_SEED: u8 = 0x59;
const KENJI_SEED: u8 = 0x5a;
const BUSY_SEED: u8 = 0x61;
const IDENTITY_SEED: u8 = 0x79;
const POLICY_SEED: u8 = 0x7a;

const OFFER_PREFIX: &str = "booking-waitlist-offer:";
/// The query a claim link carries its offer token in.
const CLAIM_QUERY: &str = "?waitlist_offer=";

const fn at(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

/// `[seed; 16]`; every seed here is outside the production-pinned id bytes.
fn test_id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("fixture id")
}

fn session(name: &str) -> SessionKey {
    SessionKey::derive(name.as_bytes())
}

/// The slot that starts `hours` after Monday midnight. The host works
/// 09:00-14:00 UTC, in 30-minute slots.
fn slot_at(hours: u64) -> TimeRange {
    let start = MONDAY + hours * HOUR;
    TimeRange {
        start,
        end: start + u64::from(DEFAULT_INTRO_DURATION_MIN) * 60,
    }
}

/// One send the sink was asked to deliver.
#[derive(Debug, Clone)]
struct Sent {
    channel: String,
    verb: String,
    target: String,
    intent: OutboundIntent,
}

/// Records every send; fails each one while `fail` is set.
#[derive(Default)]
struct RecordingSink {
    sent: Vec<Sent>,
    fail: bool,
}

impl OutboundExecutionSink for RecordingSink {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        self.sent.push(Sent {
            channel: request.intent.channel.clone(),
            verb: request.intent.verb.clone(),
            target: request.intent.target.clone(),
            intent: request.intent.clone(),
        });
        if self.fail {
            OutboundExecutionOutcome::failed("definite fixture non-delivery")
        } else {
            OutboundExecutionOutcome::delivered_to_channel("provider:message:fixture")
        }
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    host: EntityId,
    node_id: u64,
    sink: RefCell<RecordingSink>,
}

impl Fixture {
    fn open() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
        // Signing doors load this install's keys from a keystore (P6c).
        vault.install_device_keystore(std::sync::Arc::new(
            oneiron_keystore::MemoryKeystore::default(),
        ));
        let host = test_id(HOST_SEED);
        vault
            .put_entity(&host, ENTITY_TYPE_PERSON, at(1), 1, b"host")
            .expect("put host");
        for (seed, address) in [
            (OWEN_SEED, "owen@example.com"),
            (YUKI_SEED, "yuki@example.com"),
            (MIKA_SEED, "mika@example.com"),
            (KENJI_SEED, "kenji@example.com"),
        ] {
            vault
                .put_entity(
                    &test_id(seed),
                    ENTITY_TYPE_PERSON,
                    at(1),
                    1,
                    address.as_bytes(),
                )
                .expect("put a contact");
        }
        for page in [test_id(PAGE_SEED), test_id(OTHER_PAGE_SEED)] {
            vault
                .put_entity(&page, ENTITY_TYPE_ASSET, at(1), 1, b"booking page")
                .expect("put a booking page");
            // A claim is born in its subject's substrate FACET, which only a
            // PERSON's put stores (InvalidFacet, #4389).
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
        }
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        let runner = DreamerRunnerStore::new(&vault);
        let local = runner
            .local_home_node_candidate(true, true, true)
            .expect("local home node candidate");
        let node_id = local.node_id;
        runner
            .elect_home_node(&[local], 1)
            .expect("elect home node");

        // The publisher's one email identity, and a manifest that lets it act
        // with no scoped grant for email: only a page grant covers a send.
        let identity = common::self_held_identity_in_state(
            "email",
            "host@example.test",
            SelfHeldShape::DedicatedAddress,
            ChannelIdentityBinding::agent(host),
            ChannelIdentityState::Active,
            NOW,
        );
        vault
            .create_channel_identity(&test_id(IDENTITY_SEED), &identity)
            .expect("the host's email identity");
        let policy = rmp_serde::to_vec_named(&serde_json::json!({
            "schema_version": "1.2", "pack_id": "waitlist-offer-tests", "pack_version": "v1",
            "min_engine_version": env!("CARGO_PKG_VERSION"),
            "defaults": { "criticality": "normal", "sensitivity": "normal" }, "rules": [],
            "actor_ceilings": [
                { "actor_class": "agent", "actor_ref": host.to_hex(), "ceiling": "auto" },
                { "actor_class": "first_party", "ceiling": "auto" },
                { "actor_class": "human", "ceiling": "auto" }
            ],
            "scoped_grants": []
        }))
        .expect("encode the policy manifest");
        oneiron::test_support::put_policy_manifest_bytes(&vault, test_id(POLICY_SEED), &policy)
            .expect("put the policy manifest");
        oneiron::test_support::bind_host_owner(&vault, &issuer, host)
            .expect("bind the host as the owner");
        // A seeded vault refuses `email` until its built-in pack is installed
        // (OF-519); the pack is not what this test covers.
        oneiron::test_doors::builtin_pack_seed::remove_builtin_pack_seed_marker(&vault)
            .expect("remove the built-in pack seed marker");
        let fixture = Self {
            _dir: dir,
            vault,
            host,
            node_id,
            sink: RefCell::new(RecordingSink::default()),
        };
        // Each publication mints its page's standing invite grant.
        fixture.publish(test_id(PAGE_SEED));
        fixture.publish(test_id(OTHER_PAGE_SEED));
        fixture
    }

    /// Publishes `page` as the owner's own write.
    fn publish(&self, page: EntityId) {
        let publication = BookingPagePublication {
            schema_version: BOOKING_PUBLIC_PAGE_SCHEMA_VERSION,
            published: true,
            event_config_hashes: [(
                event_type().0,
                booking_config_hash(&fixture_config()).expect("config hash"),
            )]
            .into(),
            owner_display: "Page owner".to_owned(),
            event_types: vec![EventTypeCard {
                key: event_type(),
                title: "Intro call".to_owned(),
                duration_min: 30,
                description: "A first call".to_owned(),
            }],
            constraint_field: ConstraintFieldConfig {
                enabled: false,
                placeholder: String::new(),
            },
            theme: ThemeTokens(serde_json::json!({})),
            landing: BookingLandingContent::default(),
            initial_availability: PublicBookingAvailability {
                event_type: event_type(),
                start_after_secs: 86_400,
                window_secs: 86_400,
                visitor_tz: "UTC".to_owned(),
            },
            constraint_front: None,
            sponsor: None,
        };
        let input = ClaimInput {
            id: None,
            predicate: BOOKING_PUBLIC_PAGE_PREDICATE.to_owned(),
            subject_ref: page.to_hex(),
            value: serde_json::to_value(publication).expect("publication"),
            confidence: 1.0,
            source: "user_stated".to_owned(),
            world_ref: None,
            relationship_ref: None,
            scope: None,
            valid_from: Some(1),
            valid_to: Some(real_now() + 86_400),
            occurred_at: None,
            learned_at: None,
            salience: None,
            confidence_details: None,
        };
        let memory = self.vault.memory(self.host, EdgeActorClass::Human);
        let receipt = memory
            .claim_upsert(&input)
            .expect("owner publication write");
        if receipt.approval == "proposed" {
            memory
                .confirm_booking_publication(&receipt.claim_short_id, real_now())
                .expect("owner confirms the publication");
        }
    }

    /// Enqueues one verb and runs exactly that attempt at `now`, carrying
    /// its sends on the fixture's sink.
    fn run(
        &self,
        request: BookingVerbRequest,
        now: u64,
    ) -> Result<BookingVerbReceipt, BookingError> {
        let id = enqueue_booking_verb(&self.vault, request, now)?;
        let mut sink = self.sink.borrow_mut();
        let turn = run_booking_lifecycle_attempt_with_invites(
            &self.vault,
            id,
            |oracle_request| {
                let page = oracle_request
                    .page_ref
                    .expect("the consumer only builds an oracle for a resolved page");
                Ok(LifecycleSolver {
                    page,
                    exclude: oracle_request.exclude_session_key,
                    vault: &self.vault,
                    now,
                })
            },
            &BookingLifecycleConsumerInput {
                local_node_id: self.node_id,
                lease_owner: "booking-lifecycle-worker".to_owned(),
                now_utc: now,
            },
            &mut *sink,
        )?;
        match turn {
            BookingLifecycleTurn::Executed(receipt) => Ok(receipt),
            other => panic!("the home node must execute the queued attempt, got {other:?}"),
        }
    }

    fn book(&self, page: EntityId, booker: u8, slot: TimeRange, now: u64) -> ConfirmReceipt {
        let session_key = session(&format!("booker-{booker}-{}-{}", page.to_hex(), slot.start));
        let held = match self
            .run(
                BookingVerbRequest::Hold(HoldSpec {
                    page_ref: page,
                    event_type: event_type(),
                    slot,
                    session_key,
                    visitor_tz: "UTC".to_owned(),
                    constraint: None,
                    lease: HoldLeaseSpec::Ordinary,
                    idempotency_key: None,
                }),
                now,
            )
            .expect("hold")
        {
            BookingVerbReceipt::Held(hold) => hold,
            other => panic!("expected a hold receipt, got {other:?}"),
        };
        match self
            .run(
                BookingVerbRequest::Confirm(ConfirmSpec {
                    hold_token: held.token,
                    session_key,
                    booker_contact: test_id(booker),
                    intake: Vec::new(),
                    idempotency_key: None,
                }),
                now,
            )
            .expect("confirm")
        {
            BookingVerbReceipt::Confirmed(confirmed) => confirmed,
            other => panic!("expected a confirm receipt, got {other:?}"),
        }
    }

    fn cancel(&self, booking: &ConfirmReceipt, now: u64) {
        let receipt = self
            .run(
                BookingVerbRequest::Cancel(CancelSpec {
                    token: booking.cancel_token.clone(),
                    idempotency_key: None,
                }),
                now,
            )
            .expect("cancel");
        assert!(
            matches!(receipt, BookingVerbReceipt::Cancelled(_)),
            "expected a cancel receipt, got {receipt:?}"
        );
    }

    fn waitlist(
        &self,
        page: EntityId,
        action: WaitlistAction,
        now: u64,
    ) -> Result<BookingVerbReceipt, BookingError> {
        self.run(
            BookingVerbRequest::Waitlist(WaitlistSpec {
                page_ref: page,
                action,
                idempotency_key: None,
            }),
            now,
        )
    }

    /// `waiter` waits on `window` of `page`; answers its entry token.
    fn wait(
        &self,
        page: EntityId,
        waiter: u8,
        window: TimeRange,
        now: u64,
    ) -> OpaqueLifecycleToken {
        match self
            .waitlist(
                page,
                WaitlistAction::Join(WaitlistJoin {
                    event_type: event_type(),
                    window,
                    session_key: session(&format!("waiter-{waiter}")),
                    visitor_tz: "UTC".to_owned(),
                    contact_ref: test_id(waiter),
                }),
                now,
            )
            .expect("join")
        {
            BookingVerbReceipt::Waitlisted(WaitlistReceipt::Joined { token, .. }) => token,
            other => panic!("expected the visitor to wait, got {other:?}"),
        }
    }

    fn claim(
        &self,
        page: EntityId,
        waiter: u8,
        token: &OpaqueLifecycleToken,
        now: u64,
    ) -> Result<BookingVerbReceipt, BookingError> {
        self.waitlist(
            page,
            WaitlistAction::Claim(WaitlistClaim {
                token: token.clone(),
                booker_contact: test_id(waiter),
                intake: Vec::new(),
            }),
            now,
        )
    }

    fn claimed(
        &self,
        page: EntityId,
        waiter: u8,
        token: &OpaqueLifecycleToken,
        now: u64,
    ) -> ConfirmReceipt {
        match self.claim(page, waiter, token, now).expect("claim") {
            BookingVerbReceipt::Waitlisted(WaitlistReceipt::Claimed(receipt)) => receipt,
            other => panic!("expected a claimed booking, got {other:?}"),
        }
    }

    /// Every `(email, send)` the sink was asked to deliver.
    fn emails(&self) -> Vec<Sent> {
        self.sink
            .borrow()
            .sent
            .iter()
            .filter(|sent| sent.channel == "email" && sent.verb == "send")
            .cloned()
            .collect()
    }

    /// The one offer email sent to `address`: its intent, and the offer token
    /// the claim link in its rendered body carries.
    fn offer_to(&self, address: &str) -> (OutboundIntent, OpaqueLifecycleToken) {
        let sent: Vec<Sent> = self
            .emails()
            .into_iter()
            .filter(|sent| sent.target == address)
            .collect();
        assert_eq!(sent.len(), 1, "one offer email to {address}: {sent:?}");
        let intent = sent[0].intent.clone();
        let content_ref = intent.content_ref.clone().expect("an offer names its body");
        let body = self
            .vault
            .outbound_content_text(&content_ref)
            .expect("render the offer body")
            .expect("a standing offer renders its body");
        let (_, token) = body
            .split_once(CLAIM_QUERY)
            .expect("the offer body carries its claim link");
        (intent, OpaqueLifecycleToken(token.trim_end().to_owned()))
    }

    /// Dispatches an `(email, send)` as the publisher, outside any booking
    /// turn: answers the door's error, or the gate outcome it recorded.
    fn send_as_publisher(&self, intent: OutboundIntent, now: u64) -> Result<String, String> {
        let key = intent
            .idempotency_key
            .clone()
            .unwrap_or_else(|| "intent:fixture".to_owned());
        let target = intent.target.clone();
        let request = OutboundDispatchRequest::new(
            format!("outbound:{key}"),
            key,
            intent,
            OutboundDispatchActor::agent(self.host),
            OutboundDispatchGate::allow_when_policy_grants(),
            now,
            OutboundDeliveryWindowDecision::DeliverNow,
        )
        .counterparty_ref(target);
        self.vault
            .dispatch_outbound_intent(request, &mut *self.sink.borrow_mut())
            .map(|result| result.gate_outcome)
            .map_err(|error| error.to_string())
    }

    /// An `(email, send)` from the publisher to `target` with body `content_ref`
    /// under `key`, as an offer's own send is built.
    fn forged(&self, page: EntityId, target: &str, content_ref: &str, key: &str) -> OutboundIntent {
        OutboundIntent::from_trigger(
            OutboundIntentDraft::new(self.host.to_hex(), "send", "email", target.to_owned())
                .content_ref(content_ref.to_owned())
                .idempotency_key(key.to_owned()),
            OutboundIntentTrigger::agent_immediate(format!("booking_waitlist:{}", page.to_hex())),
        )
    }
}

fn real_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_secs()
}

struct LifecycleSolver<'a> {
    page: EntityId,
    exclude: Option<SessionKey>,
    vault: &'a Vault,
    now: u64,
}

impl LifecycleSolver<'_> {
    fn with_solver<T>(&self, run: impl FnOnce(&BookingSolver<'_>) -> T) -> T {
        let holds = match self.exclude {
            Some(key) => VaultActiveHoldSource::excluding(self.vault, key),
            None => VaultActiveHoldSource::new(self.vault),
        };
        let calendars = vec![(test_id(HOST_SEED), vec![CalendarSel { system: None }])];
        run(&BookingSolver {
            vault: self.vault,
            page_ref: self.page,
            calendars_by_host: &calendars,
            holds: &holds,
            now_utc: self.now,
            synthetic_config: Some(fixture_config()),
        })
    }
}

impl SlotOracle for LifecycleSolver<'_> {
    fn solve(&self, req: &SolveRequest) -> Result<SolveResult, BookingError> {
        self.with_solver(|solver| solver.solve(req))
    }

    fn minimum_notice_secs(&self, event_type: &EventTypeKey) -> Result<u64, BookingError> {
        self.with_solver(|solver| solver.minimum_notice_secs(event_type))
    }
}

fn event_type() -> EventTypeKey {
    EventTypeKey("intro-call".to_owned())
}

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

fn refusal(result: Result<BookingVerbReceipt, BookingError>) -> String {
    match result {
        Err(BookingError::InvalidConstraint(detail)) => detail,
        other => panic!("expected a typed refusal, got {other:?}"),
    }
}

/// The page's waiter is offered the freed slot by one email from the
/// publisher. Its body names the event type, the slot, the end of the offer
/// and the claim link, and the link's offer token claims the slot; once
/// claimed, the body renders nothing, a retry with the same token answers the
/// same booking, and the entry token names no entry.
#[test]
fn a_freed_slot_is_offered_by_one_email_whose_link_claims_it() {
    let fixture = Fixture::open();
    let page = test_id(PAGE_SEED);
    let noon = slot_at(12);
    let booking = fixture.book(page, OWEN_SEED, noon, NOW);
    let entry_token = fixture.wait(page, YUKI_SEED, noon, NOW + 10);
    assert!(
        fixture
            .emails()
            .iter()
            .all(|sent| sent.target != "yuki@example.com"),
        "no offer before a slot frees"
    );
    fixture.cancel(&booking, NOW + 60);

    let (intent, offer_token) = fixture.offer_to("yuki@example.com");
    assert_eq!(intent.actor, fixture.host.to_hex(), "sent as the publisher");
    let content_ref = intent.content_ref.clone().expect("body ref");
    let body = fixture
        .vault
        .outbound_content_text(&content_ref)
        .expect("render the offer body")
        .expect("a standing offer renders its body");
    let link = format!(
        "/public/booking/{}?waitlist_offer={}",
        PublicBookingPageToken::for_page(page).0,
        offer_token.0
    );
    for part in [
        "intro-call",
        "2026-03-02T12:00:00Z",
        "2026-03-02T12:30:00Z",
        "Held for you until",
        link.as_str(),
    ] {
        assert!(body.contains(part), "the offer body names {part:?}: {body}");
    }

    let booked = fixture.claimed(page, YUKI_SEED, &offer_token, NOW + 120);
    assert_eq!(
        fixture
            .vault
            .outbound_content_text(&content_ref)
            .expect("render after the claim"),
        None,
        "a claimed offer renders no body, so it is never sent again"
    );
    let again = fixture.claimed(page, YUKI_SEED, &offer_token, NOW + 130);
    assert_eq!(again.calendar.event_ref, booked.calendar.event_ref);
    assert!(
        refusal(fixture.claim(page, YUKI_SEED, &entry_token, NOW + 140))
            .contains("no waitlist entry"),
        "the entry token names nothing once the offer token claimed the slot"
    );
}

/// RED 1: a send that names an offer reaches only that offer's waiter, and
/// the page grant covers no plain email to a waiter holding no offer.
#[test]
fn a_waitlist_offer_send_to_a_contact_holding_no_offer_is_refused() {
    let fixture = Fixture::open();
    let page = test_id(PAGE_SEED);
    let noon = slot_at(12);
    let booking = fixture.book(page, OWEN_SEED, noon, NOW);
    fixture.wait(page, YUKI_SEED, noon, NOW + 10);
    fixture.wait(page, MIKA_SEED, noon, NOW + 20);
    fixture.cancel(&booking, NOW + 60);
    let (offer, _) = fixture.offer_to("yuki@example.com");
    let before = fixture.emails().len();

    let content_ref = offer.content_ref.clone().expect("body ref");
    let key = offer.idempotency_key.clone().expect("offer key");
    let redirected = fixture.forged(page, "mika@example.com", &content_ref, &key);
    assert!(
        fixture.send_as_publisher(redirected, NOW + 70).is_err(),
        "yuki's offer never goes to mika"
    );
    let plain = fixture.forged(
        page,
        "mika@example.com",
        "content:fixture",
        "intent:plain-mika",
    );
    assert_ne!(
        fixture.send_as_publisher(plain, NOW + 80).as_deref(),
        Ok("allow"),
        "the page grant covers no plain email to a waiter holding no offer"
    );
    assert_eq!(fixture.emails().len(), before, "nothing more was sent");
}

/// RED 2: one page's grant never carries an offer to another page's waiter.
#[test]
fn a_send_to_another_pages_waiter_is_refused() {
    let fixture = Fixture::open();
    let page = test_id(PAGE_SEED);
    let other = test_id(OTHER_PAGE_SEED);
    let noon = slot_at(12);
    let here = fixture.book(page, OWEN_SEED, noon, NOW);
    let there = fixture.book(other, OWEN_SEED, noon, NOW + 1);
    fixture.wait(page, YUKI_SEED, noon, NOW + 10);
    fixture.wait(other, KENJI_SEED, noon, NOW + 20);
    fixture.cancel(&here, NOW + 60);
    fixture.cancel(&there, NOW + 61);
    let (yuki_offer, _) = fixture.offer_to("yuki@example.com");
    let (kenji_offer, _) = fixture.offer_to("kenji@example.com");
    let before = fixture.emails().len();

    // Kenji's offer named under this page's grant.
    let kenji_ref = kenji_offer.content_ref.clone().expect("body ref");
    let (_, kenji_digest) = kenji_ref
        .strip_prefix(OFFER_PREFIX)
        .and_then(|rest| rest.split_once(':'))
        .expect("an offer body ref names its page and its offer");
    let crossed = format!("{OFFER_PREFIX}{}:{kenji_digest}", page.to_hex());
    let kenji_key = kenji_offer.idempotency_key.clone().expect("offer key");
    for intent in [
        fixture.forged(page, "kenji@example.com", &crossed, &kenji_key),
        fixture.forged(
            page,
            "kenji@example.com",
            &yuki_offer.content_ref.clone().expect("body ref"),
            &yuki_offer.idempotency_key.clone().expect("offer key"),
        ),
    ] {
        assert!(
            fixture.send_as_publisher(intent, NOW + 70).is_err(),
            "this page's grant never carries an offer to the other page's waiter"
        );
    }
    let plain = fixture.forged(
        page,
        "kenji@example.com",
        "content:fixture",
        "intent:plain-kenji",
    );
    assert_ne!(
        fixture.send_as_publisher(plain, NOW + 80).as_deref(),
        Ok("allow"),
        "a plain email to the other page's waiter is not the page grant's either"
    );
    assert_eq!(fixture.emails().len(), before, "nothing more was sent");
}

/// RED 3: one offer is one send. Its own intent again sends nothing new, a
/// second send of it under any other intent is refused, and a second freed
/// slot goes to the next waiter, never to the entry that holds an offer.
#[test]
fn a_second_offer_send_to_the_same_entry_is_refused() {
    let fixture = Fixture::open();
    let page = test_id(PAGE_SEED);
    let noon = slot_at(12);
    let half_past = TimeRange {
        start: noon.end,
        end: noon.end + 30 * 60,
    };
    let window = TimeRange {
        start: noon.start,
        end: half_past.end,
    };
    let first = fixture.book(page, OWEN_SEED, noon, NOW);
    let second = fixture.book(page, OWEN_SEED, half_past, NOW + 1);
    fixture.wait(page, YUKI_SEED, window, NOW + 10);
    fixture.wait(page, MIKA_SEED, window, NOW + 20);
    fixture.cancel(&first, NOW + 60);
    let (offer, _) = fixture.offer_to("yuki@example.com");
    fixture.cancel(&second, NOW + 70);
    fixture.offer_to("yuki@example.com");
    fixture.offer_to("mika@example.com");
    let before = fixture.emails().len();

    let _ = fixture.send_as_publisher(offer.clone(), NOW + 80);
    let content_ref = offer.content_ref.clone().expect("body ref");
    let again = fixture.forged(
        page,
        "yuki@example.com",
        &content_ref,
        "intent:second-offer",
    );
    assert!(
        fixture.send_as_publisher(again, NOW + 90).is_err(),
        "a second send of one offer is refused"
    );
    assert_eq!(fixture.emails().len(), before, "one offer, one email");
}

/// An offer's send names its offer by the offer token's digest: the intent
/// the ledger, its replay rows and its receipts keep holds no token a claim
/// accepts (OPUS-SECREAD-A N1, 15 Nov). The token is only in the body.
#[test]
fn an_offer_send_holds_no_claim_token() {
    let fixture = Fixture::open();
    let page = test_id(PAGE_SEED);
    let noon = slot_at(12);
    let booking = fixture.book(page, OWEN_SEED, noon, NOW);
    let entry_token = fixture.wait(page, YUKI_SEED, noon, NOW + 10);
    fixture.cancel(&booking, NOW + 60);

    let (intent, offer_token) = fixture.offer_to("yuki@example.com");
    let frozen = format!("{intent:?}");
    for token in [&offer_token, &entry_token] {
        assert!(
            !frozen.contains(&token.0),
            "the offer's intent holds no claim token: {frozen}"
        );
    }
    fixture.claimed(page, YUKI_SEED, &offer_token, NOW + 120);
}

/// A send that fails never fails the cancel that freed the slot: the offer
/// stands, and the waiter claims it with the entry token.
#[test]
fn a_failed_offer_send_never_fails_the_cancel() {
    let fixture = Fixture::open();
    let page = test_id(PAGE_SEED);
    let noon = slot_at(12);
    let booking = fixture.book(page, OWEN_SEED, noon, NOW);
    let entry_token = fixture.wait(page, YUKI_SEED, noon, NOW + 10);
    fixture.sink.borrow_mut().fail = true;
    fixture.cancel(&booking, NOW + 60);
    fixture.sink.borrow_mut().fail = false;
    assert!(
        fixture
            .emails()
            .iter()
            .any(|sent| sent.target == "yuki@example.com"),
        "the offer email was attempted"
    );
    fixture.claimed(page, YUKI_SEED, &entry_token, NOW + 120);
}
