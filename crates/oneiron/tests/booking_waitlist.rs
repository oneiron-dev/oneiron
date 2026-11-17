//! The waitlist on full slots (ARCH-0062 §7, census L3-13; RULINGs L3-13
//! OFFER = A and WINDOW = B, owner 15 Nov 01:01).
//!
//! A visitor waits on a closed window. A cancel or a move frees its slot to
//! the first waiter whose window holds it: the slot is held for that waiter
//! for two hours, or until the event type's notice cutoff when that comes
//! sooner, and the waiter books it with the entry token. A lapsed offer
//! passes to the next waiter.
//!
//! A standalone file with a trimmed copy of the booking lifecycle fixture
//! (`tests/booking_calendar_cancel_reschedule.rs`), because the `it` target
//! does not compile on main. Its solver reads the clock of each run, so an
//! offer can lapse. Run with `cargo test -p oneiron --all-features --test
//! booking_waitlist`.
#![cfg(feature = "test-support")]

use oneiron::booking::lifecycle::enqueue_booking_verb_with_publication;
use oneiron::booking::lifecycle::waitlist_entry_event_type;
use oneiron::booking::publication::PublicBookingAuthority;
use oneiron::booking::{
    BOOKING_EVENT_TYPE_PREDICATE, BOOKING_EVENT_TYPE_SCHEMA_VERSION, BOOKING_PUBLIC_PAGE_PREDICATE,
    BOOKING_PUBLIC_PAGE_SCHEMA_VERSION, BookingEventTypeClaimValue, BookingLandingContent,
    BookingPagePublication, ConstraintFieldConfig, EventTypeCard, PublicBookingAvailability,
    ThemeTokens, booking_config_hash, encode_event_type_claim_value, load_public_booking_page,
};
use oneiron::booking::{
    BookingError, BookingLifecycleConsumerInput, BookingLifecycleTurn, BookingSolver,
    BookingVerbReceipt, BookingVerbRequest, CancelSpec, ConfirmReceipt, ConfirmSpec,
    DEFAULT_INTRO_DURATION_MIN, EventTypeConfig, EventTypeKey, HoldLeaseSpec, HoldReceipt,
    HoldSpec, HostAvailabilityConfig, OpaqueLifecycleToken, RankedSlot, RescheduleSpec,
    RoutingMode, SessionKey, SlotOracle, SolveRequest, SolveResult, VaultActiveHoldSource,
    WAITLIST_OFFER_TTL_SECS, WaitlistAction, WaitlistClaim, WaitlistJoin, WaitlistReceipt,
    WaitlistSpec, WeeklyWallWindow, run_booking_lifecycle_attempt,
};
use oneiron::memory::ClaimInput;
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_PERSON};
use oneiron::{
    CalendarSel, ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject,
    DreamerHomeNodeCandidate, DreamerRunnerStore, EdgeActorClass, EntityId, TimeRange, Vault,
    VaultConfig,
};

const MONDAY: u64 = 1_772_409_600;
const NOW: u64 = MONDAY + 8 * 3_600;
const HOUR: u64 = 3_600;

const PAGE_SEED: u8 = 0x51;
const HOST_SEED: u8 = 0x52;
const BOOKER_SEED: u8 = 0x57;
const BUSY_SEED: u8 = 0x61;
const EVENT_TYPE_CLAIM_SEED: u8 = 0x72;
const HOME_NODE_ID: u64 = 9;

const fn at(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

/// `[seed; 16]`; every seed here is outside the production-pinned id bytes.
fn test_id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("fixture id")
}

/// The wall clock: a publication's validity window and its checks read it.
fn wall_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_secs()
}

fn session(name: &str) -> SessionKey {
    SessionKey::derive(name.as_bytes())
}

/// The slot of the fixture's event type that starts `hours` after Monday
/// midnight. The host works 09:00-14:00 UTC, in 30-minute slots.
fn slot_at(hours: u64) -> TimeRange {
    let start = MONDAY + hours * HOUR;
    TimeRange {
        start,
        end: start + u64::from(DEFAULT_INTRO_DURATION_MIN) * 60,
    }
}

const fn half_hour_after(start: u64) -> u64 {
    start + 30 * 60
}

struct Fixture {
    dir: tempfile::TempDir,
    vault: Vault,
    page: EntityId,
    booker: EntityId,
    notice_secs: u64,
}

impl Fixture {
    fn open() -> Self {
        Self::with_notice(0)
    }

    fn with_notice(notice_secs: u64) -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
        Self::seeded(dir, vault, notice_secs)
    }

    /// A vault that can take a checkpoint and be restored over: its vault
    /// key is minted in a keystore, and the vault sits beside the directory's
    /// checkpoint image and restore target.
    fn restorable() -> Self {
        let dir = oneiron::test_support::restore_tempdir();
        let vault =
            Vault::open(dir.path().join("vault"), VaultConfig::device()).expect("open vault");
        vault.install_device_keystore(std::sync::Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault.ensure_vault_key().expect("mint the vault data key");
        Self::seeded(dir, vault, 0)
    }

    fn seeded(dir: tempfile::TempDir, vault: Vault, notice_secs: u64) -> Self {
        let page = test_id(PAGE_SEED);
        vault
            .put_entity(&page, ENTITY_TYPE_ASSET, at(1), 1, b"booking page")
            .expect("put booking page");
        vault
            .put_entity(&test_id(HOST_SEED), ENTITY_TYPE_PERSON, at(1), 1, b"host")
            .expect("put host");
        let booker = test_id(BOOKER_SEED);
        vault
            .put_entity(&booker, ENTITY_TYPE_PERSON, at(1), 1, b"yuki@example.com")
            .expect("put booker");
        DreamerRunnerStore::new(&vault)
            .elect_home_node(
                &[DreamerHomeNodeCandidate::always_on_local(HOME_NODE_ID)],
                1,
            )
            .expect("elect home node");
        Self {
            dir,
            vault,
            page,
            booker,
            notice_secs,
        }
    }

    /// Enqueues one verb and runs exactly that attempt at `now`, with a
    /// solver whose clock is `now` too.
    fn run(
        &self,
        request: BookingVerbRequest,
        now: u64,
    ) -> Result<BookingVerbReceipt, BookingError> {
        self.run_with_publication(request, now, None)
    }

    /// [`Self::run`] for a visitor's request on the published page: the
    /// attempt carries the page's publication, and its writer rechecks it.
    fn run_with_publication(
        &self,
        request: BookingVerbRequest,
        now: u64,
        public_authority: Option<&PublicBookingAuthority>,
    ) -> Result<BookingVerbReceipt, BookingError> {
        let id = enqueue_booking_verb_with_publication(
            &self.vault,
            request,
            now,
            public_authority.cloned(),
        )?;
        let turn = run_booking_lifecycle_attempt(
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
                    notice_secs: self.notice_secs,
                })
            },
            &BookingLifecycleConsumerInput {
                local_node_id: HOME_NODE_ID,
                lease_owner: "booking-lifecycle-worker".to_owned(),
                now_utc: now,
            },
        )?;
        match turn {
            BookingLifecycleTurn::Executed(receipt) => Ok(receipt),
            other => panic!("the home node must execute the queued attempt, got {other:?}"),
        }
    }

    /// What a visitor with no hold of its own is offered on Monday at `now`.
    fn offered_at(&self, now: u64) -> Vec<TimeRange> {
        LifecycleSolver {
            page: self.page,
            exclude: None,
            vault: &self.vault,
            now,
            notice_secs: self.notice_secs,
        }
        .solve(&SolveRequest {
            event_type: event_type(),
            window: TimeRange {
                start: MONDAY,
                end: MONDAY + 86_399,
            },
            constraint: None,
            visitor_tz: "UTC".to_owned(),
        })
        .expect("solve the fixture day")
        .slots
        .iter()
        .map(slot_of)
        .collect()
    }

    fn hold(&self, session_key: SessionKey, slot: TimeRange, now: u64) -> HoldReceipt {
        match self
            .run(
                BookingVerbRequest::Hold(HoldSpec {
                    page_ref: self.page,
                    event_type: event_type(),
                    slot,
                    session_key,
                    visitor_tz: "UTC".to_owned(),
                    constraint: None,
                    lease: HoldLeaseSpec::Ordinary,
                    idempotency_key: None,
                    cap_override: None,
                }),
                now,
            )
            .expect("hold")
        {
            BookingVerbReceipt::Held(hold) => hold,
            other => panic!("expected a hold receipt, got {other:?}"),
        }
    }

    fn book(&self, session_key: SessionKey, slot: TimeRange, now: u64) -> ConfirmReceipt {
        let hold = self.hold(session_key, slot, now);
        match self
            .run(
                BookingVerbRequest::Confirm(ConfirmSpec {
                    hold_token: hold.token,
                    session_key,
                    booker_contact: self.booker,
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
        action: WaitlistAction,
        now: u64,
    ) -> Result<BookingVerbReceipt, BookingError> {
        self.waitlist_with_publication(action, now, None)
    }

    fn waitlist_with_publication(
        &self,
        action: WaitlistAction,
        now: u64,
        public_authority: Option<&PublicBookingAuthority>,
    ) -> Result<BookingVerbReceipt, BookingError> {
        self.run_with_publication(
            BookingVerbRequest::Waitlist(WaitlistSpec {
                page_ref: self.page,
                action,
                idempotency_key: None,
            }),
            now,
            public_authority,
        )
    }

    /// Publishes the page as the vault's embedded owner, with the fixture's
    /// event type, and answers the authority a visitor's request carries.
    fn publish(&self) -> PublicBookingAuthority {
        let config = fixture_config(self.notice_secs);
        let value = encode_event_type_claim_value(&BookingEventTypeClaimValue {
            schema_version: BOOKING_EVENT_TYPE_SCHEMA_VERSION,
            page_ref: self.page,
            config: config.clone(),
        })
        .expect("event type value");
        let mut body = ClaimBody::new(
            BOOKING_EVENT_TYPE_PREDICATE,
            ClaimSubject::Entity(self.page),
            value,
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )
        .expect("event type claim");
        // A claim about the ASSET page is born under the vault's default
        // facet: the constructor's derived facet names no stored FACET.
        body.scope_facet = self.vault.default_facet().expect("default facet");
        self.vault
            .put_claim(&test_id(EVENT_TYPE_CLAIM_SEED), &body, at(1), 1)
            .expect("event type claim");
        let publication = BookingPagePublication {
            schema_version: BOOKING_PUBLIC_PAGE_SCHEMA_VERSION,
            published: true,
            owner_display: "Page owner".to_owned(),
            event_types: vec![EventTypeCard {
                key: event_type(),
                title: "Intro call".to_owned(),
                duration_min: u32::from(config.duration_min),
                description: "A first call".to_owned(),
            }],
            event_config_hashes: [(
                event_type().0,
                booking_config_hash(&config).expect("config hash"),
            )]
            .into(),
            constraint_field: ConstraintFieldConfig {
                enabled: false,
                placeholder: String::new(),
            },
            constraint_front: None,
            theme: ThemeTokens(serde_json::json!({})),
            landing: BookingLandingContent::default(),
            initial_availability: PublicBookingAvailability {
                event_type: event_type(),
                start_after_secs: 86_400,
                window_secs: 86_400,
                visitor_tz: "UTC".to_owned(),
            },
            sponsor: None,
        };
        // The vault has no authority root, so the one actor whose owner
        // write it admits is its own live embedded owner.
        let owner = self
            .vault
            .ensure_embedded_owner_actor()
            .expect("embedded owner");
        let memory = self.vault.memory(owner, EdgeActorClass::Human);
        let receipt = memory
            .claim_upsert(&ClaimInput {
                id: None,
                predicate: BOOKING_PUBLIC_PAGE_PREDICATE.to_owned(),
                subject_ref: self.page.to_hex(),
                value: serde_json::to_value(publication).expect("publication"),
                confidence: 1.0,
                source: "user_stated".to_owned(),
                world_ref: None,
                relationship_ref: None,
                scope: None,
                valid_from: Some(1),
                valid_to: Some(wall_now() + 15 * 86_400),
                occurred_at: None,
                learned_at: None,
                salience: None,
                confidence_details: None,
            })
            .expect("owner publication write");
        if receipt.approval == "proposed" {
            memory
                .confirm_booking_publication(&receipt.claim_short_id, wall_now())
                .expect("owner confirms the publication");
        }
        let publication = load_public_booking_page(&self.vault, self.page, wall_now())
            .expect("read the publication")
            .expect("the page is published");
        PublicBookingAuthority {
            page_ref: self.page,
            publication,
        }
    }

    fn join(&self, session_key: SessionKey, window: TimeRange, now: u64) -> WaitlistReceipt {
        match self
            .waitlist(
                WaitlistAction::Join(WaitlistJoin {
                    event_type: event_type(),
                    window,
                    session_key,
                    visitor_tz: "UTC".to_owned(),
                    contact_ref: self.booker,
                }),
                now,
            )
            .expect("join")
        {
            BookingVerbReceipt::Waitlisted(receipt) => receipt,
            other => panic!("expected a waitlist receipt, got {other:?}"),
        }
    }

    /// Joins and expects an entry; answers its token and position.
    fn wait(
        &self,
        session_key: SessionKey,
        window: TimeRange,
        now: u64,
    ) -> (OpaqueLifecycleToken, u32) {
        match self.join(session_key, window, now) {
            WaitlistReceipt::Joined { token, position } => (token, position),
            other => panic!("expected the visitor to wait, got {other:?}"),
        }
    }

    fn claim(
        &self,
        token: &OpaqueLifecycleToken,
        now: u64,
    ) -> Result<BookingVerbReceipt, BookingError> {
        self.waitlist(
            WaitlistAction::Claim(WaitlistClaim {
                token: token.clone(),
                booker_contact: self.booker,
                intake: Vec::new(),
            }),
            now,
        )
    }

    fn claimed(&self, token: &OpaqueLifecycleToken, now: u64) -> ConfirmReceipt {
        match self.claim(token, now).expect("claim") {
            BookingVerbReceipt::Waitlisted(WaitlistReceipt::Claimed(receipt)) => receipt,
            other => panic!("expected a claimed booking, got {other:?}"),
        }
    }
}

struct LifecycleSolver<'a> {
    page: EntityId,
    exclude: Option<SessionKey>,
    vault: &'a Vault,
    now: u64,
    notice_secs: u64,
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
            synthetic_config: Some(fixture_config(self.notice_secs)),
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

fn fixture_config(min_notice_secs: u64) -> EventTypeConfig {
    EventTypeConfig {
        key: event_type(),
        duration_min: DEFAULT_INTRO_DURATION_MIN,
        slot_step_min: 30,
        pre_buffer_min: 0,
        post_buffer_min: 0,
        min_notice_secs,
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
        flex_with_ordinary: false,
        flex_windows: Vec::new(),
    }
}

fn slot_of(ranked: &RankedSlot) -> TimeRange {
    TimeRange {
        start: ranked.start_utc,
        end: ranked.end_utc,
    }
}

fn refusal(result: Result<BookingVerbReceipt, BookingError>) -> String {
    match result {
        Err(BookingError::InvalidConstraint(detail)) => detail,
        other => panic!("expected a typed refusal, got {other:?}"),
    }
}

#[test]
fn a_closed_window_takes_a_waiter_and_a_cancel_offers_it_the_slot() {
    let fixture = Fixture::open();
    let noon = slot_at(12);
    let first = fixture.book(session("owen"), noon, NOW);

    let (token, position) = fixture.wait(session("yuki"), noon, NOW + 10);
    assert_eq!(position, 1, "the first waiter on the window");

    fixture.cancel(&first, NOW + 60);
    assert!(
        !fixture.offered_at(NOW + 70).contains(&noon),
        "the freed slot is held for the waiter, not offered to everyone"
    );

    // The waiter comes back in a new session: the entry token proves it.
    let booked = fixture.claimed(&token, NOW + 120);
    assert_ne!(
        booked.calendar.event_ref, first.calendar.event_ref,
        "the claim is a new booking"
    );
    assert!(
        !fixture.offered_at(NOW + 130).contains(&noon),
        "the claimed slot is booked"
    );
    let again = fixture.claimed(&token, NOW + 140);
    assert_eq!(
        again.calendar, booked.calendar,
        "a retried claim answers the booking the first claim made"
    );
    assert_eq!(again.cancel_token, booked.cancel_token);
}

#[test]
fn an_open_window_answers_slots_and_writes_no_entry() {
    let fixture = Fixture::open();
    let noon = slot_at(12);
    let window = TimeRange {
        start: noon.start,
        end: half_hour_after(noon.end),
    };
    match fixture.join(session("yuki"), window, NOW) {
        WaitlistReceipt::Open { alternatives } => {
            let offered: Vec<TimeRange> = alternatives.iter().map(slot_of).collect();
            assert!(
                offered.contains(&noon),
                "the open slot is offered: {offered:?}"
            );
            assert!(
                offered
                    .iter()
                    .all(|slot| window.start <= slot.start && slot.end <= window.end),
                "only slots inside the window: {offered:?}"
            );
        }
        other => panic!("an open window must answer its slots, got {other:?}"),
    }

    // Nobody waits, so a later cancel holds the slot for nobody.
    let booking = fixture.book(session("owen"), noon, NOW + 10);
    fixture.cancel(&booking, NOW + 60);
    assert!(fixture.offered_at(NOW + 70).contains(&noon));
    let unknown = OpaqueLifecycleToken("0".repeat(64));
    assert!(
        refusal(fixture.waitlist(WaitlistAction::Leave { token: unknown }, NOW + 80))
            .contains("no waitlist entry"),
    );
}

#[test]
fn waiters_are_offered_in_join_order_and_an_expired_offer_passes_on() {
    let fixture = Fixture::open();
    let noon = slot_at(12);
    let first = fixture.book(session("owen"), noon, NOW);
    let (yuki, yuki_position) = fixture.wait(session("yuki"), noon, NOW + 10);
    let (mika, mika_position) = fixture.wait(session("mika"), noon, NOW + 20);
    assert_eq!((yuki_position, mika_position), (1, 2), "join order");

    fixture.cancel(&first, NOW + 60);
    assert!(
        refusal(fixture.claim(&mika, NOW + 100)).contains("holds no offered slot"),
        "the second waiter has no offer while the first one's stands"
    );

    // The first waiter lets the offer lapse; the next waitlist writer on the
    // page passes the slot to the second, and the first can no longer claim.
    let lapsed = NOW + 60 + WAITLIST_OFFER_TTL_SECS + 1;
    let booked = fixture.claimed(&mika, lapsed);
    assert!(!fixture.offered_at(lapsed + 10).contains(&noon));
    assert!(refusal(fixture.claim(&yuki, lapsed + 20)).contains("no waitlist entry"));
    assert_ne!(booked.calendar.event_ref, first.calendar.event_ref);
}

#[test]
fn an_offer_ends_at_the_notice_cutoff() {
    // Notice one hour: an offer made at 08:01 for the 09:30 slot ends at
    // 08:30, before its two hours.
    let slot = TimeRange {
        start: MONDAY + 9 * HOUR + 30 * 60,
        end: MONDAY + 10 * HOUR,
    };
    for (claim_at, books) in [(NOW + 29 * 60, true), (NOW + 31 * 60, false)] {
        let fixture = Fixture::with_notice(HOUR);
        let first = fixture.book(session("owen"), slot, NOW);
        let (token, _) = fixture.wait(session("yuki"), slot, NOW + 10);
        fixture.cancel(&first, NOW + 60);
        let claimed = fixture.claim(&token, claim_at);
        if books {
            assert!(
                matches!(
                    claimed,
                    Ok(BookingVerbReceipt::Waitlisted(WaitlistReceipt::Claimed(_)))
                ),
                "inside the cutoff the offer stands: {claimed:?}"
            );
        } else {
            assert!(
                refusal(claimed).contains("no waitlist entry"),
                "past the cutoff the offer has ended with its entry"
            );
        }
    }
}

#[test]
fn a_waiter_who_left_is_never_offered() {
    let fixture = Fixture::open();
    let noon = slot_at(12);
    let first = fixture.book(session("owen"), noon, NOW);
    let (token, _) = fixture.wait(session("yuki"), noon, NOW + 10);
    assert_eq!(
        fixture
            .waitlist(
                WaitlistAction::Leave {
                    token: token.clone()
                },
                NOW + 20
            )
            .expect("leave"),
        BookingVerbReceipt::Waitlisted(WaitlistReceipt::Left)
    );

    fixture.cancel(&first, NOW + 60);
    assert!(
        fixture.offered_at(NOW + 70).contains(&noon),
        "with nobody waiting the freed slot is everyone's again"
    );
    assert!(refusal(fixture.claim(&token, NOW + 80)).contains("no waitlist entry"));
}

#[test]
fn a_moved_booking_offers_its_old_slot() {
    let fixture = Fixture::open();
    let noon = slot_at(12);
    let one = slot_at(13);
    let first = fixture.book(session("owen"), noon, NOW);
    let (token, _) = fixture.wait(session("yuki"), noon, NOW + 10);

    let moved = fixture
        .run(
            BookingVerbRequest::Reschedule(RescheduleSpec {
                token: first.reschedule_token.clone(),
                new_slot: one,
                visitor_tz: "UTC".to_owned(),
                constraint: None,
                idempotency_key: None,
            }),
            NOW + 60,
        )
        .expect("reschedule");
    assert!(matches!(moved, BookingVerbReceipt::Rescheduled(_)));

    let offered = fixture.offered_at(NOW + 70);
    assert!(
        !offered.contains(&noon) && !offered.contains(&one),
        "the old slot is held for the waiter and the new one is booked: {offered:?}"
    );
    fixture.claimed(&token, NOW + 80);
}

#[test]
fn a_join_never_says_why_a_window_is_closed() {
    let fixture = Fixture::open();
    // Closed by a booking, by another visitor's live hold, and by the hours.
    let noon = slot_at(12);
    fixture.book(session("owen"), noon, NOW);
    let half_past_one = TimeRange {
        start: MONDAY + 13 * HOUR + 30 * 60,
        end: MONDAY + 14 * HOUR,
    };
    fixture.hold(session("mika"), half_past_one, NOW);
    let evening = TimeRange {
        start: MONDAY + 15 * HOUR,
        end: MONDAY + 16 * HOUR,
    };
    for (name, window) in [("ines", noon), ("ravi", half_past_one), ("tomo", evening)] {
        assert!(
            matches!(
                fixture.join(session(name), window, NOW + 10),
                WaitlistReceipt::Joined { position: 1, .. }
            ),
            "every closed window answers one wait, whatever closed it"
        );
    }
}

#[test]
fn a_second_join_from_one_session_replaces_its_entry() {
    let fixture = Fixture::open();
    let noon = slot_at(12);
    fixture.book(session("owen"), noon, NOW);
    let (first, _) = fixture.wait(session("yuki"), noon, NOW + 10);
    let (second, position) = fixture.wait(session("yuki"), noon, NOW + 20);
    assert_eq!(
        position, 1,
        "the session's own first entry is gone, not ahead"
    );
    assert!(
        refusal(fixture.waitlist(WaitlistAction::Leave { token: first }, NOW + 30))
            .contains("no waitlist entry")
    );
    assert_eq!(
        fixture
            .waitlist(WaitlistAction::Leave { token: second }, NOW + 40)
            .expect("leave"),
        BookingVerbReceipt::Waitlisted(WaitlistReceipt::Left)
    );
}

/// A restore over the live vault keeps the waitlist as it stands (ARCH-0038):
/// an entry is its waiter's own ask to be offered a slot. A waiter who left
/// after the checkpoint stays gone, and so does the offer it held, so no
/// ended offer stands again for its email to be sent; a waiter who joined
/// after the checkpoint keeps its place.
#[test]
fn a_restore_keeps_the_waitlist_as_it_stands() {
    let fixture = Fixture::restorable();
    let noon = slot_at(12);
    let one = slot_at(13);
    let first = fixture.book(session("owen"), noon, NOW);
    fixture.book(session("kenji"), one, NOW + 5);
    let (left, _) = fixture.wait(session("yuki"), noon, NOW + 10);
    // The cancel offers noon to the waiter: its entry holds a standing offer.
    fixture.cancel(&first, NOW + 60);
    let key = fixture.vault.checkpoint_key().expect("the checkpoint key");
    let image = fixture.dir.path().join("image");
    fixture
        .vault
        .snapshot_checkpoint(&image, NOW + 70)
        .expect("a checkpoint while the offer stands");

    assert_eq!(
        fixture
            .waitlist(
                WaitlistAction::Leave {
                    token: left.clone()
                },
                NOW + 80
            )
            .expect("leave"),
        BookingVerbReceipt::Waitlisted(WaitlistReceipt::Left)
    );
    let (joined, _) = fixture.wait(session("mika"), one, NOW + 90);

    let (restored, _) = Vault::restore_checkpoint_keeping_authority(
        &image,
        &key,
        &fixture.dir.path().join("restored"),
        VaultConfig::device(),
        &fixture.vault,
        NOW + 100,
    )
    .expect("restore the checkpoint over the live vault");
    assert_eq!(
        waitlist_entry_event_type(&restored, fixture.page, &left).expect("read the left entry"),
        None,
        "a waiter who left after the checkpoint stays gone, with the offer it held"
    );
    assert_eq!(
        waitlist_entry_event_type(&restored, fixture.page, &joined).expect("read the new entry"),
        Some(event_type()),
        "a waiter who joined after the checkpoint keeps its place"
    );
}

#[test]
fn a_visitor_leaves_through_the_published_page_and_its_offer_is_freed() {
    let fixture = Fixture::open();
    let authority = fixture.publish();
    let noon = slot_at(12);
    let first = fixture.book(session("owen"), noon, NOW);
    let joined = fixture
        .waitlist_with_publication(
            WaitlistAction::Join(WaitlistJoin {
                event_type: event_type(),
                window: noon,
                session_key: session("yuki"),
                visitor_tz: "UTC".to_owned(),
            }),
            NOW + 10,
            Some(&authority),
        )
        .expect("a join on the published page");
    let BookingVerbReceipt::Waitlisted(WaitlistReceipt::Joined { token, position: 1 }) = joined
    else {
        panic!("expected the visitor to wait first, got {joined:?}");
    };
    fixture.cancel(&first, NOW + 60);
    assert!(
        !fixture.offered_at(NOW + 70).contains(&noon),
        "the freed slot is held for the waiter"
    );

    // The leave deletes the entry its publication scope was read from; the
    // writer's last publication check must still pass, so the leave commits.
    let leave = |now| {
        fixture.waitlist_with_publication(
            WaitlistAction::Leave {
                token: token.clone(),
            },
            now,
            Some(&authority),
        )
    };
    assert_eq!(
        leave(NOW + 80).expect("a leave on the published page"),
        BookingVerbReceipt::Waitlisted(WaitlistReceipt::Left)
    );
    assert!(
        fixture.offered_at(NOW + 90).contains(&noon),
        "the leave gave the held slot back to everyone"
    );
    assert!(refusal(leave(NOW + 100)).contains("no waitlist entry"));
    assert!(refusal(fixture.claim(&token, NOW + 110)).contains("no waitlist entry"));
}
