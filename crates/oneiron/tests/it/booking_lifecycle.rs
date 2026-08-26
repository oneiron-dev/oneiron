//! ONE-1813 [BK-02] booking lifecycle oracle.
//!
//! Pins the laws the lifecycle exists to hold, at the public boundary:
//!
//! 1. **Holds are storage, not entities.** One `vault_meta` row per derived
//!    session key, lazily expiring when the clock passes it. No timer, wake, or
//!    expiry daemon exists, and no correctness depends on cleanup running.
//! 2. **The writer is the lock.** Confirm re-solves fresh availability inside
//!    the single writer it commits in, so the loser of a race sees the winner's
//!    EVENT as busy. No advisory idempotency key participates.
//! 3. **UID truth is CAL's.** Confirm mints the outbound UID ONCE through
//!    CAL-02's passport machinery at sequence 0; reschedule and cancel keep that
//!    UID and increment the sequence exactly once each.
//! 4. **Credentials are opaque.** Hold, reschedule, and cancel tokens are
//!    bearer values that encode nothing and are scoped by the row they resolve
//!    through — never by the token. A retry is answered with the credentials it
//!    already has, never with a second authority over the same booking.
//! 5. **One door.** The transition runs only in the home-node consumer. No
//!    public API executes a verb directly.

use crate::common::entity as test_id;
use oneiron::calendar::passport::{
    CALENDAR_PASSPORT_INDEX_PREFIX, live_passports_for_event, resolve_event_by_uid,
};
use oneiron::calendar::query::read_event;
use oneiron::calendar::{CalendarError, CalendarPassportDirection, CalendarPassportValue};
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_EVENT, ENTITY_TYPE_PERSON};
use oneiron::{
    ClaimApprovalStatus, ClaimCandidate, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    DreamerHomeNodeCandidate, DreamerRunnerStore, EdgeActorClass, EntityId, TimeRange, Vault,
    VaultConfig, WriteActor, WriteEnvelope, WriteProvenance,
    booking::BOOKING_BOOKER_CONTACT_PREDICATE, booking::BOOKING_EVENT_TYPE_REF_PREDICATE,
    booking::BOOKING_LIFECYCLE_ATTEMPT_KIND, booking::BOOKING_LIFECYCLE_PREDICATES,
    booking::BOOKING_PASSPORT_SYSTEM, booking::BOOKING_SOURCE_PAGE_PREDICATE,
    booking::BOOKING_STATUS_PREDICATE, booking::BOOKING_VERBS, booking::BookingBookerContactValue,
    booking::BookingError, booking::BookingEventTypeRefValue,
    booking::BookingLifecycleConsumerInput, booking::BookingLifecycleTurn, booking::BookingSolver,
    booking::BookingSourcePageValue, booking::BookingStatus, booking::BookingStatusValue,
    booking::BookingVerb, booking::BookingVerbReceipt, booking::BookingVerbRequest,
    booking::CancelSpec, booking::ConfirmReceipt, booking::ConfirmSpec,
    booking::DEFAULT_HOLD_TTL_SECS, booking::DEFAULT_INTRO_DURATION_MIN, booking::EventTypeConfig,
    booking::EventTypeKey, booking::HoldLeaseSpec, booking::HoldReceipt, booking::HoldSpec,
    booking::HostAvailabilityConfig, booking::MAX_CHECKOUT_HOLD_TTL_SECS,
    booking::OpaqueCheckoutLeaseToken, booking::OpaqueLifecycleToken, booking::RankedSlot,
    booking::RevisionReceipt, booking::RoutingMode, booking::SessionKey, booking::SlotOracle,
    booking::SolveRequest, booking::VaultActiveHoldSource, booking::WeeklyWallWindow,
    booking::booking_claim_class_descriptors, booking::enqueue_booking_verb,
    booking::is_booking_family_claim_predicate, booking::is_booking_lifecycle_claim_predicate,
    booking::issue_checkout_lease, booking::run_booking_lifecycle_once,
    booking::validate_booking_family_claim,
};
use rmpv::Value;

/// `2026-03-02T00:00:00Z`, a Monday well clear of any northern DST transition.
const MONDAY: u64 = 1_772_409_600;
/// Request time: 08:00Z that Monday.
const NOW: u64 = MONDAY + 8 * 3_600;

const PAGE_SEED: u8 = 0x51;
const HOST_SEED: u8 = 0x52;
const ACTOR_SEED: u8 = 0x56;
const BOOKER_SEED: u8 = 0x57;
const BUSY_SEED: u8 = 0x61;
const HOME_NODE_ID: u64 = 9;

const BOOKER_EMAIL: &str = "visitor@example.test";

/// Fixture claim ids are keyed `(0xB2, seed, index)` so none can alias a generic
/// `entity(seed)` id.
fn claim_id(seed: u8, index: u8) -> EntityId {
    let mut bytes = [0xB2_u8; 16];
    bytes[1] = seed;
    bytes[2] = index;
    EntityId::from_bytes(bytes).expect("fixture claim id")
}

const fn at(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

const fn hour(hours: u64) -> u64 {
    MONDAY + hours * 3_600
}

fn session(material: &[u8]) -> SessionKey {
    SessionKey::derive(material)
}

// -------------------------------------------------------------------------
// Fixture
// -------------------------------------------------------------------------

/// A vault with a booking page, a host, a booker contact, and an elected home
/// node — everything a lifecycle transition needs and nothing more.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    page: EntityId,
    booker: EntityId,
    actor: EntityId,
}

impl Fixture {
    fn open() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
        let actor = test_id(ACTOR_SEED);
        vault
            .put_entity(&actor, ENTITY_TYPE_PERSON, at(1), 1, b"booking actor")
            .expect("put actor");
        let page = test_id(PAGE_SEED);
        vault
            .put_entity(&page, ENTITY_TYPE_ASSET, at(1), 1, b"booking page")
            .expect("put booking page");
        let host = test_id(HOST_SEED);
        vault
            .put_entity(&host, ENTITY_TYPE_PERSON, at(1), 1, b"host")
            .expect("put host");
        let booker = test_id(BOOKER_SEED);
        vault
            .put_entity(
                &booker,
                ENTITY_TYPE_PERSON,
                at(1),
                1,
                BOOKER_EMAIL.as_bytes(),
            )
            .expect("put booker");

        DreamerRunnerStore::new(&vault)
            .elect_home_node(
                &[DreamerHomeNodeCandidate::always_on_local(HOME_NODE_ID)],
                1,
            )
            .expect("elect home node");

        Self {
            _dir: dir,
            vault,
            page,
            booker,
            actor,
        }
    }

    fn consumer_input(&self, now: u64) -> BookingLifecycleConsumerInput {
        BookingLifecycleConsumerInput {
            local_node_id: HOME_NODE_ID,
            lease_owner: "booking-lifecycle-worker".to_owned(),
            now_utc: now,
        }
    }

    /// Enqueues a verb and runs exactly one home-node consumer turn.
    ///
    /// The oracle is built here, per attempt, because only the consumer knows
    /// which page and which session the claimed attempt names.
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
                Ok(self.solver(page, oracle_request.exclude_session_key))
            },
            &self.consumer_input(now),
        )?;
        match turn {
            BookingLifecycleTurn::Executed(receipt) => Ok(receipt),
            other => panic!("the home node must execute the queued attempt, got {other:?}"),
        }
    }

    /// The production solver, bound to the vault-backed hold source, reading
    /// availability as of [`NOW`].
    fn solver(&self, page: EntityId, exclude: Option<SessionKey>) -> LifecycleSolver<'_> {
        self.solver_at(page, exclude, NOW)
    }

    /// The same solver at an explicit clock, for the lazy-expiry oracle: hold
    /// liveness is decided against the solve's own `now`.
    fn solver_at(
        &self,
        page: EntityId,
        exclude: Option<SessionKey>,
        now: u64,
    ) -> LifecycleSolver<'_> {
        LifecycleSolver {
            page,
            exclude,
            now,
            vault: &self.vault,
        }
    }

    /// What the solver offers over the whole Monday, for picking fixture slots
    /// without hard-coding the step grid.
    fn offered_slots(&self) -> Vec<RankedSlot> {
        self.solver(self.page, None)
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
    }

    fn live_claim_values(&self, event_ref: EntityId, predicate: &str) -> Vec<Value> {
        self.vault
            .claims_for_subject(&event_ref)
            .expect("claims for subject")
            .into_iter()
            .filter_map(|id| self.vault.get_claim(&id).expect("read claim"))
            .filter(|body| {
                body.predicate == predicate && body.lifecycle == ClaimLifecycleStatus::Active
            })
            .map(|body| body.value)
            .collect()
    }

    fn live_passports(&self, event_ref: EntityId) -> Vec<CalendarPassportValue> {
        live_passports_for_event(&self.vault, &event_ref)
            .expect("live passports")
            .into_iter()
            .map(|(_, value)| value)
            .collect()
    }

    fn event_exists(&self, event_ref: EntityId) -> bool {
        self.vault
            .get_entity_type(&event_ref)
            .expect("entity type")
            .is_some()
    }

    /// Every EVENT the vault holds, so "exactly one booking was written" is
    /// checked against the store rather than against a receipt.
    fn event_count(&self) -> usize {
        self.vault
            .entities_by_type(ENTITY_TYPE_EVENT)
            .expect("events of type")
            .len()
    }
}

/// The production [`BookingSolver`] plus the vault-backed hold source, built
/// fresh per solve so the hold read always sees committed state.
struct LifecycleSolver<'a> {
    page: EntityId,
    exclude: Option<SessionKey>,
    now: u64,
    vault: &'a Vault,
}

impl SlotOracle for LifecycleSolver<'_> {
    fn solve(&self, req: &SolveRequest) -> Result<oneiron::booking::SolveResult, BookingError> {
        let holds = match self.exclude {
            Some(key) => VaultActiveHoldSource::excluding(self.vault, key),
            None => VaultActiveHoldSource::new(self.vault),
        };
        let calendars = vec![(
            test_id(HOST_SEED),
            vec![oneiron::CalendarSel { system: None }],
        )];
        BookingSolver {
            vault: self.vault,
            page_ref: self.page,
            calendars_by_host: &calendars,
            holds: &holds,
            now_utc: self.now,
            synthetic_config: Some(fixture_config()),
        }
        .solve(req)
    }
}

fn event_type() -> EventTypeKey {
    EventTypeKey("intro-call".to_owned())
}

/// Monday 09:00–14:00 UTC, 30-minute slots, no notice and a generous horizon so
/// the fixture's own clock is the only thing that moves.
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

fn hold_spec(fixture: &Fixture, session_key: SessionKey, slot: TimeRange) -> HoldSpec {
    HoldSpec {
        page_ref: fixture.page,
        event_type: event_type(),
        slot,
        session_key,
        visitor_tz: "UTC".to_owned(),
        constraint: None,
        lease: HoldLeaseSpec::Ordinary,
        idempotency_key: None,
    }
}

fn confirm_spec(fixture: &Fixture, hold: &HoldReceipt, session_key: SessionKey) -> ConfirmSpec {
    ConfirmSpec {
        hold_token: hold.token.clone(),
        session_key,
        booker_contact: fixture.booker,
        idempotency_key: None,
    }
}

fn slot_of(ranked: &RankedSlot) -> TimeRange {
    TimeRange {
        start: ranked.start_utc,
        end: ranked.end_utc,
    }
}

fn expect_held(receipt: BookingVerbReceipt) -> HoldReceipt {
    match receipt {
        BookingVerbReceipt::Held(hold) => hold,
        other => panic!("expected a hold receipt, got {other:?}"),
    }
}

fn expect_confirmed(receipt: BookingVerbReceipt) -> ConfirmReceipt {
    match receipt {
        BookingVerbReceipt::Confirmed(confirmed) => confirmed,
        other => panic!("expected a confirm receipt, got {other:?}"),
    }
}

fn expect_slot_taken(receipt: BookingVerbReceipt) -> Vec<RankedSlot> {
    match receipt {
        BookingVerbReceipt::SlotTaken { alternatives } => alternatives,
        other => panic!("expected SlotTaken, got {other:?}"),
    }
}

fn expect_revision(receipt: BookingVerbReceipt) -> RevisionReceipt {
    match receipt {
        BookingVerbReceipt::Rescheduled(revision) | BookingVerbReceipt::Cancelled(revision) => {
            revision
        }
        other => panic!("expected a revision receipt, got {other:?}"),
    }
}

/// Holds `slot` for `session_key` and confirms it, the ordinary happy path.
fn book(fixture: &Fixture, session_key: SessionKey, slot: TimeRange) -> ConfirmReceipt {
    let hold = expect_held(
        fixture
            .run(
                BookingVerbRequest::Hold(hold_spec(fixture, session_key, slot)),
                NOW,
            )
            .expect("hold"),
    );
    expect_confirmed(
        fixture
            .run(
                BookingVerbRequest::Confirm(confirm_spec(fixture, &hold, session_key)),
                NOW,
            )
            .expect("confirm"),
    )
}

/// One busy calendar EVENT over `occupied`, written through the ordinary
/// claim-candidate door exactly as CAL's ingest would.
fn store_busy_event(fixture: &Fixture, seed: u8, occupied: TimeRange) {
    let id = test_id(seed);
    fixture
        .vault
        .put_entity(&id, ENTITY_TYPE_EVENT, occupied, 1, b"busy elsewhere")
        .expect("put busy event");
    let envelope = WriteEnvelope::new(
        WriteActor::new(fixture.actor, EdgeActorClass::Human),
        ClaimSource::Imported,
        WriteProvenance::new(Value::from("one-1813-oracle")).expect("provenance"),
        ClaimApprovalStatus::Approved,
    );
    fixture
        .vault
        .batch()
        .claim_candidate(
            &claim_id(seed, 0),
            ClaimCandidate::new(
                "calendar.time_kind",
                ClaimSubject::Entity(id),
                Value::Map(vec![
                    (Value::from("kind"), Value::from("absolute")),
                    (Value::from("busy_transparency"), Value::from("busy")),
                ]),
                1.0,
            ),
            &envelope,
            at(1),
            1,
        )
        .commit()
        .expect("busy claim commits");
}

// -------------------------------------------------------------------------
// Holds
// -------------------------------------------------------------------------

#[test]
fn hold_is_session_keyed_and_replaces_prior_session_hold() {
    let fixture = Fixture::open();
    let slots = fixture.offered_slots();
    let first = slot_of(&slots[0]);
    let second = slot_of(&slots[1]);
    let visitor = session(b"visitor-one");

    let one = expect_held(
        fixture
            .run(
                BookingVerbRequest::Hold(hold_spec(&fixture, visitor, first)),
                NOW,
            )
            .expect("first hold"),
    );
    let two = expect_held(
        fixture
            .run(
                BookingVerbRequest::Hold(hold_spec(&fixture, visitor, second)),
                NOW,
            )
            .expect("second hold"),
    );
    assert_ne!(one.token, two.token, "each hold mints its own credential");

    // The replaced hold is gone as STATE, not merely unreachable: the solver
    // sees exactly one live hold for this page, over the second slot.
    let other = session(b"someone-else");
    let offered = fixture
        .solver(fixture.page, Some(other))
        .solve(&SolveRequest {
            event_type: event_type(),
            window: TimeRange {
                start: MONDAY,
                end: MONDAY + 86_399,
            },
            constraint: None,
            visitor_tz: "UTC".to_owned(),
        })
        .expect("solve")
        .slots;
    assert!(
        offered.iter().any(|ranked| slot_of(ranked) == first),
        "the superseded hold no longer blocks its slot"
    );
    assert!(
        !offered.iter().any(|ranked| slot_of(ranked) == second),
        "the live hold still blocks its slot"
    );

    // And the first credential can no longer confirm: its row was replaced.
    let refused = fixture.run(
        BookingVerbRequest::Confirm(confirm_spec(&fixture, &one, visitor)),
        NOW,
    );
    assert!(matches!(refused, Err(BookingError::InvalidConstraint(_))));
}

#[test]
fn hold_lazily_expires_when_clock_passes() {
    let fixture = Fixture::open();
    let slot = slot_of(&fixture.offered_slots()[0]);
    let visitor = session(b"visitor-one");
    let hold = expect_held(
        fixture
            .run(
                BookingVerbRequest::Hold(hold_spec(&fixture, visitor, slot)),
                NOW,
            )
            .expect("hold"),
    );
    assert_eq!(
        hold.expires_at,
        NOW + DEFAULT_HOLD_TTL_SECS,
        "an ordinary hold takes the server default"
    );

    // `expires_at == now` is already dead: the boundary is exclusive, and no
    // timer, wake, or daemon runs to make it so.
    let refused = fixture.run(
        BookingVerbRequest::Confirm(confirm_spec(&fixture, &hold, visitor)),
        hold.expires_at,
    );
    assert!(matches!(refused, Err(BookingError::InvalidConstraint(_))));

    // The dead row also stops blocking availability, whether or not anything
    // ever deleted its bytes.
    let offered = fixture
        .solver_at(
            fixture.page,
            Some(session(b"someone-else")),
            hold.expires_at,
        )
        .solve(&SolveRequest {
            event_type: event_type(),
            window: TimeRange {
                start: MONDAY,
                end: MONDAY + 86_399,
            },
            constraint: None,
            visitor_tz: "UTC".to_owned(),
        })
        .expect("solve")
        .slots;
    assert!(
        offered.iter().any(|ranked| slot_of(ranked) == slot),
        "an expired hold occupies nothing"
    );
}

#[test]
fn hold_token_is_opaque_and_only_digest_is_persisted() {
    let fixture = Fixture::open();
    let slots = fixture.offered_slots();
    let visitor = session(b"visitor-one");
    let confirmed = book(&fixture, visitor, slot_of(&slots[0]));

    // Every credential this lane issues is pure lowercase hex of the same
    // width: there is no field for state to travel in.
    for token in [&confirmed.reschedule_token.0, &confirmed.cancel_token.0] {
        assert_eq!(token.len(), 64, "32 bytes of entropy, hex encoded");
        assert!(token.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(token.bytes().all(|byte| !byte.is_ascii_uppercase()));
    }
    assert_ne!(confirmed.reschedule_token, confirmed.cancel_token);

    // Nothing readable rides the credential: not the EVENT, the UID, the
    // booker, the action, or the clock.
    let event_hex = confirmed.calendar.event_ref.to_hex();
    for token in [
        confirmed.reschedule_token.0.as_str(),
        confirmed.cancel_token.0.as_str(),
    ] {
        for secret in [
            event_hex.as_str(),
            confirmed.calendar.uid.as_str(),
            BOOKER_EMAIL,
            "reschedule",
            "cancel",
            &NOW.to_string(),
        ] {
            assert!(
                !token.contains(secret),
                "an opaque token must not encode {secret}"
            );
        }
    }
    // A credential cannot be recomputed from the booking it belongs to: two
    // bookings of the same shape mint unrelated credentials.
    let second = book(&fixture, session(b"visitor-two"), slot_of(&slots[1]));
    assert_ne!(confirmed.cancel_token, second.cancel_token);
}

#[test]
fn hold_ttls_are_server_capped_and_checkout_extension_requires_server_lease() {
    let fixture = Fixture::open();
    let slot = slot_of(&fixture.offered_slots()[0]);
    let visitor = session(b"visitor-one");
    let other = session(b"visitor-two");

    // There is no caller TTL to supply: `HoldSpec` carries a lease SPEC, and
    // the ordinary arm resolves to the server default.
    let ordinary = expect_held(
        fixture
            .run(
                BookingVerbRequest::Hold(hold_spec(&fixture, visitor, slot)),
                NOW,
            )
            .expect("ordinary hold"),
    );
    assert_eq!(ordinary.expires_at, NOW + DEFAULT_HOLD_TTL_SECS);

    // A fabricated extension binding is refused: only a token minted by the
    // server's own door resolves to a lease row.
    let forged = HoldSpec {
        lease: HoldLeaseSpec::CheckoutExtension {
            server_issued_lease: OpaqueCheckoutLeaseToken("f".repeat(64)),
        },
        ..hold_spec(&fixture, visitor, slot)
    };
    assert!(matches!(
        fixture.run(BookingVerbRequest::Hold(forged), NOW),
        Err(BookingError::InvalidConstraint(_))
    ));

    // A real lease bound to ANOTHER session is refused too.
    let (foreign_lease, _) =
        issue_checkout_lease(&fixture.vault, &other, 15 * 60, NOW).expect("issue foreign lease");
    let borrowed = HoldSpec {
        lease: HoldLeaseSpec::CheckoutExtension {
            server_issued_lease: foreign_lease,
        },
        ..hold_spec(&fixture, visitor, slot)
    };
    assert!(matches!(
        fixture.run(BookingVerbRequest::Hold(borrowed), NOW),
        Err(BookingError::InvalidConstraint(_))
    ));

    // This session's own lease extends the hold, and only to the lease.
    let (lease, lease_expiry) =
        issue_checkout_lease(&fixture.vault, &visitor, 15 * 60, NOW).expect("issue lease");
    assert_eq!(lease_expiry, NOW + 15 * 60);
    let extended = expect_held(
        fixture
            .run(
                BookingVerbRequest::Hold(HoldSpec {
                    lease: HoldLeaseSpec::CheckoutExtension {
                        server_issued_lease: lease,
                    },
                    ..hold_spec(&fixture, visitor, slot)
                }),
                NOW,
            )
            .expect("extended hold"),
    );
    assert_eq!(extended.expires_at, lease_expiry);
    assert!(extended.expires_at > NOW + DEFAULT_HOLD_TTL_SECS);

    // And the extension itself is capped: an over-long request is clamped at
    // mint time, so no hold can outrun the server's ceiling.
    let (long_lease, long_expiry) =
        issue_checkout_lease(&fixture.vault, &visitor, 365 * 86_400, NOW)
            .expect("issue over-long lease");
    assert_eq!(long_expiry, NOW + MAX_CHECKOUT_HOLD_TTL_SECS);
    let capped = expect_held(
        fixture
            .run(
                BookingVerbRequest::Hold(HoldSpec {
                    lease: HoldLeaseSpec::CheckoutExtension {
                        server_issued_lease: long_lease,
                    },
                    ..hold_spec(&fixture, visitor, slot)
                }),
                NOW,
            )
            .expect("capped hold"),
    );
    assert_eq!(capped.expires_at, NOW + MAX_CHECKOUT_HOLD_TTL_SECS);
}

// -------------------------------------------------------------------------
// Confirm
// -------------------------------------------------------------------------

#[test]
fn confirm_excludes_own_hold_but_observes_other_live_holds() {
    let fixture = Fixture::open();
    let slots = fixture.offered_slots();
    let slot = slot_of(&slots[0]);
    let mine = session(b"visitor-one");
    let theirs = session(b"visitor-two");

    // My own hold does not block my own confirm — that is the whole point of
    // BK-00's `exclude_session_key` seam.
    let confirmed = book(&fixture, mine, slot);
    assert_eq!(confirmed.calendar.sequence, 0);

    // Another session's live hold DOES block, and the block is availability,
    // not authorization: the answer is a receipt with alternatives.
    let contested = slot_of(&slots[1]);
    expect_held(
        fixture
            .run(
                BookingVerbRequest::Hold(hold_spec(&fixture, theirs, contested)),
                NOW,
            )
            .expect("their hold"),
    );
    let third = session(b"visitor-three");
    expect_held(
        fixture
            .run(
                BookingVerbRequest::Hold(hold_spec(&fixture, third, contested)),
                NOW,
            )
            .expect("my hold on the contested slot"),
    );
    let alternatives = expect_slot_taken(
        fixture
            .run(
                BookingVerbRequest::Confirm(ConfirmSpec {
                    hold_token: OpaqueLifecycleToken(
                        latest_hold_token(&fixture, third, contested).0,
                    ),
                    session_key: third,
                    booker_contact: fixture.booker,
                    idempotency_key: None,
                }),
                NOW,
            )
            .expect("confirm answers"),
    );
    assert!(
        !alternatives
            .iter()
            .any(|ranked| slot_of(ranked) == contested),
        "the slot another session holds is not offered back"
    );
    assert_eq!(
        fixture.event_count(),
        1,
        "only the uncontested confirm wrote an EVENT"
    );
}

/// Re-holds `slot` for `session_key` and returns the fresh credential.
///
/// A hold replaces its session's prior row, so this is how a test re-acquires a
/// credential it needs to present twice.
fn latest_hold_token(
    fixture: &Fixture,
    session_key: SessionKey,
    slot: TimeRange,
) -> OpaqueLifecycleToken {
    expect_held(
        fixture
            .run(
                BookingVerbRequest::Hold(hold_spec(fixture, session_key, slot)),
                NOW,
            )
            .expect("re-hold"),
    )
    .token
}

#[test]
fn confirm_revalidates_after_new_busy_event() {
    let fixture = Fixture::open();
    let slot = slot_of(&fixture.offered_slots()[0]);
    let visitor = session(b"visitor-one");
    let hold = expect_held(
        fixture
            .run(
                BookingVerbRequest::Hold(hold_spec(&fixture, visitor, slot)),
                NOW,
            )
            .expect("hold"),
    );

    // Fresh CAL state lands AFTER the hold: the host got busy.
    store_busy_event(
        &fixture,
        BUSY_SEED,
        TimeRange {
            start: slot.start,
            end: slot.end - 1,
        },
    );

    let before = fixture.event_count();
    let alternatives = expect_slot_taken(
        fixture
            .run(
                BookingVerbRequest::Confirm(confirm_spec(&fixture, &hold, visitor)),
                NOW,
            )
            .expect("confirm answers"),
    );
    assert!(
        !alternatives.is_empty(),
        "a taken slot is answered with the SAME solver's nearest alternatives"
    );
    assert!(!alternatives.iter().any(|ranked| slot_of(ranked) == slot));
    assert_eq!(
        fixture.event_count(),
        before,
        "SlotTaken writes no EVENT, no claim, and no passport"
    );
}

#[test]
fn two_serialized_confirms_for_same_slot_only_one_commits() {
    let fixture = Fixture::open();
    let slot = slot_of(&fixture.offered_slots()[0]);
    let winner = session(b"visitor-one");
    let loser = session(b"visitor-two");

    let confirmed = book(&fixture, winner, slot);

    // The loser held the same slot and confirms second. Nothing about an
    // idempotency key participates: the refusal comes from the freebusy the
    // winner's committed EVENT changed.
    let loser_hold = expect_held(
        fixture
            .run(
                BookingVerbRequest::Hold(hold_spec(&fixture, loser, slot)),
                NOW,
            )
            .expect("loser hold"),
    );
    let alternatives = expect_slot_taken(
        fixture
            .run(
                BookingVerbRequest::Confirm(ConfirmSpec {
                    hold_token: loser_hold.token,
                    session_key: loser,
                    booker_contact: fixture.booker,
                    idempotency_key: Some("loser-key".to_owned()),
                }),
                NOW,
            )
            .expect("loser confirm answers"),
    );
    assert!(!alternatives.iter().any(|ranked| slot_of(ranked) == slot));
    assert_eq!(fixture.event_count(), 1, "exactly one confirm committed");
    assert!(fixture.event_exists(confirmed.calendar.event_ref));
}

#[test]
fn confirm_writes_event_claims_passport_tokens_and_consumes_hold_atomically() {
    let fixture = Fixture::open();
    let slot = slot_of(&fixture.offered_slots()[0]);
    let visitor = session(b"visitor-one");
    let hold_token = expect_held(
        fixture
            .run(
                BookingVerbRequest::Hold(hold_spec(&fixture, visitor, slot)),
                NOW,
            )
            .expect("hold"),
    )
    .token;
    let confirmed = expect_confirmed(
        fixture
            .run(
                BookingVerbRequest::Confirm(ConfirmSpec {
                    hold_token: hold_token.clone(),
                    session_key: visitor,
                    booker_contact: fixture.booker,
                    idempotency_key: None,
                }),
                NOW,
            )
            .expect("confirm"),
    );
    let event_ref = confirmed.calendar.event_ref;

    // An EXISTING entity type, never a new booking kind.
    assert_eq!(
        fixture
            .vault
            .get_entity_type(&event_ref)
            .expect("entity type"),
        Some(ENTITY_TYPE_EVENT)
    );

    // The four exact booking claims, one live each, with the ratified values.
    let event_type_ref: BookingEventTypeRefValue =
        decode_only(&fixture.live_claim_values(event_ref, BOOKING_EVENT_TYPE_REF_PREDICATE));
    assert_eq!(event_type_ref.event_type, event_type());
    let booker: BookingBookerContactValue =
        decode_only(&fixture.live_claim_values(event_ref, BOOKING_BOOKER_CONTACT_PREDICATE));
    assert_eq!(booker.contact_ref, fixture.booker);
    let source_page: BookingSourcePageValue =
        decode_only(&fixture.live_claim_values(event_ref, BOOKING_SOURCE_PAGE_PREDICATE));
    assert_eq!(source_page.page_ref, fixture.page);
    let status: BookingStatusValue =
        decode_only(&fixture.live_claim_values(event_ref, BOOKING_STATUS_PREDICATE));
    assert_eq!(status.status, BookingStatus::Confirmed);
    assert_eq!(status.recorded_at, NOW);

    // CAL-00's passport value, outbound, at sequence 0, indexed by CAL-02.
    let passports = fixture.live_passports(event_ref);
    assert_eq!(passports.len(), 1, "one live passport per (system x UID)");
    assert_eq!(passports[0].system, BOOKING_PASSPORT_SYSTEM);
    assert_eq!(passports[0].uid, confirmed.calendar.uid);
    assert_eq!(passports[0].last_sequence, 0);
    assert_eq!(passports[0].direction, CalendarPassportDirection::Outbound);
    assert_eq!(
        resolve_event_by_uid(&fixture.vault, &confirmed.calendar.uid).expect("resolve uid"),
        Some(event_ref),
        "CAL-02's UID index resolves the booking"
    );

    // The hold is consumed: a second confirm on the same credential resolves the
    // recorded receipt rather than the hold.
    let replay = expect_confirmed(
        fixture
            .run(
                BookingVerbRequest::Confirm(ConfirmSpec {
                    hold_token,
                    session_key: visitor,
                    booker_contact: fixture.booker,
                    idempotency_key: None,
                }),
                NOW,
            )
            .expect("replay resolves the receipt"),
    );
    assert_eq!(replay.calendar, confirmed.calendar);
    assert_eq!(fixture.event_count(), 1);

    // The negative half: a transition that fails after reading the hold writes
    // NOTHING and leaves the hold intact.
    let failing = Fixture::open();
    let failing_slot = slot_of(&failing.offered_slots()[0]);
    let failing_session = session(b"visitor-one");
    let hold = expect_held(
        failing
            .run(
                BookingVerbRequest::Hold(hold_spec(&failing, failing_session, failing_slot)),
                NOW,
            )
            .expect("hold"),
    );
    enqueue_booking_verb(
        &failing.vault,
        BookingVerbRequest::Confirm(confirm_spec(&failing, &hold, failing_session)),
        NOW,
    )
    .expect("enqueue");
    let refused = run_booking_lifecycle_once(
        &failing.vault,
        |_| Ok(RefusingOracle),
        &failing.consumer_input(NOW),
    );
    assert!(matches!(refused, Err(BookingError::SlotOracle(_))));
    assert_eq!(failing.event_count(), 0, "the writer rolled back");
    // The hold survived the rollback, so the visitor can still confirm it.
    let recovered = expect_confirmed(
        failing
            .run(
                BookingVerbRequest::Confirm(confirm_spec(&failing, &hold, failing_session)),
                NOW,
            )
            .expect("confirm after the failure"),
    );
    assert_eq!(recovered.calendar.sequence, 0);
}

/// An oracle that fails every solve, for the rollback half of the atomicity
/// oracle.
struct RefusingOracle;

impl SlotOracle for RefusingOracle {
    fn solve(&self, _req: &SolveRequest) -> Result<oneiron::booking::SolveResult, BookingError> {
        Err(BookingError::SlotOracle(
            "injected solve failure".to_owned(),
        ))
    }
}

#[test]
fn confirm_retry_returns_same_event_uid_and_sequence() {
    let fixture = Fixture::open();
    let slot = slot_of(&fixture.offered_slots()[0]);
    let visitor = session(b"visitor-one");
    let hold = expect_held(
        fixture
            .run(
                BookingVerbRequest::Hold(hold_spec(&fixture, visitor, slot)),
                NOW,
            )
            .expect("hold"),
    );

    let first = expect_confirmed(
        fixture
            .run(
                BookingVerbRequest::Confirm(ConfirmSpec {
                    hold_token: hold.token.clone(),
                    session_key: visitor,
                    booker_contact: fixture.booker,
                    idempotency_key: Some("client-key-a".to_owned()),
                }),
                NOW,
            )
            .expect("first confirm"),
    );

    // The retry CHANGES its advisory key, and then OMITS it. Neither is part of
    // the receipt's identity, so both land on the same booking.
    for key in [Some("client-key-b".to_owned()), None] {
        let retry = expect_confirmed(
            fixture
                .run(
                    BookingVerbRequest::Confirm(ConfirmSpec {
                        hold_token: hold.token.clone(),
                        session_key: visitor,
                        booker_contact: fixture.booker,
                        idempotency_key: key,
                    }),
                    NOW + 30,
                )
                .expect("retry"),
        );
        assert_eq!(
            retry.calendar, first.calendar,
            "same EVENT, UID, and sequence"
        );
    }
    assert_eq!(fixture.event_count(), 1, "no second EVENT was minted");
    assert_eq!(
        fixture.live_passports(first.calendar.event_ref).len(),
        1,
        "the UID was minted once"
    );
}

// -------------------------------------------------------------------------
// Reschedule + cancel
// -------------------------------------------------------------------------

#[test]
fn reschedule_uses_same_solver_rules_and_increments_sequence_once() {
    let fixture = Fixture::open();
    let slots = fixture.offered_slots();
    let confirmed = book(&fixture, session(b"visitor-one"), slot_of(&slots[0]));
    let moved_to = slot_of(&slots[4]);

    let revision = expect_revision(
        fixture
            .run(
                BookingVerbRequest::Reschedule(oneiron::booking::RescheduleSpec {
                    token: confirmed.reschedule_token.clone(),
                    new_slot: moved_to,
                    visitor_tz: "UTC".to_owned(),
                    constraint: None,
                    idempotency_key: None,
                }),
                NOW + 60,
            )
            .expect("reschedule"),
    );
    assert_eq!(revision.calendar.event_ref, confirmed.calendar.event_ref);
    assert_eq!(
        revision.calendar.uid, confirmed.calendar.uid,
        "the UID is kept"
    );
    assert_eq!(
        revision.calendar.sequence, 1,
        "sequence n + 1, exactly once"
    );
    assert_eq!(fixture.event_count(), 1);

    // The UTC interval moved, and only after revalidation.
    let view = read_event(
        &fixture.vault,
        &oneiron::CalendarReadRequest {
            event_ref: revision.calendar.event_ref.to_hex(),
        },
    )
    .expect("read event")
    .expect("the booking EVENT is a calendar EVENT");
    let occurrence = (view.start_utc, view.end_utc);
    assert_eq!(occurrence, (Some(moved_to.start), Some(moved_to.end - 1)));

    // The same rules that admitted the original slot govern the move: a slot
    // outside the host's working hours is refused, and nothing changes.
    let outside = TimeRange {
        start: hour(3),
        end: hour(3) + 1_800,
    };
    assert!(matches!(
        fixture.run(
            BookingVerbRequest::Reschedule(oneiron::booking::RescheduleSpec {
                token: confirmed.reschedule_token.clone(),
                new_slot: outside,
                visitor_tz: "UTC".to_owned(),
                constraint: None,
                idempotency_key: None,
            }),
            NOW + 120,
        ),
        Err(BookingError::InvalidConstraint(_))
    ));
    assert_eq!(
        fixture
            .live_passports(revision.calendar.event_ref)
            .first()
            .expect("live passport")
            .last_sequence,
        1,
        "a refused move increments nothing"
    );

    // A retry of the SAME move returns the recorded receipt, not n + 2.
    let retry = expect_revision(
        fixture
            .run(
                BookingVerbRequest::Reschedule(oneiron::booking::RescheduleSpec {
                    token: confirmed.reschedule_token,
                    new_slot: moved_to,
                    visitor_tz: "UTC".to_owned(),
                    constraint: None,
                    idempotency_key: Some("a-different-key".to_owned()),
                }),
                NOW + 180,
            )
            .expect("reschedule retry"),
    );
    assert_eq!(retry.calendar, revision.calendar);
}

#[test]
fn cancel_keeps_uid_and_increments_sequence_once() {
    let fixture = Fixture::open();
    let slot = slot_of(&fixture.offered_slots()[0]);
    let confirmed = book(&fixture, session(b"visitor-one"), slot);

    let revision = expect_revision(
        fixture
            .run(
                BookingVerbRequest::Cancel(CancelSpec {
                    token: confirmed.cancel_token.clone(),
                    idempotency_key: None,
                }),
                NOW + 60,
            )
            .expect("cancel"),
    );
    assert_eq!(revision.calendar.event_ref, confirmed.calendar.event_ref);
    assert_eq!(revision.calendar.uid, confirmed.calendar.uid);
    assert_eq!(revision.calendar.sequence, 1);

    // `booking.status` moved by SUPERSESSION: one live head, and the EVENT row
    // itself was never deleted.
    let status: BookingStatusValue = decode_only(
        &fixture.live_claim_values(revision.calendar.event_ref, BOOKING_STATUS_PREDICATE),
    );
    assert_eq!(status.status, BookingStatus::Cancelled);
    assert!(fixture.event_exists(revision.calendar.event_ref));

    // And the freed slot is bookable again: a cancelled booking that still
    // occupied the host's calendar would strand the slot forever.
    let offered = fixture.offered_slots();
    assert!(offered.iter().any(|ranked| slot_of(ranked) == slot));

    // A retry returns the same receipt rather than n + 2.
    let retry = expect_revision(
        fixture
            .run(
                BookingVerbRequest::Cancel(CancelSpec {
                    token: confirmed.cancel_token,
                    idempotency_key: Some("late-key".to_owned()),
                }),
                NOW + 120,
            )
            .expect("cancel retry"),
    );
    assert_eq!(retry.calendar, revision.calendar);
}

#[test]
fn confirm_retry_reissues_the_same_credentials_and_one_booking_cancels_once() {
    let fixture = Fixture::open();
    let slot = slot_of(&fixture.offered_slots()[0]);
    let visitor = session(b"visitor-one");
    let hold = expect_held(
        fixture
            .run(
                BookingVerbRequest::Hold(hold_spec(&fixture, visitor, slot)),
                NOW,
            )
            .expect("hold"),
    );

    let first = expect_confirmed(
        fixture
            .run(
                BookingVerbRequest::Confirm(confirm_spec(&fixture, &hold, visitor)),
                NOW,
            )
            .expect("confirm"),
    );
    let retry = expect_confirmed(
        fixture
            .run(
                BookingVerbRequest::Confirm(confirm_spec(&fixture, &hold, visitor)),
                NOW + 30,
            )
            .expect("retry"),
    );

    // A retry is answered with the SAME pair, not a second authority over one
    // booking: the credentials are derived from the hold token it re-presented.
    assert_eq!(retry.reschedule_token, first.reschedule_token);
    assert_eq!(retry.cancel_token, first.cancel_token);

    // And the receipt is keyed by the BOOKING, so even a second credential
    // cancels the same cancel: one logical cancel, one increment.
    let cancelled = expect_revision(
        fixture
            .run(
                BookingVerbRequest::Cancel(CancelSpec {
                    token: retry.cancel_token,
                    idempotency_key: None,
                }),
                NOW + 60,
            )
            .expect("cancel"),
    );
    assert_eq!(cancelled.calendar.sequence, 1);
    let again = expect_revision(
        fixture
            .run(
                BookingVerbRequest::Cancel(CancelSpec {
                    token: first.cancel_token,
                    idempotency_key: None,
                }),
                NOW + 90,
            )
            .expect("cancel with the first confirm's credential"),
    );
    assert_eq!(again.calendar, cancelled.calendar, "no second increment");
    assert_eq!(
        fixture
            .live_passports(first.calendar.event_ref)
            .first()
            .expect("live passport")
            .last_sequence,
        1,
    );
}

#[test]
fn reschedule_back_to_an_earlier_slot_is_a_new_move() {
    let fixture = Fixture::open();
    let slots = fixture.offered_slots();
    let confirmed = book(&fixture, session(b"visitor-one"), slot_of(&slots[0]));
    let middle = slot_of(&slots[4]);
    let far = slot_of(&slots[6]);

    let move_out = |target: TimeRange, now: u64| {
        expect_revision(
            fixture
                .run(
                    BookingVerbRequest::Reschedule(oneiron::booking::RescheduleSpec {
                        token: confirmed.reschedule_token.clone(),
                        new_slot: target,
                        visitor_tz: "UTC".to_owned(),
                        constraint: None,
                        idempotency_key: None,
                    }),
                    now,
                )
                .expect("reschedule"),
        )
    };

    assert_eq!(move_out(middle, NOW + 60).calendar.sequence, 1);
    assert_eq!(move_out(far, NOW + 120).calendar.sequence, 2);

    // The booking no longer sits at `middle`, so a request naming it is a fresh
    // move back — not a retry of the move that put it there two revisions ago.
    let back = move_out(middle, NOW + 180);
    assert_eq!(back.calendar.sequence, 3, "a move BACK is a new transition");
    let view = read_event(
        &fixture.vault,
        &oneiron::CalendarReadRequest {
            event_ref: confirmed.calendar.event_ref.to_hex(),
        },
    )
    .expect("read event")
    .expect("the booking EVENT is a calendar EVENT");
    assert_eq!(
        (view.start_utc, view.end_utc),
        (Some(middle.start), Some(middle.end - 1)),
        "the EVENT actually moved back",
    );
}

#[test]
fn a_cancelled_booking_cannot_be_rescheduled() {
    let fixture = Fixture::open();
    let slots = fixture.offered_slots();
    let confirmed = book(&fixture, session(b"visitor-one"), slot_of(&slots[0]));
    let event_ref = confirmed.calendar.event_ref;
    let cancelled = expect_revision(
        fixture
            .run(
                BookingVerbRequest::Cancel(CancelSpec {
                    token: confirmed.cancel_token,
                    idempotency_key: None,
                }),
                NOW + 60,
            )
            .expect("cancel"),
    );
    assert_eq!(cancelled.calendar.sequence, 1);

    // The reschedule credential outlives the booking it was issued for, so the
    // transition itself has to rule on the LIVE status: nothing else stands
    // between a cancelled booking and a Confirmed passport written over it.
    let target = slot_of(&slots[4]);
    assert!(matches!(
        fixture.run(
            BookingVerbRequest::Reschedule(oneiron::booking::RescheduleSpec {
                token: confirmed.reschedule_token,
                new_slot: target,
                visitor_tz: "UTC".to_owned(),
                constraint: None,
                idempotency_key: None,
            }),
            NOW + 120,
        ),
        Err(BookingError::InvalidConstraint(_))
    ));

    // Still cancelled, still at sequence 1, and the slot it would have taken is
    // still free for someone else.
    let status: BookingStatusValue =
        decode_only(&fixture.live_claim_values(event_ref, BOOKING_STATUS_PREDICATE));
    assert_eq!(status.status, BookingStatus::Cancelled);
    assert_eq!(
        fixture
            .live_passports(event_ref)
            .first()
            .expect("live passport")
            .last_sequence,
        1,
        "a refused move increments nothing",
    );
    assert!(
        fixture
            .offered_slots()
            .iter()
            .any(|ranked| slot_of(ranked) == target)
    );
}

// -------------------------------------------------------------------------
// Authority
// -------------------------------------------------------------------------

#[test]
fn wrong_or_expired_session_cannot_confirm_hold() {
    let fixture = Fixture::open();
    let slot = slot_of(&fixture.offered_slots()[0]);
    let visitor = session(b"visitor-one");
    let attacker = session(b"visitor-two");
    let hold = expect_held(
        fixture
            .run(
                BookingVerbRequest::Hold(hold_spec(&fixture, visitor, slot)),
                NOW,
            )
            .expect("hold"),
    );

    // A stolen credential presented under another session finds no hold at all:
    // the row is keyed by the session, so there is nothing to compare against.
    assert!(matches!(
        fixture.run(
            BookingVerbRequest::Confirm(ConfirmSpec {
                hold_token: hold.token.clone(),
                session_key: attacker,
                booker_contact: fixture.booker,
                idempotency_key: None,
            }),
            NOW,
        ),
        Err(BookingError::InvalidConstraint(_))
    ));

    // The right session with the WRONG credential is refused too: the row's
    // digest is what authorizes, not merely owning a session.
    let stale = OpaqueLifecycleToken("0".repeat(64));
    assert!(matches!(
        fixture.run(
            BookingVerbRequest::Confirm(ConfirmSpec {
                hold_token: stale,
                session_key: visitor,
                booker_contact: fixture.booker,
                idempotency_key: None,
            }),
            NOW,
        ),
        Err(BookingError::InvalidConstraint(_))
    ));

    // And an expired hold cannot be confirmed by anyone.
    assert!(matches!(
        fixture.run(
            BookingVerbRequest::Confirm(confirm_spec(&fixture, &hold, visitor)),
            hold.expires_at + 1,
        ),
        Err(BookingError::InvalidConstraint(_))
    ));
    assert_eq!(fixture.event_count(), 0);
}

#[test]
fn wrong_action_token_scope_is_rejected() {
    let fixture = Fixture::open();
    let slot = slot_of(&fixture.offered_slots()[0]);
    let confirmed = book(&fixture, session(b"visitor-one"), slot);

    // Scope lives on the row, not in the token, so a cancel credential cannot
    // drive a reschedule — or the reverse.
    assert!(matches!(
        fixture.run(
            BookingVerbRequest::Reschedule(oneiron::booking::RescheduleSpec {
                token: confirmed.cancel_token.clone(),
                new_slot: slot,
                visitor_tz: "UTC".to_owned(),
                constraint: None,
                idempotency_key: None,
            }),
            NOW + 60,
        ),
        Err(BookingError::InvalidConstraint(_))
    ));
    assert!(matches!(
        fixture.run(
            BookingVerbRequest::Cancel(CancelSpec {
                token: confirmed.reschedule_token,
                idempotency_key: None,
            }),
            NOW + 60,
        ),
        Err(BookingError::InvalidConstraint(_))
    ));

    // An unknown credential resolves to no booking at all.
    assert!(matches!(
        fixture.run(
            BookingVerbRequest::Cancel(CancelSpec {
                token: OpaqueLifecycleToken("a".repeat(64)),
                idempotency_key: None,
            }),
            NOW + 60,
        ),
        Err(BookingError::InvalidConstraint(_))
    ));
    // A malformed credential is refused at the public door, before any lookup.
    assert!(matches!(
        enqueue_booking_verb(
            &fixture.vault,
            BookingVerbRequest::Cancel(CancelSpec {
                token: OpaqueLifecycleToken("not-hex".to_owned()),
                idempotency_key: None,
            }),
            NOW,
        ),
        Err(BookingError::InvalidConstraint(_))
    ));

    // Nothing above moved the booking's sequence.
    assert_eq!(
        fixture
            .live_passports(confirmed.calendar.event_ref)
            .first()
            .expect("live passport")
            .last_sequence,
        0
    );
}

#[test]
fn lifecycle_attempt_runs_only_on_home_node_consumer() {
    let fixture = Fixture::open();
    let slot = slot_of(&fixture.offered_slots()[0]);
    let visitor = session(b"visitor-one");

    // The public verb door only enqueues. It returns an attempt handle, never a
    // receipt, and writes nothing.
    enqueue_booking_verb(
        &fixture.vault,
        BookingVerbRequest::Hold(hold_spec(&fixture, visitor, slot)),
        NOW,
    )
    .expect("enqueue");
    let queued = oneiron::attempt_queue::AttemptQueue::new(&fixture.vault)
        .list()
        .expect("list attempts");
    assert_eq!(queued.len(), 1);
    assert_eq!(
        queued[0].kind, BOOKING_LIFECYCLE_ATTEMPT_KIND,
        "the booking consumer's own kind, claimed by no public verb path"
    );

    // A node that is not the home node refuses to execute, and does not even
    // lease the row.
    let elsewhere = run_booking_lifecycle_once(
        &fixture.vault,
        |request| Ok(fixture.solver(request.page_ref.expect("page"), request.exclude_session_key)),
        &BookingLifecycleConsumerInput {
            local_node_id: HOME_NODE_ID + 1,
            lease_owner: "impostor".to_owned(),
            now_utc: NOW,
        },
    )
    .expect("a non-home node answers rather than failing");
    assert_eq!(
        elsewhere,
        BookingLifecycleTurn::NotHomeNode {
            home_node_id: HOME_NODE_ID
        }
    );
    assert_eq!(
        oneiron::attempt_queue::AttemptQueue::new(&fixture.vault)
            .list()
            .expect("list attempts")[0]
            .lease_owner,
        None,
        "a node that may not write never leases the attempt"
    );

    // The home node executes it, and then the queue is empty.
    let turn = run_booking_lifecycle_once(
        &fixture.vault,
        |request| Ok(fixture.solver(request.page_ref.expect("page"), request.exclude_session_key)),
        &fixture.consumer_input(NOW),
    )
    .expect("home node executes");
    assert!(matches!(
        turn,
        BookingLifecycleTurn::Executed(BookingVerbReceipt::Held(_))
    ));
    let drained = run_booking_lifecycle_once(
        &fixture.vault,
        |request| Ok(fixture.solver(request.page_ref.expect("page"), request.exclude_session_key)),
        &fixture.consumer_input(NOW),
    )
    .expect("second turn");
    assert_eq!(drained, BookingLifecycleTurn::Empty);
}

// -------------------------------------------------------------------------
// Seams
// -------------------------------------------------------------------------

#[test]
fn calendar_passport_types_have_one_owner() {
    let fixture = Fixture::open();
    let slot = slot_of(&fixture.offered_slots()[0]);
    let confirmed = book(&fixture, session(b"visitor-one"), slot);

    // The value BK-02 wrote IS CAL-00's type: it round-trips through CAL's own
    // decoder, and its direction enum is CAL-00's.
    let stored: CalendarPassportValue = fixture
        .live_passports(confirmed.calendar.event_ref)
        .pop()
        .expect("live passport");
    assert_eq!(stored.direction, CalendarPassportDirection::Outbound);
    assert_eq!(stored.system, BOOKING_PASSPORT_SYSTEM);

    // The UID index is CAL-02's, keyed by CAL-02's prefix — booking keeps no
    // second UID store.
    assert!(
        CALENDAR_PASSPORT_INDEX_PREFIX.starts_with(b"calendar.passport.v1:"),
        "the index prefix is CAL-02's, not a booking-local one"
    );
    assert_eq!(
        resolve_event_by_uid(&fixture.vault, &stored.uid).expect("resolve"),
        Some(confirmed.calendar.event_ref)
    );

    // No `booking.uid` claim exists: UID truth is the passport's alone.
    assert!(
        fixture
            .live_claim_values(confirmed.calendar.event_ref, "booking.uid")
            .is_empty()
    );
    assert!(!BOOKING_LIFECYCLE_PREDICATES.contains(&"booking.uid"));
}

#[test]
fn booking_error_wraps_calendar_error_opaquely() {
    let fixture = Fixture::open();
    let slot = slot_of(&fixture.offered_slots()[0]);
    let visitor = session(b"visitor-one");
    let hold = expect_held(
        fixture
            .run(
                BookingVerbRequest::Hold(hold_spec(&fixture, visitor, slot)),
                NOW,
            )
            .expect("hold"),
    );

    // A calendar-side failure surfaces through the 1816-owned wrapper. The
    // seam's taxonomy is unchanged: booking has no `Calendar` variant to match,
    // and the lane restates no CAL variant.
    enqueue_booking_verb(
        &fixture.vault,
        BookingVerbRequest::Confirm(confirm_spec(&fixture, &hold, visitor)),
        NOW,
    )
    .expect("enqueue");
    let failure = run_booking_lifecycle_once(
        &fixture.vault,
        |_| Ok(CalendarFailingOracle),
        &fixture.consumer_input(NOW),
    )
    .expect_err("the wrapped failure propagates");
    assert!(
        matches!(failure, BookingError::SlotOracle(_)),
        "calendar failures ride an existing seam variant, opaquely"
    );
    // The wrapper is a string, so no CAL variant is destructurable from it.
    let rendered = failure.to_string();
    assert!(rendered.starts_with("booking slot oracle failed:"));
}

/// An oracle whose failure is a wrapped `CalendarError`, exactly as
/// `solver.rs`'s freebusy step produces one.
struct CalendarFailingOracle;

impl SlotOracle for CalendarFailingOracle {
    fn solve(&self, _req: &SolveRequest) -> Result<oneiron::booking::SolveResult, BookingError> {
        Err(BookingError::SlotOracle(format!(
            "freebusy: {}",
            CalendarError::IcsIngest {
                reason: "feed unavailable".to_owned()
            }
        )))
    }
}

#[test]
fn booking_lifecycle_validator_is_exact() {
    // The verb table and the family table are both closed and sorted.
    let mut sorted_verbs = BOOKING_VERBS;
    sorted_verbs.sort_unstable();
    assert_eq!(sorted_verbs, BOOKING_VERBS, "the verb table is sorted");
    for verb in BOOKING_VERBS {
        assert_eq!(
            BookingVerb::parse(verb).map(BookingVerb::as_str),
            Some(verb),
            "every table entry round-trips through the closed enum"
        );
    }
    assert!(BookingVerb::parse("booking.approve").is_none());

    // Exactly the four lifecycle predicates are family members, and the family
    // door is the union with ONE-1823's configuration predicate.
    for predicate in BOOKING_LIFECYCLE_PREDICATES {
        assert!(is_booking_lifecycle_claim_predicate(predicate));
        assert!(is_booking_family_claim_predicate(predicate));
    }
    assert!(is_booking_family_claim_predicate(
        oneiron::booking::BOOKING_EVENT_TYPE_PREDICATE
    ));
    for stranger in [
        "booking.uid",
        "booking.status.v2",
        "booking.",
        "calendar.status",
    ] {
        assert!(
            !is_booking_lifecycle_claim_predicate(stranger),
            "{stranger} is not a lifecycle predicate"
        );
    }

    // The family validator accepts a well-formed value, refuses a malformed
    // one, and refuses an unknown `booking.*` predicate outright.
    let subject = ClaimSubject::Entity(test_id(0x64));
    let body = |predicate: &str, value: Value| {
        oneiron::ClaimBody::new(
            predicate,
            subject,
            value,
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )
    };
    let good = Value::Map(vec![
        (Value::from("status"), Value::from("confirmed")),
        (Value::from("recorded_at"), Value::from(NOW)),
    ]);
    validate_booking_family_claim(&body(BOOKING_STATUS_PREDICATE, good.clone()))
        .expect("a well-formed status value passes");
    // An extra key is refused: the value schemas are exact.
    let mut extra = vec![
        (Value::from("status"), Value::from("confirmed")),
        (Value::from("recorded_at"), Value::from(NOW)),
        (Value::from("uid"), Value::from("smuggled")),
    ];
    extra.sort_by_key(|(key, _)| format!("{key}"));
    assert!(
        validate_booking_family_claim(&body(BOOKING_STATUS_PREDICATE, Value::Map(extra))).is_err()
    );
    // An out-of-set status token is refused.
    assert!(
        validate_booking_family_claim(&body(
            BOOKING_STATUS_PREDICATE,
            Value::Map(vec![
                (Value::from("status"), Value::from("pending")),
                (Value::from("recorded_at"), Value::from(NOW)),
            ]),
        ))
        .is_err()
    );
    assert!(validate_booking_family_claim(&body("booking.uid", good)).is_err());
}

#[test]
fn booking_lifecycle_descriptor_rows_are_complete() {
    let rows = booking_claim_class_descriptors();
    for predicate in BOOKING_LIFECYCLE_PREDICATES {
        let row = rows
            .iter()
            .find(|row| row.predicate == predicate)
            .unwrap_or_else(|| panic!("{predicate} has a descriptor row"));
        assert_eq!(row.write_class, "recorded");
        assert!(
            row.projector_only,
            "only the engine writes a lifecycle fact"
        );
    }
    // ONE-1823's configuration row is still there: the family table is the
    // union, not a replacement.
    assert!(
        rows.iter()
            .any(|row| row.predicate == oneiron::booking::BOOKING_EVENT_TYPE_PREDICATE)
    );
    assert_eq!(
        rows.len(),
        BOOKING_LIFECYCLE_PREDICATES.len() + 1,
        "one row per exact predicate in the whole booking family"
    );
    for row in &rows {
        assert!(
            ["recorded", "human_ruled", "ordinary"].contains(&row.write_class),
            "write_class is restricted to the three ratified classes"
        );
    }
    // And there is still no descriptor runtime to register them with: the rows
    // are pure data a caller reads, not a registry a writer consults.
    assert!(
        rows.iter().all(|row| !row.enforcement),
        "no lifecycle row claims enforcement a runtime would have to apply"
    );
}

/// Decodes the single live claim value for a predicate.
fn decode_only<T: serde::de::DeserializeOwned>(values: &[Value]) -> T {
    assert_eq!(values.len(), 1, "exactly one live claim head");
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &values[0]).expect("re-encode claim value");
    rmp_serde::from_slice(&bytes).expect("decode claim value")
}
