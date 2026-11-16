//! Canon ARCH-0062:114 (promise-other-40): "A booking's stored metadata holds
//! only digests of its hold and checkout tokens, never their usable values."
//! A session takes a server checkout lease, holds a slot under it, and
//! confirms; after the hold and again after the confirm, every row of every
//! booking side table (`oneiron::test_doors::booking_side_table_rows`) is
//! scanned for each minted token, as its 64-character hex text and as its
//! 32 raw bytes. None spells one. The attempt queue, which keeps each
//! presented request by design, is not a booking side table and is out of
//! scope (FIX-LIST BOOKING-TOKEN-DIGEST-ROW-NO-DOOR).
//!
//! The fixture follows `tests/it/booking_lifecycle.rs`: the public
//! `enqueue_booking_verb` + `run_booking_lifecycle_once` door and the
//! server's own `issue_checkout_lease`.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron --all-features --test booking_token_digest_rows`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::booking::{
    BookingError, BookingLifecycleConsumerInput, BookingLifecycleTurn, BookingSolver,
    BookingVerbReceipt, BookingVerbRequest, ConfirmReceipt, ConfirmSpec,
    DEFAULT_INTRO_DURATION_MIN, EventTypeConfig, EventTypeKey, HoldLeaseSpec, HoldReceipt,
    HoldSpec, HostAvailabilityConfig, RankedSlot, RoutingMode, SessionKey, SlotOracle,
    SolveRequest, VaultActiveHoldSource, WeeklyWallWindow, enqueue_booking_verb,
    issue_checkout_lease, run_booking_lifecycle_once,
};
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_PERSON};
use oneiron::test_doors::booking_side_table_rows::{
    BookingSideTableRow, booking_side_table_names, booking_side_table_rows,
};
use oneiron::{
    DreamerHomeNodeCandidate, DreamerRunnerStore, EntityId, TimeRange, Vault, VaultConfig,
};

/// `2026-03-02T00:00:00Z`, a Monday.
const MONDAY: u64 = 1_772_409_600;
/// Request time: 08:00Z that Monday.
const NOW: u64 = MONDAY + 8 * 3_600;

const PAGE_SEED: u8 = 0x51;
const HOST_SEED: u8 = 0x52;
const ACTOR_SEED: u8 = 0x56;
const BOOKER_SEED: u8 = 0x57;
const BUSY_SEED: u8 = 0x61;
const HOME_NODE_ID: u64 = 9;

/// Canonical test entity id: `[seed; 16]` (`tests/common` `entity`).
fn test_id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("a non-pinned seed forms an entity id")
}

const fn at(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

/// A vault with a booking page, a host, a booker and an elected home node.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    page: EntityId,
    booker: EntityId,
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
        vault
            .put_entity(&test_id(HOST_SEED), ENTITY_TYPE_PERSON, at(1), 1, b"host")
            .expect("put host");
        let booker = test_id(BOOKER_SEED);
        vault
            .put_entity(
                &booker,
                ENTITY_TYPE_PERSON,
                at(1),
                1,
                b"visitor@example.test",
            )
            .expect("put booker");
        DreamerRunnerStore::new(&vault)
            .elect_home_node(
                &[DreamerHomeNodeCandidate::always_on_local(HOME_NODE_ID)],
                1,
            )
            .expect("elect home node");
        oneiron::calendar::transcript::permit_imported_calendar_source_for_test(&vault, actor)
            .expect("authorize this CAL ingest actor's Imported source");
        Self {
            _dir: dir,
            vault,
            page,
            booker,
        }
    }

    /// Enqueues a verb and runs exactly one home-node consumer turn.
    fn run(&self, request: BookingVerbRequest) -> Result<BookingVerbReceipt, BookingError> {
        enqueue_booking_verb(&self.vault, request, NOW)?;
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
            &BookingLifecycleConsumerInput {
                local_node_id: HOME_NODE_ID,
                lease_owner: "booking-lifecycle-worker".to_owned(),
                now_utc: NOW,
            },
        )?;
        match turn {
            BookingLifecycleTurn::Executed(receipt) => Ok(receipt),
            other => panic!("the home node must execute the queued attempt, got {other:?}"),
        }
    }

    /// The first slot the solver offers on the fixture Monday.
    fn first_slot(&self) -> TimeRange {
        let offered: Vec<RankedSlot> = LifecycleSolver {
            page: self.page,
            exclude: None,
            vault: &self.vault,
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
        .slots;
        let first = offered.first().expect("the fixture day offers a slot");
        TimeRange {
            start: first.start_utc,
            end: first.end_utc,
        }
    }
}

/// The production [`BookingSolver`] plus the vault-backed hold source.
struct LifecycleSolver<'a> {
    page: EntityId,
    exclude: Option<SessionKey>,
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
            now_utc: NOW,
            synthetic_config: Some(fixture_config()),
        }
        .solve(req)
    }
}

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

/// The 32 raw bytes a 64-character lowercase hex token spells.
fn raw_bytes(token: &str) -> Vec<u8> {
    assert_eq!(
        token.len(),
        64,
        "a lifecycle token is 32 bytes, hex encoded"
    );
    (0..token.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&token[at..at + 2], 16).expect("lowercase hex"))
        .collect()
}

fn spells(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).any(|window| window == needle)
}

/// Every row of every booking table, after asserting none spells a token.
fn rows_spelling_no_token(vault: &Vault, tokens: &[(&str, &str)]) -> Vec<BookingSideTableRow> {
    let rows = booking_side_table_rows(vault).expect("the booking side-table rows");
    for (name, token) in tokens {
        for needle in [token.as_bytes().to_vec(), raw_bytes(token)] {
            for row in &rows {
                assert!(
                    !spells(&row.key, &needle) && !spells(&row.value, &needle),
                    "a {} row spells the {name} token's usable value",
                    row.table
                );
            }
        }
    }
    rows
}

fn count(rows: &[BookingSideTableRow], table: &str) -> usize {
    rows.iter().filter(|row| row.table == table).count()
}

#[test]
fn booking_rows_hold_only_digests_of_the_hold_checkout_and_revision_tokens() {
    let walked = booking_side_table_names();
    for table in ["BOOKING_HOLD", "BOOKING_TOKEN", "BOOKING_LIFECYCLE_RECEIPT"] {
        assert!(
            walked.contains(&table),
            "the scan walks {table}: {walked:?}"
        );
    }

    let fixture = Fixture::open();
    let slot = fixture.first_slot();
    let visitor = SessionKey::derive(b"digest-visitor");
    let (lease, _) =
        issue_checkout_lease(&fixture.vault, &visitor, 15 * 60, NOW).expect("issue lease");
    let hold: HoldReceipt = match fixture
        .run(BookingVerbRequest::Hold(HoldSpec {
            page_ref: fixture.page,
            event_type: event_type(),
            slot,
            session_key: visitor,
            visitor_tz: "UTC".to_owned(),
            constraint: None,
            lease: HoldLeaseSpec::CheckoutExtension {
                server_issued_lease: lease.clone(),
            },
            idempotency_key: None,
        }))
        .expect("hold under the lease")
    {
        BookingVerbReceipt::Held(hold) => hold,
        other => panic!("expected a hold receipt, got {other:?}"),
    };

    let held = rows_spelling_no_token(
        &fixture.vault,
        &[
            ("hold", hold.token.0.as_str()),
            ("checkout lease", lease.0.as_str()),
        ],
    );
    assert_eq!(count(&held, "BOOKING_HOLD"), 1, "the hold row is stored");
    assert!(
        count(&held, "BOOKING_TOKEN") >= 1,
        "the lease row is stored"
    );

    let confirmed: ConfirmReceipt = match fixture
        .run(BookingVerbRequest::Confirm(ConfirmSpec {
            hold_token: hold.token.clone(),
            session_key: visitor,
            booker_contact: fixture.booker,
            intake: Vec::new(),
            idempotency_key: None,
        }))
        .expect("confirm")
    {
        BookingVerbReceipt::Confirmed(confirmed) => confirmed,
        other => panic!("expected a confirm receipt, got {other:?}"),
    };

    let booked = rows_spelling_no_token(
        &fixture.vault,
        &[
            ("hold", hold.token.0.as_str()),
            ("checkout lease", lease.0.as_str()),
            ("reschedule", confirmed.reschedule_token.0.as_str()),
            ("cancel", confirmed.cancel_token.0.as_str()),
        ],
    );
    assert!(
        count(&booked, "BOOKING_TOKEN") >= 2,
        "the revision pair is stored: {}",
        count(&booked, "BOOKING_TOKEN")
    );
    assert!(
        count(&booked, "BOOKING_LIFECYCLE_RECEIPT") >= 1,
        "the confirm receipt is stored"
    );
}
