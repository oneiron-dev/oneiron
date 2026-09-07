#[path = "scope_tests.rs"]
mod scope_tests;

use super::*;
use crate::booking::config::{
    BOOKING_EVENT_TYPE_PREDICATE, BOOKING_EVENT_TYPE_SCHEMA_VERSION, BookingEventTypeClaimValue,
    DEFAULT_INTRO_DURATION_MIN, DEFAULT_MIN_NOTICE_SECS, EventTypeConfig, HostAvailabilityConfig,
    RoutingMode, WeeklyWallWindow, encode_event_type_claim_value,
};
use crate::test_util::entity as id;

const PAGE: u8 = 0x51;
const OWNER: u8 = 0x52;
const STAMP: u8 = 0x53;
const OTHER_PAGE: u8 = 0x54;

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault =
        Vault::open(dir.path(), crate::VaultConfig::default()).expect("open anti-abuse vault");
    (dir, vault)
}

fn install_page_and_config(vault: &Vault, page: EntityId, event_type: &EventTypeKey) {
    vault
        .put_entity(
            &page,
            crate::registry::ENTITY_TYPE_EVENT,
            TimeRange { start: 1, end: 1 },
            1,
            b"booking page fixture",
        )
        .expect("page entity");
    let value = BookingEventTypeClaimValue {
        schema_version: BOOKING_EVENT_TYPE_SCHEMA_VERSION,
        page_ref: page,
        config: EventTypeConfig {
            key: event_type.clone(),
            duration_min: DEFAULT_INTRO_DURATION_MIN,
            slot_step_min: 30,
            pre_buffer_min: 0,
            post_buffer_min: 0,
            min_notice_secs: DEFAULT_MIN_NOTICE_SECS,
            booking_window_secs: 86_400,
            daily_cap: None,
            weekly_cap: None,
            routing: RoutingMode::Either,
            hosts: vec![HostAvailabilityConfig {
                host_ref: id(0x55),
                calendar_refs: vec![id(0x56)],
                host_tz: "UTC".to_owned(),
                working_hours: vec![WeeklyWallWindow {
                    weekday: 0,
                    start_minute: 0,
                    end_minute: 60,
                }],
                preferred_hours: Vec::new(),
            }],
            flex_windows: Vec::new(),
        },
    };
    let body = ClaimBody::new(
        BOOKING_EVENT_TYPE_PREDICATE,
        ClaimSubject::Entity(page),
        encode_event_type_claim_value(&value).expect("config value"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    vault
        .put_claim(&id(0x57), &body, TimeRange { start: 1, end: 1 }, 1)
        .expect("live config");
}

fn nz16(value: u16) -> NonZeroU16 {
    match NonZeroU16::new(value) {
        Some(nz) => nz,
        None => panic!("fixture must be non-zero"),
    }
}

fn nz32(value: u32) -> NonZeroU32 {
    match NonZeroU32::new(value) {
        Some(nz) => nz,
        None => panic!("fixture must be non-zero"),
    }
}

fn nz64(value: u64) -> NonZeroU64 {
    match NonZeroU64::new(value) {
        Some(nz) => nz,
        None => panic!("fixture must be non-zero"),
    }
}

fn scope() -> BookingRuleScope {
    BookingRuleScope {
        page_ref: id(PAGE),
        event_type: Some(EventTypeKey("intro-call".to_owned())),
    }
}

/// Ratified owner-supplied values: 24h/48h notice, 120 slot-list
/// lookups/min with a 45s cache, 10 books/min with one active future
/// booking per email, one active hold per session behind a 30/min IP cap.
fn owner_config() -> BookingAntiAbuseOwnerConfig {
    BookingAntiAbuseOwnerConfig {
        min_intake_chars: nz16(10),
        normal_notice_secs: nz64(86_400),
        high_value_notice_secs: nz64(172_800),
        min_submit_millis: nz64(1_500),
        slot_list_per_minute_per_ip: nz32(120),
        slot_list_cache_ttl_secs: nz64(45),
        book_per_minute_per_ip: nz32(10),
        max_active_future_per_email: 1,
        max_active_holds_per_session: 1,
        hold_per_minute_per_ip: nz32(30),
        tentative_confirm_ttl_secs: nz64(900),
    }
}

fn seed_rows() -> Vec<BookingAntiAbuseRuleRow> {
    default_booking_anti_abuse_rows(
        id(PAGE),
        Some(EventTypeKey("intro-call".to_owned())),
        &owner_config(),
    )
    .expect("seed rows validate")
}

fn install_rows(vault: &Vault, rows: &[BookingAntiAbuseRuleRow]) {
    let scope = &rows.first().expect("rows").scope;
    install_page_and_config(
        vault,
        scope.page_ref,
        scope.event_type.as_ref().expect("event type"),
    );
    for row in rows {
        let outcome = apply_rule_amendment(vault, 0, row.clone(), None).expect("install row");
        assert!(outcome.owner_notice_required);
    }
}

fn seed_rule(rule: &BookingAntiAbuseRule) -> BookingAntiAbuseRuleRow {
    let scope = scope();
    BookingAntiAbuseRuleRow {
        row_id: booking_rule_row_id(&scope, rule),
        scope,
        rule: rule.clone(),
        version: 1,
        amended_at: 1_777_777_777,
        amended_by: id(OWNER),
        owner_stamp_ref: None,
    }
}

fn assert_rejected_without_activation(vault: &Vault, row: BookingAntiAbuseRuleRow) {
    let row_id = row.row_id.clone();
    let scope = row.scope.clone();
    assert!(matches!(
        apply_rule_amendment(vault, 0, row, None),
        Err(BookingError::InvalidConstraint(message)) if message.contains("InvalidBookingPage")
    ));
    assert!(
        booking_anti_abuse_rules(vault, &scope)
            .expect("read rows")
            .is_empty(),
        "a rejected activation must not store a rule row"
    );
    let rtxn = vault.store.env.read_txn().expect("read transaction");
    assert!(
        read_meta_bytes(vault, &rtxn, &notice_key(&row_id, 1))
            .expect("read owner notice")
            .is_none(),
        "a rejected activation must not write an owner notice"
    );
}

fn facts() -> BookingRequestFacts {
    BookingRequestFacts {
        page_ref: id(PAGE),
        event_type: Some(EventTypeKey("intro-call".to_owned())),
        ip_hash: booking_ip_hash("203.0.113.10"),
        email_hash: None,
        session_hash: Some(booking_session_hash("sess-alpha")),
        started_at_millis: 1_000_000,
        submitted_at_millis: 1_000_000 + 5_000,
        submission_fingerprint: digest_with(b"test-submission", b"facts"),
        selected_slot_hash: digest_with(b"test-slot", b"slot-alpha"),
        intake_content_hash: digest_with(b"test-intake", b"canonical intake"),
        honeypot_nonempty: false,
        intake_chars: 40,
        active_future_bookings_for_email: 0,
        active_holds_for_session: 0,
        email: None,
    }
}

fn amend_with(rule: &BookingAntiAbuseRule, version: u64) -> BookingAntiAbuseRuleRow {
    BookingAntiAbuseRuleRow {
        version,
        ..seed_rule(rule)
    }
}

#[test]
fn owner_config_rows_cover_exact_ship_skip_reserve_stack() {
    let rows = seed_rows();
    assert_eq!(
        rows.len(),
        10,
        "eight SHIP controls plus two RESERVE rows, nothing else"
    );

    let mut required_intake = 0;
    let mut minimum_notice = 0;
    let mut honeypot_floor = 0;
    let mut slot_list_rate = 0;
    let mut book_rate = 0;
    let mut hold_rate = 0;
    let mut email_prompt = 0;
    let mut quarantine = 0;
    let mut otp_reserve = 0;
    let mut link_reserve = 0;
    for row in &rows {
        // This match is deliberately exhaustive: the SKIP stack ships by
        // absence, so the compiler proves the closed variant set carries
        // no interactive-challenge or client-probing control.
        match &row.rule {
            BookingAntiAbuseRule::RequiredIntake { min_chars } => {
                required_intake += 1;
                assert_eq!(min_chars.get(), 10);
            }
            BookingAntiAbuseRule::MinimumNotice { .. } => minimum_notice += 1,
            BookingAntiAbuseRule::HoneypotAndSubmitFloor { .. } => honeypot_floor += 1,
            BookingAntiAbuseRule::SlotListRate { .. } => slot_list_rate += 1,
            BookingAntiAbuseRule::BookRate { .. } => book_rate += 1,
            BookingAntiAbuseRule::HoldRate { .. } => hold_rate += 1,
            BookingAntiAbuseRule::EmailPromptToCorrect {
                check_syntax,
                check_mx,
                check_disposable_domain,
            } => {
                email_prompt += 1;
                assert!(*check_syntax && *check_mx && *check_disposable_domain);
            }
            BookingAntiAbuseRule::QuarantineBorderline => quarantine += 1,
            BookingAntiAbuseRule::EmailOtpReserve { enabled } => {
                otp_reserve += 1;
                assert!(!enabled, "OTP reserve starts off");
            }
            BookingAntiAbuseRule::TentativeConfirmLinkReserve {
                enabled,
                expires_after_secs,
            } => {
                link_reserve += 1;
                assert!(!enabled, "confirm-link reserve starts off");
                assert_eq!(expires_after_secs.get(), 900);
            }
        }
        validate_rule_row(row).expect("seed row must validate");
        assert!(row.owner_stamp_ref.is_none());
        assert_eq!(row.version, 1);
    }
    assert_eq!(
        (
            required_intake,
            minimum_notice,
            honeypot_floor,
            slot_list_rate,
            book_rate,
            hold_rate,
            email_prompt,
            quarantine,
            otp_reserve,
            link_reserve
        ),
        (1, 1, 1, 1, 1, 1, 1, 1, 1, 1),
        "exactly one SHIP row per control plus the two RESERVE rows"
    );
}

#[test]
fn owner_config_thresholds_validate_ratified_ranges_without_constants() {
    let config = owner_config();
    let rows = seed_rows();
    let mut seen_slot = false;
    let mut seen_notice = false;
    let mut seen_book = false;
    let mut seen_hold = false;
    let mut seen_intake = false;
    let mut seen_floor = false;
    for row in &rows {
        match &row.rule {
            BookingAntiAbuseRule::SlotListRate {
                per_minute_per_ip,
                cache_ttl_secs,
            } => {
                seen_slot = true;
                assert_eq!(per_minute_per_ip.get(), 120);
                assert_eq!(cache_ttl_secs.get(), 45);
                assert_eq!(*per_minute_per_ip, config.slot_list_per_minute_per_ip);
                assert_eq!(*cache_ttl_secs, config.slot_list_cache_ttl_secs);
            }
            BookingAntiAbuseRule::MinimumNotice {
                normal_secs,
                high_value_secs,
            } => {
                seen_notice = true;
                assert_eq!(normal_secs.get(), 86_400);
                assert_eq!(high_value_secs.get(), 172_800);
                assert_eq!(*normal_secs, config.normal_notice_secs);
                assert_eq!(*high_value_secs, config.high_value_notice_secs);
            }
            BookingAntiAbuseRule::BookRate {
                per_minute_per_ip,
                max_active_future_per_email,
            } => {
                seen_book = true;
                assert_eq!(per_minute_per_ip.get(), 10);
                assert_eq!(*max_active_future_per_email, 1);
            }
            BookingAntiAbuseRule::HoldRate {
                max_active_per_session,
                per_minute_per_ip,
            } => {
                seen_hold = true;
                assert_eq!(*max_active_per_session, 1);
                assert_eq!(per_minute_per_ip.get(), 30);
            }
            BookingAntiAbuseRule::RequiredIntake { min_chars } => {
                seen_intake = true;
                assert_eq!(*min_chars, config.min_intake_chars);
            }
            BookingAntiAbuseRule::HoneypotAndSubmitFloor { min_submit_millis } => {
                seen_floor = true;
                assert_eq!(*min_submit_millis, config.min_submit_millis);
            }
            _ => {}
        }
    }
    assert!(
        seen_slot && seen_notice && seen_book && seen_hold && seen_intake && seen_floor,
        "every owner-chosen threshold preserved through construction"
    );

    // Nothing is baked: changing one constructor argument changes the row.
    let mut tuned = owner_config();
    tuned.slot_list_per_minute_per_ip = nz32(99);
    let retuned = default_booking_anti_abuse_rows(
        id(PAGE),
        Some(EventTypeKey("intro-call".to_owned())),
        &tuned,
    )
    .expect("retuned rows");
    let slot = retuned
        .iter()
        .find_map(|row| match &row.rule {
            BookingAntiAbuseRule::SlotListRate {
                per_minute_per_ip, ..
            } => Some(*per_minute_per_ip),
            _ => None,
        })
        .expect("slot row");
    assert_eq!(slot.get(), 99);

    // Ratified ranges hold: cache TTL outside 30-60, inverted notice
    // dials, and an out-of-band email cap all refuse.
    for bad_ttl in [29_u64, 61] {
        let row = seed_rule(&BookingAntiAbuseRule::SlotListRate {
            per_minute_per_ip: nz32(120),
            cache_ttl_secs: nz64(bad_ttl),
        });
        assert!(
            validate_rule_row(&row).is_err(),
            "ttl {bad_ttl} must refuse"
        );
    }
    let inverted = seed_rule(&BookingAntiAbuseRule::MinimumNotice {
        normal_secs: nz64(200_000),
        high_value_secs: nz64(100_000),
    });
    assert!(validate_rule_row(&inverted).is_err());
    for bad_cap in [0_u8, 3] {
        let row = seed_rule(&BookingAntiAbuseRule::BookRate {
            per_minute_per_ip: nz32(10),
            max_active_future_per_email: bad_cap,
        });
        assert!(
            validate_rule_row(&row).is_err(),
            "cap {bad_cap} must refuse"
        );
    }
    let good_cap = seed_rule(&BookingAntiAbuseRule::BookRate {
        per_minute_per_ip: nz32(10),
        max_active_future_per_email: 2,
    });
    assert!(validate_rule_row(&good_cap).is_ok());
}

#[test]
fn tightening_auto_applies_and_emits_notice() {
    let (_dir, vault) = open_vault();
    install_rows(&vault, &seed_rows());
    let row_id = booking_rule_row_id(
        &scope(),
        &BookingAntiAbuseRule::RequiredIntake {
            min_chars: nz16(10),
        },
    );

    let mut tighter = amend_with(
        &BookingAntiAbuseRule::RequiredIntake {
            min_chars: nz16(20),
        },
        2,
    );
    tighter.row_id.clone_from(&row_id);
    let outcome = apply_rule_amendment(&vault, 1, tighter.clone(), None).expect("tighten");
    assert!(outcome.owner_notice_required);
    assert_eq!(outcome.stored.version, 2);
    assert!(outcome.stored.owner_stamp_ref.is_none());

    let rows = booking_anti_abuse_rules(&vault, &scope()).expect("read rows");
    let stored = rows
        .iter()
        .find(|row| row.row_id == row_id)
        .expect("stored row");
    assert_eq!(
        stored.rule,
        BookingAntiAbuseRule::RequiredIntake {
            min_chars: nz16(20)
        }
    );
    assert_eq!(stored.version, 2);

    let notices = booking_anti_abuse_notices(&vault).expect("notices");
    let row_notices: Vec<&String> = notices
        .iter()
        .filter(|notice| notice.contains(&row_id))
        .collect();
    assert_eq!(row_notices.len(), 2, "one notice per activation");
    assert!(row_notices[0].contains("version 1 (tightening)"));
    assert!(row_notices[1].contains("version 2 (tightening)"));

    // The compare-and-set refuses a stale expected version.
    let stale = apply_rule_amendment(&vault, 1, tighter, None);
    assert!(stale.is_err(), "stale expected version must refuse");
}

#[test]
fn loosening_requires_exact_row_version_stamp_hash() {
    let (_dir, vault) = open_vault();
    install_rows(&vault, &seed_rows());
    let row_id = booking_rule_row_id(
        &scope(),
        &BookingAntiAbuseRule::RequiredIntake {
            min_chars: nz16(10),
        },
    );

    let mut looser = amend_with(
        &BookingAntiAbuseRule::RequiredIntake { min_chars: nz16(4) },
        2,
    );
    looser.row_id.clone_from(&row_id);

    // No stamp: refused.
    assert!(
        apply_rule_amendment(&vault, 1, looser.clone(), None).is_err(),
        "a loosening without a stamp must refuse"
    );

    // A stamp bound to a different proposed row: refused.
    let other = amend_with(
        &BookingAntiAbuseRule::RequiredIntake { min_chars: nz16(6) },
        2,
    );
    let other_hash = booking_rule_row_version_hash(&other).expect("hash other");
    let wrong_row_stamp = BookingRuleOwnerStampBinding {
        stamp_ref: id(STAMP),
        proposed_row_version_hash: other_hash,
    };
    assert!(
        apply_rule_amendment(&vault, 1, looser.clone(), Some(&wrong_row_stamp)).is_err(),
        "a stamp bound to different rows must refuse"
    );

    // A stamp bound to the same rows but a different version: refused.
    let wrong_version = amend_with(
        &BookingAntiAbuseRule::RequiredIntake { min_chars: nz16(4) },
        3,
    );
    let wrong_version_stamp = BookingRuleOwnerStampBinding {
        stamp_ref: id(STAMP),
        proposed_row_version_hash: booking_rule_row_version_hash(&wrong_version)
            .expect("hash wrong version"),
    };
    assert!(
        apply_rule_amendment(&vault, 1, looser.clone(), Some(&wrong_version_stamp)).is_err(),
        "a stamp bound to a different version must refuse"
    );

    // Only the exact binding activates, and the transaction records it.
    let exact_hash = booking_rule_row_version_hash(&looser).expect("hash looser");
    let stamp = BookingRuleOwnerStampBinding {
        stamp_ref: id(STAMP),
        proposed_row_version_hash: exact_hash,
    };
    let outcome = apply_rule_amendment(&vault, 1, looser, Some(&stamp)).expect("stamped loosening");
    assert!(outcome.owner_notice_required);
    assert_eq!(outcome.stored.owner_stamp_ref, Some(id(STAMP)));
    assert_eq!(outcome.stored.version, 2);

    let rows = booking_anti_abuse_rules(&vault, &scope()).expect("read rows");
    let stored = rows
        .iter()
        .find(|row| row.row_id == row_id)
        .expect("stored row");
    assert_eq!(stored.owner_stamp_ref, Some(id(STAMP)));

    // No staged state lingers: a fresh proposal needs a fresh binding.
    let replay = amend_with(
        &BookingAntiAbuseRule::RequiredIntake { min_chars: nz16(2) },
        3,
    );
    let replay_bound_stamp = BookingRuleOwnerStampBinding {
        proposed_row_version_hash: booking_rule_row_version_hash(&replay).expect("hash replay"),
        ..stamp
    };
    assert!(
        apply_rule_amendment(&vault, 2, replay, Some(&replay_bound_stamp)).is_ok(),
        "a fresh stamp binds a fresh proposal; nothing pending exists to replay"
    );
}

#[test]
fn activation_refuses_a_missing_booking_page() {
    let (_dir, vault) = open_vault();
    let row = seed_rule(&BookingAntiAbuseRule::RequiredIntake {
        min_chars: nz16(10),
    });
    assert_rejected_without_activation(&vault, row);
}

#[test]
fn page_wide_activation_refuses_an_existing_non_booking_subject() {
    let (_dir, vault) = open_vault();
    let mut row = seed_rule(&BookingAntiAbuseRule::RequiredIntake {
        min_chars: nz16(10),
    });
    row.scope.event_type = None;
    row.row_id = booking_rule_row_id(&row.scope, &row.rule);
    vault
        .put_entity(
            &row.scope.page_ref,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"non-booking subject fixture",
        )
        .expect("non-booking entity");
    assert_rejected_without_activation(&vault, row);
}

#[test]
fn activation_refuses_a_page_without_live_event_configuration() {
    let (_dir, vault) = open_vault();
    let row = seed_rule(&BookingAntiAbuseRule::RequiredIntake {
        min_chars: nz16(10),
    });
    vault
        .put_entity(
            &row.scope.page_ref,
            crate::registry::ENTITY_TYPE_EVENT,
            TimeRange { start: 1, end: 1 },
            1,
            b"booking page fixture",
        )
        .expect("page entity");
    assert_rejected_without_activation(&vault, row);
}

#[test]
fn activation_refuses_a_mismatched_live_event_configuration() {
    let (_dir, vault) = open_vault();
    let row = seed_rule(&BookingAntiAbuseRule::RequiredIntake {
        min_chars: nz16(10),
    });
    install_page_and_config(
        &vault,
        row.scope.page_ref,
        &EventTypeKey("different-event".to_owned()),
    );
    assert_rejected_without_activation(&vault, row);
}

#[test]
fn page_wide_activation_accepts_a_configured_booking_page() {
    let (_dir, vault) = open_vault();
    let mut row = seed_rule(&BookingAntiAbuseRule::RequiredIntake {
        min_chars: nz16(10),
    });
    row.scope.event_type = None;
    row.row_id = booking_rule_row_id(&row.scope, &row.rule);
    install_page_and_config(
        &vault,
        row.scope.page_ref,
        &EventTypeKey("intro-call".to_owned()),
    );
    let outcome = apply_rule_amendment(&vault, 0, row.clone(), None)
        .expect("configured booking page activates page-wide row");
    assert!(outcome.owner_notice_required);
    assert_eq!(
        booking_anti_abuse_rules(&vault, &row.scope)
            .expect("read rows")
            .as_slice(),
        &[row]
    );
}

#[test]
fn put_rule_is_private_and_public_activation_is_amendment_only() {
    let (_dir, vault) = open_vault();
    let first = seed_rule(&BookingAntiAbuseRule::RequiredIntake {
        min_chars: nz16(10),
    });

    // First activation is a version-0-expected, version-1 proposal.
    install_page_and_config(
        &vault,
        first.scope.page_ref,
        first.scope.event_type.as_ref().expect("event type"),
    );
    assert!(apply_rule_amendment(&vault, 0, first.clone(), None).is_ok());

    // The private-put bypasses this module cannot offer: every wrong
    // version framing refuses, so only the versioned transaction stores.
    assert!(
        apply_rule_amendment(&vault, 0, first.clone(), None).is_err(),
        "re-creation through the version-0 door must refuse an existing row"
    );
    let mut v3 = first.clone();
    v3.version = 3;
    assert!(
        apply_rule_amendment(&vault, 1, v3, None).is_err(),
        "skipping a version must refuse"
    );
    let mut v1_again = first;
    v1_again.version = 1;
    assert!(
        apply_rule_amendment(&vault, 1, v1_again, None).is_err(),
        "restating version 1 must refuse"
    );
    let v2 = amend_with(
        &BookingAntiAbuseRule::RequiredIntake {
            min_chars: nz16(20),
        },
        2,
    );
    assert!(
        apply_rule_amendment(&vault, 5, v2, None).is_err(),
        "an expected version the store does not hold must refuse"
    );

    // What did land is exactly what the versioned transaction reports.
    let rows = booking_anti_abuse_rules(&vault, &scope()).expect("read rows");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].version, 1);
}

#[test]
fn amendment_direction_orders_each_variant_axis() {
    let scope = scope();
    let current = BookingAntiAbuseRuleRow {
        row_id: booking_rule_row_id(
            &scope,
            &BookingAntiAbuseRule::MinimumNotice {
                normal_secs: nz64(86_400),
                high_value_secs: nz64(172_800),
            },
        ),
        scope: scope.clone(),
        rule: BookingAntiAbuseRule::MinimumNotice {
            normal_secs: nz64(86_400),
            high_value_secs: nz64(172_800),
        },
        version: 1,
        amended_at: 7,
        amended_by: id(OWNER),
        owner_stamp_ref: None,
    };
    let mut proposed = current.clone();
    proposed.version = 2;
    assert_eq!(
        amendment_direction(&current, &proposed).expect("ordered"),
        AmendmentDirection::Equivalent
    );

    proposed.rule = BookingAntiAbuseRule::MinimumNotice {
        normal_secs: nz64(100_000),
        high_value_secs: nz64(172_800),
    };
    assert_eq!(
        amendment_direction(&current, &proposed).expect("ordered"),
        AmendmentDirection::Tightening
    );

    proposed.rule = BookingAntiAbuseRule::MinimumNotice {
        normal_secs: nz64(100_000),
        high_value_secs: nz64(100_000),
    };
    assert_eq!(
        amendment_direction(&current, &proposed).expect("ordered"),
        AmendmentDirection::Loosening,
        "one loosened axis routes the whole amendment to the stamp"
    );

    // Variant drift is unorderable and therefore a stamp case.
    proposed.rule = BookingAntiAbuseRule::QuarantineBorderline;
    assert_eq!(
        amendment_direction(&current, &proposed).expect("ordered"),
        AmendmentDirection::Loosening
    );
    proposed.rule = BookingAntiAbuseRule::MinimumNotice {
        normal_secs: nz64(86_400),
        high_value_secs: nz64(172_800),
    };

    // Versions must advance by exactly one; scope and id are immutable.
    proposed.version = 3;
    assert!(amendment_direction(&current, &proposed).is_err());
    proposed.version = 2;
    proposed.scope = BookingRuleScope {
        page_ref: id(OTHER_PAGE),
        event_type: None,
    };
    assert!(amendment_direction(&current, &proposed).is_err());

    // Slot-list: lowering the minute cap tightens; a TTL-only move is an
    // equivalent re-assertion.
    let slot = BookingAntiAbuseRuleRow {
        row_id: booking_rule_row_id(
            &scope,
            &BookingAntiAbuseRule::SlotListRate {
                per_minute_per_ip: nz32(120),
                cache_ttl_secs: nz64(45),
            },
        ),
        scope,
        rule: BookingAntiAbuseRule::SlotListRate {
            per_minute_per_ip: nz32(120),
            cache_ttl_secs: nz64(45),
        },
        version: 1,
        amended_at: 7,
        amended_by: id(OWNER),
        owner_stamp_ref: None,
    };
    let mut slot_tighter = slot.clone();
    slot_tighter.version = 2;
    slot_tighter.rule = BookingAntiAbuseRule::SlotListRate {
        per_minute_per_ip: nz32(60),
        cache_ttl_secs: nz64(45),
    };
    assert_eq!(
        amendment_direction(&slot, &slot_tighter).expect("ordered"),
        AmendmentDirection::Tightening
    );
    let mut slot_refresh = slot.clone();
    slot_refresh.version = 2;
    slot_refresh.rule = BookingAntiAbuseRule::SlotListRate {
        per_minute_per_ip: nz32(120),
        cache_ttl_secs: nz64(30),
    };
    assert_eq!(
        amendment_direction(&slot, &slot_refresh).expect("ordered"),
        AmendmentDirection::Equivalent,
        "the cache TTL shapes freshness, not admission"
    );
}

#[test]
fn version_hash_binds_the_exact_row_and_version() {
    let row = seed_rule(&BookingAntiAbuseRule::RequiredIntake {
        min_chars: nz16(10),
    });
    let hash = booking_rule_row_version_hash(&row).expect("hash");
    assert_eq!(hash, booking_rule_row_version_hash(&row).expect("hash"));

    let mut bumped = row.clone();
    bumped.version = 2;
    assert_ne!(hash, booking_rule_row_version_hash(&bumped).expect("hash"));

    let mut stamped_elsewhere = row;
    stamped_elsewhere.amended_at += 1;
    assert_ne!(
        hash,
        booking_rule_row_version_hash(&stamped_elsewhere).expect("hash"),
        "any field move re-keys the binding"
    );
}

#[test]
fn invalid_email_prompts_but_does_not_hard_block() {
    let rows = vec![
        seed_rule(&BookingAntiAbuseRule::EmailPromptToCorrect {
            check_syntax: true,
            check_mx: true,
            check_disposable_domain: true,
        }),
        seed_rule(&BookingAntiAbuseRule::HoneypotAndSubmitFloor {
            min_submit_millis: nz64(1),
        }),
    ];
    let mut facts = facts();

    facts.email = Some(EmailValidationEvidence {
        syntax_valid: false,
        mx_present: Some(true),
        disposable_domain: false,
    });
    assert!(matches!(
        evaluate_booking_request(&rows, &facts),
        BookingAbuseVerdict::PromptCorrection { field: "email", .. }
    ));

    facts.email = Some(EmailValidationEvidence {
        syntax_valid: true,
        mx_present: Some(false),
        disposable_domain: false,
    });
    assert!(matches!(
        evaluate_booking_request(&rows, &facts),
        BookingAbuseVerdict::PromptCorrection { field: "email", .. }
    ));

    facts.email = Some(EmailValidationEvidence {
        syntax_valid: true,
        mx_present: Some(true),
        disposable_domain: true,
    });
    assert!(matches!(
        evaluate_booking_request(&rows, &facts),
        BookingAbuseVerdict::PromptCorrection { field: "email", .. }
    ));

    // An unperformed MX check is no signal: the request proceeds.
    facts.email = Some(EmailValidationEvidence {
        syntax_valid: true,
        mx_present: None,
        disposable_domain: false,
    });
    assert_eq!(
        evaluate_booking_request(&rows, &facts),
        BookingAbuseVerdict::Allow
    );

    // Multi-signal inconsistency without the quarantine row under-blocks
    // into a prompt rather than any permanent denial.
    facts.email = Some(EmailValidationEvidence {
        syntax_valid: false,
        mx_present: Some(false),
        disposable_domain: true,
    });
    let verdict = evaluate_booking_request(&rows, &facts);
    assert!(
        matches!(
            verdict,
            BookingAbuseVerdict::PromptCorrection { field: "email", .. }
        ),
        "never a hard block: {verdict:?}"
    );
}

#[test]
fn borderline_submission_builds_pending_review_inbox_group() {
    let (_dir, vault) = open_vault();
    let rows = vec![
        seed_rule(&BookingAntiAbuseRule::EmailPromptToCorrect {
            check_syntax: true,
            check_mx: true,
            check_disposable_domain: true,
        }),
        seed_rule(&BookingAntiAbuseRule::QuarantineBorderline),
    ];
    let mut facts = facts();
    facts.email = Some(EmailValidationEvidence {
        syntax_valid: true,
        mx_present: Some(false),
        disposable_domain: true,
    });
    let verdict = evaluate_booking_request(&rows, &facts);
    let BookingAbuseVerdict::Quarantine { reason } = verdict else {
        panic!("two live negatives route to quarantine: {verdict:?}");
    };

    // The quarantine claim names the page as its subject through the
    // ordinary claim door, so the fixture page exists the way a
    // published booking page does.
    vault
        .put_entity(
            &facts.page_ref,
            crate::registry::ENTITY_TYPE_EVENT,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"booking page fixture",
        )
        .expect("page entity");
    let receipt = quarantine_borderline_submission(&vault, &facts, &reason, 1).expect("quarantine");

    // The pending-review pattern, verified through the same store doors
    // `inbox.rs`'s pending-group construction reads and writes.
    let run_id = {
        let rtxn = vault.store.env.read_txn().expect("read txn");
        let claim = EntityId::from_bytes(receipt.claim_id).expect("claim id bytes");
        let pending = vault
            .store
            .pending_gate_consent_in_txn(&rtxn, &claim)
            .expect("pending read")
            .expect("pending row present");
        assert_eq!(pending.claim_id, receipt.claim_id);
        assert_eq!(pending.version, 0);
        assert!(
            !pending.diff_handle.is_empty(),
            "the consent binding handle the pattern requires"
        );
        assert_eq!(pending.reason_codes, receipt.reason_codes);
        assert!(
            pending
                .reason_codes
                .iter()
                .all(|code| code.starts_with("gate.pending.")),
            "exactly the pending-review reason family the inbox pattern carries"
        );
        let decision = vault
            .store
            .gate_decision_in_txn(&rtxn, pending.decision_id)
            .expect("decision read")
            .expect("decision row present");
        assert_eq!(decision.outcome, "pending");
        assert_eq!(decision.claim_id, Some(receipt.claim_id));
        assert_eq!(
            decision.diff_handle, pending.diff_handle,
            "the decision and the pending row bind one claim body"
        );

        // The scan door behind pending-group enumeration still surfaces
        // the row.
        let scanned = vault
            .store
            .pending_gate_consents_in_txn(&rtxn, 50)
            .expect("pending scan");
        assert!(
            scanned.iter().any(|row| row.claim_id == receipt.claim_id),
            "the pending-review scan must enumerate the quarantined submission"
        );

        pending
            .dreamer_run_id
            .expect("a quarantine row stamps a pending-review run id")
    };

    // The minted CLAIM body is durable at the content-keyed id.
    let claim = EntityId::from_bytes(receipt.claim_id).expect("claim id bytes");
    let body = vault
        .get_claim(&claim)
        .expect("claim read")
        .expect("quarantine claim stored");
    assert_eq!(body.predicate, QUARANTINE_CLAIM_PREDICATE);
    assert_eq!(body.subject, ClaimSubject::Entity(facts.page_ref));
    assert_eq!(body.approval, ClaimApprovalStatus::Proposed);

    // Done-means: `Vault::inbox_groups` with a nonzero limit returns the
    // quarantined submission as a pending-review group member — not
    // merely a raw pending-scan row. Review-everything is the dial
    // stance that shows every open member; under the default
    // exceptions-only dial the card waits held, never lost.
    vault
        .set_inbox_review_dial(crate::inbox::InboxReviewDial::ReviewEverything)
        .expect("review dial");
    let groups = vault
        .inbox_groups(crate::inbox::InboxQuery::new(10))
        .expect("inbox groups");
    let group = groups
        .iter()
        .find(|group| group.run_id == run_id)
        .expect("the quarantine run projects a pending-review inbox group");
    assert!(
        group
            .members
            .iter()
            .any(|member| member.claim_id == receipt.claim_ref),
        "the quarantined claim surfaces as a pending-review card member: {groups:?}"
    );
    assert_eq!(group.new_claim_count, 1);
}

#[test]
fn booking_rule_row_ids_bind_full_page_and_event_identity() {
    // Two pages sharing their first four id bytes — the prefix the old
    // derivation keyed on — must still own distinct rows.
    let mut head_a = [0x61_u8; 16];
    head_a[4..].copy_from_slice(&[0x00; 12]);
    let mut head_b = [0x61_u8; 16];
    head_b[4..].copy_from_slice(&[0xCC; 12]);
    let page_a = EntityId::from_bytes(head_a).expect("page a");
    let page_b = EntityId::from_bytes(head_b).expect("page b");
    let event = EventTypeKey("intro-call".to_owned());
    let rule = BookingAntiAbuseRule::SlotListRate {
        per_minute_per_ip: nz32(120),
        cache_ttl_secs: nz64(45),
    };
    let scope_a = BookingRuleScope {
        page_ref: page_a,
        event_type: Some(event.clone()),
    };
    let scope_b = BookingRuleScope {
        page_ref: page_b,
        event_type: Some(event.clone()),
    };

    let id_a = booking_rule_row_id(&scope_a, &rule);
    let id_b = booking_rule_row_id(&scope_b, &rule);
    assert_ne!(
        id_a, id_b,
        "prefix-colliding pages still own distinct row ids"
    );
    assert_ne!(
        rule_row_key(&id_a),
        rule_row_key(&id_b),
        "distinct ids never share a storage key"
    );

    // The full page hex and the full 32-byte event-key digest are bound —
    // no 8/4-hex truncation anywhere in the id.
    assert!(id_a.contains(&page_a.to_hex()));
    let event_digest = digest_with(RULE_KEY_DOMAIN, event.0.as_bytes());
    assert!(id_a.contains(&hex_lower(&event_digest)));
    assert!(id_a.len() <= ROW_ID_MAX_LEN);

    // Both pages activate their full stack at the expected first
    // version: the second page never trips the first page's
    // "already exists".
    let (_dir, vault) = open_vault();
    for page in [page_a, page_b] {
        install_page_and_config(&vault, page, &event);
        let rows = default_booking_anti_abuse_rows(page, Some(event.clone()), &owner_config())
            .expect("seed rows");
        for row in rows {
            let outcome = apply_rule_amendment(&vault, 0, row, None).expect("activate");
            assert_eq!(outcome.stored.version, 1);
        }
    }
    let listed_a = booking_anti_abuse_rules(&vault, &scope_a).expect("list a");
    let listed_b = booking_anti_abuse_rules(&vault, &scope_b).expect("list b");
    assert_eq!(listed_a.len(), 10, "page a owns its ten rows");
    assert_eq!(listed_b.len(), 10, "page b owns its ten rows");
}

#[test]
fn honeypot_signal_requires_an_activated_honeypot_floor_row() {
    let mut facts = facts();
    facts.honeypot_nonempty = true;

    // No rows at all: the honeypot signal must not invent a rejection —
    // the sole public activation path decides which controls fire.
    let verdict = evaluate_booking_request(&[], &facts);
    assert_ne!(
        verdict,
        BookingAbuseVerdict::SilentHttp200Reject,
        "an unactivated honeypot control must not fire: {verdict:?}"
    );

    // Rows in scope that omit HoneypotAndSubmitFloor: the same law.
    let rows = vec![seed_rule(&BookingAntiAbuseRule::RequiredIntake {
        min_chars: nz16(10),
    })];
    let verdict = evaluate_booking_request(&rows, &facts);
    assert_ne!(
        verdict,
        BookingAbuseVerdict::SilentHttp200Reject,
        "a scope without the honeypot row must not fire it: {verdict:?}"
    );

    // With the row activated, the control keeps its silent-200 shape.
    let rows = seed_rows();
    let verdict = evaluate_booking_request(&rows, &facts);
    assert_eq!(
        verdict,
        BookingAbuseVerdict::SilentHttp200Reject,
        "the activated honeypot row still rejects silently"
    );
}

#[test]
fn slot_list_cache_window_is_bound_and_lazy_expiring() {
    let (_dir, vault) = open_vault();
    let page = id(PAGE);
    let event = EventTypeKey("intro-call".to_owned());
    let body = b"{\"slots\":[]}".to_vec();

    assert!(
        write_slot_list_cache(&vault, &page, Some(&event), &body, nz64(29), 1_000).is_err(),
        "TTL below the ratified window refuses"
    );
    assert!(
        write_slot_list_cache(&vault, &page, Some(&event), &body, nz64(61), 1_000).is_err(),
        "TTL above the ratified window refuses"
    );
    write_slot_list_cache(&vault, &page, Some(&event), &body, nz64(45), 1_000)
        .expect("cache write");

    assert_eq!(
        read_slot_list_cache(&vault, &page, Some(&event), 1_000).expect("read"),
        Some(body.clone())
    );
    assert_eq!(
        read_slot_list_cache(&vault, &page, Some(&event), 1_044).expect("read"),
        Some(body)
    );
    assert_eq!(
        read_slot_list_cache(&vault, &page, Some(&event), 1_045).expect("read"),
        None,
        "the 45s window closes exactly at 1_045"
    );

    let other_page = id(OTHER_PAGE);
    assert_eq!(
        read_slot_list_cache(&vault, &other_page, Some(&event), 1_000).expect("read"),
        None,
        "cache entries are scope-keyed"
    );
    assert_eq!(
        read_slot_list_cache(&vault, &page, None, 1_000).expect("read"),
        None,
        "page-wide and type-scoped entries never alias"
    );
}

#[test]
fn rate_counters_window_rollover_and_reset() {
    let (_dir, vault) = open_vault();
    let ip = booking_ip_hash("198.51.100.7");
    assert_eq!(
        observe_slot_list_request(&vault, &ip, nz32(2), 120).expect("count"),
        BookingRateDecision::Allowed
    );
    assert_eq!(
        observe_slot_list_request(&vault, &ip, nz32(2), 150).expect("count"),
        BookingRateDecision::Allowed
    );
    let exceeded = observe_slot_list_request(&vault, &ip, nz32(2), 179).expect("count");
    assert_eq!(
        exceeded,
        BookingRateDecision::Exceeded {
            retry_after_secs: 60 - 179 % 60
        }
    );
    // A rejected request consumed nothing: re-asking in the same window
    // stays rejected rather than sneaking a token in.
    assert_eq!(
        observe_slot_list_request(&vault, &ip, nz32(2), 179).expect("count"),
        exceeded
    );
    // The next window overwrites the same key rather than stacking rows.
    assert_eq!(
        observe_slot_list_request(&vault, &ip, nz32(2), 180).expect("count"),
        BookingRateDecision::Allowed
    );
}

#[test]
fn quarantine_scope_quota_bounds_rotating_identities() {
    let (_dir, vault) = open_vault();
    let page = id(PAGE);
    let _event = EventTypeKey("intro-call".to_owned());
    for n in 0..8_u8 {
        let ip = [n; 32];
        let email = [n.wrapping_add(10); 32];
        // Event strings are deliberately absent from the page-wide key.
        let _attacker_event = EventTypeKey(format!("attacker-event-{n}"));
        let decision =
            observe_quarantine_request(&vault, &page, nz32(1), 120).expect("quota write");
        if n == 0 {
            assert_eq!(decision, BookingRateDecision::Allowed);
        } else {
            assert!(
                matches!(decision, BookingRateDecision::Exceeded { .. }),
                "rotating IP/email {ip:?}/{email:?} cannot mint another quarantine budget"
            );
        }
    }
    let rtxn = vault.store.env.read_txn().expect("counter read txn");
    let mut counters = 0;
    let prefix = [BOOKING_ANTI_ABUSE_META_PREFIX, RATE_KEY_TAG].concat();
    for row in vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, &prefix)
        .expect("counter scan")
    {
        row.expect("counter row");
        counters += 1;
    }
    assert_eq!(
        counters, 1,
        "rotating events retain one page-wide counter row"
    );
}

#[test]
fn server_submission_fingerprint_ignores_untrusted_timing() {
    let original = facts();
    let mut timestamp_only_retry = original.clone();
    timestamp_only_retry.started_at_millis = 0;
    timestamp_only_retry.submitted_at_millis = u64::MAX;
    assert_eq!(
        server_submission_fingerprint(&original),
        server_submission_fingerprint(&timestamp_only_retry),
        "changing only transport timing cannot mint a new quarantine identity"
    );
    let mut distinct = original.clone();
    distinct.intake_content_hash = digest_with(b"test-intake", b"different same-length");
    assert_ne!(
        server_submission_fingerprint(&original),
        server_submission_fingerprint(&distinct),
        "canonical submitted evidence distinguishes a separate submission"
    );
}

#[test]
fn quarantine_claim_identity_binds_event_type_presence_and_value() {
    let (_dir, vault) = open_vault();
    let mut facts_a = facts();
    facts_a.event_type = Some(EventTypeKey("intro-call".to_owned()));
    let mut facts_b = facts();
    facts_b.event_type = Some(EventTypeKey("sales-call".to_owned()));
    let shared_millis = 1_700_000_000_000_u64;
    facts_a.submitted_at_millis = shared_millis;
    facts_b.submitted_at_millis = shared_millis;
    facts_a.email_hash = None;
    facts_b.email_hash = None;
    let reason = "quarantine-test";
    for facts in [&facts_a, &facts_b] {
        vault
            .put_entity(
                &facts.page_ref,
                crate::registry::ENTITY_TYPE_EVENT,
                crate::temporal::TimeRange { start: 1, end: 1 },
                1,
                b"booking page fixture",
            )
            .ok();
    }
    let receipt_a =
        quarantine_borderline_submission(&vault, &facts_a, reason, 1).expect("quarantine a");
    let receipt_b =
        quarantine_borderline_submission(&vault, &facts_b, reason, 1).expect("quarantine b");
    assert_ne!(
        receipt_a.claim_id, receipt_b.claim_id,
        "distinct event types must mint distinct claim ids"
    );
    assert_ne!(
        receipt_a.claim_ref, receipt_b.claim_ref,
        "claim_ref hex must differ"
    );
    let run_a = format!(
        "{QUARANTINE_RUN_ID_PREFIX}{}",
        hex_lower(&receipt_a.claim_id)
    );
    let run_b = format!(
        "{QUARANTINE_RUN_ID_PREFIX}{}",
        hex_lower(&receipt_b.claim_id)
    );
    assert_ne!(run_a, run_b, "synthetic run ids must differ across events");
    {
        let rtxn = vault.store.env.read_txn().expect("read txn");
        let claim_a = EntityId::from_bytes(receipt_a.claim_id).expect("claim a bytes");
        let claim_b = EntityId::from_bytes(receipt_b.claim_id).expect("claim b bytes");
        let pending_a = vault
            .store
            .pending_gate_consent_in_txn(&rtxn, &claim_a)
            .expect("pending a read")
            .expect("pending a present");
        let pending_b = vault
            .store
            .pending_gate_consent_in_txn(&rtxn, &claim_b)
            .expect("pending b read")
            .expect("pending b present");
        assert_eq!(pending_a.claim_id, receipt_a.claim_id);
        assert_eq!(pending_b.claim_id, receipt_b.claim_id);
        assert_ne!(pending_a.decision_id, pending_b.decision_id);
    }
    {
        let claim_a = EntityId::from_bytes(receipt_a.claim_id).expect("claim a bytes");
        let claim_b = EntityId::from_bytes(receipt_b.claim_id).expect("claim b bytes");
        let body_a = vault
            .get_claim(&claim_a)
            .expect("claim a read")
            .expect("claim a present");
        let body_b = vault
            .get_claim(&claim_b)
            .expect("claim b read")
            .expect("claim b present");
        let val_a = body_a.value;
        let val_b = body_b.value;
        assert_ne!(val_a, val_b, "claim bodies must carry distinct event_type");
        let map_a = match val_a {
            rmpv::Value::Map(m) => m,
            _ => panic!("expected map"),
        };
        let map_b = match val_b {
            rmpv::Value::Map(m) => m,
            _ => panic!("expected map"),
        };
        let find_event = |map: &Vec<(rmpv::Value, rmpv::Value)>| {
            map.iter()
                .find(|(k, _)| *k == rmpv::Value::from("event_type"))
                .map(|(_, v)| v.clone())
        };
        assert_eq!(find_event(&map_a), Some(rmpv::Value::from("intro-call")));
        assert_eq!(find_event(&map_b), Some(rmpv::Value::from("sales-call")));
    }
    let mut facts_none = facts();
    facts_none.event_type = None;
    facts_none.submitted_at_millis = shared_millis;
    facts_none.email_hash = None;
    vault
        .put_entity(
            &facts_none.page_ref,
            crate::registry::ENTITY_TYPE_EVENT,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"booking page fixture",
        )
        .ok();
    let receipt_none =
        quarantine_borderline_submission(&vault, &facts_none, reason, 1).expect("quarantine none");
    assert_ne!(
        receipt_a.claim_id, receipt_none.claim_id,
        "Some(event) vs None must give distinct claim ids"
    );
    let mut distinct_submission = facts_a.clone();
    distinct_submission.intake_content_hash = digest_with(b"test-intake", b"different same-length");
    let distinct_receipt =
        quarantine_borderline_submission(&vault, &distinct_submission, reason, 2)
            .expect("distinct same-identity submission");
    assert_ne!(
        receipt_a.claim_id, distinct_receipt.claim_id,
        "same identity submissions with distinct fingerprints must not collapse"
    );
    let receipt_a2 =
        quarantine_borderline_submission(&vault, &facts_a, reason, 1).expect("quarantine a retry");
    assert_eq!(
        receipt_a.claim_id, receipt_a2.claim_id,
        "exact-duplicate retry must be idempotent on claim_id"
    );
    assert_eq!(
        receipt_a.claim_ref, receipt_a2.claim_ref,
        "claim_ref must be stable"
    );
    {
        let rtxn = vault.store.env.read_txn().expect("read txn");
        let claim = EntityId::from_bytes(receipt_a.claim_id).expect("claim bytes");
        let pending = vault
            .store
            .pending_gate_consent_in_txn(&rtxn, &claim)
            .expect("pending read")
            .expect("pending present");
        assert_eq!(pending.claim_id, receipt_a.claim_id);
    }
}

#[test]
fn quarantine_retry_after_rejection_replays_without_reappending() {
    let (_dir, vault) = open_vault();
    let facts = facts();
    vault
        .put_entity(
            &facts.page_ref,
            crate::registry::ENTITY_TYPE_EVENT,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"booking page fixture",
        )
        .expect("page entity");

    let receipt = quarantine_borderline_submission(&vault, &facts, "quarantine-test", 1)
        .expect("initial quarantine");
    let claim_ref = EntityId::from_bytes(receipt.claim_id).expect("claim id");
    let initial_claim = vault
        .get_claim(&claim_ref)
        .expect("claim read")
        .expect("claim present");
    assert_eq!(
        initial_claim.valid_from,
        Some(1),
        "first write records trusted chronology"
    );
    let initial_pending = {
        let rtxn = vault.store.env.read_txn().expect("read txn");
        vault
            .store
            .pending_gate_consent_in_txn(&rtxn, &claim_ref)
            .expect("pending read")
            .expect("pending present")
    };
    assert_eq!(initial_pending.created_at, 1);
    let initial_decision = vault
        .gate_decisions(10)
        .expect("decisions")
        .into_iter()
        .find(|decision| decision.decision_id == initial_pending.decision_id)
        .expect("decision present");
    assert_eq!(initial_decision.created_at, 1);
    let initial_metadata = {
        let rtxn = vault.store.env.read_txn().expect("metadata read txn");
        let raw = vault
            .store
            .entities
            .get(&rtxn, claim_ref.as_bytes())
            .expect("claim raw")
            .expect("claim row");
        crate::batch::EntityMetadataHeader::parse(&raw).expect("claim metadata")
    };
    assert_eq!(initial_metadata.occurred_start, 1);
    assert_eq!(initial_metadata.occurred_end, 1);
    assert_eq!(initial_metadata.learned_at, 1);
    // An exact retry while still pending arrives at a later wall-clock
    // value but must preserve the complete first-write chronology.
    let pending_retry = quarantine_borderline_submission(&vault, &facts, "quarantine-test", 99)
        .expect("pending retry replays");
    assert_eq!(pending_retry, receipt);
    assert_eq!(
        vault
            .get_claim(&claim_ref)
            .expect("claim reread")
            .expect("claim present")
            .valid_from,
        Some(1)
    );
    let pending_after_retry = {
        let rtxn = vault.store.env.read_txn().expect("pending retry read txn");
        vault
            .store
            .pending_gate_consent_in_txn(&rtxn, &claim_ref)
            .expect("pending retry read")
            .expect("pending remains")
    };
    assert_eq!(pending_after_retry.created_at, initial_pending.created_at);
    let decision_after_retry = vault
        .gate_decisions(10)
        .expect("decisions")
        .into_iter()
        .find(|decision| decision.decision_id == initial_pending.decision_id)
        .expect("decision remains");
    assert_eq!(decision_after_retry.created_at, initial_decision.created_at);
    let metadata_after_retry = {
        let rtxn = vault.store.env.read_txn().expect("metadata retry read txn");
        let raw = vault
            .store
            .entities
            .get(&rtxn, claim_ref.as_bytes())
            .expect("claim raw")
            .expect("claim row");
        crate::batch::EntityMetadataHeader::parse(&raw).expect("claim metadata")
    };
    assert_eq!(
        metadata_after_retry.occurred_start,
        initial_metadata.occurred_start
    );
    assert_eq!(
        metadata_after_retry.occurred_end,
        initial_metadata.occurred_end
    );
    assert_eq!(metadata_after_retry.learned_at, initial_metadata.learned_at);
    vault
        .with_write_txn(|wtxn| {
            vault.store.close_pending_gate_consent_in_txn(
                wtxn,
                &claim_ref,
                2,
                "rejected",
                vec!["gate.pending.bundle_rejected".to_owned()],
                None,
            )
        })
        .expect("close pending quarantine")
        .expect("rejection receipt");
    let decisions_before_retry = vault.gate_decisions(10).expect("decisions");

    let replay = quarantine_borderline_submission(&vault, &facts, "quarantine-test", 2)
        .expect("retry after rejection replays");
    assert_eq!(replay, receipt, "the original receipt remains stable");
    assert_eq!(
        vault
            .get_claim(&claim_ref)
            .expect("claim reread")
            .expect("claim present")
            .valid_from,
        Some(1),
        "retry with a different supplied now never restamps the claim chronology"
    );
    let replay_metadata = {
        let rtxn = vault.store.env.read_txn().expect("metadata reread txn");
        let raw = vault
            .store
            .entities
            .get(&rtxn, claim_ref.as_bytes())
            .expect("claim raw")
            .expect("claim row");
        crate::batch::EntityMetadataHeader::parse(&raw).expect("claim metadata")
    };
    assert_eq!(
        replay_metadata.occurred_start,
        initial_metadata.occurred_start
    );
    assert_eq!(replay_metadata.occurred_end, initial_metadata.occurred_end);
    assert_eq!(replay_metadata.learned_at, initial_metadata.learned_at);
    assert_eq!(
        vault.gate_decisions(10).expect("decisions"),
        decisions_before_retry,
        "retry must not append a colliding pending decision"
    );
    let rtxn = vault.store.env.read_txn().expect("read txn");
    assert!(
        vault
            .store
            .pending_gate_consent_in_txn(&rtxn, &claim_ref)
            .expect("pending read")
            .is_none(),
        "retry must not resurrect the rejected pending row"
    );
}

#[test]
fn booking_rule_storage_is_disjoint_from_campaign_compliance() {
    assert_eq!(BOOKING_ANTI_ABUSE_META_PREFIX, b"booking:anti_abuse:v1:");

    // Behavioural arm: everything this module stores — rules plus the
    // per-activation notices — sits under the booking-only prefix, and
    // the rule rows round-trip through the public reader.
    let (_dir, vault) = open_vault();
    install_rows(&vault, &seed_rows());
    let rows = booking_anti_abuse_rules(&vault, &scope()).expect("read rows");
    assert_eq!(rows.len(), 10);
    let notices = booking_anti_abuse_notices(&vault).expect("notices");
    assert_eq!(notices.len(), 10);

    let rtxn = vault.store.env.read_txn().expect("read txn");
    let mut ours = 0;
    let iter = vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, BOOKING_ANTI_ABUSE_META_PREFIX)
        .expect("prefix scan");
    for entry in iter {
        let (key, _) = entry.expect("meta row");
        assert!(key.starts_with(BOOKING_ANTI_ABUSE_META_PREFIX));
        ours += 1;
    }
    assert_eq!(ours, 20, "ten rule rows plus their ten activation notices");
}

#[test]
fn concurrent_exact_quarantine_retries_share_one_token_and_receipt() {
    use std::sync::Barrier;

    let (_dir, vault) = open_vault();
    let facts = facts();
    vault
        .put_entity(
            &facts.page_ref,
            crate::registry::ENTITY_TYPE_EVENT,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"booking page fixture",
        )
        .expect("page entity");
    let barrier = Barrier::new(2);
    let (first, second) = std::thread::scope(|scope| {
        let one = scope.spawn(|| {
            barrier.wait();
            admit_quarantine_submission(&vault, &facts, "concurrent", nz32(1), 120)
                .expect("first admission")
        });
        let two = scope.spawn(|| {
            barrier.wait();
            admit_quarantine_submission(&vault, &facts, "concurrent", nz32(1), 120)
                .expect("second admission")
        });
        (
            one.join().expect("first thread"),
            two.join().expect("second thread"),
        )
    });
    let BookingQuarantineAdmission::Accepted(first) = first else {
        panic!("first exact retry must be accepted");
    };
    let BookingQuarantineAdmission::Accepted(second) = second else {
        panic!("second exact retry must be accepted");
    };
    assert_eq!(first, second, "concurrent exact retries replay one receipt");
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let counter_key = rate_counter_key(
        b"quarantine",
        &digest_with(QUARANTINE_RATE_DOMAIN, facts.page_ref.as_bytes()),
    );
    let raw = read_meta_bytes(&vault, &rtxn, &counter_key)
        .expect("counter read")
        .expect("counter present");
    assert_eq!(
        u64::from_le_bytes(raw[8..].try_into().expect("count bytes")),
        1
    );
    let claim_ref = EntityId::from_bytes(first.claim_id).expect("claim id");
    assert!(
        vault
            .get_claim_in_txn(&rtxn, &claim_ref)
            .expect("claim read")
            .is_some()
    );
    assert!(
        vault
            .store
            .pending_gate_consent_in_txn(&rtxn, &claim_ref)
            .expect("pending read")
            .is_some()
    );
    drop(rtxn);
    assert_eq!(vault.gate_decisions(10).expect("decisions").len(), 1);
}
