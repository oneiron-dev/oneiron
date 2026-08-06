//! ONE-1761 (ED-05) unit tests: the posterior guard's discrimination, threshold
//! resolution across the three row sources, the offer-answer ladder through
//! snooze to manual-pin and back out through settings, the receipts every
//! transition leaves, and the trust table's agreement with MS-06's own stats.

use super::*;

use crate::identity_topology::ProposalOutcome;
use crate::store::GateDecisionId;

fn open_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config())
}

/// The eligible fixture scope — a propose-lane surface, the same tuple MS-06's
/// tests and the merge/split oracle use.
fn scope() -> RampScope {
    RampScope::new("send_email", "client_followup", "agent-a").expect("scope")
}

fn owner(vault: &Vault) -> AuthenticatedOwner {
    let actor = crate::test_util::entity(0x25);
    vault
        .put_entity(
            &actor,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange {
                start: 100,
                end: 100,
            },
            100,
            b"graduation fixture owner",
        )
        .expect("put owner");
    vault
        .authenticate_owner(actor, "principal:owner", true, GateDecisionId::now())
        .expect("authenticate owner")
}

/// Drives one scope's history through MS-06's real propose-lane door: `wins`
/// clean rulings after `losses` rejections, so the streak is `wins` and the
/// lifetime correction count is `losses`.
fn record_history(vault: &Vault, scope: &RampScope, wins: u32, losses: u32) {
    for _ in 0..losses {
        vault
            .record_proposal_outcome_for_ramp(scope, ProposalOutcome::Rejected)
            .expect("record rejection");
    }
    for _ in 0..wins {
        vault
            .record_proposal_outcome_for_ramp(scope, ProposalOutcome::ApprovedUntouched)
            .expect("record clean approval");
    }
}

fn answer_receipts(vault: &Vault) -> Vec<ReceiptRecord> {
    vault
        .receipts(ReceiptQuery::default().with_kind(ReceiptKind::Gate))
        .expect("gate receipts")
        .into_iter()
        .filter(is_graduation_answer_receipt)
        .collect()
}

const DAY: u64 = 86_400;

// ---------------------------------------------------------------------------
// The posterior guard
// ---------------------------------------------------------------------------

#[test]
fn the_guard_anchors_where_the_pinned_formula_says_they_do() {
    // Two clean approvals are barely evidence; ninety out of a hundred are. The
    // anchors are the ones SK-05's independent implementation of this same
    // formula documents, which is how the two are kept from drifting apart.
    assert!((posterior_lower_bound(2, 0) - 0.431).abs() < 0.005);
    assert!((posterior_lower_bound(90, 10) - 0.842).abs() < 0.005);
    // A spotless twelve — the compiled row — clears the compiled guard, and the
    // same twelve with two corrections behind it does not.
    assert!(posterior_lower_bound(12, 0) >= DEFAULT_POSTERIOR_GUARD);
    assert!(posterior_lower_bound(12, 2) < DEFAULT_POSTERIOR_GUARD);
    // No history at all is not neutral evidence, it is no evidence.
    assert!(posterior_lower_bound(0, 0) < posterior_lower_bound(1, 0));
}

#[test]
fn the_guard_rises_with_clean_rulings_and_falls_with_corrections() {
    for wins in 1..40 {
        assert!(
            posterior_lower_bound(wins, 0) < posterior_lower_bound(wins + 1, 0),
            "another clean ruling must be worth something at {wins}"
        );
        assert!(
            posterior_lower_bound(wins, 1) < posterior_lower_bound(wins, 0),
            "a correction must cost something at {wins}"
        );
    }
    assert!((posterior_lower_bound(u32::MAX, 0) - 1.0).abs() < 0.001);
}

#[test]
fn guard_evidence_reads_the_streak_against_every_correction_ever_drawn() {
    let (_dir, vault) = open_vault();
    let scope = scope();
    record_history(&vault, &scope, 3, 2);
    vault
        .record_proposal_outcome_for_ramp(&scope, ProposalOutcome::ApprovedAmended)
        .expect("amendment");
    record_history(&vault, &scope, 4, 0);

    let stats = vault.scope_stats(&scope).expect("stats").expect("row");
    assert_eq!(
        guard_evidence(&stats),
        (4, 3),
        "the streak restarted at the amendment; the three corrections did not"
    );
}

// ---------------------------------------------------------------------------
// Threshold rows
// ---------------------------------------------------------------------------

#[test]
fn a_row_must_name_three_axes_a_real_streak_and_a_probability() {
    assert!(ThresholdRow::new(WILDCARD_PATTERN, 5, 0.5).is_ok());
    assert!(ThresholdRow::new("send_email/*/agent-a", 5, 0.0).is_ok());
    assert!(ThresholdRow::new(r"send\/email/\*/agent-a", 5, 0.5).is_ok());
    for illegal in [
        "",
        "*",
        "*/*",
        "*/*/*/*",
        "send_email//agent-a",
        // An escape is only an escape of a RESERVED character; allowing it
        // anywhere would give one axis two spellings and one meaning two keys.
        r"send\_email/*/agent-a",
        // A dangling escape names no character at all.
        r"send_email/*/agent-a\",
        // An escaped separator is not an axis boundary, so this is two axes.
        r"send\/email/agent-a",
    ] {
        assert!(
            ThresholdRow::new(illegal, 5, 0.5).is_err(),
            "{illegal:?} is not a scope pattern"
        );
    }
    assert!(
        ThresholdRow::new(WILDCARD_PATTERN, 0, 0.5).is_err(),
        "a threshold of zero clean rulings is not a threshold"
    );
    for illegal in [-0.1, 1.1, f32::NAN] {
        assert!(ThresholdRow::new(WILDCARD_PATTERN, 5, illegal).is_err());
    }
}

#[test]
fn a_pattern_matches_on_each_axis_independently() {
    let scope = scope();
    for pattern in [
        WILDCARD_PATTERN,
        "send_email/*/*",
        "*/client_followup/*",
        "*/*/agent-a",
        "send_email/client_followup/agent-a",
    ] {
        let row = ThresholdRow::new(pattern, 5, 0.5).expect("row");
        assert!(row.matches(&scope), "{pattern:?} must match");
    }
    for pattern in [
        "draft_email/*/*",
        "*/cold_outreach/*",
        "*/*/agent-b",
        "send_email/client_followup/agent-b",
    ] {
        let row = ThresholdRow::new(pattern, 5, 0.5).expect("row");
        assert!(!row.matches(&scope), "{pattern:?} must not match");
    }
    assert_eq!(exact_pattern(&scope), "send_email/client_followup/agent-a");
}

#[test]
fn a_scope_field_carrying_a_reserved_character_still_names_exactly_itself() {
    let (_dir, vault) = open_vault();
    // A `RampScope` field is arbitrary text — trimmed, non-empty, length-capped
    // and nothing else — so both characters this grammar reserves appear in
    // perfectly valid MS-06 scope tuples.
    let slashed = RampScope::new("send/email", "client_followup", "agent-a").expect("scope");
    let starred = RampScope::new("send_email", "*", "agent-a").expect("scope");
    let plain = scope();

    for scope in [&slashed, &starred] {
        let row = ThresholdRow::new(exact_pattern(scope), 5, 0.5)
            .expect("every scope has an exact pattern, or `exact_pattern` is a lie");
        assert!(row.matches(scope));
        assert!(
            !row.matches(&plain),
            "exact means exactly one scope: {:?} must govern nothing else",
            row.scope_pattern
        );
        assert_eq!(
            row.specificity(),
            3,
            "an escaped literal is a literal, not a wildcard"
        );
    }
    // The wildcard still wildcards, including over a field that IS a star.
    assert!(
        ThresholdRow::new(WILDCARD_PATTERN, 5, 0.5)
            .expect("row")
            .matches(&starred)
    );
    assert!(
        ThresholdRow::new(r"send\/email/*/*", 5, 0.5)
            .expect("row")
            .matches(&slashed),
        "the owner can spell the same literal by hand"
    );
    assert!(
        !ThresholdRow::new("send/email/*", 5, 0.5)
            .expect("row")
            .matches(&slashed),
        "an UNescaped separator is still an axis boundary"
    );

    // And MS-06's per-scope dial keeps working across the whole scope domain,
    // rather than writing a row that no later read can rebuild.
    vault.set_ramp_streak_floor(&slashed, 4).expect("set floor");
    record_history(&vault, &slashed, 4, 0);
    assert_eq!(
        graduation_policy_for(&vault, &slashed)
            .expect("policy")
            .required_streak,
        4
    );
    assert_eq!(
        vault.ramp_scope_state(&slashed).expect("state"),
        RampState::Offered
    );
    assert_eq!(
        graduation_policy_for(&vault, &plain)
            .expect("policy")
            .required_streak,
        DEFAULT_GRADUATION_STREAK_FLOOR,
        "one scope's dial governs one scope"
    );
    assert_eq!(trust_table(&vault).expect("trust table").len(), 1);
}

#[test]
fn the_compiled_catch_all_governs_a_vault_with_no_rows_of_its_own() {
    let (_dir, vault) = open_vault();
    let row = graduation_policy_for(&vault, &scope()).expect("policy");
    assert_eq!(row.scope_pattern, WILDCARD_PATTERN);
    assert_eq!(row.required_streak, DEFAULT_GRADUATION_STREAK_FLOOR);
    assert!((row.posterior_guard - DEFAULT_POSTERIOR_GUARD).abs() < f32::EPSILON);
    assert!(graduation_policy_rows(&vault).expect("rows").is_empty());
}

#[test]
fn the_most_specific_row_wins_and_clearing_it_falls_back() {
    let (_dir, vault) = open_vault();
    let scope = scope();
    for (pattern, streak) in [
        ("send_email/*/*", 9_u32),
        (WILDCARD_PATTERN, 40),
        ("send_email/client_followup/agent-a", 3),
        ("draft_email/*/*", 1),
    ] {
        set_graduation_policy(
            &vault,
            &ThresholdRow::new(pattern, streak, 0.5).expect("row"),
        )
        .expect("set policy");
    }
    assert_eq!(
        graduation_policy_for(&vault, &scope)
            .expect("policy")
            .required_streak,
        3,
        "three literal axes beat one, and a non-matching row is not consulted"
    );

    assert!(clear_graduation_policy(&vault, "send_email/client_followup/agent-a").expect("clear"));
    assert_eq!(
        graduation_policy_for(&vault, &scope)
            .expect("policy")
            .required_streak,
        9
    );
    assert!(clear_graduation_policy(&vault, "send_email/*/*").expect("clear"));
    assert_eq!(
        graduation_policy_for(&vault, &scope)
            .expect("policy")
            .required_streak,
        40,
        "the owner's catch-all beats the compiled one"
    );
    assert!(
        !clear_graduation_policy(&vault, "send_email/*/*").expect("clear"),
        "clearing what is not there is not an error, but it is not a deletion"
    );

    assert!(clear_graduation_policy(&vault, WILDCARD_PATTERN).expect("clear"));
    assert_eq!(
        graduation_policy_for(&vault, &scope)
            .expect("policy")
            .required_streak,
        DEFAULT_GRADUATION_STREAK_FLOOR,
        "the compiled row is the floor nothing can delete"
    );
}

#[test]
fn a_row_written_twice_replaces_itself() {
    let (_dir, vault) = open_vault();
    for streak in [5_u32, 7] {
        set_graduation_policy(
            &vault,
            &ThresholdRow::new(WILDCARD_PATTERN, streak, 0.5).expect("row"),
        )
        .expect("set policy");
    }
    let rows = graduation_policy_rows(&vault).expect("rows");
    assert_eq!(rows.len(), 1, "one pattern is one row");
    assert_eq!(rows[0].required_streak, 7);
}

#[test]
fn the_write_door_re_validates_a_row_the_caller_assembled_by_hand() {
    let (_dir, vault) = open_vault();
    let scope = scope();
    record_history(&vault, &scope, 3, 0);

    // The fields are `pub` (the keystone shape), so a struct literal is a door
    // around `ThresholdRow::new` — and a row that reached storage that way is
    // unreadable on the way back out, which would take every policy read in the
    // vault down rather than failing the one write that was wrong.
    for illegal in [
        ThresholdRow {
            scope_pattern: WILDCARD_PATTERN.to_owned(),
            required_streak: 0,
            posterior_guard: 0.0,
        },
        ThresholdRow {
            scope_pattern: "send_email/client_followup".to_owned(),
            required_streak: 5,
            posterior_guard: 0.5,
        },
        ThresholdRow {
            scope_pattern: WILDCARD_PATTERN.to_owned(),
            required_streak: 5,
            posterior_guard: 1.5,
        },
    ] {
        assert!(
            matches!(
                set_graduation_policy(&vault, &illegal).expect_err("hand-assembled row"),
                Error::InvalidConsentBound(_)
            ),
            "{illegal:?} must be refused at the write door, not on every later read"
        );
    }

    // Nothing landed, so the policy in force is still the one that was in force.
    assert!(graduation_policy_rows(&vault).expect("rows").is_empty());
    assert_eq!(
        graduation_policy_for(&vault, &scope)
            .expect("policy")
            .required_streak,
        DEFAULT_GRADUATION_STREAK_FLOOR
    );
    assert!(vault.ramp_scope_state(&scope).is_ok());
}

#[test]
fn a_malformed_stored_row_is_a_typed_error_never_a_waived_threshold() {
    let (_dir, vault) = open_vault();
    let scope = scope();
    // A history, so the all-scopes reads below have a row whose policy they
    // must resolve before they can answer anything.
    record_history(&vault, &scope, 3, 0);
    let key = pattern_key(WILDCARD_PATTERN);
    vault
        .with_write_txn(|wtxn| {
            vault.store.vault_meta.put(wtxn, &key, b"not a row")?;
            Ok(())
        })
        .expect("plant a corrupt row");

    let error = graduation_policy_for(&vault, &scope).expect_err("corrupt row");
    assert!(matches!(error, Error::CorruptedIndex(_)));
    // Fail-closed all the way up: an unreadable policy holds the offer rather
    // than resolving to a threshold nobody wrote.
    assert!(vault.ramp_scope_state(&scope).is_err());
    assert!(vault.graduation_offers().is_err());

    // A row whose bytes decode but whose VALUES are no longer a legal threshold
    // is the same answer, not a silently repaired one.
    let stored = StoredThresholdRow {
        v: ROW_VERSION,
        scope_pattern: WILDCARD_PATTERN.to_owned(),
        required_streak: 0,
        posterior_guard: 0.5,
    };
    let data = encode_row(&stored, "test row").expect("encode");
    vault
        .with_write_txn(|wtxn| {
            vault.store.vault_meta.put(wtxn, &key, &data)?;
            Ok(())
        })
        .expect("plant a zero-threshold row");
    assert!(matches!(
        graduation_policy_for(&vault, &scope).expect_err("zero threshold"),
        Error::CorruptedIndex(_)
    ));
}

#[test]
fn ms06s_per_scope_dial_becomes_an_exact_row_a_spotless_streak_clears() {
    let (_dir, vault) = open_vault();
    let scope = scope();
    // A guard co-designed with a streak of twelve must not silently outlaw a
    // dialed streak of two — and must still hold a dialed streak that has
    // corrections behind it.
    for dialed in [0_u32, 1, 2, 3, 5, 12, 40] {
        vault
            .set_ramp_streak_floor(&scope, dialed)
            .expect("set floor");
        let row = graduation_policy_for(&vault, &scope).expect("policy");
        assert_eq!(row.scope_pattern, exact_pattern(&scope));
        assert_eq!(row.required_streak, dialed.max(1));
        assert!(
            row.is_cleared_by(dialed.max(1), 0),
            "a spotless streak of {dialed} must clear the dial the owner set to {dialed}"
        );
        assert!(
            !row.is_cleared_by(dialed.max(1), 2),
            "the same length with corrections behind it must not"
        );
        assert_eq!(
            vault.ramp_streak_floor(&scope).expect("floor"),
            row.required_streak
        );
    }
}

#[test]
fn an_exact_row_the_owner_wrote_outranks_the_dial_the_engine_derived() {
    let (_dir, vault) = open_vault();
    let scope = scope();
    vault.set_ramp_streak_floor(&scope, 4).expect("set floor");
    set_graduation_policy(
        &vault,
        &ThresholdRow::new(exact_pattern(&scope), 6, 0.9).expect("row"),
    )
    .expect("set policy");

    let row = graduation_policy_for(&vault, &scope).expect("policy");
    assert_eq!(row.required_streak, 6);
    assert!((row.posterior_guard - 0.9).abs() < f32::EPSILON);
}

// ---------------------------------------------------------------------------
// The offer: streak AND evidence
// ---------------------------------------------------------------------------

#[test]
fn a_streak_that_meets_the_row_but_not_the_guard_surfaces_no_offer() {
    let (_dir, vault) = open_vault();
    let scope = scope();
    // A row whose GUARD is the binding constraint: two clean rulings satisfy
    // its streak, and 0.6 is above what two clean rulings are worth (0.43) and
    // below what nine-out-of-ten are (0.66).
    set_graduation_policy(
        &vault,
        &ThresholdRow::new(exact_pattern(&scope), 2, 0.6).expect("row"),
    )
    .expect("set policy");

    record_history(&vault, &scope, 2, 0);
    assert_eq!(
        vault.ramp_scope_state(&scope).expect("state"),
        RampState::Propose,
        "two clean approvals meet the streak and are not yet evidence"
    );
    assert!(vault.graduation_offers().expect("offers").is_empty());

    // Nine clean rulings against one earlier rejection clear the same guard.
    let earned = scope_with_history(&vault, "agent-b", 9, 1);
    assert_eq!(
        vault.ramp_scope_state(&earned).expect("state"),
        RampState::Offered
    );
    assert_eq!(vault.graduation_offers().expect("offers"), vec![earned]);
}

/// A second scope on the same pattern, driven to `(wins, losses)`.
fn scope_with_history(vault: &Vault, actor: &str, wins: u32, losses: u32) -> RampScope {
    let scope = RampScope::new("send_email", "client_followup", actor).expect("scope");
    set_graduation_policy(
        vault,
        &ThresholdRow::new(exact_pattern(&scope), 2, 0.6).expect("row"),
    )
    .expect("set policy");
    record_history(vault, &scope, wins, losses);
    scope
}

// ---------------------------------------------------------------------------
// The offer-answer ladder
// ---------------------------------------------------------------------------

/// Drives `scope` to a standing offer under the compiled policy.
fn earn_an_offer(vault: &Vault, scope: &RampScope) {
    record_history(vault, scope, DEFAULT_GRADUATION_STREAK_FLOOR, 0);
    assert_eq!(
        vault.ramp_scope_state(scope).expect("state"),
        RampState::Offered
    );
}

#[test]
fn go_auto_mints_the_grant_through_ms06s_own_door() {
    let (_dir, vault) = open_vault();
    let scope = scope();
    let owner = owner(&vault);
    earn_an_offer(&vault, &scope);

    let outcome = answer_graduation_offer(&vault, &scope, OfferAnswer::GoAuto(&owner))
        .expect("the owner accepts");
    assert!(matches!(outcome, OfferAnswerOutcome::Graduated(_)));
    assert_eq!(
        vault
            .active_standing_consent_grants()
            .expect("grants")
            .len(),
        1,
        "the tap creates exactly one grant, through the one door that can"
    );
    assert_eq!(
        vault.ramp_scope_state(&scope).expect("state"),
        RampState::Graduated
    );
    assert!(vault.graduation_offers().expect("offers").is_empty());

    let receipts = answer_receipts(&vault);
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].outcome, "go_auto");
    assert_eq!(
        receipts[0].fields.get(crate::receipt::FIELD_OP_KIND),
        Some(&scope.op_kind)
    );
}

#[test]
fn an_offer_no_evidence_supports_cannot_be_answered_at_all() {
    let (_dir, vault) = open_vault();
    let scope = scope();
    let owner = owner(&vault);
    record_history(&vault, &scope, 3, 0);

    for answer in [OfferAnswer::GoAuto(&owner), OfferAnswer::NotNow] {
        assert!(
            answer_graduation_offer(&vault, &scope, answer).is_err(),
            "there is no offer standing to answer"
        );
    }
    assert!(answer_receipts(&vault).is_empty());
    assert!(
        vault
            .active_standing_consent_grants()
            .expect("grants")
            .is_empty()
    );
}

#[test]
fn a_ruling_that_retracts_the_offer_beats_a_tap_already_in_flight() {
    let (_dir, vault) = open_vault();
    let scope = scope();
    let owner = owner(&vault);
    earn_an_offer(&vault, &scope);
    vault
        .record_proposal_outcome_for_ramp(&scope, ProposalOutcome::Rejected)
        .expect("the rejection lands first");

    assert!(answer_graduation_offer(&vault, &scope, OfferAnswer::GoAuto(&owner)).is_err());
    assert!(
        vault
            .active_standing_consent_grants()
            .expect("grants")
            .is_empty()
    );
    assert!(
        answer_receipts(&vault).is_empty(),
        "a refused answer records nothing"
    );
}

#[test]
fn not_now_holds_the_offer_for_the_backoff_and_the_third_one_pins_the_scope() {
    let (_dir, vault) = open_vault();
    let scope = scope();
    earn_an_offer(&vault, &scope);
    // Anchored on the real clock, because the suppression the surfacing query
    // applies is against the real clock: a backoff window in the past would
    // assert nothing.
    let start = crate::unix_seconds_now();

    // First decline: held for a week. The offer is still STANDING — only the
    // asking stopped.
    let outcome = answer_graduation_offer_at(&vault, &scope, OfferAnswer::NotNow, start)
        .expect("first decline");
    assert!(matches!(
        outcome,
        OfferAnswerOutcome::Snoozed(SnoozeState::Snoozed { count: 1, .. })
    ));
    assert_eq!(
        vault.ramp_scope_state(&scope).expect("state"),
        RampState::Offered
    );
    assert!(vault.graduation_offers().expect("offers").is_empty());

    let SnoozeState::Snoozed {
        next_eligible_at, ..
    } = snooze_state(&vault, &scope).expect("snooze")
    else {
        panic!("a declined offer is snoozed");
    };
    assert_eq!(next_eligible_at, start + 7 * DAY);

    // Declining an offer that is not being made is not a second decline: the
    // ladder counts three separate askings, not three taps.
    assert!(
        answer_graduation_offer_at(&vault, &scope, OfferAnswer::NotNow, start + DAY).is_err(),
        "the offer is held; there is nothing to decline"
    );
    assert!(
        answer_graduation_offer_at(&vault, &scope, OfferAnswer::NotNow, next_eligible_at - 1)
            .is_err()
    );

    // Second decline, once the week is up: held a month.
    let outcome = answer_graduation_offer_at(&vault, &scope, OfferAnswer::NotNow, next_eligible_at)
        .expect("second decline");
    assert!(matches!(
        outcome,
        OfferAnswerOutcome::Snoozed(SnoozeState::Snoozed { count: 2, .. })
    ));
    let SnoozeState::Snoozed {
        next_eligible_at, ..
    } = snooze_state(&vault, &scope).expect("snooze")
    else {
        panic!("still snoozed");
    };
    assert_eq!(next_eligible_at, start + 7 * DAY + 30 * DAY);

    // Third decline: past the end of the ladder, which is the owner saying stop.
    let outcome = answer_graduation_offer_at(&vault, &scope, OfferAnswer::NotNow, next_eligible_at)
        .expect("third decline");
    assert!(matches!(
        outcome,
        OfferAnswerOutcome::Snoozed(SnoozeState::ManualPinned)
    ));
    assert_eq!(
        snooze_state(&vault, &scope).expect("snooze"),
        SnoozeState::ManualPinned
    );
    assert_eq!(
        answer_receipts(&vault).len(),
        3,
        "every decline is receipted"
    );
}

#[test]
fn a_pin_never_expires_and_never_lets_the_engine_ask_again() {
    let (_dir, vault) = open_vault();
    let scope = scope();
    earn_an_offer(&vault, &scope);
    pin_the_scope(&vault, &scope);

    // No passage of time, and no further clean rulings, reopen the question.
    record_history(&vault, &scope, DEFAULT_GRADUATION_STREAK_FLOOR * 4, 0);
    assert!(vault.graduation_offers().expect("offers").is_empty());
    assert!(
        SnoozeState::ManualPinned.suppresses_asks_at(u64::MAX),
        "a pin is not a very long snooze"
    );
    // And the offer it suppresses is still an offer: the ramp posture is
    // untouched, and the propose lane keeps running exactly as before.
    assert_eq!(
        vault.ramp_scope_state(&scope).expect("state"),
        RampState::Offered
    );
}

/// Declines three times across the backoff, leaving the scope pinned.
fn pin_the_scope(vault: &Vault, scope: &RampScope) {
    let mut at = crate::unix_seconds_now();
    for _ in 0..3 {
        answer_graduation_offer_at(vault, scope, OfferAnswer::NotNow, at).expect("decline");
        at += 31 * DAY;
    }
    assert_eq!(
        snooze_state(vault, scope).expect("snooze"),
        SnoozeState::ManualPinned
    );
}

#[test]
fn unpinning_from_settings_restores_eligibility_and_resets_the_ladder() {
    let (_dir, vault) = open_vault();
    let scope = scope();
    earn_an_offer(&vault, &scope);
    pin_the_scope(&vault, &scope);
    assert!(vault.graduation_offers().expect("offers").is_empty());

    // The unpin's `at` is EARLIER than two of the declines it undoes (the
    // fixture declined across a synthetic future). It still wins, because the
    // log replays in write order, never in caller-clock order.
    unpin_scope(&vault, &scope).expect("unpin");
    assert_eq!(
        snooze_state(&vault, &scope).expect("snooze"),
        SnoozeState::None
    );
    assert_eq!(
        vault.graduation_offers().expect("offers"),
        vec![scope.clone()],
        "the offer surfaces again the moment the owner reopens the question"
    );
    assert_eq!(
        answer_receipts(&vault).len(),
        4,
        "three declines and the unpin that undid them"
    );

    // The ladder restarts: the next decline is the FIRST one again.
    let outcome = answer_graduation_offer(&vault, &scope, OfferAnswer::NotNow).expect("decline");
    assert!(matches!(
        outcome,
        OfferAnswerOutcome::Snoozed(SnoozeState::Snoozed { count: 1, .. })
    ));
}

#[test]
fn the_owner_may_accept_a_snoozed_offer_because_suppression_binds_the_engine() {
    let (_dir, vault) = open_vault();
    let scope = scope();
    let owner = owner(&vault);
    earn_an_offer(&vault, &scope);
    pin_the_scope(&vault, &scope);

    answer_graduation_offer(&vault, &scope, OfferAnswer::GoAuto(&owner))
        .expect("a pin suppresses asks, not answers");
    assert_eq!(
        vault
            .active_standing_consent_grants()
            .expect("grants")
            .len(),
        1
    );
    assert_eq!(
        snooze_state(&vault, &scope).expect("snooze"),
        SnoozeState::None,
        "saying yes supersedes every earlier not-now"
    );
}

#[test]
fn ms06s_own_acceptance_door_answers_the_offer_exactly_as_this_ones_does() {
    let (_dir, vault) = open_vault();
    let scope = scope();
    let owner = owner(&vault);
    earn_an_offer(&vault, &scope);
    pin_the_scope(&vault, &scope);

    // The same owner act through MS-06's method — the door its own tests and
    // the merge/split oracle call — must leave the same durable state as
    // `answer_graduation_offer(.., GoAuto)`. Two public doors onto one act that
    // disagree about the answer log are two different state machines.
    vault
        .accept_graduation_offer(&owner, &scope)
        .expect("the owner accepts through MS-06's door");

    let receipts = answer_receipts(&vault);
    assert_eq!(
        receipts.len(),
        4,
        "three declines and the acceptance that answered them"
    );
    assert_eq!(
        receipts
            .iter()
            .filter(|receipt| receipt.outcome == "go_auto")
            .count(),
        1
    );
    assert_eq!(
        snooze_state(&vault, &scope).expect("snooze"),
        SnoozeState::None,
        "saying yes supersedes every earlier not-now, whichever door it arrived through"
    );

    // Which is the whole point: a pin that outlived the acceptance would
    // suppress this scope forever the moment a correction took the grant away
    // and the scope re-earned its threshold.
    vault
        .record_proposal_outcome_for_ramp(&scope, ProposalOutcome::Rejected)
        .expect("a correction demotes the graduated scope");
    record_history(&vault, &scope, DEFAULT_GRADUATION_STREAK_FLOOR * 4, 0);
    assert_eq!(
        vault.ramp_scope_state(&scope).expect("state"),
        RampState::Offered
    );
    assert_eq!(
        vault.graduation_offers().expect("offers"),
        vec![scope],
        "the re-earned offer is asked about again"
    );
}

#[test]
fn an_unbuildable_scope_never_leaves_an_answer_behind() {
    let (_dir, vault) = open_vault();
    let unbuildable = RampScope {
        op_kind: " send_email".to_owned(),
        target_class: "client_followup".to_owned(),
        actor: String::new(),
    };
    assert!(answer_graduation_offer(&vault, &unbuildable, OfferAnswer::NotNow).is_err());
    assert!(unpin_scope(&vault, &unbuildable).is_err());
    assert!(answer_receipts(&vault).is_empty());
}

#[test]
fn a_malformed_answer_row_is_a_typed_error_never_a_silently_dropped_decline() {
    let (_dir, vault) = open_vault();
    let scope = scope();
    earn_an_offer(&vault, &scope);
    answer_graduation_offer(&vault, &scope, OfferAnswer::NotNow).expect("decline");

    let key = answer_key(&scope, &EntityId::now());
    vault
        .with_write_txn(|wtxn| {
            vault.store.vault_meta.put(wtxn, &key, b"not a row")?;
            Ok(())
        })
        .expect("plant a corrupt answer");
    assert!(matches!(
        snooze_state(&vault, &scope).expect_err("corrupt answer"),
        Error::CorruptedIndex(_)
    ));
    assert!(vault.graduation_offers().is_err());
}

#[test]
fn a_capped_answer_scan_keeps_the_newest_transitions_not_the_oldest() {
    // The answer log persists for the life of the vault and `unpin_scope`
    // appends unconditionally, so its growth is bounded by nothing. Past the
    // family work cap the walk answers from a PREFIX — and the half worth
    // keeping is the recent one: an oldest-first cap would make the owner's
    // latest decision permanently unprojectable.
    let mut config = crate::test_util::embedding_test_config();
    // A cap-sized log outgrows the default test map.
    config.map_size = 256 * 1024 * 1024;
    let (_dir, vault) = crate::test_util::open_test_vault_with(config);
    let scope = scope();

    let answer_id = |index: u32| {
        let mut bytes = [0_u8; ENTITY_ID_LEN];
        bytes[..4].copy_from_slice(&index.to_be_bytes());
        // The index leads the id, so key order is the write order this fixture
        // is asserting about.
        bytes[4] = 1;
        EntityId::from_bytes(bytes).expect("16 bytes is a well-formed entity id")
    };
    let cap = u32::try_from(crate::receipt::MAX_RECEIPT_QUERY_SCAN).expect("the cap fits in u32");
    let row = StoredAnswer {
        v: ROW_VERSION,
        op_kind: scope.op_kind.clone(),
        target_class: scope.target_class.clone(),
        actor: scope.actor.clone(),
        answer: ANSWER_NOT_NOW.to_owned(),
        at: 0,
    };
    let data = encode_row(&row, ANSWER_ROW_LABEL).expect("encode");
    // Exactly ONE row past the cap: the smallest log that must truncate.
    vault
        .with_write_txn(|wtxn| {
            for index in 0..=cap {
                vault
                    .store
                    .vault_meta
                    .put(wtxn, &answer_key(&scope, &answer_id(index)), &data)?;
            }
            Ok(())
        })
        .expect("plant a cap-sized answer log");

    reset_answer_scan_capped();
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let projected = answer_receipts_in_txn(&vault.store, &rtxn, &ReceiptQuery::default())
        .expect("answer receipts");

    assert_eq!(
        projected.len(),
        crate::receipt::MAX_RECEIPT_QUERY_SCAN,
        "the scan terminates at the family work cap instead of walking the log"
    );
    assert_eq!(
        answer_scan_capped(),
        1,
        "a truncated scan raises the cap signal exactly once"
    );
    let projected_ids = |id: &EntityId| {
        let receipt_id = format!("{ANSWER_RECEIPT_PREFIX}{}", id.to_hex());
        projected
            .iter()
            .any(|receipt| receipt.receipt_id == receipt_id)
    };
    assert!(
        projected_ids(&answer_id(cap)),
        "the cap keeps the newest transition"
    );
    assert!(
        !projected_ids(&answer_id(0)),
        "and drops the oldest one, which is the half nobody is asking about"
    );
}

// ---------------------------------------------------------------------------
// The trust table
// ---------------------------------------------------------------------------

#[test]
fn the_trust_table_agrees_with_ms06_over_a_scripted_outcome_sequence() {
    let (_dir, vault) = open_vault();
    let owner = owner(&vault);
    let script: [(&str, &[ProposalOutcome]); 4] = [
        ("agent-clean", &[ProposalOutcome::ApprovedUntouched; 14]),
        (
            "agent-corrected",
            &[
                ProposalOutcome::ApprovedUntouched,
                ProposalOutcome::ApprovedAmended,
                ProposalOutcome::Rejected,
                ProposalOutcome::ApprovedUntouched,
            ],
        ),
        ("agent-quiet", &[ProposalOutcome::ApprovedUntouched]),
        ("agent-pinned", &[ProposalOutcome::ApprovedUntouched; 13]),
    ];
    let mut scopes = Vec::new();
    for (actor, outcomes) in script {
        let scope = RampScope::new("send_email", "client_followup", actor).expect("scope");
        for outcome in outcomes {
            vault
                .record_proposal_outcome_for_ramp(&scope, *outcome)
                .expect("record");
        }
        scopes.push(scope);
    }
    // One scope graduates, one gets pinned — so the table has to carry every
    // posture at once rather than one interesting row.
    answer_graduation_offer(&vault, &scopes[0], OfferAnswer::GoAuto(&owner)).expect("accept");
    pin_the_scope(&vault, &scopes[3]);

    let table = trust_table(&vault).expect("trust table");
    assert_eq!(
        table.len(),
        scopes.len(),
        "every scope with ramp history is a row"
    );
    let mut sorted = scopes.clone();
    sorted.sort_unstable();
    assert_eq!(
        table
            .iter()
            .map(|row| row.scope.clone())
            .collect::<Vec<_>>(),
        sorted,
        "the table is scope-ordered, so two reads of one vault agree"
    );

    for row in &table {
        // Every column is the one MS-06 and this module would each answer alone.
        let stats = vault
            .scope_stats(&row.scope)
            .expect("stats")
            .expect("a row means a history");
        assert_eq!(row.stats, stats);
        assert_eq!(row.state, stats.state);
        assert_eq!(
            row.state,
            vault.ramp_scope_state(&row.scope).expect("state")
        );
        assert_eq!(
            row.threshold,
            graduation_policy_for(&vault, &row.scope).expect("policy")
        );
        assert_eq!(
            row.snooze,
            snooze_state(&vault, &row.scope).expect("snooze")
        );
        assert_eq!(
            row.grant_ref.is_some(),
            row.state == RampState::Graduated,
            "a grant reference is exactly what makes a scope graduated"
        );
        let (wins, losses) = guard_evidence(&stats);
        assert_eq!(
            row.offer_is_earned,
            row.threshold.is_cleared_by(wins, losses)
        );
        // The surfaced list is the earned rows minus the suppressed ones, and
        // nothing else moves between them.
        assert_eq!(
            vault
                .graduation_offers()
                .expect("offers")
                .contains(&row.scope),
            row.state == RampState::Offered
                && !row.snooze.suppresses_asks_at(crate::unix_seconds_now()),
        );
    }

    let by_actor = |actor: &str| {
        table
            .iter()
            .find(|row| row.scope.actor == actor)
            .expect("row")
    };
    assert_eq!(by_actor("agent-clean").state, RampState::Graduated);
    assert_eq!(by_actor("agent-corrected").stats.untouched_streak, 1);
    assert_eq!(by_actor("agent-corrected").state, RampState::Propose);
    assert_eq!(by_actor("agent-quiet").state, RampState::Propose);
    assert_eq!(by_actor("agent-pinned").snooze, SnoozeState::ManualPinned);
    assert!(by_actor("agent-pinned").offer_is_earned);
}

#[test]
fn an_identity_topology_scope_shows_in_the_table_and_never_earns_an_offer() {
    let (_dir, vault) = open_vault();
    let scope = RampScope::new("merge", "PERSON", "agent-a").expect("scope");
    record_history(&vault, &scope, DEFAULT_GRADUATION_STREAK_FLOOR * 3, 0);

    let table = trust_table(&vault).expect("trust table");
    assert_eq!(table.len(), 1, "measurement is universal");
    assert_eq!(table[0].state, RampState::Propose);
    assert!(
        !table[0].offer_is_earned,
        "merge rides its own consent axis; there is no propose lane to graduate out of"
    );
    assert!(vault.graduation_offers().expect("offers").is_empty());
}

#[test]
fn an_empty_vault_has_an_empty_table() {
    let (_dir, vault) = open_vault();
    assert!(trust_table(&vault).expect("trust table").is_empty());
}
