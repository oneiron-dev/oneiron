//! ONE-1761 (ED-05) unit tests: the posterior guard's discrimination, threshold
//! resolution across the three row sources, the offer-answer ladder through
//! snooze to manual-pin and back out through settings, the receipts every
//! transition leaves, and the trust table's agreement with MS-06's own stats.

use super::*;

use crate::error::GateError;
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
// Threshold rows
// ---------------------------------------------------------------------------

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
                Error::Gate(GateError::InvalidConsentBound(_))
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
    let key = THRESHOLD.key_bytes(&pattern_key(WILDCARD_PATTERN));
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
