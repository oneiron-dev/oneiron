//! ONE-1762 (ED-06) unit tests: the ledger's round trip through the receipt
//! projection, aggregation per `(scope, trigger)` and its rebuild-from-receipts
//! identity, the stable-pattern proposal and the band ceiling that guards it,
//! and the one acceptance door.

use super::*;

use crate::edit_distance::delta::{DeltaSource, OpsSummary};

fn open_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config())
}

const SCOPE: &str = "fan_out/consult";
const OTHER_SCOPE: &str = "send_email/client_followup";

/// A Δ fixture parameterized on ONE measured field, so "the same amendment
/// twice" and "two different amendments" are the same shape at two arguments —
/// which is what makes the ruling-equality tests about the Δ and nothing else.
fn delta(d_norm: f32) -> AmendmentDelta {
    AmendmentDelta {
        proposed_ref: "aa".repeat(16),
        final_ref: "bb".repeat(16),
        source: DeltaSource::FieldDiff,
        d_norm,
        ops_summary: OpsSummary {
            ins: 3,
            del: 1,
            kept: 9,
            moved: 0,
        },
        engine_ver: "test".to_owned(),
    }
}

fn ask(trigger: EscalationTrigger, ruling: EscalationRuling) -> EscalationReceipt {
    EscalationReceipt {
        task_ref: crate::test_util::entity(0x31),
        scope: SCOPE.to_owned(),
        trigger,
        question: "run this fan-out of nine consults?".to_owned(),
        ruling,
        rationale: "the peer list is the one we agreed".to_owned(),
        budget_band: None,
    }
}

/// Records `count` identical rulings on `(SCOPE, trigger)`, one per second so
/// receipt order is stable, returning their row handles in write order.
fn record_run(
    vault: &Vault,
    trigger: EscalationTrigger,
    ruling: &EscalationRuling,
    count: usize,
    first_at: u64,
) -> Vec<EntityId> {
    (0..count)
        .map(|index| {
            record_escalation_at(vault, ask(trigger, ruling.clone()), first_at + index as u64)
                .expect("record escalation")
        })
        .collect()
}

fn gate_receipts(vault: &Vault) -> Vec<ReceiptRecord> {
    vault
        .receipts(ReceiptQuery::new(1_000).with_kind(ReceiptKind::Gate))
        .expect("gate receipts")
}

fn ledger_receipts(vault: &Vault) -> Vec<ReceiptRecord> {
    gate_receipts(vault)
        .into_iter()
        .filter(is_escalation_receipt)
        .collect()
}

fn policy_receipts(vault: &Vault) -> Vec<ReceiptRecord> {
    gate_receipts(vault)
        .into_iter()
        .filter(is_standing_policy_receipt)
        .collect()
}

fn field<'a>(record: &'a ReceiptRecord, key: &str) -> Option<&'a str> {
    record.fields.get(key).map(String::as_str)
}

// ---------------------------------------------------------------------------
// The ledger round trip
// ---------------------------------------------------------------------------

#[test]
fn a_recorded_escalation_reads_back_every_field_it_was_given() {
    let (_dir, vault) = open_vault();
    let task_ref = crate::test_util::entity(0x31);
    let id = record_escalation_at(
        &vault,
        EscalationReceipt {
            task_ref,
            scope: SCOPE.to_owned(),
            trigger: EscalationTrigger::Policy,
            question: "outside standing policy — run it?".to_owned(),
            ruling: EscalationRuling::Deny,
            rationale: "that peer is not on the list".to_owned(),
            budget_band: None,
        },
        1_000,
    )
    .expect("record");

    let records = ledger_receipts(&vault);
    let record = records
        .iter()
        .find(|record| record.receipt_id == escalation_receipt_id(&id))
        .expect("the ruling projects a receipt");

    assert_eq!(record.receipt_kind, ReceiptKind::Gate);
    assert_eq!(record.occurred_at, 1_000);
    assert_eq!(
        field(record, FIELD_TASK_REF),
        Some(task_ref.to_hex()).as_deref()
    );
    assert_eq!(field(record, FIELD_ESCALATION_SCOPE), Some(SCOPE));
    assert_eq!(field(record, FIELD_ESCALATION_TRIGGER), Some("policy"));
    assert_eq!(field(record, FIELD_ESCALATION_RULING), Some("deny"));
    assert_eq!(
        field(record, FIELD_ESCALATION_QUESTION),
        Some("outside standing policy — run it?")
    );
    assert_eq!(
        field(record, FIELD_ESCALATION_RATIONALE),
        Some("that peer is not on the list")
    );
    assert_eq!(record.outcome, "deny");
    // No Δ and no band on a plain denial: an absent field is the absence of the
    // fact, never a default.
    assert!(field(record, FIELD_AMENDMENT_DELTA).is_none());
    assert!(field(record, FIELD_ESCALATION_BUDGET_BAND).is_none());
}

#[test]
fn an_amend_ruling_round_trips_the_ed01_delta_bytes() {
    let (_dir, vault) = open_vault();
    let amendment = delta(0.25);
    record_escalation_at(
        &vault,
        ask(
            EscalationTrigger::Unsure,
            EscalationRuling::Amend(amendment.clone()),
        ),
        1_000,
    )
    .expect("record");

    // Through the stats read: the Δ decodes to the same value it went in as.
    let stats = escalation_stats(&vault, SCOPE, EscalationTrigger::Unsure).expect("stats");
    assert_eq!(
        stats.last_rulings,
        vec![EscalationRuling::Amend(amendment.clone())]
    );

    // And through the receipt: the SAME BYTES ED-01's own attachment writes,
    // in the same reserved slot, in the same hex spelling.
    let records = ledger_receipts(&vault);
    let record = records.first().expect("one receipt");
    assert_eq!(
        field(record, FIELD_AMENDMENT_DELTA),
        Some(bytes_to_hex_lower(&amendment.encode().expect("encode"))).as_deref()
    );
    assert_eq!(record.outcome, "amend");
}

#[test]
fn a_magnitude_band_is_rejected_on_a_trigger_that_has_no_magnitude() {
    let (_dir, vault) = open_vault();
    for trigger in [EscalationTrigger::Unsure, EscalationTrigger::Policy] {
        let mut receipt = ask(trigger, EscalationRuling::Approve);
        receipt.budget_band = Some(5);
        let error = record_escalation_at(&vault, receipt, 1_000).expect_err("banded non-budget");
        assert!(matches!(error, Error::InvalidConsentBound(_)));
    }
    // The budget trigger takes it, and projects it.
    let mut receipt = ask(EscalationTrigger::Budget, EscalationRuling::Approve);
    receipt.budget_band = Some(5);
    record_escalation_at(&vault, receipt, 1_000).expect("banded budget ask");
    let records = ledger_receipts(&vault);
    assert_eq!(
        field(
            records.first().expect("one receipt"),
            FIELD_ESCALATION_BUDGET_BAND
        ),
        Some("5")
    );
}

#[test]
fn an_unusable_scope_never_reaches_storage() {
    let (_dir, vault) = open_vault();
    for scope in ["", "   ", &"x".repeat(MAX_ESCALATION_SCOPE_LEN + 1)] {
        let mut receipt = ask(EscalationTrigger::Unsure, EscalationRuling::Approve);
        receipt.scope = scope.to_owned();
        let error = record_escalation_at(&vault, receipt, 1_000).expect_err("unusable scope");
        assert!(matches!(error, Error::InvalidConsentBound(_)));
    }
    assert!(ledger_receipts(&vault).is_empty());
}

// ---------------------------------------------------------------------------
// Aggregation
// ---------------------------------------------------------------------------

#[test]
fn stats_aggregate_per_scope_and_per_trigger() {
    let (_dir, vault) = open_vault();
    record_run(
        &vault,
        EscalationTrigger::Unsure,
        &EscalationRuling::Approve,
        2,
        1_000,
    );
    record_run(
        &vault,
        EscalationTrigger::Unsure,
        &EscalationRuling::Deny,
        1,
        2_000,
    );
    record_run(
        &vault,
        EscalationTrigger::Policy,
        &EscalationRuling::Approve,
        4,
        3_000,
    );
    // Another scope's history must not leak into this one's.
    let mut elsewhere = ask(EscalationTrigger::Unsure, EscalationRuling::Deny);
    elsewhere.scope = OTHER_SCOPE.to_owned();
    record_escalation_at(&vault, elsewhere, 4_000).expect("record");

    let unsure = escalation_stats(&vault, SCOPE, EscalationTrigger::Unsure).expect("stats");
    assert_eq!((unsure.approve, unsure.deny, unsure.amend), (2, 1, 0));
    let policy = escalation_stats(&vault, SCOPE, EscalationTrigger::Policy).expect("stats");
    assert_eq!((policy.approve, policy.deny, policy.amend), (4, 0, 0));
    let budget = escalation_stats(&vault, SCOPE, EscalationTrigger::Budget).expect("stats");
    assert_eq!((budget.approve, budget.deny, budget.amend), (0, 0, 0));
    let other = escalation_stats(&vault, OTHER_SCOPE, EscalationTrigger::Unsure).expect("stats");
    assert_eq!((other.approve, other.deny, other.amend), (0, 1, 0));
}

#[test]
fn stats_are_rebuildable_from_the_receipts_alone() {
    let (_dir, vault) = open_vault();
    record_run(
        &vault,
        EscalationTrigger::Unsure,
        &EscalationRuling::Approve,
        3,
        1_000,
    );
    record_run(
        &vault,
        EscalationTrigger::Unsure,
        &EscalationRuling::Amend(delta(0.4)),
        2,
        2_000,
    );
    record_run(
        &vault,
        EscalationTrigger::Unsure,
        &EscalationRuling::Deny,
        1,
        3_000,
    );

    // CID-7: the projection carries everything the fold counted, so a reader
    // holding only receipts arrives at the same numbers.
    let mut rebuilt = EscalationStats::default();
    for record in ledger_receipts(&vault) {
        if field(&record, FIELD_ESCALATION_SCOPE) != Some(SCOPE)
            || field(&record, FIELD_ESCALATION_TRIGGER) != Some(EscalationTrigger::Unsure.as_str())
        {
            continue;
        }
        match field(&record, FIELD_ESCALATION_RULING) {
            Some("approve") => rebuilt.approve += 1,
            Some("deny") => rebuilt.deny += 1,
            Some("amend") => rebuilt.amend += 1,
            other => panic!("unexpected ruling token {other:?}"),
        }
    }
    let stats = escalation_stats(&vault, SCOPE, EscalationTrigger::Unsure).expect("stats");
    assert_eq!((rebuilt.approve, rebuilt.deny, rebuilt.amend), (3, 1, 2));
    assert_eq!(
        (stats.approve, stats.deny, stats.amend),
        (rebuilt.approve, rebuilt.deny, rebuilt.amend)
    );
}

#[test]
fn last_rulings_keeps_the_newest_bound_oldest_first() {
    let (_dir, vault) = open_vault();
    // One denial, then a long run of approvals: the denial is the oldest, so it
    // is exactly what the bound must drop.
    record_run(
        &vault,
        EscalationTrigger::Policy,
        &EscalationRuling::Deny,
        1,
        1_000,
    );
    record_run(
        &vault,
        EscalationTrigger::Policy,
        &EscalationRuling::Approve,
        ESCALATION_LAST_RULINGS_BOUND,
        2_000,
    );

    let stats = escalation_stats(&vault, SCOPE, EscalationTrigger::Policy).expect("stats");
    // Counts are over the WHOLE history; only the retained history is bounded.
    assert_eq!((stats.approve, stats.deny), (8, 1));
    assert_eq!(stats.last_rulings.len(), ESCALATION_LAST_RULINGS_BOUND);
    assert!(
        stats
            .last_rulings
            .iter()
            .all(|ruling| *ruling == EscalationRuling::Approve),
        "the dropped ruling is the OLDEST, not the newest"
    );

    // With one fewer than the bound, the order is oldest-to-newest verbatim.
    let (_dir, vault) = open_vault();
    record_run(
        &vault,
        EscalationTrigger::Policy,
        &EscalationRuling::Deny,
        1,
        1_000,
    );
    record_run(
        &vault,
        EscalationTrigger::Policy,
        &EscalationRuling::Approve,
        2,
        2_000,
    );
    let stats = escalation_stats(&vault, SCOPE, EscalationTrigger::Policy).expect("stats");
    assert_eq!(
        stats.last_rulings,
        vec![
            EscalationRuling::Deny,
            EscalationRuling::Approve,
            EscalationRuling::Approve
        ]
    );
}

// ---------------------------------------------------------------------------
// The stable pattern
// ---------------------------------------------------------------------------

#[test]
fn n_agreeing_rulings_propose_exactly_one_row_that_cites_them() {
    let (_dir, vault) = open_vault();
    let n = escalation_standing_n(&vault).expect("dial");
    assert_eq!(n, DEFAULT_ESCALATION_STANDING_N);

    // One short of the threshold proposes nothing.
    let ids = record_run(
        &vault,
        EscalationTrigger::Policy,
        &EscalationRuling::Approve,
        (n - 1) as usize,
        1_000,
    );
    assert!(
        maybe_propose_standing_policy_at(&vault, SCOPE, EscalationTrigger::Policy, 5_000)
            .expect("propose")
            .is_none()
    );

    let mut ids = ids;
    ids.extend(record_run(
        &vault,
        EscalationTrigger::Policy,
        &EscalationRuling::Approve,
        1,
        2_000,
    ));
    let row_ref = maybe_propose_standing_policy_at(&vault, SCOPE, EscalationTrigger::Policy, 5_000)
        .expect("propose")
        .expect("the pattern is stable");

    let policy = standing_policy_for(&vault, SCOPE, EscalationTrigger::Policy)
        .expect("read")
        .expect("row exists");
    assert_eq!(policy.row_ref, row_ref);
    assert_eq!(policy.scope, SCOPE);
    assert_eq!(policy.trigger, EscalationTrigger::Policy);
    assert_eq!(policy.status, StandingPolicyStatus::Proposed);
    assert_eq!(policy.ruling, EscalationRuling::Approve);
    assert_eq!(policy.budget_band_ceiling, None);
    assert_eq!(
        policy.cited_receipts,
        ids.iter().map(escalation_receipt_id).collect::<Vec<_>>(),
        "the row names the rulings that earned it"
    );

    // A second call mints nothing: one row per (scope, trigger), and the
    // keyspace is what enforces it.
    assert!(
        maybe_propose_standing_policy_at(&vault, SCOPE, EscalationTrigger::Policy, 6_000)
            .expect("propose")
            .is_none()
    );
    assert_eq!(policy_receipts(&vault).len(), 1);
}

#[test]
fn mixed_rulings_propose_nothing() {
    let (_dir, vault) = open_vault();
    record_run(
        &vault,
        EscalationTrigger::Unsure,
        &EscalationRuling::Approve,
        4,
        1_000,
    );
    record_run(
        &vault,
        EscalationTrigger::Unsure,
        &EscalationRuling::Deny,
        1,
        2_000,
    );
    assert!(
        maybe_propose_standing_policy_at(&vault, SCOPE, EscalationTrigger::Unsure, 5_000)
            .expect("propose")
            .is_none(),
        "the NEWEST N are what the pattern is read from, and they disagree"
    );
    assert!(
        standing_policy_for(&vault, SCOPE, EscalationTrigger::Unsure)
            .expect("read")
            .is_none()
    );
}

#[test]
fn two_amendments_that_changed_different_things_are_not_one_pattern() {
    let (_dir, vault) = open_vault();
    record_run(
        &vault,
        EscalationTrigger::Unsure,
        &EscalationRuling::Amend(delta(0.2)),
        2,
        1_000,
    );
    record_run(
        &vault,
        EscalationTrigger::Unsure,
        &EscalationRuling::Amend(delta(0.9)),
        1,
        2_000,
    );
    assert!(
        maybe_propose_standing_policy_at(&vault, SCOPE, EscalationTrigger::Unsure, 5_000)
            .expect("propose")
            .is_none()
    );

    // Three of the SAME amendment do form one, Δ and all.
    record_run(
        &vault,
        EscalationTrigger::Unsure,
        &EscalationRuling::Amend(delta(0.9)),
        2,
        3_000,
    );
    maybe_propose_standing_policy_at(&vault, SCOPE, EscalationTrigger::Unsure, 5_000)
        .expect("propose")
        .expect("stable amendment pattern");
    let policy = standing_policy_for(&vault, SCOPE, EscalationTrigger::Unsure)
        .expect("read")
        .expect("row");
    assert_eq!(policy.ruling, EscalationRuling::Amend(delta(0.9)));
}

#[test]
fn the_n_dial_moves_the_threshold_and_refuses_zero() {
    let (_dir, vault) = open_vault();
    assert!(matches!(
        set_escalation_standing_n(&vault, 0).expect_err("zero is not a threshold"),
        Error::InvalidConsentBound(_)
    ));
    set_escalation_standing_n(&vault, 2).expect("dial");
    assert_eq!(escalation_standing_n(&vault).expect("read"), 2);

    record_run(
        &vault,
        EscalationTrigger::Policy,
        &EscalationRuling::Deny,
        2,
        1_000,
    );
    maybe_propose_standing_policy_at(&vault, SCOPE, EscalationTrigger::Policy, 5_000)
        .expect("propose")
        .expect("two agreeing rulings clear the dialed threshold");

    // The dial's key shares this module's `edit_distance/escalation/` namespace
    // with the ledger, so the projector's range walk is where a badly-chosen key
    // would surface — as a decode failure on four bytes of little-endian u32.
    assert_eq!(ledger_receipts(&vault).len(), 2);
    assert_eq!(policy_receipts(&vault).len(), 1);
}

// ---------------------------------------------------------------------------
// The budget band guard
// ---------------------------------------------------------------------------

/// Records `count` budget approvals of `band`.
fn record_budget_run(vault: &Vault, band: Option<u64>, count: usize, first_at: u64) {
    for index in 0..count {
        let mut receipt = ask(EscalationTrigger::Budget, EscalationRuling::Approve);
        receipt.budget_band = band;
        record_escalation_at(vault, receipt, first_at + index as u64).expect("record");
    }
}

#[test]
fn a_budget_policy_covers_only_the_band_every_citing_ruling_covered() {
    let (_dir, vault) = open_vault();
    // Two small approvals and one large one: the large ask is a single data
    // point at its magnitude, so it must not widen what the window is worth.
    record_budget_run(&vault, Some(10), 2, 1_000);
    record_budget_run(&vault, Some(1_000), 1, 2_000);
    let row_ref = maybe_propose_standing_policy_at(&vault, SCOPE, EscalationTrigger::Budget, 5_000)
        .expect("propose")
        .expect("three agreeing approvals");
    accept_standing_policy_at(&vault, &row_ref, 6_000).expect("accept");

    let policy = standing_policy_for(&vault, SCOPE, EscalationTrigger::Budget)
        .expect("read")
        .expect("row");
    assert_eq!(policy.budget_band_ceiling, Some(10));
    assert!(policy.covers_ask(Some(10)));
    assert!(policy.covers_ask(Some(1)));
    assert!(!policy.covers_ask(Some(11)));
    assert!(!policy.covers_ask(Some(1_000)));
    // An unmeasured budget ask clears no ceiling.
    assert!(!policy.covers_ask(None));
}

#[test]
fn a_band_less_budget_policy_covers_nothing() {
    let (_dir, vault) = open_vault();
    record_budget_run(&vault, Some(10), 2, 1_000);
    record_budget_run(&vault, None, 1, 2_000);
    let row_ref = maybe_propose_standing_policy_at(&vault, SCOPE, EscalationTrigger::Budget, 5_000)
        .expect("propose")
        .expect("three agreeing approvals");
    accept_standing_policy_at(&vault, &row_ref, 6_000).expect("accept");

    let policy = standing_policy_for(&vault, SCOPE, EscalationTrigger::Budget)
        .expect("read")
        .expect("row");
    assert_eq!(policy.budget_band_ceiling, None);
    assert!(!policy.covers_ask(Some(1)));
    assert!(!policy.covers_ask(None));
}

#[test]
fn the_band_is_not_consulted_on_the_two_triggers_without_a_magnitude() {
    let (_dir, vault) = open_vault();
    for trigger in [EscalationTrigger::Unsure, EscalationTrigger::Policy] {
        record_run(&vault, trigger, &EscalationRuling::Approve, 3, 1_000);
        let row_ref = maybe_propose_standing_policy_at(&vault, SCOPE, trigger, 5_000)
            .expect("propose")
            .expect("stable pattern");
        accept_standing_policy_at(&vault, &row_ref, 6_000).expect("accept");
        let policy = standing_policy_for(&vault, SCOPE, trigger)
            .expect("read")
            .expect("row");
        assert_eq!(policy.budget_band_ceiling, None);
        assert!(policy.covers_ask(None), "the (scope, trigger) key stands");
        assert!(policy.covers_ask(Some(9_999)));
    }
}

// ---------------------------------------------------------------------------
// The acceptance door
// ---------------------------------------------------------------------------

#[test]
fn acceptance_is_the_only_door_and_it_is_receipted() {
    let (_dir, vault) = open_vault();
    record_run(
        &vault,
        EscalationTrigger::Policy,
        &EscalationRuling::Approve,
        3,
        1_000,
    );
    let row_ref = maybe_propose_standing_policy_at(&vault, SCOPE, EscalationTrigger::Policy, 5_000)
        .expect("propose")
        .expect("stable pattern");

    // Proposed is not in force: the offer suppresses nothing.
    let proposed = standing_policy_for(&vault, SCOPE, EscalationTrigger::Policy)
        .expect("read")
        .expect("row");
    assert_eq!(proposed.status, StandingPolicyStatus::Proposed);
    assert!(!proposed.covers_ask(None));
    let receipts = policy_receipts(&vault);
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].outcome, "proposed");
    assert_eq!(receipts[0].occurred_at, 5_000);
    assert_eq!(
        field(&receipts[0], FIELD_ESCALATION_CITED_RECEIPTS)
            .map(|joined| joined.split(CITED_RECEIPTS_SEPARATOR).count()),
        Some(3)
    );

    accept_standing_policy_at(&vault, &row_ref, 6_000).expect("accept");
    let accepted = standing_policy_for(&vault, SCOPE, EscalationTrigger::Policy)
        .expect("read")
        .expect("row");
    assert_eq!(accepted.status, StandingPolicyStatus::Accepted);
    assert!(accepted.covers_ask(None));

    // The proposal receipt survives the acceptance: two acts, two records.
    let receipts = policy_receipts(&vault);
    assert_eq!(receipts.len(), 2);
    let outcomes: Vec<&str> = receipts
        .iter()
        .map(|record| record.outcome.as_str())
        .collect();
    assert!(outcomes.contains(&"proposed") && outcomes.contains(&"accepted"));

    // Re-accepting keeps the time the act happened.
    accept_standing_policy_at(&vault, &row_ref, 9_999).expect("idempotent accept");
    let accepted_receipt = policy_receipts(&vault)
        .into_iter()
        .find(|record| record.outcome == "accepted")
        .expect("acceptance receipt");
    assert_eq!(accepted_receipt.occurred_at, 6_000);
}

#[test]
fn accepting_an_unknown_row_ref_is_a_typed_refusal() {
    let (_dir, vault) = open_vault();
    let error = accept_standing_policy_at(&vault, &crate::test_util::entity(0x32), 6_000)
        .expect_err("no such row");
    assert!(matches!(error, Error::InvalidConsentBound(_)));
}

// ---------------------------------------------------------------------------
// The ES-07 suppression read
// ---------------------------------------------------------------------------

#[test]
fn the_suppression_read_is_scope_and_trigger_exact() {
    let (_dir, vault) = open_vault();
    record_run(
        &vault,
        EscalationTrigger::Policy,
        &EscalationRuling::Approve,
        3,
        1_000,
    );
    let row_ref = maybe_propose_standing_policy_at(&vault, SCOPE, EscalationTrigger::Policy, 5_000)
        .expect("propose")
        .expect("stable pattern");
    accept_standing_policy_at(&vault, &row_ref, 6_000).expect("accept");

    assert!(
        standing_policy_for(&vault, SCOPE, EscalationTrigger::Policy)
            .expect("read")
            .is_some()
    );
    // A row for one trigger answers for that trigger and no other, and a row
    // for one scope answers for that scope and no other.
    assert!(
        standing_policy_for(&vault, SCOPE, EscalationTrigger::Unsure)
            .expect("read")
            .is_none()
    );
    assert!(
        standing_policy_for(&vault, OTHER_SCOPE, EscalationTrigger::Policy)
            .expect("read")
            .is_none()
    );
    // A scope the engine would refuse to record is refused on the read too,
    // rather than answering "no policy" for a question it cannot key.
    assert!(matches!(
        standing_policy_for(&vault, "  ", EscalationTrigger::Policy).expect_err("unusable scope"),
        Error::InvalidConsentBound(_)
    ));
}

#[test]
fn an_undecodable_policy_row_is_uncertainty_not_absence() {
    let (_dir, vault) = open_vault();
    record_run(
        &vault,
        EscalationTrigger::Policy,
        &EscalationRuling::Approve,
        3,
        1_000,
    );
    maybe_propose_standing_policy_at(&vault, SCOPE, EscalationTrigger::Policy, 5_000)
        .expect("propose")
        .expect("stable pattern");

    // Corrupt the row in place. ES-07 maps the Err arm to "escalate", so the
    // distinction from `Ok(None)` — which means "ask, there is no policy" — is
    // load-bearing rather than cosmetic.
    vault
        .with_write_txn(|wtxn| {
            vault.store.vault_meta.put(
                wtxn,
                &standing_policy_key(SCOPE, EscalationTrigger::Policy),
                b"not a policy row",
            )?;
            Ok(())
        })
        .expect("corrupt the row");

    assert!(matches!(
        standing_policy_for(&vault, SCOPE, EscalationTrigger::Policy).expect_err("undecodable"),
        Error::CorruptedIndex(_)
    ));
}

#[test]
fn the_trigger_token_round_trips_and_rejects_what_the_engine_never_wrote() {
    for trigger in EscalationTrigger::ALL {
        assert_eq!(
            EscalationTrigger::from_token(trigger.as_str()),
            Some(trigger)
        );
    }
    assert_eq!(EscalationTrigger::from_token("other"), None);
    // Key bytes are distinct and never zero, so a zero-filled or truncated key
    // cannot decode as a trigger.
    let bytes: Vec<u8> = EscalationTrigger::ALL
        .into_iter()
        .map(EscalationTrigger::key_byte)
        .collect();
    assert!(bytes.iter().all(|byte| *byte != 0));
    let mut sorted = bytes.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), bytes.len());
}

#[test]
fn the_two_receipt_families_never_answer_for_each_other() {
    let (_dir, vault) = open_vault();
    record_run(
        &vault,
        EscalationTrigger::Policy,
        &EscalationRuling::Approve,
        3,
        1_000,
    );
    maybe_propose_standing_policy_at(&vault, SCOPE, EscalationTrigger::Policy, 5_000)
        .expect("propose")
        .expect("stable pattern");

    let ledger = ledger_receipts(&vault);
    let policies = policy_receipts(&vault);
    assert_eq!(ledger.len(), 3);
    assert_eq!(policies.len(), 1);
    assert!(
        ledger
            .iter()
            .all(|record| !is_standing_policy_receipt(record))
    );
    assert!(policies.iter().all(|record| !is_escalation_receipt(record)));
    // Neither family displaced the Gate projectors already in the kind.
    assert!(
        gate_receipts(&vault).len() >= ledger.len() + policies.len(),
        "escalation receipts join the Gate family rather than replacing it"
    );
}
