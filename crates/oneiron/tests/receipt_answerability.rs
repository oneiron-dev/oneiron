use std::collections::{BTreeMap, BTreeSet};

use oneiron::{
    GrantReceiptProjection, PendingTrayAsk, ReceiptKind, ReceiptRecord, ReceiptView,
    StandingOutboundGrantLensRow, StandingOutboundGrantRevokeAction, StandingOutboundGrantsLens,
    project_receipts_by_brief, project_receipts_by_counterparty, project_receipts_by_grant,
};

const BRIEF_REF: &str = "brief:party";
const PARTY_GRANT_REF: &str = "party-grant";

struct AnswerabilityFixture {
    receipts: Vec<ReceiptRecord>,
    pending_tray: Vec<PendingTrayAsk>,
    grants_lens: StandingOutboundGrantsLens,
}

#[derive(Clone, Copy)]
struct ReceiptFixture<'a> {
    receipt_id: &'a str,
    receipt_kind: ReceiptKind,
    occurred_at: u64,
    outcome: &'a str,
    job_ref: Option<&'a str>,
    trigger_ref: Option<&'a str>,
    policy_trace: &'a [&'a str],
    fields: &'a [(&'a str, &'a str)],
}

fn answerability_fixture() -> AnswerabilityFixture {
    let receipts = vec![
        receipt(ReceiptFixture {
            receipt_id: "scoped_read:party-grant:created",
            receipt_kind: ReceiptKind::ScopedRead,
            occurred_at: 90,
            outcome: "active",
            job_ref: Some(BRIEF_REF),
            trigger_ref: Some("grant:party-bundle"),
            policy_trace: &[],
            fields: &[
                ("grant_ref", PARTY_GRANT_REF),
                ("origin_receipt_ref", "gate:bundle-party"),
                ("scope_dial", "always_this_brief_invites"),
                ("status", "active"),
                ("brief_ref", BRIEF_REF),
            ],
        }),
        receipt(ReceiptFixture {
            receipt_id: "gate:bundle-party",
            receipt_kind: ReceiptKind::Gate,
            occurred_at: 95,
            outcome: "approved",
            job_ref: Some(BRIEF_REF),
            trigger_ref: Some("bundle:party-invites"),
            policy_trace: &["gate.allow.owner_bundle_approval"],
            fields: &[
                ("run_ref", "run:planning-session"),
                ("bundle_ref", "bundle:party-invites"),
                ("event", "bundle"),
                ("grant_ref", PARTY_GRANT_REF),
            ],
        }),
        receipt(ReceiptFixture {
            receipt_id: "outbound:intent:invite-yuki",
            receipt_kind: ReceiptKind::Outbound,
            occurred_at: 100,
            outcome: "delivered_to_channel",
            job_ref: Some(BRIEF_REF),
            trigger_ref: Some("intent:invite-yuki"),
            policy_trace: &["delivery_window.no_restriction"],
            fields: &[
                ("run_ref", "run:planning-session"),
                ("intent_ref", "intent:invite-yuki"),
                ("counterparty_ref", "person:yuki"),
                ("first_touch", "user_introduction"),
                ("opt_out", "false"),
                ("promo_consent", "true"),
                ("intent_source", "agent_immediate"),
                ("verb", "send"),
                ("channel", "line"),
                ("grant_ref", PARTY_GRANT_REF),
                ("budget_debit", "3"),
            ],
        }),
        receipt(ReceiptFixture {
            receipt_id: "outbound:intent:invite-kenji",
            receipt_kind: ReceiptKind::Outbound,
            occurred_at: 101,
            outcome: "held",
            job_ref: Some(BRIEF_REF),
            trigger_ref: Some("intent:invite-kenji"),
            policy_trace: &[
                "delivery_window.quiet_hours",
                "delivery_window.retry_at_morning",
            ],
            fields: &[
                ("run_ref", "run:planning-session"),
                ("intent_ref", "intent:invite-kenji"),
                ("counterparty_ref", "person:kenji"),
                ("first_touch", "user_introduction"),
                ("opt_out", "false"),
                ("promo_consent", "true"),
                ("intent_source", "commitment"),
                ("hold_reason", "quiet_hours"),
                ("retry_at", "2026-07-07T09:00:00+09:00"),
                ("verb", "send"),
                ("channel", "line"),
                ("grant_ref", PARTY_GRANT_REF),
                ("budget_debit", "0"),
            ],
        }),
        receipt(ReceiptFixture {
            receipt_id: "outbound:intent:invite-yuki-dedupe",
            receipt_kind: ReceiptKind::Outbound,
            occurred_at: 102,
            outcome: "suppressed",
            job_ref: Some(BRIEF_REF),
            trigger_ref: Some("intent:invite-yuki-dedupe"),
            policy_trace: &["dedupe.cooldown"],
            fields: &[
                ("run_ref", "run:planning-session"),
                ("intent_ref", "intent:invite-yuki-dedupe"),
                ("counterparty_ref", "person:yuki"),
                ("suppression", "dedupe"),
                ("dedupe_key", "party-invite:yuki"),
                ("intent_source", "gap_queue"),
                ("grant_ref", PARTY_GRANT_REF),
                ("budget_debit", "0"),
            ],
        }),
        receipt(ReceiptFixture {
            receipt_id: "outbound:intent:party-photo-push",
            receipt_kind: ReceiptKind::Outbound,
            occurred_at: 103,
            outcome: "degraded",
            job_ref: Some(BRIEF_REF),
            trigger_ref: Some("intent:party-photo-push"),
            policy_trace: &[
                "delivery_window.quiet_hours",
                "delivery_window.degrade_interrupt",
            ],
            fields: &[
                ("run_ref", "run:planning-session"),
                ("intent_ref", "intent:party-photo-push"),
                ("counterparty_ref", "person:yuki"),
                ("degraded_from", "push:time_sensitive"),
                ("degraded_to", "chat:passive"),
                ("intent_source", "agent_immediate"),
                ("grant_ref", PARTY_GRANT_REF),
                ("budget_debit", "1"),
            ],
        }),
        receipt(ReceiptFixture {
            receipt_id: "outbound:intent:invite-mika",
            receipt_kind: ReceiptKind::Outbound,
            occurred_at: 104,
            outcome: "declined",
            job_ref: Some(BRIEF_REF),
            trigger_ref: Some("intent:invite-mika"),
            policy_trace: &["counterparty.opt_out"],
            fields: &[
                ("run_ref", "run:followup-session"),
                ("intent_ref", "intent:invite-mika"),
                ("counterparty_ref", "person:mika"),
                ("first_touch", "user_introduction"),
                ("opt_out", "true"),
                ("promo_consent", "false"),
                ("intent_source", "agent_immediate"),
                ("decline_reason", "counterparty_opt_out"),
                ("budget_debit", "0"),
            ],
        }),
        receipt(ReceiptFixture {
            receipt_id: "outbound:intent:venue-email",
            receipt_kind: ReceiptKind::Outbound,
            occurred_at: 105,
            outcome: "delivered_to_channel",
            job_ref: Some(BRIEF_REF),
            trigger_ref: Some("intent:venue-email"),
            policy_trace: &["delivery_window.no_restriction"],
            fields: &[
                ("run_ref", "run:venue-logistics"),
                ("intent_ref", "intent:venue-email"),
                ("counterparty_ref", "venue:sakura-hall"),
                ("first_touch", "public"),
                ("opt_out", "false"),
                ("promo_consent", "false"),
                ("intent_source", "agent_immediate"),
                ("verb", "send"),
                ("channel", "email"),
                ("grant_ref", PARTY_GRANT_REF),
                ("budget_debit", "8"),
            ],
        }),
        receipt(ReceiptFixture {
            receipt_id: "outbound:intent:venue-email-retry",
            receipt_kind: ReceiptKind::Outbound,
            occurred_at: 106,
            outcome: "failed",
            job_ref: Some(BRIEF_REF),
            trigger_ref: Some("intent:venue-email-retry"),
            policy_trace: &["connector.email.transient_failure"],
            fields: &[
                ("run_ref", "run:venue-logistics"),
                ("intent_ref", "intent:venue-email-retry"),
                ("counterparty_ref", "venue:sakura-hall"),
                ("channel_error", "smtp_tempfail"),
                ("retry_state", "retry_after:300"),
                ("intent_source", "agent_immediate"),
                ("grant_ref", PARTY_GRANT_REF),
                ("budget_debit", "0"),
            ],
        }),
        receipt(ReceiptFixture {
            receipt_id: "outbound:intent:late-reminder",
            receipt_kind: ReceiptKind::Outbound,
            occurred_at: 107,
            outcome: "delivered_to_channel",
            job_ref: Some(BRIEF_REF),
            trigger_ref: Some("commitment:party-reminder"),
            policy_trace: &[
                "delivery_window.async_surface_allowed",
                "delivery_window.no_interrupt",
            ],
            fields: &[
                ("run_ref", "run:commitment-wake"),
                ("intent_ref", "intent:late-reminder"),
                ("counterparty_ref", "owner"),
                ("intent_source", "commitment"),
                ("local_time", "02:00"),
                ("verb", "send"),
                ("channel", "chat"),
                ("budget_debit", "1"),
            ],
        }),
        receipt(ReceiptFixture {
            receipt_id: "gate:pending:guest-count",
            receipt_kind: ReceiptKind::Gate,
            occurred_at: 108,
            outcome: "pending",
            job_ref: Some(BRIEF_REF),
            trigger_ref: Some("claim:guest-count"),
            policy_trace: &["gate.pending.source_trust"],
            fields: &[
                ("run_ref", "run:planning-session"),
                ("content_kind", "external_effect"),
                ("receipt_reason", "gate.pending.source_trust"),
                ("dreamer_run_id", "dreamer:party-planning"),
            ],
        }),
        receipt(ReceiptFixture {
            receipt_id: "outbound:intent:venue-call-let-go",
            receipt_kind: ReceiptKind::Outbound,
            occurred_at: 109,
            outcome: "let_go",
            job_ref: Some(BRIEF_REF),
            trigger_ref: Some("intent:venue-call"),
            policy_trace: &["gate.pending.gap_decayed"],
            fields: &[
                ("run_ref", "run:venue-logistics"),
                ("intent_ref", "intent:venue-call"),
                ("counterparty_ref", "venue:sakura-hall"),
                ("intent_source", "gap_queue"),
                ("let_go_reason", "gap_decayed"),
                ("budget_debit", "0"),
            ],
        }),
    ];

    let pending_receipt = receipts
        .iter()
        .find(|receipt| receipt.receipt_id == "gate:pending:guest-count")
        .expect("pending receipt fixture")
        .clone();
    let pending_tray = vec![PendingTrayAsk {
        claim_id: "claim:guest-count".to_owned(),
        created_at: pending_receipt.occurred_at,
        age_secs: 60 * 60,
        hold_reason: "gate.pending.source_trust".to_owned(),
        hold_reasons: pending_receipt.policy_trace.clone(),
        dreamer_run_id: Some("dreamer:party-planning".to_owned()),
        receipt_view: ReceiptView::new(pending_receipt),
    }];

    let receipt_join = project_receipts_by_grant(PARTY_GRANT_REF, receipts.clone());
    let grants_lens = StandingOutboundGrantsLens {
        grants: vec![StandingOutboundGrantLensRow {
            grant_ref: PARTY_GRANT_REF.to_owned(),
            origin_component_id: "bundle-approve-party".to_owned(),
            origin_action_id: "approve_bundle_brief_verb_class".to_owned(),
            origin_receipt_ref: Some("gate:bundle-party".to_owned()),
            scope_dial: "always_this_brief_invites".to_owned(),
            status: "active".to_owned(),
            stale: false,
            created_at: 90,
            last_used_at: Some(105),
            revoked_at: None,
            receipt_join,
            revoke_action: StandingOutboundGrantRevokeAction {
                command: "revoke_standing_outbound_grant".to_owned(),
                grant_ref: PARTY_GRANT_REF.to_owned(),
            },
        }],
    };

    AnswerabilityFixture {
        receipts,
        pending_tray,
        grants_lens,
    }
}

fn receipt(fixture: ReceiptFixture<'_>) -> ReceiptRecord {
    ReceiptRecord {
        receipt_id: fixture.receipt_id.to_owned(),
        receipt_kind: fixture.receipt_kind,
        occurred_at: fixture.occurred_at,
        actor: Some("eiri".to_owned()),
        on_behalf_of: Some("owner".to_owned()),
        outcome: fixture.outcome.to_owned(),
        job_ref: fixture.job_ref.map(str::to_owned),
        trigger_ref: fixture.trigger_ref.map(str::to_owned),
        policy_trace: fixture
            .policy_trace
            .iter()
            .map(|entry| (*entry).to_owned())
            .collect(),
        fields: field_map(fixture.fields),
    }
}

fn field_map(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
    entries
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
}

fn receipt_by_id<'a>(receipts: &'a [ReceiptRecord], receipt_id: &str) -> &'a ReceiptRecord {
    receipts
        .iter()
        .find(|receipt| receipt.receipt_id == receipt_id)
        .unwrap_or_else(|| panic!("fixture missing receipt {receipt_id}"))
}

fn field<'a>(receipt: &'a ReceiptRecord, key: &str, question: &str) -> &'a str {
    receipt
        .fields
        .get(key)
        .map(String::as_str)
        .unwrap_or_else(|| panic!("{question}: missing receipt field {key}"))
}

fn receipt_ids(projection: &GrantReceiptProjection) -> BTreeSet<&str> {
    projection
        .receipts
        .iter()
        .map(|receipt| receipt.receipt_id.as_str())
        .collect()
}

#[test]
fn answerability_test_pack_why_didnt_you_send_it_from_receipts_alone() {
    let question = "Why didn't you send it?";
    let fixture = answerability_fixture();
    let negative_space = fixture
        .receipts
        .iter()
        .filter(|receipt| {
            matches!(
                receipt.outcome.as_str(),
                "held" | "degraded" | "suppressed" | "let_go" | "failed"
            )
        })
        .collect::<Vec<_>>();

    assert!(
        negative_space
            .iter()
            .any(|receipt| receipt.outcome == "held"
                && receipt
                    .policy_trace
                    .iter()
                    .any(|trace| trace == "delivery_window.quiet_hours")
                && field(receipt, "retry_at", question) == "2026-07-07T09:00:00+09:00"),
        "{question}: held quiet-hours receipt lacks retry_at and policy_trace"
    );
    assert!(
        negative_space
            .iter()
            .any(|receipt| receipt.outcome == "suppressed"
                && field(receipt, "suppression", question) == "dedupe"
                && field(receipt, "dedupe_key", question) == "party-invite:yuki"),
        "{question}: suppressed(dedupe) receipt is not answerable"
    );
    assert!(
        negative_space
            .iter()
            .any(|receipt| receipt.outcome == "let_go"
                && receipt
                    .policy_trace
                    .iter()
                    .any(|trace| trace == "gate.pending.gap_decayed")),
        "{question}: let_go receipt lacks gap-decay policy_trace"
    );
    assert!(
        negative_space
            .iter()
            .any(|receipt| receipt.outcome == "failed"
                && field(receipt, "retry_state", question) == "retry_after:300"),
        "{question}: failed receipt lacks retry_state"
    );
}

#[test]
fn answerability_test_pack_why_message_at_2am_from_receipts_alone() {
    let question = "Why did you message at 2am?";
    let fixture = answerability_fixture();
    let receipt = receipt_by_id(&fixture.receipts, "outbound:intent:late-reminder");

    assert_eq!(
        field(receipt, "local_time", question),
        "02:00",
        "{question}: fixture receipt is not the 2am send"
    );
    assert_eq!(
        field(receipt, "intent_source", question),
        "commitment",
        "{question}: receipt does not expose intent_source"
    );
    assert!(
        receipt
            .policy_trace
            .iter()
            .any(|trace| trace == "delivery_window.async_surface_allowed"),
        "{question}: receipt does not expose the delivery-window policy_trace"
    );
    assert_eq!(
        receipt.trigger_ref.as_deref(),
        Some("commitment:party-reminder"),
        "{question}: receipt does not link back to the triggering commitment"
    );
}

#[test]
fn answerability_test_pack_what_happened_with_the_party_from_brief_projection() {
    let question = "What happened with the party?";
    let fixture = answerability_fixture();
    let projection = project_receipts_by_brief(BRIEF_REF, fixture.receipts);

    assert_eq!(projection.brief_ref, BRIEF_REF, "{question}: wrong brief");
    assert_eq!(
        projection.runs.len(),
        4,
        "{question}: multi-session party fixture is incomplete"
    );
    assert_eq!(
        projection.consent_grants.len(),
        1,
        "{question}: bundle grant is absent from the brief projection"
    );
    assert_eq!(
        projection.bundles.len(),
        1,
        "{question}: bundle event is absent from the brief projection"
    );

    let outcomes = projection
        .runs
        .iter()
        .flat_map(|run| run.intents.iter())
        .flat_map(|intent| intent.receipts.iter())
        .map(|receipt| receipt.outcome.as_str())
        .collect::<BTreeSet<_>>();
    for expected in [
        "delivered_to_channel",
        "held",
        "degraded",
        "suppressed",
        "declined",
        "failed",
        "let_go",
    ] {
        assert!(
            outcomes.contains(expected),
            "{question}: brief projection is missing outcome {expected}"
        );
    }
}

#[test]
fn answerability_test_pack_who_contacted_on_my_behalf_from_counterparty_projection() {
    let question = "Who have you contacted on my behalf?";
    let fixture = answerability_fixture();
    let projections = project_receipts_by_counterparty(fixture.receipts);
    let counterparties = projections
        .iter()
        .map(|projection| projection.counterparty_ref.as_str())
        .collect::<BTreeSet<_>>();

    for expected in [
        "person:yuki",
        "person:kenji",
        "person:mika",
        "venue:sakura-hall",
    ] {
        assert!(
            counterparties.contains(expected),
            "{question}: counterparty projection is missing {expected}"
        );
    }

    let mika = projections
        .iter()
        .find(|projection| projection.counterparty_ref == "person:mika")
        .unwrap_or_else(|| panic!("{question}: missing declined counterparty"));
    assert_eq!(mika.first_touch.as_deref(), Some("user_introduction"));
    assert_eq!(mika.opt_out, Some(true));
    assert_eq!(mika.promo_consent, Some(false));
    assert_eq!(mika.budget_debit_total, 0);
}

#[test]
fn answerability_test_pack_what_did_that_cost_from_budget_debits() {
    let question = "What did that cost?";
    let fixture = answerability_fixture();
    let brief = project_receipts_by_brief(BRIEF_REF, fixture.receipts.clone());
    let grant = project_receipts_by_grant(PARTY_GRANT_REF, fixture.receipts);

    assert_eq!(
        brief.budget_debit_total, 13,
        "{question}: brief projection did not sum every receipt budget_debit"
    );
    assert_eq!(
        grant.budget_debit_total, 12,
        "{question}: grant projection did not sum grant-scoped receipt debits"
    );
}

#[test]
fn answerability_test_pack_whats_waiting_on_me_from_pending_tray_surface() {
    let question = "What's waiting on me?";
    let fixture = answerability_fixture();
    let ask = fixture
        .pending_tray
        .iter()
        .find(|ask| ask.claim_id == "claim:guest-count")
        .unwrap_or_else(|| panic!("{question}: pending tray did not expose guest-count ask"));

    assert_eq!(ask.hold_reason, "gate.pending.source_trust");
    assert_eq!(
        ask.dreamer_run_id.as_deref(),
        Some("dreamer:party-planning")
    );
    assert_eq!(ask.receipt_view.receipt.receipt_kind, ReceiptKind::Gate);
    assert_eq!(ask.receipt_view.receipt.outcome, "pending");
    assert_eq!(
        ask.receipt_view.receipt.trigger_ref.as_deref(),
        Some("claim:guest-count"),
        "{question}: pending tray receipt does not deep-link to the waiting claim"
    );
}

#[test]
fn answerability_test_pack_what_can_she_do_without_asking_from_grants_lens() {
    let question = "What can she do without asking?";
    let fixture = answerability_fixture();
    let row = fixture
        .grants_lens
        .grants
        .iter()
        .find(|row| row.grant_ref == PARTY_GRANT_REF)
        .unwrap_or_else(|| panic!("{question}: grants lens is missing the party grant"));

    assert_eq!(row.status, "active");
    assert!(!row.stale, "{question}: active grant is unexpectedly stale");
    assert_eq!(row.scope_dial, "always_this_brief_invites");
    assert_eq!(row.origin_receipt_ref.as_deref(), Some("gate:bundle-party"));
    assert_eq!(row.last_used_at, Some(105));

    let joined_receipts = receipt_ids(&row.receipt_join);
    for expected in [
        "scoped_read:party-grant:created",
        "outbound:intent:invite-yuki",
        "outbound:intent:venue-email",
    ] {
        assert!(
            joined_receipts.contains(expected),
            "{question}: grant receipt join is missing {expected}"
        );
    }
    assert_eq!(
        row.receipt_join.budget_debit_total, 12,
        "{question}: grant receipt join did not preserve budget cost"
    );
}
