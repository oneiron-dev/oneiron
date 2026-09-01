use crate::common::entity;
use std::collections::{BTreeMap, BTreeSet};

use oneiron::{
    ClaimApprovalStatus, ClaimCandidate, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EntityId, Error, HnswConfig, Result, TimeRange, Vault, VaultConfig, WriteActor,
    WriteEnvelope, WriteProvenance, commitment::CommitmentBirthKind,
    commitment::CommitmentBirthProvenance, commitment::CommitmentContent,
    commitment::CommitmentObligor, commitment::CommitmentObligorKind, commitment::CommitmentRecord,
    commitment::CommitmentStatus, commitment::CommitmentStrength,
    dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND, genui::GrantMintIntent,
    genui::GrantMintIntentScope, genui::ReceiptDeepLinkKind, genui::ViewTimeResolution,
    genui::resolve_commitment_receipt_link, outbound::OutboundIntentSource,
    receipt::GrantReceiptProjection, receipt::PendingTrayQuery, receipt::ReceiptKind,
    receipt::ReceiptQuery, receipt::ReceiptRecord, receipt::StandingOutboundGrantsLensQuery,
    receipt::project_receipts_by_brief, receipt::project_receipts_by_counterparty,
    receipt::project_receipts_by_grant, registry::ENTITY_TYPE_PERSON,
};
use rmpv::Value;

const BRIEF_REF: &str = "brief:party";
const PENDING_DREAMER_RUN_ID: &str = "dreamer:party-planning";

struct AnswerabilityFixture {
    receipts: Vec<ReceiptRecord>,
    grant_ref: String,
}

struct PublicSurfaceFixture {
    _tmp: tempfile::TempDir,
    vault: Vault,
    grant_ref: String,
    pending_claim_id: EntityId,
}

/// A vault carrying one real CMT-1 commitment behind an outbound receipt, plus
/// the heads the history door must still answer for once the promise stops
/// being the live one: a superseded head, a retracted head, a CLAIM that is not
/// a commitment at all, and an id that was never written.
struct CommitmentDoorFixture {
    _tmp: tempfile::TempDir,
    vault: Vault,
    record: CommitmentRecord,
    open: EntityId,
    superseded: EntityId,
    retracted: EntityId,
    stranger_claim: EntityId,
    absent: EntityId,
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

fn answerability_fixture() -> Result<AnswerabilityFixture> {
    let surfaces = public_surface_fixture()?;
    let grant_ref = surfaces.grant_ref.clone();
    let mut receipts = vec![
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
                ("grant_ref", grant_ref.as_str()),
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
                ("grant_ref", grant_ref.as_str()),
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
                ("grant_ref", grant_ref.as_str()),
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
                ("grant_ref", grant_ref.as_str()),
                ("budget_debit", "1"),
            ],
        }),
        receipt(ReceiptFixture {
            receipt_id: "outbound:intent:invite-mika",
            receipt_kind: ReceiptKind::Outbound,
            occurred_at: 104,
            outcome: "suppressed",
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
                ("suppression", "counterparty_opt_out"),
                ("suppression_reason", "counterparty.opt_out"),
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
                ("grant_ref", grant_ref.as_str()),
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
                ("grant_ref", grant_ref.as_str()),
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
                ("intent_source", "commitment"),
                ("local_time", "02:00"),
                ("verb", "send"),
                ("channel", "chat"),
                ("budget_debit", "1"),
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

    receipts.extend(
        surfaces
            .vault
            .receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::ScopedRead))?,
    );

    Ok(AnswerabilityFixture {
        receipts,
        grant_ref,
    })
}

fn public_surface_fixture() -> Result<PublicSurfaceFixture> {
    let (_tmp, vault) = temp_vault()?;

    let grant_id = entity(0xD9);
    let grant_ref = format!("grant:{}", grant_id.to_hex());
    let grant_intent = GrantMintIntent {
        principal_ref: "owner".to_owned(),
        origin_component_id: "bundle-approve-party".to_owned(),
        origin_action_id: "approve_bundle_brief_verb_class".to_owned(),
        origin_receipt_ref: Some("gate:bundle-party".to_owned()),
        scope: GrantMintIntentScope::BriefVerbClass {
            brief_ref: BRIEF_REF.to_owned(),
            verb_class: "send".to_owned(),
        },
    };
    vault.mint_standing_outbound_grant(&grant_id, &grant_intent, 90)?;

    let actor = entity(0x90);
    let subject = entity(0x92);
    vault.put_entity(
        &actor,
        ENTITY_TYPE_PERSON,
        test_time(1),
        1,
        b"eiri agent actor",
    )?;
    vault.put_entity(
        &subject,
        ENTITY_TYPE_PERSON,
        test_time(1),
        1,
        b"party guest-count subject",
    )?;

    let pending_claim_id = entity(0x91);
    let candidate = ClaimCandidate::new(
        "profile.party_guest_count",
        ClaimSubject::Entity(subject),
        Value::from("confirm final guest count before sending venue update"),
        0.82,
    );
    let envelope = WriteEnvelope::new(
        WriteActor::new(actor, EdgeActorClass::Agent),
        ClaimSource::Generated,
        WriteProvenance::new(Value::Map(vec![
            (
                Value::from("runner"),
                Value::from(DREAMER_RUNNER_ATTEMPT_KIND),
            ),
            (Value::from("run_id"), Value::from(PENDING_DREAMER_RUN_ID)),
        ]))?,
        ClaimApprovalStatus::Proposed,
    );
    vault
        .batch()
        .claim_candidate(&pending_claim_id, candidate, &envelope, test_time(108), 108)
        .commit()?;

    Ok(PublicSurfaceFixture {
        _tmp,
        vault,
        grant_ref,
        pending_claim_id,
    })
}

fn commitment_door_fixture() -> Result<CommitmentDoorFixture> {
    let (_tmp, vault) = temp_vault()?;
    let obligor = entity(0x61);
    let beneficiary = entity(0x62);
    vault.put_entity(&obligor, ENTITY_TYPE_PERSON, test_time(1), 1, b"party host")?;
    vault.put_entity(
        &beneficiary,
        ENTITY_TYPE_PERSON,
        test_time(1),
        1,
        b"venue contact",
    )?;

    let envelope = WriteEnvelope::new(
        WriteActor::new(obligor, EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(Value::from("owner stated the venue commitment"))?,
        ClaimApprovalStatus::Auto,
    );
    let record = CommitmentRecord::new(
        CommitmentObligor::new(CommitmentObligorKind::Owner, obligor),
        beneficiary,
        CommitmentContent::new("send the venue the final guest count", None)?,
        // Opaque on purpose: the receipt door never looks inside the schedule,
        // and this pack imports no schedule type to build one.
        Value::Map(vec![
            (Value::from("kind"), Value::from("opaque")),
            (Value::from("payload"), Value::Array(vec![Value::from(7)])),
        ]),
        CommitmentStrength::Commitment,
        CommitmentStatus::Open,
        CommitmentBirthProvenance::new(CommitmentBirthKind::Brief, BRIEF_REF)?,
    )?;
    let due = TimeRange {
        start: 120,
        end: 200,
    };

    let open = entity(0x63);
    vault.put_commitment_claim(&open, &record, &envelope, due, 110)?;

    // A live successor takes over, but the receipt cited the head it was minted
    // against, so that head must stay reachable.
    let superseded = entity(0x64);
    let successor = entity(0x65);
    vault.put_commitment_claim(&superseded, &record, &envelope, due, 111)?;
    vault.put_commitment_claim(&successor, &record, &envelope, due, 112)?;
    vault.supersede_claim(&successor, &superseded, 210)?;

    let retracted = entity(0x66);
    vault.put_commitment_claim(&retracted, &record, &envelope, due, 113)?;
    vault.retract_claim(&retracted, 215)?;

    // A CLAIM that is not a `commitment.record`, written through the same
    // public claim door the rest of this pack uses.
    let stranger_claim = entity(0x67);
    vault
        .batch()
        .claim_candidate(
            &stranger_claim,
            ClaimCandidate::new(
                "profile.display_name",
                ClaimSubject::Entity(beneficiary),
                Value::from("Sakura Hall"),
                0.9,
            ),
            &envelope,
            test_time(114),
            114,
        )
        .commit()?;

    Ok(CommitmentDoorFixture {
        _tmp,
        vault,
        record,
        open,
        superseded,
        retracted,
        stranger_claim,
        absent: entity(0x68),
    })
}

fn commitment_trigger(id: EntityId) -> String {
    format!("commitment:{}", id.to_hex())
}

/// The 2am-reminder receipt shape, with the two fields the commitment door
/// actually reads left free so each case names the single axis it moves.
fn commitment_door_receipt(
    intent_source: Option<&str>,
    trigger_ref: Option<&str>,
) -> ReceiptRecord {
    let fields: Vec<(&str, &str)> = intent_source
        .into_iter()
        .map(|source| ("intent_source", source))
        .collect();
    receipt(ReceiptFixture {
        receipt_id: "outbound:intent:venue-guest-count",
        receipt_kind: ReceiptKind::Outbound,
        occurred_at: 120,
        outcome: "delivered_to_channel",
        job_ref: Some(BRIEF_REF),
        trigger_ref,
        policy_trace: &["delivery_window.async_surface_allowed"],
        fields: &fields,
    })
}

fn temp_vault() -> Result<(tempfile::TempDir, Vault)> {
    let dir = tempfile::tempdir()?;
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = Some("test/model@v1".to_owned());
    config.max_readers = 16;
    config.hnsw = HnswConfig::default();
    let vault = Vault::open(dir.path(), config)?;
    Ok((dir, vault))
}

const fn test_time(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

fn receipt(fixture: ReceiptFixture<'_>) -> ReceiptRecord {
    let mut fields = field_map(fixture.fields);
    if fixture.receipt_kind == ReceiptKind::Outbound {
        fields
            .entry("receipt_schema".to_owned())
            .or_insert_with(|| "outbound_receipt.v1".to_owned());
        fields
            .entry("engine_register".to_owned())
            .or_insert_with(|| "neutral".to_owned());
        fields
            .entry("care_register".to_owned())
            .or_insert_with(|| "eirispec_care_register".to_owned());
        fields
            .entry("audit_register".to_owned())
            .or_insert_with(|| "dashboard_atom_kit_audit".to_owned());
    }

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
        fields,
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
    receipt.fields.get(key).map_or_else(
        || panic!("{question}: missing receipt field {key}"),
        String::as_str,
    )
}

fn receipt_ids(projection: &GrantReceiptProjection) -> BTreeSet<&str> {
    projection
        .receipts
        .iter()
        .map(|receipt| receipt.receipt_id.as_str())
        .collect()
}

#[test]
fn answerability_pack_outbound_receipts_use_o5_shape_and_register_split() -> Result<()> {
    let fixture = answerability_fixture()?;
    let canonical_outcomes = BTreeSet::from([
        "delivered_to_channel",
        "held",
        "degraded",
        "suppressed",
        "let_go",
        "failed",
    ]);

    for receipt in fixture
        .receipts
        .iter()
        .filter(|receipt| receipt.receipt_kind == ReceiptKind::Outbound)
    {
        assert!(
            canonical_outcomes.contains(receipt.outcome.as_str()),
            "outbound receipt {} used non-O5 outcome {}",
            receipt.receipt_id,
            receipt.outcome
        );
        assert_ne!(receipt.outcome, "seen");
        assert_ne!(receipt.outcome, "declined");
        assert_ne!(receipt.outcome, "denied");
        assert_eq!(
            field(receipt, "receipt_schema", "O5 shape"),
            "outbound_receipt.v1"
        );
        assert_eq!(field(receipt, "engine_register", "O5 shape"), "neutral");
        assert_eq!(
            field(receipt, "care_register", "O5 shape"),
            "eirispec_care_register"
        );
        assert_eq!(
            field(receipt, "audit_register", "O5 shape"),
            "dashboard_atom_kit_audit"
        );
    }

    Ok(())
}

#[test]
fn answerability_test_pack_why_didnt_you_send_it_from_receipts_alone() -> Result<()> {
    let question = "Why didn't you send it?";
    let fixture = answerability_fixture()?;
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
            .any(|receipt| receipt.outcome == "degraded"
                && field(receipt, "degraded_from", question) == "push:time_sensitive"
                && field(receipt, "degraded_to", question) == "chat:passive"),
        "{question}: degraded receipt lacks degraded_from/degraded_to explanation"
    );
    assert!(
        negative_space
            .iter()
            .any(|receipt| receipt.outcome == "suppressed"
                && receipt
                    .policy_trace
                    .iter()
                    .any(|trace| trace == "counterparty.opt_out")
                && field(receipt, "suppression", question) == "counterparty_opt_out"
                && field(receipt, "opt_out", question) == "true"),
        "{question}: suppressed opt-out receipt lacks counterparty explanation"
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
    Ok(())
}

#[test]
fn answerability_test_pack_why_message_at_2am_from_receipts_alone() -> Result<()> {
    let question = "Why did you message at 2am?";
    let fixture = answerability_fixture()?;
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
    Ok(())
}

#[test]
fn answerability_test_pack_what_happened_with_the_party_from_brief_projection() -> Result<()> {
    let question = "What happened with the party?";
    let fixture = answerability_fixture()?;
    let grant_ref = fixture.grant_ref.clone();
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
    let grant_receipt = projection
        .consent_grants
        .iter()
        .find(|receipt| field(receipt, "grant_ref", question) == grant_ref)
        .unwrap_or_else(|| panic!("{question}: real grant-created receipt is absent"));
    assert_eq!(grant_receipt.receipt_kind, ReceiptKind::ScopedRead);
    assert_eq!(grant_receipt.job_ref.as_deref(), Some(BRIEF_REF));
    assert_eq!(field(grant_receipt, "scope", question), "brief_verb_class");
    assert_eq!(
        field(grant_receipt, "origin_action_id", question),
        "approve_bundle_brief_verb_class"
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
        "failed",
        "let_go",
    ] {
        assert!(
            outcomes.contains(expected),
            "{question}: brief projection is missing outcome {expected}"
        );
    }
    Ok(())
}

#[test]
fn answerability_test_pack_who_contacted_on_my_behalf_from_counterparty_projection() -> Result<()> {
    let question = "Who have you contacted on my behalf?";
    let fixture = answerability_fixture()?;
    let projections = project_receipts_by_counterparty(fixture.receipts);
    let counterparties = projections
        .iter()
        .map(|projection| projection.counterparty_ref.as_str())
        .collect::<BTreeSet<_>>();
    let expected_counterparties = BTreeSet::from([
        "person:yuki",
        "person:kenji",
        "person:mika",
        "venue:sakura-hall",
    ]);

    assert_eq!(
        counterparties, expected_counterparties,
        "{question}: counterparty projection should contain exactly the external counterparties"
    );
    assert!(
        !counterparties.contains("owner"),
        "{question}: counterparty projection should not report the owner as an external contact"
    );

    let mika = projections
        .iter()
        .find(|projection| projection.counterparty_ref == "person:mika")
        .unwrap_or_else(|| panic!("{question}: missing suppressed opt-out counterparty"));
    assert_eq!(mika.first_touch.as_deref(), Some("user_introduction"));
    assert_eq!(mika.opt_out, Some(true));
    assert_eq!(mika.promo_consent, Some(false));
    assert_eq!(mika.budget_debit_total, 0);
    Ok(())
}

#[test]
fn answerability_test_pack_what_did_that_cost_from_budget_debits() -> Result<()> {
    let question = "What did that cost?";
    let fixture = answerability_fixture()?;
    let brief = project_receipts_by_brief(BRIEF_REF, fixture.receipts.clone());
    let grant = project_receipts_by_grant(fixture.grant_ref, fixture.receipts);

    assert_eq!(
        brief.budget_debit_total, 13,
        "{question}: brief projection did not sum every receipt budget_debit"
    );
    assert_eq!(
        grant.budget_debit_total, 12,
        "{question}: grant projection did not sum grant-scoped receipt debits"
    );
    Ok(())
}

#[test]
fn answerability_test_pack_whats_waiting_on_me_from_pending_tray_surface() -> Result<()> {
    let question = "What's waiting on me?";
    let fixture = public_surface_fixture()?;
    let pending_claim_ref = fixture.pending_claim_id.to_hex();
    let initial_asks = fixture.vault.pending_tray(PendingTrayQuery::new(10))?;
    let created_at = initial_asks
        .iter()
        .find(|ask| ask.claim_id == pending_claim_ref)
        .unwrap_or_else(|| panic!("{question}: pending tray did not expose guest-count ask"))
        .created_at;
    let asks = fixture
        .vault
        .pending_tray(PendingTrayQuery::at(created_at + 60 * 60, 10))?;
    let ask = asks
        .iter()
        .find(|ask| ask.claim_id == pending_claim_ref)
        .unwrap_or_else(|| panic!("{question}: pending tray did not expose guest-count ask"));

    assert_eq!(ask.hold_reason, "gate.pending.actor_ceiling");
    assert_eq!(ask.age_secs, 60 * 60);
    assert!(
        ask.hold_reasons
            .iter()
            .any(|reason| reason == "gate.pending.actor_ceiling"),
        "{question}: pending tray does not expose the actor-ceiling hold"
    );
    assert_eq!(ask.dreamer_run_id.as_deref(), Some(PENDING_DREAMER_RUN_ID));
    assert_eq!(ask.receipt_view.receipt.receipt_kind, ReceiptKind::Gate);
    assert_eq!(ask.receipt_view.receipt.outcome, "pending");
    let pending_trigger_ref = format!("claim:{pending_claim_ref}");
    assert_eq!(
        ask.receipt_view.receipt.trigger_ref.as_deref(),
        Some(pending_trigger_ref.as_str()),
        "{question}: pending tray receipt does not deep-link to the waiting claim"
    );
    Ok(())
}

#[test]
fn answerability_test_pack_what_can_she_do_without_asking_from_grants_lens() -> Result<()> {
    let question = "What can she do without asking?";
    let fixture = public_surface_fixture()?;
    let lens = fixture
        .vault
        .standing_outbound_grants_lens(StandingOutboundGrantsLensQuery::new(10, 10))?;
    let row = lens
        .grants
        .iter()
        .find(|row| row.grant_ref == fixture.grant_ref)
        .unwrap_or_else(|| panic!("{question}: grants lens is missing the party grant"));

    assert_eq!(row.status, "active");
    assert!(!row.stale, "{question}: active grant is unexpectedly stale");
    assert_eq!(row.scope_dial, "brief_verb_class");
    assert_eq!(row.origin_receipt_ref.as_deref(), Some("gate:bundle-party"));
    assert_eq!(row.created_at, 90);
    assert_eq!(row.last_used_at, None);
    assert_eq!(row.revoke_action.command, "revoke_standing_outbound_grant");
    assert_eq!(row.revoke_action.grant_ref, fixture.grant_ref);

    let joined_receipts = receipt_ids(&row.receipt_join);
    let created_receipt_id = format!("scoped_read:{}:created", fixture.grant_ref);
    assert!(
        joined_receipts.contains(created_receipt_id.as_str()),
        "{question}: grant receipt join is missing the real grant-created receipt"
    );
    assert_eq!(
        row.receipt_join.budget_debit_total, 0,
        "{question}: real grants-lens join should only include receipt-family rows it queries"
    );
    Ok(())
}

#[test]
fn answerability_test_pack_which_promise_made_you_send_this_round_trips_to_the_commitment()
-> Result<()> {
    let question = "Which promise made you send this?";
    let fixture = commitment_door_fixture()?;
    let target = commitment_trigger(fixture.open);

    let link = resolve_commitment_receipt_link(
        &fixture.vault,
        &commitment_door_receipt(Some("commitment"), Some(target.as_str())),
        "the commitment behind this message",
    )?
    .unwrap_or_else(|| panic!("{question}: commitment-sourced receipt did not open the door"));

    assert_eq!(link.target_kind, ReceiptDeepLinkKind::Commitment);
    assert_eq!(
        link.target_ref, target,
        "{question}: link lost the cited commitment"
    );
    assert_eq!(link.label, "the commitment behind this message");
    assert_eq!(link.resolution, ViewTimeResolution::Active);

    // The link is only worth anything if the ref it hands back reads out as the
    // very commitment the receipt was minted against — so the round trip goes
    // through the link's own target_ref, not through the fixture's handle.
    let linked = EntityId::from_hex(
        link.target_ref
            .strip_prefix("commitment:")
            .unwrap_or_else(|| panic!("{question}: link target lost its commitment: prefix")),
    )?;
    assert_eq!(linked, fixture.open, "{question}: link points elsewhere");
    assert_eq!(
        fixture
            .vault
            .get_commitment_claim(&linked)?
            .unwrap_or_else(|| panic!("{question}: linked commitment is unreadable")),
        fixture.record,
        "{question}: the door did not land back on the minted commitment"
    );
    Ok(())
}

#[test]
fn answerability_test_pack_is_that_promise_still_standing_from_claim_lifecycle() -> Result<()> {
    let question = "Is that promise still standing?";
    let fixture = commitment_door_fixture()?;
    let vault = &fixture.vault;

    // Ground the three heads first: without this the resolution assertions
    // below could pass against claims that never left `active`.
    for (id, lifecycle) in [
        (fixture.open, ClaimLifecycleStatus::Active),
        (fixture.superseded, ClaimLifecycleStatus::Superseded),
        (fixture.retracted, ClaimLifecycleStatus::Retracted),
    ] {
        assert_eq!(
            vault
                .get_claim(&id)?
                .unwrap_or_else(|| panic!("{question}: fixture head {id:?} is missing"))
                .lifecycle,
            lifecycle,
            "{question}: fixture head is not in the state under test"
        );
    }

    // A readable claim head is `Active` view-time even when the promise itself
    // has been replaced; only a retracted head is `Revoked`. A closed door is
    // never an absent one.
    for (id, expected) in [
        (fixture.open, ViewTimeResolution::Active),
        (fixture.superseded, ViewTimeResolution::Active),
        (fixture.retracted, ViewTimeResolution::Revoked),
    ] {
        let target = commitment_trigger(id);
        let link = resolve_commitment_receipt_link(
            vault,
            &commitment_door_receipt(Some("commitment"), Some(target.as_str())),
            "the commitment behind this message",
        )?
        .unwrap_or_else(|| panic!("{question}: {target} did not resolve"));
        assert_eq!(link.target_kind, ReceiptDeepLinkKind::Commitment);
        assert_eq!(link.target_ref, target);
        assert_eq!(
            link.resolution, expected,
            "{question}: {target} resolved to the wrong view-time state"
        );
    }

    // Past the source gate the door either links or fails typed. A receipt that
    // cites an unreadable commitment must never answer a quiet "no link".
    let absent = commitment_trigger(fixture.absent);
    let missing = resolve_commitment_receipt_link(
        vault,
        &commitment_door_receipt(Some("commitment"), Some(absent.as_str())),
        "label",
    )
    .expect_err("no claim head under the cited id");
    assert!(
        matches!(missing, Error::EntityNotFound),
        "{question}: got {missing:?}"
    );

    let stranger = commitment_trigger(fixture.stranger_claim);
    let wrong_family = resolve_commitment_receipt_link(
        vault,
        &commitment_door_receipt(Some("commitment"), Some(stranger.as_str())),
        "label",
    )
    .expect_err("CLAIM head is not a commitment.record");
    assert!(
        matches!(wrong_family, Error::InvalidClaimBody(_)),
        "{question}: got {wrong_family:?}"
    );

    let malformed = resolve_commitment_receipt_link(
        vault,
        &commitment_door_receipt(Some("commitment"), Some("commitment:not-hex")),
        "label",
    )
    .expect_err("malformed hex suffix");
    assert!(
        matches!(malformed, Error::InvalidKey),
        "{question}: got {malformed:?}"
    );

    // Label validation stays with the fallible deep-link constructor.
    let open_target = commitment_trigger(fixture.open);
    let empty_label = resolve_commitment_receipt_link(
        vault,
        &commitment_door_receipt(Some("commitment"), Some(open_target.as_str())),
        "",
    )
    .expect_err("empty deep-link label");
    assert!(
        matches!(empty_label, Error::InvalidConfig(_)),
        "{question}: got {empty_label:?}"
    );
    Ok(())
}

#[test]
fn answerability_test_pack_why_message_at_2am_gates_on_intent_source_before_trigger_shape()
-> Result<()> {
    let question = "Why did you message at 2am?";
    let fixture = commitment_door_fixture()?;
    let vault = &fixture.vault;
    let target = commitment_trigger(fixture.open);

    assert_eq!(
        OutboundIntentSource::parse("commitment"),
        Some(OutboundIntentSource::Commitment)
    );
    assert_eq!(
        OutboundIntentSource::parse("commitment_timer_wake"),
        Some(OutboundIntentSource::Commitment),
        "{question}: the timer-wake alias is the same door"
    );
    for source in ["commitment", "commitment_timer_wake"] {
        assert!(
            resolve_commitment_receipt_link(
                vault,
                &commitment_door_receipt(Some(source), Some(target.as_str())),
                "label",
            )?
            .is_some(),
            "{question}: {source} must open the commitment door"
        );
    }

    // The source gate is primary: a perfectly shaped commitment trigger on a
    // non-commitment receipt is still not a commitment door, and the fields map
    // is serde-defaulted, so an absent source is a valid receipt shape rather
    // than a read failure.
    for source in [Some("gap_queue"), None] {
        assert!(
            resolve_commitment_receipt_link(
                vault,
                &commitment_door_receipt(source, Some(target.as_str())),
                "label",
            )?
            .is_none(),
            "{question}: {source:?} must not open the commitment door"
        );
    }

    // Commitment-sourced legacy rows: SPINE-COMM owns producer-side prefix
    // enforcement, so a missing or differently prefixed trigger is tolerated.
    for trigger in [None, Some("intent:invite-kenji")] {
        assert!(
            resolve_commitment_receipt_link(
                vault,
                &commitment_door_receipt(Some("commitment"), trigger),
                "label",
            )?
            .is_none(),
            "{question}: {trigger:?} is not a commitment trigger"
        );
    }

    // A present-but-broken `commitment:` suffix is a producer bug: it fails
    // typed and never collapses to Ok(None). `commitment:party-reminder` is the
    // literal this pack already carries on the 2am receipt, and exactly one
    // prefix comes off, so a doubled prefix does not resolve to the id inside.
    let doubled = format!("commitment:{target}");
    for broken in ["commitment:", "commitment:party-reminder", doubled.as_str()] {
        let error = resolve_commitment_receipt_link(
            vault,
            &commitment_door_receipt(Some("commitment"), Some(broken)),
            "label",
        )
        .expect_err("malformed commitment trigger suffix");
        assert!(
            matches!(error, Error::InvalidKey),
            "{question}: {broken} must fail typed, got {error:?}"
        );
    }
    Ok(())
}
