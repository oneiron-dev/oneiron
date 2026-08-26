// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
//! ONE-1777 (CA-06) shipping oracle for the campaign-compliance dispatch gate.
//!
//! The in-crate unit tests pin the pack parser, the row selector, the evidence
//! hydrator, and the amendment classifier. This file proves the same walls
//! through the SHIPPING path only — `Vault::dispatch_outbound_intent` — using
//! nothing but the public API, so a refactor that keeps the evaluator honest
//! while detaching it from the send pipeline still fails here.
//!
//! The vault is deliberately UNSEEDED, so the external-effect ladder is
//! fail-closed and a compliant dispatch lands on
//! `gate.pending.external_effect_authority`. That pending IS the control: the
//! compliance stage must convert it to a hard `deny` when a row refuses, and
//! must leave it untouched when the facts satisfy every governing row. Nothing
//! reaches the transport in either case, which is what makes the difference
//! between the two arms attributable to compliance alone.
//!
//! CLOCK NOTE: the gate stamps its own trusted clock, so these arms run against
//! the real one. The seeded rows carry a verification date and the pack carries
//! an annual verification-age dial; when that window closes, the compliant arms
//! below start failing with `campaign_compliance_stale_rule`. That is the
//! designed tripwire, not a flake — a pack past re-verification must refuse to
//! send, and the fix is a data revision to `compliance/seed_v1.json`.

use crate::common::entity as test_id;

use oneiron::campaign::claims::PREDICATE_CAMPAIGN_MEMBER;
use oneiron::campaign::compliance::{
    PREDICATE_CRM_COMPLIANCE_EVIDENCE, PREDICATE_CRM_COMPLIANCE_JP_PUBLICATION,
    PREDICATE_CRM_COMPLIANCE_LIST_PROVENANCE, PREDICATE_CRM_COMPLIANCE_MESSAGE_ELEMENTS,
    embedded_seed_pack,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId, Result,
    TimeRange, Vault, VaultConfig, outbound::OutboundDeliveryWindowDecision,
    outbound::OutboundDispatchActor, outbound::OutboundDispatchGate,
    outbound::OutboundDispatchRequest, outbound::OutboundDispatchResult,
    outbound::OutboundExecutionOutcome, outbound::OutboundExecutionRequest,
    outbound::OutboundExecutionSink, outbound::OutboundIntent, outbound::OutboundIntentDraft,
    outbound::OutboundIntentTrigger,
};
use rmpv::Value;

/// The campaign member every governed dispatch addresses.
const COUNTERPARTY: &str = "kenji@example.com";
/// A counterparty carrying no campaign membership.
const NON_MEMBER: &str = "ops@example.net";
const EMAIL: &str = "email";
/// The platform direct-message lane.
const DM: &str = "linkedin";
const EMAIL_VERB: &str = "send";
const DM_VERB: &str = "send_dm";
/// The gate stage a compliant dispatch falls through to on this fixture.
const PENDING_AUTHORITY: &str = "gate.pending.external_effect_authority";
/// The reason code the compliance stage raises.
const DENY_COMPLIANCE: &str = "gate.deny.campaign_compliance";

const ACTOR_SEED: u8 = 0xB1;
const CAMPAIGN_SEED: u8 = 0xB2;
const EMAIL_IDENTITY_SEED: u8 = 0xB3;
const DM_IDENTITY_SEED: u8 = 0xB4;
const BASIS_SEED: u8 = 0xB5;
const SENDER_SEED: u8 = 0xB6;
const MEMBERSHIP_SEED: u8 = 0xB7;
const EMAIL_ELEMENTS_SEED: u8 = 0xB8;
const DM_ELEMENTS_SEED: u8 = 0xB9;
const EVIDENCE_SEED: u8 = 0xBA;
const PROVENANCE_SEED: u8 = 0xBB;
const PUBLICATION_SEED: u8 = 0xBC;
const JURISDICTION_SEED: u8 = 0xBF;
const FULL_EVIDENCE_SEED: u8 = 0xC0;

#[derive(Default)]
struct RecordingSink {
    calls: usize,
}

impl OutboundExecutionSink for RecordingSink {
    fn execute(&mut self, _request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        self.calls += 1;
        OutboundExecutionOutcome::delivered_to_channel("provider:message:one")
    }
}

fn test_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    config
}

/// Everything the fixtures below address.
struct Fixture {
    vault: Vault,
    member: EntityId,
}

/// An unseeded vault plus the comm-owned PERSON every governed dispatch
/// addresses. See the module note for why unseeded is the right control.
fn oracle_vault() -> (tempfile::TempDir, Fixture) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open_unseeded_for_test(dir.path(), test_config()).unwrap();
    for seed in [
        ACTOR_SEED,
        CAMPAIGN_SEED,
        EMAIL_IDENTITY_SEED,
        DM_IDENTITY_SEED,
    ] {
        put_person(&vault, seed);
    }
    let member = oneiron::comm::resolve_or_create_comm_party(&vault, COUNTERPARTY).unwrap();
    (dir, Fixture { vault, member })
}

fn put_person(vault: &Vault, seed: u8) -> EntityId {
    let id = test_id(seed);
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"campaign compliance oracle fixture",
        )
        .unwrap();
    id
}

fn map(entries: &[(&str, Value)]) -> Value {
    Value::Map(
        entries
            .iter()
            .map(|(key, value)| (Value::from(*key), value.clone()))
            .collect(),
    )
}

fn put_claim(
    vault: &Vault,
    seed: u8,
    predicate: &str,
    subject: EntityId,
    value: Value,
) -> Result<()> {
    let body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(subject),
        value,
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    vault.put_claim(&test_id(seed), &body, TimeRange { start: 1, end: 1 }, 1)
}

/// Membership is the campaign scope: it is what puts a dispatch under CA-06.
fn enroll(vault: &Vault, member: EntityId) -> Result<()> {
    let channel_row = |channel: &str| {
        map(&[
            ("channel", Value::from(channel)),
            ("basis_evidence", Value::from(test_id(BASIS_SEED).to_hex())),
            ("sender_ref", Value::from(test_id(SENDER_SEED).to_hex())),
        ])
    };
    put_claim(
        vault,
        MEMBERSHIP_SEED,
        PREDICATE_CAMPAIGN_MEMBER,
        member,
        map(&[
            ("campaign", Value::from(test_id(CAMPAIGN_SEED).to_hex())),
            ("state", map(&[("kind", Value::from("enrolled"))])),
            (
                "channels",
                Value::Array(vec![channel_row(EMAIL), channel_row(DM)]),
            ),
        ]),
    )
}

/// The sending identity's compliance footer configuration.
fn configure_message_elements(vault: &Vault, seed: u8, identity: EntityId) -> Result<()> {
    put_claim(
        vault,
        seed,
        PREDICATE_CRM_COMPLIANCE_MESSAGE_ELEMENTS,
        identity,
        map(&[
            ("sender_identity", Value::from(true)),
            ("physical_address", Value::from(true)),
            ("optout_mechanism", Value::from(true)),
            ("commercial_marking", Value::from(true)),
        ]),
    )
}

/// The connector capability table names each lane's verb; a platform DM is not
/// an email send.
fn verb_for(channel: &str) -> &'static str {
    if channel == DM { DM_VERB } else { EMAIL_VERB }
}

fn dispatch(
    vault: &Vault,
    intent_ref: &str,
    channel: &str,
    counterparty: &str,
    identity: EntityId,
    sink: &mut RecordingSink,
) -> OutboundDispatchResult {
    let intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new("agent-alpha", verb_for(channel), channel, counterparty)
            .on_behalf_of("owner")
            .content_ref("content:campaign-touch"),
        OutboundIntentTrigger::agent_immediate("session:compliance-oracle"),
    );
    let request = OutboundDispatchRequest::new(
        format!("outbound:{intent_ref}"),
        intent_ref,
        intent,
        OutboundDispatchActor::agent(test_id(ACTOR_SEED)),
        OutboundDispatchGate::allow_when_policy_grants(),
        1_000,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .counterparty_ref(counterparty)
    .channel_identity_ref(identity);
    vault.dispatch_outbound_intent(request, sink).unwrap()
}

fn blocked_by_compliance(result: &OutboundDispatchResult) -> bool {
    result
        .gate_reason_codes
        .iter()
        .any(|code| code == DENY_COMPLIANCE)
}

/// The compliance stage let this dispatch through to the next existing gate
/// stage: no compliance denial, and the fail-closed authority ask survived
/// intact rather than being converted.
fn cleared_compliance(result: &OutboundDispatchResult) -> bool {
    !blocked_by_compliance(result)
        && result.gate_outcome == "pending"
        && result
            .gate_reason_codes
            .iter()
            .any(|code| code == PENDING_AUTHORITY)
}

#[test]
fn campaign_compliance_gate_oracle() -> Result<()> {
    let (_dir, fixture) = oracle_vault();
    let vault = &fixture.vault;
    let mut sink = RecordingSink::default();

    // A counterparty with no campaign membership is outside CA-06 entirely:
    // compliance never runs, and the existing gate ladder decides alone. This
    // is what keeps booking confirmations and support replies untouched.
    let non_member = oneiron::comm::resolve_or_create_comm_party(vault, NON_MEMBER).unwrap();
    assert_ne!(non_member, fixture.member);
    let ungoverned = dispatch(
        vault,
        "intent:non-member",
        EMAIL,
        NON_MEMBER,
        test_id(EMAIL_IDENTITY_SEED),
        &mut sink,
    );
    assert!(
        !blocked_by_compliance(&ungoverned),
        "a non-campaign send must never enter the compliance stage: {:?}",
        ungoverned.gate_reason_codes
    );
    assert!(
        cleared_compliance(&ungoverned),
        "an ungoverned send keeps the existing ladder's own answer: {:?}",
        ungoverned.gate_reason_codes
    );

    // Enroll the counterparty. With no jurisdiction observation recorded, the
    // pack's unknown disposition routes to the strictest seeded pole — and the
    // pole's conditional consent-class row needs the recipient's legal form,
    // which nothing has supplied yet.
    enroll(vault, fixture.member)?;
    configure_message_elements(vault, EMAIL_ELEMENTS_SEED, test_id(EMAIL_IDENTITY_SEED))?;
    let no_jurisdiction = dispatch(
        vault,
        "intent:no-jurisdiction",
        EMAIL,
        COUNTERPARTY,
        test_id(EMAIL_IDENTITY_SEED),
        &mut sink,
    );
    assert_eq!(no_jurisdiction.gate_outcome, "deny");
    assert!(blocked_by_compliance(&no_jurisdiction));
    assert!(
        no_jurisdiction
            .receipt
            .policy_trace
            .contains(&DENY_COMPLIANCE.to_owned()),
        "the refusal must reach the receipt: {:?}",
        no_jurisdiction.receipt.policy_trace
    );
    assert_eq!(
        sink.calls, 0,
        "a blocking verdict must prevent connector dispatch"
    );

    // Supplying the legal form satisfies the pole, and the dispatch falls
    // through to the gate stage that would have decided it anyway. Nothing
    // asked a human to approve the send itself: compliance adds no approval
    // surface, it only subtracts unlawful dispatches.
    put_claim(
        vault,
        EVIDENCE_SEED,
        PREDICATE_CRM_COMPLIANCE_EVIDENCE,
        fixture.member,
        map(&[("legal_form", Value::from("corporate"))]),
    )?;
    let evidenced = dispatch(
        vault,
        "intent:evidenced",
        EMAIL,
        COUNTERPARTY,
        test_id(EMAIL_IDENTITY_SEED),
        &mut sink,
    );
    assert!(
        cleared_compliance(&evidenced),
        "a fully evidenced send passes to the next existing gate stage: {:?}",
        evidenced.gate_reason_codes
    );
    assert!(
        !evidenced
            .receipt
            .policy_trace
            .contains(&DENY_COMPLIANCE.to_owned())
    );
    Ok(())
}

#[test]
fn campaign_compliance_gate_oracle_missing_message_elements_block_the_send() -> Result<()> {
    let (_dir, fixture) = oracle_vault();
    let vault = &fixture.vault;
    let mut sink = RecordingSink::default();

    enroll(vault, fixture.member)?;
    put_claim(
        vault,
        EVIDENCE_SEED,
        PREDICATE_CRM_COMPLIANCE_EVIDENCE,
        fixture.member,
        map(&[("legal_form", Value::from("corporate"))]),
    )?;

    // The sending identity has no compliance footer configured, so the
    // mandatory message elements are not established and the send is refused.
    let unconfigured = dispatch(
        vault,
        "intent:no-elements",
        EMAIL,
        COUNTERPARTY,
        test_id(EMAIL_IDENTITY_SEED),
        &mut sink,
    );
    assert_eq!(unconfigured.gate_outcome, "deny");
    assert!(blocked_by_compliance(&unconfigured));

    configure_message_elements(vault, EMAIL_ELEMENTS_SEED, test_id(EMAIL_IDENTITY_SEED))?;
    let configured = dispatch(
        vault,
        "intent:elements",
        EMAIL,
        COUNTERPARTY,
        test_id(EMAIL_IDENTITY_SEED),
        &mut sink,
    );
    assert!(cleared_compliance(&configured));
    assert_eq!(
        sink.calls, 0,
        "nothing reaches the transport on this fixture"
    );
    Ok(())
}

#[test]
fn campaign_compliance_gate_oracle_jurisdiction_rows_are_channel_local() -> Result<()> {
    let (_dir, fixture) = oracle_vault();
    let vault = &fixture.vault;
    let mut sink = RecordingSink::default();

    enroll(vault, fixture.member)?;
    configure_message_elements(vault, EMAIL_ELEMENTS_SEED, test_id(EMAIL_IDENTITY_SEED))?;
    configure_message_elements(vault, DM_ELEMENTS_SEED, test_id(DM_IDENTITY_SEED))?;
    put_claim(
        vault,
        EVIDENCE_SEED,
        PREDICATE_CRM_COMPLIANCE_EVIDENCE,
        fixture.member,
        map(&[("legal_form", Value::from("corporate"))]),
    )?;

    // Record a Japanese jurisdiction. The Act's published-business-address
    // exemption governs the email lane and needs a publication-context record;
    // the platform lane sits outside the Act, so the same missing record does
    // not stop it. One global DM rule could not produce both answers.
    let mut jurisdiction = ClaimBody::new(
        "comm.jurisdiction",
        ClaimSubject::Entity(fixture.member),
        map(&[
            ("jurisdiction", Value::from("JP")),
            ("observed_at", Value::from(10u64)),
        ]),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    jurisdiction.evidence = Some(Value::from("owner attestation"));
    vault.put_claim(
        &test_id(JURISDICTION_SEED),
        &jurisdiction,
        TimeRange { start: 1, end: 1 },
        1,
    )?;

    let jp_email = dispatch(
        vault,
        "intent:jp-email",
        EMAIL,
        COUNTERPARTY,
        test_id(EMAIL_IDENTITY_SEED),
        &mut sink,
    );
    assert_eq!(jp_email.gate_outcome, "deny");
    assert!(blocked_by_compliance(&jp_email));

    let jp_dm = dispatch(
        vault,
        "intent:jp-dm",
        DM,
        COUNTERPARTY,
        test_id(DM_IDENTITY_SEED),
        &mut sink,
    );
    assert!(
        cleared_compliance(&jp_dm),
        "the platform lane is governed by its own row: {:?}",
        jp_dm.gate_reason_codes
    );

    // Hydrating the publication context — a real record proving all three
    // Art. 3(1)(iv) facts, not a bare reference — opens the email lane too.
    put_claim(
        vault,
        PUBLICATION_SEED,
        PREDICATE_CRM_COMPLIANCE_JP_PUBLICATION,
        fixture.member,
        map(&[
            ("published_by_recipient", Value::from(true)),
            ("in_course_of_business", Value::from(true)),
            ("no_marketing_statement_attached", Value::from(true)),
        ]),
    )?;
    put_claim(
        vault,
        PROVENANCE_SEED,
        PREDICATE_CRM_COMPLIANCE_LIST_PROVENANCE,
        fixture.member,
        map(&[("class", Value::from("published_business_address"))]),
    )?;
    // The evidence claim is replaced, not doubled: a retracted head leaves one
    // live evidence statement, which is what the hydrator reads.
    vault.retract_claim(&test_id(EVIDENCE_SEED), 2)?;
    put_claim(
        vault,
        FULL_EVIDENCE_SEED,
        PREDICATE_CRM_COMPLIANCE_EVIDENCE,
        fixture.member,
        map(&[
            ("legal_form", Value::from("corporate")),
            (
                "jp_publication",
                map(&[("ref", Value::from(test_id(PUBLICATION_SEED).to_hex()))]),
            ),
            (
                "list_provenance",
                map(&[
                    ("ref", Value::from(test_id(PROVENANCE_SEED).to_hex())),
                    ("class", Value::from("published_business_address")),
                ]),
            ),
        ]),
    )?;

    let jp_email_evidenced = dispatch(
        vault,
        "intent:jp-email-evidenced",
        EMAIL,
        COUNTERPARTY,
        test_id(EMAIL_IDENTITY_SEED),
        &mut sink,
    );
    assert!(
        cleared_compliance(&jp_email_evidenced),
        "hydrated publication context opens the email lane: {:?}",
        jp_email_evidenced.gate_reason_codes
    );
    assert_eq!(
        sink.calls, 0,
        "nothing reaches the transport on this fixture"
    );
    Ok(())
}

#[test]
fn campaign_compliance_seed_pack_is_readable_from_outside_the_crate() {
    // The pack is public data: a host surface can render the rows, their
    // citations, and the standing caveat without reaching into the engine.
    let pack = embedded_seed_pack().expect("seed pack parses");
    assert!(!pack.warning.trim().is_empty());
    assert!(pack.rows.len() >= 20, "the seed carries the four row sets");
    for row in &pack.rows {
        assert!(!row.source.citation.trim().is_empty());
        assert!(!row.source.url.trim().is_empty());
        assert!(row.verified_at > 0);
    }
}
