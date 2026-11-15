// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
#![cfg(feature = "test-support")]
//! OPUS-PACKWAVE-W3 C09: the pack key `campaign.contact_without_recorded_objection`.
//!
//! The default, true, is today's opt-out behaviour: a 1:1 campaign send needs no recorded
//! consent, and the compliance gate's verdict is the pack's alone. With the key false the
//! campaign compliance leg holds every governed send to a PERSON whose resolved consent record
//! does not opt in on the send's channel from its sender — `ConsentEvidenceMissing` when no
//! record resolves, `MissingLawfulBasis` when one resolves but does not opt in — whatever the
//! pack allows. A send outside every campaign never enters the stage, key or no key.
//!
//! Like the oracle this file trims (`campaign_compliance_oracle.rs`), every arm drives the
//! SHIPPING path only — `Vault::dispatch_outbound_intent` — on an UNSEEDED vault, so the
//! external-effect ladder is fail-closed and a compliant dispatch lands on
//! `gate.pending.external_effect_authority`. Nothing reaches the transport in any arm.
//!
//! Red/green: on the base (the head minus `setting_keys.rs` and the overlay) the owner's set
//! fails with an unknown key, so all three tests fail at the set. That is the expected red;
//! nothing here works around it.
//!
//! Run: `cargo test --locked -p oneiron --all-features --test pack_keys_campaign_consent`
//!
//! CLOCK NOTE: the gate stamps its own trusted clock, so these arms run against
//! the real one. The seeded rows carry a verification date and the pack carries
//! an annual verification-age dial; when that window closes, the compliant arms
//! below start failing with `campaign_compliance_stale_rule`. That is the
//! designed tripwire, not a flake — a pack past re-verification must refuse to
//! send, and the fix is a data revision to `compliance/seed_v1.json`.

use oneiron::campaign::claims::PREDICATE_CAMPAIGN_MEMBER;
use oneiron::campaign::compliance::{
    PREDICATE_CRM_COMPLIANCE_CONSENT, PREDICATE_CRM_COMPLIANCE_EVIDENCE,
    PREDICATE_CRM_COMPLIANCE_MESSAGE_ELEMENTS,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::store::GateDecisionId;
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
use serde_json::json;

mod common;

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
/// The reason code the compliance stage raises: an owner-clearable hold
/// (FIX 12542, 177035af710 #4499), not a denial.
const PENDING_COMPLIANCE: &str = "gate.pending.campaign_compliance";
/// The pack key under test: false holds every governed send until its PERSON has a recorded
/// consent that opts in.
const CONTACT_WITHOUT_RECORDED_OBJECTION: &str = "campaign.contact_without_recorded_objection";
/// The receipt reason the key-off overlay records when no consent record resolves.
const CONSENT_EVIDENCE_MISSING: &str = "counterparty_compliance_consent_evidence_missing";
/// The receipt reason the key-off overlay records when a record resolves but does not opt in.
const MISSING_LAWFUL_BASIS: &str = "counterparty_compliance_missing_lawful_basis";

const ACTOR_SEED: u8 = 0xB1;
const CAMPAIGN_SEED: u8 = 0xB2;
const EMAIL_IDENTITY_SEED: u8 = 0xB3;
const DM_IDENTITY_SEED: u8 = 0xB4;
const BASIS_SEED: u8 = 0xB5;
const SENDER_SEED: u8 = 0xB6;
const MEMBERSHIP_SEED: u8 = 0xB7;
const EMAIL_ELEMENTS_SEED: u8 = 0xB8;
const EVIDENCE_SEED: u8 = 0xBA;
/// The consent record the consent-citing arms put.
const CONSENT_SEED: u8 = 0xC1;
/// The replacement evidence that cites the consent record (see `cite_consent_from_fresh_evidence`).
const CONSENTED_EVIDENCE_SEED: u8 = 0xC2;

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
    // The host installs this device's keystore after each open; the outbound
    // and claim doors load this install's keys from it (P6c).
    vault.install_device_keystore(std::sync::Arc::new(
        oneiron_keystore::MemoryKeystore::default(),
    ));
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
    let id = common::entity(seed);
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"campaign consent key fixture",
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
    )?;
    vault.put_claim(
        &common::entity(seed),
        &body,
        TimeRange { start: 1, end: 1 },
        1,
    )
}

/// Membership is the campaign scope: it is what puts a dispatch under CA-06.
fn enroll(vault: &Vault, member: EntityId) -> Result<()> {
    let channel_row = |channel: &str| {
        map(&[
            ("channel", Value::from(channel)),
            (
                "basis_evidence",
                Value::from(common::entity(BASIS_SEED).to_hex()),
            ),
            (
                "sender_ref",
                Value::from(common::entity(SENDER_SEED).to_hex()),
            ),
        ])
    };
    put_claim(
        vault,
        MEMBERSHIP_SEED,
        PREDICATE_CAMPAIGN_MEMBER,
        member,
        map(&[
            (
                "campaign",
                Value::from(common::entity(CAMPAIGN_SEED).to_hex()),
            ),
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
        OutboundIntentTrigger::agent_immediate("session:consent-key"),
    );
    let request = OutboundDispatchRequest::new(
        format!("outbound:{intent_ref}"),
        intent_ref,
        intent,
        OutboundDispatchActor::agent(common::entity(ACTOR_SEED)),
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
        .any(|code| code == PENDING_COMPLIANCE)
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

/// The vault's owner, authenticated: the key is the owner's to set.
fn owner_proof(vault: &Vault) -> AuthenticatedOwner {
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    vault
        .authenticate_owner(owner, "principal:owner", true, GateDecisionId::now())
        .unwrap()
}

/// The owner sets the pack key; the set must apply, not wait or refuse.
fn set_contact_without_recorded_objection(vault: &Vault, value: bool) -> Result<()> {
    let proof = owner_proof(vault);
    let outcome = vault.set_setting(
        SettingCaller::Owner(&proof),
        SetSetting::vault_value(CONTACT_WITHOUT_RECORDED_OBJECTION, json!(value)),
    )?;
    assert!(
        matches!(outcome, SetSettingOutcome::Applied { .. }),
        "the owner's set of {CONTACT_WITHOUT_RECORDED_OBJECTION} applies: {outcome:?}"
    );
    Ok(())
}

/// An ACTIVE `crm.compliance.consent` claim on the member PERSON, opting in (or not) on
/// `channels`, from any sender (no `sender_ref` binds it to one identity). Returns the record's
/// id for the evidence citation.
fn put_consent_record(
    vault: &Vault,
    member: EntityId,
    channels: &[&str],
    opt_in: bool,
) -> Result<EntityId> {
    let consent = common::entity(CONSENT_SEED);
    put_claim(
        vault,
        CONSENT_SEED,
        PREDICATE_CRM_COMPLIANCE_CONSENT,
        member,
        map(&[
            ("opt_in", Value::from(opt_in)),
            (
                "channels",
                Value::Array(
                    channels
                        .iter()
                        .map(|channel| Value::from(*channel))
                        .collect(),
                ),
            ),
        ]),
    )?;
    Ok(consent)
}

/// The member's legal-form evidence citing the consent record `consent`: one ACTIVE evidence
/// claim carrying both the form and the `consent`/`ref` citation.
fn put_evidence_citing_consent(
    vault: &Vault,
    seed: u8,
    member: EntityId,
    consent: EntityId,
) -> Result<()> {
    put_claim(
        vault,
        seed,
        PREDICATE_CRM_COMPLIANCE_EVIDENCE,
        member,
        map(&[
            ("legal_form", Value::from("corporate")),
            ("consent", map(&[("ref", Value::from(consent.to_hex()))])),
        ]),
    )
}

/// Replaces the legal-form-only evidence with one that also cites `consent`. The evidence reader
/// takes the sole live head — a second, disagreeing evidence claim would make the evidence
/// unreadable — so the old head is retracted and one fresh claim carries both facts.
fn cite_consent_from_fresh_evidence(
    vault: &Vault,
    member: EntityId,
    consent: EntityId,
) -> Result<()> {
    vault.retract_claim(&common::entity(EVIDENCE_SEED), 2)?;
    put_evidence_citing_consent(vault, CONSENTED_EVIDENCE_SEED, member, consent)
}

#[test]
fn a_campaign_send_needs_no_recorded_consent_by_default_and_waits_for_one_once_the_owner_turns_the_key_off()
-> Result<()> {
    let (_dir, fixture) = oracle_vault();
    let vault = &fixture.vault;
    let mut sink = RecordingSink::default();

    enroll(vault, fixture.member)?;
    configure_message_elements(
        vault,
        EMAIL_ELEMENTS_SEED,
        common::entity(EMAIL_IDENTITY_SEED),
    )?;
    put_claim(
        vault,
        EVIDENCE_SEED,
        PREDICATE_CRM_COMPLIANCE_EVIDENCE,
        fixture.member,
        map(&[("legal_form", Value::from("corporate"))]),
    )?;

    // By default (the key true) the evidenced send clears compliance: no recorded consent needed.
    let evidenced = dispatch(
        vault,
        "intent:consent-default-allow",
        EMAIL,
        COUNTERPARTY,
        common::entity(EMAIL_IDENTITY_SEED),
        &mut sink,
    );
    assert!(
        cleared_compliance(&evidenced),
        "a fully evidenced send passes to the next existing gate stage: {codes:?}",
        codes = evidenced.gate_reason_codes
    );
    assert!(
        !evidenced
            .receipt
            .policy_trace
            .contains(&PENDING_COMPLIANCE.to_owned())
    );

    // The owner turns the key off. The same dispatch shape, under a new intent id, is now held:
    // no consent record resolves, so the receipt names the missing evidence.
    set_contact_without_recorded_objection(vault, false)?;
    let held = dispatch(
        vault,
        "intent:consent-key-off-held",
        EMAIL,
        COUNTERPARTY,
        common::entity(EMAIL_IDENTITY_SEED),
        &mut sink,
    );
    assert_eq!(held.gate_outcome, "pending");
    assert!(
        blocked_by_compliance(&held),
        "with the key off, a send with no consent record is held: {codes:?}",
        codes = held.gate_reason_codes
    );
    assert!(
        held.receipt
            .policy_trace
            .contains(&CONSENT_EVIDENCE_MISSING.to_owned()),
        "the hold must name the missing consent evidence on the receipt: {trace:?}",
        trace = held.receipt.policy_trace
    );
    assert_eq!(
        sink.calls, 0,
        "a blocking verdict must prevent connector dispatch"
    );

    // A consent that opts in on email, cited from the evidence, opens the lane again.
    let consent = put_consent_record(vault, fixture.member, &["email"], true)?;
    cite_consent_from_fresh_evidence(vault, fixture.member, consent)?;
    let consented = dispatch(
        vault,
        "intent:consent-recorded-allow",
        EMAIL,
        COUNTERPARTY,
        common::entity(EMAIL_IDENTITY_SEED),
        &mut sink,
    );
    assert!(
        cleared_compliance(&consented),
        "a send with a recorded opt-in clears again: {codes:?}",
        codes = consented.gate_reason_codes
    );
    Ok(())
}

#[test]
fn a_consent_record_without_an_opt_in_holds_the_send_as_a_missing_lawful_basis() -> Result<()> {
    let (_dir, fixture) = oracle_vault();
    let vault = &fixture.vault;
    let mut sink = RecordingSink::default();

    set_contact_without_recorded_objection(vault, false)?;
    enroll(vault, fixture.member)?;
    configure_message_elements(
        vault,
        EMAIL_ELEMENTS_SEED,
        common::entity(EMAIL_IDENTITY_SEED),
    )?;

    // The record resolves — it is ACTIVE, on the member, and cited — but it does not opt in, so
    // the hold is a missing lawful basis rather than missing evidence.
    let consent = put_consent_record(vault, fixture.member, &["email"], false)?;
    put_evidence_citing_consent(vault, EVIDENCE_SEED, fixture.member, consent)?;

    let held = dispatch(
        vault,
        "intent:consent-no-opt-in-held",
        EMAIL,
        COUNTERPARTY,
        common::entity(EMAIL_IDENTITY_SEED),
        &mut sink,
    );
    assert_eq!(held.gate_outcome, "pending");
    assert!(
        blocked_by_compliance(&held),
        "with the key off, a send whose record does not opt in is held: {codes:?}",
        codes = held.gate_reason_codes
    );
    assert!(
        held.receipt
            .policy_trace
            .contains(&MISSING_LAWFUL_BASIS.to_owned()),
        "the hold must name the missing lawful basis on the receipt: {trace:?}",
        trace = held.receipt.policy_trace
    );
    assert_eq!(
        sink.calls, 0,
        "a blocking verdict must prevent connector dispatch"
    );
    Ok(())
}

#[test]
fn a_send_outside_every_campaign_is_untouched_by_the_key() -> Result<()> {
    let (_dir, fixture) = oracle_vault();
    let vault = &fixture.vault;
    let mut sink = RecordingSink::default();

    set_contact_without_recorded_objection(vault, false)?;

    // A counterparty with no campaign membership is outside CA-06 entirely: compliance never
    // runs, and the existing gate ladder decides alone — even with the key off.
    let non_member = oneiron::comm::resolve_or_create_comm_party(vault, NON_MEMBER).unwrap();
    assert_ne!(non_member, fixture.member);
    let ungoverned = dispatch(
        vault,
        "intent:non-member-key-off",
        EMAIL,
        NON_MEMBER,
        common::entity(EMAIL_IDENTITY_SEED),
        &mut sink,
    );
    assert!(
        !blocked_by_compliance(&ungoverned),
        "a non-campaign send must never enter the compliance stage: {codes:?}",
        codes = ungoverned.gate_reason_codes
    );
    assert!(
        cleared_compliance(&ungoverned),
        "an ungoverned send keeps the existing ladder's own answer: {codes:?}",
        codes = ungoverned.gate_reason_codes
    );
    Ok(())
}
