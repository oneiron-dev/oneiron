// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
//! ONE-1772 (CA-01) public-surface oracle for the `comm.do_not_contact` gate leg.
//!
//! The in-crate unit tests in `src/campaign/claims/tests.rs` pin the gate
//! decision itself. This file proves the default opt-out hold through the SHIPPING
//! path only — `Vault::dispatch_outbound_intent` — using nothing but the public
//! API, so a future refactor that keeps the internal helper honest while
//! detaching it from the send pipeline still fails here.

use crate::common::entity as test_id;
use oneiron::campaign::claims::{
    CAMPAIGN_PACK_CLAIM_PREDICATES, DO_NOT_CONTACT_SCOPE_ALL, PREDICATE_COMM_DO_NOT_CONTACT,
    claim_class_descriptors, is_campaign_pack_claim_predicate,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId, Result,
    TimeRange, Vault, VaultConfig, outbound::OutboundDeliveryWindowDecision,
    outbound::OutboundDispatchActor, outbound::OutboundDispatchGate,
    outbound::OutboundDispatchOutcome, outbound::OutboundDispatchRequest,
    outbound::OutboundDispatchResult, outbound::OutboundExecutionOutcome,
    outbound::OutboundExecutionRequest, outbound::OutboundExecutionSink, outbound::OutboundIntent,
    outbound::OutboundIntentDraft, outbound::OutboundIntentTrigger,
};
use rmpv::Value;

/// The counterparty every dispatch in this file addresses.
const COUNTERPARTY: &str = "kenji@example.com";
const CHANNEL: &str = "email";
const VERB: &str = "send";
/// Default owner-decision hold for a suppressed counterparty (ONE-1752).
const PENDING_OPT_OUT: &str = "gate.pending.counterparty_opt_out";

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

/// An unseeded vault plus the comm-owned PERSON for [`COUNTERPARTY`].
///
/// Unseeded keeps the claim write door open without a policy fixture; the
/// external-effect gate is then fail-closed, so a dispatch with no suppression
/// lands on `gate.pending.external_effect_authority`. That is the control the
/// opt-out arm is measured against: the do-not-contact owner-decision hold
/// must preempt the ordinary authority pending, retaining its specific reason.
fn oracle_vault() -> (tempfile::TempDir, Vault, EntityId) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open_unseeded_for_test(dir.path(), test_config()).unwrap();
    let agent = test_id(0x73);
    vault
        .put_entity(
            &agent,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"campaign oracle actor",
        )
        .unwrap();
    let person = oneiron::comm::resolve_or_create_comm_party(&vault, COUNTERPARTY).unwrap();
    (dir, vault, person)
}

fn dispatch(vault: &Vault, intent_ref: &str, sink: &mut RecordingSink) -> OutboundDispatchResult {
    let intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new("agent-alpha", VERB, CHANNEL, COUNTERPARTY)
            .on_behalf_of("owner")
            .content_ref("content:campaign-touch"),
        OutboundIntentTrigger::agent_immediate("session:campaign-oracle"),
    );
    let request = OutboundDispatchRequest::new(
        format!("outbound:{intent_ref}"),
        intent_ref,
        intent,
        OutboundDispatchActor::agent(test_id(0x73)),
        OutboundDispatchGate::allow_when_policy_grants(),
        1_000,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .counterparty_ref(COUNTERPARTY);
    vault.dispatch_outbound_intent(request, sink).unwrap()
}

fn write_do_not_contact(
    vault: &Vault,
    id: &EntityId,
    person: EntityId,
    channel: Option<&str>,
    scope: &str,
) -> Result<()> {
    let mut entries = vec![(Value::from("scope"), Value::from(scope))];
    if let Some(channel) = channel {
        entries.push((Value::from("channel"), Value::from(channel)));
    }
    let claim = ClaimBody::new(
        PREDICATE_COMM_DO_NOT_CONTACT,
        ClaimSubject::Entity(person),
        Value::Map(entries),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    vault.put_claim(id, &claim, TimeRange { start: 1, end: 1 }, 1)
}

fn assert_opt_out_hold(result: &OutboundDispatchResult) {
    assert_eq!(result.outcome, OutboundDispatchOutcome::Held);
    assert_eq!(result.gate_outcome, "pending");
    assert_eq!(result.gate_reason_codes, vec![PENDING_OPT_OUT.to_owned()]);
    assert_eq!(result.receipt.outcome, "held");
    for reason in [PENDING_OPT_OUT, "counterparty_opt_out_do_not_contact"] {
        assert!(
            result
                .receipt
                .policy_trace
                .iter()
                .any(|code| code == reason),
            "the opt-out hold retains its receipt reason: {reason}"
        );
    }
    assert_eq!(
        result.receipt.fields.get("hold_reason").map(String::as_str),
        Some(PENDING_OPT_OUT)
    );
    assert!(!result.receipt.fields.contains_key("suppression"));
    assert!(!result.receipt.fields.contains_key("suppression_reason"));
    assert!(
        !result.receipt.fields.contains_key("intent_state"),
        "the gate hold stops before dispatch ledger admission"
    );
}

#[test]
fn do_not_contact_holds_the_shipping_send_path() -> Result<()> {
    let (_dir, vault, person) = oracle_vault();
    let mut sink = RecordingSink::default();

    // Control: no suppression, so only the ordinary authority pending fires.
    let control = dispatch(&vault, "intent:control", &mut sink);
    assert_eq!(control.gate_outcome, "pending");
    assert_eq!(
        control.gate_reason_codes,
        vec!["gate.pending.external_effect_authority".to_owned()]
    );
    assert!(
        !control
            .gate_reason_codes
            .iter()
            .any(|code| code == PENDING_OPT_OUT),
        "unsuppressed dispatch must not raise the opt-out hold: {:?}",
        control.gate_reason_codes
    );

    write_do_not_contact(&vault, &test_id(0x74), person, Some(CHANNEL), VERB)?;

    let held = dispatch(&vault, "intent:suppressed", &mut sink);
    assert_opt_out_hold(&held);
    assert_eq!(sink.calls, 0, "no held send may reach the transport");
    Ok(())
}

#[test]
fn do_not_contact_scope_and_channel_bound_the_hold() -> Result<()> {
    let (_dir, vault, person) = oracle_vault();
    let mut sink = RecordingSink::default();

    // A suppression on another channel leaves this dispatch alone.
    write_do_not_contact(&vault, &test_id(0x75), person, Some("sms"), VERB)?;
    let other_channel = dispatch(&vault, "intent:other-channel", &mut sink);
    assert!(
        !other_channel
            .gate_reason_codes
            .iter()
            .any(|code| code == PENDING_OPT_OUT)
    );
    assert_eq!(other_channel.gate_outcome, "pending");
    assert_eq!(
        other_channel.gate_reason_codes,
        vec!["gate.pending.external_effect_authority".to_owned()]
    );

    // Nor does one scoped to a verb this dispatch is not performing.
    write_do_not_contact(&vault, &test_id(0x76), person, Some(CHANNEL), "notify")?;
    let other_scope = dispatch(&vault, "intent:other-scope", &mut sink);
    assert!(
        !other_scope
            .gate_reason_codes
            .iter()
            .any(|code| code == PENDING_OPT_OUT)
    );
    assert_eq!(other_scope.gate_outcome, other_channel.gate_outcome);
    assert_eq!(
        other_scope.gate_reason_codes,
        other_channel.gate_reason_codes
    );

    // The channel-wildcard, scope-wildcard row covers everything.
    write_do_not_contact(
        &vault,
        &test_id(0x77),
        person,
        None,
        DO_NOT_CONTACT_SCOPE_ALL,
    )?;
    let held = dispatch(&vault, "intent:wildcard", &mut sink);
    assert_opt_out_hold(&held);
    assert_eq!(sink.calls, 0, "no held send may reach the transport");
    Ok(())
}

#[test]
fn campaign_pack_claim_surface_is_public_and_pure_data() {
    // The six predicates and their descriptor rows are readable from outside
    // the crate, which is what makes the interim table usable by the descriptor
    // registry when it lands.
    assert_eq!(CAMPAIGN_PACK_CLAIM_PREDICATES.len(), 6);
    for predicate in CAMPAIGN_PACK_CLAIM_PREDICATES {
        assert!(is_campaign_pack_claim_predicate(predicate));
    }
    let rows = claim_class_descriptors();
    assert_eq!(rows.len(), CAMPAIGN_PACK_CLAIM_PREDICATES.len());
    for row in &rows {
        assert!(is_campaign_pack_claim_predicate(row.predicate));
        assert!(
            matches!(row.write_class, "recorded" | "human_ruled" | "ordinary"),
            "{} has a write_class outside the allowed tokens",
            row.predicate
        );
    }
    // Exactly one enforcement-gated restrictive class: do-not-contact.
    let enforcement: Vec<&str> = rows
        .iter()
        .filter(|row| row.enforcement && row.restrictive)
        .map(|row| row.predicate)
        .collect();
    assert_eq!(enforcement, vec![PREDICATE_COMM_DO_NOT_CONTACT]);
    // Calling the table twice has no side effect: it is pure data, not a
    // registry write.
    assert_eq!(rows, claim_class_descriptors());
}
