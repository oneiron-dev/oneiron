// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! ARCH-0057 §3 cutover (census L6-21): the send gate asks the claims-read
//! door for registry-selected enforcement heads, plus matching override
//! heads, and the contact family's own opt-out head is retired as a source.
//!
//! Every send goes through the direct dispatch pipeline
//! (`Vault::dispatch_outbound_intent`) on an unseeded vault, as the
//! `it/counterparty_opt_out_shipping_paths_oracle.rs` fixtures do: an
//! unsuppressed send pends on `gate.pending.external_effect_authority`, and a
//! held one on `gate.pending.counterparty_opt_out`.

use oneiron::comm::{
    ClaimClassDescriptor, ClaimSubjectKind, ClaimValidatorKind, ClaimWriteClass, SendOverrideScope,
};
use oneiron::counterparty_contact::{CounterpartyContactRecord, CounterpartyOptOutReason};
use oneiron::outbound::{
    OutboundDeliveryWindowDecision, OutboundDispatchActor, OutboundDispatchGate,
    OutboundDispatchRequest, OutboundDispatchResult, OutboundExecutionOutcome,
    OutboundExecutionRequest, OutboundExecutionSink, OutboundIntent, OutboundIntentDraft,
    OutboundIntentTrigger,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeActorClass, EntityId,
    TimeRange, Vault, VaultConfig, WriteActor,
};
use rmpv::Value;

/// The counterparty every send in this file addresses.
const COUNTERPARTY: &str = "owen@example.com";
const EMAIL: &str = "email";
const SMS: &str = "sms";
const VERB: &str = "send";
/// A class no compiled table names; only an owner stamp can enforce it.
const HOLD_CLASS: &str = "acme.legal_hold_contact";
const PENDING_OPT_OUT: &str = "gate.pending.counterparty_opt_out";
const ENFORCEMENT_HOLD_REASON: &str = "counterparty_enforcement_hold";
const OVERRIDE_REASON: &str = "comm_send_override_standing";

const ACTOR_SEED: u8 = 0x61;
const OWNER_SEED: u8 = 0x62;
const CONTACT_SEED: u8 = 0x63;
const IDENTITY_SEED: u8 = 0x64;
const HEAD_SEED: u8 = 0x65;

fn test_id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).unwrap()
}

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

/// An unseeded vault plus the sending actor.
fn cutover_vault() -> (tempfile::TempDir, Vault, EntityId) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open_unseeded_for_test(dir.path(), test_config()).unwrap();
    vault.install_device_keystore(std::sync::Arc::new(
        oneiron_keystore::MemoryKeystore::default(),
    ));
    let actor = test_id(ACTOR_SEED);
    vault
        .put_entity(
            &actor,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"cutover sender",
        )
        .unwrap();
    (dir, vault, actor)
}

/// The vault's owner, authenticated: the descriptor door's approve-once is
/// the owner's human stamp.
fn owner_proof(vault: &Vault) -> oneiron::consent::AuthenticatedOwner {
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the vault's owner");
    vault
        .authenticate_owner(
            owner,
            "principal:owner",
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .expect("owner proof")
}

/// The owner's descriptor for [`HOLD_CLASS`]: restrictive, generic, a
/// PERSON-or-any entity subject, and a value naming its channel class.
/// `enforcement` true is stamped by the door's approve-once.
fn put_hold_class(vault: &Vault, enforcement: bool) {
    let descriptor = ClaimClassDescriptor {
        predicate: HOLD_CLASS.to_owned(),
        write_class: ClaimWriteClass::Ordinary,
        enforcement,
        restrictive: true,
        projector_only: false,
        enforcement_stamp: None,
        validator_kind: ClaimValidatorKind::Generic,
        subject_kind: ClaimSubjectKind::Entity,
        schema: Some(serde_json::json!({
            "type": "object",
            "properties": {"channel_class": {"type": "string"}},
            "required": ["channel_class"],
        })),
    };
    vault
        .put_claim_class_descriptor(&owner_proof(vault), &descriptor, 2)
        .expect("the owner puts the class's descriptor");
}

/// One live [`HOLD_CLASS`] head on the counterparty's PERSON, naming
/// `channel_class`.
fn put_hold_head(vault: &Vault, channel_class: &str) {
    let person = oneiron::comm::resolve_or_create_comm_party(vault, COUNTERPARTY).unwrap();
    let claim = ClaimBody::new(
        HOLD_CLASS,
        ClaimSubject::Entity(person),
        Value::Map(vec![(
            Value::from("channel_class"),
            Value::from(channel_class),
        )]),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )
    .unwrap();
    vault
        .put_claim(
            &test_id(HEAD_SEED),
            &claim,
            TimeRange { start: 3, end: 3 },
            3,
        )
        .expect("the class's head lands");
}

/// A contact for [`COUNTERPARTY`] whose sending identity resolves to no
/// ChannelIdentity row, so its class is UNKNOWN and matches every send.
fn contact_record() -> CounterpartyContactRecord {
    CounterpartyContactRecord::user_introduction(test_id(IDENTITY_SEED), COUNTERPARTY, 1).unwrap()
}

fn put_contact(vault: &Vault, record: &CounterpartyContactRecord) {
    vault
        .create_counterparty_contact(&test_id(CONTACT_SEED), record)
        .unwrap();
}

/// One direct-pipeline send on `channel`.
fn dispatch(
    vault: &Vault,
    actor: EntityId,
    channel: &str,
    intent_ref: &str,
) -> OutboundDispatchResult {
    let mut sink = RecordingSink::default();
    let intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new(actor.to_hex(), VERB, channel, COUNTERPARTY)
            .content_ref("content:cutover"),
        OutboundIntentTrigger::agent_immediate("session:cutover"),
    );
    let request = OutboundDispatchRequest::new(
        format!("outbound:{intent_ref}"),
        intent_ref,
        intent,
        OutboundDispatchActor::agent(actor),
        OutboundDispatchGate::allow_when_policy_grants(),
        1_000,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .counterparty_ref(COUNTERPARTY);
    let result = vault.dispatch_outbound_intent(request, &mut sink).unwrap();
    assert_eq!(sink.calls, 0, "no send reaches the transport on this vault");
    result
}

/// Whether the opt-out hold fired.
fn held(result: &OutboundDispatchResult) -> bool {
    result
        .gate_reason_codes
        .iter()
        .any(|code| code == PENDING_OPT_OUT)
}

fn traces(result: &OutboundDispatchResult, reason: &str) -> bool {
    result
        .receipt
        .policy_trace
        .iter()
        .any(|code| code == reason)
}

#[test]
fn a_stamped_enforcement_class_holds_a_send_to_its_party() {
    let (_dir, vault, actor) = cutover_vault();
    let control = dispatch(&vault, actor, EMAIL, "intent:control");
    assert!(!held(&control), "{:?}", control.gate_reason_codes);

    put_hold_class(&vault, true);
    put_hold_head(&vault, EMAIL);

    let result = dispatch(&vault, actor, EMAIL, "intent:held");
    assert_eq!(result.gate_outcome, "pending");
    assert_eq!(
        result.gate_reason_codes,
        vec![PENDING_OPT_OUT.to_owned()],
        "the owner-stamped class holds the send"
    );
    assert!(
        traces(&result, ENFORCEMENT_HOLD_REASON),
        "the hold names its source: {:?}",
        result.receipt.policy_trace
    );
}

#[test]
fn an_unstamped_class_does_not_hold() {
    let (_dir, vault, actor) = cutover_vault();
    put_hold_class(&vault, false);
    put_hold_head(&vault, EMAIL);

    let result = dispatch(&vault, actor, EMAIL, "intent:unstamped");
    assert!(
        !held(&result),
        "a class nobody stamped is not consulted: {:?}",
        result.gate_reason_codes
    );
    assert!(!traces(&result, ENFORCEMENT_HOLD_REASON));
}

#[test]
fn a_stamped_class_head_holds_only_its_own_channel_class() {
    let (_dir, vault, actor) = cutover_vault();
    put_hold_class(&vault, true);
    put_hold_head(&vault, SMS);

    let email = dispatch(&vault, actor, EMAIL, "intent:email");
    assert!(
        !held(&email),
        "an sms head does not hold an email send: {:?}",
        email.gate_reason_codes
    );
    let sms = dispatch(&vault, actor, SMS, "intent:sms");
    assert!(
        held(&sms),
        "the sms head holds an sms send: {:?}",
        sms.gate_reason_codes
    );
    assert!(traces(&sms, ENFORCEMENT_HOLD_REASON));
}

#[test]
fn a_send_override_lifts_a_stamped_class_hold() {
    let (_dir, vault, actor) = cutover_vault();
    put_hold_class(&vault, true);
    put_hold_head(&vault, EMAIL);

    let owner = test_id(OWNER_SEED);
    vault
        .put_entity(
            &owner,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"owner",
        )
        .unwrap();
    oneiron::mint_send_override(
        &vault,
        COUNTERPARTY,
        Some(EMAIL),
        SendOverrideScope::Standing,
        None,
        WriteActor::new(owner, EdgeActorClass::Human),
        4,
        None,
    )
    .expect("the owner may rule on a send override");

    let result = dispatch(&vault, actor, EMAIL, "intent:overridden");
    assert!(
        !held(&result),
        "the override answers the hold: {:?}",
        result.gate_reason_codes
    );
    assert!(
        traces(&result, OVERRIDE_REASON),
        "the receipt names the override that decided it: {:?}",
        result.receipt.policy_trace
    );
    assert!(traces(&result, ENFORCEMENT_HOLD_REASON));
}

#[test]
fn a_contact_family_opt_out_alone_no_longer_holds() {
    let (_dir, vault, actor) = cutover_vault();
    // The contact door accepts a record that already carries an opt-out and
    // writes only the contact family's heads: no party `comm.opt_out` twin.
    let record = contact_record()
        .opted_out(CounterpartyOptOutReason::Unsubscribe, 2)
        .unwrap();
    put_contact(&vault, &record);
    assert!(
        vault
            .get_counterparty_contact(&test_id(CONTACT_SEED))
            .unwrap()
            .expect("contact")
            .is_opted_out(),
        "the contact family's own head says opted out"
    );

    let result = dispatch(&vault, actor, EMAIL, "intent:retired");
    assert!(
        !held(&result),
        "COUNTERPARTY_CONTACT is no second authority: {:?}",
        result.gate_reason_codes
    );
}

#[test]
fn a_counterparty_stop_still_holds() {
    let (_dir, vault, actor) = cutover_vault();
    put_contact(&vault, &contact_record());
    vault
        .opt_out_counterparty_contact(
            &test_id(CONTACT_SEED),
            CounterpartyOptOutReason::Unsubscribe,
            2,
        )
        .unwrap();

    let result = dispatch(&vault, actor, EMAIL, "intent:stopped");
    assert_eq!(result.gate_reason_codes, vec![PENDING_OPT_OUT.to_owned()]);
    assert!(
        traces(&result, "counterparty_opt_out_unsubscribe"),
        "{:?}",
        result.receipt.policy_trace
    );
}

#[test]
fn a_revoked_contact_still_holds() {
    let (_dir, vault, actor) = cutover_vault();
    put_contact(&vault, &contact_record());
    vault
        .revoke_counterparty_contact(&test_id(CONTACT_SEED), 2)
        .unwrap();

    let result = dispatch(&vault, actor, EMAIL, "intent:revoked");
    assert_eq!(result.gate_reason_codes, vec![PENDING_OPT_OUT.to_owned()]);
    assert!(
        traces(&result, "counterparty_contact_revoked"),
        "{:?}",
        result.receipt.policy_trace
    );
}
