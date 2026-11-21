// The contact family's head writer is reached through `oneiron::test_doors`.
#![cfg(oneiron_test_support)]
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
/// A send connector of a recipient class other than email (outbound
/// manifests; no built-in pack on an unseeded vault).
const DISCORD: &str = "discord";
const VERB: &str = "send";
/// A class no compiled table names; only an owner stamp can enforce it.
const HOLD_CLASS: &str = "acme.legal_hold_contact";
const PENDING_OPT_OUT: &str = "gate.pending.counterparty_opt_out";
const ENFORCEMENT_HOLD_REASON: &str = "counterparty_enforcement_hold";
const OVERRIDE_REASON: &str = "comm_send_override_standing";

/// A second counterparty, held by a STOP as well as by the stamped class.
const SECOND_COUNTERPARTY: &str = "yuki@example.com";
const POLICY_SEED: u8 = 0x66;
const SECOND_CONTACT_SEED: u8 = 0x67;
const SECOND_HEAD_SEED: u8 = 0x68;

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
    put_hold_head_for(vault, COUNTERPARTY, HEAD_SEED, channel_class);
}

fn put_hold_head_for(vault: &Vault, counterparty: &str, seed: u8, channel_class: &str) {
    let person = oneiron::comm::resolve_or_create_comm_party(vault, counterparty).unwrap();
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
        .put_claim(&test_id(seed), &claim, TimeRange { start: 3, end: 3 }, 3)
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
    let (result, calls) = dispatch_to(vault, actor, COUNTERPARTY, channel, intent_ref);
    assert_eq!(calls, 0, "no send reaches the transport on this vault");
    result
}

/// One direct-pipeline send to `counterparty`, and how many sends reached
/// the transport.
fn dispatch_to(
    vault: &Vault,
    actor: EntityId,
    counterparty: &str,
    channel: &str,
    intent_ref: &str,
) -> (OutboundDispatchResult, usize) {
    let mut sink = RecordingSink::default();
    let intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new(actor.to_hex(), VERB, channel, counterparty)
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
    .counterparty_ref(counterparty);
    let result = vault.dispatch_outbound_intent(request, &mut sink).unwrap();
    (result, sink.calls)
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
    put_hold_head(&vault, DISCORD);

    let email = dispatch(&vault, actor, EMAIL, "intent:email");
    assert!(
        !held(&email),
        "a discord head does not hold an email send: {:?}",
        email.gate_reason_codes
    );
    let discord = dispatch(&vault, actor, DISCORD, "intent:discord");
    assert!(
        held(&discord),
        "the discord head holds a discord send: {:?}",
        discord.gate_reason_codes
    );
    assert!(traces(&discord, ENFORCEMENT_HOLD_REASON));
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
        traces(&result, ENFORCEMENT_HOLD_REASON),
        "the stamped class holds the send: {:?}",
        result.receipt.policy_trace
    );
    assert!(
        traces(&result, OVERRIDE_REASON),
        "the receipt names the override that decided it: {:?}",
        result.receipt.policy_trace
    );
    assert!(
        !held(&result),
        "the override answers the hold: {:?}",
        result.gate_reason_codes
    );
}

#[test]
fn a_contact_family_opt_out_alone_no_longer_holds() {
    let (_dir, vault, actor) = cutover_vault();
    let record = contact_record();
    put_contact(&vault, &record);
    // Only the contact family's own heads move: no party `comm.opt_out`.
    oneiron::test_doors::contact_family_heads::write_contact_family_heads(
        &vault,
        &test_id(CONTACT_SEED),
        &record
            .opted_out(CounterpartyOptOutReason::Unsubscribe, 2)
            .unwrap(),
        2,
    )
    .unwrap();
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
fn a_contact_created_opted_out_still_holds() {
    let (_dir, vault, actor) = cutover_vault();
    // The create door moves the party's `comm.opt_out` with the contact's.
    put_contact(
        &vault,
        &contact_record()
            .opted_out(CounterpartyOptOutReason::Unsubscribe, 2)
            .unwrap(),
    );

    let result = dispatch(&vault, actor, EMAIL, "intent:born-opted-out");
    assert_eq!(result.gate_reason_codes, vec![PENDING_OPT_OUT.to_owned()]);
    assert!(
        traces(&result, "counterparty_opt_out_unsubscribe"),
        "{:?}",
        result.receipt.policy_trace
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

/// A policy manifest that grants `actor` the send on email and sets
/// [`HOLD_CLASS`]'s posture to allow_with_receipt, as an owner's
/// deployment-local row does. The vault-wide `comm_opt_out_posture` keeps its
/// shipped default, escalate.
fn class_posture_manifest(actor: EntityId) -> Vec<u8> {
    let actor_ref = actor.to_hex();
    let manifest = serde_json::json!({
        "schema_version": "1.2",
        "pack_id": "class-posture-fixture",
        "pack_version": "v1",
        "min_engine_version": env!("CARGO_PKG_VERSION"),
        "defaults": {"criticality": "normal", "sensitivity": "normal"},
        "rules": [],
        "actor_ceilings": [
            {"actor_class": "agent", "actor_ref": actor_ref, "ceiling": "auto"}
        ],
        "scoped_grants": [{
            "actor_ref": actor_ref,
            "effector": format!("external:{VERB}"),
            "scope": oneiron::test_support::effect_preset(),
            "selectors": {"channel": EMAIL},
        }],
        "policy_values": [{
            "row_ref": "class-posture.acme-legal-hold",
            "key": format!("claim_class_posture:{HOLD_CLASS}"),
            "value": "allow_with_receipt",
            "scope": {"level": "vault"},
        }],
    });
    rmp_serde::to_vec_named(&manifest).unwrap()
}

#[test]
fn a_class_posture_row_allows_with_receipt_for_its_class_only() {
    let (_dir, vault, actor) = cutover_vault();
    put_hold_class(&vault, true);
    // The first counterparty is held by the stamped class alone.
    put_hold_head_for(&vault, COUNTERPARTY, HEAD_SEED, EMAIL);
    // The second is held by the stamped class and by a STOP.
    put_hold_head_for(&vault, SECOND_COUNTERPARTY, SECOND_HEAD_SEED, EMAIL);
    let second = CounterpartyContactRecord::user_introduction(
        test_id(IDENTITY_SEED),
        SECOND_COUNTERPARTY,
        1,
    )
    .unwrap();
    vault
        .create_counterparty_contact(&test_id(SECOND_CONTACT_SEED), &second)
        .unwrap();
    vault
        .opt_out_counterparty_contact(
            &test_id(SECOND_CONTACT_SEED),
            CounterpartyOptOutReason::Unsubscribe,
            2,
        )
        .unwrap();
    oneiron::test_support::put_policy_manifest_bytes(
        &vault,
        test_id(POLICY_SEED),
        &class_posture_manifest(actor),
    )
    .unwrap();

    let (allowed, _) = dispatch_to(&vault, actor, COUNTERPARTY, EMAIL, "intent:class-allowed");
    assert!(
        traces(&allowed, ENFORCEMENT_HOLD_REASON),
        "the class still holds the send, on the receipt: {:?}",
        allowed.receipt.policy_trace
    );
    assert!(
        !held(&allowed),
        "the class's own posture row allows it with the receipt: {:?}",
        allowed.gate_reason_codes
    );

    let (escalated, calls) = dispatch_to(
        &vault,
        actor,
        SECOND_COUNTERPARTY,
        EMAIL,
        "intent:stop-escalates",
    );
    assert_eq!(
        escalated.gate_reason_codes,
        vec![PENDING_OPT_OUT.to_owned()],
        "the STOP's class has no row, so the vault's escalate holds the send"
    );
    assert_eq!(calls, 0);
}
