// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
//! ONE-1868 (CA-07) per-shipping-path oracle for the counterparty opt-out wall.
//!
//! The audit finding this file exists to close: the legal-class hard deny
//! `gate.deny.counterparty_opt_out` was DEAD CODE on every shipping send path,
//! because hydration only read COUNTERPARTY_CONTACT contact records when the effect already
//! carried a `channel_identity_ref` — and every shipping constructor leaves that
//! field `None`.
//!
//! So every path test here deliberately sends with NO channel identity, and
//! every one runs both the COUNTERPARTY_CONTACT arm and the `comm.do_not_contact` arm. All
//! three shipping doors are driven through their real public API:
//!
//! * `Memory::schedule_outbound` — the bridge,
//! * `Vault::dispatch_outbound_intent` — the direct pipeline,
//! * `Vault::run_connector_task_executor` — the connector task realizer.
//!
//! Two fixtures, because "not sent" is not one fact:
//!
//! * [`oracle_vault`] is unseeded, so an unsuppressed dispatch lands on
//!   `gate.pending.external_effect_authority`. The deny arm is measured against
//!   THAT — the opt-out deny must PREEMPT the fail-closed pending, exactly as
//!   the restrictive-wins law requires.
//! * [`sending_vault`] is seeded and granted, so an unsuppressed send is
//!   observed reaching the connector. The executor assertions need it: on a
//!   fail-closed vault the connector is never called either way, so
//!   `sink.calls == 0` there would be vacuously true.

use crate::common::entity as test_id;
use oneiron::campaign::claims::PREDICATE_COMM_DO_NOT_CONTACT;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeActorClass, EntityId,
    OutboundDraftInput, Result, TimeRange, Vault, VaultConfig, channel_identity::ChannelIdentity,
    channel_identity::ChannelIdentityBinding, channel_identity::ChannelIdentityShape,
    channel_identity::ChannelIdentityState, connector_key::ConnectorKeyRecord,
    counterparty_contact::CounterpartyContactRecord,
    counterparty_contact::CounterpartyOptOutReason, genui::GrantMintIntent,
    genui::GrantMintIntentScope, outbound::OutboundDeliveryWindowDecision,
    outbound::OutboundDispatchActor, outbound::OutboundDispatchGate,
    outbound::OutboundDispatchRequest, outbound::OutboundDispatchResult,
    outbound::OutboundExecutionOutcome, outbound::OutboundExecutionRequest,
    outbound::OutboundExecutionSink, outbound::OutboundIntent, outbound::OutboundIntentDraft,
    outbound::OutboundIntentTrigger,
};
use rmpv::Value;

/// The counterparty every send in this file addresses.
const COUNTERPARTY: &str = "mika@example.com";
const CHANNEL: &str = "email";
/// A second channel class, used to prove the party-channel scope does not bleed.
const OTHER_CHANNEL: &str = "telegram";
const VERB: &str = "send";
const DENY_OPT_OUT: &str = "gate.deny.counterparty_opt_out";
const PENDING_AUTHORITY: &str = "gate.pending.external_effect_authority";

const ACTOR_SEED: u8 = 0x51;
const IDENTITY_SEED: u8 = 0x52;
const CONTACT_SEED: u8 = 0x53;
const SECOND_IDENTITY_SEED: u8 = 0x54;
const SECOND_CONTACT_SEED: u8 = 0x55;
const DO_NOT_CONTACT_SEED: u8 = 0x56;
const CONNECTOR_KEY_SEED: u8 = 0x57;
const SEND_GRANT_SEED: u8 = 0x58;

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
fn oracle_vault() -> (tempfile::TempDir, Vault, EntityId) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open_unseeded_for_test(dir.path(), test_config()).unwrap();
    let actor = test_id(ACTOR_SEED);
    vault
        .put_entity(
            &actor,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"opt-out oracle actor",
        )
        .unwrap();
    (dir, vault, actor)
}

/// A vault whose sends actually REACH the transport: seeded policy plus a
/// standing `send` grant for the actor.
///
/// The unseeded fixture above cannot tell "denied" from "never got that far" on
/// the executor path, because a fail-closed pending never calls the connector
/// either. Every executor assertion is therefore measured against a control on
/// THIS vault, where an unsuppressed send is observed to hit the sink.
fn sending_vault() -> (tempfile::TempDir, Vault, EntityId) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), test_config()).unwrap();
    // The pinned first-party Eiri connector actor, constructed directly rather
    // than through `test_id`: under the seeded manifest this exact id is the one
    // with an Auto actor ceiling, so it is the only actor whose send can be
    // observed reaching the connector. A generic seed pends on
    // `gate.pending.actor_ceiling` and would make the control meaningless.
    let actor = EntityId::from_bytes([0xE1; 16]).unwrap();
    vault
        .put_entity(
            &actor,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"opt-out oracle actor",
        )
        .unwrap();
    vault
        .mint_standing_outbound_grant(
            &test_id(SEND_GRANT_SEED),
            &GrantMintIntent {
                principal_ref: actor.to_hex(),
                origin_component_id: "tasks".to_owned(),
                origin_action_id: "create".to_owned(),
                origin_receipt_ref: None,
                scope: GrantMintIntentScope::VerbClass {
                    verb_class: VERB.to_owned(),
                },
            },
            1,
        )
        .unwrap();
    (dir, vault, actor)
}

/// An ACTIVE sending identity on `channel`, bound to `actor`.
fn put_channel_identity(vault: &Vault, seed: u8, channel: &str, address: &str, actor: EntityId) {
    let identity = ChannelIdentity {
        channel: channel.to_owned(),
        address_or_handle: address.to_owned(),
        shape: ChannelIdentityShape::DedicatedAddress,
        binding: ChannelIdentityBinding::agent(actor),
        state: ChannelIdentityState::Active,
        pending_fulfillment: None,
        state_changed_at: 1,
        quarantine_until: None,
        reputation_ref: None,
        manifest_ref: None,
    };
    vault
        .create_channel_identity(&test_id(seed), &identity)
        .unwrap();
}

/// A COUNTERPARTY_CONTACT contact row for [`COUNTERPARTY`] recorded through `identity_seed`.
fn put_contact(vault: &Vault, contact_seed: u8, identity_seed: u8) {
    let record =
        CounterpartyContactRecord::user_introduction(test_id(identity_seed), COUNTERPARTY, 1)
            .unwrap();
    vault
        .create_counterparty_contact(&test_id(contact_seed), &record)
        .unwrap();
}

fn record_opt_out(vault: &Vault, contact_seed: u8, recorded_at: u64) {
    vault
        .opt_out_counterparty_contact(
            &test_id(contact_seed),
            CounterpartyOptOutReason::Unsubscribe,
            recorded_at,
        )
        .unwrap();
}

/// The standard suppressed setup: a resolvable email identity, a contact row
/// recorded through it, and a recorded opt-out.
fn recorded_opt_out(vault: &Vault, actor: EntityId) {
    put_channel_identity(vault, IDENTITY_SEED, CHANNEL, "owner@example.com", actor);
    put_contact(vault, CONTACT_SEED, IDENTITY_SEED);
    record_opt_out(vault, CONTACT_SEED, 2);
}

/// Writes a CA-01 `comm.do_not_contact` head against the comm-owned PERSON for
/// [`COUNTERPARTY`]. The predicate, value shape, and restrictive semantics are
/// CA-01's; this file only proves the gate folds them.
fn write_do_not_contact(
    vault: &Vault,
    seed: u8,
    channel: Option<&str>,
    scope: &str,
    approval: ClaimApprovalStatus,
    at: u64,
) -> Result<()> {
    let person = oneiron::comm::resolve_or_create_comm_party(vault, COUNTERPARTY).unwrap();
    let mut entries = vec![(Value::from("scope"), Value::from(scope))];
    if let Some(channel) = channel {
        entries.push((Value::from("channel"), Value::from(channel)));
    }
    let claim = ClaimBody::new(
        PREDICATE_COMM_DO_NOT_CONTACT,
        ClaimSubject::Entity(person),
        Value::Map(entries),
        1.0,
        approval,
        ClaimLifecycleStatus::Active,
    );
    vault.put_claim(&test_id(seed), &claim, TimeRange { start: at, end: at }, at)
}

/// One direct-pipeline send. `channel_identity_ref` is deliberately never set:
/// the whole point of the repair is that its absence cannot answer "no".
fn dispatch(
    vault: &Vault,
    actor: EntityId,
    channel: &str,
    intent_ref: &str,
    sink: &mut RecordingSink,
) -> OutboundDispatchResult {
    dispatch_with_identity(vault, actor, channel, intent_ref, None, sink)
}

/// The same send with a caller-pinned `channel_identity_ref`, which explicit
/// callers may set to anything they hold — including a stale or foreign-class
/// identity. Enrichment must never move the verdict either way.
fn dispatch_with_identity(
    vault: &Vault,
    actor: EntityId,
    channel: &str,
    intent_ref: &str,
    channel_identity_ref: Option<EntityId>,
    sink: &mut RecordingSink,
) -> OutboundDispatchResult {
    let intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new(actor.to_hex(), VERB, channel, COUNTERPARTY)
            .content_ref("content:opt-out-oracle"),
        OutboundIntentTrigger::agent_immediate("session:opt-out-oracle"),
    );
    let mut request = OutboundDispatchRequest::new(
        format!("outbound:{intent_ref}"),
        intent_ref,
        intent,
        OutboundDispatchActor::agent(actor),
        OutboundDispatchGate::allow_when_policy_grants(),
        1_000,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .counterparty_ref(COUNTERPARTY);
    if let Some(identity_ref) = channel_identity_ref {
        request = request.channel_identity_ref(identity_ref);
    }
    vault.dispatch_outbound_intent(request, sink).unwrap()
}

fn schedule(
    vault: &Vault,
    actor: EntityId,
    idempotency_key: &str,
) -> oneiron::memory::OutboundIntentReceipt {
    vault
        .memory(actor, EdgeActorClass::Agent)
        .schedule_outbound(&OutboundDraftInput {
            verb: VERB.to_owned(),
            channel: CHANNEL.to_owned(),
            target: COUNTERPARTY.to_owned(),
            on_behalf_of: None,
            content_ref: None,
            idempotency_key: Some(idempotency_key.to_owned()),
            dedupe_key: None,
            trigger: "agent_immediate".to_owned(),
            trigger_ref: "session:opt-out-oracle".to_owned(),
            job_ref: None,
            occurred_at: Some(1_000),
        })
        .unwrap()
}

fn denies(reason_codes: &[String]) -> bool {
    reason_codes.iter().any(|code| code == DENY_OPT_OUT)
}

// --- Shipping path 1: the facade bridge ---------------------------------------

#[test]
fn facade_bridge_recorded_opt_out_denies_send() {
    let (_dir, vault, actor) = oracle_vault();

    // Control: the bridge admits an unsuppressed schedule to the durable queue.
    let control = schedule(&vault, actor, "control");
    assert_eq!(control.outcome, "held");
    assert!(!denies(&control.gate_reason_codes));
    assert_eq!(vault.connector_send_tasks().unwrap().len(), 1);

    recorded_opt_out(&vault, actor);

    let denied = schedule(&vault, actor, "suppressed");
    assert_eq!(denied.outcome, "suppressed");
    assert_eq!(denied.gate_outcome.as_deref(), Some("deny"));
    assert!(
        denies(&denied.gate_reason_codes),
        "the bridge must raise the opt-out deny: {:?}",
        denied.gate_reason_codes
    );
    // The suppressed schedule never became executable work.
    assert_eq!(
        vault.connector_send_tasks().unwrap().len(),
        1,
        "a denied schedule must not enqueue a send task"
    );
}

#[test]
fn facade_bridge_do_not_contact_denies_send() -> Result<()> {
    let (_dir, vault, actor) = oracle_vault();
    write_do_not_contact(
        &vault,
        DO_NOT_CONTACT_SEED,
        Some(CHANNEL),
        VERB,
        ClaimApprovalStatus::Approved,
        1,
    )?;

    let denied = schedule(&vault, actor, "dnc");
    assert_eq!(denied.outcome, "suppressed");
    assert!(denies(&denied.gate_reason_codes));
    assert!(vault.connector_send_tasks().unwrap().is_empty());
    Ok(())
}

// --- Shipping path 2: the direct dispatch pipeline -----------------------------

#[test]
fn dispatch_pipeline_recorded_opt_out_denies_send() {
    let (_dir, vault, actor) = oracle_vault();
    let mut sink = RecordingSink::default();

    let control = dispatch(&vault, actor, CHANNEL, "intent:control", &mut sink);
    assert!(!denies(&control.gate_reason_codes));

    recorded_opt_out(&vault, actor);

    let denied = dispatch(&vault, actor, CHANNEL, "intent:suppressed", &mut sink);
    assert_eq!(denied.gate_outcome, "deny");
    assert_eq!(denied.gate_reason_codes, vec![DENY_OPT_OUT.to_owned()]);
    assert!(
        denied
            .receipt
            .policy_trace
            .contains(&DENY_OPT_OUT.to_owned()),
        "the denial must reach the receipt: {:?}",
        denied.receipt.policy_trace
    );
    assert_eq!(sink.calls, 0, "no suppressed send may reach the transport");
}

#[test]
fn dispatch_pipeline_do_not_contact_denies_send() -> Result<()> {
    let (_dir, vault, actor) = oracle_vault();
    let mut sink = RecordingSink::default();
    write_do_not_contact(
        &vault,
        DO_NOT_CONTACT_SEED,
        Some(CHANNEL),
        VERB,
        ClaimApprovalStatus::Approved,
        1,
    )?;

    let denied = dispatch(&vault, actor, CHANNEL, "intent:dnc", &mut sink);
    assert_eq!(denied.gate_outcome, "deny");
    assert!(denies(&denied.gate_reason_codes));
    // A do-not-contact-only deny is explainable in the receipt.
    assert!(
        denied
            .receipt
            .policy_trace
            .contains(&"counterparty_opt_out_do_not_contact".to_owned()),
        "the do-not-contact deny needs a receipt reason: {:?}",
        denied.receipt.policy_trace
    );
    assert_eq!(sink.calls, 0);
    Ok(())
}

// --- Shipping path 3: the connector task executor ------------------------------

/// The executor control: on a vault whose sends are granted, an unsuppressed
/// scheduled task really does reach the connector. Without this measurement,
/// `sink.calls == 0` below would be indistinguishable from "the send never got
/// that far".
#[test]
fn connector_task_executor_control_reaches_the_connector() {
    let (_dir, vault, actor) = sending_vault();
    let mut sink = RecordingSink::default();

    assert_eq!(schedule(&vault, actor, "executor-control").outcome, "held");
    vault.run_connector_task_executor(&mut sink, 2_000).unwrap();
    assert_eq!(sink.calls, 1, "an unsuppressed task must reach the sink");
}

#[test]
fn connector_task_executor_recorded_opt_out_denies_send() {
    let (_dir, vault, actor) = sending_vault();
    let mut sink = RecordingSink::default();

    // Schedule FIRST, so the task is already durable executable work; the
    // opt-out then arrives between admission and realization. The wall has to
    // fire at execution time, not only at schedule time.
    assert_eq!(schedule(&vault, actor, "executor").outcome, "held");
    assert_eq!(vault.connector_send_tasks().unwrap().len(), 1);

    recorded_opt_out(&vault, actor);

    vault.run_connector_task_executor(&mut sink, 2_000).unwrap();
    assert_eq!(
        sink.calls, 0,
        "the executor must not call the connector for a suppressed counterparty"
    );
}

#[test]
fn connector_task_executor_do_not_contact_denies_send() -> Result<()> {
    let (_dir, vault, actor) = sending_vault();
    let mut sink = RecordingSink::default();

    assert_eq!(schedule(&vault, actor, "executor-dnc").outcome, "held");

    // Proposed, not Approved: the seeded manifest's criticality floor pends an
    // Approved write, and a merely-proposed head is the harder case anyway —
    // restrictive-wins does not wait for approval.
    write_do_not_contact(
        &vault,
        DO_NOT_CONTACT_SEED,
        Some(CHANNEL),
        VERB,
        ClaimApprovalStatus::Proposed,
        1_500,
    )?;

    vault.run_connector_task_executor(&mut sink, 2_000).unwrap();
    assert_eq!(sink.calls, 0);
    Ok(())
}

// --- Aggregate shape ----------------------------------------------------------

#[test]
fn all_matching_type132_records_are_restrictively_folded() {
    let (_dir, vault, actor) = oracle_vault();
    let mut sink = RecordingSink::default();

    // Two sending identities on the same channel class, two contact rows for
    // the same party. Only the SECOND is opted out; a lookup that collapsed to
    // one arbitrary record would have a 50% chance of answering "no".
    put_channel_identity(&vault, IDENTITY_SEED, CHANNEL, "one@example.com", actor);
    put_channel_identity(
        &vault,
        SECOND_IDENTITY_SEED,
        CHANNEL,
        "two@example.com",
        actor,
    );
    put_contact(&vault, CONTACT_SEED, IDENTITY_SEED);
    put_contact(&vault, SECOND_CONTACT_SEED, SECOND_IDENTITY_SEED);
    record_opt_out(&vault, SECOND_CONTACT_SEED, 2);

    let denied = dispatch(&vault, actor, CHANNEL, "intent:aggregate", &mut sink);
    assert_eq!(denied.gate_outcome, "deny");
    assert!(denies(&denied.gate_reason_codes));
    assert_eq!(sink.calls, 0);
}

#[test]
fn proposed_and_stale_do_not_contact_heads_remain_restrictive() -> Result<()> {
    let (_dir, vault, actor) = oracle_vault();
    let mut sink = RecordingSink::default();

    // A head that is only PROPOSED still suppresses: restrictive-wins does not
    // wait for approval.
    write_do_not_contact(
        &vault,
        DO_NOT_CONTACT_SEED,
        Some(CHANNEL),
        VERB,
        ClaimApprovalStatus::Proposed,
        1,
    )?;
    let proposed = dispatch(&vault, actor, CHANNEL, "intent:proposed", &mut sink);
    assert_eq!(proposed.gate_outcome, "deny");
    assert!(denies(&proposed.gate_reason_codes));

    // And it keeps suppressing long after it was written: a suppression that
    // expires on its own is a suppression that leaks. Only an authorized clear
    // stamp (CA-01's retract/supersede surface) may remove it.
    let stale = dispatch(&vault, actor, CHANNEL, "intent:stale", &mut sink);
    assert_eq!(stale.gate_outcome, "deny");
    assert!(denies(&stale.gate_reason_codes));
    assert_eq!(sink.calls, 0);
    Ok(())
}

// --- Fallback completeness ----------------------------------------------------

#[test]
fn incomplete_party_channel_index_full_scans_before_no() {
    let (_dir, vault, actor) = oracle_vault();
    let mut sink = RecordingSink::default();

    // This contact's identity resolves to NO ChannelIdentity row, so its channel
    // class was underivable at write time and the party-channel index never
    // learned about it. The mandatory full scan is the only thing that can find
    // it, and an unknown class matches every queried class.
    put_contact(&vault, CONTACT_SEED, IDENTITY_SEED);
    record_opt_out(&vault, CONTACT_SEED, 2);

    let denied = dispatch(&vault, actor, CHANNEL, "intent:unindexed", &mut sink);
    assert_eq!(
        denied.gate_outcome, "deny",
        "an unindexed opted-out row must never fall through to a false no"
    );
    assert!(denies(&denied.gate_reason_codes));
    assert_eq!(sink.calls, 0);
}

#[test]
fn legacy_type132_row_is_visible_without_migration_gate() {
    let (_dir, vault, actor) = oracle_vault();
    let mut sink = RecordingSink::default();

    // Contact first, identity second: at contact-write time there was nothing to
    // index against, exactly like a row written before the index existed. No
    // migration or lazy repair runs — the class is resolved at READ time and the
    // scan finds the row anyway.
    put_contact(&vault, CONTACT_SEED, IDENTITY_SEED);
    record_opt_out(&vault, CONTACT_SEED, 2);
    put_channel_identity(&vault, IDENTITY_SEED, CHANNEL, "owner@example.com", actor);

    let denied = dispatch(&vault, actor, CHANNEL, "intent:legacy", &mut sink);
    assert_eq!(denied.gate_outcome, "deny");
    assert!(denies(&denied.gate_reason_codes));
    assert_eq!(sink.calls, 0);
}

// --- Scope + non-regression ---------------------------------------------------

#[test]
fn party_channel_scope_does_not_bleed() {
    let (_dir, vault, actor) = oracle_vault();
    let mut sink = RecordingSink::default();

    recorded_opt_out(&vault, actor);

    let same_channel = dispatch(&vault, actor, CHANNEL, "intent:email", &mut sink);
    assert!(denies(&same_channel.gate_reason_codes));

    // The opt-out was recorded through an EMAIL identity; a telegram send to the
    // same party is a different channel class and is not falsely suppressed.
    let other_channel = dispatch(&vault, actor, OTHER_CHANNEL, "intent:telegram", &mut sink);
    assert!(
        !denies(&other_channel.gate_reason_codes),
        "an email opt-out must not suppress another channel class: {:?}",
        other_channel.gate_reason_codes
    );
    assert_eq!(sink.calls, 0, "the control is still fail-closed pending");
}

#[test]
fn explicit_cross_channel_identity_never_changes_the_verdict() {
    let (_dir, vault, actor) = oracle_vault();
    let mut sink = RecordingSink::default();

    // The opt-out row was recorded through an EMAIL identity.
    recorded_opt_out(&vault, actor);

    // A caller pins that email identity onto a TELEGRAM send — stale, explicit,
    // or simply held over between transactions. Identity is enrichment, so the
    // pinned send and its identity-absent twin must land on the same verdict:
    // folding the foreign-class row would make enrichment the deny source of
    // truth and cross the channel scope the aggregate is keyed by.
    let absent = dispatch(
        &vault,
        actor,
        OTHER_CHANNEL,
        "intent:telegram-bare",
        &mut sink,
    );
    let pinned = dispatch_with_identity(
        &vault,
        actor,
        OTHER_CHANNEL,
        "intent:telegram-pinned",
        Some(test_id(IDENTITY_SEED)),
        &mut sink,
    );

    assert!(
        !denies(&pinned.gate_reason_codes),
        "an email opt-out must not suppress telegram merely because an email \
         identity rode along: {:?}",
        pinned.gate_reason_codes
    );
    assert_eq!(pinned.gate_outcome, absent.gate_outcome);
    assert_eq!(pinned.gate_reason_codes, absent.gate_reason_codes);
    assert_eq!(sink.calls, 0, "the control is still fail-closed pending");
}

#[test]
fn non_opted_out_contact_preserves_existing_gate_result() {
    let (_dir, vault, actor) = oracle_vault();
    let mut sink = RecordingSink::default();

    let before = dispatch(&vault, actor, CHANNEL, "intent:before", &mut sink);

    // A contact with no opt-out is now hydrated on every send. It must not
    // become a blanket wall: the pre-existing authority decision stands.
    put_channel_identity(&vault, IDENTITY_SEED, CHANNEL, "owner@example.com", actor);
    put_contact(&vault, CONTACT_SEED, IDENTITY_SEED);

    let after = dispatch(&vault, actor, CHANNEL, "intent:after", &mut sink);
    assert_eq!(after.gate_outcome, before.gate_outcome);
    assert_eq!(after.gate_reason_codes, before.gate_reason_codes);
    assert!(
        after
            .gate_reason_codes
            .iter()
            .any(|code| code == PENDING_AUTHORITY),
        "the control must still be the fail-closed pending: {:?}",
        after.gate_reason_codes
    );
}

// --- Leg 2: cheap identity enrichment -----------------------------------------

#[test]
fn cheap_connector_identity_is_attached_when_available() {
    let (_dir, vault, actor) = oracle_vault();
    let mut sink = RecordingSink::default();

    // No governing connector key yet: nothing to resolve from, and the send is
    // decided without an identity.
    let unbound = dispatch(&vault, actor, CHANNEL, "intent:unbound", &mut sink);
    assert!(!unbound.receipt.fields.contains_key("channel_identity_ref"));

    vault
        .register_connector_key(
            &test_id(CONNECTOR_KEY_SEED),
            ConnectorKeyRecord::active(CHANNEL, Some(actor), Vec::new(), 1),
        )
        .unwrap();
    put_channel_identity(&vault, IDENTITY_SEED, CHANNEL, "owner@example.com", actor);

    let bound = dispatch(&vault, actor, CHANNEL, "intent:bound", &mut sink);
    assert_eq!(
        bound.receipt.fields.get("channel_identity_ref"),
        Some(&test_id(IDENTITY_SEED).to_hex()),
        "the governing connector key's identity belongs on the receipt"
    );
    // Enrichment changed no verdict: both sends land on the same gate result.
    assert_eq!(bound.gate_outcome, unbound.gate_outcome);
}

#[test]
fn resolved_identity_never_becomes_the_deny_source_of_truth() {
    let (_dir, vault, actor) = oracle_vault();
    let mut sink = RecordingSink::default();

    // Identity resolution is live AND the opt-out was recorded through a
    // completely different identity that resolution would never pick. The deny
    // still fires, because `(party, channel_class)` is what decides.
    vault
        .register_connector_key(
            &test_id(CONNECTOR_KEY_SEED),
            ConnectorKeyRecord::active(CHANNEL, Some(actor), Vec::new(), 1),
        )
        .unwrap();
    put_channel_identity(&vault, IDENTITY_SEED, CHANNEL, "sender@example.com", actor);
    put_channel_identity(
        &vault,
        SECOND_IDENTITY_SEED,
        CHANNEL,
        "legacy@example.com",
        actor,
    );
    put_contact(&vault, CONTACT_SEED, SECOND_IDENTITY_SEED);
    record_opt_out(&vault, CONTACT_SEED, 2);

    let denied = dispatch(&vault, actor, CHANNEL, "intent:cross-identity", &mut sink);
    assert_eq!(denied.gate_outcome, "deny");
    assert!(denies(&denied.gate_reason_codes));
    assert_eq!(sink.calls, 0);
}
