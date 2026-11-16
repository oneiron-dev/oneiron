//! PLAN L3-35 PR 3 (ARCH-0046 #send-grant: "A send needs a press per send,
//! one press for a reviewed batch, or no press"; Engine rulings L3-35-BATCH =
//! A, Sat 14 Nov 03:02, and L335-BATCH-REACH = A, Mon 16 Nov 12:11): one
//! press for a reviewed batch, under the vault's send grant.
//!
//! The batch tests send in a family whose single press releases a send
//! today: an agent's native-mail cold sends, which the vault's default mail
//! row holds for the Owner's press, set up as the native-mail adapter's own
//! once-press test sets them up (channel_identity_provider/native_mail/tests.rs:
//! an Active self-held `mail-<id>@` sender bound to the agent, the default
//! mail row and the self-held sender posture).
//!
//! - Under a `manual` row with `ask_per: batch`, one Owner press releases
//!   exactly the reviewed sends: each is delivered once and replays after,
//!   and a send outside the batch stays held.
//! - Under a press per send (`manual` with no `ask_per`, or no send row at
//!   all), a batch of more than one send is refused and nothing is minted;
//!   one press still releases one send.
//! - A batch that is not exactly the reviewed sends, once each, is refused
//!   and nothing is minted.
//! - A send whose family pins its target takes the digest its held result
//!   names (an agent `email/send` with no sender identity).
//! - The bundle card's "Approve these sends" press of several sends answers
//!   a no-op under a press per send, and a grant-mint intent for exactly
//!   those sends under `ask_per: batch`.
//!
//! On PR 2's head this file does not build: `Vault::approve_outbound_batch`
//! and `ConsentActionDecision::NoopPerSendGrant` do not exist.
//!
//! `cargo test --locked -p oneiron --all-features --test send_grant_reviewed_batch`.
#![cfg(feature = "test-support")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::channel_identity::{
    ChannelIdentity, ChannelIdentityBinding, ChannelIdentityFulfillment, ChannelIdentityStep,
    SelfHeldShape,
};
use oneiron::consent::{AuthenticatedOwner, ConsentGrant, ConsentReceipt, EffectDigest};
use oneiron::genui::{
    BundleApprovalScope, BundleApproveCard, BundleSendItem, ConsentActionDecision,
    ConsentActionKind, ConsentActionRequest, ConsentActorIdentity, ConsentSurface,
    GrantMintIntentScope,
};
use oneiron::outbound::{
    OutboundDeliveryWindowDecision, OutboundDispatchActor, OutboundDispatchGate,
    OutboundDispatchRequest, OutboundDispatchResult, OutboundExecutionOutcome,
    OutboundExecutionRequest, OutboundExecutionSink, OutboundIntent, OutboundIntentDraft,
    OutboundIntentTrigger, outbound_approve_once_digest,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use serde_json::{Value, json};

const CHANNEL: &str = "email";
const VERB: &str = "send";
const COUNTERPARTY: &str = "noor@example.com";
const OWNER_PRINCIPAL: &str = "principal:owner";
const NATIVE_MAIL_DOMAIN: &str = "mail.example.test";

const POLICY_SEED: u8 = 0x73;
const SENDER_SEED: u8 = 0xD7;

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

fn owner_proof(vault: &Vault) -> AuthenticatedOwner {
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the vault's owner");
    vault
        .authenticate_owner(
            owner,
            OWNER_PRINCIPAL,
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .expect("owner proof")
}

/// The policy every test runs under: an Auto ceiling for `actor` and the
/// `check_in` row, and no scoped grant, so nothing covers the agent's send.
/// With `native_mail`, also what a native-mail send needs, as the
/// native-mail once-press test installs it: the vault's default mail row (a
/// recipient with no introduction is cold, and a cold send holds for the
/// press) and the self-held sender posture (ONE-1970: silence about it
/// denies the send).
fn send_manifest(actor: EntityId, check_in: Value, native_mail: bool) -> Vec<u8> {
    let mut manifest = json!({
        "schema_version": "1.2",
        "pack_id": "send-grant-reviewed-batch",
        "pack_version": "v1",
        "min_engine_version": env!("CARGO_PKG_VERSION"),
        "defaults": {"criticality": "normal", "sensitivity": "normal"},
        "rules": [],
        "actor_ceilings": [
            {"actor_class": "agent", "actor_ref": actor.to_hex(), "ceiling": "auto"}
        ],
        "check_in": check_in,
    });
    if native_mail {
        manifest["native_mail_policy"] = json!([{
            "scope": "vault",
            "holder": null,
            "identity": null,
            "known_first_touch": ["user_introduction", "inbound_first"],
            "cold_posture": "hold_to_proposal",
            "max_complaint_rate": 0.002,
            "max_bounce_rate": 0.02,
            "max_spam_labels": 0,
            "allowed_attestation": ["a", "b"],
            "allowed_warmup": ["established"],
            "precedence": "nested_narrowing_holder_capped_at_vault",
        }]);
        manifest["scoped_grants"] = json!([]);
        manifest["act_policy"] = json!([{
            "act_class": "channel_identity.outbound_send",
            "subject_class": "self_held",
            "posture": "require_capability",
        }]);
    }
    rmp_serde::to_vec_named(&manifest).expect("a manifest body")
}

/// A vault, the agent that sends and the Owner's proof, under
/// [`send_manifest`] with `check_in`, opened as the send-row tests open
/// theirs.
fn open_vault(
    check_in: Value,
    native_mail: bool,
) -> (tempfile::TempDir, Vault, EntityId, AuthenticatedOwner) {
    let dir = tempfile::tempdir().expect("a temp dir");
    let vault = Vault::open_unseeded_for_test(dir.path(), test_config()).expect("open the vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let actor = EntityId::from_bytes([0xE1; 16]).expect("the actor id");
    vault
        .put_entity(
            &actor,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"send grant actor",
        )
        .expect("put the actor");
    oneiron::test_support::put_policy_manifest_bytes(
        &vault,
        EntityId::from_bytes([POLICY_SEED; 16]).expect("the manifest id"),
        &send_manifest(actor, check_in, native_mail),
    )
    .expect("put the policy manifest");
    let owner = owner_proof(&vault);
    (dir, vault, actor, owner)
}

/// [`open_vault`] for sends with no sender identity.
fn vault_under(check_in: Value) -> (tempfile::TempDir, Vault, EntityId, AuthenticatedOwner) {
    open_vault(check_in, false)
}

/// [`open_vault`] with the mail policy, and the agent's Active native-mail
/// sender (a self-held `mail-<id>@` address, bound to the agent).
fn native_vault_under(
    check_in: Value,
) -> (
    tempfile::TempDir,
    Vault,
    EntityId,
    AuthenticatedOwner,
    EntityId,
) {
    let (dir, vault, actor, owner) = open_vault(check_in, true);
    let sender = EntityId::from_bytes([SENDER_SEED; 16]).expect("the sender id");
    let row = ChannelIdentity::requested(
        CHANNEL,
        format!("mail-{}@{NATIVE_MAIL_DOMAIN}", sender.to_hex()),
        SelfHeldShape::DedicatedAddress,
        ChannelIdentityBinding::agent(actor),
        1,
    )
    .step(
        ChannelIdentityStep::Bind(ChannelIdentityFulfillment::Api),
        1,
    )
    .expect("bind the sender")
    .step(ChannelIdentityStep::Fulfill, 1)
    .expect("fulfil the sender");
    vault
        .create_channel_identity(&sender, &row)
        .expect("create the native-mail sender");
    (dir, vault, actor, owner, sender)
}

/// The send grant at one press for a reviewed batch.
fn batch_row() -> Value {
    json!({
        "version": 1,
        "mode": [{
            "row_ref": "send-batch",
            "act_class": "outbound_send",
            "mode": "manual",
            "ask_per": "batch",
        }],
    })
}

/// The send grant at a press per send (`ask_per` absent reads `send`).
fn per_send_row() -> Value {
    json!({
        "version": 1,
        "mode": [{"row_ref": "send-press", "act_class": "outbound_send", "mode": "manual"}],
    })
}

/// A `check_in` row with waits only: no row names a send mode, so the
/// shipped defaults decide.
fn no_send_row() -> Value {
    json!({
        "version": 1,
        "rung_wait": [{"row_ref": "waits", "secs": 3600}],
    })
}

/// One agent `email/send` with no sender identity, as the send-row tests
/// dispatch it.
fn send(actor: EntityId, intent_ref: &str) -> OutboundDispatchRequest {
    let intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new(actor.to_hex(), VERB, CHANNEL, COUNTERPARTY)
            .content_ref("content:send-grant"),
        OutboundIntentTrigger::agent_immediate("session:send-grant"),
    );
    OutboundDispatchRequest::new(
        format!("outbound:{intent_ref}"),
        intent_ref,
        intent,
        OutboundDispatchActor::agent(actor),
        OutboundDispatchGate::allow_when_policy_grants(),
        1_000,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .counterparty_ref(COUNTERPARTY)
}

/// One agent native-mail send from `sender` to `recipient`, a cold
/// recipient, as the native-mail once-press test sends it.
fn native_send(
    actor: EntityId,
    sender: EntityId,
    intent_ref: &str,
    recipient: &str,
) -> OutboundDispatchRequest {
    let intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new(actor.to_hex(), VERB, CHANNEL, recipient)
            .content_ref("draft:reviewed"),
        OutboundIntentTrigger::agent_immediate("session:send-grant"),
    );
    OutboundDispatchRequest::new(
        format!("outbound:{intent_ref}"),
        intent_ref,
        intent,
        OutboundDispatchActor::agent(actor),
        OutboundDispatchGate::allow_when_policy_grants(),
        1_000,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .channel_identity_ref(sender)
}

/// Three native-mail sends from `sender`, each to its own cold recipient.
fn three_native_sends(actor: EntityId, sender: EntityId) -> [OutboundDispatchRequest; 3] {
    [
        ("intent:one", "noor@example.org"),
        ("intent:two", "yuki@example.org"),
        ("intent:three", "owen@example.org"),
    ]
    .map(|(intent_ref, recipient)| native_send(actor, sender, intent_ref, recipient))
}

fn dispatch(
    vault: &Vault,
    request: &OutboundDispatchRequest,
    sink: &mut RecordingSink,
) -> OutboundDispatchResult {
    vault
        .dispatch_outbound_intent(request.clone(), sink)
        .expect("the dispatch runs")
}

/// Dispatches each of `requests` and asserts it is held for its press.
fn assert_held(vault: &Vault, requests: &[OutboundDispatchRequest], sink: &mut RecordingSink) {
    for request in requests {
        let held = dispatch(vault, request, sink);
        assert_eq!(
            held.outcome.as_str(),
            "held",
            "{} waits for its press: {held:?}",
            request.intent_ref
        );
    }
}

fn refs(intent_refs: &[&str]) -> Vec<String> {
    intent_refs
        .iter()
        .map(|named| (*named).to_owned())
        .collect()
}

/// The digest an approve-once receipt names.
fn approved_digest(receipt: &ConsentReceipt) -> EffectDigest {
    match receipt {
        ConsentReceipt::Approved {
            grant: ConsentGrant::ApproveOnce(digest),
            ..
        } => *digest,
        other => panic!("an approve-once receipt, not {other:?}"),
    }
}

#[test]
fn one_press_releases_exactly_the_reviewed_batch() {
    let (_dir, vault, actor, owner, sender) = native_vault_under(batch_row());
    let sends = three_native_sends(actor, sender);
    let mut sink = RecordingSink::default();
    assert_held(&vault, &sends, &mut sink);
    assert_eq!(sink.calls, 0, "a held send never reaches the transport");

    let receipts = vault
        .approve_outbound_batch(&owner, &refs(&["intent:two", "intent:one"]), &sends[..2])
        .expect("one press approves the reviewed batch");
    assert_eq!(
        receipts.len(),
        2,
        "one approve-once proof per reviewed send"
    );

    for request in &sends[..2] {
        let sent = dispatch(&vault, request, &mut sink);
        assert_eq!(
            sent.outcome.as_str(),
            "delivered_to_channel",
            "the batch press releases {}: {sent:?}",
            request.intent_ref
        );
    }
    assert_eq!(sink.calls, 2);
    assert_held(&vault, &sends[2..], &mut sink);
    let again = dispatch(&vault, &sends[0], &mut sink);
    assert_eq!(again.outcome.as_str(), "delivered_to_channel", "{again:?}");
    assert_eq!(
        sink.calls, 2,
        "a released send replays and is never sent twice"
    );
}

#[test]
fn a_per_send_row_refuses_a_batch_press() {
    let (_dir, vault, actor, owner, sender) = native_vault_under(per_send_row());
    let sends = three_native_sends(actor, sender);
    let mut sink = RecordingSink::default();
    assert_held(&vault, &sends[..2], &mut sink);

    let refused =
        vault.approve_outbound_batch(&owner, &refs(&["intent:one", "intent:two"]), &sends[..2]);
    assert!(
        refused.is_err(),
        "a per-send grant takes no batch press: {refused:?}"
    );
    assert_held(&vault, &sends[..2], &mut sink);

    vault
        .approve_outbound_batch(&owner, &refs(&["intent:one"]), &sends[..1])
        .expect("one press still releases one send");
    let sent = dispatch(&vault, &sends[0], &mut sink);
    assert_eq!(sent.outcome.as_str(), "delivered_to_channel", "{sent:?}");
    assert_held(&vault, &sends[1..2], &mut sink);
    assert_eq!(sink.calls, 1);
}

#[test]
fn with_no_send_row_a_batch_press_is_refused() {
    let (_dir, vault, actor, owner, sender) = native_vault_under(no_send_row());
    let sends = three_native_sends(actor, sender);
    let mut sink = RecordingSink::default();

    let refused =
        vault.approve_outbound_batch(&owner, &refs(&["intent:one", "intent:two"]), &sends[..2]);

    assert!(
        refused.is_err(),
        "the shipped defaults ask a press per send: {refused:?}"
    );
    assert_held(&vault, &sends[..2], &mut sink);
    assert_eq!(sink.calls, 0);
}

#[test]
fn a_batch_press_must_name_exactly_the_reviewed_sends() {
    let (_dir, vault, actor, owner, sender) = native_vault_under(batch_row());
    let [one, two, three] = three_native_sends(actor, sender);

    let other_send = vault.approve_outbound_batch(
        &owner,
        &refs(&["intent:one", "intent:two"]),
        &[one.clone(), three.clone()],
    );
    assert!(
        other_send.is_err(),
        "a send the holder did not review: {other_send:?}"
    );
    let twice = vault.approve_outbound_batch(
        &owner,
        &refs(&["intent:one", "intent:one"]),
        &[one.clone(), one.clone()],
    );
    assert!(twice.is_err(), "one send named twice: {twice:?}");
    let empty = vault.approve_outbound_batch(&owner, &[], &[]);
    assert!(empty.is_err(), "an empty batch: {empty:?}");

    let mut sink = RecordingSink::default();
    assert_held(&vault, &[one, two, three], &mut sink);
    assert_eq!(sink.calls, 0, "a refused batch mints no approval");
}

#[test]
fn a_pinned_target_send_takes_the_digest_its_held_result_names() {
    let (_dir, vault, actor, owner) = vault_under(batch_row());
    let sends = ["intent:one", "intent:two"].map(|intent_ref| send(actor, intent_ref));
    let mut sink = RecordingSink::default();
    let named = sends
        .iter()
        .map(|request| {
            let held = dispatch(&vault, request, &mut sink);
            assert_eq!(held.gate_outcome, "pending", "{held:?}");
            let digest = outbound_approve_once_digest(&vault, request)
                .expect("the send prepares")
                .expect("an email send with no sender pins its target");
            assert_eq!(
                held.approval_digest.as_deref(),
                Some(digest.to_hex().as_str()),
                "the held send names the digest its own press carries"
            );
            digest
        })
        .collect::<Vec<_>>();

    let receipts = vault
        .approve_outbound_batch(&owner, &refs(&["intent:one", "intent:two"]), &sends)
        .expect("one press approves the reviewed batch");

    assert_eq!(
        receipts.iter().map(approved_digest).collect::<Vec<_>>(),
        named,
        "each send's proof is the digest its held result names"
    );
    for digest in named {
        assert!(
            vault.approve_once(&owner, digest).is_err(),
            "the batch spent that press"
        );
    }
}

/// A bundle card of two held sends, its principal the Owner.
fn two_send_card() -> BundleApproveCard {
    BundleApproveCard::new(
        "bundle-1",
        OWNER_PRINCIPAL,
        "Send these two replies?",
        "brief:replies",
        VERB,
        vec![
            BundleSendItem::new("intent:one", COUNTERPARTY, CHANNEL, "the first reply")
                .expect("an item"),
            BundleSendItem::new("intent:two", COUNTERPARTY, CHANNEL, "the second reply")
                .expect("an item"),
        ],
        Vec::new(),
    )
    .expect("a bundle card")
}

/// The Owner's "Approve these sends" press on [`two_send_card`].
fn exact_sends_press() -> ConsentActionRequest {
    let scope = BundleApprovalScope::ExactEnumeratedSends;
    ConsentActionRequest::new(
        "bundle-1",
        format!("approve_bundle_{}", scope.as_str()),
        ConsentActionKind::BundleApprove(scope),
        ConsentActorIdentity::SurfaceActor {
            actor_ref: OWNER_PRINCIPAL.to_owned(),
        },
        ConsentSurface::CompanionConversation,
        102,
    )
    .expect("a card press")
}

#[test]
fn the_bundle_card_offers_these_exact_sends_only_under_a_batch_grant() {
    let (_per_send_dir, per_send, _, per_send_owner) = vault_under(per_send_row());
    let refused = two_send_card()
        .evaluate_action(&per_send, &exact_sends_press(), &per_send_owner)
        .expect("the card evaluates");
    assert_eq!(
        refused.decision,
        ConsentActionDecision::NoopPerSendGrant,
        "{refused:?}"
    );
    assert!(refused.grant_mint_intent.is_none());

    let (_batch_dir, batch, _, batch_owner) = vault_under(batch_row());
    let pressed = two_send_card()
        .evaluate_action(&batch, &exact_sends_press(), &batch_owner)
        .expect("the card evaluates");
    assert_eq!(
        pressed.decision,
        ConsentActionDecision::GrantMintIntent,
        "{pressed:?}"
    );
    assert_eq!(
        pressed.grant_mint_intent.map(|intent| intent.scope),
        Some(GrantMintIntentScope::BundleExactSends {
            send_refs: refs(&["intent:one", "intent:two"]),
        })
    );
}
