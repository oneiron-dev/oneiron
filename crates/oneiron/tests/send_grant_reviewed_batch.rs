//! PLAN L3-35 PR 3 (ARCH-0046 #send-grant: "A send needs a press per send,
//! one press for a reviewed batch, or no press"; Engine ruling L3-35-BATCH =
//! A, Sat 14 Nov 03:02): one press for a reviewed batch, under the vault's
//! send grant.
//!
//! - Under a `manual` row with `ask_per: batch`, one Owner press approves
//!   exactly the reviewed sends: one approve-once proof per send, each the
//!   digest that send's own per-send press names (the digest its held result
//!   carries), and no other send's.
//! - Under a press per send (`manual` with no `ask_per`, or no send row at
//!   all), a batch of more than one send is refused and nothing is minted;
//!   one press still covers one send.
//! - A batch that is not exactly the reviewed sends, once each, is refused
//!   and nothing is minted.
//! - The bundle card's "Approve these sends" press of several sends answers
//!   a no-op under a press per send, and a grant-mint intent for exactly
//!   those sends under `ask_per: batch`.
//!
//! On PR 2's head this file does not build: `Vault::approve_outbound_batch`
//! and `ConsentActionDecision::NoopPerSendGrant` do not exist.
//!
//! The sends are agent `email/send`s with no sender identity, as the send-row
//! tests send them: they pin their target, so each has a per-send press
//! digest. Whether a press then releases a held send is its family's rule
//! (the mail and artifact-publish presses do), which a batch does not change.
//!
//! `cargo test --locked -p oneiron --all-features --test send_grant_reviewed_batch`.
#![cfg(feature = "test-support")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::consent::{AuthenticatedOwner, ConsentGrant, ConsentReceipt, EffectDigest};
use oneiron::genui::{
    BundleApprovalScope, BundleApproveCard, BundleSendItem, ConsentActionDecision,
    ConsentActionKind, ConsentActionRequest, ConsentActorIdentity, ConsentSurface,
    GrantMintIntentScope,
};
use oneiron::outbound::{
    OutboundDeliveryWindowDecision, OutboundDispatchActor, OutboundDispatchGate,
    OutboundDispatchRequest, OutboundExecutionOutcome, OutboundExecutionRequest,
    OutboundExecutionSink, OutboundIntent, OutboundIntentDraft, OutboundIntentTrigger,
    outbound_approve_once_digest,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use serde_json::{Value, json};

const CHANNEL: &str = "email";
const VERB: &str = "send";
const COUNTERPARTY: &str = "noor@example.com";
const OWNER_PRINCIPAL: &str = "principal:owner";

const POLICY_SEED: u8 = 0x73;

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
fn send_manifest(actor: EntityId, check_in: Value) -> Vec<u8> {
    let manifest = json!({
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
    rmp_serde::to_vec_named(&manifest).expect("a manifest body")
}

/// A vault, the agent that sends and the Owner's proof, under
/// [`send_manifest`] with `check_in`, opened as the send-row tests open
/// theirs.
fn vault_under(check_in: Value) -> (tempfile::TempDir, Vault, EntityId, AuthenticatedOwner) {
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
        &send_manifest(actor, check_in),
    )
    .expect("put the policy manifest");
    let owner = owner_proof(&vault);
    (dir, vault, actor, owner)
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

/// One agent `email/send`, as the send-row tests dispatch it.
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

/// The digest `request`'s own per-send press names.
fn press_digest(vault: &Vault, request: &OutboundDispatchRequest) -> EffectDigest {
    outbound_approve_once_digest(vault, request)
        .expect("the send prepares")
        .expect("an email send pins its target, so it has a press digest")
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

/// Whether `digest` is still unpressed: the Owner's own approve-once press on
/// it lands. A digest a batch already approved refuses as spent.
fn unpressed(vault: &Vault, owner: &AuthenticatedOwner, digest: EffectDigest) -> bool {
    vault.approve_once(owner, digest).is_ok()
}

#[test]
fn one_press_approves_exactly_the_reviewed_batch() {
    let (_dir, vault, actor, owner) = vault_under(batch_row());
    let sends = ["intent:one", "intent:two", "intent:three"].map(|named| send(actor, named));
    let mut sink = RecordingSink::default();
    let digests = sends
        .iter()
        .map(|request| {
            let held = vault
                .dispatch_outbound_intent(request.clone(), &mut sink)
                .expect("the dispatch runs");
            assert_eq!(
                held.gate_outcome, "pending",
                "the row holds the send: {held:?}"
            );
            let digest = press_digest(&vault, request);
            assert_eq!(
                held.approval_digest.as_deref(),
                Some(digest.to_hex().as_str()),
                "the held send names the digest its own press carries"
            );
            digest
        })
        .collect::<Vec<_>>();
    assert_eq!(sink.calls, 0, "a held send never reaches the transport");

    let receipts = vault
        .approve_outbound_batch(&owner, &refs(&["intent:two", "intent:one"]), &sends[..2])
        .expect("one press approves the reviewed batch");

    assert_eq!(
        receipts.iter().map(approved_digest).collect::<Vec<_>>(),
        digests[..2].to_vec(),
        "one approve-once proof per reviewed send, each its own press's digest"
    );
    for digest in &digests[..2] {
        assert!(
            !unpressed(&vault, &owner, *digest),
            "the batch spent each reviewed send's press"
        );
    }
    assert!(
        unpressed(&vault, &owner, digests[2]),
        "a send the holder did not review keeps its own press"
    );
}

#[test]
fn a_press_per_send_refuses_a_batch_and_mints_nothing() {
    let (_dir, vault, actor, owner) = vault_under(per_send_row());
    let sends = ["intent:one", "intent:two"].map(|named| send(actor, named));

    let refused =
        vault.approve_outbound_batch(&owner, &refs(&["intent:one", "intent:two"]), &sends);

    assert!(
        refused.is_err(),
        "a per-send grant takes no batch press: {refused:?}"
    );
    for request in &sends {
        assert!(
            unpressed(&vault, &owner, press_digest(&vault, request)),
            "a refused batch mints no approval"
        );
    }
}

#[test]
fn with_no_send_row_a_batch_is_refused_and_one_send_is_pressed() {
    let (_dir, vault, actor, owner) = vault_under(no_send_row());
    let sends = ["intent:one", "intent:two"].map(|named| send(actor, named));

    let refused =
        vault.approve_outbound_batch(&owner, &refs(&["intent:one", "intent:two"]), &sends);
    assert!(
        refused.is_err(),
        "the shipped defaults ask a press per send: {refused:?}"
    );

    let receipts = vault
        .approve_outbound_batch(&owner, &refs(&["intent:one"]), &sends[..1])
        .expect("one press covers one send under any grant");
    assert_eq!(
        receipts.iter().map(approved_digest).collect::<Vec<_>>(),
        vec![press_digest(&vault, &sends[0])]
    );
    assert!(
        unpressed(&vault, &owner, press_digest(&vault, &sends[1])),
        "the other send keeps its own press"
    );
}

#[test]
fn a_batch_press_must_name_exactly_the_reviewed_sends() {
    let (_dir, vault, actor, owner) = vault_under(batch_row());
    let one = send(actor, "intent:one");
    let two = send(actor, "intent:two");
    let three = send(actor, "intent:three");

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

    for request in [&one, &two, &three] {
        assert!(
            unpressed(&vault, &owner, press_digest(&vault, request)),
            "a refused batch mints no approval"
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
