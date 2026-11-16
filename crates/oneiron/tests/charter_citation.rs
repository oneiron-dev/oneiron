//! Census L8-64: a gate receipt that a connector charter decided cites the
//! charter stamp behind it. On main the charter wall
//! (`gate/effect/evaluate.rs`) recorded only the check that fired
//! (`charter_never_list`, `charter_drift`): the explanation named the check,
//! never the stamped charter that decided.
//!
//! Public doors only: the vault, the connector key and charter doors, the
//! dispatch pipeline and the receipt explanation. The sending fixture is the
//! opt-out oracle's (`tests/it/counterparty_opt_out_shipping_paths_oracle.rs`
//! `sending_vault`): an unseeded vault under an explicit policy that grants
//! the actor's send, so the charter wall is what refuses it.
//!
//! `cargo test --locked -p oneiron --all-features --test charter_citation`
#![cfg(feature = "test-support")]

use std::sync::Arc;

use oneiron::claim::ScopedReadActorKey;
use oneiron::connector_key::ConnectorKeyRecord;
use oneiron::genui::{GrantMintIntent, GrantMintIntentScope};
use oneiron::outbound::{
    OutboundDeliveryWindowDecision, OutboundDispatchActor, OutboundDispatchGate,
    OutboundDispatchRequest, OutboundDispatchResult, OutboundExecutionOutcome,
    OutboundExecutionRequest, OutboundExecutionSink, OutboundIntent, OutboundIntentDraft,
    OutboundIntentTrigger,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

const CHANNEL: &str = "email";
const VERB: &str = "send";
const COUNTERPARTY: &str = "owen@example.com";
/// One line the charter compiler reads as the never-list entry `email:send`.
const CHARTER_TEXT: &str = "never send on email";

const CONNECTOR_KEY_SEED: u8 = 0x64;
const SEND_GRANT_SEED: u8 = 0x65;
const POLICY_SEED: u8 = 0x66;

fn test_id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("a fixture id")
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

/// The vault's owner, authenticated: a standing outbound grant is the
/// owner's standing consent row, minted by the owner.
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

fn test_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    config
}

/// The explicit policy the vault runs under: an Auto ceiling and an
/// `external:send` grant on `email` for `actor`.
fn send_grant_manifest(actor: EntityId) -> Vec<u8> {
    let actor_ref = actor.to_hex();
    let manifest = serde_json::json!({
        "schema_version": "1.2",
        "pack_id": "charter-citation-send",
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
            "selectors": {"channel": CHANNEL},
        }],
    });
    rmp_serde::to_vec_named(&manifest).expect("a manifest body")
}

/// An unseeded vault whose policy grants the actor's send, a standing `send`
/// grant for the actor, and the actor's connector key on `email`.
fn sending_vault() -> (tempfile::TempDir, Vault, EntityId) {
    let dir = tempfile::tempdir().expect("a temp dir");
    let vault = Vault::open_unseeded_for_test(dir.path(), test_config()).expect("open the vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    // The pinned first-party connector actor: under the explicit manifest
    // this id has the Auto ceiling, so its send is not held for review.
    let actor = EntityId::from_bytes([0xE1; 16]).expect("the actor id");
    vault
        .put_entity(
            &actor,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"charter citation actor",
        )
        .expect("put the actor");
    vault
        .mint_standing_outbound_grant(
            &owner_proof(&vault),
            test_id(SEND_GRANT_SEED),
            &GrantMintIntent {
                principal_ref: actor.to_hex(),
                origin_component_id: "tasks".to_owned(),
                origin_action_id: "create".to_owned(),
                origin_receipt_ref: None,
                scope: GrantMintIntentScope::VerbClass {
                    verb_class: VERB.to_owned(),
                },
            },
        )
        .expect("mint the standing send grant");
    oneiron::test_support::put_policy_manifest_bytes(
        &vault,
        test_id(POLICY_SEED),
        &send_grant_manifest(actor),
    )
    .expect("put the policy manifest");
    vault
        .register_connector_key(
            &test_id(CONNECTOR_KEY_SEED),
            ConnectorKeyRecord::active(CHANNEL, Some(actor), Vec::new(), 1),
        )
        .expect("register the connector key");
    (dir, vault, actor)
}

fn dispatch(vault: &Vault, actor: EntityId, sink: &mut RecordingSink) -> OutboundDispatchResult {
    let intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new(actor.to_hex(), VERB, CHANNEL, COUNTERPARTY)
            .content_ref("content:charter-citation"),
        OutboundIntentTrigger::agent_immediate("session:charter-citation"),
    );
    let request = OutboundDispatchRequest::new(
        "outbound:intent:charter-citation",
        "intent:charter-citation",
        intent,
        OutboundDispatchActor::agent(actor),
        OutboundDispatchGate::allow_when_policy_grants(),
        1_000,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .counterparty_ref(COUNTERPARTY);
    vault
        .dispatch_outbound_intent(request, sink)
        .expect("the dispatch runs")
}

/// The owner stamps a charter whose never-list covers the send; the gate
/// refuses it on that charter, and the receipt's explanation names the
/// stamp that decided beside the check that fired.
#[test]
fn gate_explanation_cites_charter() {
    let (_dir, vault, actor) = sending_vault();
    let key = test_id(CONNECTOR_KEY_SEED);
    let proposed = vault
        .propose_connector_charter(&key, CHARTER_TEXT, 2)
        .expect("propose the charter");
    vault
        .approve_connector_charter(&key, proposed.text_hash, proposed.compiled_hash, "owner", 3)
        .expect("stamp the charter");
    let stamp = vault
        .get_connector_key(&key)
        .expect("read the key")
        .expect("the key exists")
        .charter
        .expect("the stamped charter")
        .approval_id;

    let mut sink = RecordingSink::default();
    let refused = dispatch(&vault, actor, &mut sink);
    assert_eq!(
        (
            refused.gate_outcome.as_str(),
            refused.gate_reason_codes.clone()
        ),
        ("deny", vec!["gate.deny.charter_never_list".to_owned()]),
        "the charter's never-list refuses the send: {refused:?}"
    );
    assert_eq!(sink.calls, 0, "a refused send never reaches the transport");
    let receipt = refused
        .gate_decision_id
        .expect("the refusal is a recorded gate decision");

    let writer = vault.scoped_read(
        ScopedReadActorKey::with_actor_class(actor.to_hex(), "agent").expect("the writer's key"),
    );
    let explained = vault
        .explain_gate_receipt(&writer, &receipt)
        .expect("explain the receipt")
        .expect("the writer reads its own receipt");
    assert_eq!(explained.outcome, "deny");
    assert!(
        explained
            .receipt_reasons
            .contains(&"charter_never_list".to_owned()),
        "the explanation names the check that fired: {:?}",
        explained.receipt_reasons
    );
    let citation = format!("charter_stamp_{}", stamp.to_hex());
    assert!(
        explained.receipt_reasons.contains(&citation),
        "the explanation names the stamped charter ({citation}): {:?}",
        explained.receipt_reasons
    );
}
