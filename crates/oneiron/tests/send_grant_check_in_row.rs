//! PLAN L3-35 PR 1 (ARCH-0046 #send-grant and #check-in-roles-20261110;
//! ARCH-0082 #modes and #composing; Engine rulings L3-35-ROLE = A and
//! L3-35-PRINCIPAL = A, Sat 14 Nov 03:02): the vault's send grant is a `mode`
//! row of the `check_in` policy row on act class `outbound_send`, and the Gate
//! reads it on each agent send.
//!
//! - `full-access` releases an agent's send that nothing else covers, with no
//!   press; the Gate's decision stands on the row and names it.
//! - `manual` holds that send; `auto` holds it too while the Gate has no
//!   unsure test.
//! - With no `mode` row, the press-per-send floor holds it, and the decision
//!   says the shipped default decided.
//! - Rung 0: a standing grant still covers its send under a `manual` row.
//! - A `mode` row with no act class, or with `ask_per` on another class, makes
//!   the manifest unreadable, and the Owner's install refuses it; the same row
//!   with its class installs. So does a row ref the decision's receipt reason
//!   (`check_in_row_<ref>`) cannot carry.
//!
//! On main every test fails: main's row decoder refuses any `mode` field, and
//! no Gate decision names `check_in`.
//!
//! `cargo test --locked -p oneiron --all-features --test send_grant_check_in_row`.
#![cfg(feature = "test-support")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::genui::{GrantMintIntent, GrantMintIntentScope};
use oneiron::outbound::{
    OutboundDeliveryWindowDecision, OutboundDispatchActor, OutboundDispatchGate,
    OutboundDispatchRequest, OutboundDispatchResult, OutboundExecutionOutcome,
    OutboundExecutionRequest, OutboundExecutionSink, OutboundIntent, OutboundIntentDraft,
    OutboundIntentTrigger,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use serde_json::{Value, json};

const CHANNEL: &str = "email";
const VERB: &str = "send";
const COUNTERPARTY: &str = "noor@example.com";

const SEND_GRANT_SEED: u8 = 0x71;
const POLICY_SEED: u8 = 0x72;

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

fn test_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    config
}

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

/// The policy every send test runs under: an Auto ceiling for `actor` and
/// the `check_in` row, and no scoped grant, so nothing but the row (or a
/// standing grant a test mints) covers the agent's send.
fn send_manifest(actor: EntityId, check_in: Value) -> Vec<u8> {
    let manifest = json!({
        "schema_version": "1.2",
        "pack_id": "send-grant-check-in-row",
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

/// A vault and the agent that sends, under [`send_manifest`] with `check_in`.
/// The actor is the one the charter and opt-out oracles send as.
fn vault_under(check_in: Value) -> (tempfile::TempDir, Vault, EntityId) {
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
        test_id(POLICY_SEED),
        &send_manifest(actor, check_in),
    )
    .expect("put the policy manifest");
    (dir, vault, actor)
}

/// A `check_in` row with one vault `mode` row on `outbound_send`.
fn send_row(row_ref: &str, mode: &str) -> Value {
    json!({
        "version": 1,
        "mode": [{"row_ref": row_ref, "act_class": "outbound_send", "mode": mode}],
    })
}

/// One agent `email/send` through the direct pipeline.
fn dispatch(
    vault: &Vault,
    actor: EntityId,
    intent_ref: &str,
    sink: &mut RecordingSink,
) -> OutboundDispatchResult {
    let intent = OutboundIntent::from_trigger(
        OutboundIntentDraft::new(actor.to_hex(), VERB, CHANNEL, COUNTERPARTY)
            .content_ref("content:send-grant"),
        OutboundIntentTrigger::agent_immediate("session:send-grant"),
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
    vault
        .dispatch_outbound_intent(request, sink)
        .expect("the dispatch runs")
}

/// The Gate decision record `result` names: its receipt reasons and the
/// grant ref it stands on.
fn decision_of(vault: &Vault, result: &OutboundDispatchResult) -> (Vec<String>, Option<String>) {
    let id = result
        .gate_decision_id
        .as_deref()
        .expect("the dispatch names its gate decision");
    let record = vault
        .gate_decisions(64)
        .expect("read the gate decisions")
        .into_iter()
        .find(|record| id.trim_start_matches("gate:") == record.decision_id.to_hex())
        .unwrap_or_else(|| panic!("the gate decision {id} is recorded"));
    (record.receipt_reasons, record.grant_ref)
}

fn names(reasons: &[String], reason: &str) -> bool {
    reasons.iter().any(|named| named == reason)
}

#[test]
fn full_access_send_row_releases_an_agent_send_with_no_press() {
    let (_dir, vault, actor) = vault_under(send_row("send-free", "full-access"));
    let mut sink = RecordingSink::default();

    let sent = dispatch(&vault, actor, "intent:free", &mut sink);

    assert_eq!(
        sent.gate_outcome, "allow",
        "the row releases the send: {sent:?}"
    );
    assert_eq!(sent.outcome.as_str(), "delivered_to_channel", "{sent:?}");
    assert_eq!(
        sink.calls, 1,
        "the released send reaches the transport once"
    );
    let (reasons, grant_ref) = decision_of(&vault, &sent);
    assert_eq!(
        grant_ref.as_deref(),
        Some("check_in:row:send-free"),
        "the decision stands on the row"
    );
    assert!(names(&reasons, "check_in_row_send-free"), "{reasons:?}");
    assert!(names(&reasons, "check_in_go_never_ask"), "{reasons:?}");
}

#[test]
fn manual_send_row_holds_the_send() {
    let (_dir, vault, actor) = vault_under(send_row("send-hold", "manual"));
    let mut sink = RecordingSink::default();

    let held = dispatch(&vault, actor, "intent:hold", &mut sink);

    assert_eq!(
        held.gate_outcome, "pending",
        "the row holds the send: {held:?}"
    );
    assert_eq!(sink.calls, 0, "a held send never reaches the transport");
    let (reasons, grant_ref) = decision_of(&vault, &held);
    assert_eq!(grant_ref, None, "nothing covers the held send");
    assert!(names(&reasons, "check_in_row_send-hold"), "{reasons:?}");
    assert!(names(&reasons, "check_in_wait_always_ask"), "{reasons:?}");
}

#[test]
fn auto_send_row_holds_the_send_while_the_gate_has_no_unsure_test() {
    let (_dir, vault, actor) = vault_under(send_row("send-unsure", "auto"));
    let mut sink = RecordingSink::default();

    let held = dispatch(&vault, actor, "intent:unsure", &mut sink);

    assert_eq!(held.gate_outcome, "pending", "{held:?}");
    assert_eq!(sink.calls, 0);
    let (reasons, _) = decision_of(&vault, &held);
    assert!(names(&reasons, "check_in_row_send-unsure"), "{reasons:?}");
    assert!(names(&reasons, "check_in_wait_unsure"), "{reasons:?}");
}

#[test]
fn no_send_row_keeps_the_press_per_send_floor() {
    // A `check_in` row with waits only: no row names a send mode.
    let (_dir, vault, actor) = vault_under(json!({
        "version": 1,
        "rung_wait": [{"row_ref": "waits", "secs": 3600}],
    }));
    let mut sink = RecordingSink::default();

    let held = dispatch(&vault, actor, "intent:floor", &mut sink);

    assert_eq!(held.gate_outcome, "pending", "{held:?}");
    assert_eq!(sink.calls, 0);
    let (reasons, _) = decision_of(&vault, &held);
    assert!(names(&reasons, "check_in_shipped_default"), "{reasons:?}");
    assert!(names(&reasons, "check_in_wait_always_ask"), "{reasons:?}");
}

#[test]
fn a_standing_grant_still_covers_its_send_under_a_manual_row() {
    let (_dir, vault, actor) = vault_under(send_row("send-hold", "manual"));
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
    let mut sink = RecordingSink::default();

    let sent = dispatch(&vault, actor, "intent:standing", &mut sink);

    assert_eq!(
        sent.gate_outcome, "allow",
        "rung 0 covers the send: {sent:?}"
    );
    assert_eq!(sink.calls, 1);
    let (reasons, grant_ref) = decision_of(&vault, &sent);
    assert!(
        grant_ref
            .as_deref()
            .is_some_and(|grant| !grant.starts_with("check_in:")),
        "the decision stands on the standing grant, not the row: {grant_ref:?}"
    );
    assert!(names(&reasons, "check_in_row_send-hold"), "{reasons:?}");
    assert!(names(&reasons, "check_in_wait_always_ask"), "{reasons:?}");
}

/// The Owner's install of a manifest whose only row beside the header is
/// `check_in`, on a vault opened as the rung-wait tests open theirs.
fn owner_install(check_in: Value) -> oneiron::error::Result<()> {
    let dir = tempfile::tempdir().expect("a temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open the vault");
    let policy = json!({
        "schema_version": "1.2",
        "pack_id": "send-grant-rows",
        "pack_version": "1.0.0",
        "min_engine_version": "0.0.0",
        "defaults": {},
        "rules": [],
        "actor_ceilings": [],
        "check_in": check_in,
    });
    vault.install_owner_policy_manifest(
        &owner_proof(&vault),
        EntityId::now(),
        rmp_serde::to_vec_named(&policy).expect("encode"),
        vault.now_recorded_at(),
    )
}

#[test]
fn a_mode_row_must_name_its_act_class() {
    assert!(
        owner_install(json!({
            "version": 1,
            "mode": [{"row_ref": "classless", "mode": "full-access"}],
        }))
        .is_err(),
        "a mode row with no act class would pass every act"
    );
    owner_install(send_row("send-free", "full-access"))
        .expect("the same row with its class installs");
}

#[test]
fn ask_per_on_another_class_makes_the_manifest_unreadable() {
    assert!(
        owner_install(json!({
            "version": 1,
            "mode": [{
                "row_ref": "spawn-batch",
                "act_class": "spawn",
                "mode": "manual",
                "ask_per": "batch",
            }],
        }))
        .is_err(),
        "ask_per is a send setting"
    );
    assert!(
        owner_install(json!({
            "version": 1,
            "mode": [{
                "row_ref": "send-free-batch",
                "act_class": "outbound_send",
                "mode": "full-access",
                "ask_per": "batch",
            }],
        }))
        .is_err(),
        "ask_per is a setting of a manual send row"
    );
    owner_install(json!({
        "version": 1,
        "mode": [{
            "row_ref": "send-batch",
            "act_class": "outbound_send",
            "mode": "manual",
            "ask_per": "batch",
        }],
    }))
    .expect("a manual send row may ask once per reviewed batch");
}

#[test]
fn a_mode_row_ref_must_fit_its_receipt_reason() {
    let row = |row_ref: &str| {
        json!({
            "version": 1,
            "mode": [{"row_ref": row_ref, "act_class": "outbound_send", "mode": "manual"}],
        })
    };
    assert!(
        owner_install(row("Send Hold")).is_err(),
        "a ref outside the receipt vocabulary would make the send's decision unrecordable"
    );
    assert!(
        owner_install(row(&"r".repeat(116))).is_err(),
        "check_in_row_ and 116 bytes overflow the 128-byte receipt reason"
    );
    owner_install(row(&"r".repeat(115))).expect("a 115-byte lowercase ref fits");
}
