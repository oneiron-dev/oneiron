//! PLAN L3-35 PR 2 (ARCH-0082 #role-defaults and #changing; Engine ruling
//! L3-35-ROLE, Sat 14 Nov 03:02: the press-per-send floor in PR 1, then the
//! canon role column in PR 2): with no `mode` row naming `outbound_send`, an
//! agent's send checks in by its role's default, the "Outbound send" row of
//! the role table, and the Gate's decision names the role
//! (`check_in_role_<role>`).
//!
//! - An agent holding Owner on the vault's shared vault sends with no press;
//!   the decision stands on its role.
//! - A Deputy's send is `AskWhenUnsure`; the Gate has no unsure test yet, so
//!   it is held as unsure.
//! - A Member, an Admin and a Steward ask; so does an agent in a vault that
//!   is not shared, which reads the Member column.
//! - A `manual` row still holds an Owner agent's send: an explicit row beats
//!   the role's default (a guard; PR 1 holds it too).
//!
//! At PR 1's head (ed8a8009d6f8) every test but the guard fails: the floor
//! holds the Owner's send, and no decision names a role.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test send_grant_role_default`.
#![cfg(all(oneiron_test_support, feature = "test-support"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::federation::FederationGrantRole;
use oneiron::outbound::{
    OutboundDeliveryWindowDecision, OutboundDispatchActor, OutboundDispatchGate,
    OutboundDispatchRequest, OutboundDispatchResult, OutboundExecutionOutcome,
    OutboundExecutionRequest, OutboundExecutionSink, OutboundIntent, OutboundIntentDraft,
    OutboundIntentTrigger,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::test_doors::membership::stand_member_grant;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use serde_json::{Value, json};

const CHANNEL: &str = "email";
const VERB: &str = "send";
const COUNTERPARTY: &str = "noor@example.com";

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
        "pack_id": "send-grant-role-default",
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
            .content_ref("content:send-role"),
        OutboundIntentTrigger::agent_immediate("session:send-role"),
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

/// The shared vault's id in every shared test.
const SHARED: u64 = 43;

/// A `check_in` row with waits only: no row names a send mode.
fn waits_only() -> Value {
    json!({
        "version": 1,
        "rung_wait": [{"row_ref": "waits", "secs": 3600}],
    })
}

/// Shares `vault` (its Owner the creator) and stands `actor`'s membership
/// at `role`, as a founding grant or a house link's bind writes it.
fn share_with(vault: &Vault, actor: EntityId, role: FederationGrantRole) {
    vault
        .initialize_shared_vault(&owner_proof(vault), SHARED, None, &[], 1)
        .expect("share the vault");
    stand_member_grant(vault, actor, SHARED, role).expect("the agent's membership");
}

#[test]
fn an_agent_holding_owner_sends_with_no_press_when_no_row_names_the_send() {
    let (_dir, vault, actor) = vault_under(waits_only());
    share_with(&vault, actor, FederationGrantRole::Owner);
    let mut sink = RecordingSink::default();

    let sent = dispatch(&vault, actor, "intent:owner", &mut sink);

    assert_eq!(
        sent.gate_outcome, "allow",
        "the Owner's default goes: {sent:?}"
    );
    assert_eq!(sent.outcome.as_str(), "delivered_to_channel", "{sent:?}");
    assert_eq!(sink.calls, 1, "the send reaches the transport once");
    let (reasons, grant_ref) = decision_of(&vault, &sent);
    assert_eq!(
        grant_ref.as_deref(),
        Some("check_in:role:owner"),
        "the decision stands on the sender's role"
    );
    assert!(names(&reasons, "check_in_shipped_default"), "{reasons:?}");
    assert!(names(&reasons, "check_in_role_owner"), "{reasons:?}");
    assert!(names(&reasons, "check_in_go_never_ask"), "{reasons:?}");
}

#[test]
fn a_deputy_agents_send_is_held_as_unsure() {
    let (_dir, vault, actor) = vault_under(waits_only());
    share_with(&vault, actor, FederationGrantRole::Deputy);
    let mut sink = RecordingSink::default();

    let held = dispatch(&vault, actor, "intent:deputy", &mut sink);

    assert_eq!(held.gate_outcome, "pending", "{held:?}");
    assert_eq!(sink.calls, 0, "a held send never reaches the transport");
    let (reasons, grant_ref) = decision_of(&vault, &held);
    assert_eq!(grant_ref, None, "nothing covers the held send");
    assert!(names(&reasons, "check_in_role_deputy"), "{reasons:?}");
    assert!(names(&reasons, "check_in_wait_unsure"), "{reasons:?}");
}

#[test]
fn a_member_an_admin_and_a_steward_ask() {
    for (role, token) in [
        (FederationGrantRole::Member, "check_in_role_member"),
        (FederationGrantRole::Admin, "check_in_role_admin"),
        (FederationGrantRole::Steward, "check_in_role_steward"),
    ] {
        let (_dir, vault, actor) = vault_under(waits_only());
        share_with(&vault, actor, role);
        let mut sink = RecordingSink::default();

        let held = dispatch(&vault, actor, "intent:asks", &mut sink);

        assert_eq!(held.gate_outcome, "pending", "{role:?}: {held:?}");
        assert_eq!(sink.calls, 0, "{role:?}");
        let (reasons, _) = decision_of(&vault, &held);
        assert!(names(&reasons, token), "{role:?}: {reasons:?}");
        assert!(
            names(&reasons, "check_in_wait_always_ask"),
            "{role:?}: {reasons:?}"
        );
    }
}

#[test]
fn an_agent_in_a_vault_that_is_not_shared_reads_the_member_column() {
    let (_dir, vault, actor) = vault_under(waits_only());
    let mut sink = RecordingSink::default();

    let held = dispatch(&vault, actor, "intent:personal", &mut sink);

    assert_eq!(held.gate_outcome, "pending", "{held:?}");
    assert_eq!(sink.calls, 0);
    let (reasons, _) = decision_of(&vault, &held);
    assert!(names(&reasons, "check_in_role_member"), "{reasons:?}");
    assert!(names(&reasons, "check_in_wait_always_ask"), "{reasons:?}");
}

#[test]
fn a_manual_row_holds_an_owner_agents_send() {
    let (_dir, vault, actor) = vault_under(send_row("send-hold", "manual"));
    share_with(&vault, actor, FederationGrantRole::Owner);
    let mut sink = RecordingSink::default();

    let held = dispatch(&vault, actor, "intent:row", &mut sink);

    assert_eq!(
        held.gate_outcome, "pending",
        "the row beats the role: {held:?}"
    );
    assert_eq!(sink.calls, 0);
    let (reasons, grant_ref) = decision_of(&vault, &held);
    assert_eq!(grant_ref, None);
    assert!(names(&reasons, "check_in_row_send-hold"), "{reasons:?}");
    assert!(names(&reasons, "check_in_wait_always_ask"), "{reasons:?}");
    assert!(
        !reasons
            .iter()
            .any(|reason| reason.starts_with("check_in_role_")),
        "a row decided, not the role: {reasons:?}"
    );
}
