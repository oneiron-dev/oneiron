//! PLAN L4-03 (ARCH-0046 #send-grant and #check-in-roles-20261110; EIRI-ARCH-0002
//! #runtime-boundary; Engine ruling L4-03-BROWSER-BATCH = A): the press a
//! browser or desktop guest's send runs under starts from the vault's send
//! grant, as the Gate's check-in of an agent's send reads it, and the
//! standing action grants then cover their classes as before.
//!
//! - A `full-access` row lifts the press on an agent's `browser.send` and
//!   `browser.publish`, and the policy names the row; a payment stays a
//!   person's press, and an account change or a destructive act keeps its
//!   press.
//! - A `manual` row keeps a press per browser send.
//! - Under a `manual` row asked per batch, a budgeted standing grant is the
//!   reviewed batch: that many sends, named by the grant.
//! - A grant naming a project covers only the sends in it (FIX 10422).
//! - With no row naming the send, the agent's role decides, as at the Gate:
//!   an agent holding Owner sends with no press; a Deputy keeps its press,
//!   since a guest has no unsure test, and so do a Member and an agent of a
//!   vault that is not shared (Engine ruling L403-NO-ROW-ROLE = A).
//! - A person's own browser sends, and a run's policy before its first call
//!   names its caller, take no check-in.
//! - A budgeted grant never puts a press back on a class the row released.
//!
//! At #8895's head (e5994888e1e4) this target does not build: there is no
//! `Vault::browser_send_policy`, no `SendPolicy::sources` or
//! `SendPolicy::source_of`, and no `oneiron_browser::SEND_CLASSES`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test browser_send_press_row`.
#![cfg(all(oneiron_test_support, feature = "test-support"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::consent::{
    ActionClass, ActionEnvelope, ActorBound, AuthenticatedOwner, BrowserSendScope, GrantBound,
};
use oneiron::federation::FederationGrantRole;
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_POLICY_MANIFEST};
use oneiron::test_doors::membership::stand_member_grant;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_browser::{
    EFFECT_ACCOUNT, EFFECT_DESTRUCTIVE, EFFECT_PAY, EFFECT_PUBLISH, EFFECT_SEND, PressMode,
    SEND_CLASSES, SendPolicy,
};
use serde_json::{Value, json};

const POLICY_SEED: u8 = 0x73;

/// The shared vault's id in every shared test.
const SHARED: u64 = 47;

fn test_id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("a fixture id")
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
            "principal:owner",
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .expect("owner proof")
}

/// The shipped `federation_grant_rows` (the precedence row and the role
/// defaults), read from a seeded vault's policy manifest: sharing a vault and
/// standing a membership resolve each grant's scope from them.
fn shipped_grant_rows() -> Value {
    let dir = tempfile::tempdir().expect("a temp dir");
    let seeded = Vault::open(dir.path(), VaultConfig::device()).expect("open a seeded vault");
    let ids = seeded
        .entities_by_type(ENTITY_TYPE_POLICY_MANIFEST)
        .expect("the seeded manifests");
    assert_eq!(ids.len(), 1, "a fresh vault has one seeded policy manifest");
    let manifest: Value = rmp_serde::from_slice(
        &seeded
            .get(&ids[0])
            .expect("read the seeded manifest")
            .expect("the seeded manifest"),
    )
    .expect("decode the seeded manifest");
    let rows = manifest["federation_grant_rows"].clone();
    assert!(rows.is_array(), "the seeded manifest's grant rows: {rows}");
    rows
}

/// The policy every test runs under: the shipped grant rows and the
/// `check_in` row.
fn press_manifest(check_in: Value) -> Vec<u8> {
    let manifest = json!({
        "schema_version": "1.2",
        "pack_id": "browser-send-press-row",
        "pack_version": "v1",
        "min_engine_version": env!("CARGO_PKG_VERSION"),
        "defaults": {"criticality": "normal", "sensitivity": "normal"},
        "rules": [],
        "actor_ceilings": [],
        "federation_grant_rows": shipped_grant_rows(),
        "check_in": check_in,
    });
    rmp_serde::to_vec_named(&manifest).expect("a manifest body")
}

/// A vault under [`press_manifest`] with `check_in`, and the agent whose
/// program drives the browser.
fn vault_under(check_in: Value) -> (tempfile::TempDir, Vault, EntityId) {
    let dir = tempfile::tempdir().expect("a temp dir");
    let vault = Vault::open_unseeded_for_test(dir.path(), test_config()).expect("open the vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let agent = EntityId::from_bytes([0xE3; 16]).expect("the agent id");
    vault
        .put_entity(
            &agent,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"browser send agent",
        )
        .expect("put the agent");
    oneiron::test_support::put_policy_manifest_bytes(
        &vault,
        test_id(POLICY_SEED),
        &press_manifest(check_in),
    )
    .expect("put the policy manifest");
    (dir, vault, agent)
}

/// A `check_in` row with one vault `mode` row on `outbound_send`.
fn send_row(row_ref: &str, mode: &str) -> Value {
    json!({
        "version": 1,
        "mode": [{"row_ref": row_ref, "act_class": "outbound_send", "mode": mode}],
    })
}

/// A `check_in` row with waits only: no row names a send mode.
fn waits_only() -> Value {
    json!({
        "version": 1,
        "rung_wait": [{"row_ref": "waits", "secs": 3600}],
    })
}

/// A project's id.
fn project(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("a project id")
}

/// The sends `actor` of `actor_class` makes from a run in `project`.
fn scope_of(
    actor: EntityId,
    actor_class: EdgeActorClass,
    project: Option<EntityId>,
) -> BrowserSendScope {
    BrowserSendScope {
        actor,
        actor_class,
        project,
        audience: None,
    }
}

/// The owner's standing action grant on `class` for `agent` in `project`,
/// as the consent card mints it, with `budget` sends when it names one.
/// Returns the press source the grant gives: `grant:<digest>`.
fn grant(
    vault: &Vault,
    agent: EntityId,
    class: &str,
    project: EntityId,
    budget: Option<u64>,
) -> String {
    let project = project.to_hex();
    let mut envelope = ActionEnvelope::new([format!("project:{project}")])
        .expect("the selectors")
        .with_target(project)
        .expect("the target");
    if let Some(budget) = budget {
        envelope = envelope.with_budget(budget);
    }
    let bound = GrantBound::action(
        ActorBound::new(agent.to_hex()).expect("the agent"),
        ActionClass::new(class).expect("the class"),
        envelope,
    )
    .expect("the bound");
    let source = format!("grant:{}", bound.digest().to_hex());
    vault
        .create_standing_grant(&owner_proof(vault), bound)
        .expect("the owner mints the grant");
    source
}

fn policy_for(vault: &Vault, scope: Option<&BrowserSendScope>) -> SendPolicy {
    vault
        .browser_send_policy(scope)
        .expect("the press policy reads")
}

/// Shares `vault` (its Owner the creator) and stands `agent`'s membership
/// at `role`.
fn share_with(vault: &Vault, agent: EntityId, role: FederationGrantRole) {
    vault
        .initialize_shared_vault(&owner_proof(vault), SHARED, None, &[], 1)
        .expect("share the vault");
    stand_member_grant(vault, agent, SHARED, role).expect("the agent's membership");
}

#[test]
fn a_full_access_send_row_lifts_the_agents_browser_send_press() {
    let (_dir, vault, agent) = vault_under(send_row("send-free", "full-access"));

    let policy = policy_for(&vault, Some(&scope_of(agent, EdgeActorClass::Agent, None)));

    for class in SEND_CLASSES {
        assert_eq!(
            policy.mode_for(class),
            PressMode::None,
            "{class}: {policy:?}"
        );
        assert_eq!(
            policy.sources.get(*class).map(String::as_str),
            Some("check_in:row:send-free"),
            "{class} names the row: {policy:?}"
        );
    }
    assert_eq!(SEND_CLASSES, &[EFFECT_SEND, EFFECT_PUBLISH]);
    assert_eq!(
        policy.source_of(Some(EFFECT_SEND), PressMode::None),
        Some("check_in:row:send-free"),
        "a send's receipt names the row"
    );
    for class in [EFFECT_PAY, EFFECT_ACCOUNT, EFFECT_DESTRUCTIVE] {
        assert_eq!(
            policy.mode_for(class),
            PressMode::PerSend,
            "{class} is no send: {policy:?}"
        );
    }
    assert!(SendPolicy::person_only(EFFECT_PAY));
}

#[test]
fn a_manual_send_row_keeps_a_press_per_browser_send() {
    let (_dir, vault, agent) = vault_under(send_row("send-asks", "manual"));

    let policy = policy_for(&vault, Some(&scope_of(agent, EdgeActorClass::Agent, None)));

    for class in SEND_CLASSES {
        assert_eq!(
            policy.mode_for(class),
            PressMode::PerSend,
            "{class}: {policy:?}"
        );
    }
    assert!(
        policy.sources.is_empty(),
        "nothing lifted a press: {policy:?}"
    );
    assert_eq!(
        policy.source_of(Some(EFFECT_SEND), PressMode::PerSend),
        None
    );
}

#[test]
fn a_budgeted_grant_is_the_reviewed_batch_under_a_manual_row() {
    let (_dir, vault, agent) = vault_under(json!({
        "version": 1,
        "mode": [{
            "row_ref": "send-batch",
            "act_class": "outbound_send",
            "mode": "manual",
            "ask_per": "batch",
        }],
    }));
    let home = project(0x51);
    let source = grant(&vault, agent, EFFECT_SEND, home, Some(3));

    let policy = policy_for(
        &vault,
        Some(&scope_of(agent, EdgeActorClass::Agent, Some(home))),
    );

    assert_eq!(
        policy.mode_for(EFFECT_SEND),
        PressMode::PerBatch,
        "{policy:?}"
    );
    assert_eq!(policy.batch.get(EFFECT_SEND), Some(&3), "{policy:?}");
    assert_eq!(
        policy.sources.get(EFFECT_SEND),
        Some(&source),
        "the batch names its grant"
    );
    assert_eq!(
        policy.source_of(Some(EFFECT_SEND), PressMode::PerBatch),
        Some(source.as_str())
    );
    assert_eq!(
        policy.mode_for(EFFECT_PUBLISH),
        PressMode::PerSend,
        "the grant names only the send class: {policy:?}"
    );
}

#[test]
fn a_scoped_grant_covers_only_the_sends_in_its_project() {
    let (_dir, vault, agent) = vault_under(waits_only());
    let home = project(0x52);
    let elsewhere = project(0x53);
    let source = grant(&vault, agent, EFFECT_SEND, home, None);

    let outside = policy_for(
        &vault,
        Some(&scope_of(agent, EdgeActorClass::Agent, Some(elsewhere))),
    );
    let inside = policy_for(
        &vault,
        Some(&scope_of(agent, EdgeActorClass::Agent, Some(home))),
    );

    assert_eq!(
        outside.mode_for(EFFECT_SEND),
        PressMode::PerSend,
        "a send in another project: {outside:?}"
    );
    assert_eq!(inside.mode_for(EFFECT_SEND), PressMode::None, "{inside:?}");
    assert_eq!(inside.sources.get(EFFECT_SEND), Some(&source));
}

#[test]
fn an_agent_holding_owner_sends_in_the_browser_with_no_press_when_no_row_names_the_send() {
    let (_dir, vault, agent) = vault_under(waits_only());
    share_with(&vault, agent, FederationGrantRole::Owner);

    let policy = policy_for(&vault, Some(&scope_of(agent, EdgeActorClass::Agent, None)));

    for class in SEND_CLASSES {
        assert_eq!(
            policy.mode_for(class),
            PressMode::None,
            "{class}: {policy:?}"
        );
        assert_eq!(
            policy.sources.get(*class).map(String::as_str),
            Some("check_in:role:owner"),
            "{class} stands on the agent's role: {policy:?}"
        );
    }
    assert_eq!(policy.mode_for(EFFECT_PAY), PressMode::PerSend);
}

#[test]
fn a_deputy_member_or_unshared_agent_keeps_its_browser_send_press_when_no_row_names_the_send() {
    for role in [
        None,
        Some(FederationGrantRole::Deputy),
        Some(FederationGrantRole::Member),
    ] {
        let (_dir, vault, agent) = vault_under(waits_only());
        if let Some(role) = role {
            share_with(&vault, agent, role);
        }

        let policy = policy_for(&vault, Some(&scope_of(agent, EdgeActorClass::Agent, None)));

        for class in SEND_CLASSES {
            assert_eq!(
                policy.mode_for(class),
                PressMode::PerSend,
                "{role:?} {class}: {policy:?}"
            );
        }
        assert!(policy.sources.is_empty(), "{role:?}: {policy:?}");
    }
}

#[test]
fn the_send_row_never_reaches_a_persons_browser_sends_or_a_run_with_no_caller() {
    let (_dir, vault, agent) = vault_under(send_row("send-free", "full-access"));

    let person = policy_for(&vault, Some(&scope_of(agent, EdgeActorClass::Human, None)));
    let no_caller = policy_for(&vault, None);

    for policy in [&person, &no_caller] {
        assert_eq!(
            policy.mode_for(EFFECT_SEND),
            PressMode::PerSend,
            "{policy:?}"
        );
        assert!(policy.sources.is_empty(), "{policy:?}");
    }
}

#[test]
fn a_budgeted_grant_never_puts_a_press_back_on_a_send_the_row_released() {
    let (_dir, vault, agent) = vault_under(send_row("send-free", "full-access"));
    let home = project(0x54);
    grant(&vault, agent, EFFECT_SEND, home, Some(2));
    let publish = grant(&vault, agent, EFFECT_PUBLISH, home, None);

    let policy = policy_for(
        &vault,
        Some(&scope_of(agent, EdgeActorClass::Agent, Some(home))),
    );

    assert_eq!(policy.mode_for(EFFECT_SEND), PressMode::None, "{policy:?}");
    assert_eq!(
        policy.sources.get(EFFECT_SEND).map(String::as_str),
        Some("check_in:row:send-free"),
        "{policy:?}"
    );
    assert_eq!(policy.batch.get(EFFECT_SEND), None, "{policy:?}");
    assert_eq!(policy.mode_for(EFFECT_PUBLISH), PressMode::None);
    assert_eq!(
        policy.sources.get(EFFECT_PUBLISH),
        Some(&publish),
        "a grant that covers the class names itself: {policy:?}"
    );
}
