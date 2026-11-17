//! Restriction wave 11, PR 1: the confirm sheet's line for letting an agent
//! pay (RESTRICTION-WAVE-11-CAP-NOTE; CAP-SCOPE = B). Turning on `top_up`,
//! `pay_as_you_go` or `use_fallback` (the standing fallback, paid models
//! included; WAVE11-QUOTA-CANON) of `models.quota.agent_may_answer` states
//! the hard cap of the open roots the row's scope reaches: every open root
//! for the vault row, only the roots over that agent's open attempts for an
//! agent's row. With none in reach it states "no cap" and the provider's
//! account. The answers that spend nothing state no line.
//!
//! Read through the engine's pub `Vault::setting_loosening_note`, the line the
//! sheet shows, and through `Vault::setting_ask_as_owner`, the agent's pending
//! ask as the owner's sheet reads it: the row, the value and that line, read
//! when the owner looks. Deterministic: one in-process vault per case.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron-server --all-features --features oneiron/test-support
//! --test restriction_wave11_cap_note`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::agent_dispatch::budget_doors::OpenSpendLeaseRequest;
use oneiron::agent_dispatch::{AgentDispatchOutcome, AgentDispatcher, SpendScopeId};
use oneiron::authority::{ActSurface, HOST_ISSUER_SEED_BYTES, HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::setting::{
    SetSetting, SetSettingOutcome, SettingCaller, SettingMode, SettingScope, set_line,
};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::spend::reserve_child_scope;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::json;

/// The quota key under test.
const QUOTA_KEY: &str = "models.quota.agent_may_answer";

/// The line with no open root in reach (RESTRICTION-WAVE-11-CAP-NOTE Q2).
const NO_CAP_LINE: &str = "no cap; the engine does not meter this provider's calls; the payment goes through the provider's account";

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let mut config = VaultConfig::device();
    config.map_size = 32 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open_owned(dir.path(), config).expect("open vault");
    (dir, vault)
}

/// The owner opens one root spend scope with a hard cap in tokens.
fn open_root(vault: &Vault, launch: &str, cap_units: u64) -> SpendScopeId {
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    oneiron::verbs::vault_budgets_lease_open(
        &vault.memory(owner, EdgeActorClass::Human),
        OpenSpendLeaseRequest {
            launch: launch.to_owned(),
            cap_units,
            unit: "tokens".to_owned(),
            shown_at_ms: 1,
            funding_grant_ref: None,
        },
    )
    .expect("the owner opens a root");
    SpendScopeId::launch(launch).expect("a launch scope id")
}

/// The confirm sheet's line for turning on one quota answer at `scope`.
fn quota_note(vault: &Vault, scope: &SettingScope, item: &str) -> Option<String> {
    vault
        .setting_loosening_note(QUOTA_KEY, scope, Some(item))
        .expect("read the confirm sheet's line")
}

/// With no open root: "no cap" and the provider's account, for `top_up`,
/// `pay_as_you_go` and `use_fallback`, at the vault row and at an agent's
/// row; no line for the answers that spend nothing.
#[test]
fn a_payment_answer_states_no_cap_without_an_open_root() {
    let (_dir, vault) = open_vault();
    for scope in [SettingScope::Vault, SettingScope::Agent(EntityId::now())] {
        for item in ["top_up", "pay_as_you_go", "use_fallback"] {
            assert_eq!(
                quota_note(&vault, &scope, item).as_deref(),
                Some(NO_CAP_LINE),
                "{scope:?} {item}"
            );
        }
        for item in ["wait", "add_account"] {
            assert_eq!(quota_note(&vault, &scope, item), None, "{scope:?} {item}");
        }
    }
}

/// At the vault row, the line names every open root's hard cap: one root's
/// amount and unit, then the largest of two and how many are open.
#[test]
fn a_payment_answer_states_the_open_root_cap() {
    let (_dir, vault) = open_vault();
    open_root(&vault, "launch-wave11-a", 5_000);
    for item in ["top_up", "pay_as_you_go", "use_fallback"] {
        assert_eq!(
            quota_note(&vault, &SettingScope::Vault, item).as_deref(),
            Some("spend cap in force: 5000 tokens"),
            "{item}"
        );
    }
    open_root(&vault, "launch-wave11-b", 9_000);
    assert_eq!(
        quota_note(&vault, &SettingScope::Vault, "top_up").as_deref(),
        Some("spend cap in force: up to 9000 tokens per run, across 2 open runs")
    );
    assert_eq!(quota_note(&vault, &SettingScope::Vault, "wait"), None);
}

/// At an agent's row, the line names only the roots over that agent's open
/// attempts: another open root no attempt of that agent spends under is not
/// named, and an agent with no open attempt reads "no cap".
#[test]
fn an_agent_row_states_only_the_roots_over_its_own_attempts() {
    let (_dir, vault) = open_vault();
    let launch = open_root(&vault, "launch-wave11-own", 5_000);
    let AgentDispatchOutcome::Dispatched(status) = AgentDispatcher::new(&vault)
        .dispatch_default_base(None, None, None, 1)
        .expect("dispatch the default agent")
    else {
        panic!("expected one fresh spawn");
    };
    let agent = status
        .input
        .target
        .agent_definition_ref()
        .expect("the run's agent");
    reserve_child_scope(&vault, &launch, &status.attempt.id, 100, 1)
        .expect("the agent's run spends under its root");
    open_root(&vault, "launch-wave11-other", 9_000);

    for item in ["top_up", "use_fallback"] {
        assert_eq!(
            quota_note(&vault, &SettingScope::Agent(agent), item).as_deref(),
            Some("spend cap in force: 5000 tokens"),
            "{item}"
        );
    }
    assert_eq!(
        quota_note(&vault, &SettingScope::Vault, "top_up").as_deref(),
        Some("spend cap in force: up to 9000 tokens per run, across 2 open runs")
    );
    assert_eq!(
        quota_note(&vault, &SettingScope::Agent(EntityId::now()), "top_up").as_deref(),
        Some(NO_CAP_LINE)
    );
}

/// A rooted device vault, as an agent's Grant needs one: the install's
/// keystore, a host root, the engine's machine identities and this install's
/// profile.
fn open_rooted_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = HostSlipIssuer::from_seed(&[0x5A; HOST_ISSUER_SEED_BYTES]).expect("host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    vault
        .provision_engine_machine_identities(&issuer)
        .expect("engine machine identities");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's machine profile");
    (dir, vault)
}

/// The owner's proof on `vault`.
fn owner_proof(vault: &Vault) -> AuthenticatedOwner {
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof")
}

/// An enabled agent the owner creates, with a live owner Grant naming
/// `vault.settings.set` and the quota key's own line, so it may ask to set
/// the key.
fn quota_asker(vault: &Vault, owner: &AuthenticatedOwner) -> EntityId {
    let agent = EntityId::now();
    create_agent_definition_as(
        vault,
        owner,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": format!("wave11-quota-asker-{}", agent.to_hex()),
                "desc": "Wave 11 quota ask test agent",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("typed agent definition"),
        },
    )
    .expect("the owner creates an enabled agent");
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from([
        "vault.settings.set".to_owned(),
        set_line(QUOTA_KEY),
    ]));
    let minted = mint_agent_grant_as(
        vault,
        owner,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
        },
    )
    .expect("the owner mints the agent a Grant");
    assert!(minted.grant.confers, "the Grant confers");
    agent
}

/// `agent` asks to turn on `top_up` at the vault row: a loosening, so it
/// waits on a check-in, whose id this returns.
fn ask_top_up(vault: &Vault, agent: EntityId) -> EntityId {
    let mut request = SetSetting::vault_value(QUOTA_KEY, json!(true));
    request.item = Some("top_up".to_owned());
    match vault
        .set_setting(SettingCaller::Agent(agent), request)
        .expect("the agent asks")
    {
        SetSettingOutcome::Pending { check_in } => {
            EntityId::from_hex(&check_in).expect("a check-in id")
        }
        outcome => panic!("turning on top_up waits for the owner: {outcome:?}"),
    }
}

/// The owner's sheet reads an agent's pending `top_up` ask: the row it
/// changes, the value it asks for, and the cap line as the vault stands when
/// the owner looks: "no cap" before a root opens, that root's cap after.
#[test]
fn the_owner_reads_an_agents_payment_ask_with_its_cap_line() {
    let (_dir, vault) = open_rooted_vault();
    let owner = owner_proof(&vault);
    let agent = quota_asker(&vault, &owner);
    let check_in = ask_top_up(&vault, agent);

    let ask = vault
        .setting_ask_as_owner(&owner, &check_in)
        .expect("read the ask")
        .expect("the ask is kept beside its check-in");
    assert_eq!(ask.check_in, check_in);
    assert_eq!(ask.asker, agent);
    assert_eq!(ask.key, QUOTA_KEY);
    assert_eq!(ask.item.as_deref(), Some("top_up"));
    assert_eq!(ask.mode, SettingMode::Value);
    assert_eq!(ask.scope, SettingScope::Vault);
    assert_eq!(ask.value, Some(json!(true)));
    assert_eq!(ask.loosening_note.as_deref(), Some(NO_CAP_LINE));

    open_root(&vault, "launch-wave11-ask", 5_000);
    let ask = vault
        .setting_ask_as_owner(&owner, &check_in)
        .expect("read the ask again")
        .expect("the ask is still kept");
    assert_eq!(
        ask.loosening_note.as_deref(),
        Some("spend cap in force: 5000 tokens"),
        "the line is read when the owner looks, not when the agent asked"
    );
}

/// A check-in no setting ask waits on reads as none.
#[test]
fn a_check_in_no_setting_ask_waits_on_reads_none() {
    let (_dir, vault) = open_rooted_vault();
    let owner = owner_proof(&vault);
    assert_eq!(
        vault
            .setting_ask_as_owner(&owner, &EntityId::now())
            .expect("read an unknown check-in"),
        None
    );
}
