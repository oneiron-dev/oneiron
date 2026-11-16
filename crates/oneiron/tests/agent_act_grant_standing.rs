//! An owner act an agent carries stands only on its Grant's counted mint (pass 28 R3b2).
//!
//! A FEDERATION_GRANT row gives nothing by itself: a row no counted mint gives, or a minted
//! row widened in place, names no owner act for its agent, and a git push Grant row no counted
//! mint gives is no active Grant in the owner's consent registry. The judge of a carried act
//! reads the fold's own grant line, never the row: a row narrowed in place does not hold back
//! the act its mint named. The honest mint keeps naming its act.
//!
//! Runs on public paths and the test doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features
//! --test agent_act_grant_standing`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{
    ActSurface, EffectiveRead, HostSlipIssuer, MachineRole, OwnerActKind, ReadLocation,
    WorldPrivacy,
};
use oneiron::consent::{AuthenticatedOwner, ConsentRegistryQuery};
use oneiron::federation::{
    FederationGrant, FederationGrantKind, FederationGrantPreset, FederationGrantRole,
    GIT_PUSH_VERB, GitPushBounds, GitPushRepo, Scope, ScopeAxis, ScopeId,
    decode_federation_grant_body, own_device_residence_scope,
};
use oneiron::policy_model::WorldPrivacyOutcome;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::authority_view_grant::bind_agent;
use oneiron::test_doors::grant_act::put_unkeyed_member_grant;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use serde_json::json;

/// The verb an agent's Grant names its free-time policy act by.
const FREE_TIME_POLICY_SET: &str = "free_time_policy_set";

/// The verb an agent's Grant names a world tighten by.
const WORLD_PRIVACY_TIGHTEN: &str = "world_privacy_tighten";

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
}

/// A device vault whose live install profile carries the owner's acts.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let keystore = Arc::new(MemoryKeystore::default());
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::<MemoryKeystore>::clone(&keystore));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    let (owner, owner_proof) = embedded_owner(&vault).expect("authenticated embedded owner");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    Fixture {
        vault,
        _dir: dir,
        owner,
        owner_proof,
    }
}

fn verb_scope(verbs: &[&str]) -> Scope {
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(verbs.iter().map(|verb| (*verb).to_owned()).collect());
    scope
}

/// The owner mints `agent` an agent Grant over `scope`; its id.
fn mint(
    vault: &Vault,
    owner_proof: &AuthenticatedOwner,
    agent: EntityId,
    scope: Scope,
) -> EntityId {
    let minted = mint_agent_grant_as(
        vault,
        owner_proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope: scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
        },
    )
    .expect("the owner mints the agent Grant");
    EntityId::from_hex(&minted.grant.grant_ref).expect("Grant id hex")
}

/// The Grant row `id` as it is stored now.
fn row(vault: &Vault, id: EntityId) -> FederationGrant {
    let body = vault
        .get(&id)
        .expect("grant read")
        .expect("a live Grant row");
    decode_federation_grant_body(&body).expect("the Grant row decodes")
}

fn named_agent(vault: &Vault, name: &str) -> EntityId {
    vault
        .ensure_agent_principal(name)
        .expect("a named agent principal")
}

/// The owner's consent registry rows that stand now.
fn active_registry_rows(vault: &Vault) -> usize {
    vault
        .consent_registry(ConsentRegistryQuery::new(1_000, false))
        .expect("the owner's consent registry")
        .rows
        .len()
}

#[test]
fn a_bare_agent_grant_row_names_no_owner_act() {
    let fixture = fixture();
    let yuki = named_agent(&fixture.vault, "yuki");
    let mika = named_agent(&fixture.vault, "mika");
    let honest = mint(
        &fixture.vault,
        &fixture.owner_proof,
        yuki,
        verb_scope(&["read", FREE_TIME_POLICY_SET]),
    );
    let mut forged = row(&fixture.vault, honest);
    forged.member_ref = mika;
    let forged_id = EntityId::now();
    put_unkeyed_member_grant(&fixture.vault, forged_id, &forged).expect("the bare row lands");

    let granted = fixture
        .vault
        .granted_act(mika, forged_id, OwnerActKind::FreeTimePolicy);
    assert!(
        granted.is_err(),
        "agent={mika:?} grant={forged_id:?}; expected a row no counted mint gives to name no \
         owner act; seen {granted:?}"
    );
}

#[test]
fn an_agent_grant_widened_in_place_names_no_owner_act() {
    let fixture = fixture();
    let yuki = named_agent(&fixture.vault, "yuki");
    let id = mint(
        &fixture.vault,
        &fixture.owner_proof,
        yuki,
        verb_scope(&["read"]),
    );
    let mut widened = row(&fixture.vault, id);
    widened.authority_scope = verb_scope(&["read", FREE_TIME_POLICY_SET]);
    put_unkeyed_member_grant(&fixture.vault, id, &widened).expect("the widened row lands");

    let granted = fixture
        .vault
        .granted_act(yuki, id, OwnerActKind::FreeTimePolicy);
    assert!(
        granted.is_err(),
        "agent={yuki:?} grant={id:?}; expected a row whose terms are not its mint's to name no \
         owner act; seen {granted:?}"
    );
}

#[test]
fn a_minted_agent_grant_names_its_owner_act() {
    let fixture = fixture();
    let yuki = named_agent(&fixture.vault, "yuki");
    let id = mint(
        &fixture.vault,
        &fixture.owner_proof,
        yuki,
        verb_scope(&["read", FREE_TIME_POLICY_SET]),
    );

    let granted = fixture
        .vault
        .granted_act(yuki, id, OwnerActKind::FreeTimePolicy);
    assert!(
        granted.is_ok(),
        "agent={yuki:?} grant={id:?}; expected the honest mint to name its act; seen {granted:?}"
    );
}

#[test]
fn a_bare_git_push_grant_row_is_no_active_grant() {
    let fixture = fixture();
    let pusher = named_agent(&fixture.vault, "pusher");
    let before = active_registry_rows(&fixture.vault);
    let mut forged = FederationGrant::new(
        own_device_residence_scope(),
        pusher,
        FederationGrantRole::Delegate,
        FederationGrantPreset::Delegate,
    );
    let project = EntityId::now();
    forged.kind = FederationGrantKind::GitPush;
    forged.delegated_by = Some(fixture.owner);
    forged.git_push_bounds = Some(GitPushBounds {
        repos: BTreeSet::from([GitPushRepo {
            repo: EntityId::now(),
            project,
        }]),
    });
    // The one scope a git push body holds (federation/grant/git_push.rs git_push_scope): the
    // `git_push` verb, the bounds' projects as its audience, every other axis bottom.
    forged.authority_scope = Scope {
        audience: ScopeAxis::Some(BTreeSet::from([ScopeId(project)])),
        verbs: ScopeAxis::Some(BTreeSet::from([GIT_PUSH_VERB.to_owned()])),
        ..Scope::default()
    };
    let forged_id = EntityId::now();
    put_unkeyed_member_grant(&fixture.vault, forged_id, &forged).expect("the bare row lands");

    let after = active_registry_rows(&fixture.vault);
    assert_eq!(
        after, before,
        "grant={forged_id:?}; expected a git push row no counted mint gives to add no active \
         consent registry row; rows before={before} after={after}"
    );
}

/// The judge of a carried act reads the fold's grant line, not the row: a row narrowed in
/// place, with no act, holds back nothing the owner's mint named.
#[test]
fn a_carried_tighten_stands_when_its_grant_row_is_narrowed_in_place() {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let issuer = HostSlipIssuer::from_secret(b"agent-act-grant-standing").expect("fixture issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("live install profile to carry owner acts");
    let owner_proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("authenticated owner");
    let world = vault
        .create_world(&owner_proof, "Grant line world", vault.now_recorded_at())
        .expect("owner creates a world with default privacy");
    let agent = EntityId::now();
    create_agent_definition_as(
        &vault,
        &owner_proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": "agent_act_grant_standing_agent",
                "desc": "World privacy agent",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("typed agent definition"),
        },
    )
    .expect("owner creates the agent");
    let mut scope = verb_scope(&["read", WORLD_PRIVACY_TIGHTEN]);
    scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(world)]));
    let grant = mint(&vault, &owner_proof, agent, scope);
    // The fixture binder rebinds the host key, so owner setup precedes it.
    let writer = bind_agent(&vault, &issuer, agent).expect("active agent writer");
    let outcome = vault
        .agent_world_privacy(
            &writer,
            Vec::new(),
            world,
            WorldPrivacy {
                read: ReadLocation::MyMachines,
                ..WorldPrivacy::default()
            },
            None,
        )
        .expect("agent tightens the world under its Grant");
    assert!(
        matches!(outcome, WorldPrivacyOutcome::Applied(_)),
        "precondition: the agent's tighten applied, not a proposal or ask: {outcome:?}",
    );
    let mut narrowed = row(&vault, grant);
    narrowed.authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    put_unkeyed_member_grant(&vault, grant, &narrowed).expect("the narrowed row lands");

    let read = vault.world_privacy(world).expect("world privacy read").read;
    assert_eq!(
        read,
        EffectiveRead::MyMachines,
        "grant={grant:?} world={world:?}; expected the tighten its counted mint named to stand \
         after its row was narrowed in place with no act; seen read={read:?}"
    );
}
