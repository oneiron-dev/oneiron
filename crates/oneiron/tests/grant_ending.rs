//! Pass 28 R2c: every Grant giving is a signed authority-log act, and a Grant row stands
//! only on its counted giving until a counted act ends its line.
//!
//! What this stem pins:
//! - a lapsed sign-in ends the owner's agent Grant by rule, at once with a loaded key and
//!   owed until the key loads without one;
//! - a batch delete of a member row owes its end, carried once the key loads;
//! - a torn row whose giving reaches the install only later stays owed until it does, and its
//!   end then ends the line (Astra r1-r2d F3);
//! - a hard erase and a soft delete of a member row each end its line in its writer;
//! - a delegate stands on its admin's giving, and refuses on an install with no install key;
//! - a house link gives each row by act, and an unlink ends each line it removes;
//! - an inquiry edge terms change gives the new terms.
//!
//! Runs on public paths and the test doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features
//! --test grant_ending`.
#![cfg(all(oneiron_test_support, feature = "sync"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, AuthorityVaultId, HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::DeleteEntityOptions;
use oneiron::federation::{
    FederationGrant, FederationGrantRole as Role, FederationGrantScope, InitialSharedMember, Scope,
    ScopeAxis, SharedVaultChange, decode_federation_grant_body,
};
use oneiron::inquiry::{
    InquiryCheckInMode, InquiryEdgeRequest, InquiryTermsChange, InquiryTermsChangeOutcome,
};
use oneiron::registry::{ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::grant_act::put_keyed_member_grant;
use oneiron::test_doors::grant_ending::{
    batch_delete_row, give_member_grant_act_alone, load_install_carrier, standing_grant_in_family,
    withdraw_lapsed_agent_grant,
};
use oneiron::test_doors::grant_standing::{grant_line, grant_row, standing_grant_act};
use oneiron::test_support::{bind_host_owner, provision_act_carrier, provision_engine_machines};
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::workspace_roster::{WorkCompanionPolicy, WorkspaceRosterPreset};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use serde_json::json;

const SHARED: u64 = 42;

/// The terms key of a row a test puts and gives at once.
const TERMS_KEY: [u8; 32] = [0x5a; 32];

/// A rooted install whose key carries acts, its keystore and its owner.
#[allow(dead_code, reason = "copied fixture; this stem reads no issuer")]
struct Install {
    dir: tempfile::TempDir,
    vault: Vault,
    keystore: Arc<MemoryKeystore>,
    issuer: HostSlipIssuer,
    owner: EntityId,
}

fn carrier_install() -> Install {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    let keystore = Arc::new(MemoryKeystore::default());
    vault.install_device_keystore(keystore.clone());
    let issuer = provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile, to carry acts");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
    Install {
        dir,
        vault,
        keystore,
        issuer,
        owner,
    }
}

fn person(vault: &Vault, id: EntityId) {
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
}

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("a person proof")
}

/// `owner` shares the vault as its Owner and invites each of `invited` at its role.
fn share(vault: &Vault, owner: EntityId, invited: &[(EntityId, Role)]) {
    let mut members = vec![InitialSharedMember {
        member_ref: owner,
        role: Some(Role::Owner),
    }];
    members.extend(invited.iter().map(|(member, role)| InitialSharedMember {
        member_ref: *member,
        role: Some(*role),
    }));
    vault
        .initialize_shared_vault(
            &proof(vault, owner),
            SHARED,
            None,
            &members,
            vault.now_recorded_at(),
        )
        .expect("a shared vault");
}

/// `member` accepts its founding invitation at `role`.
fn accept(vault: &Vault, member: EntityId, role: Role) {
    let member_proof = proof(vault, member);
    let invitation = vault
        .shared_invitations(&member_proof, SHARED)
        .expect("invitations")
        .into_iter()
        .find(|open| open.role == role)
        .expect("the founding invitation");
    vault
        .accept_shared_invitation(&member_proof, SHARED, &invitation.id)
        .expect("the member accepts");
}

/// `member`'s membership Grant row in the shared vault: its id and terms.
fn member_row(vault: &Vault, member: EntityId) -> Option<(EntityId, FederationGrant)> {
    vault
        .entities_by_type(ENTITY_TYPE_FEDERATION_GRANT)
        .expect("grants")
        .into_iter()
        .find_map(|id| {
            let body = vault.get(&id).expect("grant row")?;
            let grant = decode_federation_grant_body(&body).ok()?;
            (grant.member_ref == member
                && grant.role != Role::Delegate
                && grant.scope == FederationGrantScope::vault(SHARED))
            .then_some((id, grant))
        })
}

/// A vault whose owner minted his agent a read Grant, keeping the keystore.
struct MintedAgent {
    dir: tempfile::TempDir,
    vault: Vault,
    grant: EntityId,
    keystore: Arc<MemoryKeystore>,
}

/// The owner mints his agent a read Grant.
fn minted_agent_grant() -> MintedAgent {
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    let owner_actor = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let issuer = HostSlipIssuer::from_secret(b"grant-ending-r2c").expect("fixture host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    let keystore = Arc::new(MemoryKeystore::default());
    vault.install_device_keystore(keystore.clone());
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("live install profile to carry owner acts");
    let owner = vault
        .authenticate_owner(
            owner_actor,
            &owner_actor.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("authenticated owner");
    let agent = EntityId::now();
    create_agent_definition_as(
        &vault,
        &owner,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": "grant_ending_agent",
                "desc": "Grant ending agent",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("typed agent definition"),
        },
    )
    .expect("owner creates the agent");
    let minted = mint_agent_grant_as(
        &vault,
        &owner,
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
    .expect("owner mints the agent a Grant");
    assert!(minted.grant.confers, "precondition: the Grant is live");
    MintedAgent {
        dir,
        vault,
        grant: minted.grant.grant_ref,
        keystore,
    }
}

/// The agent the owner's agent Grant `grant` names: its row's member.
fn agent_of(vault: &Vault, grant: EntityId) -> EntityId {
    let body = grant_row(vault, grant)
        .expect("grant row read")
        .expect("the minted row is live");
    decode_federation_grant_body(&body)
        .expect("minted row decodes")
        .member_ref
}

const WORKSPACE: &str = "house-bind-deputy-workspace";
/// The workspace's shared vault. Not 7, the own-device residence scope's id.
const VAULT_ID: u64 = 43;
const VENTURE: &str = "Garden Works";

/// A shared vault with an Admin and a Member who joined it, and a stored workspace.
struct HouseOrg {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner_proof: AuthenticatedOwner,
    house: EntityId,
}

/// The stored workspace whose house is the seeded `sys.default` agent, over
/// `org`. Its house.
fn store_workspace(vault: &Vault, owner_proof: &AuthenticatedOwner, org: EntityId) -> EntityId {
    let (house, _) = vault
        .get_seeded_agent_definition_by_logical_id("sys.default")
        .expect("read the seeded agents")
        .expect("sys.default is seeded on open");
    let preset = WorkspaceRosterPreset {
        workspace_ref: WORKSPACE.to_owned(),
        workspace_vault_id: VAULT_ID,
        org_ref: org,
        venture_name: VENTURE.to_owned(),
        house_display_name: None,
        house_actor_ref: house,
        house_identity_ref: None,
    };
    vault
        .establish_workspace_preset(&preset, WorkCompanionPolicy::Choose, owner_proof)
        .expect("the owner stores the workspace");
    house
}

/// `person` joins the shared vault at `role`: the owner invites, the person
/// accepts. Their proof.
fn join(
    vault: &Vault,
    owner_proof: &AuthenticatedOwner,
    person: EntityId,
    role: Role,
) -> AuthenticatedOwner {
    let invited = vault
        .add_shared_member(owner_proof, VAULT_ID, person, Some(role))
        .expect("the owner's add");
    let SharedVaultChange::MemberInvited { invitation, .. } = invited.change else {
        panic!("the owner's add is an invitation");
    };
    let proof = vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("person proof");
    vault
        .accept_shared_invitation(&proof, VAULT_ID, &invitation.id)
        .expect("the person accepts");
    proof
}

fn house_org() -> HouseOrg {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("fresh vault");
    let (_, owner) = provision_act_carrier(&vault);
    let owner_proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let row = |entity_type: u8| {
        let id = EntityId::now();
        vault
            .put_entity(
                &id,
                entity_type,
                TimeRange { start: 1, end: 1 },
                1,
                b"grant ending house fixture",
            )
            .expect("fixture row");
        id
    };
    let org = row(ENTITY_TYPE_ORG);
    let admin = row(ENTITY_TYPE_PERSON);
    let member = row(ENTITY_TYPE_PERSON);
    vault
        .initialize_shared_vault(&owner_proof, VAULT_ID, None, &[], vault.now_recorded_at())
        .expect("a shared vault");
    join(&vault, &owner_proof, admin, Role::Admin);
    join(&vault, &owner_proof, member, Role::Member);
    let house = store_workspace(&vault, &owner_proof, org);
    HouseOrg {
        _dir: dir,
        vault,
        owner_proof,
        house,
    }
}

/// Every live FEDERATION_GRANT row whose member is the house.
fn house_grant_ids(vault: &Vault, house: EntityId) -> Vec<EntityId> {
    vault
        .entities_by_type(ENTITY_TYPE_FEDERATION_GRANT)
        .expect("grants")
        .into_iter()
        .filter(|id| {
            vault
                .get(id)
                .expect("grant row")
                .and_then(|body| decode_federation_grant_body(&body).ok())
                .is_some_and(|grant| grant.member_ref == house)
        })
        .collect()
}

/// The house's Grant rows that are live now and were not in `before`: the rows a link wrote.
fn added_since(vault: &Vault, house: EntityId, before: &[EntityId]) -> Vec<EntityId> {
    house_grant_ids(vault, house)
        .into_iter()
        .filter(|id| !before.contains(id))
        .collect()
}

/// A company vault no fixture opens: an edge needs no live peer to mint.
const UNOPENED_COMPANY: AuthorityVaultId = [0xbd; 32];

/// A carried vault whose owner minted an inquiry edge to a company: the vault, his proof and
/// the edge's grant.
fn inquiry_edge() -> (tempfile::TempDir, Vault, AuthenticatedOwner, EntityId) {
    let dir = tempfile::tempdir().expect("vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    let (_, owner) = provision_act_carrier(&vault);
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let edge = vault
        .mint_inquiry_edge(
            &proof,
            &InquiryEdgeRequest::member_defaults(UNOPENED_COMPANY, "Acme"),
        )
        .expect("the member mints the inquiry edge");
    (dir, vault, proof, edge.grant)
}

/// Catches a lapsed sign-in that deletes the agent Grant without ending its line.
#[test]
fn a_lapsed_sign_in_ends_the_agent_grant_by_rule() {
    let minted = minted_agent_grant();
    let agent = agent_of(&minted.vault, minted.grant);
    assert!(
        withdraw_lapsed_agent_grant(&minted.vault, minted.grant, agent)
            .expect("a lapse is never refused"),
        "the lapse withdrew the live agent Grant",
    );
    assert_eq!(
        grant_line(&minted.vault, minted.grant)
            .expect("grant line")
            .map(|(_, ended)| ended),
        Some(true),
        "the rule's end ended the Grant's line",
    );
    let now = minted.vault.now_recorded_at();
    assert_eq!(
        standing_grant_act(&minted.vault, minted.grant, now).expect("standing read"),
        None,
        "an ended agent Grant stands for nothing",
    );
}

/// Catches a lapse that refuses with no loaded key, or never ends the line once it loads.
#[test]
fn a_lapse_with_no_loaded_key_is_never_refused_and_ends_the_line_once_the_key_loads() {
    let minted = minted_agent_grant();
    let agent = agent_of(&minted.vault, minted.grant);
    let MintedAgent {
        dir,
        vault,
        grant,
        keystore,
    } = minted;
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the vault again");
    assert!(
        withdraw_lapsed_agent_grant(&vault, grant, agent)
            .expect("a lapse with no loaded key is never refused"),
        "the lapse withdrew the live agent Grant",
    );
    assert_eq!(
        grant_line(&vault, grant)
            .expect("grant line")
            .map(|(_, ended)| ended),
        Some(false),
        "the end waits owed while no key is loaded",
    );
    vault.install_device_keystore(keystore);
    load_install_carrier(&vault);
    assert_eq!(
        grant_line(&vault, grant)
            .expect("grant line")
            .map(|(_, ended)| ended),
        Some(true),
        "the owed end ended the line once the key loaded",
    );
}

/// Catches a batch delete that tears a Grant row without owing the end its key load carries.
#[test]
fn a_batch_delete_of_a_member_row_ends_its_line_once_the_key_loads() {
    let install = carrier_install();
    let member = EntityId::now();
    person(&install.vault, member);
    share(&install.vault, install.owner, &[(member, Role::Member)]);
    accept(&install.vault, member, Role::Member);
    let (id, _) = member_row(&install.vault, member).expect("the member's grant");
    batch_delete_row(&install.vault, id).expect("a batch delete of the member row");
    assert!(
        member_row(&install.vault, member).is_none(),
        "the delete tore the row",
    );
    let Install {
        dir,
        vault,
        keystore,
        ..
    } = install;
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the vault again");
    vault.install_device_keystore(keystore);
    load_install_carrier(&vault);
    assert_eq!(
        grant_line(&vault, id)
            .expect("line read")
            .map(|(_, ended)| ended),
        Some(true),
        "the owed end ended the line once the key loaded",
    );
}

/// Reopens the vault in `dir` with `keystore` and loads its key, which carries every end the
/// install owes.
fn reopen_carrying(dir: &tempfile::TempDir, keystore: &Arc<MemoryKeystore>) -> Vault {
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the vault again");
    vault.install_device_keystore(keystore.clone());
    load_install_carrier(&vault);
    vault
}

/// Catches a torn row's debt dropped with no act because the row's giving had not reached this
/// install yet (Astra r1-r2d F3). A member row arrives before its giving and a batch delete
/// tears it; a key load carries the install's debts; then the giving arrives. The next carry
/// ends the line, so no copy of the row stands on that giving.
#[test]
fn a_torn_row_whose_giving_arrives_later_still_ends_its_line() {
    let install = carrier_install();
    let member = EntityId::now();
    person(&install.vault, member);
    share(&install.vault, install.owner, &[(member, Role::Member)]);
    accept(&install.vault, member, Role::Member);
    let (_, grant) = member_row(&install.vault, member).expect("the member's grant");
    let id = EntityId::now();
    put_keyed_member_grant(&install.vault, id, &grant, &TERMS_KEY)
        .expect("the row, before its giving");
    batch_delete_row(&install.vault, id).expect("a batch delete of the row");
    let Install {
        dir,
        vault,
        keystore,
        owner,
        ..
    } = install;
    drop(vault);
    let vault = reopen_carrying(&dir, &keystore);
    assert_eq!(
        grant_line(&vault, id).expect("line read"),
        None,
        "no act names the row before its giving arrives",
    );
    give_member_grant_act_alone(&vault, id, &grant, &TERMS_KEY, owner).expect("the giving arrives");
    drop(vault);
    let vault = reopen_carrying(&dir, &keystore);
    assert_eq!(
        grant_line(&vault, id)
            .expect("line read")
            .map(|(_, ended)| ended),
        Some(true),
        "the torn row's end was dropped before its giving arrived",
    );
}

/// Catches a hard erase that purges a Grant row without ending its line in its writer.
#[test]
fn a_hard_erase_of_a_member_row_ends_its_line_in_its_writer() {
    let install = carrier_install();
    let member = EntityId::now();
    person(&install.vault, member);
    share(&install.vault, install.owner, &[(member, Role::Member)]);
    accept(&install.vault, member, Role::Member);
    let (id, _) = member_row(&install.vault, member).expect("the member's grant");
    let erased = install
        .vault
        .delete_entity_with_options(&id, DeleteEntityOptions { purge: true })
        .expect("hard erase of the member row");
    assert!(erased, "the erase removed the row");
    assert_eq!(
        grant_line(&install.vault, id)
            .expect("line read")
            .map(|(_, ended)| ended),
        Some(true),
        "the erase ended the line in its writer",
    );
}

/// Catches a soft delete that takes a Grant row back without ending its line.
#[test]
fn a_soft_delete_of_a_member_row_ends_its_line_in_its_writer() {
    let install = carrier_install();
    let member = EntityId::now();
    person(&install.vault, member);
    share(&install.vault, install.owner, &[(member, Role::Member)]);
    accept(&install.vault, member, Role::Member);
    let (id, _) = member_row(&install.vault, member).expect("the member's grant");
    let deleted = install
        .vault
        .delete_entity(&id)
        .expect("soft delete of the member row");
    assert!(deleted, "the delete took the row back");
    assert!(
        member_row(&install.vault, member).is_none(),
        "the row no longer reads live",
    );
    assert_eq!(
        grant_line(&install.vault, id)
            .expect("line read")
            .map(|(_, ended)| ended),
        Some(true),
        "the soft delete ended the line in its writer",
    );
}

/// Catches a delegate mint that writes its row without the admin's counted giving.
#[test]
fn a_delegate_stands_on_its_admins_giving() {
    let install = carrier_install();
    share(&install.vault, install.owner, &[]);
    let (owner_grant, _) =
        member_row(&install.vault, install.owner).expect("the creator's Owner grant");
    let delegate = EntityId::now();
    person(&install.vault, delegate);
    let now = install.vault.now_recorded_at();
    let id = install
        .vault
        .create_federation_delegate(
            &proof(&install.vault, install.owner),
            owner_grant,
            delegate,
            now,
            now + 3600,
        )
        .expect("the Owner mints a delegate");
    assert!(
        standing_grant_in_family(&install.vault, id, "delegate", now)
            .expect("standing read")
            .is_some(),
        "the delegate stands on its admin's giving",
    );
}

/// Catches a delegate mint that lands with no install key instead of refusing.
#[test]
fn a_delegate_refuses_on_an_install_with_no_install_key() {
    let install = carrier_install();
    share(&install.vault, install.owner, &[]);
    let (owner_grant, _) =
        member_row(&install.vault, install.owner).expect("the creator's Owner grant");
    let delegate = EntityId::now();
    person(&install.vault, delegate);
    let before = install
        .vault
        .entities_by_type(ENTITY_TYPE_FEDERATION_GRANT)
        .expect("grants")
        .len();
    let Install {
        dir, vault, owner, ..
    } = install;
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the vault again");
    let now = vault.now_recorded_at();
    let error = vault
        .create_federation_delegate(
            &proof(&vault, owner),
            owner_grant,
            delegate,
            now,
            now + 3600,
        )
        .expect_err("a delegate mint with no install key refuses");
    assert!(
        error.to_string().contains("no live machine profile"),
        "{error}",
    );
    let after = vault
        .entities_by_type(ENTITY_TYPE_FEDERATION_GRANT)
        .expect("grants")
        .len();
    assert_eq!(after, before, "the refused mint wrote no Grant row");
}

/// Catches a house link that seats the house without giving each row by act.
#[test]
fn a_house_link_gives_each_row_by_act() {
    let fx = house_org();
    let before = house_grant_ids(&fx.vault, fx.house);
    fx.vault
        .set_house_role(&fx.owner_proof, WORKSPACE, Role::Member)
        .expect("the Owner seats the house at member");
    let ids = added_since(&fx.vault, fx.house, &before);
    assert!(!ids.is_empty(), "the set wrote the house's grant");
    let now = fx.vault.now_recorded_at();
    for id in &ids {
        assert!(
            standing_grant_in_family(&fx.vault, *id, "house_link", now)
                .expect("standing read")
                .is_some(),
            "the house's grant {} stands on its giving",
            id.to_hex(),
        );
    }
}

/// Catches a house unlink that removes the rows without ending each line.
#[test]
fn a_house_unlink_ends_each_line_it_removes() {
    let fx = house_org();
    let before = house_grant_ids(&fx.vault, fx.house);
    fx.vault
        .set_house_role(&fx.owner_proof, WORKSPACE, Role::Member)
        .expect("the Owner seats the house at member");
    let ids = added_since(&fx.vault, fx.house, &before);
    assert!(!ids.is_empty(), "the set wrote the house's grant");
    assert!(
        fx.vault
            .clear_house_role(&fx.owner_proof, WORKSPACE)
            .expect("the Owner clears the house"),
        "the clear removed the link",
    );
    for id in &ids {
        assert_eq!(
            grant_line(&fx.vault, *id)
                .expect("line read")
                .map(|(_, ended)| ended),
            Some(true),
            "the unlink ended the house's grant {}",
            id.to_hex(),
        );
    }
}

/// Catches an inquiry edge terms change that rewrites the row without giving the new terms.
#[test]
fn an_inquiry_edge_terms_change_gives_the_new_terms() {
    let (_dir, vault, proof, grant) = inquiry_edge();
    let now = vault.now_recorded_at();
    assert_eq!(
        standing_grant_in_family(&vault, grant, "inquiry_edge", now).expect("standing read"),
        None,
        "the minted edge stands on no giving yet",
    );
    let changed = vault
        .change_inquiry_edge_terms(
            &proof,
            grant,
            InquiryTermsChange {
                task: Some(InquiryCheckInMode::NeverAnswer),
                ..InquiryTermsChange::default()
            },
        )
        .expect("the member narrows task to never");
    assert_eq!(
        changed.outcome,
        InquiryTermsChangeOutcome::Narrowed,
        "the change narrowed",
    );
    assert!(
        standing_grant_in_family(&vault, grant, "inquiry_edge", vault.now_recorded_at())
            .expect("standing read")
            .is_some(),
        "the edge stands on the new terms' giving",
    );
}
