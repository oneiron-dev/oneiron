//! DEL-2: the delete authority on every delete (ARCH-0043, owner DEL-2 = A,
//! 9 Oct: "Members delete their own items, Admins delete in scope, and
//! Owners delete anything. An agent deletes only by a Grant from an Admin or
//! an Owner"). `vault.delete` (`Memory::safe_delete`) was an owner verb:
//! every other caller got OWNER_BINDING_REQUIRED or FORBIDDEN. The owner
//! path is unchanged; a caller the owner predicate refuses is now judged by
//! the one delete authority the cleanup archive's door already used.
//!
//! Red on main: a Member's own delete, the Admin's in-scope delete, the
//! agent's delete under a delete Grant, and the two typed refusals
//! (`not_owner_of_item`, `no_delete_grant`). Guards (pass on main too): the
//! owner's delete, and a person with no role keeping the owner refusal.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test delete_authority`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember, Scope, ScopeAxis};
use oneiron::memory::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_OWNER_BINDING_REQUIRED, MemoryError, SafeDeleteReason,
};
use oneiron::note::TakeTarget;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::json;

const SHARED: u64 = 43;

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

/// `member` accepts its founding invitation to the shared vault at `role`.
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

/// A NOTE `author` writes about `subject`, by its full hex ref.
fn note_by(vault: &Vault, author: EntityId, class: EdgeActorClass, subject: EntityId) -> String {
    vault
        .memory(author, class)
        .author_take(TakeTarget::Subject(subject), "a take about the subject")
        .expect("author a NOTE")
        .id_hex
}

fn deleted(vault: &Vault, note: &str) -> bool {
    vault
        .is_deleted_shell(&EntityId::from_hex(note).expect("note id"))
        .expect("shell read")
}

fn delete_as(vault: &Vault, actor: EntityId, note: &str) -> Result<bool, MemoryError> {
    vault
        .memory(actor, EdgeActorClass::Human)
        .safe_delete(note, SafeDeleteReason::UserDelete)
        .map(|receipt| receipt.existed)
}

/// A shared vault: its owner, an Admin, two Members and a person with no
/// role, and a subject PERSON the NOTEs are about.
struct Shared {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    admin: EntityId,
    member_a: EntityId,
    member_b: EntityId,
    stranger: EntityId,
    subject: EntityId,
}

fn shared() -> Shared {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
    // A delete signs its receipt with this install's key.
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    oneiron::test_support::provision_engine_machines(&vault);
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let [admin, member_a, member_b, stranger, subject] = std::array::from_fn(|_| EntityId::now());
    for id in [admin, member_a, member_b, stranger, subject] {
        person(&vault, id);
    }
    let member = |member_ref, role| InitialSharedMember {
        member_ref,
        role: Some(role),
    };
    vault
        .initialize_shared_vault(
            &proof(&vault, owner),
            SHARED,
            None,
            &[
                member(owner, Role::Owner),
                member(admin, Role::Admin),
                member(member_a, Role::Member),
                member(member_b, Role::Member),
            ],
            1,
        )
        .expect("a shared vault with an Admin and two Members");
    accept(&vault, admin, Role::Admin);
    accept(&vault, member_a, Role::Member);
    accept(&vault, member_b, Role::Member);
    Shared {
        _dir: dir,
        vault,
        owner,
        admin,
        member_a,
        member_b,
        stranger,
        subject,
    }
}

#[test]
fn a_member_deletes_its_own_note() {
    let fx = shared();
    let note = note_by(&fx.vault, fx.member_a, EdgeActorClass::Human, fx.subject);
    let existed = delete_as(&fx.vault, fx.member_a, &note)
        .unwrap_or_else(|error| panic!("a Member deletes the NOTE it authored: {error:?}"));
    assert!(existed, "the Member's NOTE existed");
    assert!(
        deleted(&fx.vault, &note),
        "the Member's NOTE is a deleted shell"
    );
}

#[test]
fn a_member_is_refused_another_members_note() {
    let fx = shared();
    let note = note_by(&fx.vault, fx.member_a, EdgeActorClass::Human, fx.subject);
    let error = delete_as(&fx.vault, fx.member_b, &note)
        .expect_err("a Member is refused another Member's NOTE");
    assert_eq!(error.code, MEMORY_CODE_FORBIDDEN, "{error:?}");
    assert!(
        error.message.starts_with("not_owner_of_item:"),
        "the refusal names its reason: {error:?}"
    );
    assert!(!deleted(&fx.vault, &note), "the refused NOTE is untouched");
}

#[test]
fn an_admin_deletes_a_member_note_in_scope() {
    let fx = shared();
    let note = note_by(&fx.vault, fx.member_a, EdgeActorClass::Human, fx.subject);
    let existed = delete_as(&fx.vault, fx.admin, &note)
        .unwrap_or_else(|error| panic!("an Admin deletes in scope: {error:?}"));
    assert!(existed);
    assert!(deleted(&fx.vault, &note), "the NOTE is a deleted shell");
}

#[test]
fn the_owner_deletes_any_note_as_before() {
    let fx = shared();
    let note = note_by(&fx.vault, fx.member_a, EdgeActorClass::Human, fx.subject);
    let existed = delete_as(&fx.vault, fx.owner, &note)
        .unwrap_or_else(|error| panic!("the owner deletes anything: {error:?}"));
    assert!(existed);
    assert!(deleted(&fx.vault, &note), "the NOTE is a deleted shell");
}

#[test]
fn a_person_with_no_role_keeps_the_owner_refusal() {
    let fx = shared();
    let note = note_by(&fx.vault, fx.member_a, EdgeActorClass::Human, fx.subject);
    let error = delete_as(&fx.vault, fx.stranger, &note)
        .expect_err("a person with no role in the vault is refused");
    assert_eq!(error.code, MEMORY_CODE_OWNER_BINDING_REQUIRED, "{error:?}");
    assert!(!deleted(&fx.vault, &note), "the refused NOTE is untouched");
}

/// A personal vault whose owner made two enabled agents: `granted` holds a
/// Grant naming `read` and `delete`, `read_only` one naming `read` alone.
struct Personal {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    granted: EntityId,
    read_only: EntityId,
    subject: EntityId,
}

fn personal() -> Personal {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    // The owner's agent Grant act is carried by this install's live machine
    // profile (FIX 4648).
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let (owner, owner_proof) = embedded_owner(&vault).expect("authenticated embedded owner");
    let subject = EntityId::now();
    person(&vault, subject);
    let granted = agent_with_grant(
        &vault,
        &owner_proof,
        "delete_granted_agent",
        &["read", "delete"],
    );
    let read_only = agent_with_grant(&vault, &owner_proof, "read_only_agent", &["read"]);
    Personal {
        _dir: dir,
        vault,
        owner,
        granted,
        read_only,
        subject,
    }
}

/// An enabled agent the owner creates and gives one Grant naming `verbs`.
fn agent_with_grant(
    vault: &Vault,
    owner_proof: &AuthenticatedOwner,
    agent_id: &str,
    verbs: &[&str],
) -> EntityId {
    let agent = EntityId::now();
    create_agent_definition_as(
        vault,
        owner_proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": agent_id,
                "desc": "Delete authority test agent",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("typed agent definition"),
        },
    )
    .expect("owner creates an enabled, active agent definition");
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(verbs.iter().map(|verb| (*verb).to_owned()).collect());
    let minted = mint_agent_grant_as(
        vault,
        owner_proof,
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
    .expect("owner mints the agent a Grant");
    assert!(minted.grant.confers, "{agent_id}: the Grant confers");
    agent
}

/// `agent` calls the `vault.delete` verb on `note`.
fn agent_deletes(
    vault: &Vault,
    agent: EntityId,
    note: &str,
) -> Result<serde_json::Value, MemoryError> {
    invoke(
        &vault.memory(agent, EdgeActorClass::Agent),
        "vault.delete",
        json!({ "entity_ref": note, "reason": "user_delete" }),
    )
}

#[test]
fn an_agent_with_a_delete_grant_deletes_through_vault_delete() {
    let fx = personal();
    let note = note_by(&fx.vault, fx.owner, EdgeActorClass::Human, fx.subject);
    let receipt = agent_deletes(&fx.vault, fx.granted, &note)
        .unwrap_or_else(|error| panic!("an agent under a delete Grant deletes: {error:?}"));
    assert_eq!(receipt["existed"], true, "{receipt}");
    assert!(deleted(&fx.vault, &note), "the NOTE is a deleted shell");
}

#[test]
fn an_agent_without_a_delete_grant_is_refused() {
    let fx = personal();
    let note = note_by(&fx.vault, fx.owner, EdgeActorClass::Human, fx.subject);
    let error = agent_deletes(&fx.vault, fx.read_only, &note)
        .expect_err("an agent whose Grant names no delete is refused");
    assert_eq!(error.code, MEMORY_CODE_FORBIDDEN, "{error:?}");
    assert!(
        error.message.starts_with("no_delete_grant:"),
        "the refusal names its reason: {error:?}"
    );
    assert!(!deleted(&fx.vault, &note), "the refused NOTE is untouched");
}
