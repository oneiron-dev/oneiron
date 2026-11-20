//! DEL-2: the delete authority on every delete (ARCH-0043, owner DEL-2 = A,
//! 9 Oct: "Members delete their own items, Admins delete in scope, and
//! Owners delete anything. An agent deletes only by a Grant from an Admin or
//! an Owner"). `vault.delete` (`Memory::safe_delete`) was an owner verb:
//! every other caller got OWNER_BINDING_REQUIRED or FORBIDDEN. The owner
//! path is unchanged; a caller the owner predicate refuses is now judged by
//! the one delete authority the cleanup archive's door already used.
//!
//! The shared vault is rooted, as every served vault is. A human binding is
//! the owner's (H149), so its Members and its Admin hold none: each acts by
//! the live `human` credential this host minted it, as a transport binds it.
//!
//! A `user_delete` scrubs the row before the transaction that publishes its
//! tombstone reads the delete authority again; that read judges the record
//! as its last live read held it, so every admitted delete here publishes.
//!
//! Red on main: a Member's own delete, the Admin's in-scope delete, the
//! agent's delete under a delete Grant, and the two typed refusals
//! (`not_owner_of_item`, `no_delete_grant`). Guards (pass on main too): the
//! owner's delete, a person with no role keeping the owner refusal though it
//! presents a credential, and a Member with no credential keeping it. UC-03
//! PR 5b: the owner's delete row reads `approved` (red on its base, which
//! wrote `allow`), and a Member's admitted delete row keeps `allow`.
//!
//! DELEGATE-PERSON-DELETE (the lead, 21 Nov: "the 10 Nov act table wins. A
//! person whose Delegate grant names delete may delete within its scope.
//! Erase stays manual, as DEL-2 also says"). A person who holds only a
//! Delegate grant the Owner gave it: red on main, which judged that person
//! by membership alone and kept the owner refusal: its delete under a grant
//! that names `delete` and holds the NOTE lands; a grant that names no
//! `delete`, or whose worlds do not hold the NOTE, is refused
//! `no_delete_grant`. Guard (passes on main too): the same person's erase of
//! the NOTE is refused, and the NOTE stays.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test delete_authority`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole, VerifiedSlip};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::ScopeId;
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember, Scope, ScopeAxis};
use oneiron::memory::{
    EraseOptions, EraseReason, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_OWNER_BINDING_REQUIRED,
    MemoryError, SafeDeleteReason,
};
use oneiron::note::TakeTarget;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::registry::{ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_POLICY_MANIFEST};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_support::{bind_host_actor, bind_host_owner};
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

/// `actor`'s own delete of `note` on the in-process handle: no credential.
fn delete_as(vault: &Vault, actor: EntityId, note: &str) -> Result<bool, MemoryError> {
    vault
        .memory(actor, EdgeActorClass::Human)
        .safe_delete(note, SafeDeleteReason::UserDelete)
        .map(|receipt| receipt.existed)
}

/// A distinct slip id for each credential a test mints.
fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// A rooted shared vault: its owner, an Admin, two Members and a person
/// with no role, and a subject PERSON the NOTEs are about.
struct Shared {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
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
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
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
        issuer,
        owner,
        admin,
        member_a,
        member_b,
        stranger,
        subject,
    }
}

impl Shared {
    /// A NOTE Member A authors about the subject. The fixture binds the host
    /// key to the Member for this one write and then gives it back to the
    /// owner, so the Member holds no binding when it deletes.
    fn member_note(&self) -> String {
        bind_host_actor(&self.vault, &self.issuer, self.member_a, "human")
            .expect("the host key bound to Member A for its write");
        let note = note_by(
            &self.vault,
            self.member_a,
            EdgeActorClass::Human,
            self.subject,
        );
        bind_host_owner(&self.vault, &self.issuer, self.owner).expect("the owner's binding again");
        note
    }

    /// The live `human` credential this host mints `person`, verified as a
    /// transport verifies the slip a request presents.
    fn credential(&self, person: EntityId) -> VerifiedSlip {
        let root = self
            .vault
            .ensure_host_root_slip(&self.issuer)
            .expect("the host root slip");
        let issued_at = self.vault.capability_slip_now().expect("slip clock");
        let mut claims = root.claims;
        claims.slip_id = next_slip_id();
        claims.holder_ref = person.to_hex();
        claims.actor_class = Some("human".into());
        claims.issued_at = issued_at;
        claims.expires_at = issued_at + 3_600;
        claims.ttl_secs = 3_600;
        let slip = self
            .vault
            .mint_capability_slip(&self.issuer, claims)
            .expect("the person's credential");
        let challenge = b"delete-authority";
        let proof = self
            .issuer
            .binding_proof(&slip, challenge)
            .expect("binding proof");
        self.vault
            .verify_capability_slip(&self.issuer.public_key(), &slip, challenge, &proof)
            .expect("a verified credential")
    }

    /// The Owner's membership grant: the parent of the Delegate grants here
    /// (the shipped Admin row names no `delete`, so an Admin's Delegate grant
    /// never does).
    fn owner_grant(&self) -> EntityId {
        self.vault
            .entities_by_type(ENTITY_TYPE_FEDERATION_GRANT)
            .expect("grants")
            .into_iter()
            .find(|id| {
                self.vault
                    .get(id)
                    .expect("grant row")
                    .and_then(|body| oneiron::federation::decode_federation_grant_body(&body).ok())
                    .is_some_and(|grant| {
                        grant.member_ref == self.owner && grant.role == Role::Owner
                    })
            })
            .expect("the Owner's membership grant")
    }

    /// The owner's policy lets a Delegate grant name `delete` beside `read`
    /// (its shipped row names `read` alone).
    fn delegate_default_names_delete(&self) {
        let ids = self
            .vault
            .entities_by_type(ENTITY_TYPE_POLICY_MANIFEST)
            .expect("policy rows");
        assert_eq!(ids.len(), 1, "a fresh vault has one seeded policy manifest");
        let id = ids[0];
        let mut manifest: serde_json::Value =
            rmp_serde::from_slice(&self.vault.get(&id).expect("policy").expect("seeded policy"))
                .expect("decode seeded policy");
        let row = manifest["federation_grant_rows"]
            .as_array_mut()
            .expect("grant policy rows")
            .iter_mut()
            .find(|row| row["kind"] == "role_default" && row["role"] == "delegate")
            .expect("the Delegate role default");
        let mut scope: Scope = serde_json::from_value(row["scope"].clone()).expect("scope");
        scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "delete".to_owned()]));
        row["scope"] = serde_json::to_value(scope).expect("scope");
        self.vault
            .install_owner_policy_manifest(
                &proof(&self.vault, self.owner),
                id,
                rmp_serde::to_vec_named(&manifest).expect("encode policy"),
                self.vault.now_recorded_at(),
            )
            .expect("the owner installs the policy");
    }

    /// The Owner gives `person` a Delegate grant narrowed to `requested`.
    fn delegate(&self, person: EntityId, requested: &Scope) {
        self.vault
            .create_scoped_federation_delegate(
                &proof(&self.vault, self.owner),
                self.owner_grant(),
                person,
                requested,
                self.vault.now_recorded_at() + 3_600,
            )
            .expect("the Owner's Delegate grant");
    }

    /// `person` deletes `note` over its own credential.
    fn delete_with_credential(&self, person: EntityId, note: &str) -> Result<bool, MemoryError> {
        let credential = self.credential(person);
        self.vault
            .memory(person, EdgeActorClass::Human)
            .with_transport_invocation()
            .with_read_proof(&credential)
            .safe_delete(note, SafeDeleteReason::UserDelete)
            .map(|receipt| receipt.existed)
    }
}

#[test]
fn a_member_deletes_its_own_note() {
    let fx = shared();
    let note = fx.member_note();
    let existed = fx
        .delete_with_credential(fx.member_a, &note)
        .unwrap_or_else(|error| {
            panic!(
                "a Member deletes the NOTE it authored: {error:?}; scrubbed: {}",
                deleted(&fx.vault, &note)
            )
        });
    assert!(existed, "the Member's NOTE existed");
    assert!(
        deleted(&fx.vault, &note),
        "the Member's NOTE is a deleted shell"
    );
}

#[test]
fn a_member_is_refused_another_members_note() {
    let fx = shared();
    let note = fx.member_note();
    let error = fx
        .delete_with_credential(fx.member_b, &note)
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
    let note = fx.member_note();
    let existed = fx
        .delete_with_credential(fx.admin, &note)
        .unwrap_or_else(|error| {
            panic!(
                "an Admin deletes in scope: {error:?}; scrubbed: {}",
                deleted(&fx.vault, &note)
            )
        });
    assert!(existed);
    assert!(deleted(&fx.vault, &note), "the NOTE is a deleted shell");
}

#[test]
fn the_owner_deletes_any_note_as_before() {
    let fx = shared();
    let note = fx.member_note();
    let existed = delete_as(&fx.vault, fx.owner, &note)
        .unwrap_or_else(|error| panic!("the owner deletes anything: {error:?}"));
    assert!(existed);
    assert!(deleted(&fx.vault, &note), "the NOTE is a deleted shell");
}

/// UC-03 PR 5b (D2): the owner's own delete is the owner's yes, so its Gate
/// row reads `approved`; a Member's delete the delete authority admitted is
/// the rule letting it go and keeps `allow`. Red on the base for the owner's
/// row (it read `allow`); the Member's row is a guard.
#[test]
fn the_owner_delete_row_reads_approved_and_an_admitted_delete_row_allow() {
    let fx = shared();
    let member_note = fx.member_note();
    let owner_note = fx.member_note();
    let member_deleted = fx
        .delete_with_credential(fx.member_a, &member_note)
        .unwrap_or_else(|error| panic!("a Member deletes its own NOTE: {error:?}"));
    assert!(member_deleted);
    let owner_deleted = delete_as(&fx.vault, fx.owner, &owner_note)
        .unwrap_or_else(|error| panic!("the owner deletes the NOTE: {error:?}"));
    assert!(owner_deleted);
    let rows: Vec<(Option<String>, String, Vec<String>)> = fx
        .vault
        .gate_decisions(64)
        .expect("gate decisions")
        .into_iter()
        .filter(|row| row.content_kind == "deletion")
        .map(|row| (row.actor_ref, row.outcome, row.reason_codes))
        .collect();
    let rows_of = |actor: EntityId| -> Vec<(String, Vec<String>)> {
        rows.iter()
            .filter(|(actor_ref, _, _)| actor_ref.as_deref() == Some(actor.to_hex().as_str()))
            .map(|(_, outcome, reasons)| (outcome.clone(), reasons.clone()))
            .collect()
    };
    assert_eq!(
        rows_of(fx.owner),
        [(
            "approved".to_owned(),
            vec!["gate.allow.owner_delete".to_owned()]
        )],
        "the owner's delete row: {rows:?}"
    );
    assert_eq!(
        rows_of(fx.member_a),
        [(
            "allow".to_owned(),
            vec!["gate.allow.delete_member".to_owned()]
        )],
        "the Member's admitted delete row: {rows:?}"
    );
}

#[test]
fn a_person_with_no_role_keeps_the_owner_refusal() {
    let fx = shared();
    let note = fx.member_note();
    let error = fx
        .delete_with_credential(fx.stranger, &note)
        .expect_err("a person with no role in the vault is refused, credential or not");
    assert_eq!(error.code, MEMORY_CODE_OWNER_BINDING_REQUIRED, "{error:?}");
    assert!(!deleted(&fx.vault, &note), "the refused NOTE is untouched");
}

#[test]
fn a_member_with_no_credential_keeps_the_owner_refusal() {
    let fx = shared();
    let note = fx.member_note();
    let error = delete_as(&fx.vault, fx.member_a, &note)
        .expect_err("a Member with no binding and no credential is no one here");
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
    let receipt = agent_deletes(&fx.vault, fx.granted, &note).unwrap_or_else(|error| {
        panic!(
            "an agent under a delete Grant deletes: {error:?}; scrubbed: {}",
            deleted(&fx.vault, &note)
        )
    });
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

/// `verbs` over every world.
fn delegate_scope(verbs: &[&str]) -> Scope {
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(verbs.iter().map(|verb| (*verb).to_owned()).collect());
    scope
}

/// `refused` is the typed `no_delete_grant` refusal, and `note` stands.
fn assert_no_delete_grant(fx: &Shared, refused: Result<bool, MemoryError>, note: &str) {
    let error = refused.expect_err("the Delegate's delete is refused");
    assert_eq!(error.code, MEMORY_CODE_FORBIDDEN, "{error:?}");
    assert!(
        error.message.starts_with("no_delete_grant:"),
        "the refusal names its reason: {error:?}"
    );
    assert!(!deleted(&fx.vault, note), "the refused NOTE is untouched");
}

#[test]
fn a_persons_delegate_grant_that_names_delete_deletes_in_scope() {
    let fx = shared();
    fx.delegate_default_names_delete();
    fx.delegate(fx.stranger, &delegate_scope(&["read", "delete"]));
    let note = fx.member_note();
    let existed = fx
        .delete_with_credential(fx.stranger, &note)
        .unwrap_or_else(|error| panic!("a Delegate grant that names delete deletes: {error:?}"));
    assert!(existed, "the NOTE existed");
    assert!(deleted(&fx.vault, &note), "the NOTE is a deleted shell");
}

#[test]
fn a_persons_delegate_grant_that_names_no_delete_is_refused() {
    let fx = shared();
    fx.delegate(fx.stranger, &delegate_scope(&["read"]));
    let note = fx.member_note();
    assert_no_delete_grant(&fx, fx.delete_with_credential(fx.stranger, &note), &note);
}

#[test]
fn a_persons_delegate_grant_out_of_scope_is_refused() {
    let fx = shared();
    fx.delegate_default_names_delete();
    let mut elsewhere = delegate_scope(&["read", "delete"]);
    elsewhere.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(EntityId::now())]));
    fx.delegate(fx.stranger, &elsewhere);
    let note = fx.member_note();
    assert_no_delete_grant(&fx, fx.delete_with_credential(fx.stranger, &note), &note);
}

#[test]
fn a_persons_delegate_grant_does_not_erase() {
    let fx = shared();
    fx.delegate_default_names_delete();
    fx.delegate(fx.stranger, &delegate_scope(&["read", "delete"]));
    let note = fx.member_note();
    let credential = fx.credential(fx.stranger);
    let memory = fx
        .vault
        .memory(fx.stranger, EdgeActorClass::Human)
        .with_transport_invocation()
        .with_read_proof(&credential);
    let id = EntityId::from_hex(&note).expect("note id");
    let erased = memory.preview_entity_delete(&id).and_then(|preview| {
        memory.confirm_entity_erase(
            &preview,
            EraseOptions {
                reason: EraseReason::OwnerErase,
                also_same_bytes: false,
                veto_starter: None,
            },
        )
    });
    assert!(erased.is_err(), "erase stays the Owner's own act");
    assert!(!deleted(&fx.vault, &note), "the NOTE stands");
}
