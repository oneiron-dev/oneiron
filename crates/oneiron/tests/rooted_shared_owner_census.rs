//! [CLAIM-RETRACT-HUMAN-BINDING-IS-NOT-OWNERSHIP] (Engine ANSWER 17 Nov
//! 00:11, CLAIM-RETRACT-ADMIN-SCOPE = A): on a ROOTED vault the owner-verb
//! rule passed any actor with an active `human` binding in the authority log.
//! A human binding names who acts under the root, not who owns the vault: a
//! shared vault's Admin or Delegate can hold one, and so can a co-owner whose
//! binding outlived its Owner standing. So such an Admin retracted another
//! author's claim and deleted as "the owner". The rule now asks the vault's
//! live owner census after the binding, as the unrooted arm does since
//! UNROOTED-OWNER-CENSUS = A and as `memory::authorship::is_root_owner` does:
//! a shared vault's live Owner-role members, and on a personal vault its live
//! embedded owner. An Admin keeps deleting in scope through the role delete
//! authority (DEL-2 = A, ARCH-0043: "Admins delete in scope, and Owners
//! delete anything"); an Admin's cross-author retract has no role arm.
//!
//! No product door binds a non-Owner as `human` (the host root binds the
//! embedded owner, an owner key enrolment binds a live Owner, and a move that
//! ends Owner standing revokes the binding or is refused). The bindings here
//! come from the host root's test binder, as a binding signed elsewhere and
//! synced in would arrive: the fold checks the signing key, not the census.
//!
//! Red on main: `an_admin_with_a_human_binding_retracts_no_other_authors_claim`,
//! `a_co_owner_made_an_admin_with_a_left_over_binding_retracts_no_claim`,
//! `an_admin_with_a_human_binding_deletes_in_scope_as_an_admin`
//! (its delete row reads the owner's `approved` on main) and
//! `a_bound_person_who_is_not_a_personal_vaults_owner_holds_no_owner_verb`.
//! Guard (passes on main too): `the_owner_retracts_a_co_owners_claim`.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --no-fail-fast --test rooted_shared_owner_census`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use oneiron::authority::{HostSlipIssuer, VerifiedSlip};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember};
use oneiron::memory::{
    ClaimInput, MEMORY_CODE_OWNER_BINDING_REQUIRED, MemoryError, SafeDeleteReason,
};
use oneiron::note::TakeTarget;
use oneiron::registry::{ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::test_support::{bind_host_actor, bind_host_owner};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::json;

const SHARED: u64 = 45;

/// How the owner-verb rule refuses a bound actor the census does not name.
const NOT_A_LIVE_OWNER: &str = "is not a live Owner of this vault";

/// The reason the owner's own delete row carries (UC-03 PR 5b).
const OWNER_DELETE_REASON: &str = "gate.allow.owner_delete";

fn person(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
    id
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

/// The role `member` holds in the shared vault now, read from its grant rows.
fn role_of(vault: &Vault, member: EntityId) -> Option<Role> {
    vault
        .entities_by_type(ENTITY_TYPE_FEDERATION_GRANT)
        .expect("grants")
        .into_iter()
        .find_map(|id| {
            let body = vault.get(&id).expect("grant row")?;
            let grant = oneiron::federation::decode_federation_grant_body(&body).ok()?;
            (grant.member_ref == member && grant.role != Role::Delegate).then_some(grant.role)
        })
}

/// The owner verbs' own check for `person`.
fn owner_check(vault: &Vault, person: EntityId) -> Result<(), MemoryError> {
    vault.memory(person, EdgeActorClass::Human).verify_owner()
}

/// Asserts `error` is the census refusal of a bound actor.
fn assert_census_refusal(error: &MemoryError) {
    assert_eq!(error.code, MEMORY_CODE_OWNER_BINDING_REQUIRED, "{error:?}");
    assert!(
        error.message.contains(NOT_A_LIVE_OWNER),
        "the refusal names the census: {error:?}"
    );
}

/// A distinct slip id for each credential a test mints.
fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// A rooted shared vault: its embedded owner, whom the host root binds, a
/// second Owner the owner added, an Admin, a Member, and a subject PERSON the
/// claims and NOTEs are about.
struct Shared {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    co_owner: EntityId,
    admin: EntityId,
    member: EntityId,
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
    let [admin, member, subject] = std::array::from_fn(|_| person(&vault));
    let seat = |member_ref, role| InitialSharedMember {
        member_ref,
        role: Some(role),
    };
    vault
        .initialize_shared_vault(
            &proof(&vault, owner),
            SHARED,
            None,
            &[
                seat(owner, Role::Owner),
                seat(admin, Role::Admin),
                seat(member, Role::Member),
            ],
            1,
        )
        .expect("a shared vault with an Admin and a Member");
    accept(&vault, admin, Role::Admin);
    accept(&vault, member, Role::Member);
    let co_owner = person(&vault);
    let owner_proof = proof(&vault, owner);
    let act = vault
        .propose_add_owner(&owner_proof, SHARED, co_owner)
        .expect("the owner starts add_owner");
    vault
        .execute_completed_shared_act(&owner_proof, &act.id, Some(&issuer))
        .expect("add_owner runs at once");
    assert_eq!(role_of(&vault, co_owner), Some(Role::Owner));
    assert_eq!(role_of(&vault, admin), Some(Role::Admin));
    Shared {
        _dir: dir,
        vault,
        issuer,
        owner,
        co_owner,
        admin,
        member,
        subject,
    }
}

impl Shared {
    /// Binds the host root's key to `actor` as `human`: the binding an Admin
    /// or a former Owner holds in these cases. The host key holds one live
    /// binding, so the owner's ends until [`Self::bind_the_owner_again`].
    fn bind_as_human(&self, actor: EntityId) {
        bind_host_actor(&self.vault, &self.issuer, actor, "human")
            .expect("the host key bound to the actor as human");
    }

    fn bind_the_owner_again(&self) {
        bind_host_owner(&self.vault, &self.issuer, self.owner).expect("the owner's binding again");
    }

    /// A claim `author` writes about the subject, by its full hex ref. The
    /// host key is bound to `author` for this one write and then given back
    /// to the owner.
    fn claim_by(&self, author: EntityId) -> String {
        self.bind_as_human(author);
        let facet = self.vault.default_facet().expect("default facet");
        let id = EntityId::now().to_hex();
        let input = ClaimInput {
            id: Some(id.clone()),
            predicate: "profile.note".to_owned(),
            subject_ref: self.subject.to_hex(),
            value: json!("a note about the subject"),
            confidence: 1.0,
            confidence_details: None,
            source: "user_stated".to_owned(),
            world_ref: None,
            relationship_ref: None,
            scope: Some(json!({ "facet": facet.to_hex() })),
            valid_from: None,
            valid_to: None,
            occurred_at: None,
            learned_at: None,
            salience: None,
        };
        self.vault
            .memory(author, EdgeActorClass::Human)
            .claim_propose(&input)
            .expect("the author writes a claim");
        self.bind_the_owner_again();
        id
    }

    /// A NOTE the Member authors about the subject, written as
    /// [`Self::claim_by`] writes a claim.
    fn member_note(&self) -> String {
        self.bind_as_human(self.member);
        let note = self
            .vault
            .memory(self.member, EdgeActorClass::Human)
            .author_take(
                TakeTarget::Subject(self.subject),
                "a take about the subject",
            )
            .expect("the Member authors a NOTE")
            .id_hex;
        self.bind_the_owner_again();
        note
    }

    /// The owner makes the co-Owner an Admin through `remove_owner`, which
    /// runs at once under its zero wait. The host root signs the move, so it
    /// revokes every owner key and binding that names the co-Owner.
    fn owner_demotes_the_co_owner(&self) {
        let owner_proof = proof(&self.vault, self.owner);
        let act = self
            .vault
            .propose_remove_owner(
                &owner_proof,
                SHARED,
                self.co_owner,
                None,
                Some(Role::Admin),
                false,
            )
            .expect("the owner starts remove_owner, the co-Owner keeping Admin");
        self.vault
            .execute_completed_shared_act(&owner_proof, &act.id, Some(&self.issuer))
            .expect("remove_owner runs");
        assert_eq!(
            role_of(&self.vault, self.co_owner),
            Some(Role::Admin),
            "the co-Owner is an Admin now"
        );
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
        let challenge = b"rooted-owner-census";
        let proof = self
            .issuer
            .binding_proof(&slip, challenge)
            .expect("binding proof");
        self.vault
            .verify_capability_slip(&self.issuer.public_key(), &slip, challenge, &proof)
            .expect("a verified credential")
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

    fn deleted(&self, note: &str) -> bool {
        self.vault
            .is_deleted_shell(&EntityId::from_hex(note).expect("note id"))
            .expect("shell read")
    }

    /// The deletion Gate rows `actor` wrote: (outcome, reason codes).
    fn delete_rows_of(&self, actor: EntityId) -> Vec<(String, Vec<String>)> {
        self.vault
            .gate_decisions(64)
            .expect("gate decisions")
            .into_iter()
            .filter(|row| {
                row.content_kind == "deletion"
                    && row.actor_ref.as_deref() == Some(actor.to_hex().as_str())
            })
            .map(|row| (row.outcome, row.reason_codes))
            .collect()
    }
}

/// The finding (Astra keptfix-memverbs T1): an Admin whose `human` binding
/// is active retracted a claim the owner wrote, recorded as the owner's
/// explicit retraction. The census now refuses it.
#[test]
fn an_admin_with_a_human_binding_retracts_no_other_authors_claim() {
    let fx = shared();
    let claim = fx.claim_by(fx.owner);
    fx.bind_as_human(fx.admin);

    let retracted = fx
        .vault
        .memory(fx.admin, EdgeActorClass::Human)
        .claim_retract(&claim);

    let refused = retracted.expect_err("an Admin retracts no claim another author wrote");
    assert_census_refusal(&refused);
    assert_census_refusal(
        &owner_check(&fx.vault, fx.admin).expect_err("a bound Admin holds no owner verb"),
    );
}

/// Astra census-l2-8106 F4: a co-Owner the owner made an Admin, whose
/// `human` binding outlived its Owner standing, still passed every owner
/// verb. The move that demotes it revokes its bindings when the host root
/// signs it; the binding here is the one a move without that revocation
/// would leave.
#[test]
fn a_co_owner_made_an_admin_with_a_left_over_binding_retracts_no_claim() {
    let fx = shared();
    let claim = fx.claim_by(fx.owner);
    fx.owner_demotes_the_co_owner();
    fx.bind_as_human(fx.co_owner);

    let retracted = fx
        .vault
        .memory(fx.co_owner, EdgeActorClass::Human)
        .claim_retract(&claim);

    let refused = retracted.expect_err("a former Owner retracts no claim another author wrote");
    assert_census_refusal(&refused);
}

/// Guard: a live Owner the host root binds retracts a claim another Owner
/// wrote, as before.
#[test]
fn the_owner_retracts_a_co_owners_claim() {
    let fx = shared();
    let claim = fx.claim_by(fx.co_owner);

    fx.vault
        .memory(fx.owner, EdgeActorClass::Human)
        .claim_retract(&claim)
        .unwrap_or_else(|error| panic!("a live Owner retracts another author's claim: {error:?}"));
    owner_check(&fx.vault, fx.owner).expect("a live, bound Owner passes the owner verbs");
}

/// An Admin with a `human` binding still deletes a Member's NOTE in its
/// scope, now through the role delete authority: its delete row is the
/// rule's `allow`, not the owner's `approved` (red on main, where the binding
/// took the owner path).
#[test]
fn an_admin_with_a_human_binding_deletes_in_scope_as_an_admin() {
    let fx = shared();
    let note = fx.member_note();
    fx.bind_as_human(fx.admin);

    let existed = fx
        .delete_with_credential(fx.admin, &note)
        .unwrap_or_else(|error| {
            panic!(
                "an Admin deletes in scope: {error:?}; scrubbed: {}",
                fx.deleted(&note)
            )
        });

    assert!(existed, "the Member's NOTE existed");
    assert!(fx.deleted(&note), "the NOTE is a deleted shell");
    let rows = fx.delete_rows_of(fx.admin);
    assert_eq!(rows.len(), 1, "one delete row: {rows:?}");
    let (outcome, reasons) = &rows[0];
    assert_eq!(
        outcome, "allow",
        "the delete authority admitted the Admin: {rows:?}"
    );
    assert!(
        !reasons.iter().any(|reason| reason == OWNER_DELETE_REASON),
        "the Admin did not delete as the owner: {rows:?}"
    );
}

/// The personal side of the census: on a rooted personal vault the live
/// embedded owner is the owner, and another person the authority log binds
/// as `human` holds no owner verb.
#[test]
fn a_bound_person_who_is_not_a_personal_vaults_owner_holds_no_owner_verb() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
    owner_check(&vault, owner).expect("the bound embedded owner passes");
    let other = person(&vault);

    bind_host_actor(&vault, &issuer, other, "human").expect("another person bound as human");

    assert_census_refusal(
        &owner_check(&vault, other).expect_err("a bound person who is not the owner"),
    );
}
