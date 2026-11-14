//! OWNER-ENROL (Engine TASK 14 Nov 16:10), part 1: a member whose Owner
//! standing ends keeps no owner key and no `human` binding on the shared
//! vault's authority log, whatever role they keep, and neither does a member
//! who leaves (OWNER-ENROL-TRANSFER-REVOKE = A, the lead 16:2x). A co-Owner
//! may enrol an owner signing key of their own: the door admits every live
//! Owner, and the key lands on the roster as an owner root. On main nothing
//! revoked it. A removed Owner, or one who handed ownership on and stayed as
//! Admin, kept that live root, which signs any authority entry, and with a
//! binding on it they kept every owner verb. Now the membership move that
//! ends their Owner standing revokes each live key whose enrolment names
//! them, which ends the binding on it, and each other live `human` binding
//! that names them, under the issuer that signs the move.
//!
//! Red on main: `a_removed_owner_keeps_no_owner_key_or_binding` and
//! `an_owner_who_hands_ownership_on_and_stays_as_admin_keeps_no_owner_key`
//! (the key stays live, and the owner verb still passes). Guard, which passes
//! on main too: `removing_another_owner_leaves_an_owners_key_and_binding`.
//!
//! Part 2: an added Owner's first owner key binds them as `human` in the
//! enrolment's transaction, signed by the enrolment's predecessor, on a
//! self-hosted vault (BIND-TIMING, BIND-SIGNER and OP-SHAPE = A, the Engine
//! 16:23; KEY-ORIGIN = A, the lead 16:2x). Red before it:
//! `an_added_owners_first_owner_key_binds_them` (the added Owner's owner verb
//! answers OWNER_BINDING_REQUIRED). Guard: an Owner a binding names already,
//! the embedded owner included, gains no second one.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test owner_enrol`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    ActAuthority, ActSurface, ActorBindingStatus, AuthorityKey, HostSlipIssuer, MachineRole,
    OwnerKeyEnrollment,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember};
use oneiron::memory::MEMORY_CODE_OWNER_BINDING_REQUIRED;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::test_support::bind_host_owner;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

const SHARED: u64 = 44;

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

/// A rooted shared vault whose embedded owner the host root binds, with a
/// second Owner the owner added.
struct Shared {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    co_owner: EntityId,
}

fn shared() -> Shared {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    // An owner key enrolment is carried by this install's live machine
    // profile, as every owner act is.
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
    vault
        .initialize_shared_vault(
            &proof(&vault, owner),
            SHARED,
            None,
            &[InitialSharedMember {
                member_ref: owner,
                role: Some(Role::Owner),
            }],
            1,
        )
        .expect("a shared vault");
    let co_owner = add_owner(&vault, &issuer, owner);
    Shared {
        _dir: dir,
        vault,
        issuer,
        owner,
        co_owner,
    }
}

/// A new person `owner` adds as an Owner; the add is instant.
fn add_owner(vault: &Vault, issuer: &HostSlipIssuer, owner: EntityId) -> EntityId {
    let added = person(vault);
    let owner_proof = proof(vault, owner);
    let act = vault
        .propose_add_owner(&owner_proof, SHARED, added)
        .expect("the owner starts add_owner");
    vault
        .execute_completed_shared_act(&owner_proof, &act.id, Some(issuer))
        .expect("add_owner runs at once");
    added
}

impl Shared {
    /// The owner removes `target`, who leaves the vault.
    fn remove_owner(&self, target: EntityId) {
        let owner_proof = proof(&self.vault, self.owner);
        let act = self
            .vault
            .propose_remove_owner(&owner_proof, SHARED, target, None, None, false)
            .expect("the owner starts remove_owner");
        self.vault
            .execute_completed_shared_act(&owner_proof, &act.id, Some(&self.issuer))
            .expect("remove_owner runs at once");
    }

    /// `person` enrols an owner signing key of their own, made from `seed`,
    /// through the owner-signing-key door, which signs with this host's root
    /// as its predecessor. Answers the key.
    fn enrol_owner_key(&self, person: EntityId, seed: u8) -> [u8; 32] {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let public_key = key.verifying_key().to_bytes();
        let machine = self
            .vault
            .prepare_install_signing()
            .expect("this install's machine");
        let authority = ActAuthority::Owner(proof(&self.vault, person), ActSurface::ThisInstall);
        let challenge = self
            .vault
            .owner_key_enrollment_challenge_as(&authority, machine, &public_key)
            .expect("the enrolment challenge");
        let input = OwnerKeyEnrollment {
            machine,
            public_key,
            proof: key.sign(&challenge).to_bytes().to_vec(),
        };
        self.vault
            .enrol_owner_signing_key_as_host(&authority, input, &self.issuer)
            .expect("an Owner enrols an owner key of their own");
        public_key
    }

    fn key_is_live(&self, public_key: [u8; 32]) -> bool {
        self.vault
            .enrolled_owner_keys()
            .expect("the enrolled keys")
            .into_iter()
            .find(|key| key.public_key == public_key)
            .expect("the key is listed")
            .live
    }

    /// The person a live `human` binding on `public_key` names, if any.
    fn bound_to(&self, public_key: [u8; 32]) -> Option<EntityId> {
        self.vault
            .authority_fold()
            .expect("the fold")
            .actor_bindings
            .get(&AuthorityKey::Ed25519(public_key))
            .filter(|binding| {
                binding.status == ActorBindingStatus::Active && binding.actor_class == "human"
            })
            .map(|binding| binding.actor_ref)
    }

    fn passes_owner_verbs(&self, person: EntityId) -> bool {
        match self
            .vault
            .memory(person, EdgeActorClass::Human)
            .verify_owner()
        {
            Ok(()) => true,
            Err(error) => {
                assert_eq!(error.code, MEMORY_CODE_OWNER_BINDING_REQUIRED, "{error:?}");
                false
            }
        }
    }

    /// The co-Owner's own key, enrolled, which binds them.
    fn bound_co_owner_key(&self) -> [u8; 32] {
        let key = self.enrol_owner_key(self.co_owner, 7);
        assert!(self.key_is_live(key), "the enrolled key is live");
        assert!(
            self.passes_owner_verbs(self.co_owner),
            "a bound co-Owner passes the owner verbs"
        );
        key
    }
}

#[test]
fn a_removed_owner_keeps_no_owner_key_or_binding() {
    let shared = shared();
    let key = shared.bound_co_owner_key();

    shared.remove_owner(shared.co_owner);

    assert!(
        !shared.key_is_live(key),
        "the removed Owner's own owner key is revoked with the removal"
    );
    assert!(
        !shared.passes_owner_verbs(shared.co_owner),
        "the removed Owner's binding ends with their key"
    );
    assert!(
        shared.passes_owner_verbs(shared.owner),
        "the Owner who stays keeps the host root's binding"
    );
}

#[test]
fn removing_another_owner_leaves_an_owners_key_and_binding() {
    let shared = shared();
    let key = shared.bound_co_owner_key();
    let third = add_owner(&shared.vault, &shared.issuer, shared.owner);

    shared.remove_owner(third);

    assert!(
        shared.key_is_live(key),
        "the co-Owner who stays keeps their key"
    );
    assert!(
        shared.passes_owner_verbs(shared.co_owner),
        "the co-Owner who stays keeps their binding"
    );
    assert!(
        shared.passes_owner_verbs(shared.owner),
        "the embedded owner keeps the host root's binding"
    );
}

#[test]
fn an_owner_who_hands_ownership_on_and_stays_as_admin_keeps_no_owner_key() {
    let shared = shared();
    let key = shared.bound_co_owner_key();
    let successor = person(&shared.vault);
    let co_owner_proof = proof(&shared.vault, shared.co_owner);
    let act = shared
        .vault
        .propose_transfer_ownership(&co_owner_proof, SHARED, successor, Some(Role::Admin))
        .expect("the co-Owner starts transfer_ownership");
    shared
        .vault
        .execute_completed_shared_act(&co_owner_proof, &act.id, Some(&shared.issuer))
        .expect("transfer_ownership runs at once");

    assert!(
        !shared.key_is_live(key),
        "the former Owner's own owner key retires with their Owner standing"
    );
    assert!(
        !shared.passes_owner_verbs(shared.co_owner),
        "the former Owner, now an Admin, passes no owner verb"
    );
    assert!(
        shared.passes_owner_verbs(shared.owner),
        "the Owner who stays keeps the host root's binding"
    );
}

#[test]
fn an_added_owners_first_owner_key_binds_them() {
    let shared = shared();
    assert!(
        !shared.passes_owner_verbs(shared.co_owner),
        "an added Owner holds no binding before their first owner key"
    );

    let key = shared.enrol_owner_key(shared.co_owner, 7);

    assert_eq!(
        shared.bound_to(key),
        Some(shared.co_owner),
        "the added Owner's first owner key is bound to them"
    );
    assert!(
        shared.passes_owner_verbs(shared.co_owner),
        "the added Owner passes the owner verbs"
    );
    assert!(
        shared.passes_owner_verbs(shared.owner),
        "the first owner keeps the host root's binding"
    );
    let second = shared.enrol_owner_key(shared.co_owner, 8);
    assert!(shared.key_is_live(second), "a second owner key enrols");
    assert_eq!(
        shared.bound_to(second),
        None,
        "an Owner a live binding names gains no second one"
    );
}

#[test]
fn the_embedded_owners_enrolled_key_binds_no_one() {
    let shared = shared();

    let key = shared.enrol_owner_key(shared.owner, 9);

    assert!(shared.key_is_live(key), "the embedded owner's key enrols");
    assert_eq!(
        shared.bound_to(key),
        None,
        "the host root binds the embedded owner already"
    );
    assert!(shared.passes_owner_verbs(shared.owner));
}
