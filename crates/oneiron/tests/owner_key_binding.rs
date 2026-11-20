//! HOSTED-RELAY-OWNER-HUMAN-BIND-CEREMONY (lead ruling B, Sat 21 Nov 04:3x):
//! an Owner of a hosted or relay vault binds themselves, as `human`, to an
//! owner device key of theirs, and that key signs the binding.
//!
//! A hosted vault's enrolment predecessor is the custodial host root, and the
//! hosted fold counts no `human` binding that only a key in the host's
//! custody signs, so the enrolment binds no one; a relay vault holds no root
//! of its own, and its enrolment binds no one either. Until a binding names
//! them, the Owner's owner verbs answer OWNER_BINDING_REQUIRED
//! (`Memory::verify_owner`, through `verify_owner_actor_binding_in_txn`).
//! The two-step door binds them: `prepare_owner_key_binding_as` builds
//! `BindActor{K, owner, human}` with K as its one signer, the device signs the
//! transcript with K, and `land_owner_key_binding_as` lands it once the fold
//! counted it. These tests call the door, so they run on the head only; the
//! red/green pair through the owner routes is the server's
//! `owner_key_binding_routes`.
//!
//! - `a_hosted_vaults_first_owner_binds_with_their_device_key` and
//!   `a_hosted_vaults_added_owner_binds_with_their_device_key`: unbound after
//!   enrolment, OWNER_BINDING_REQUIRED; bound after the door, the owner verb
//!   passes.
//! - `a_relay_vaults_added_owner_binds_with_their_device_key`: a vault whose
//!   owner-origin root a self-host install minted, served as a relay.
//! - Refusals, each leaving the owner unbound:
//!   `a_signature_by_another_key_binds_no_one`,
//!   `an_owner_binds_no_key_enrolled_for_another_owner`,
//!   `a_binding_prepared_for_one_owner_lands_for_no_other`,
//!   `a_bound_owner_binds_no_second_key`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test owner_key_binding`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    ActAuthority, ActSurface, ActorBindingStatus, AuthorityKey, HostSlipIssuer, MachineRole,
    OwnerKeyEnrollment, PreparedOwnerKeyBinding,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::error::RecordError;
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember};
use oneiron::memory::MEMORY_CODE_OWNER_BINDING_REQUIRED;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::{EdgeActorClass, EntityId, HostingPrivacyPosture, Vault, VaultConfig};

const SHARED: u64 = 47;
/// The seed of the owner's own owner key, on a device of theirs.
const OWNER_SEED: u8 = 7;
/// The seed of the co-Owner's owner key, on a device of theirs.
const CO_OWNER_SEED: u8 = 9;
/// The seed of a key the binding names no one for.
const STRANGER_SEED: u8 = 13;
/// The seed of the owner's second owner key.
const OWNER_SECOND_SEED: u8 = 15;

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

fn as_owner(vault: &Vault, person: EntityId) -> ActAuthority {
    ActAuthority::Owner(proof(vault, person), ActSurface::ThisInstall)
}

fn device_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn public(key: &SigningKey) -> [u8; 32] {
    key.verifying_key().to_bytes()
}

/// A shared vault, an owner and a co-Owner they added, served under a posture
/// whose enrolment binds no one.
struct Served {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    co_owner: EntityId,
}

/// A shared vault as a managed host serves it: the Hosted posture, rooted
/// under the host's custodial root, this install profiled, the embedded owner
/// bound by no one, and a co-Owner the owner added.
fn hosted() -> Served {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.privacy.posture = HostingPrivacyPosture::Hosted;
    let vault = Vault::open(dir.path(), config).expect("hosted vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    share(&vault, owner);
    let co_owner = add_owner(&vault, &issuer, owner);
    Served {
        _dir: dir,
        vault,
        issuer,
        owner,
        co_owner,
    }
}

/// A shared vault rooted by a self-host install, whose root binds its
/// embedded owner, with a co-Owner who holds no owner key yet, then served
/// on the same keystore as a relay. Its root is owner-origin, so the relay
/// fold counts what it signs.
fn relay() -> Served {
    let dir = tempfile::tempdir().expect("tempdir");
    let keystore = Arc::new(oneiron_keystore::MemoryKeystore::default());
    let (issuer, owner, co_owner) = {
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("self-host vault");
        vault.install_device_keystore(keystore.clone());
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's live machine profile");
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        oneiron::test_support::bind_host_owner(&vault, &issuer, owner)
            .expect("the owner's binding");
        share(&vault, owner);
        let co_owner = add_owner(&vault, &issuer, owner);
        (issuer, owner, co_owner)
    };
    let mut config = VaultConfig::device();
    config.privacy.posture = HostingPrivacyPosture::Relay;
    let vault = Vault::open(dir.path(), config).expect("the vault served as a relay");
    vault.install_device_keystore(keystore);
    Served {
        _dir: dir,
        vault,
        issuer,
        owner,
        co_owner,
    }
}

/// `owner` makes the vault a shared vault with themselves as its one Owner.
fn share(vault: &Vault, owner: EntityId) {
    vault
        .initialize_shared_vault(
            &proof(vault, owner),
            SHARED,
            None,
            &[InitialSharedMember {
                member_ref: owner,
                role: Some(Role::Owner),
            }],
            1,
        )
        .expect("a shared vault");
}

/// The owner adds a new person as an Owner; answers them.
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

impl Served {
    /// `person` enrols the owner key of a device of theirs, made from `seed`,
    /// with the host's root as its predecessor. This install never holds it.
    fn enrol_device_key(&self, person: EntityId, seed: u8) -> SigningKey {
        let key = device_key(seed);
        let public_key = public(&key);
        let machine = self
            .vault
            .prepare_install_signing()
            .expect("this install's machine");
        let authority = as_owner(&self.vault, person);
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
        key
    }

    /// `person`'s binding to `key`, prepared.
    fn prepare(
        &self,
        person: EntityId,
        key: &SigningKey,
    ) -> oneiron::Result<PreparedOwnerKeyBinding> {
        self.vault
            .prepare_owner_key_binding_as(&as_owner(&self.vault, person), public(key))
    }

    /// `person` lands `prepared` with `signer`'s signature over its transcript.
    fn land(
        &self,
        person: EntityId,
        prepared: &PreparedOwnerKeyBinding,
        signer: &SigningKey,
    ) -> oneiron::Result<oneiron::authority::OwnerKeyBindingReceipt> {
        self.vault.land_owner_key_binding_as(
            &as_owner(&self.vault, person),
            &prepared.entry,
            signer.sign(&prepared.transcript).to_bytes().to_vec(),
        )
    }

    /// The person a live `human` binding on `key` names, if any.
    fn bound_to(&self, key: &SigningKey) -> Option<EntityId> {
        self.vault
            .authority_fold()
            .expect("the fold")
            .actor_bindings
            .get(&AuthorityKey::Ed25519(public(key)))
            .filter(|binding| {
                binding.status == ActorBindingStatus::Active && binding.actor_class == "human"
            })
            .map(|binding| binding.actor_ref)
    }

    /// Whether `person`'s owner verbs pass; an unbound Owner's answer
    /// OWNER_BINDING_REQUIRED.
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

    /// `person` enrols a device key from `seed`, which leaves them unbound,
    /// then binds with it; answers the key.
    fn enrol_and_bind(&self, person: EntityId, seed: u8) -> SigningKey {
        let key = self.enrol_device_key(person, seed);
        assert_eq!(self.bound_to(&key), None, "the enrolment binds no one");
        assert!(
            !self.passes_owner_verbs(person),
            "an unbound Owner's owner verbs answer OWNER_BINDING_REQUIRED"
        );
        let prepared = self.prepare(person, &key).expect("the binding is prepared");
        let receipt = self
            .land(person, &prepared, &key)
            .expect("the key's own binding lands");
        assert_eq!(receipt.owner, person, "the receipt names the owner");
        assert_eq!(
            receipt.public_key,
            public(&key),
            "the receipt names the key"
        );
        assert_eq!(receipt.epoch, 1, "a fresh key's binding is its first");
        key
    }
}

fn assert_refused(result: oneiron::Result<impl std::fmt::Debug>) {
    match result {
        Err(oneiron::Error::Record(RecordError::AuthorityRefused(_))) => {}
        other => panic!("expected an authority refusal, saw {other:?}"),
    }
}

fn assert_not_valid(result: oneiron::Result<impl std::fmt::Debug>) {
    match result {
        Err(oneiron::Error::Record(RecordError::InvalidAuthorityLogBody(_))) => {}
        other => panic!("expected an integrity refusal, saw {other:?}"),
    }
}

#[test]
fn a_hosted_vaults_first_owner_binds_with_their_device_key() {
    let served = hosted();
    let key = served.enrol_and_bind(served.owner, OWNER_SEED);
    assert_eq!(
        served.bound_to(&key),
        Some(served.owner),
        "the key binds the owner"
    );
    assert!(
        served.passes_owner_verbs(served.owner),
        "the bound owner's owner verbs pass"
    );
    assert!(
        !served.passes_owner_verbs(served.co_owner),
        "the owner's binding binds no other Owner"
    );
}

#[test]
fn a_hosted_vaults_added_owner_binds_with_their_device_key() {
    let served = hosted();
    let key = served.enrol_and_bind(served.co_owner, CO_OWNER_SEED);
    assert_eq!(
        served.bound_to(&key),
        Some(served.co_owner),
        "the key binds the co-Owner"
    );
    assert!(
        served.passes_owner_verbs(served.co_owner),
        "the bound co-Owner's owner verbs pass"
    );
}

#[test]
fn a_relay_vaults_added_owner_binds_with_their_device_key() {
    let served = relay();
    assert_eq!(
        served.vault.privacy_posture(),
        HostingPrivacyPosture::Relay,
        "the vault serves as a relay"
    );
    let key = served.enrol_and_bind(served.co_owner, CO_OWNER_SEED);
    assert_eq!(
        served.bound_to(&key),
        Some(served.co_owner),
        "the key binds the co-Owner"
    );
    assert!(
        served.passes_owner_verbs(served.co_owner),
        "the bound co-Owner's owner verbs pass"
    );
}

#[test]
fn a_signature_by_another_key_binds_no_one() {
    let served = hosted();
    let key = served.enrol_device_key(served.owner, OWNER_SEED);
    let prepared = served
        .prepare(served.owner, &key)
        .expect("the binding is prepared");
    assert_not_valid(served.land(served.owner, &prepared, &device_key(STRANGER_SEED)));
    assert_eq!(served.bound_to(&key), None, "nothing was bound");
    assert!(
        !served.passes_owner_verbs(served.owner),
        "the owner stays unbound"
    );
    served
        .land(served.owner, &prepared, &key)
        .expect("the key's own signature still lands the binding");
    assert!(
        served.passes_owner_verbs(served.owner),
        "now the owner is bound"
    );
}

#[test]
fn an_owner_binds_no_key_enrolled_for_another_owner() {
    let served = hosted();
    let owners_key = served.enrol_device_key(served.owner, OWNER_SEED);
    assert_not_valid(served.prepare(served.co_owner, &owners_key));
    assert_not_valid(served.prepare(served.owner, &device_key(STRANGER_SEED)));
    assert_eq!(served.bound_to(&owners_key), None, "nothing was bound");
    assert!(
        !served.passes_owner_verbs(served.co_owner),
        "the co-Owner stays unbound"
    );
}

#[test]
fn a_binding_prepared_for_one_owner_lands_for_no_other() {
    let served = hosted();
    let owners_key = served.enrol_device_key(served.owner, OWNER_SEED);
    let prepared = served
        .prepare(served.owner, &owners_key)
        .expect("the owner's binding is prepared");
    assert_not_valid(served.land(served.co_owner, &prepared, &owners_key));
    assert_eq!(served.bound_to(&owners_key), None, "nothing was bound");
    assert!(
        !served.passes_owner_verbs(served.co_owner),
        "the co-Owner stays unbound"
    );
}

#[test]
fn a_bound_owner_binds_no_second_key() {
    let served = hosted();
    served.enrol_and_bind(served.owner, OWNER_SEED);
    let second = served.enrol_device_key(served.owner, OWNER_SECOND_SEED);
    assert_refused(served.prepare(served.owner, &second));
    assert_eq!(
        served.bound_to(&second),
        None,
        "the second key binds no one"
    );
}
