//! An Owner's removal ends the owner authority their keys signed in (row
//! OWNER-REVOKE-BY-NAMED-ATTRIBUTION; ruled OWNER-REVOKE-NAMED-ATTRIBUTION =
//! A, direction (b)).
//!
//! A row names the person an owner key speaks for, and an Owner who will be
//! removed can still write such rows while they stand. Three routes, each
//! with rows the fold counts and no production door writes:
//! - their key enrols a new owner key whose enrolment names another live
//!   Owner;
//! - their key enrols one key twice on sibling branches, once for them and
//!   once for another Owner, and the row for the other Owner is the one the
//!   key list keeps (the smallest entry);
//! - their key signs a `human` binding of another Owner's key.
//!
//! On removal every such key ends and every such binding is revoked. A key
//! the host root enrolled for another Owner stays live, and that Owner's own
//! binding stays.
//!
//! Real self-hosted shared vaults, as `tests/owner_enrol.rs` builds them.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test owner_revoke_named_attribution`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    ActAuthority, ActSurface, ActorBindingStatus, AuthorityEntryHash, AuthorityKey, AuthorityOp,
    HostSlipIssuer, MachineRole, OwnerKeyEnrollment,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::passkey_vouch_limits::{
    SignedRow, append_signed_rows, enrol_owner_key_on, main_log_heads,
};
use oneiron::test_support::bind_host_owner;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_authority::authority::ACTOR_CLASS_HUMAN;

const SHARED: u64 = 44;
/// The seed of the co-Owner's own owner key, which the host root enrols.
const CO_OWNER_SEED: u8 = 7;
/// The seed of the owner's own owner key, which the host root enrols.
const OWNER_SEED: u8 = 9;
/// The seed of the key the co-Owner's key enrols for the owner.
const PLANTED_SEED: u8 = 11;
/// The first seed of the keys the co-Owner's key enrols on sibling branches.
const SIBLING_FIRST_SEED: u8 = 40;
/// How many sibling pairs to try before one keeps the owner's row.
const SIBLING_TRIES: u8 = 24;

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

fn signing(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn ed25519(key: &SigningKey) -> AuthorityKey {
    AuthorityKey::Ed25519(key.verifying_key().to_bytes())
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
    let co_owner = person(&vault);
    let owner_proof = proof(&vault, owner);
    let act = vault
        .propose_add_owner(&owner_proof, SHARED, co_owner)
        .expect("the owner starts add_owner");
    vault
        .execute_completed_shared_act(&owner_proof, &act.id, Some(&issuer))
        .expect("add_owner runs at once");
    Shared {
        _dir: dir,
        vault,
        issuer,
        owner,
        co_owner,
    }
}

impl Shared {
    /// The owner removes the co-Owner, who leaves the vault.
    fn remove_co_owner(&self) {
        let owner_proof = proof(&self.vault, self.owner);
        let act = self
            .vault
            .propose_remove_owner(&owner_proof, SHARED, self.co_owner, None, None, false)
            .expect("the owner starts remove_owner");
        self.vault
            .execute_completed_shared_act(&owner_proof, &act.id, Some(&self.issuer))
            .expect("remove_owner runs at once");
    }

    /// `person`'s enrolment of `key` on this install: the door's input,
    /// with `key`'s proof of possession.
    fn enrolment(&self, person: EntityId, key: &SigningKey) -> (ActAuthority, OwnerKeyEnrollment) {
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
        (authority, input)
    }

    /// `person` enrols `seed`'s key through the owner-signing-key door, which
    /// signs with this host's root as its predecessor. Answers the key.
    fn enrol_owner_key(&self, person: EntityId, seed: u8) -> [u8; 32] {
        let key = signing(seed);
        let (authority, input) = self.enrolment(person, &key);
        self.vault
            .enrol_owner_signing_key_as_host(&authority, input, &self.issuer)
            .expect("an Owner enrols an owner key of their own");
        key.verifying_key().to_bytes()
    }

    /// An enrolment of `key` naming `person` on `parents`, signed by
    /// `predecessor` and carried by this install, as a hostile Owner writes
    /// it by hand. True when the fold counted it.
    fn enrol_signed_by(
        &self,
        person: EntityId,
        key: &SigningKey,
        parents: Vec<AuthorityEntryHash>,
        predecessor: &SigningKey,
    ) -> bool {
        let (authority, input) = self.enrolment(person, key);
        enrol_owner_key_on(
            &self.vault,
            &authority,
            input,
            parents,
            ed25519(predecessor),
            |transcript| predecessor.sign(transcript).to_bytes().to_vec(),
        )
        .expect("the door stores the enrolment")
    }

    /// The person the key list's row of `public_key` names: its smallest
    /// counted enrolment's.
    fn listed_owner(&self, public_key: [u8; 32]) -> EntityId {
        self.vault
            .enrolled_owner_keys()
            .expect("the enrolled keys")
            .into_iter()
            .find(|key| key.public_key == public_key)
            .expect("the key is listed")
            .owner
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

    /// The person a live `human` binding on `key` names, if any.
    fn bound_to(&self, key: &AuthorityKey) -> Option<EntityId> {
        self.vault
            .authority_fold()
            .expect("the fold")
            .actor_bindings
            .get(key)
            .filter(|binding| {
                binding.status == ActorBindingStatus::Active
                    && binding.actor_class == ACTOR_CLASS_HUMAN
            })
            .map(|binding| binding.actor_ref)
    }

    /// The co-Owner's own key, enrolled by the host root, which binds them.
    fn co_owner_key(&self) -> SigningKey {
        let public_key = self.enrol_owner_key(self.co_owner, CO_OWNER_SEED);
        assert!(self.key_is_live(public_key), "the co-Owner's key is live");
        assert_eq!(
            self.bound_to(&AuthorityKey::Ed25519(public_key)),
            Some(self.co_owner),
            "the co-Owner's first key binds them"
        );
        signing(CO_OWNER_SEED)
    }
}

#[test]
fn a_removed_owners_key_ends_the_key_it_enrolled_for_another_owner() {
    let shared = shared();
    let co_owner_key = shared.co_owner_key();
    let owner_key = shared.enrol_owner_key(shared.owner, OWNER_SEED);
    let planted = signing(PLANTED_SEED);
    let heads = main_log_heads(&shared.vault).expect("the heads");
    assert!(
        shared.enrol_signed_by(shared.owner, &planted, heads, &co_owner_key),
        "the fold counts an enrolment for the owner that the co-Owner's key signed"
    );
    let planted = planted.verifying_key().to_bytes();
    assert_eq!(
        shared.listed_owner(planted),
        shared.owner,
        "the planted key's enrolment names the owner"
    );
    assert!(shared.key_is_live(planted), "the planted key is live");

    shared.remove_co_owner();

    assert!(
        !shared.key_is_live(co_owner_key.verifying_key().to_bytes()),
        "the removed Owner's own key ends with the removal"
    );
    assert!(
        !shared.key_is_live(planted),
        "a key the removed Owner's key enrolled for another Owner ends with the removal"
    );
    assert!(
        shared.key_is_live(owner_key),
        "the key the host root enrolled for the owner stays live"
    );
    assert_eq!(
        shared.bound_to(&shared.issuer.public_key()),
        Some(shared.owner),
        "the owner's own binding stays"
    );
}

#[test]
fn a_removed_owners_key_ends_a_key_it_enrolled_twice_on_sibling_branches() {
    let shared = shared();
    let co_owner_key = shared.co_owner_key();
    // Each pair enrols one key twice on the same heads, once naming the
    // co-Owner and once naming the owner. Which row the key list keeps
    // follows the two entries' hashes, so pairs are tried until the row
    // naming the owner is the one kept.
    let kept_for_owner = (SIBLING_FIRST_SEED..SIBLING_FIRST_SEED + SIBLING_TRIES)
        .find_map(|seed| {
            let key = signing(seed);
            let heads = main_log_heads(&shared.vault).expect("the heads");
            assert!(
                shared.enrol_signed_by(shared.co_owner, &key, heads.clone(), &co_owner_key),
                "the fold counts the co-Owner's enrolment of the key"
            );
            assert!(
                shared.enrol_signed_by(shared.owner, &key, heads, &co_owner_key),
                "the fold counts the sibling enrolment of the key for the owner"
            );
            let public_key = key.verifying_key().to_bytes();
            (shared.listed_owner(public_key) == shared.owner).then_some(public_key)
        })
        .expect("one of the pairs keeps the row naming the owner");
    assert!(shared.key_is_live(kept_for_owner), "the key is live");

    shared.remove_co_owner();

    assert!(
        !shared.key_is_live(kept_for_owner),
        "a key one counted enrolment names the removed Owner for ends with the removal, \
         whichever enrolment the key list keeps"
    );
}

#[test]
fn a_removed_owners_key_ends_the_binding_it_signed_for_another_owner() {
    let shared = shared();
    let co_owner_key = shared.co_owner_key();
    let owner_key = shared.enrol_owner_key(shared.owner, OWNER_SEED);
    assert_eq!(
        shared.bound_to(&AuthorityKey::Ed25519(owner_key)),
        None,
        "the owner, already bound by the host root, gains no binding on a second key"
    );
    let counted = append_signed_rows(
        &shared.vault,
        vec![SignedRow {
            op: AuthorityOp::BindActor {
                authority_key: AuthorityKey::Ed25519(owner_key),
                actor_ref: shared.owner,
                actor_class: ACTOR_CLASS_HUMAN.into(),
                epoch: 1,
            },
            signer: ed25519(&co_owner_key),
            cosigners: Vec::new(),
        }],
        |_, transcript| co_owner_key.sign(transcript).to_bytes().to_vec(),
    )
    .expect("the door stores the binding");
    assert_eq!(
        counted,
        vec![true],
        "the fold counts a binding the co-Owner's key signed"
    );
    assert_eq!(
        shared.bound_to(&AuthorityKey::Ed25519(owner_key)),
        Some(shared.owner)
    );

    shared.remove_co_owner();

    assert_eq!(
        shared.bound_to(&AuthorityKey::Ed25519(owner_key)),
        None,
        "a binding the removed Owner's key signed is revoked with the removal"
    );
    assert!(
        shared.key_is_live(owner_key),
        "the key the host root enrolled for the owner stays live"
    );
    assert_eq!(
        shared.bound_to(&shared.issuer.public_key()),
        Some(shared.owner),
        "the owner's own binding stays"
    );
}
