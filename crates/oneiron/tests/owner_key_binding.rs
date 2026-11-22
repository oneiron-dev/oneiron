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
//! - `a_rebinding_takes_an_epoch_above_the_keys_revocation`: a key's own
//!   revoke of its binding at an epoch above it raises the fold's floor for
//!   the key's next binding; the door prepares the next binding above that
//!   floor, so it counts (review of stack #10009, finding 3). Red on the
//!   door that took the epoch from the last binding only (the binding is
//!   refused as not counted), green on the head.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test owner_key_binding`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActAuthority, ActSurface, ActorBindingStatus, AuthorityKey,
    AuthorityLogEntry, AuthorityOp, AuthoritySignature, AuthoritySignatureSuite, HostSlipIssuer,
    MachineRole, OwnerKeyBindingReceipt, OwnerKeyChangeKind, OwnerKeyEnrollment,
    PreparedOwnerKeyBinding, authority_entry_hash, authority_log_entity_id_from_hash,
    authority_transcript,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::error::RecordError;
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember};
use oneiron::memory::MEMORY_CODE_OWNER_BINDING_REQUIRED;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::{EdgeActorClass, EntityId, HostingPrivacyPosture, Vault, VaultConfig};
use oneiron_authority::authority::{decode_entry_value, encode_value, entry_value};

const SHARED: u64 = 47;
/// The seed of the owner's own owner key, on a device of theirs.
const OWNER_SEED: u8 = 7;
/// The seed of the co-Owner's owner key, on a device of theirs.
const CO_OWNER_SEED: u8 = 9;
/// The seed of a key the binding names no one for.
const STRANGER_SEED: u8 = 13;
/// The seed of the owner's second owner key.
const OWNER_SECOND_SEED: u8 = 15;
/// The epoch a key's own revoke names, above its binding's first.
const REVOKED_EPOCH: u64 = 9;

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
    ) -> oneiron::Result<OwnerKeyBindingReceipt> {
        self.vault.land_owner_key_binding_as(
            &as_owner(&self.vault, person),
            &prepared.entry,
            signer.sign(&prepared.transcript).to_bytes().to_vec(),
        )
    }

    /// `key`'s own `RevokeActor` of its binding at `epoch`, signed by `key`
    /// at its next sequence on the binding `bound` names (the main log's one
    /// head once it landed), stored as a replica's row is; it must count.
    fn revoke_own_binding(&self, key: &SigningKey, bound: &OwnerKeyBindingReceipt, epoch: u64) {
        let binding = self
            .vault
            .get_authority_log_entry(
                &authority_log_entity_id_from_hash(&bound.entry).expect("the binding's id"),
            )
            .expect("the log reads")
            .expect("the binding is stored");
        let authority_key = AuthorityKey::Ed25519(public(key));
        let mut entry = AuthorityLogEntry {
            schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
            vault_id: binding.vault_id,
            seq: binding.seq + 1,
            parent_hashes: vec![bound.entry],
            op: AuthorityOp::RevokeActor {
                authority_key: authority_key.clone(),
                epoch,
            },
            signer: AuthoritySignature {
                suite: AuthoritySignatureSuite::Ed25519,
                public_key: authority_key,
                signature: vec![0; 64],
            },
            cosigns: Vec::new(),
            ts: binding.ts,
            overlay_seed: None,
        };
        let transcript = authority_transcript(&entry).expect("the revoke's transcript");
        entry.signer.signature = key.sign(&transcript).to_bytes().to_vec();
        let at = TimeRange {
            start: entry.ts,
            end: entry.ts,
        };
        self.vault
            .put_authority_log_entry(&entry, at, entry.ts)
            .expect("the revoke is stored");
        let hash = authority_entry_hash(&entry).expect("the revoke's hash");
        assert!(
            self.vault
                .authority_fold()
                .expect("the fold")
                .valid_entries
                .contains(&hash),
            "a key's own revoke of its binding counts"
        );
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

/// The unsigned entry `bytes` encode, as prepare answered it.
fn entry_of(bytes: &[u8]) -> AuthorityLogEntry {
    let value = rmpv::decode::read_value(&mut &bytes[..]).expect("one MessagePack value");
    decode_entry_value(&value).expect("the prepared entry decodes")
}

/// `prepared`'s entry at `seq` in its one encoding, with its transcript.
fn at_sequence(prepared: &PreparedOwnerKeyBinding, seq: u64) -> PreparedOwnerKeyBinding {
    let mut entry = entry_of(&prepared.entry);
    entry.seq = seq;
    PreparedOwnerKeyBinding {
        entry: encode_value(&entry_value(&entry, true)).expect("the entry encodes"),
        transcript: authority_transcript(&entry).expect("its transcript"),
    }
}

/// Blind review #10043 P1 (the passkey's binding door; this door is its
/// sibling): prepare names the key's next sequence, and a binding the key
/// signs above it is none prepare built. Landed, it would move the key's
/// next sequence to its own; at `u64::MAX` the key would have no sequence
/// left to sign at.
#[test]
fn a_binding_signed_above_the_prepared_sequence_binds_no_one() {
    let served = hosted();
    let key = served.enrol_device_key(served.owner, OWNER_SEED);
    let prepared = served
        .prepare(served.owner, &key)
        .expect("the binding is prepared");
    let prepared_seq = entry_of(&prepared.entry).seq;
    for seq in [prepared_seq + 1, u64::MAX] {
        assert_not_valid(served.land(served.owner, &at_sequence(&prepared, seq), &key));
    }
    assert_eq!(served.bound_to(&key), None, "nothing was bound");
    served
        .land(served.owner, &prepared, &key)
        .expect("the prepared binding still lands at its own sequence");
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

#[test]
fn a_rebinding_takes_an_epoch_above_the_keys_revocation() {
    let served = hosted();
    let key = served.enrol_device_key(served.owner, OWNER_SEED);
    let prepared = served
        .prepare(served.owner, &key)
        .expect("the binding is prepared");
    let bound = served
        .land(served.owner, &prepared, &key)
        .expect("the key's own binding lands");
    served.revoke_own_binding(&key, &bound, REVOKED_EPOCH);
    assert_eq!(served.bound_to(&key), None, "the revoke ends the binding");
    assert!(
        !served.passes_owner_verbs(served.owner),
        "the Owner is unbound again"
    );
    let prepared = served
        .prepare(served.owner, &key)
        .expect("the binding is prepared again");
    let receipt = served
        .land(served.owner, &prepared, &key)
        .expect("the binding above the revoke's epoch counts");
    assert_eq!(
        receipt.epoch,
        REVOKED_EPOCH + 1,
        "the binding takes the epoch above the revoke's"
    );
    assert_eq!(served.bound_to(&key), Some(served.owner));
    assert!(
        served.passes_owner_verbs(served.owner),
        "the bound Owner's owner verbs pass"
    );
}

#[test]
fn a_device_keys_binding_lists_as_bound_by_device_key() {
    let served = hosted();
    let key = served.enrol_and_bind(served.owner, OWNER_SEED);
    let bound = AuthorityKey::Ed25519(public(&key));
    let changes = served
        .vault
        .owner_key_changes(&proof(&served.vault, served.owner))
        .expect("the owner key changes list");
    let listed = changes
        .iter()
        .find(|change| change.change == OwnerKeyChangeKind::BoundByDeviceKey)
        .expect("the list names the device key's binding");
    assert_eq!(
        listed.public_key, bound,
        "the list names the bound device key"
    );
    assert_eq!(
        listed.signed_by, bound,
        "the list names the device key as its signer"
    );
}
