//! The membership move that ends a member's owner keys proves each revoke
//! with an owner key (row HOSTED-ROOT-REVOKES-OWNER-KEY; ruling
//! OWNERKEY-7930-WINDOW = A, the Engine 15 Nov 21:42). The fold counts a
//! `RevokeDevice` of an owner key only with an owner key's proof, never with
//! the custodial root's alone, so on a hosted vault the move cosigns each
//! revoke with an owner key this install holds. Where it holds none, the move
//! refuses before it writes, as the owner-key refusal, and names the next
//! step and the member as reason codes (the lead, 15 Nov 21:42: never a bare
//! error). The shared act stays pending, so the same act runs once this
//! install holds an owner key. A self-host root proves for the owner itself;
//! `owner_enrol.rs` keeps those moves.
//!
//! Red on main, where the custodial root's revoke counts alone:
//! `a_hosted_removal_is_refused_until_this_install_holds_an_owner_key` (the
//! removal runs at once) and
//! `a_hosted_removal_cosigns_each_revoke_with_the_owner_key_this_install_holds`
//! (the revoke carries no cosign). Guard, green on main too:
//! `a_removal_that_ends_this_installs_own_key_revokes_it_last` (red on a
//! door that revokes the held key first).
//!
//! No managed host holds an owner key today (its serving install's
//! enrolment refuses on a Hosted vault), so in production the hosted move
//! refuses. These tests hold an owner key on the hosted install through the
//! device door (`enrol_device_owner_signing_key`) to pin the door's contract
//! for an install that holds one.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test owner_key_move_proof`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    ActAuthority, ActSurface, AuthorityKey, AuthorityLogEntry, AuthorityOp, HostSlipIssuer,
    MachineRole, OwnerKeyEnrollment, decode_authority_log_entry_body,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::test_support::bind_host_owner;
use oneiron::{EntityId, ErrorKind, HostingPrivacyPosture, Vault, VaultConfig};

const SHARED: u64 = 45;
/// The seed of the co-Owner's own owner key, on a device of theirs.
const CO_OWNER_SEED: u8 = 9;

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

/// A shared vault as a managed host serves it: the Hosted posture, rooted
/// under the host's custodial root (which proves for no owner), the embedded
/// owner bound by it, and a second Owner the owner added.
struct Hosted {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    co_owner: EntityId,
}

fn hosted() -> Hosted {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.privacy.posture = HostingPrivacyPosture::Hosted;
    let vault = Vault::open(dir.path(), config).expect("hosted vault");
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
    let co_owner = person(&vault);
    let owner_proof = proof(&vault, owner);
    let act = vault
        .propose_add_owner(&owner_proof, SHARED, co_owner)
        .expect("the owner starts add_owner");
    vault
        .execute_completed_shared_act(&owner_proof, &act.id, Some(&issuer))
        .expect("add_owner runs at once");
    Hosted {
        _dir: dir,
        vault,
        issuer,
        owner,
        co_owner,
    }
}

impl Hosted {
    /// The owner starts the removal of the co-Owner; answers the act's id.
    fn propose_removal(&self) -> String {
        self.vault
            .propose_remove_owner(
                &proof(&self.vault, self.owner),
                SHARED,
                self.co_owner,
                None,
                None,
                false,
            )
            .expect("the owner starts remove_owner")
            .id
    }

    /// The owner runs the removal `act` under the host's issuer.
    fn run(&self, act: &str) -> oneiron::Result<()> {
        self.vault
            .execute_completed_shared_act(&proof(&self.vault, self.owner), act, Some(&self.issuer))
            .map(|_| ())
    }

    /// The co-Owner enrols an owner signing key of a device of theirs, made
    /// from `seed`, through the owner-signing-key door, with this host's
    /// root as its predecessor. This install never holds it. Answers the key.
    fn enrol_device_key(&self, seed: u8) -> [u8; 32] {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let public_key = key.verifying_key().to_bytes();
        let machine = self
            .vault
            .prepare_install_signing()
            .expect("this install's machine");
        let authority =
            ActAuthority::Owner(proof(&self.vault, self.co_owner), ActSurface::ThisInstall);
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

    /// `person` enrols this install's own owner signing key, which this
    /// handle then holds. Answers the key.
    fn enrol_install_key(&self, person: EntityId) -> [u8; 32] {
        self.vault
            .enrol_device_owner_signing_key(
                &ActAuthority::Owner(proof(&self.vault, person), ActSurface::ThisInstall),
                &self.issuer,
            )
            .expect("an Owner enrols this install's owner signing key")
            .public_key
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

    /// The stored `RevokeDevice` row that ends `public_key`.
    fn revoke_of(&self, public_key: [u8; 32]) -> AuthorityLogEntry {
        let revoked = AuthorityKey::Ed25519(public_key);
        self.vault
            .export_signed_authority_history()
            .expect("the signed history")
            .iter()
            .map(|bytes| decode_authority_log_entry_body(bytes).expect("a row"))
            .find(|row| {
                matches!(&row.op, AuthorityOp::RevokeDevice { revoked_key } if *revoked_key == revoked)
            })
            .expect("the key's revoke is stored")
    }
}

/// The co-Owner holds an owner key on a device of theirs, and this hosted
/// install holds none. Removing them would end that key under the custodial
/// root alone, so the move is refused before it writes, as the owner-key
/// refusal, with the next step and the member as reason codes, and the key
/// stays live. Once the owner enrols an owner key on this install, the same
/// act runs, and the co-Owner's key ends.
#[test]
fn a_hosted_removal_is_refused_until_this_install_holds_an_owner_key() {
    let hosted = hosted();
    let key = hosted.enrol_device_key(CO_OWNER_SEED);
    let act = hosted.propose_removal();

    let refusal = hosted
        .run(&act)
        .expect_err("no owner key on this install proves the revoke");

    assert_eq!(refusal.kind(), ErrorKind::OwnerKeyRequired, "{refusal}");
    let reply = oneiron::memory::MemoryError::from(refusal);
    assert_eq!(
        reply.reason_codes,
        vec![
            "owner_key_required".to_owned(),
            "next_step:owner_device_proof_unavailable".to_owned(),
            format!("member:{}", hosted.co_owner.to_hex()),
        ],
        "the refusal names its next step and the member: {reply:?}"
    );
    assert!(
        hosted.key_is_live(key),
        "nothing moved: their key stays live"
    );

    hosted.enrol_install_key(hosted.owner);
    hosted
        .run(&act)
        .expect("the same act runs once this install holds an owner key");

    assert!(
        !hosted.key_is_live(key),
        "the removal ends the co-Owner's key"
    );
}

/// This hosted install holds the owner's owner key. The removal's revoke of
/// the co-Owner's key is signed by the host root and cosigned by that key,
/// and it counts.
#[test]
fn a_hosted_removal_cosigns_each_revoke_with_the_owner_key_this_install_holds() {
    let hosted = hosted();
    let held = hosted.enrol_install_key(hosted.owner);
    let key = hosted.enrol_device_key(CO_OWNER_SEED);

    hosted
        .run(&hosted.propose_removal())
        .expect("the removal runs with this install's owner key");

    assert!(!hosted.key_is_live(key), "the co-Owner's key is revoked");
    assert!(hosted.key_is_live(held), "the owner's own key stays live");
    let revoke = hosted.revoke_of(key);
    assert_eq!(
        revoke.signer.public_key,
        hosted.issuer.public_key(),
        "the host root signs the revoke"
    );
    let cosigners: Vec<&AuthorityKey> = revoke
        .cosigns
        .iter()
        .map(|cosign| &cosign.public_key)
        .collect();
    assert_eq!(
        cosigners,
        vec![&AuthorityKey::Ed25519(held)],
        "the owner key this install holds proves the revoke"
    );
}

/// The co-Owner's own key is the one this install holds, beside a key on a
/// device of theirs that sorts after it, so the door finds the held key
/// first. The removal ends both: the held key proves the other's revoke
/// first, and its own revoke comes last, while it still proves.
#[test]
fn a_removal_that_ends_this_installs_own_key_revokes_it_last() {
    let hosted = hosted();
    let held = hosted.enrol_install_key(hosted.co_owner);
    let seed = (1..=u8::MAX)
        .find(|seed| {
            SigningKey::from_bytes(&[*seed; 32])
                .verifying_key()
                .to_bytes()
                > held
        })
        .expect("a device key that sorts after the held key");
    let key = hosted.enrol_device_key(seed);

    hosted
        .run(&hosted.propose_removal())
        .expect("the removal ends both of the co-Owner's keys");

    assert!(!hosted.key_is_live(key), "the device key is revoked");
    assert!(
        !hosted.key_is_live(held),
        "this install's key is revoked too"
    );
    assert!(
        hosted.revoke_of(held).seq > hosted.revoke_of(key).seq,
        "the held key's own revoke comes after the revoke it proved"
    );
}
