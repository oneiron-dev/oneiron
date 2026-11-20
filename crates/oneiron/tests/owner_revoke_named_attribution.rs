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
//! - their key signs or cosigns a `human` binding of another Owner's key.
//!
//! On removal every such key ends and every such binding is revoked. A key
//! the host root enrolled for another Owner stays live, even when their key
//! enrolled it again on a sibling branch (REVIEW-9585 P1), and that Owner's
//! own binding stays.
//!
//! Real self-hosted shared vaults, as `tests/owner_enrol.rs` builds them.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test owner_revoke_named_attribution`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    ActAuthority, ActSurface, ActorBindingStatus, AuthorityEntryHash, AuthorityKey, AuthorityOp,
    HostSlipIssuer, MachineRole, OwnerKeyEnrollment, OwnerPasskeyEnrollment,
    webauthn_assertion_envelope, webauthn_challenge,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::passkey_vouch_limits::{
    SignedRow, append_signed_rows, enrol_owner_key_on, main_log_heads, sign_as_host_root,
};
use oneiron::test_support::bind_host_owner;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_authority::authority::ACTOR_CLASS_HUMAN;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use sha2::{Digest as _, Sha256};

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

/// Blind review round 1 of #9585, P1: a second enrolment the removed Owner's
/// key signs for a key that already stands on a row no key of theirs signed
/// does not make the key theirs. The host root enrols the owner's key; the
/// co-Owner's key enrols the same key for the owner on a sibling branch,
/// replaying its proof, and the fold counts both rows.
#[test]
fn a_removed_owners_sibling_enrolment_leaves_a_key_the_host_root_enrolled_live() {
    let shared = shared();
    let co_owner_key = shared.co_owner_key();
    let fork = main_log_heads(&shared.vault).expect("the heads before the owner's key");
    let owner_key = shared.enrol_owner_key(shared.owner, OWNER_SEED);
    assert!(
        shared.enrol_signed_by(shared.owner, &signing(OWNER_SEED), fork, &co_owner_key),
        "the fold counts the co-Owner's sibling enrolment of the owner's key"
    );
    assert!(shared.key_is_live(owner_key), "the owner's key is live");

    shared.remove_co_owner();

    assert!(
        !shared.key_is_live(co_owner_key.verifying_key().to_bytes()),
        "the removed Owner's own key ends with the removal"
    );
    assert!(
        shared.key_is_live(owner_key),
        "the key the host root enrolled for the owner stays live, though the removed Owner's \
         key enrolled it again"
    );
    assert_eq!(
        shared.bound_to(&shared.issuer.public_key()),
        Some(shared.owner),
        "the owner's own binding stays"
    );
}

/// Blind review round 2 of #9585, P1 2: a binding the removed Owner's key
/// cosigned does not stand without them because another key is its primary
/// signer. The host root signs a `human` binding of the owner's second key
/// with the co-Owner's key as its one cosigner; the co-Owner's removal
/// revokes it.
#[test]
fn a_removed_owners_cosign_ends_a_binding_the_host_root_signed() {
    let shared = shared();
    let co_owner_key = shared.co_owner_key();
    let owner_key = shared.enrol_owner_key(shared.owner, OWNER_SEED);
    let root = shared.issuer.public_key();
    let counted = append_signed_rows(
        &shared.vault,
        vec![SignedRow {
            op: AuthorityOp::BindActor {
                authority_key: AuthorityKey::Ed25519(owner_key),
                actor_ref: shared.owner,
                actor_class: ACTOR_CLASS_HUMAN.into(),
                epoch: 1,
            },
            signer: root.clone(),
            cosigners: vec![ed25519(&co_owner_key)],
        }],
        |key, transcript| {
            if *key == root {
                sign_as_host_root(&shared.issuer, transcript)
            } else {
                co_owner_key.sign(transcript).to_bytes().to_vec()
            }
        },
    )
    .expect("the door stores the binding");
    assert_eq!(
        counted,
        vec![true],
        "the fold counts a binding the host root signed and the co-Owner's key cosigned"
    );
    assert_eq!(
        shared.bound_to(&AuthorityKey::Ed25519(owner_key)),
        Some(shared.owner)
    );

    shared.remove_co_owner();

    assert_eq!(
        shared.bound_to(&AuthorityKey::Ed25519(owner_key)),
        None,
        "a binding the removed Owner's key cosigned is revoked with the removal, though the host \
         root signed it"
    );
    assert!(
        shared.key_is_live(owner_key),
        "the key the host root enrolled for the owner stays live"
    );
    assert_eq!(
        shared.bound_to(&root),
        Some(shared.owner),
        "the owner's own binding stays"
    );
}

// ---------------------------------------------------------------------------
// Passkey helpers copied from passkey_owner_key.rs: the software P-256
// passkey, its assertions, and its enrolment/vouch builders. Test files never
// import from each other, so the minimal set this test needs is copied
// verbatim from crates/oneiron/tests/passkey_owner_key.rs lines 1-280
// (P-256 key, assertion, passkey_enrollment, passkey_signs, the
// FLAGS_PRESENT_VERIFIED and CREDENTIAL_ID consts). SIBLING_ORIGIN and
// FLAGS_PRESENT_ONLY are not copied: no assertion in this test uses them.
// ---------------------------------------------------------------------------

/// User present and user verified.
const FLAGS_PRESENT_VERIFIED: u8 = 0x05;

/// The passkey's credential id (`rawId`).
const CREDENTIAL_ID: &[u8] = b"passkey-credential-0001";

/// The passkey a platform authenticator holds, as a software key.
fn passkey() -> P256SigningKey {
    P256SigningKey::from_slice(&[0x5A; 32]).expect("a P-256 scalar")
}

/// The credential's public key as `getPublicKey()` hands its point:
/// uncompressed SEC1.
fn passkey_public_key() -> Vec<u8> {
    passkey()
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec()
}

/// The passkey's key as the roster names it: compressed SEC1.
fn passkey_roster_key() -> AuthorityKey {
    AuthorityKey::P256(
        passkey()
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec(),
    )
}

/// What `navigator.credentials.get` returns for `challenge`: authenticator
/// data (RP id hash, `flags`, a zero sign count), the client data JSON, and
/// the DER signature over the one and SHA-256 of the other.
struct Assertion {
    authenticator_data: Vec<u8>,
    client_data_json: Vec<u8>,
    signature: Vec<u8>,
}

/// The origin the passkey enrols at.
const ORIGIN: &str = "https://oneiron.test";

fn assert_over(challenge: &[u8], flags: u8) -> Assertion {
    assert_over_at(challenge, flags, ORIGIN)
}

fn assert_over_at(challenge: &[u8], flags: u8, origin: &str) -> Assertion {
    assert_by(&passkey(), challenge, flags, origin)
}

/// What `navigator.credentials.get` returns for `challenge` when the
/// passkey `key` answers it at `origin`.
fn assert_by(key: &P256SigningKey, challenge: &[u8], flags: u8, origin: &str) -> Assertion {
    let mut authenticator_data = Sha256::digest(b"oneiron.test").to_vec();
    authenticator_data.push(flags);
    authenticator_data.extend_from_slice(&[0; 4]);
    let client_data_json = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"{origin}","crossOrigin":false}}"#,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge)
    )
    .into_bytes();
    let mut signed = authenticator_data.clone();
    signed.extend_from_slice(&Sha256::digest(&client_data_json));
    let signature: P256Signature = key.sign(&signed);
    Assertion {
        authenticator_data,
        client_data_json,
        signature: signature.to_der().as_bytes().to_vec(),
    }
}

fn passkey_enrollment(assertion: Assertion) -> OwnerPasskeyEnrollment {
    OwnerPasskeyEnrollment {
        credential_id: CREDENTIAL_ID.to_vec(),
        public_key: passkey_public_key(),
        authenticator_data: assertion.authenticator_data,
        client_data_json: assertion.client_data_json,
        signature: assertion.signature,
    }
}

/// The passkey signs an authority transcript as the browser would: an
/// assertion over its challenge, in its envelope.
fn passkey_signs(transcript: &[u8], flags: u8) -> Vec<u8> {
    passkey_signs_at(transcript, flags, ORIGIN)
}

fn passkey_signs_at(transcript: &[u8], flags: u8, origin: &str) -> Vec<u8> {
    let assertion = assert_over_at(&webauthn_challenge(transcript), flags, origin);
    webauthn_assertion_envelope(
        &assertion.authenticator_data,
        &assertion.client_data_json,
        &assertion.signature,
    )
    .expect("an envelope")
}
// End of the helpers copied from passkey_owner_key.rs.

/// The seed of the key the co-Owner's passkey vouches for and the owner's
/// own device key confirms.
const CONFIRMED_SEED: u8 = 13;

/// A removed Owner's passkey vouch ends the key the owner confirmed: the
/// confirmation signs no key in, so the key stands on the removed Owner's
/// vouch alone (REVIEW-9585 round 2 P1 1; FIX [OWNER-REVOKE-CONFIRMATION-PROOF]).
#[test]
fn a_removed_owners_passkey_vouch_ends_the_key_the_owner_confirmed() {
    let shared = shared();
    let co_owner_key = shared.co_owner_key();
    let owner_key = shared.enrol_owner_key(shared.owner, OWNER_SEED);
    // The co-Owner enrols a passkey as an owner key of theirs.
    let co_owner_authority = ActAuthority::Owner(
        proof(&shared.vault, shared.co_owner),
        ActSurface::ThisInstall,
    );
    let challenge = shared
        .vault
        .owner_passkey_enrollment_challenge_as(&co_owner_authority, &passkey_public_key())
        .expect("the co-Owner's passkey enrolment challenge");
    shared
        .vault
        .enrol_owner_passkey_as_host(
            &co_owner_authority,
            &passkey_enrollment(assert_over(&challenge, FLAGS_PRESENT_VERIFIED)),
            &shared.issuer,
        )
        .expect("the co-Owner enrols a passkey");
    // The co-Owner's passkey vouches for a fresh key enrolled for the owner.
    let confirmed = signing(CONFIRMED_SEED);
    let (owner_authority, input) = shared.enrolment(shared.owner, &confirmed);
    shared
        .vault
        .enrol_owner_signing_key_as(
            &owner_authority,
            input,
            passkey_roster_key(),
            |transcript| Ok(passkey_signs(transcript, FLAGS_PRESENT_VERIFIED)),
        )
        .expect("the co-Owner's passkey vouches for a key enrolled for the owner");
    // The owner's own device key confirms it.
    let (owner_authority, input) = shared.enrolment(shared.owner, &confirmed);
    shared
        .vault
        .confirm_owner_key_as(
            &owner_authority,
            input,
            AuthorityKey::Ed25519(owner_key),
            |transcript| Ok(signing(OWNER_SEED).sign(transcript).to_bytes().to_vec()),
        )
        .expect("the owner's device key confirms the passkey-vouched key");
    let confirmed = confirmed.verifying_key().to_bytes();
    assert!(
        shared.key_is_live(confirmed),
        "guard: the confirmed key is live"
    );
    assert_eq!(
        shared.listed_owner(confirmed),
        shared.owner,
        "guard: the confirmed key's enrolment names the owner"
    );

    shared.remove_co_owner();

    assert!(
        !shared.key_is_live(co_owner_key.verifying_key().to_bytes()),
        "the removed Owner's own key ends with the removal"
    );
    assert!(
        !shared.key_is_live(confirmed),
        "a key the removed Owner's passkey vouched for ends with the removal, though the \
         owner's own device key confirmed it"
    );
    assert!(
        shared.key_is_live(owner_key),
        "the owner's own device key stays live"
    );
}
