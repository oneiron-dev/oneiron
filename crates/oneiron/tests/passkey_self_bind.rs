//! A hosted owner who signs in with a passkey alone binds as the vault's
//! owner with that passkey (the Oneiron lead 21 Nov 04:5x: "a passkey may
//! sign its own human binding, while the binding itself grants nothing the
//! passkey limits bar"; row PASSKEY-SELF-BIND).
//!
//! The host enrols the owner's passkey with its custodial root as the
//! predecessor, and the hosted fold counts no `human` binding that only the
//! host signs, so the owner is unbound: their owner verbs answer
//! OWNER_BINDING_REQUIRED and their owner writes (a learning setting) are
//! refused. The passkey then signs its own first binding,
//! `BindActor{P, owner, human, epoch 1}`, with a user-verified assertion on
//! the page its enrolment pinned, and both pass.
//!
//! The binding grants the passkey nothing else: it still re-roots nothing,
//! revokes no other owner key, binds no other key and rebinds nothing, and a
//! key it vouches for stays limited until a key that is no passkey confirms
//! it. Only that one shape counts: a binding of another owner, another class
//! or another epoch, a cosigned one, one with a raw signature or an
//! unverified or misplaced assertion, one by a passkey no host vouched for
//! (or only another passkey vouched for), and one after the binding was
//! revoked, all count for nothing.
//!
//! The tests above the `door` module use only the base API (a row stored
//! through the signed-row test door), so they run red on the base: there the
//! fold bars every passkey from a `BindActor`. The `door` module exercises
//! the binding door and the owner key changes list, which name the binding
//! on every owner device.
//!
//! The passkey is a software P-256 key; each assertion is built as a
//! browser's `navigator.credentials.get` returns it.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test passkey_self_bind`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use base64::Engine as _;
use ed25519_dalek::Signer as _;
use oneiron::authority::{
    ActAuthority, ActSurface, ActorBindingStatus, AuthorityAttestation, AuthorityKey, AuthorityOp,
    AuthorityTier, DeviceAuthority, HostSlipIssuer, MachineRole, OwnerKeyEnrollment,
    OwnerPasskeyEnrollment, ROLE_OWNER, webauthn_assertion_envelope, webauthn_challenge,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::learning_setting_doors::{
    LearningSettingMode, LearningSettingPut, put_learning_setting_as_owner,
};
use oneiron::memory::MEMORY_CODE_OWNER_BINDING_REQUIRED;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_doors::passkey_vouch_limits::{
    SignedRow, append_signed_rows, revoke_owner_key_signed_by, sign_as_host_root,
};
use oneiron::{EdgeActorClass, EntityId, HostingPrivacyPosture, Vault, VaultConfig};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use sha2::{Digest as _, Sha256};

/// User present and user verified.
const FLAGS_PRESENT_VERIFIED: u8 = 0x05;
/// User present alone.
const FLAGS_PRESENT_ONLY: u8 = 0x01;
/// The origin the passkey enrols at.
const ORIGIN: &str = "https://oneiron.test";
/// Another page under the same RP id.
const SIBLING_ORIGIN: &str = "https://docs.oneiron.test";
/// The passkey's credential id (`rawId`).
const CREDENTIAL_ID: &[u8] = b"passkey-credential-0001";
/// A second passkey's credential id.
const SECOND_CREDENTIAL_ID: &[u8] = b"passkey-credential-0002";
/// The learning setting the owner pins, an owner write.
const CALL_BUDGET_KEY: &str = "question_call_budget_ms";

/// One vault under the Hosted posture, rooted under the test host, with this
/// install's machine profile enrolled and the embedded owner authenticated
/// but bound to no key. The vault drops first.
struct HostedVault {
    vault: Vault,
    issuer: HostSlipIssuer,
    proof: AuthenticatedOwner,
    owner: EntityId,
    _dir: tempfile::TempDir,
}

impl HostedVault {
    fn open() -> Self {
        let dir = tempfile::tempdir().expect("vault directory");
        let mut config = VaultConfig::device();
        config.privacy.posture = HostingPrivacyPosture::Hosted;
        let vault = Vault::open(dir.path(), config).expect("hosted vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's machine profile under the host root");
        let (_, proof) = embedded_owner(&vault).expect("authenticated embedded owner");
        let owner = proof.actor_for_read(&vault).expect("the vault's owner");
        Self {
            vault,
            issuer,
            proof,
            owner,
            _dir: dir,
        }
    }

    fn as_owner(&self) -> ActAuthority {
        ActAuthority::Owner(self.proof.clone(), ActSurface::ThisInstall)
    }

    fn live_owner_key(&self, key: &AuthorityKey) -> bool {
        let fold = self.vault.authority_fold().expect("authority fold");
        fold.roster
            .get(key)
            .is_some_and(|device| !device.revoked && device.roles & ROLE_OWNER != 0)
    }

    /// The binding the fold holds on `key`: its actor, class, epoch and
    /// whether it is active.
    fn binding_of(&self, key: &AuthorityKey) -> Option<(EntityId, String, u64, bool)> {
        let fold = self.vault.authority_fold().expect("authority fold");
        fold.actor_bindings.get(key).map(|binding| {
            (
                binding.actor_ref,
                binding.actor_class.clone(),
                binding.epoch,
                binding.status == ActorBindingStatus::Active,
            )
        })
    }

    /// Whether the owner's owner verbs pass; an unbound owner's answer
    /// OWNER_BINDING_REQUIRED and nothing else.
    fn passes_owner_verbs(&self) -> bool {
        match self
            .vault
            .memory(self.owner, EdgeActorClass::Human)
            .verify_owner()
        {
            Ok(()) => true,
            Err(error) => {
                assert_eq!(error.code, MEMORY_CODE_OWNER_BINDING_REQUIRED, "{error:?}");
                false
            }
        }
    }

    /// The owner pins a learning setting, one of their owner writes.
    fn pins_a_learning_setting(&self) -> oneiron::Result<()> {
        put_learning_setting_as_owner(
            &self.vault,
            &self.proof,
            LearningSettingPut {
                key: CALL_BUDGET_KEY.to_owned(),
                mode: LearningSettingMode::Pin,
                value: Some(12_000.0),
                choice: None,
                weight_runs: None,
                why: "the owner pins the call budget".to_owned(),
                goal: None,
                project: None,
                task_type: None,
            },
        )
        .map(|_| ())
    }

    /// The host enrols the owner's device key, with its custodial root as
    /// the predecessor; on a hosted vault that binds no one.
    fn enrol_device_key(&self, machine: EntityId) {
        self.vault
            .enrol_owner_signing_key_as_host(
                &self.as_owner(),
                keyed_enrollment(self, machine, &owner_device()),
                &self.issuer,
            )
            .expect("the host enrols the owner's device key");
    }

    /// `row`, signed and stored at the heads alone; true when the fold
    /// counted it.
    fn counts(&self, row: SignedRow, flags: u8) -> bool {
        self.counts_signed(row, |key, transcript| {
            self.signs(key, transcript, flags, ORIGIN)
        })
    }

    fn counts_signed<S>(&self, row: SignedRow, sign: S) -> bool
    where
        S: FnMut(&AuthorityKey, &[u8]) -> Vec<u8>,
    {
        append_signed_rows(&self.vault, vec![row], sign)
            .unwrap_or_default()
            .first()
            .copied()
            .unwrap_or(false)
    }

    /// Signs `transcript` as `key`: a passkey with an assertion of `flags`
    /// at `origin` in its envelope, a device key or the host root with its
    /// Ed25519 signature.
    fn signs(&self, key: &AuthorityKey, transcript: &[u8], flags: u8, origin: &str) -> Vec<u8> {
        if *key == self.issuer.public_key() {
            return sign_as_host_root(&self.issuer, transcript);
        }
        if let Some(passkey) = [passkey(), second_passkey()]
            .into_iter()
            .find(|passkey| roster_key_of(passkey) == *key)
        {
            return envelope_of(&assert_by(
                &passkey,
                &webauthn_challenge(transcript),
                flags,
                origin,
            ));
        }
        [owner_device(), vouched_device()]
            .into_iter()
            .find(|held| ed_key(held) == *key)
            .map(|held| held.sign(transcript).to_bytes().to_vec())
            .expect("a key this file holds")
    }
}

/// The passkey a platform authenticator holds, as a software key.
fn passkey() -> P256SigningKey {
    P256SigningKey::from_slice(&[0x5A; 32]).expect("a P-256 scalar")
}

/// A second passkey.
fn second_passkey() -> P256SigningKey {
    P256SigningKey::from_slice(&[0x4C; 32]).expect("a P-256 scalar")
}

/// The owner's device key.
fn owner_device() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0x71; 32])
}

/// A device key the bound passkey vouches for.
fn vouched_device() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0x6B; 32])
}

/// The key the passkey would re-root the vault to.
fn new_root() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0x2F; 32])
}

fn ed_key(key: &ed25519_dalek::SigningKey) -> AuthorityKey {
    AuthorityKey::Ed25519(key.verifying_key().to_bytes())
}

/// `passkey`'s key as the roster names it: compressed SEC1.
fn roster_key_of(passkey: &P256SigningKey) -> AuthorityKey {
    AuthorityKey::P256(
        passkey
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec(),
    )
}

/// The passkey's key as the roster names it.
fn passkey_key() -> AuthorityKey {
    roster_key_of(&passkey())
}

/// What `navigator.credentials.get` returns for `challenge`: authenticator
/// data (RP id hash, `flags`, a zero sign count), the client data JSON, and
/// the DER signature over the one and SHA-256 of the other.
struct Assertion {
    authenticator_data: Vec<u8>,
    client_data_json: Vec<u8>,
    signature: Vec<u8>,
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

/// `assertion` in its envelope, the signature an authority row carries.
fn envelope_of(assertion: &Assertion) -> Vec<u8> {
    webauthn_assertion_envelope(
        &assertion.authenticator_data,
        &assertion.client_data_json,
        &assertion.signature,
    )
    .expect("an envelope")
}

/// `passkey`'s enrollment input with `credential_id`, its assertion over
/// the enrollment challenge as its proof of possession.
fn passkey_enrollment(
    hosted: &HostedVault,
    passkey: &P256SigningKey,
    credential_id: &[u8],
) -> OwnerPasskeyEnrollment {
    let public_key = passkey
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let challenge = hosted
        .vault
        .owner_passkey_enrollment_challenge_as(&hosted.as_owner(), &public_key)
        .expect("the passkey's enrollment challenge");
    let assertion = assert_by(passkey, &challenge, FLAGS_PRESENT_VERIFIED, ORIGIN);
    OwnerPasskeyEnrollment {
        credential_id: credential_id.to_vec(),
        public_key,
        authenticator_data: assertion.authenticator_data,
        client_data_json: assertion.client_data_json,
        signature: assertion.signature,
    }
}

/// The host enrols the owner's passkey with its custodial root as the
/// predecessor, as a hosted vault with no owner key enrols its first one.
/// Answers the carrier that served the ceremony.
fn host_enrols_passkey(hosted: &HostedVault) -> EntityId {
    hosted
        .vault
        .enrol_owner_passkey_as_host(
            &hosted.as_owner(),
            &passkey_enrollment(hosted, &passkey(), CREDENTIAL_ID),
            &hosted.issuer,
        )
        .expect("the host enrols the owner's passkey")
        .machine
}

/// `device`'s enrollment input for `machine`: its key and its proof.
fn keyed_enrollment(
    hosted: &HostedVault,
    machine: EntityId,
    device: &ed25519_dalek::SigningKey,
) -> OwnerKeyEnrollment {
    let public_key = device.verifying_key().to_bytes();
    let challenge = hosted
        .vault
        .owner_key_enrollment_challenge_as(&hosted.as_owner(), machine, &public_key)
        .expect("the device key's challenge");
    OwnerKeyEnrollment {
        machine,
        public_key,
        proof: device.sign(&challenge).to_bytes().to_vec(),
    }
}

/// A `BindActor` of `key` to `actor_ref` as `class` at `epoch`, signed by
/// `signer` alone.
fn binding(
    key: AuthorityKey,
    actor_ref: EntityId,
    class: &str,
    epoch: u64,
    signer: AuthorityKey,
) -> SignedRow {
    SignedRow {
        op: AuthorityOp::BindActor {
            authority_key: key,
            actor_ref,
            actor_class: class.to_owned(),
            epoch,
        },
        signer,
        cosigners: Vec::new(),
    }
}

/// The passkey's own first `human` binding of the owner, signed by itself.
fn self_binding(hosted: &HostedVault) -> SignedRow {
    binding(passkey_key(), hosted.owner, "human", 1, passkey_key())
}

/// The host enrols the owner's passkey and the passkey binds the owner;
/// asserts the binding counted and stands. Answers the carrier.
fn passkey_binds_its_owner(hosted: &HostedVault) -> EntityId {
    let machine = host_enrols_passkey(hosted);
    assert!(
        hosted.counts(self_binding(hosted), FLAGS_PRESENT_VERIFIED),
        "the fold counts the passkey's own first binding of its owner"
    );
    assert_eq!(
        hosted.binding_of(&passkey_key()),
        Some((hosted.owner, "human".to_owned(), 1, true)),
        "the passkey's binding names the owner, as human, at epoch 1"
    );
    machine
}

#[test]
fn a_passkey_only_owner_binds_with_their_own_passkey_and_their_owner_acts_pass() {
    let hosted = HostedVault::open();
    host_enrols_passkey(&hosted);
    assert!(
        !hosted.passes_owner_verbs(),
        "guard: the host-enrolled passkey binds no one, so the owner verbs answer \
         OWNER_BINDING_REQUIRED"
    );
    assert!(
        hosted.pins_a_learning_setting().is_err(),
        "guard: an unbound owner's owner write is refused"
    );
    assert!(
        hosted.counts(self_binding(&hosted), FLAGS_PRESENT_VERIFIED),
        "the fold counts the passkey's own first binding of its owner"
    );
    assert!(
        hosted.passes_owner_verbs(),
        "once the passkey binds them, the owner's owner verbs pass"
    );
    hosted
        .pins_a_learning_setting()
        .expect("once the passkey binds them, the owner pins a learning setting");
}

#[test]
fn the_bound_passkey_re_roots_nothing_and_ends_or_binds_no_other_owner_key() {
    let hosted = HostedVault::open();
    let machine = passkey_binds_its_owner(&hosted);
    hosted.enrol_device_key(machine);
    let device = ed_key(&owner_device());
    let re_root = SignedRow {
        op: AuthorityOp::ReRoot {
            new_device: DeviceAuthority {
                key: ed_key(&new_root()),
                transport_key_binding: [0; 32],
                attestation: AuthorityAttestation {
                    kind: "software".to_owned(),
                    evidence: Vec::new(),
                },
                tier: AuthorityTier::Software,
                roles: ROLE_OWNER,
            },
        },
        signer: passkey_key(),
        cosigners: Vec::new(),
    };
    assert!(
        !hosted.counts(re_root, FLAGS_PRESENT_VERIFIED),
        "the bound passkey re-roots nothing"
    );
    assert!(
        !hosted.live_owner_key(&ed_key(&new_root())),
        "no new root stands"
    );
    let revoke = SignedRow {
        op: AuthorityOp::RevokeDevice {
            revoked_key: device.clone(),
        },
        signer: passkey_key(),
        cosigners: Vec::new(),
    };
    assert!(
        !hosted.counts(revoke, FLAGS_PRESENT_VERIFIED),
        "the bound passkey revokes no other owner key"
    );
    assert!(
        hosted.live_owner_key(&device),
        "the owner's device key stands"
    );
    assert!(
        !hosted.counts(
            binding(device.clone(), hosted.owner, "human", 1, passkey_key()),
            FLAGS_PRESENT_VERIFIED,
        ),
        "the bound passkey binds no other key"
    );
    assert_eq!(
        hosted.binding_of(&device),
        None,
        "the device key stays unbound"
    );
    let rebind = SignedRow {
        op: AuthorityOp::RebindActor {
            authority_key: passkey_key(),
            actor_ref: EntityId::now(),
            actor_class: "human".to_owned(),
            epoch: 2,
        },
        signer: passkey_key(),
        cosigners: Vec::new(),
    };
    assert!(
        !hosted.counts(rebind, FLAGS_PRESENT_VERIFIED),
        "the bound passkey rebinds itself to no one"
    );
    assert_eq!(
        hosted.binding_of(&passkey_key()),
        Some((hosted.owner, "human".to_owned(), 1, true)),
        "the passkey's own binding stands as it was"
    );
}

#[test]
fn the_binding_confirms_no_vouch_and_the_vouched_key_stays_limited() {
    let hosted = HostedVault::open();
    let machine = passkey_binds_its_owner(&hosted);
    hosted.enrol_device_key(machine);
    hosted
        .vault
        .enrol_owner_signing_key_as(
            &hosted.as_owner(),
            keyed_enrollment(&hosted, machine, &vouched_device()),
            passkey_key(),
            |transcript| {
                Ok(hosted.signs(&passkey_key(), transcript, FLAGS_PRESENT_VERIFIED, ORIGIN))
            },
        )
        .expect("the bound passkey vouches for a device key, as any passkey may");
    assert!(
        hosted.live_owner_key(&ed_key(&vouched_device())),
        "guard: the vouched key is a live owner key"
    );
    let revoked = revoke_owner_key_signed_by(
        &hosted.vault,
        ed_key(&vouched_device()),
        ed_key(&owner_device()),
        |transcript| vouched_device().sign(transcript).to_bytes().to_vec(),
    )
    .unwrap_or(false);
    assert!(
        !revoked,
        "a key the bound passkey vouched for still revokes no other owner key"
    );
    assert!(
        hosted.live_owner_key(&ed_key(&owner_device())),
        "the owner's device key stands"
    );
}

#[test]
fn a_passkey_whose_binding_was_revoked_binds_never_again() {
    let hosted = HostedVault::open();
    let machine = passkey_binds_its_owner(&hosted);
    hosted.enrol_device_key(machine);
    let revoke = SignedRow {
        op: AuthorityOp::RevokeActor {
            authority_key: passkey_key(),
            epoch: 1,
        },
        signer: ed_key(&owner_device()),
        cosigners: Vec::new(),
    };
    assert!(
        hosted.counts(revoke, FLAGS_PRESENT_VERIFIED),
        "guard: the owner's device key revokes the passkey's binding"
    );
    for epoch in [1, 2] {
        assert!(
            !hosted.counts(
                binding(passkey_key(), hosted.owner, "human", epoch, passkey_key()),
                FLAGS_PRESENT_VERIFIED,
            ),
            "the passkey signs no binding once its first one was revoked (epoch {epoch})"
        );
    }
}

#[test]
fn a_passkey_binds_itself_to_no_other_actor_class_or_epoch() {
    let hosted = HostedVault::open();
    host_enrols_passkey(&hosted);
    let stranger = EntityId::now();
    for (actor, class, epoch, what) in [
        (stranger, "human", 1, "another person"),
        (hosted.owner, "agent", 1, "the owner as an agent"),
        (hosted.owner, "human", 2, "the owner at epoch 2"),
    ] {
        assert!(
            !hosted.counts(
                binding(passkey_key(), actor, class, epoch, passkey_key()),
                FLAGS_PRESENT_VERIFIED,
            ),
            "the passkey binds itself to {what}: it must not count"
        );
    }
    assert_eq!(
        hosted.binding_of(&passkey_key()),
        None,
        "the passkey is unbound"
    );
}

#[test]
fn a_self_binding_cosigned_raw_signed_unverified_or_made_elsewhere_counts_for_nothing() {
    let hosted = HostedVault::open();
    host_enrols_passkey(&hosted);
    let mut cosigned = self_binding(&hosted);
    cosigned.cosigners = vec![hosted.issuer.public_key()];
    assert!(
        !hosted.counts(cosigned, FLAGS_PRESENT_VERIFIED),
        "a self-binding the host root cosigns counts for nothing"
    );
    assert!(
        !hosted.counts_signed(self_binding(&hosted), |_, transcript| {
            let signature: P256Signature = passkey().sign(transcript);
            signature.to_bytes().to_vec()
        }),
        "a self-binding with a raw P-256 signature, no assertion, counts for nothing"
    );
    assert!(
        !hosted.counts(self_binding(&hosted), FLAGS_PRESENT_ONLY),
        "a self-binding the authenticator made without verifying the person counts for nothing"
    );
    assert!(
        !hosted.counts_signed(self_binding(&hosted), |key, transcript| {
            hosted.signs(key, transcript, FLAGS_PRESENT_VERIFIED, SIBLING_ORIGIN)
        }),
        "a self-binding asserted on another page than the enrolment's counts for nothing"
    );
    assert_eq!(
        hosted.binding_of(&passkey_key()),
        None,
        "the passkey is unbound"
    );
    assert!(!hosted.passes_owner_verbs(), "the owner stays unbound");
}

#[test]
fn a_passkey_no_host_vouched_for_binds_no_one() {
    let hosted = HostedVault::open();
    let machine = host_enrols_passkey(&hosted);
    hosted.enrol_device_key(machine);
    // The owner's device key enrols a second passkey: no host vouched for it.
    let second = roster_key_of(&second_passkey());
    hosted
        .vault
        .enrol_owner_passkey_as(
            &hosted.as_owner(),
            &passkey_enrollment(&hosted, &second_passkey(), SECOND_CREDENTIAL_ID),
            ed_key(&owner_device()),
            |transcript| Ok(owner_device().sign(transcript).to_bytes().to_vec()),
        )
        .expect("the owner's device key enrols a second passkey");
    assert!(
        hosted.live_owner_key(&second),
        "guard: the second passkey is a live owner key"
    );
    assert!(
        !hosted.counts(
            binding(second.clone(), hosted.owner, "human", 1, second.clone()),
            FLAGS_PRESENT_VERIFIED,
        ),
        "a passkey a key of the owner's enrolled signs no binding of its own"
    );
    assert_eq!(
        hosted.binding_of(&second),
        None,
        "the second passkey is unbound"
    );
}

#[test]
fn a_passkey_only_another_passkey_vouched_for_binds_no_one() {
    let hosted = HostedVault::open();
    host_enrols_passkey(&hosted);
    let second = roster_key_of(&second_passkey());
    hosted
        .vault
        .enrol_owner_passkey_as(
            &hosted.as_owner(),
            &passkey_enrollment(&hosted, &second_passkey(), SECOND_CREDENTIAL_ID),
            passkey_key(),
            |transcript| {
                Ok(hosted.signs(&passkey_key(), transcript, FLAGS_PRESENT_VERIFIED, ORIGIN))
            },
        )
        .expect("the passkey vouches for a second passkey");
    assert!(
        hosted.live_owner_key(&second),
        "guard: the second passkey is a live owner key"
    );
    assert!(
        !hosted.counts(
            binding(second.clone(), hosted.owner, "human", 1, second.clone()),
            FLAGS_PRESENT_VERIFIED,
        ),
        "a passkey only another passkey vouched for signs no binding of its own"
    );
    assert_eq!(
        hosted.binding_of(&second),
        None,
        "the second passkey is unbound"
    );
}

/// The binding door and the owner key changes list (head only: the base has
/// neither the door nor the list's binding line).
mod door {
    use oneiron::authority::{OwnerKeyChangeKind, PreparedOwnerPasskeyBinding};
    use oneiron::error::RecordError;

    use super::*;

    impl HostedVault {
        fn prepare(&self, credential_id: &[u8]) -> oneiron::Result<PreparedOwnerPasskeyBinding> {
            self.vault
                .prepare_owner_passkey_binding_as(&self.as_owner(), credential_id)
        }

        /// The owner lands `prepared` with the passkey's assertion of
        /// `flags` over its challenge.
        fn land(
            &self,
            prepared: &PreparedOwnerPasskeyBinding,
            flags: u8,
        ) -> oneiron::Result<oneiron::authority::OwnerPasskeyBindingReceipt> {
            let assertion = assert_by(&passkey(), &prepared.challenge, flags, ORIGIN);
            self.vault.land_owner_passkey_binding_as(
                &self.as_owner(),
                &prepared.entry,
                envelope_of(&assertion),
            )
        }
    }

    fn assert_invalid<T: std::fmt::Debug>(result: oneiron::Result<T>, what: &str) {
        match result {
            Err(oneiron::Error::Record(RecordError::InvalidAuthorityLogBody(_))) => {}
            other => panic!("{what}: expected an invalid-body refusal, got {other:?}"),
        }
    }

    fn assert_refused<T: std::fmt::Debug>(result: oneiron::Result<T>, what: &str) {
        match result {
            Err(oneiron::Error::Record(RecordError::AuthorityRefused(_))) => {}
            other => panic!("{what}: expected an authority refusal, got {other:?}"),
        }
    }

    #[test]
    fn the_owner_binds_through_the_passkey_binding_door_and_every_device_lists_it() {
        let hosted = HostedVault::open();
        host_enrols_passkey(&hosted);
        assert!(!hosted.passes_owner_verbs(), "guard: the owner is unbound");
        let prepared = hosted
            .prepare(CREDENTIAL_ID)
            .expect("the binding is prepared");
        let receipt = hosted
            .land(&prepared, FLAGS_PRESENT_VERIFIED)
            .expect("the passkey's binding lands");
        assert_eq!(receipt.owner, hosted.owner, "the receipt names the owner");
        assert_eq!(receipt.epoch, 1, "a passkey's first binding is at epoch 1");
        assert_eq!(
            AuthorityKey::P256(receipt.public_key.clone()),
            passkey_key(),
            "the receipt names the passkey"
        );
        assert!(
            hosted.passes_owner_verbs(),
            "once bound, the owner's verbs pass"
        );
        let changes = hosted
            .vault
            .owner_key_changes(&hosted.proof)
            .expect("the owner key changes list");
        let listed = changes
            .iter()
            .find(|change| change.entry == receipt.entry)
            .expect("the list names the binding's entry");
        assert_eq!(
            listed.change,
            OwnerKeyChangeKind::OwnerBound,
            "the list names the passkey's binding of its owner"
        );
        assert_eq!(
            listed.public_key,
            passkey_key(),
            "the list names the passkey"
        );
        assert_eq!(
            listed.signed_by,
            passkey_key(),
            "the list names the passkey as its signer"
        );
        assert_refused(
            hosted.prepare(CREDENTIAL_ID),
            "a second binding of a bound owner",
        );
    }

    #[test]
    fn the_door_lands_no_binding_without_the_passkeys_verified_assertion() {
        let hosted = HostedVault::open();
        host_enrols_passkey(&hosted);
        assert_invalid(
            hosted.prepare(SECOND_CREDENTIAL_ID),
            "a credential id no passkey of the owner's carries",
        );
        let prepared = hosted
            .prepare(CREDENTIAL_ID)
            .expect("the binding is prepared");
        assert_invalid(
            hosted.land(&prepared, FLAGS_PRESENT_ONLY),
            "an assertion made without verifying the person",
        );
        assert_invalid(
            hosted.vault.land_owner_passkey_binding_as(
                &hosted.as_owner(),
                &prepared.entry,
                vec![0; 64],
            ),
            "a raw signature in place of an assertion",
        );
        let mut changed = prepared.clone();
        if let Some(last) = changed.entry.last_mut() {
            *last ^= 1;
        }
        assert_invalid(
            hosted.land(&changed, FLAGS_PRESENT_VERIFIED),
            "an entry changed in hand",
        );
        assert_eq!(
            hosted.binding_of(&passkey_key()),
            None,
            "nothing was written"
        );
        hosted
            .land(&prepared, FLAGS_PRESENT_VERIFIED)
            .expect("the prepared binding still lands with the passkey's assertion");
    }

    #[test]
    fn the_door_offers_no_binding_to_a_passkey_no_host_vouched_for() {
        let hosted = HostedVault::open();
        let machine = host_enrols_passkey(&hosted);
        hosted.enrol_device_key(machine);
        hosted
            .vault
            .enrol_owner_passkey_as(
                &hosted.as_owner(),
                &passkey_enrollment(&hosted, &second_passkey(), SECOND_CREDENTIAL_ID),
                ed_key(&owner_device()),
                |transcript| Ok(owner_device().sign(transcript).to_bytes().to_vec()),
            )
            .expect("the owner's device key enrols a second passkey");
        assert_invalid(
            hosted.prepare(SECOND_CREDENTIAL_ID),
            "a passkey a key of the owner's enrolled",
        );
    }
}
