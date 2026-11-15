//! An owner key vouches for another device's new key (pass 27 R2; MFA-1 A:
//! vault authority on a new device comes from an old device by QR approval).
//! The new device makes its key and the key's proof of possession alone and
//! writes nothing; an owner device that holds a key the vault trusts as the
//! owner's enrols it, as the entry's predecessor, carried by its own install.
//! On a hosted vault the host's custodial root signs nothing of it, and an
//! install that holds only that root vouches for nothing.
//!
//! Red at the base (OPUS-SPLIT-6's carrier top 6ec8b3b708f0): the file does
//! not compile, as neither door nor the request exists. Green at the head.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test owner_key_vouch`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{
    ActAuthority, ActSurface, AuthorityEntryHash, AuthorityKey, AuthorityLogEntry,
    CheckpointRootSigner, DeviceOwnerKeyVouch, HostSlipIssuer, MachineAnswerLanding,
    MachineOwnership, MachineRole, OWNER_KEY_VOUCH_LABEL_MAX, OwnerKeyVouchRequest, ROLE_OWNER,
    authority_entry_hash, decode_authority_log_entry_body,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::error::RecordError;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EntityId, Error, HostingPrivacyPosture, Vault, VaultConfig};

fn hosted_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.privacy.posture = HostingPrivacyPosture::Hosted;
    config
}

fn owner_act(proof: &AuthenticatedOwner) -> ActAuthority {
    ActAuthority::Owner(proof.clone(), ActSurface::ThisInstall)
}

/// The owner's device: an install of a hosted vault rooted under the test
/// host (a custodial root), its own machine profile live, the owner bound
/// and authenticated. With `with_key` it holds its own enrolled owner key,
/// which the host root enrolled (the door main has today).
struct OwnerDevice {
    vault: Vault,
    issuer: Arc<HostSlipIssuer>,
    proof: AuthenticatedOwner,
    vault_id: [u8; 32],
    key: Option<[u8; 32]>,
    _dir: tempfile::TempDir,
}

fn owner_device(with_key: bool) -> OwnerDevice {
    let dir = tempfile::tempdir().expect("vault directory");
    let vault = Vault::open(dir.path(), hosted_config()).expect("the owner device's install");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = Arc::new(oneiron::test_support::provision_engine_machines(&vault));
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's machine profile under the host root");
    let (_, proof) = embedded_owner(&vault).expect("the authenticated owner");
    let key = with_key.then(|| {
        vault
            .enrol_device_owner_signing_key(&owner_act(&proof), &issuer)
            .expect("the owner enrols this device's own owner key")
            .public_key
    });
    let vault_id = vault
        .authority_vault_id()
        .expect("the vault's fold")
        .expect("a rooted vault");
    OwnerDevice {
        vault,
        issuer,
        proof,
        vault_id,
        key,
        _dir: dir,
    }
}

impl OwnerDevice {
    fn vouch(
        &self,
        request: &OwnerKeyVouchRequest,
    ) -> oneiron::Result<oneiron::authority::OwnerKeyEnrollmentReceipt> {
        self.vault
            .enrol_vouched_owner_signing_key(&owner_act(&self.proof), request)
    }

    fn history(&self) -> Vec<Vec<u8>> {
        self.vault
            .export_signed_authority_history()
            .expect("the owner device's history")
    }

    /// The stored authority entry `hash` names.
    fn entry(&self, hash: AuthorityEntryHash) -> AuthorityLogEntry {
        self.history()
            .iter()
            .filter_map(|row| decode_authority_log_entry_body(row).ok())
            .find(|entry| authority_entry_hash(entry).is_ok_and(|found| found == hash))
            .expect("the entry is stored")
    }

    fn roster_lists(&self, key: [u8; 32]) -> bool {
        self.vault
            .authority_fold()
            .expect("the owner device's fold")
            .roster
            .contains_key(&AuthorityKey::Ed25519(key))
    }
}

/// The new device: its own install of the vault, enrolled as the owner's
/// machine by the owner device, holding no owner key. It takes the vault's
/// authority history from the owner device, as sync does.
struct NewDevice {
    vault: Vault,
    machine: EntityId,
    held: BTreeSet<Vec<u8>>,
    _dir: tempfile::TempDir,
}

fn new_device(owner: &OwnerDevice) -> NewDevice {
    let dir = tempfile::tempdir().expect("vault directory");
    let vault = Vault::open(dir.path(), hosted_config()).expect("the new device's install");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let key = vault
        .machine_encryption_key(owner.vault_id)
        .expect("the new device's encryption key");
    let request = vault
        .machine_enrolment_request(owner.vault_id, key)
        .expect("the new device's enrolment request");
    let landing = owner
        .vault
        .enroll_machine(
            &owner.proof,
            ActSurface::ThisInstall,
            &request,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("the owner enrols the new device as his");
    assert!(
        matches!(landing, MachineAnswerLanding::Stands(_)),
        "guard: the new device is a live machine of the vault: {landing:?}"
    );
    vault
        .ensure_embedded_owner_actor()
        .expect("the owner on the new device");
    let mut device = NewDevice {
        vault,
        machine: request.machine,
        held: BTreeSet::new(),
        _dir: dir,
    };
    device.take(owner);
    device
}

impl NewDevice {
    /// Imports the rows of the owner device's history this device does not
    /// hold yet.
    fn take(&mut self, owner: &OwnerDevice) {
        let new: Vec<Vec<u8>> = owner
            .history()
            .into_iter()
            .filter(|row| !self.held.contains(row))
            .collect();
        self.vault
            .import_signed_authority_history(&new)
            .expect("the new device takes the rows");
        self.held.extend(new);
    }

    fn proof(&self) -> AuthenticatedOwner {
        let person = self
            .vault
            .ensure_embedded_owner_actor()
            .expect("the owner on the new device");
        self.vault
            .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
            .expect("an owner proof on the new device")
    }

    fn vouch_request(&self, label: &str) -> oneiron::Result<DeviceOwnerKeyVouch> {
        self.vault
            .device_owner_key_vouch_request(&owner_act(&self.proof()), label)
    }

    fn request(&self) -> OwnerKeyVouchRequest {
        match self
            .vouch_request("Laptop")
            .expect("the new device makes its key's request")
        {
            DeviceOwnerKeyVouch::Request(request) => request,
            DeviceOwnerKeyVouch::Enrolled(receipt) => {
                panic!("the new device's key is not enrolled yet: {receipt:?}")
            }
        }
    }
}

/// The owner key on one device signs another device's new key in: the
/// entry's predecessor is that key, its carrier the owner device's install,
/// and the host's custodial root signs nothing. The new key is a live owner
/// key outside the host's custody.
#[test]
fn an_owner_key_on_one_device_enrols_another_devices_key_on_a_hosted_vault() {
    let owner = owner_device(true);
    let vouching = owner.key.expect("the owner device's key");
    let device = new_device(&owner);
    let request = device.request();
    assert_eq!(
        request.machine, device.machine,
        "the new device holds the key"
    );
    assert_eq!(
        request.vault_id, owner.vault_id,
        "the request names the vault"
    );
    assert!(
        !owner.roster_lists(request.public_key),
        "guard: making the request wrote nothing the owner device sees"
    );

    let receipt = owner
        .vouch(&request)
        .expect("the owner's key on the owner device vouches for the new key");
    assert_eq!(receipt.public_key, request.public_key);
    assert_eq!(receipt.machine, device.machine);

    let entry = owner.entry(receipt.entry);
    let host_root = owner.issuer.public_key();
    assert_eq!(
        entry.signer.public_key,
        AuthorityKey::Ed25519(vouching),
        "the owner's key on the owner device is the enrollment's predecessor"
    );
    assert!(
        entry.signer.public_key != host_root
            && entry
                .cosigns
                .iter()
                .all(|cosign| cosign.public_key != host_root),
        "the host's custodial root signs nothing of the enrollment"
    );
    let fold = owner
        .vault
        .authority_fold()
        .expect("the owner device's fold");
    let new_key = AuthorityKey::Ed25519(request.public_key);
    let listed = fold
        .roster
        .get(&new_key)
        .expect("the new key is on the roster");
    assert!(
        !listed.revoked && listed.roles & ROLE_OWNER != 0,
        "the new key is a live owner key"
    );
    assert!(
        !owner
            .vault
            .authority_key_in_host_custody(&new_key)
            .expect("custody read"),
        "the vouched key starts its own custody line on a hosted vault"
    );
}

/// Once the new device takes the row, its request door answers the
/// enrollment's receipt and its handle holds the key.
#[test]
fn the_new_device_holds_its_vouched_key_after_sync() {
    let owner = owner_device(true);
    let mut device = new_device(&owner);
    let request = device.request();
    let receipt = owner.vouch(&request).expect("the owner device vouches");
    device.take(&owner);
    match device
        .vouch_request("Laptop")
        .expect("the new device asks again")
    {
        DeviceOwnerKeyVouch::Enrolled(found) => assert_eq!(found, receipt),
        DeviceOwnerKeyVouch::Request(again) => {
            panic!("the new device's key is enrolled now: {again:?}")
        }
    }
    let root = AuthorityKey::Ed25519(request.public_key);
    assert!(
        device
            .vault
            .checkpoint_root_signers()
            .iter()
            .any(|signer| signer.root() == root),
        "the new device's handle holds its vouched key"
    );
}

/// Two owner devices may answer one ask: a second vouch of the same request
/// answers the first enrollment's receipt and writes nothing.
#[test]
fn a_second_vouch_of_the_same_request_answers_the_first_receipt() {
    let owner = owner_device(true);
    let device = new_device(&owner);
    let request = device.request();
    let first = owner.vouch(&request).expect("the first vouch");
    let rows = owner.history().len();
    let second = owner.vouch(&request).expect("the second vouch");
    assert_eq!(second, first, "the second answer is the first receipt");
    assert_eq!(
        owner.history().len(),
        rows,
        "the second answer writes nothing"
    );
}

/// An install that holds only the host's custodial root holds no key the
/// hosted vault trusts as the owner's, so it vouches for nothing.
#[test]
fn an_install_that_holds_no_owner_key_vouches_for_nothing() {
    let owner = owner_device(false);
    owner
        .vault
        .hold_checkpoint_root_signer(owner.issuer.clone());
    let device = new_device(&owner);
    let request = device.request();
    let rows = owner.history().len();
    let refused = owner
        .vouch(&request)
        .expect_err("the custodial root vouches for nothing");
    assert!(
        matches!(refused, Error::Record(RecordError::OwnerKeyRequired)),
        "the refusal asks for an owner key: {refused:?}"
    );
    assert!(
        !owner.roster_lists(request.public_key),
        "the key is not enrolled"
    );
    assert_eq!(owner.history().len(), rows, "nothing was written");
}

/// A request for another vault, or whose proof is not the key's own, is
/// refused before anything is written.
#[test]
fn a_request_for_another_vault_or_with_a_forged_proof_is_refused() {
    let owner = owner_device(true);
    let device = new_device(&owner);
    let request = device.request();
    let rows = owner.history().len();

    let mut other_vault = request.clone();
    other_vault.vault_id[0] ^= 1;
    let mut forged = request.clone();
    forged.proof[0] ^= 1;
    for (case, bad) in [("another vault", other_vault), ("a forged proof", forged)] {
        let refused = owner.vouch(&bad).expect_err(case);
        assert!(
            matches!(
                refused,
                Error::Record(RecordError::InvalidAuthorityLogBody(_))
            ),
            "{case} is an integrity refusal: {refused:?}"
        );
    }
    assert!(
        !owner.roster_lists(request.public_key),
        "the key is not enrolled"
    );
    assert_eq!(owner.history().len(), rows, "nothing was written");
    owner
        .vouch(&request)
        .expect("guard: the request as made still vouches");
}

/// The request's digest names its bytes, and its text (the QR payload)
/// reads back to the same request; a device label stays within its rules.
#[test]
fn the_request_digest_names_its_bytes_and_survives_its_text_form() {
    let request = OwnerKeyVouchRequest {
        vault_id: [1; 32],
        machine: EntityId::from_bytes([9; 16]).expect("a machine id"),
        public_key: [2; 32],
        proof: vec![3; 64],
        label: "Laptop".to_owned(),
    };
    let text = request.to_text().expect("the request's text");
    let read = OwnerKeyVouchRequest::from_text(&text).expect("the text reads back");
    assert_eq!(read, request);
    assert_eq!(read.digest().unwrap(), request.digest().unwrap());

    let mut relabelled = request.clone();
    relabelled.label = "Phone".to_owned();
    assert_ne!(
        relabelled.digest().unwrap(),
        request.digest().unwrap(),
        "a changed request is another digest"
    );

    let cut = text.get(..text.len() - 4).expect("a shorter text");
    assert!(
        OwnerKeyVouchRequest::from_text(cut).is_err(),
        "a cut text is refused"
    );
    assert!(
        OwnerKeyVouchRequest::from_text(text.trim_start_matches("oneiron-")).is_err(),
        "another prefix is refused"
    );
    let mut short_proof = request.clone();
    short_proof.proof.pop();
    assert!(
        OwnerKeyVouchRequest::from_bytes(&short_proof.to_bytes().unwrap()).is_err(),
        "a proof of another length is refused"
    );
    let mut long_label = request;
    long_label.label = "x".repeat(OWNER_KEY_VOUCH_LABEL_MAX + 1);
    assert!(
        OwnerKeyVouchRequest::from_bytes(&long_label.to_bytes().unwrap()).is_err(),
        "a label over its bound is refused"
    );
}

/// The new device's door refuses a label over its bound before it makes a
/// key.
#[test]
fn the_new_devices_door_refuses_a_label_over_its_bound() {
    let owner = owner_device(true);
    let device = new_device(&owner);
    let refused = device
        .vouch_request(&"x".repeat(OWNER_KEY_VOUCH_LABEL_MAX + 1))
        .expect_err("a label over its bound");
    assert!(
        matches!(
            refused,
            Error::Record(RecordError::InvalidAuthorityLogBody(_))
        ),
        "{refused:?}"
    );
}
