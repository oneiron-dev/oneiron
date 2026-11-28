//! An owner key vouches for another device's new key (pass 27 R2; MFA-1 A:
//! vault authority on a new device comes from an old device by QR approval).
//! The new device makes its key and the key's proof of possession alone and
//! writes nothing; an owner device that holds a key the vault trusts as the
//! owner's enrols it, as the entry's predecessor, carried by its own install.
//! On a hosted vault the host's custodial root signs nothing of it, and an
//! install that holds only that root vouches for nothing.
//!
//! Sol xhigh on 060e227ce0ac (F1, F2, F3, F6, F8): the vouching key is the
//! deciding owner's own, so a co-owner's key vouches no key into another
//! owner; the request carries its machine's install-key signature, and an
//! install the owner never answered as theirs makes no owner key; text and
//! bytes past a request's bound are refused before they are decoded; a label
//! carries no bidirectional override or invisible character; the host-only
//! refusal runs on a new device the owner answered as work or school, since
//! "yours" would wait for the owner key no install there holds.
//!
//! Red at the base (OPUS-SPLIT-6's carrier top 6ec8b3b708f0): the file does
//! not compile, as neither door nor the request exists. Green at the head.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test owner_key_vouch`.
//!
//! REVIEW2 #8796 P3-1: an agent's act is refused at both doors before
//! anything is readied, and a machine with a removed chain is refused
//! although another chain of it is live and the owner's. Red on the mutation
//! branch that drops those two checks, green at the head.
//!
//! FIX APPOINTMENT-PIN-STEP-AND-VOUCH-ENTRY-FOLD-NO-TEST: the vouching key
//! signs on the fold of the entry it signs, which the enrollment's writer
//! reads, so a key revoked after the door picked it refuses its own
//! signature. Red with the key asked on the fold of the door's earlier read:
//! it signs there, and the append's admission refuses the row instead.
//!
//! FIX VOUCH-DOOR-ROLE-CHECK-OUTSIDE-WRITE: the holding machine is judged
//! the owner's again on the fold of the entry the vouching key signs, so a
//! machine the owner answered as a hosted node after the door's read takes
//! no owner key. FIX VOUCH-DOOR-LABEL-NOT-RECHECKED: the owner device's door
//! refuses a request whose label breaks its rules as the label's. Red at
//! main 3c75f527c38 (the key enrols; the machine proof's refusal answers),
//! green at the head.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use oneiron::authority::{
    ActAuthority, ActSurface, AuthorityEntryHash, AuthorityKey, AuthorityLogEntry,
    CheckpointRootSigner, DeviceOwnerKeyVouch, HostSlipIssuer, MachineAnswerLanding,
    MachineOwnership, MachineRole, OWNER_KEY_VOUCH_LABEL_MAX, OwnerActKind, OwnerKeyVouchRequest,
    OwnerProofGround, ROLE_OWNER, authority_entry_hash, decode_authority_log_entry_body,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::error::RecordError;
use oneiron::federation::{FederationGrantRole, InitialSharedMember, Scope, ScopeAxis};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_doors::owner_key_vouch_between::enrol_vouched_owner_signing_key_between;
use oneiron::test_doors::owner_key_vouch_holding_machine::require_holding_machine_beside_anchor_chain;
use oneiron::test_doors::passkey_vouch_limits::revoke_owner_key_signed_by;
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::world_keys::OwnerActImportance;
use oneiron::{EntityId, Error, HostingPrivacyPosture, TimeRange, Vault, VaultConfig};
use oneiron_keystore::{
    AuthBoundSecretStore, DeviceKeystore, KeystoreAssurance, KeystoreLocality, KeystoreSlot,
    MemoryKeystore, SealedBytesStore,
};
use zeroize::Zeroizing;

/// The co-Owner fixture's shared vault id.
const SHARED: u64 = 27;

/// What an owner signing key answers when the roster it is asked on does not
/// list it live (`KEY_NOT_LIVE` of `world_keys::owner_signing`).
const KEY_NOT_LIVE: &str = "the roster does not list this owner signing key live";

/// What the vouch door answers for a machine the owner has not answered as
/// theirs (`MACHINE_NOT_THE_OWNERS` of `authority::owner_key_vouch`).
const MACHINE_NOT_THE_OWNERS: &str = "an owner key is held only on a machine the owner \
                                      answered as theirs; this one is a hosted or execution \
                                      node, or unanswered";

/// What the vouch door answers for a label that breaks its rules
/// (`LABEL_NOT_VALID` of `authority::owner_key_vouch`).
const LABEL_NOT_VALID: &str = "a device label is at most 64 bytes of text with no control or \
                               invisible format characters";

fn hosted_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.privacy.posture = HostingPrivacyPosture::Hosted;
    config
}

fn owner_act(proof: &AuthenticatedOwner) -> ActAuthority {
    ActAuthority::Owner(proof.clone(), ActSurface::ThisInstall)
}

fn person_proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof")
}

/// The request `vault`'s door makes for its own key as `authority`'s owner.
fn request_on(vault: &Vault, authority: &ActAuthority) -> OwnerKeyVouchRequest {
    match vault
        .device_owner_key_vouch_request(authority, "Laptop")
        .expect("the install makes its key's request")
    {
        DeviceOwnerKeyVouch::Request(request) => request,
        DeviceOwnerKeyVouch::Enrolled(receipt) => {
            panic!("the install's key is not enrolled yet: {receipt:?}")
        }
    }
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
/// machine ("yours") by the owner device, holding no owner key. It takes the
/// vault's authority history from the owner device, as sync does.
struct NewDevice {
    vault: Vault,
    machine: EntityId,
    held: BTreeSet<Vec<u8>>,
    _dir: tempfile::TempDir,
}

fn new_device(owner: &OwnerDevice) -> NewDevice {
    new_device_as(owner, MachineRole::Owned(MachineOwnership::Yours))
}

/// [`new_device`], the owner device answering the new machine as `role`.
fn new_device_as(owner: &OwnerDevice, role: MachineRole) -> NewDevice {
    new_device_on(owner, role, Arc::new(MemoryKeystore::default()))
}

/// [`new_device_as`], the new device's install keeping its slots in
/// `keystore`.
fn new_device_on(
    owner: &OwnerDevice,
    role: MachineRole,
    keystore: Arc<dyn DeviceKeystore>,
) -> NewDevice {
    let dir = tempfile::tempdir().expect("vault directory");
    let vault = Vault::open(dir.path(), hosted_config()).expect("the new device's install");
    vault.install_device_keystore(keystore);
    let key = vault
        .machine_encryption_key(owner.vault_id)
        .expect("the new device's encryption key");
    let request = vault
        .machine_enrolment_request(owner.vault_id, key)
        .expect("the new device's enrolment request");
    let landing = owner
        .vault
        .enroll_machine(&owner.proof, ActSurface::ThisInstall, &request, role, None)
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
            .import_signed_authority_history(&new, &std::collections::BTreeMap::new())
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
        request_on(&self.vault, &owner_act(&self.proof()))
    }
}

/// A memory keystore that counts every slot read and write, so a test can
/// show that a door read and made no slot.
#[derive(Default)]
struct CountedKeystore {
    slots: MemoryKeystore,
    touched: AtomicUsize,
}

impl CountedKeystore {
    /// The slot reads and writes so far.
    fn touched(&self) -> usize {
        self.touched.load(Ordering::SeqCst)
    }

    fn touch(&self) {
        self.touched.fetch_add(1, Ordering::SeqCst);
    }
}

impl DeviceKeystore for CountedKeystore {
    fn get(&self, slot: &KeystoreSlot) -> oneiron_keystore::Result<Option<Zeroizing<[u8; 32]>>> {
        self.touch();
        self.slots.get(slot)
    }

    fn create(&self, slot: &KeystoreSlot, secret: &[u8; 32]) -> oneiron_keystore::Result<()> {
        self.touch();
        self.slots.create(slot, secret)
    }

    fn delete(&self, slot: &KeystoreSlot) -> oneiron_keystore::Result<()> {
        self.touch();
        self.slots.delete(slot)
    }

    fn replace(&self, slot: &KeystoreSlot, secret: &[u8; 32]) -> oneiron_keystore::Result<bool> {
        self.touch();
        self.slots.replace(slot, secret)
    }

    fn locality(&self) -> KeystoreLocality {
        self.slots.locality()
    }

    fn assurance(&self) -> KeystoreAssurance {
        self.slots.assurance()
    }

    fn sealed_bytes(&self) -> Option<&dyn SealedBytesStore> {
        self.slots.sealed_bytes()
    }

    fn auth_bound_secret(&self) -> Option<&dyn AuthBoundSecretStore> {
        self.slots.auth_bound_secret()
    }
}

/// An agent's act on `vault`: a named agent whose live Grant from `owner`
/// names the free-time policy act, one of the acts an agent's Grant may name.
fn agent_act(vault: &Vault, owner: &AuthenticatedOwner) -> ActAuthority {
    let agent = vault
        .ensure_agent_principal("owner-key-vouch-agent")
        .expect("a named agent");
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from([
        "read".to_owned(),
        "free_time_policy_set".to_owned(),
    ]));
    let minted = mint_agent_grant_as(
        vault,
        owner,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
            check_in_ref: None,
        },
    )
    .expect("the owner grants the agent the act");
    assert!(minted.grant.confers, "guard: the agent's Grant is live");
    ActAuthority::Agent(
        vault
            .granted_act(agent, minted.grant.grant_ref, OwnerActKind::FreeTimePolicy)
            .expect("the agent's Grant names the act"),
    )
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

/// The vouching key is revoked after the door's read picked it and before
/// the enrollment's writer. The key is asked on the fold of the entry it
/// signs, which the writer reads after the revoke, so its own check refuses
/// the signature: the writer stores nothing and the new key is not enrolled.
#[test]
fn a_vouching_key_revoked_after_the_pick_refuses_its_signature_and_enrols_nothing() {
    let owner = owner_device(true);
    let vouching = owner.key.expect("the owner device's key");
    let vouching_key = AuthorityKey::Ed25519(vouching);
    let device = new_device(&owner);
    let request = device.request();
    let signer = owner
        .vault
        .device_owner_signing_key()
        .expect("the owner device's key, read from its slot");
    assert_eq!(
        signer.public_key(),
        vouching,
        "guard: the slot holds the enrolled owner key"
    );
    let picked_on = owner
        .vault
        .authority_fold()
        .expect("the owner device's fold");
    assert!(
        picked_on
            .roster
            .get(&vouching_key)
            .is_some_and(|listed| !listed.revoked),
        "guard: the vouching key is live when the door picks it"
    );

    let witness = owner
        .vault
        .owner_presence(OwnerActImportance::Ordinary, "a test signs a proof")
        .expect("an ordinary witness for the test's proof");
    let ground = OwnerProofGround::witnessed(&witness);
    let mut after_revoke = None;
    let refusal = enrol_vouched_owner_signing_key_between(
        &owner.vault,
        &owner_act(&owner.proof),
        &request,
        || {
            let counted = revoke_owner_key_signed_by(
                &owner.vault,
                vouching_key.clone(),
                vouching_key.clone(),
                |transcript| {
                    signer
                        .sign_owner_proof(&owner.vault, &picked_on, &ground, transcript)
                        .expect("the key, live at the revoke's parents, signs its own revoke")
                },
            )
            .expect("the revoke is stored");
            assert!(counted, "guard: the owner key's own revoke counts");
            after_revoke = Some(owner.history());
        },
    )
    .expect_err("a key revoked since the door picked it vouches for no key");
    let after_revoke = after_revoke.expect("the revoke ran between the door's read and its writer");

    assert!(
        matches!(
            &refusal,
            Error::Record(RecordError::AuthorityRefused(reason)) if *reason == KEY_NOT_LIVE
        ),
        "the vouching key's own check refuses on the entry's fold: {refusal:?}"
    );
    assert_eq!(
        owner.history(),
        after_revoke,
        "the refused vouch stores no row"
    );
    assert!(
        !owner.roster_lists(request.public_key),
        "the new key is not enrolled"
    );
    assert!(
        owner
            .vault
            .authority_fold()
            .expect("the owner device's fold")
            .roster
            .get(&vouching_key)
            .is_some_and(|listed| listed.revoked),
        "the vouching key stays revoked"
    );
}

/// The owner answers the new device's machine as a hosted node after the
/// vouch door's read judged it the owner's and before the enrollment's
/// writer (FIX VOUCH-DOOR-ROLE-CHECK-OUTSIDE-WRITE). The holding machine is
/// judged again on the fold of the entry the vouching key signs, so the
/// vouch is refused as the machine's: the writer stores nothing and the new
/// key is not enrolled. Red at the base: the writer asked only that the
/// machine be live, in any role, and the key enrolled on a hosted node.
#[test]
fn a_machine_answered_as_a_hosted_node_after_the_read_takes_no_owner_key() {
    let owner = owner_device(true);
    let device = new_device(&owner);
    let request = device.request();

    let mut after_answer = None;
    let refusal = enrol_vouched_owner_signing_key_between(
        &owner.vault,
        &owner_act(&owner.proof),
        &request,
        || {
            let landing = owner
                .vault
                .set_machine_role(
                    &owner.proof,
                    ActSurface::ThisInstall,
                    device.machine,
                    MachineRole::HostedNode,
                    None,
                )
                .expect("the owner answers the new device's machine again");
            assert!(
                matches!(landing, MachineAnswerLanding::Stands(_)),
                "guard: the owner's answer stands: {landing:?}"
            );
            after_answer = Some(owner.history());
        },
    )
    .expect_err("a machine the owner answered as a hosted node takes no owner key");
    let after_answer = after_answer.expect("the answer ran between the door's read and its writer");

    assert!(
        matches!(
            &refusal,
            Error::Record(RecordError::AuthorityRefused(reason))
                if *reason == MACHINE_NOT_THE_OWNERS
        ),
        "the holding machine is refused on the entry's fold: {refusal:?}"
    );
    assert_eq!(
        owner.history(),
        after_answer,
        "the refused vouch stores no row"
    );
    assert!(
        !owner.roster_lists(request.public_key),
        "the new key is not enrolled"
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
/// hosted vault trusts as the owner's, so it vouches for nothing. The new
/// device is the owner's work or school machine: answering it "yours" would
/// wait for an owner key's proof, which no install of this vault holds (Sol
/// F8).
#[test]
fn an_install_that_holds_no_owner_key_vouches_for_nothing() {
    let owner = owner_device(false);
    owner
        .vault
        .hold_checkpoint_root_signer(owner.issuer.clone());
    let device = new_device_as(&owner, MachineRole::Owned(MachineOwnership::WorkSchool));
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

/// A request for another vault, whose proof is not the key's own, or that
/// the install key of the machine it names did not sign, is refused before
/// anything is written.
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
    let mut forged_machine = request.clone();
    forged_machine.machine_proof[0] ^= 1;
    for (case, bad) in [
        ("another vault", other_vault),
        ("a forged proof", forged),
        ("a forged machine proof", forged_machine),
    ] {
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
        machine_proof: vec![4; 64],
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
    let mut long_label = request.clone();
    long_label.label = "x".repeat(OWNER_KEY_VOUCH_LABEL_MAX + 1);
    assert!(
        OwnerKeyVouchRequest::from_bytes(&long_label.to_bytes().unwrap()).is_err(),
        "a label over its bound is refused"
    );
    for (case, label) in [
        ("a right-to-left override", "Lap\u{202E}pot"),
        ("a zero-width space", "Lap\u{200B}top"),
        ("a line separator", "Lap\u{2028}top"),
    ] {
        let mut hidden = request.clone();
        hidden.label = label.to_owned();
        assert!(
            OwnerKeyVouchRequest::from_bytes(&hidden.to_bytes().unwrap()).is_err(),
            "a label with {case} is refused"
        );
    }
    let mut wide = request;
    wide.label = "\u{00E9}".repeat(OWNER_KEY_VOUCH_LABEL_MAX / 2);
    assert_eq!(
        OwnerKeyVouchRequest::from_bytes(&wide.to_bytes().unwrap()),
        Ok(wide.clone()),
        "a label of exactly its bound in two-byte characters reads back"
    );
}

/// Text or bytes longer than any request are refused before they are
/// decoded, and so is a body that is not one flat map (Sol F3).
#[test]
fn a_request_past_its_bound_is_refused_before_it_is_decoded() {
    let long_text = format!(
        "{}{}",
        oneiron::authority::OWNER_KEY_VOUCH_TEXT_PREFIX,
        "A".repeat(1 << 20)
    );
    assert!(
        OwnerKeyVouchRequest::from_text(&long_text).is_err(),
        "a megabyte of text is refused"
    );
    let mut long_bytes = vec![0xc5, 0xff, 0xff];
    long_bytes.resize(0xffff + 3, 0);
    assert!(
        OwnerKeyVouchRequest::from_bytes(&long_bytes).is_err(),
        "a 64 KiB binary is refused"
    );
    let nested = [0x81, 0xa1, b'a', 0x91, 0x90];
    assert!(
        OwnerKeyVouchRequest::from_bytes(&nested).is_err(),
        "a nested body is refused"
    );
}

/// A co-owner's key never vouches a key into another owner (Sol F1): on a
/// self-hosted shared vault whose host root holds the owner's `human`
/// binding, a co-Owner signed in on that install holds no key of their own
/// there, so their request for the install's key is refused and nothing is
/// written; the owner's own request for the same key vouches.
#[test]
fn a_co_owners_key_never_vouches_for_another_owner() {
    let dir = tempfile::tempdir().expect("vault directory");
    let mut config = VaultConfig::device();
    config.privacy.posture = HostingPrivacyPosture::SelfHostLocal;
    let vault = Vault::open(dir.path(), config).expect("the self-hosted install");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = Arc::new(oneiron::test_support::provision_engine_machines(&vault));
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Owned(MachineOwnership::Yours))
        .expect("this install is the owner's machine");
    vault.hold_checkpoint_root_signer(issuer.clone());
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    oneiron::test_support::bind_host_owner(&vault, issuer.as_ref(), owner)
        .expect("the host root holds the owner's binding");
    vault
        .initialize_shared_vault(
            &person_proof(&vault, owner),
            SHARED,
            None,
            &[InitialSharedMember {
                member_ref: owner,
                role: Some(FederationGrantRole::Owner),
            }],
            1,
        )
        .expect("a shared vault");
    let co_owner = EntityId::now();
    vault
        .put_entity(
            &co_owner,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
    let owner_proof = person_proof(&vault, owner);
    let act = vault
        .propose_add_owner(&owner_proof, SHARED, co_owner)
        .expect("the owner starts add_owner");
    vault
        .execute_completed_shared_act(&owner_proof, &act.id, Some(issuer.as_ref()))
        .expect("add_owner runs at once");
    let history = || {
        vault
            .export_signed_authority_history()
            .expect("the install's history")
            .len()
    };
    let lists = |key: [u8; 32]| {
        vault
            .authority_fold()
            .expect("the fold")
            .roster
            .contains_key(&AuthorityKey::Ed25519(key))
    };

    let co_owner_act = owner_act(&person_proof(&vault, co_owner));
    let theirs = request_on(&vault, &co_owner_act);
    let rows = history();
    let refused = vault
        .enrol_vouched_owner_signing_key(&co_owner_act, &theirs)
        .expect_err("the owner's host root is not the co-Owner's key");
    assert!(
        matches!(refused, Error::Record(RecordError::OwnerKeyRequired)),
        "the co-Owner holds no key of their own here: {refused:?}"
    );
    assert!(!lists(theirs.public_key), "the key is not enrolled");
    assert_eq!(history(), rows, "nothing was written");

    let owner_authority = owner_act(&owner_proof);
    let own = request_on(&vault, &owner_authority);
    assert_eq!(
        own.public_key, theirs.public_key,
        "guard: one key in this install's slot"
    );
    let receipt = vault
        .enrol_vouched_owner_signing_key(&owner_authority, &own)
        .expect("the owner's own root vouches for the owner's request");
    assert_eq!(receipt.public_key, own.public_key);
    assert!(lists(own.public_key), "the owner's key is enrolled");
}

/// An install the owner never answered as theirs makes no owner key by a
/// vouch: the hosted vault's own serving install (unanswered) asks for its
/// key, and the request is refused before anything is written (ruling
/// CARRIER-HOSTED-SERVER-OWNER-KEY = A; Sol F2).
#[test]
fn an_install_the_owner_never_answered_makes_no_owner_key() {
    let owner = owner_device(false);
    let request = request_on(&owner.vault, &owner_act(&owner.proof));
    let rows = owner.history().len();
    let refused = owner
        .vouch(&request)
        .expect_err("an unanswered install holds no owner key");
    assert!(
        matches!(refused, Error::Record(RecordError::AuthorityRefused(_))),
        "an authority refusal: {refused:?}"
    );
    assert!(
        !owner.roster_lists(request.public_key),
        "the key is not enrolled"
    );
    assert_eq!(owner.history().len(), rows, "nothing was written");
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

/// A request whose label breaks its rules is refused as the label's at the
/// owner device's door, and nothing is written (FIX
/// VOUCH-DOOR-LABEL-NOT-RECHECKED): the decoders and the new device's door
/// keep the rules, and a request built in code reaches the vouch door
/// without either. Red at the base: the door never read the label, and the
/// request was refused only because its machine proof, which covers the
/// label, no longer verified.
#[test]
fn a_request_whose_label_breaks_its_rules_is_refused_as_the_labels() {
    let owner = owner_device(true);
    let device = new_device(&owner);
    let mut request = device.request();
    request.label = "Laptop\u{202e}".to_owned();
    let rows = owner.history().len();

    let refused = owner
        .vouch(&request)
        .expect_err("a label with a bidirectional override");

    assert!(
        matches!(
            &refused,
            Error::Record(RecordError::InvalidAuthorityLogBody(reason))
                if *reason == LABEL_NOT_VALID
        ),
        "the label's refusal: {refused:?}"
    );
    assert!(
        !owner.roster_lists(request.public_key),
        "the key is not enrolled"
    );
    assert_eq!(owner.history().len(), rows, "nothing was written");
}

/// An agent's act is refused at both doors before anything is readied
/// (REVIEW2 #8796 P3-1 a): the new device's request door reads and makes no
/// keystore slot for it, and the owner device's vouch writes nothing. Both
/// doors refuse an agent's act by its kind before they read its Grant, so
/// the act the owner device's Grant names is an agent's act at both.
#[test]
fn an_agents_act_is_refused_at_both_doors_before_anything_is_readied() {
    let owner = owner_device(true);
    let keystore = Arc::new(CountedKeystore::default());
    let device = new_device_on(
        &owner,
        MachineRole::Owned(MachineOwnership::Yours),
        keystore.clone(),
    );
    let agent = agent_act(&owner.vault, &owner.proof);

    let touched = keystore.touched();
    let refused = device
        .vault
        .device_owner_key_vouch_request(&agent, "Laptop")
        .expect_err("an agent asks for no owner key");
    assert!(
        matches!(refused, Error::Record(RecordError::AuthorityRefused(_))),
        "an authority refusal: {refused:?}"
    );
    assert_eq!(
        keystore.touched(),
        touched,
        "the request door read and made no slot for the agent"
    );
    let request = device.request();
    assert!(
        keystore.touched() > touched,
        "guard: the owner's own ask reads and makes the slot"
    );

    let rows = owner.history().len();
    let refused = owner
        .vault
        .enrol_vouched_owner_signing_key(&agent, &request)
        .expect_err("an agent vouches for no owner key");
    assert!(
        matches!(refused, Error::Record(RecordError::AuthorityRefused(_))),
        "an authority refusal: {refused:?}"
    );
    assert!(
        !owner.roster_lists(request.public_key),
        "the key is not enrolled"
    );
    assert_eq!(owner.history().len(), rows, "nothing was written");
    owner
        .vouch(&request)
        .expect("guard: the owner's own act vouches for the same request");
}

/// A machine with a removed chain makes no owner key, although another
/// chain of it is live and the owner's (REVIEW2 #8796 P3-1 b): on the owner
/// device's fold shaped so the new device's machine has an anchor's chain
/// beside its roster chain, both live and `Owned(Yours)`, the vouch door's
/// holding-machine check admits the request; once the roster chain is
/// removed it refuses the request, although the anchor's chain still says
/// "yours".
#[test]
fn a_machine_with_a_removed_chain_is_refused_beside_a_live_owned_chain() {
    let owner = owner_device(true);
    let device = new_device(&owner);
    let request = device.request();
    let anchor = [7; 32];
    require_holding_machine_beside_anchor_chain(&owner.vault, &request, anchor, false)
        .expect("guard: two live chains the owner answered as theirs admit the machine");
    let refused = require_holding_machine_beside_anchor_chain(&owner.vault, &request, anchor, true)
        .expect_err("a removed chain refuses the machine");
    assert!(
        matches!(
            refused,
            Error::Record(RecordError::InvalidAuthorityLogBody(_))
        ),
        "no live chain of a machine with a removed chain verifies its proof: {refused:?}"
    );
}
