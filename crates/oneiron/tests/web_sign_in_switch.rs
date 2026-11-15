//! The owner switches a hosted vault back to web sign-in (row AUTH-5 PR c).
//!
//! A vault that has held an owner key asks for one until its owner switches
//! it back. The owner key this install holds proves the switch, on the value
//! the owner reviewed: an install that holds none switches nothing, and a key
//! enrolled since the review refuses it. A vault that never held an owner
//! key, one that runs on web sign-in already and a self-host vault have
//! nothing to switch.
//!
//! On web sign-in the last device key is removed with no question. A key
//! enrolled after the switch, or a later act of the setting with any other
//! value, makes the vault ask again. The changes list and the audit say what
//! the fold landed: only a landed switch is a switch there.
//!
//! Real hosted vaults whose serving install holds its owner key, with a
//! second machine and key enrolled where a test needs them.

#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActAuthority, ActSurface, AuthorityEntryHash, AuthorityKey,
    AuthorityLogEntry, AuthorityOp, AuthoritySignature, AuthorityVaultId, CheckpointPolicyView,
    HostSlipIssuer, LastDeviceKeyConfirmation, MACHINE_ENCRYPTION_KEY_LEN,
    MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineDeviceClass, MachineEncryptionKey,
    MachineEnrolmentRequest, MachineOwnership, MachineProfile, MachineRole, OwnerAct,
    OwnerKeyChangeKind, OwnerKeyEnrollment, OwnerKeyRemoval, OwnerKeyRequirement, WebSignInAct,
    authority_entry_hash, authority_log_entity_id_from_hash, authority_transcript,
    decode_authority_log_entry_body, machine_profile_proof_transcript,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::error::RecordError;
use oneiron::receipt::AuthorityAuditQuery;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_doors::owner_key_release::release_owner_keys;
use oneiron::{EntityId, Error, HostingPrivacyPosture, TimeRange, Vault, VaultConfig};
use oneiron_authority::authority::{PolicySetting, PolicySettingSet, policy_setting_revision};

/// The seed of the second machine's machine key.
const JOINING_SEED: u8 = 68;

fn owner() -> EntityId {
    EntityId::from_bytes([0x71; 16]).expect("an id")
}

/// `node`'s profile of `machine` in `role` at `revision`, carried by
/// `carried` when it is an owner act.
fn node_profile(
    vault_id: AuthorityVaultId,
    machine: EntityId,
    node: &SigningKey,
    role: MachineRole,
    revision: u64,
    carried: Option<(EntityId, OwnerAct)>,
) -> MachineProfile {
    let machine_key = node.verifying_key().to_bytes();
    let encryption_key = MachineEncryptionKey {
        suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
        key: vec![7; MACHINE_ENCRYPTION_KEY_LEN],
    };
    let machine_proof = node
        .sign(&machine_profile_proof_transcript(
            &vault_id,
            machine,
            &machine_key,
            MachineDeviceClass::Computer,
            &encryption_key,
        ))
        .to_bytes();
    MachineProfile {
        machine,
        owner: owner(),
        machine_key,
        device_class: MachineDeviceClass::Computer,
        encryption_key,
        role,
        revision,
        machine_proof,
        seen_world_edits: BTreeSet::new(),
        carrier: carried.as_ref().map(|(carrier, _)| *carrier),
        act: carried.map(|(_, act)| act),
    }
}

/// One vault as a managed host serves it: the Hosted posture, rooted under
/// the test host, this install profiled `Unanswered`, and the embedded owner
/// authenticated. The vault drops first.
struct WebSignInVault {
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: AuthenticatedOwner,
    _dir: tempfile::TempDir,
}

impl WebSignInVault {
    fn hosted() -> Self {
        let dir = tempfile::tempdir().expect("vault directory");
        let mut config = VaultConfig::device();
        config.privacy.posture = HostingPrivacyPosture::Hosted;
        let vault = Vault::open(dir.path(), config).expect("hosted vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's machine profile under the host root");
        let (_, owner) = embedded_owner(&vault).expect("authenticated embedded owner");
        Self {
            vault,
            issuer,
            owner,
            _dir: dir,
        }
    }

    /// This install's MACHINE row.
    fn install(&self) -> EntityId {
        self.vault
            .local_machine()
            .expect("read this install")
            .expect("this install is profiled")
            .id
    }

    /// The owner enrols this install's owner signing key: the roster then
    /// holds a key that proves for him, and this handle holds it.
    fn enrol_owner_key(&self) {
        self.vault
            .enrol_device_owner_signing_key(
                &ActAuthority::Owner(self.owner.clone(), ActSurface::ThisInstall),
                &self.issuer,
            )
            .expect("the owner enrols this install's owner signing key");
    }

    /// Another machine's request to join this vault: its own keys, and its
    /// own proof over them for this vault.
    fn joining_machine(&self) -> MachineEnrolmentRequest {
        let vault_id = self
            .vault
            .authority_fold()
            .expect("authority fold")
            .vault_id
            .expect("the vault is rooted");
        let machine = EntityId::from_bytes([0x76; 16]).expect("an id");
        let profile = node_profile(
            vault_id,
            machine,
            &SigningKey::from_bytes(&[JOINING_SEED; 32]),
            MachineRole::Unanswered,
            1,
            None,
        );
        MachineEnrolmentRequest {
            vault_id,
            machine,
            machine_key: profile.machine_key,
            device_class: profile.device_class,
            encryption_key: profile.encryption_key,
            machine_proof: profile.machine_proof,
        }
    }

    /// The owner enrols a second machine as his and a second owner key whose
    /// enrolment names it, from `second_signing_key`'s proof of possession.
    /// Answers the machine and the enrolled key.
    fn enrol_second_machine_and_key(
        &self,
        second_signing_key: &SigningKey,
    ) -> (EntityId, [u8; 32]) {
        let request = self.joining_machine();
        let landing = self
            .vault
            .enroll_machine(
                &self.owner,
                ActSurface::ThisInstall,
                &request,
                MachineRole::Owned(MachineOwnership::Yours),
                None,
            )
            .expect("the owner enrols the second machine");
        assert!(
            landing.held().is_none(),
            "the second machine stands with the owner's key"
        );
        let second_key = second_signing_key.verifying_key().to_bytes();
        let authority = ActAuthority::Owner(self.owner.clone(), ActSurface::ThisInstall);
        let challenge = self
            .vault
            .owner_key_enrollment_challenge_as(&authority, request.machine, &second_key)
            .expect("the second key's challenge");
        let receipt = self
            .vault
            .enrol_owner_signing_key_as_host(
                &authority,
                OwnerKeyEnrollment {
                    machine: request.machine,
                    public_key: second_key,
                    proof: second_signing_key.sign(&challenge).to_bytes().to_vec(),
                },
                &self.issuer,
            )
            .expect("the owner enrols the second key on the second machine");
        assert_eq!(
            receipt.public_key, second_key,
            "the receipt names the second key"
        );
        assert_eq!(
            receipt.machine, request.machine,
            "the receipt names the second machine"
        );
        (request.machine, second_key)
    }
}

impl WebSignInVault {
    /// A self-host vault as its own server starts one: rooted under the
    /// host's root, the owner bound by it, this install profiled.
    fn self_host() -> Self {
        let dir = tempfile::tempdir().expect("vault directory");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("self-host vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's machine profile under the host root");
        let person = vault.ensure_embedded_owner_actor().expect("the owner");
        oneiron::test_support::bind_host_owner(&vault, &issuer, person)
            .expect("the owner's binding");
        let owner = vault
            .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
            .expect("the owner's proof");
        Self {
            vault,
            issuer,
            owner,
            _dir: dir,
        }
    }
}

impl WebSignInVault {
    /// How many authority log rows the fold holds valid.
    fn stored_rows(&self) -> usize {
        self.vault
            .authority_fold()
            .expect("authority fold")
            .valid_entries
            .len()
    }

    /// A refused act left nothing: the fold holds `rows` valid rows as
    /// before it, and no choice waits.
    fn assert_nothing_stored_since(&self, rows: usize) {
        let fold = self.vault.authority_fold().expect("authority fold");
        assert_eq!(fold.valid_entries.len(), rows, "the refusal stores no row");
        assert_eq!(
            fold.waiting_owner_choices(),
            &BTreeSet::new(),
            "nothing waits: the door stored nothing"
        );
    }

    /// The owner clears his checkpoint root choice through this install.
    fn clear_checkpoint_policy(&self) -> oneiron::Result<CheckpointPolicyView> {
        self.vault.set_checkpoint_policy_as(
            &ActAuthority::Owner(self.owner.clone(), ActSurface::ThisInstall),
            None,
            None,
        )
    }
}

impl WebSignInVault {
    /// Every pending-mirror marker this vault holds: a window, then the row
    /// the window is owed.
    fn pending_mirror_markers(&self) -> Vec<String> {
        let mut markers = Vec::new();
        let mut after: Option<String> = None;
        loop {
            after = self
                .vault
                .sync_state_prefix_page("lm:w:", after.as_deref(), 256, |key, _| {
                    markers.push(key.to_owned());
                    Ok(())
                })
                .expect("a page of the pending-mirror markers");
            if after.is_none() {
                break;
            }
        }
        markers
    }

    /// Asserts that a pending-mirror marker names the authority row of
    /// `entry`.
    fn assert_marked_for_the_live_mirror(&self, entry: &AuthorityEntryHash, row: &str) {
        let id = authority_log_entity_id_from_hash(entry)
            .expect("the row's id")
            .to_hex();
        let markers = self.pending_mirror_markers();
        assert!(
            markers
                .iter()
                .any(|marker| marker.ends_with(&format!(":{id}"))),
            "the switch's row is marked for the live mirror: {row} {id} carries a marker for its window: {markers:?}"
        );
    }
}

impl WebSignInVault {
    /// The authority log's heads: the rows no row names as a parent.
    fn authority_heads(&self) -> Vec<AuthorityEntryHash> {
        let rows: Vec<AuthorityLogEntry> = self
            .vault
            .export_signed_authority_history()
            .expect("the signed history")
            .iter()
            .map(|bytes| decode_authority_log_entry_body(bytes).expect("a row"))
            .collect();
        let parents: BTreeSet<AuthorityEntryHash> = rows
            .iter()
            .flat_map(|row| row.parent_hashes.iter().copied())
            .collect();
        rows.iter()
            .map(|row| authority_entry_hash(row).expect("a hash"))
            .filter(|hash| !parents.contains(hash))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// The signer's next sequence in the stored history.
    fn next_sequence_for(&self, signer: &AuthorityKey) -> u64 {
        self.vault
            .export_signed_authority_history()
            .expect("the signed history")
            .iter()
            .map(|bytes| decode_authority_log_entry_body(bytes).expect("a row"))
            .filter(|row| row.signer_key() == signer)
            .map(|row| row.seq + 1)
            .max()
            .unwrap_or(0)
            .max(1)
    }
}

fn signature_slot(key: AuthorityKey) -> AuthoritySignature {
    AuthoritySignature {
        suite: key.suite(),
        public_key: key,
        signature: vec![0; 64],
    }
}

#[test]
fn the_owner_switches_a_hosted_vault_back_to_web_sign_in_with_the_key_this_install_holds() {
    let web_sign_in_vault = WebSignInVault::hosted();
    web_sign_in_vault.enrol_owner_key();
    let first_key = web_sign_in_vault
        .vault
        .enrolled_owner_keys()
        .expect("enrolled owner keys")
        .into_iter()
        .find(|key| key.live)
        .expect("this install's owner key")
        .public_key;
    let requirement = web_sign_in_vault
        .vault
        .owner_key_requirement(&web_sign_in_vault.owner)
        .expect("the owner's requirement");
    let OwnerKeyRequirement::Required {
        web_sign_in_switch: Some(value),
    } = requirement
    else {
        panic!("a hosted vault that held an owner key offers its reviewed switch: {requirement:?}");
    };
    let rows = web_sign_in_vault.stored_rows();
    let switch = web_sign_in_vault
        .vault
        .switch_to_web_sign_in(&web_sign_in_vault.owner, ActSurface::ThisInstall, value)
        .expect("the owner switches back with the held key");
    assert_eq!(
        web_sign_in_vault
            .vault
            .owner_key_requirement(&web_sign_in_vault.owner)
            .expect("the new requirement"),
        OwnerKeyRequirement::WebSignIn,
        "the proven switch ends the owner-key requirement"
    );
    assert_eq!(
        web_sign_in_vault.stored_rows(),
        rows + 1,
        "the switch writes exactly one authority entry"
    );
    let entry = web_sign_in_vault
        .vault
        .export_signed_authority_history()
        .expect("the signed history")
        .iter()
        .map(|bytes| decode_authority_log_entry_body(bytes).expect("a signed entry"))
        .find(|entry| authority_entry_hash(entry).expect("the entry hash") == switch.entry)
        .expect("the stored switch entry");
    assert_eq!(
        entry.cosigns.len(),
        1,
        "exactly one owner key proves the switch"
    );
    assert_eq!(
        entry.cosigns[0].public_key,
        AuthorityKey::Ed25519(first_key),
        "the owner key this install holds is the switch's one proof"
    );
    assert_eq!(
        switch.signed_by,
        AuthorityKey::Ed25519(first_key),
        "the switch receipt names the owner key held here"
    );
    assert_eq!(
        switch.machine,
        web_sign_in_vault.install(),
        "the serving install carries the owner's switch"
    );
    match &entry.op {
        AuthorityOp::PolicySettingSet(setting) => {
            assert_eq!(
                setting.setting,
                PolicySetting::WebSignIn,
                "the switch writes the web sign-in setting"
            );
            assert_eq!(
                setting.value,
                Some(value),
                "the switch signs the reviewed value"
            );
            assert_eq!(
                setting.machine, switch.machine,
                "the signed entry names the carrier"
            );
        }
        other => panic!("the switch writes one PolicySettingSet entry: {other:?}"),
    }
    let fold = web_sign_in_vault
        .vault
        .authority_fold()
        .expect("authority fold");
    assert_eq!(
        fold.web_sign_in_acts().get(&switch.entry),
        Some(&WebSignInAct::SwitchedBack),
        "the fold counts the entry as the switch back"
    );
    let changes = web_sign_in_vault
        .vault
        .owner_key_changes(&web_sign_in_vault.owner)
        .expect("the owner reads key changes");
    let switches: Vec<_> = changes
        .iter()
        .filter(|change| change.change == OwnerKeyChangeKind::SwitchedToWebSignIn)
        .collect();
    assert_eq!(
        switches.len(),
        1,
        "the changes list contains exactly one switch"
    );
    let change = switches[0];
    assert_eq!(
        change.entry, switch.entry,
        "the changes list names the landed entry"
    );
    assert_eq!(
        change.machine, switch.machine,
        "the changes list names its carrier"
    );
    assert_eq!(
        change.signed_by,
        AuthorityKey::Ed25519(first_key),
        "the changes list names the owner key that proved the switch, not the install key"
    );
    assert!(
        change.change.key().is_none(),
        "the switch changes no individual key"
    );
    let page = web_sign_in_vault
        .vault
        .authority_audit(
            &web_sign_in_vault.owner,
            &AuthorityAuditQuery {
                limit: Some(500),
                ..AuthorityAuditQuery::default()
            },
        )
        .expect("the owner's audit page");
    let entry_hash = oneiron_hex::encode(&switch.entry);
    let audit = page
        .rows
        .iter()
        .find(|row| row.entry_hash == entry_hash)
        .expect("the switch's audit row");
    assert_eq!(
        audit.detail.as_deref(),
        Some("web_sign_in set"),
        "the audit labels the landed switch as set"
    );
    assert!(
        audit
            .cosigner_keys
            .contains(&oneiron_hex::encode(&first_key)),
        "the audit names the owner key among the cosigners"
    );
    web_sign_in_vault.assert_marked_for_the_live_mirror(&switch.entry, "the web sign-in switch");
}

#[test]
fn after_the_switch_the_last_device_key_is_removed_with_no_question() {
    let web_sign_in_vault = WebSignInVault::hosted();
    web_sign_in_vault.enrol_owner_key();
    let first_key = web_sign_in_vault
        .vault
        .enrolled_owner_keys()
        .expect("enrolled owner keys")
        .into_iter()
        .find(|key| key.live)
        .expect("the only owner key")
        .public_key;
    let requirement = web_sign_in_vault
        .vault
        .owner_key_requirement(&web_sign_in_vault.owner)
        .expect("the owner's requirement");
    let OwnerKeyRequirement::Required {
        web_sign_in_switch: Some(value),
    } = requirement
    else {
        panic!("the hosted vault offers its switch: {requirement:?}");
    };
    web_sign_in_vault
        .vault
        .switch_to_web_sign_in(&web_sign_in_vault.owner, ActSurface::ThisInstall, value)
        .expect("the switch lands before the removal");
    let removal = web_sign_in_vault
        .vault
        .remove_owner_key(
            &web_sign_in_vault.owner,
            first_key,
            LastDeviceKeyConfirmation::NotGiven,
        )
        .expect("the last-key removal answers");
    assert!(
        matches!(removal, OwnerKeyRemoval::Removed { .. }),
        "web sign-in removes the last device key with no question: {removal:?}"
    );
    assert!(
        !web_sign_in_vault
            .vault
            .enrolled_owner_keys()
            .expect("enrolled owner keys")
            .iter()
            .find(|key| key.public_key == first_key)
            .expect("the removed key's row")
            .live,
        "the last device key is no longer live"
    );
    assert_eq!(
        web_sign_in_vault
            .vault
            .owner_key_requirement(&web_sign_in_vault.owner)
            .expect("the requirement after removal"),
        OwnerKeyRequirement::WebSignIn,
        "removing the last key does not undo the switch back"
    );
    release_owner_keys(&web_sign_in_vault.vault);
    let choice = web_sign_in_vault
        .clear_checkpoint_policy()
        .expect("a choice without an owner key lands on web sign-in");
    assert_eq!(
        choice.heads.len(),
        1,
        "the checkpoint-policy clear lands as the one live choice without an owner key"
    );
    assert_eq!(
        web_sign_in_vault
            .vault
            .authority_fold()
            .expect("authority fold")
            .waiting_owner_choices(),
        &BTreeSet::new(),
        "a choice on web sign-in waits for no owner-key proof"
    );
}

#[test]
fn an_install_that_holds_no_owner_key_cannot_switch_the_vault_back() {
    let web_sign_in_vault = WebSignInVault::hosted();
    web_sign_in_vault.enrol_owner_key();
    web_sign_in_vault.enrol_second_machine_and_key(&SigningKey::from_bytes(&[74; 32]));
    release_owner_keys(&web_sign_in_vault.vault);
    let requirement = web_sign_in_vault
        .vault
        .owner_key_requirement(&web_sign_in_vault.owner)
        .expect("the owner's requirement");
    let OwnerKeyRequirement::Required {
        web_sign_in_switch: Some(value),
    } = requirement
    else {
        panic!("a hosted vault with an enrolled key offers its switch: {requirement:?}");
    };
    let rows = web_sign_in_vault.stored_rows();
    let answer = web_sign_in_vault.vault.switch_to_web_sign_in(
        &web_sign_in_vault.owner,
        ActSurface::ThisInstall,
        value,
    );
    assert!(
        matches!(answer, Err(Error::Record(RecordError::OwnerKeyRequired))),
        "an install that holds no owner key cannot switch back: {answer:?}"
    );
    web_sign_in_vault.assert_nothing_stored_since(rows);
    assert_eq!(
        web_sign_in_vault
            .vault
            .owner_key_requirement(&web_sign_in_vault.owner)
            .expect("the unchanged requirement"),
        requirement,
        "an unproven switch leaves the owner-key requirement unchanged"
    );
}

#[test]
fn a_vault_that_never_held_an_owner_key_has_nothing_to_switch() {
    let web_sign_in_vault = WebSignInVault::hosted();
    assert_eq!(
        web_sign_in_vault
            .vault
            .owner_key_requirement(&web_sign_in_vault.owner)
            .expect("the owner's requirement"),
        OwnerKeyRequirement::NeverHeld,
        "a fresh hosted vault has never held an owner key"
    );
    let rows = web_sign_in_vault.stored_rows();
    let answer = web_sign_in_vault.vault.switch_to_web_sign_in(
        &web_sign_in_vault.owner,
        ActSurface::ThisInstall,
        [0; 32],
    );
    assert!(
        matches!(answer, Err(Error::Record(RecordError::AuthorityRefused(_)))),
        "a vault that never held an owner key has nothing to switch: {answer:?}"
    );
    web_sign_in_vault.assert_nothing_stored_since(rows);
}

#[test]
fn a_self_host_vault_has_no_web_sign_in_to_switch_to() {
    let web_sign_in_vault = WebSignInVault::self_host();
    assert_eq!(
        web_sign_in_vault
            .vault
            .owner_key_requirement(&web_sign_in_vault.owner)
            .expect("the self-host requirement"),
        OwnerKeyRequirement::Required {
            web_sign_in_switch: None
        },
        "a self-host owner root requires an owner key and offers no web sign-in"
    );
    let rows = web_sign_in_vault.stored_rows();
    let answer = web_sign_in_vault.vault.switch_to_web_sign_in(
        &web_sign_in_vault.owner,
        ActSurface::ThisInstall,
        [0; 32],
    );
    assert!(
        matches!(answer, Err(Error::Record(RecordError::AuthorityRefused(_)))),
        "a self-host vault has no web sign-in to switch to: {answer:?}"
    );
    web_sign_in_vault.assert_nothing_stored_since(rows);
}

#[test]
fn a_second_switch_is_refused_as_already_in_force() {
    let web_sign_in_vault = WebSignInVault::hosted();
    web_sign_in_vault.enrol_owner_key();
    let requirement = web_sign_in_vault
        .vault
        .owner_key_requirement(&web_sign_in_vault.owner)
        .expect("the owner's requirement");
    let OwnerKeyRequirement::Required {
        web_sign_in_switch: Some(value),
    } = requirement
    else {
        panic!("the hosted vault offers its switch: {requirement:?}");
    };
    web_sign_in_vault
        .vault
        .switch_to_web_sign_in(&web_sign_in_vault.owner, ActSurface::ThisInstall, value)
        .expect("the first switch lands");
    let rows = web_sign_in_vault.stored_rows();
    let answer = web_sign_in_vault.vault.switch_to_web_sign_in(
        &web_sign_in_vault.owner,
        ActSurface::ThisInstall,
        value,
    );
    assert!(
        matches!(answer, Err(Error::Record(RecordError::AuthorityRefused(_)))),
        "a switch already in force is refused without another entry: {answer:?}"
    );
    web_sign_in_vault.assert_nothing_stored_since(rows);
    let changes = web_sign_in_vault
        .vault
        .owner_key_changes(&web_sign_in_vault.owner)
        .expect("the owner reads key changes");
    assert_eq!(
        changes
            .iter()
            .filter(|change| change.change == OwnerKeyChangeKind::SwitchedToWebSignIn)
            .count(),
        1,
        "a refused second switch adds no changes line"
    );
}

#[test]
fn a_key_enrolled_since_the_review_refuses_the_switch() {
    let web_sign_in_vault = WebSignInVault::hosted();
    web_sign_in_vault.enrol_owner_key();
    let requirement = web_sign_in_vault
        .vault
        .owner_key_requirement(&web_sign_in_vault.owner)
        .expect("the reviewed requirement");
    let OwnerKeyRequirement::Required {
        web_sign_in_switch: Some(value_before),
    } = requirement
    else {
        panic!("the hosted vault offers its reviewed switch: {requirement:?}");
    };
    web_sign_in_vault.enrol_second_machine_and_key(&SigningKey::from_bytes(&[75; 32]));
    let rows = web_sign_in_vault.stored_rows();
    let answer = web_sign_in_vault.vault.switch_to_web_sign_in(
        &web_sign_in_vault.owner,
        ActSurface::ThisInstall,
        value_before,
    );
    assert!(
        matches!(answer, Err(Error::ConcurrentWrite(_))),
        "a key enrolled since the review refuses the stale switch: {answer:?}"
    );
    web_sign_in_vault.assert_nothing_stored_since(rows);
    let requirement = web_sign_in_vault
        .vault
        .owner_key_requirement(&web_sign_in_vault.owner)
        .expect("the requirement after enrollment");
    let OwnerKeyRequirement::Required {
        web_sign_in_switch: Some(value_after),
    } = requirement
    else {
        panic!("the new key keeps the hosted vault requiring a key: {requirement:?}");
    };
    assert_ne!(
        value_after, value_before,
        "the review value includes every enrolled owner key"
    );
    web_sign_in_vault
        .vault
        .switch_to_web_sign_in(
            &web_sign_in_vault.owner,
            ActSurface::ThisInstall,
            value_after,
        )
        .expect("the owner switches after reviewing the new value");
    assert_eq!(
        web_sign_in_vault
            .vault
            .owner_key_requirement(&web_sign_in_vault.owner)
            .expect("the requirement after review"),
        OwnerKeyRequirement::WebSignIn,
        "a fresh review permits the proven switch back"
    );
}

#[test]
fn a_key_enrolled_after_the_switch_makes_the_vault_ask_again() {
    let web_sign_in_vault = WebSignInVault::hosted();
    web_sign_in_vault.enrol_owner_key();
    let requirement = web_sign_in_vault
        .vault
        .owner_key_requirement(&web_sign_in_vault.owner)
        .expect("the owner's requirement");
    let OwnerKeyRequirement::Required {
        web_sign_in_switch: Some(value),
    } = requirement
    else {
        panic!("the hosted vault offers its switch: {requirement:?}");
    };
    let switch = web_sign_in_vault
        .vault
        .switch_to_web_sign_in(&web_sign_in_vault.owner, ActSurface::ThisInstall, value)
        .expect("the switch lands before the new enrollment");
    let (_, second_key) =
        web_sign_in_vault.enrol_second_machine_and_key(&SigningKey::from_bytes(&[76; 32]));
    let requirement = web_sign_in_vault
        .vault
        .owner_key_requirement(&web_sign_in_vault.owner)
        .expect("the requirement after enrollment");
    let OwnerKeyRequirement::Required {
        web_sign_in_switch: Some(value_2),
    } = requirement
    else {
        panic!("a later enrolled key makes the vault ask again: {requirement:?}");
    };
    assert_ne!(
        value_2, value,
        "the first switch never spoke for the later key"
    );
    let changes = web_sign_in_vault
        .vault
        .owner_key_changes(&web_sign_in_vault.owner)
        .expect("the owner reads key changes");
    let switches: Vec<_> = changes
        .iter()
        .filter(|change| change.change == OwnerKeyChangeKind::SwitchedToWebSignIn)
        .collect();
    assert_eq!(
        switches.len(),
        1,
        "the history keeps exactly the first switch line"
    );
    assert_eq!(
        switches[0].entry, switch.entry,
        "a later key does not erase the first switch"
    );
    let second_key_enrolled = changes.iter().any(|change| {
        matches!(change.change, OwnerKeyChangeKind::Enrolled(key) if key.public_key == second_key)
    });
    assert!(
        second_key_enrolled,
        "the history lists the second key's enrolment beside the first switch"
    );
    let fold = web_sign_in_vault
        .vault
        .authority_fold()
        .expect("authority fold");
    assert_eq!(
        fold.web_sign_in_acts().get(&switch.entry),
        Some(&WebSignInAct::SwitchedBack),
        "the fold remembers how the first switch landed, not whether it still governs"
    );
}

/// The owner's second device carries a later act of the setting with a value
/// that is not the switch's, under its own owner key's proof. Every key that
/// signs it is a raw key this test holds.
#[test]
fn an_act_with_another_value_asks_for_an_owner_key_again() {
    let web_sign_in_vault = WebSignInVault::hosted();
    web_sign_in_vault.enrol_owner_key();
    let second_signing_key = SigningKey::from_bytes(&[77; 32]);
    let (second_machine, _) = web_sign_in_vault.enrol_second_machine_and_key(&second_signing_key);
    let requirement = web_sign_in_vault
        .vault
        .owner_key_requirement(&web_sign_in_vault.owner)
        .expect("the owner's requirement");
    let OwnerKeyRequirement::Required {
        web_sign_in_switch: Some(value),
    } = requirement
    else {
        panic!("the hosted vault offers its switch: {requirement:?}");
    };
    let switch = web_sign_in_vault
        .vault
        .switch_to_web_sign_in(&web_sign_in_vault.owner, ActSurface::ThisInstall, value)
        .expect("the original switch lands");
    let mut other_value = value;
    other_value[0] ^= 1;
    let carrier_signing_key = SigningKey::from_bytes(&[JOINING_SEED; 32]);
    let carrier_key = AuthorityKey::Ed25519(carrier_signing_key.verifying_key().to_bytes());
    let proof_key = AuthorityKey::Ed25519(second_signing_key.verifying_key().to_bytes());
    let target = PolicySetting::WebSignIn
        .reserved_target()
        .expect("the setting's target")
        .expect("a vault-wide setting");
    let person = web_sign_in_vault
        .vault
        .ensure_embedded_owner_actor()
        .expect("the owner");
    let act = OwnerAct::by_owner(
        person,
        PolicySetting::WebSignIn.act_kind(),
        target,
        ActSurface::ThisInstall,
        policy_setting_revision([switch.entry]),
    );
    let mut entry = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: web_sign_in_vault
            .vault
            .authority_fold()
            .expect("authority fold")
            .vault_id,
        seq: web_sign_in_vault.next_sequence_for(&carrier_key),
        parent_hashes: web_sign_in_vault.authority_heads(),
        op: AuthorityOp::PolicySettingSet(PolicySettingSet {
            act,
            machine: second_machine,
            setting: PolicySetting::WebSignIn,
            prior: [0; 32],
            value: Some(other_value),
        }),
        signer: signature_slot(carrier_key),
        cosigns: vec![signature_slot(proof_key)],
        ts: switch.at,
    };
    let transcript = authority_transcript(&entry).expect("the ask-again transcript");
    entry.signer.signature = carrier_signing_key.sign(&transcript).to_bytes().to_vec();
    entry.cosigns[0].signature = second_signing_key.sign(&transcript).to_bytes().to_vec();
    let asks_again = authority_entry_hash(&entry).expect("the ask-again entry hash");
    web_sign_in_vault
        .vault
        .put_authority_log_entry(
            &entry,
            TimeRange {
                start: switch.at,
                end: switch.at,
            },
            switch.at,
        )
        .expect("the hand-signed ask-again entry is stored");
    let fold = web_sign_in_vault
        .vault
        .authority_fold()
        .expect("authority fold");
    assert_eq!(
        fold.web_sign_in_acts().get(&asks_again),
        Some(&WebSignInAct::AsksAgain),
        "fixture guard: the other value lands as ask again, not a switch"
    );
    assert!(
        matches!(
            fold.owner_key_requirement(),
            OwnerKeyRequirement::Required { .. }
        ),
        "fixture guard: the other value makes the vault require an owner key"
    );
    let changes = web_sign_in_vault
        .vault
        .owner_key_changes(&web_sign_in_vault.owner)
        .expect("the owner reads key changes");
    let switches: Vec<_> = changes
        .iter()
        .filter(|change| change.change == OwnerKeyChangeKind::SwitchedToWebSignIn)
        .collect();
    assert_eq!(
        switches.len(),
        1,
        "only landed switches enter the changes list; an ask-again act adds no switch line"
    );
    assert_eq!(
        switches[0].entry, switch.entry,
        "the changes list keeps the landed switch, never the ask-again act"
    );
    let page = web_sign_in_vault
        .vault
        .authority_audit(
            &web_sign_in_vault.owner,
            &AuthorityAuditQuery {
                limit: Some(500),
                ..AuthorityAuditQuery::default()
            },
        )
        .expect("the owner's audit page");
    let entry_hash = oneiron_hex::encode(&asks_again);
    let audit = page
        .rows
        .iter()
        .find(|row| row.entry_hash == entry_hash)
        .expect("the ask-again audit row");
    assert_eq!(
        audit.detail.as_deref(),
        Some("web_sign_in clear"),
        "the audit labels a landed ask-again act as clear even when its signed value is Some"
    );
}

#[test]
fn a_vault_whose_last_owner_key_was_removed_with_no_switch_still_asks_for_one() {
    let web_sign_in_vault = WebSignInVault::hosted();
    web_sign_in_vault.enrol_owner_key();
    let first_key = web_sign_in_vault
        .vault
        .enrolled_owner_keys()
        .expect("enrolled owner keys")
        .into_iter()
        .find(|key| key.live)
        .expect("the only owner key")
        .public_key;
    let rows = web_sign_in_vault.stored_rows();
    let removal = web_sign_in_vault
        .vault
        .remove_owner_key(
            &web_sign_in_vault.owner,
            first_key,
            LastDeviceKeyConfirmation::NotGiven,
        )
        .expect("the last-key removal asks first");
    assert!(
        matches!(removal, OwnerKeyRemoval::LastDeviceKey(_)),
        "while Required the last device key asks before removal: {removal:?}"
    );
    web_sign_in_vault.assert_nothing_stored_since(rows);
    let removal = web_sign_in_vault
        .vault
        .remove_owner_key(
            &web_sign_in_vault.owner,
            first_key,
            LastDeviceKeyConfirmation::Given,
        )
        .expect("the owner confirms the last key's removal");
    assert!(
        matches!(removal, OwnerKeyRemoval::Removed { .. }),
        "the confirmed last device key removal lands: {removal:?}"
    );
    let requirement = web_sign_in_vault
        .vault
        .owner_key_requirement(&web_sign_in_vault.owner)
        .expect("the requirement after removal");
    let OwnerKeyRequirement::Required {
        web_sign_in_switch: Some(value),
    } = requirement
    else {
        panic!("removal without a switch still requires an owner key: {requirement:?}");
    };
    let rows = web_sign_in_vault.stored_rows();
    let answer = web_sign_in_vault.vault.switch_to_web_sign_in(
        &web_sign_in_vault.owner,
        ActSurface::ThisInstall,
        value,
    );
    assert!(
        matches!(answer, Err(Error::Record(RecordError::OwnerKeyRequired))),
        "a removed key cannot prove the switch back: {answer:?}"
    );
    web_sign_in_vault.assert_nothing_stored_since(rows);
}
