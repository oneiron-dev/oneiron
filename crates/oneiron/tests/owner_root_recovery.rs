//! Pass 27 R4: the recovery root's one door, `Vault::recover_owner_root`
//! (Engine RULINGs WAYBACK-E2 = A and WAYBACK-BOX-AUTHORITY-SEED = A).
//!
//! On a hosted vault whose roster holds the kit root's authority key live,
//! that key vouches: it enrols the new key (`OwnerKeyEnroll`, the key as
//! predecessor) and revokes the lost one (`RevokeDevice`, signed by the key)
//! in one transaction, and the custodial root stays live. The recovery box's
//! released authority seed does the same. A root key never enrolled, a host
//! root or the root's own key named as lost: refused, nothing written. On a
//! roster with no live root key the kit's anchor appoints instead, and the
//! box's key alone is refused there.
//!
//! Red on the anchor top 6166098690ef: the file does not compile there (no
//! `recover_owner_root`, `RootMaterial`, `RootSuccessor`,
//! `RecoveryAuthoritySigner::from_released_seed` or the test door
//! `root_recovery`).
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test owner_root_recovery`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActAuthority, ActSurface, AuthorityAttestation,
    AuthorityEntryHash, AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature,
    AuthorityTier, DeviceAuthority, HostSlipIssuer, MachineRole, OwnerKeyEnrollment, ROLE_OWNER,
    RootMaterial, RootRecovery, RootSuccessor, authority_entry_hash, authority_transcript,
    decode_authority_log_entry_body, encode_authority_log_entry_body,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::recovery::{
    KitIssue, KitSecretKind, PassphraseCost, PieceHome, issue_recovery_root_kit, restore_kit,
};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::root_recovery::released_authority_seed;
use oneiron::test_support::bind_host_owner;
use oneiron::world_keys::{RecoveryAuthoritySigner, RecoveryRootSeed};
use oneiron::{EntityId, HostingPrivacyPosture, Vault, VaultConfig};

/// The seed of the owner's device key that is lost.
const LOST_KEY_SEED: u8 = 21;
/// The seed of the new device's key.
const NEW_KEY_SEED: u8 = 41;
/// The seeds of the two handoffs' successors in the rootless fixture.
const FIRST_HANDOFF_SEED: u8 = 33;
const SECOND_HANDOFF_SEED: u8 = 34;

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof")
}

fn key_of(signing: &SigningKey) -> AuthorityKey {
    AuthorityKey::Ed25519(signing.verifying_key().to_bytes())
}

/// `seed` rebuilt from two stored pieces of a kit issued for it: the owner's
/// restore.
fn restored(vault_id: [u8; 32], seed: &RecoveryRootSeed) -> RecoveryRootSeed {
    let issue = KitIssue {
        vault_id,
        homes: [
            PieceHome::ThisMachine,
            PieceHome::OtherMachine(EntityId::now()),
            PieceHome::OtherMachine(EntityId::now()),
        ],
        passphrase: None,
        cost: PassphraseCost::FLOOR,
        only_machine: false,
    };
    let pieces = issue_recovery_root_kit(&issue, &seed.kit_bytes())
        .expect("the kit")
        .into_pieces();
    let secret = restore_kit(
        vault_id,
        KitSecretKind::RecoveryRoot,
        &[&pieces[0], &pieces[1]],
        None,
    )
    .expect("two stored pieces restore the seed");
    RecoveryRootSeed::from_restored_kit(secret).expect("the restored seed")
}

/// A vault under the test host's root with the owner bound, one owner device
/// key enrolled (the key that is lost), and a kit root.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    person: EntityId,
    vault_id: [u8; 32],
    machine: EntityId,
    lost_key: SigningKey,
    seed: RecoveryRootSeed,
}

fn fixture(posture: HostingPrivacyPosture) -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.privacy.posture = posture;
    let vault = Vault::open(dir.path(), config).expect("the vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::HostedNode)
        .expect("this install's live machine profile");
    let person = vault.ensure_embedded_owner_actor().expect("the owner");
    bind_host_owner(&vault, &issuer, person).expect("the owner's binding");
    let vault_id = vault
        .authority_fold()
        .expect("the fold")
        .vault_id
        .expect("a rooted vault");
    let machine = vault
        .prepare_install_signing()
        .expect("this install's machine");
    let fixture = Fixture {
        _dir: dir,
        seed: restored(
            vault_id,
            &RecoveryRootSeed::generate().expect("a root seed"),
        ),
        vault,
        issuer,
        person,
        vault_id,
        machine,
        lost_key: SigningKey::from_bytes(&[LOST_KEY_SEED; 32]),
    };
    let input = fixture.enrollment(&fixture.lost_key);
    fixture
        .vault
        .enrol_owner_signing_key_as_host(&fixture.authority(), input, &fixture.issuer)
        .expect("the owner enrols a device key");
    fixture
}

impl Fixture {
    fn owner(&self) -> AuthenticatedOwner {
        proof(&self.vault, self.person)
    }

    fn authority(&self) -> ActAuthority {
        ActAuthority::Owner(self.owner(), ActSurface::ThisInstall)
    }

    /// `key`'s enrolment input for this vault and owner, with its proof of
    /// possession.
    fn enrollment(&self, key: &SigningKey) -> OwnerKeyEnrollment {
        let public_key = key.verifying_key().to_bytes();
        let challenge = self
            .vault
            .owner_key_enrollment_challenge_as(&self.authority(), self.machine, &public_key)
            .expect("the challenge");
        OwnerKeyEnrollment {
            machine: self.machine,
            public_key,
            proof: key.sign(&challenge).to_bytes().to_vec(),
        }
    }

    /// The owner enrols the kit root's authority key before the loss.
    fn enrol_root_key(&self) -> AuthorityKey {
        let receipt = self
            .vault
            .enrol_recovery_authority_key_as_host(
                &self.authority(),
                self.machine,
                &self.seed,
                &self.issuer,
            )
            .expect("the owner enrols the root's authority key");
        AuthorityKey::Ed25519(receipt.public_key)
    }

    fn kit(&self) -> RootMaterial {
        RootMaterial::Kit {
            seed: restored(self.vault_id, &self.seed),
            confirm: None,
        }
    }

    fn released(&self) -> RootMaterial {
        let root = self.seed.public(&self.vault_id).expect("the root").id;
        RootMaterial::Released(
            RecoveryAuthoritySigner::from_released_seed(
                released_authority_seed(&self.seed, &self.vault_id),
                &self.vault_id,
                root,
            )
            .expect("the released key"),
        )
    }

    fn recover(
        &self,
        material: RootMaterial,
        successor: RootSuccessor,
        lost: &[AuthorityKey],
    ) -> oneiron::Result<RootRecovery> {
        self.vault.recover_owner_root(
            &self.owner(),
            ActSurface::ThisInstall,
            material,
            successor,
            lost,
        )
    }

    fn live(&self, key: &AuthorityKey) -> bool {
        self.vault
            .authority_fold()
            .expect("the fold")
            .roster
            .get(key)
            .is_some_and(|device| !device.revoked)
    }

    fn history(&self) -> Vec<AuthorityLogEntry> {
        self.vault
            .export_signed_authority_history()
            .expect("the signed history")
            .iter()
            .map(|row| decode_authority_log_entry_body(row).expect("a row"))
            .collect()
    }

    fn row(&self, entry: &AuthorityEntryHash) -> AuthorityLogEntry {
        self.history()
            .into_iter()
            .find(|row| authority_entry_hash(row).expect("a hash") == *entry)
            .expect("the row is stored")
    }

    /// The owner key hands the vault to two new keys on the heads, and both
    /// handoffs arrive together: a fork that leaves no live root key.
    fn fork(&self) {
        let rows = self.history();
        let parents: BTreeSet<AuthorityEntryHash> = rows
            .iter()
            .flat_map(|row| row.parent_hashes.iter().copied())
            .collect();
        let mut heads: Vec<AuthorityEntryHash> = rows
            .iter()
            .map(|row| authority_entry_hash(row).expect("a hash"))
            .filter(|row| !parents.contains(row))
            .collect();
        heads.sort_unstable();
        heads.dedup();
        let signer = key_of(&self.lost_key);
        let seq = rows
            .iter()
            .filter(|row| row.signer_key() == &signer)
            .map(|row| row.seq + 1)
            .max()
            .unwrap_or(0)
            .max(1);
        let handoff = |seq: u64, successor: u8| {
            let mut row = AuthorityLogEntry {
                schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
                vault_id: Some(self.vault_id),
                seq,
                parent_hashes: heads.clone(),
                op: AuthorityOp::ReRoot {
                    new_device: DeviceAuthority {
                        key: key_of(&SigningKey::from_bytes(&[successor; 32])),
                        transport_key_binding: [7; 32],
                        attestation: AuthorityAttestation {
                            kind: "SoftwareArgon2id".to_owned(),
                            evidence: vec![1, 2, 3],
                        },
                        tier: AuthorityTier::Software,
                        roles: ROLE_OWNER,
                    },
                },
                signer: AuthoritySignature {
                    suite: signer.suite(),
                    public_key: signer.clone(),
                    signature: vec![0; 64],
                },
                cosigns: Vec::new(),
                ts: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("a clock after 1970")
                    .as_secs(),
            };
            let transcript = authority_transcript(&row).expect("the transcript");
            row.signer.signature = self.lost_key.sign(&transcript).to_bytes().to_vec();
            encode_authority_log_entry_body(&row).expect("the signed bytes")
        };
        self.vault
            .import_signed_authority_history(&[
                handoff(seq, FIRST_HANDOFF_SEED),
                handoff(seq + 1, SECOND_HANDOFF_SEED),
            ])
            .expect("both handoffs land");
    }
}

/// Asserts the door's answer is a vouch that enrolled `new` and revoked
/// exactly `lost`, each signed by `root_key`, and that the custodial root
/// and the root's key stay live.
fn assert_vouched(
    fixture: &Fixture,
    answer: RootRecovery,
    root_key: &AuthorityKey,
    new: &AuthorityKey,
    lost: &AuthorityKey,
) {
    let RootRecovery::Vouched {
        enrollment,
        revoked,
    } = answer
    else {
        panic!("the root's live authority key vouches; the anchor appoints nothing here");
    };
    assert_eq!(AuthorityKey::Ed25519(enrollment.public_key), *new);
    let enrolment = fixture.row(&enrollment.entry);
    assert!(matches!(enrolment.op, AuthorityOp::OwnerKeyEnroll(_)));
    assert_eq!(
        enrolment.signer_key(),
        root_key,
        "the root's key is the predecessor"
    );
    assert_eq!(revoked.len(), 1, "one lost key, one revocation");
    let revocation = fixture.row(&revoked[0]);
    assert!(
        matches!(&revocation.op, AuthorityOp::RevokeDevice { revoked_key } if revoked_key == lost),
        "the revocation names the lost key"
    );
    assert_eq!(revocation.signer_key(), root_key, "the root's key signs it");
    assert!(fixture.live(new), "the new key is live");
    assert!(!fixture.live(lost), "the lost key is revoked");
    assert!(fixture.live(root_key), "the root's key stays live");
    assert!(
        fixture.live(&fixture.issuer.public_key()),
        "the custodial root stays live: no ReRoot ran"
    );
    fixture
        .vault
        .ensure_host_root_slip(&fixture.issuer)
        .expect("the host root still signs");
}

#[test]
fn the_root_key_vouches_a_new_key_and_revokes_the_lost_one_on_a_hosted_vault() {
    let fixture = fixture(HostingPrivacyPosture::Hosted);
    let root_key = fixture.enrol_root_key();
    let new_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);
    let lost = key_of(&fixture.lost_key);

    let answer = fixture
        .recover(
            fixture.kit(),
            RootSuccessor::Device(fixture.enrollment(&new_key)),
            std::slice::from_ref(&lost),
        )
        .expect("the root's key vouches");

    assert_vouched(&fixture, answer, &root_key, &key_of(&new_key), &lost);
}

#[test]
fn the_released_authority_seed_vouches_as_the_kit_does() {
    let fixture = fixture(HostingPrivacyPosture::Hosted);
    let root_key = fixture.enrol_root_key();
    let new_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);
    let lost = key_of(&fixture.lost_key);

    let answer = fixture
        .recover(
            fixture.released(),
            RootSuccessor::Device(fixture.enrollment(&new_key)),
            std::slice::from_ref(&lost),
        )
        .expect("the box's released key vouches");

    assert_vouched(&fixture, answer, &root_key, &key_of(&new_key), &lost);
}

#[test]
fn the_root_key_vouches_for_a_fresh_key_of_this_install() {
    let fixture = fixture(HostingPrivacyPosture::Hosted);
    fixture.enrol_root_key();

    let answer = fixture
        .recover(fixture.kit(), RootSuccessor::ThisInstall, &[])
        .expect("the root's key vouches for this install's key");

    let RootRecovery::Vouched {
        enrollment,
        revoked,
    } = answer
    else {
        panic!("the root's live authority key vouches");
    };
    let held = fixture
        .vault
        .device_owner_signing_key()
        .expect("this install's owner signing key");
    assert_eq!(enrollment.public_key, held.public_key());
    assert!(fixture.live(&AuthorityKey::Ed25519(held.public_key())));
    assert!(revoked.is_empty());
    assert!(
        fixture
            .recover(fixture.kit(), RootSuccessor::ThisInstall, &[])
            .is_err(),
        "a live key of this install needs no recovery"
    );
}

#[test]
fn a_root_key_never_enrolled_is_refused_on_a_rooted_roster() {
    let fixture = fixture(HostingPrivacyPosture::Hosted);
    let new_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);
    let lost = key_of(&fixture.lost_key);
    let stored = fixture.history().len();

    for material in [fixture.kit(), fixture.released()] {
        assert!(
            fixture
                .recover(
                    material,
                    RootSuccessor::Device(fixture.enrollment(&new_key)),
                    std::slice::from_ref(&lost),
                )
                .is_err(),
            "a key the roster does not hold vouches for nothing"
        );
    }

    assert_eq!(
        fixture.history().len(),
        stored,
        "the refusal writes nothing"
    );
    assert!(!fixture.live(&key_of(&new_key)));
    assert!(fixture.live(&lost), "the device key stays live");
}

#[test]
fn a_host_root_or_the_root_key_is_never_a_lost_key() {
    let fixture = fixture(HostingPrivacyPosture::Hosted);
    let root_key = fixture.enrol_root_key();
    let new_key = SigningKey::from_bytes(&[NEW_KEY_SEED; 32]);
    let stored = fixture.history().len();

    for lost in [
        fixture.issuer.public_key(),
        root_key.clone(),
        key_of(&new_key),
    ] {
        assert!(
            fixture
                .recover(
                    fixture.kit(),
                    RootSuccessor::Device(fixture.enrollment(&new_key)),
                    &[lost],
                )
                .is_err(),
            "the root's door revokes only a lost owner device key"
        );
    }

    assert_eq!(
        fixture.history().len(),
        stored,
        "the refusal writes nothing"
    );
    assert!(!fixture.live(&key_of(&new_key)), "no key was enrolled");
    assert!(fixture.live(&fixture.issuer.public_key()));
    assert!(fixture.live(&root_key));
}

#[test]
fn a_rootless_roster_takes_the_anchor_arm() {
    let fixture = fixture(HostingPrivacyPosture::SelfHostLocal);
    let owner = fixture.owner();
    let prepared = fixture
        .vault
        .prepare_owner_root(&owner)
        .expect("a kit root");
    let seed = restored(fixture.vault_id, prepared.seed());
    let root = fixture
        .vault
        .activate_owner_root(&owner, prepared, &BTreeSet::new())
        .expect("the owner activates his root")
        .root;
    let fixture = Fixture { seed, ..fixture };
    fixture.fork();
    let stored = fixture.history().len();

    assert!(
        fixture
            .recover(fixture.released(), RootSuccessor::ThisInstall, &[])
            .is_err(),
        "the box's key alone never appoints"
    );
    assert!(
        fixture
            .recover(
                fixture.kit(),
                RootSuccessor::Device(
                    fixture.enrollment(&SigningKey::from_bytes(&[NEW_KEY_SEED; 32]))
                ),
                &[],
            )
            .is_err(),
        "the anchor appoints a key of this install only"
    );
    assert_eq!(
        fixture.history().len(),
        stored,
        "the refusals write nothing"
    );

    let answer = fixture
        .recover(fixture.kit(), RootSuccessor::ThisInstall, &[])
        .expect("the anchor appoints on a rootless roster");

    let RootRecovery::Appointed(receipt) = answer else {
        panic!("a rootless roster takes the anchor arm");
    };
    assert_eq!(receipt.root, root);
    assert!(fixture.live(&AuthorityKey::Ed25519(receipt.successor)));
}
