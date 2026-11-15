//! OWNER-ANCHOR-ROOT-RECOVERY part (b2) (PLAN v3 section 7; Engine RULINGs
//! 14 Nov 21:01, 21:47 and 22:32): the root appointment door and the
//! admission bridge, on a vault.
//!
//! An owner key of the vault signs two sibling handoffs, which arrive
//! together. Each fences every roster key, the host root included, so they
//! conflict: neither installs its successor, and the roster holds no live
//! root key. No root key can bind the owner, so owner verbs stop. The owner
//! restores his kit on an install that pins its root and runs
//! `appoint_owner_root`: the root's anchor appoints a fresh owner signing key
//! of this install, on the conflict's two handoffs (the witnesses) and the
//! heads, and the successor binds the owner as `human` at its own first
//! epoch. The fold counts both, the roster holds a root key again, and owner
//! verbs pass.
//!
//! The same appointment and binding, signed elsewhere, arrive by an import:
//! the walk that refuses rows standing on a retired key reads neither the
//! appointment's witnesses against it nor, through the counted appointment,
//! against its binding. A row that also reaches a witness by a path of its
//! own still stands on the retired key and is refused.
//!
//! Two runs of the door on one install, the second checked before the first
//! commits: the second is refused before it makes a key, so the install's
//! owner signing slot still holds the successor the roster names live.
//!
//! The owner's second install awaits the root a pin request this install
//! carries names (PLAN v3 test 7): an awaited root is no pin, so the second
//! install stores the root's appointment without judging it, and its door
//! refuses, until the owner pins the root at that install's own pin door.
//!
//! Red before part (b2): every test here but the slot test
//! (`a_door_run_beside_a_committed_appointment_keeps_the_successor_in_the_slot`),
//! which needs its test door. The door answered `AppointmentUnavailable`;
//! the import held the appointment as a row no admitter signed, its
//! witnesses signed by a key the conflict retired, and the successor's
//! binding with it. Red before the fix of review-b2's P1: the slot test,
//! since the second run dropped the slot's seed before its writer read the
//! roster, and the live successor was a key no install held. Red with the
//! pickup pinning a carried root (as before CARRIED-PIN): the awaited-root
//! test, whose second install then holds a pin no owner confirmed there.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test owner_anchor_appointment`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActAuthority, ActSurface, AppointmentVerdict,
    AuthorityAttestation, AuthorityEntryHash, AuthorityFoldIssue, AuthorityKey, AuthorityLogEntry,
    AuthorityOp, AuthoritySignature, AuthorityTier, DeviceAuthority, HostSlipIssuer,
    MachineOwnership, MachineRole, OwnerKeyEnrollment, ROLE_ADMIN, ROLE_AGENT, ROLE_OWNER,
    ROOT_APPOINTMENT_SUCCESSOR_PROOF_KIND, RecoveryRootId, RootAppointment, RootChange,
    authority_entry_hash, authority_transcript, decode_authority_log_entry_body,
    encode_authority_log_entry_body, root_appointment_challenge,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::MEMORY_CODE_OWNER_BINDING_REQUIRED;
use oneiron::recovery::{
    KitIssue, KitSecretKind, PassphraseCost, PieceHome, issue_recovery_root_kit, restore_kit,
};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::root_appointment::appoint_owner_root_between;
use oneiron::test_support::bind_host_owner;
use oneiron::world_keys::RecoveryRootSeed;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

/// The seed of the owner key that signs the fork.
const OWNER_KEY_SEED: u8 = 21;
/// The seeds of the two handoffs' successors.
const FIRST_HANDOFF_SEED: u8 = 33;
const SECOND_HANDOFF_SEED: u8 = 34;
/// The seed of the unrelated key whose binding the owner key revokes.
const UNRELATED_SEED: u8 = 35;
/// The seed of a successor signed outside the door.
const SUCCESSOR_SEED: u8 = 36;
/// The seed of the agent key a successor's row enrols.
const AGENT_SEED: u8 = 37;

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof")
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after 1970")
        .as_secs()
}

fn signing(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn key_of(signing: &SigningKey) -> AuthorityKey {
    AuthorityKey::Ed25519(signing.verifying_key().to_bytes())
}

fn device(key: AuthorityKey, roles: u16) -> DeviceAuthority {
    DeviceAuthority {
        key,
        transport_key_binding: [7; 32],
        attestation: AuthorityAttestation {
            kind: "SoftwareArgon2id".to_owned(),
            evidence: vec![1, 2, 3],
        },
        tier: AuthorityTier::Software,
        roles,
    }
}

fn hash(row: &AuthorityLogEntry) -> AuthorityEntryHash {
    authority_entry_hash(row).expect("a hash")
}

fn bytes(row: &AuthorityLogEntry) -> Vec<u8> {
    encode_authority_log_entry_body(row).expect("the signed bytes")
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

/// A rooted self-hosted vault: the host root binds the embedded owner, the
/// owner enrolled an owner key of his own, and his kit's root is published
/// and pinned on this install.
struct Owned {
    _dir: tempfile::TempDir,
    vault: Vault,
    _issuer: HostSlipIssuer,
    person: EntityId,
    vault_id: [u8; 32],
    owner_key: SigningKey,
    root: RecoveryRootId,
    seed: RecoveryRootSeed,
}

fn owned() -> Owned {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the vault");
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
    let owner_key = signing(OWNER_KEY_SEED);
    let machine = vault
        .prepare_install_signing()
        .expect("this install's machine");
    let authority = ActAuthority::Owner(proof(&vault, person), ActSurface::ThisInstall);
    let public_key = owner_key.verifying_key().to_bytes();
    let challenge = vault
        .owner_key_enrollment_challenge_as(&authority, machine, &public_key)
        .expect("the enrolment challenge");
    vault
        .enrol_owner_signing_key_as_host(
            &authority,
            OwnerKeyEnrollment {
                machine,
                public_key,
                proof: owner_key.sign(&challenge).to_bytes().to_vec(),
            },
            &issuer,
        )
        .expect("the owner enrols an owner key");
    let owner = proof(&vault, person);
    vault
        .enrol_device_owner_signing_key(&authority, &issuer)
        .expect("this install holds a predecessor for the activation");
    let prepared = vault.prepare_owner_root(&owner).expect("a kit root");
    let seed = restored(vault_id, prepared.seed());
    let root = vault
        .activate_owner_root(&owner, prepared, &BTreeSet::new())
        .expect("the owner activates his root")
        .root;
    Owned {
        _dir: dir,
        vault,
        _issuer: issuer,
        person,
        vault_id,
        owner_key,
        root,
        seed,
    }
}

impl Owned {
    fn history(&self) -> Vec<AuthorityLogEntry> {
        self.vault
            .export_signed_authority_history()
            .expect("the signed history")
            .iter()
            .map(|row| decode_authority_log_entry_body(row).expect("a row"))
            .collect()
    }

    /// The rows no row names as a parent.
    fn heads(&self) -> Vec<AuthorityEntryHash> {
        let rows = self.history();
        let parents: BTreeSet<AuthorityEntryHash> = rows
            .iter()
            .flat_map(|row| row.parent_hashes.iter().copied())
            .collect();
        rows.iter()
            .map(hash)
            .filter(|row| !parents.contains(row))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// The next sequence of `signer` over the rows the vault holds.
    fn next_seq(&self, signer: &AuthorityKey) -> u64 {
        self.history()
            .iter()
            .filter(|row| row.signer_key() == signer)
            .map(|row| row.seq + 1)
            .max()
            .unwrap_or(0)
    }

    /// `op`, signed by `signer` at `seq` on `parents`.
    fn signed(
        &self,
        signer: &SigningKey,
        seq: u64,
        mut parents: Vec<AuthorityEntryHash>,
        op: AuthorityOp,
    ) -> AuthorityLogEntry {
        parents.sort_unstable();
        parents.dedup();
        let public_key = key_of(signer);
        let mut row = AuthorityLogEntry {
            schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
            vault_id: Some(self.vault_id),
            seq,
            parent_hashes: parents,
            op,
            signer: AuthoritySignature {
                suite: public_key.suite(),
                public_key,
                signature: vec![0; 64],
            },
            cosigns: Vec::new(),
            ts: now_secs(),
        };
        let transcript = authority_transcript(&row).expect("the transcript");
        row.signer.signature = signer.sign(&transcript).to_bytes().to_vec();
        row
    }

    /// The owner key revokes the binding of an unrelated key at the highest
    /// epoch: a floor no fresh key's binding meets.
    fn revoke_unrelated_binding(&self) {
        let row = self.signed(
            &self.owner_key,
            self.next_seq(&key_of(&self.owner_key)).max(1),
            self.heads(),
            AuthorityOp::RevokeActor {
                authority_key: key_of(&signing(UNRELATED_SEED)),
                epoch: u64::MAX,
            },
        );
        self.vault
            .import_signed_authority_history(&[bytes(&row)])
            .expect("the owner key revokes an unrelated binding");
    }

    /// The owner key hands the vault to two new keys on the heads, and both
    /// handoffs arrive together: a fork. Answers the two handoffs.
    fn fork(&self) -> [AuthorityEntryHash; 2] {
        let heads = self.heads();
        let seq = self.next_seq(&key_of(&self.owner_key)).max(1);
        let first = self.signed(
            &self.owner_key,
            seq,
            heads.clone(),
            AuthorityOp::ReRoot {
                new_device: device(key_of(&signing(FIRST_HANDOFF_SEED)), ROLE_OWNER),
            },
        );
        let second = self.signed(
            &self.owner_key,
            seq + 1,
            heads,
            AuthorityOp::ReRoot {
                new_device: device(key_of(&signing(SECOND_HANDOFF_SEED)), ROLE_OWNER),
            },
        );
        self.vault
            .import_signed_authority_history(&[bytes(&first), bytes(&second)])
            .expect("both handoffs land");
        [hash(&first), hash(&second)]
    }

    /// The pinned root's appointment of `successor` on `parents`, signed by
    /// its anchor outside the door, and the successor's binding of the owner
    /// on it.
    fn appointment_and_binding(
        &self,
        successor: &SigningKey,
        parents: Vec<AuthorityEntryHash>,
    ) -> (AuthorityLogEntry, AuthorityLogEntry) {
        let anchor = self.seed.anchor();
        let mut parents = parents;
        parents.sort_unstable();
        parents.dedup();
        let successor_key = successor.verifying_key().to_bytes();
        let challenge =
            root_appointment_challenge(&self.vault_id, &self.root, &parents, &successor_key)
                .expect("the challenge");
        let appointment = self.signed(
            &anchor,
            self.next_seq(&key_of(&anchor)),
            parents,
            AuthorityOp::RootAppointment(RootAppointment {
                root: self.root,
                successor: DeviceAuthority {
                    key: AuthorityKey::Ed25519(successor_key),
                    transport_key_binding: [0; 32],
                    attestation: AuthorityAttestation {
                        kind: ROOT_APPOINTMENT_SUCCESSOR_PROOF_KIND.to_owned(),
                        evidence: successor.sign(&challenge).to_bytes().to_vec(),
                    },
                    tier: AuthorityTier::Software,
                    roles: ROLE_OWNER | ROLE_ADMIN,
                },
            }),
        );
        let binding = self.signed(
            successor,
            1,
            vec![hash(&appointment)],
            AuthorityOp::BindActor {
                authority_key: key_of(successor),
                actor_ref: self.person,
                actor_class: "human".to_owned(),
                epoch: 1,
            },
        );
        (appointment, binding)
    }

    fn live(&self, key: &AuthorityKey) -> bool {
        self.vault
            .authority_fold()
            .expect("the fold")
            .roster
            .get(key)
            .is_some_and(|device| !device.revoked)
    }

    fn rootless(&self) -> bool {
        self.vault
            .authority_fold()
            .expect("the fold")
            .issues
            .contains(&AuthorityFoldIssue::NoRootKey)
    }

    fn valid(&self, row: &AuthorityEntryHash) -> bool {
        self.vault
            .authority_fold()
            .expect("the fold")
            .valid_entries
            .contains(row)
    }

    fn passes_owner_verbs(&self) -> bool {
        match self
            .vault
            .memory(self.person, EdgeActorClass::Human)
            .verify_owner()
        {
            Ok(()) => true,
            Err(error) => {
                assert_eq!(error.code, MEMORY_CODE_OWNER_BINDING_REQUIRED, "{error:?}");
                false
            }
        }
    }
}

/// The door end to end on a handoff fork (PLAN v3 test 1, with test 17's
/// floor): the appointment names the conflict's two handoffs, the successor
/// is a live root key of its own line, it binds the owner at epoch 1 though
/// an unrelated key's binding was revoked at the highest epoch, and owner
/// verbs pass again. A second run of the door is refused: the roster holds a
/// root key now.
#[test]
fn the_pinned_anchor_appoints_a_root_after_a_handoff_fork() {
    let owned = owned();
    assert!(owned.passes_owner_verbs(), "the bound owner passes");
    owned.revoke_unrelated_binding();
    let witnesses = owned.fork();
    assert!(owned.rootless(), "the fork leaves no live root key");
    assert!(
        !owned.passes_owner_verbs(),
        "no root key binds the owner after the fork"
    );
    assert!(!owned.live(&key_of(&owned.owner_key)));

    let receipt = owned
        .vault
        .appoint_owner_root(&proof(&owned.vault, owned.person), &owned.seed, None)
        .expect("the pinned root's anchor appoints a successor");

    assert_eq!(receipt.root, owned.root);
    assert_eq!(receipt.epoch, 1, "the successor binds at its own floor");
    let appointment = owned
        .history()
        .into_iter()
        .find(|row| hash(row) == receipt.entry)
        .expect("the appointment is stored");
    for witness in witnesses {
        assert!(
            appointment.parent_hashes.contains(&witness),
            "the appointment names the conflict's handoffs"
        );
        assert!(!owned.valid(&witness), "the handoffs stay refused");
    }
    let successor = AuthorityKey::Ed25519(receipt.successor);
    assert!(owned.live(&successor), "the successor is a live root key");
    assert!(owned.valid(&receipt.entry) && owned.valid(&receipt.binding));
    assert!(!owned.rootless(), "the roster holds a root key again");
    assert!(
        !owned.live(&key_of(&owned.owner_key)),
        "the old key stays retired"
    );
    assert!(
        owned.passes_owner_verbs(),
        "the successor's binding lets owner verbs pass"
    );

    let stored = owned.history().len();
    assert!(
        owned
            .vault
            .appoint_owner_root(&proof(&owned.vault, owned.person), &owned.seed, None)
            .is_err(),
        "a rooted roster needs no appointment"
    );
    assert_eq!(owned.history().len(), stored, "the refusal writes nothing");
}

/// On a roster that still holds a live root key the door refuses, names
/// why, and writes nothing.
#[test]
fn a_rooted_roster_refuses_the_appointment_and_writes_nothing() {
    let owned = owned();
    let stored = owned.history().len();

    let refusal = owned
        .vault
        .appoint_owner_root(&proof(&owned.vault, owned.person), &owned.seed, None)
        .expect_err("no appointment while a root key is live");

    assert!(
        refusal.to_string().contains("live root key"),
        "the refusal names the live root key: {refusal}"
    );
    assert_eq!(owned.history().len(), stored);
    assert!(owned.passes_owner_verbs());
}

/// The appointment and the successor's binding, signed outside the door,
/// arrive in one import past the conflict's handoffs: both land, and the
/// owner is bound again (the admission bridge).
#[test]
fn an_appointment_and_its_binding_land_together_over_the_witnesses() {
    let owned = owned();
    let heads = owned.heads();
    let witnesses = owned.fork();
    let successor = signing(SUCCESSOR_SEED);
    let parents: Vec<_> = witnesses.iter().chain(&heads).copied().collect();
    let (appointment, binding) = owned.appointment_and_binding(&successor, parents);

    let arrival = owned
        .vault
        .import_signed_authority_history(&[bytes(&appointment), bytes(&binding)]);

    assert!(arrival.is_ok(), "the import takes both rows: {arrival:?}");
    assert!(owned.valid(&hash(&appointment)) && owned.valid(&hash(&binding)));
    assert!(owned.live(&key_of(&successor)));
    assert!(owned.passes_owner_verbs());
}

/// A row the successor signs that also names a witness as its own parent
/// stands on the retired key through that path, so the import that carries
/// it with the appointment is refused whole; without it, the appointment and
/// the binding land.
#[test]
fn a_row_with_its_own_path_to_a_witness_is_refused() {
    let owned = owned();
    let heads = owned.heads();
    let witnesses = owned.fork();
    let successor = signing(SUCCESSOR_SEED);
    let parents: Vec<_> = witnesses.iter().chain(&heads).copied().collect();
    let (appointment, binding) = owned.appointment_and_binding(&successor, parents);
    let beside = owned.signed(
        &successor,
        2,
        vec![hash(&binding), witnesses[0]],
        AuthorityOp::EnrollDevice {
            device: device(key_of(&signing(AGENT_SEED)), ROLE_AGENT),
        },
    );

    let refused = owned.vault.import_signed_authority_history(&[
        bytes(&appointment),
        bytes(&binding),
        bytes(&beside),
    ]);

    assert!(
        refused.is_err(),
        "a row that reaches a witness by its own path stands on the retired key"
    );
    assert!(
        !owned.valid(&hash(&appointment)),
        "the refused import writes nothing"
    );
    owned
        .vault
        .import_signed_authority_history(&[bytes(&appointment), bytes(&binding)])
        .expect("the appointment and its binding land alone");
    assert!(owned.live(&key_of(&successor)));
    assert!(!owned.valid(&hash(&beside)));
}

/// A second run of the door whose read-only check passed before the first
/// run committed: the first appoints its successor; the second, at its
/// writer, finds a live root key and is refused before it makes a key. The
/// install's owner signing slot still holds the successor the roster names
/// live, so the owner's root key stays one this install can sign with.
#[test]
fn a_door_run_beside_a_committed_appointment_keeps_the_successor_in_the_slot() {
    let owned = owned();
    owned.revoke_unrelated_binding();
    owned.fork();
    assert!(owned.rootless(), "the fork leaves no live root key");

    let mut first = None;
    let refusal = appoint_owner_root_between(
        &owned.vault,
        &proof(&owned.vault, owned.person),
        &owned.seed,
        None,
        || {
            first = Some(owned.vault.appoint_owner_root(
                &proof(&owned.vault, owned.person),
                &owned.seed,
                None,
            ));
        },
    )
    .expect_err("the roster holds a root key once the first run commits");
    let first = first
        .expect("the first run ran between the check and the writer")
        .expect("the first run appoints a successor");

    assert!(
        refusal.to_string().contains("live root key"),
        "the second run names the live root key: {refusal}"
    );
    assert!(
        owned.live(&AuthorityKey::Ed25519(first.successor)),
        "the first run's successor is a live root key"
    );
    let held = owned
        .vault
        .device_owner_signing_key()
        .expect("the install's owner signing key")
        .public_key();
    assert_eq!(
        held, first.successor,
        "the install's owner signing slot holds the live successor"
    );
    assert!(owned.passes_owner_verbs());
}

/// The owner's second install: enrolled as his through the hosted console,
/// never pinned. It takes the vault's authority history from the first
/// install, as sync does.
struct SecondInstall {
    _dir: tempfile::TempDir,
    vault: Vault,
    machine: EntityId,
    held: BTreeSet<Vec<u8>>,
}

impl Owned {
    /// Enrols the owner's second install, as the hosted console does, and
    /// hands it this install's history.
    fn enrol_second_install(&self) -> SecondInstall {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the second install");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let key = vault
            .machine_encryption_key(self.vault_id)
            .expect("the second install's encryption key");
        let request = vault
            .machine_enrolment_request(self.vault_id, key)
            .expect("the second install's enrolment request");
        self.vault
            .enroll_machine(
                &proof(&self.vault, self.person),
                ActSurface::HostedConsole,
                &request,
                MachineRole::Owned(MachineOwnership::Yours),
                None,
            )
            .expect("the owner enrols the second install as his");
        vault
            .ensure_embedded_owner_actor()
            .expect("the owner on the second install");
        let mut second = SecondInstall {
            _dir: dir,
            vault,
            machine: request.machine,
            held: BTreeSet::new(),
        };
        second.take(self);
        second
    }

    /// Records a pin of this install's root on `target`, carried by this
    /// install as the hosted console's act.
    fn request_pin(&self, target: EntityId) {
        let receipt = self
            .vault
            .request_root_change(
                &proof(&self.vault, self.person),
                ActSurface::HostedConsole,
                target,
                RootChange::Pin { root: self.root },
            )
            .expect("the pin request");
        assert!(
            receipt.request.is_some(),
            "the pin request is recorded for the second install: {receipt:?}"
        );
    }
}

impl SecondInstall {
    /// Imports the rows of `from`'s history this install does not hold yet.
    fn take(&mut self, from: &Owned) {
        let new: Vec<Vec<u8>> = from
            .vault
            .export_signed_authority_history()
            .expect("the first install's history")
            .into_iter()
            .filter(|row| !self.held.contains(row))
            .collect();
        self.vault
            .import_signed_authority_history(&new)
            .expect("the second install takes the rows");
        self.held.extend(new);
    }

    /// Two syncs and pickups: the first may only commit the wait for a root
    /// whose record the install does not store yet.
    fn sync_and_pick_up(&mut self, from: &Owned) {
        for _ in 0..2 {
            self.take(from);
            let _drain = self
                .vault
                .run_pending_owner_work(|| true)
                .expect("the second install's pickup");
        }
        self.take(from);
    }

    fn owner(&self) -> AuthenticatedOwner {
        let person = self
            .vault
            .ensure_embedded_owner_actor()
            .expect("the owner on the second install");
        proof(&self.vault, person)
    }

    fn pinned(&self) -> Option<RecoveryRootId> {
        self.vault
            .owner_root_view(None, 16)
            .expect("the second install's roots")
            .pinned
    }

    fn awaiting(&self) -> Option<RecoveryRootId> {
        self.vault
            .owner_root_view(None, 16)
            .expect("the second install's roots")
            .awaiting
            .map(|awaited| awaited.root)
    }

    fn stored(&self) -> usize {
        self.vault
            .export_signed_authority_history()
            .expect("the second install's history")
            .len()
    }

    fn live(&self, key: &AuthorityKey) -> bool {
        self.vault
            .authority_fold()
            .expect("the second install's fold")
            .roster
            .get(key)
            .is_some_and(|device| !device.revoked)
    }

    fn rootless(&self) -> bool {
        self.vault
            .authority_fold()
            .expect("the second install's fold")
            .issues
            .contains(&AuthorityFoldIssue::NoRootKey)
    }

    fn valid(&self, row: &AuthorityEntryHash) -> bool {
        self.vault
            .authority_fold()
            .expect("the second install's fold")
            .valid_entries
            .contains(row)
    }

    /// The verdict the install's fold names for a refused appointment.
    fn refused_as(&self, appointment: AuthorityEntryHash) -> Option<AppointmentVerdict> {
        self.vault
            .authority_fold()
            .expect("the second install's fold")
            .issues
            .iter()
            .find_map(|issue| match issue {
                AuthorityFoldIssue::AppointmentRefused { entry, verdict }
                    if *entry == appointment =>
                {
                    Some(*verdict)
                }
                _ => None,
            })
    }
}

/// PLAN v3 test 7 (round-1 finding 1): this install carries a pin of its
/// root for the owner's second install, which never pinned one. The pickup
/// leaves the root awaited there. The fork, and the root's appointment of a
/// successor signed outside the door, reach the second install: it stores
/// the appointment and does not judge it, since an awaited root is no pin,
/// so the successor has no standing there and the door refuses with the pin
/// door's name. Once the owner pins the root at the second install's own pin
/// door, it counts the stored appointment, and the successor's binding lands.
#[test]
fn an_awaited_root_counts_no_appointment_until_the_pin_door_writes_it() {
    let owned = owned();
    let mut second = owned.enrol_second_install();
    owned.request_pin(second.machine);
    second.sync_and_pick_up(&owned);
    assert_eq!(second.pinned(), None, "a carried pin request sets no pin");
    assert_eq!(
        second.awaiting(),
        Some(owned.root),
        "the second install awaits the requested root"
    );

    let heads = owned.heads();
    let witnesses = owned.fork();
    second.take(&owned);
    assert!(second.rootless(), "the fork reaches the second install");
    let successor = signing(SUCCESSOR_SEED);
    let parents: Vec<_> = witnesses.iter().chain(&heads).copied().collect();
    let (appointment, binding) = owned.appointment_and_binding(&successor, parents);
    second
        .vault
        .import_signed_authority_history(&[bytes(&appointment)])
        .expect("the second install stores the appointment of the root it awaits");

    assert_eq!(
        second.refused_as(hash(&appointment)),
        Some(AppointmentVerdict::Unjudged),
        "an awaited root judges no appointment"
    );
    assert!(
        !second.live(&key_of(&successor)),
        "the successor has no standing on the second install"
    );
    assert!(second.rootless());
    let stored = second.stored();
    let refusal = second
        .vault
        .appoint_owner_root(&second.owner(), &owned.seed, None)
        .expect_err("an awaited root is no pin for the door");
    assert!(
        refusal.to_string().contains("pin_owner_root"),
        "the refusal names the pin door: {refusal}"
    );
    assert_eq!(second.stored(), stored, "the refusal writes nothing");

    second
        .vault
        .pin_owner_root(&second.owner(), owned.root)
        .expect("the owner pins the awaited root at the second install's pin door");

    assert_eq!(second.pinned(), Some(owned.root));
    assert!(
        second.valid(&hash(&appointment)),
        "the pinned root's stored appointment counts"
    );
    assert!(second.live(&key_of(&successor)));
    assert!(!second.rootless());
    second
        .vault
        .import_signed_authority_history(&[bytes(&binding)])
        .expect("the successor's binding lands");
    assert!(second.valid(&hash(&binding)));
}
