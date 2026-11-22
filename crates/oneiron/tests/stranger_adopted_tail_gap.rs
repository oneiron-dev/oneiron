//! FIX [STRANGER-GAP-STALLS-ADOPTED-TAIL-FOLD]: on a vault that adopted a
//! checkpoint image, a stranger's stored tail row naming a withheld parent no
//! longer refuses the adopted tail fold, while a believed row's missing parent
//! still does and delivery still fetches the stranger's parent.
//!
//! `fold_adopted_checkpoint_tail` took every tail row's parent that is neither
//! covered by the image nor a tail row and answered NeedHistory before any
//! settle. Attack: publish a valid foreign root F (covered by the adopted
//! image); under F sign machine revision Q and keep it; sign C naming Q as
//! parent and deliver only C by replicated ingest. C is stored (an
//! anchor-signed profile under the stranger bound) with Q missing; the adopted
//! fold then refuses with `AuthorityHistoryRequired`, so every authority view
//! read on the vault fails and `authority_fold_settled` returns false at its
//! first out (the fold must read) with every honest head unchanged. The fold
//! now counts only the gaps the believed tail rows rest on, holding the rows
//! above any other gap invalid as the stored fold does, while the whole
//! history request still names those gaps for delivery.
//!
//! T1 is the attack (red on main, green with the fix); T2 guards a believed
//! row's withheld parent and T3 the whole delivery request (green on both).
//! Review round 2 of #9476: a stranger batch above withheld parents still
//! stores once the pending probes believe the whole batch (green on both),
//! and a dropped row with a parent-scope fault keeps `InvalidEntry` (red
//! before the fix, which read it `InvalidAncestry`).
//! The stranger-row setup mirrors `stranger_parent_settled.rs`; the adoption
//! runs the public checkpoint path (build, host-attest, pin, bundle, adopt) on
//! the vault's own image, so no test door is needed there.
//! `batch_enrolled_signer` holds the batch-belief case of review round 2
//! (FIX [ADOPTED-PENDING-BATCH-BELIEF-RED-TEST]): one granting batch whose
//! host-signed enrolment of a key sits above a withheld parent, which only
//! the test door `host_signed_row` signs.
//!
//! Run: `cargo test --locked -p oneiron --all-features --test
//! stranger_adopted_tail_gap`; with `RUSTFLAGS="--cfg oneiron_test_support"`
//! for `batch_enrolled_signer` too.

#![cfg(all(feature = "sync", feature = "test-support"))]

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActSurface, AuthorityCheckpointUnresolved, AuthorityEntryHash,
    AuthorityEntryStatus, AuthorityFoldIssue, AuthorityKey, AuthorityLogEntry, AuthorityOp,
    AuthoritySignature, AuthorityVaultId, HostSlipIssuer, MACHINE_ENCRYPTION_KEY_LEN,
    MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineDeviceClass, MachineEncryptionKey,
    MachineEnrolmentRequest, MachineOwnership, MachineProfile, MachineRole, OwnerRootRecord,
    authority_entry_hash, authority_log_entity_id, authority_transcript,
    encode_authority_log_entry_body, machine_profile_proof_transcript,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::registry::ENTITY_TYPE_AUTHORITY_LOG;
use oneiron::store::GateDecisionId;
use oneiron::sync::client::ImportTier;
use oneiron::sync::peer_route::authority_fold_settled;
use oneiron::sync::replay::{ReplicatedEntity, replay_entity};
use oneiron::world_keys::RecoveryRootSeed;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_authority::authority::{
    HomeCandidacy, PolicyRevision, WORLD_KEY_EPOCH, WORLD_KEY_PAYLOAD_LEN, WorldKeyId,
    WorldKeyWrapsRecord, WrapRecipient,
};
use oneiron_crypto::{HybridSecretKey, Purpose, SealKey, SealParams, SuiteId};

/// The seed of the joining machine's machine key.
const JOINING_SEED: u8 = 68;
/// The seed of the machine key a stranger holds for the machine it marks.
const STRANGER_MACHINE_SEED: u8 = 71;
/// The stored rows' occurred range and learned-at, as the store-door tests use.
const AT: TimeRange = TimeRange { start: 2, end: 2 };

fn signing(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn key_of(signing: &SigningKey) -> AuthorityKey {
    AuthorityKey::Ed25519(signing.verifying_key().to_bytes())
}

fn signature_slot(key: AuthorityKey) -> AuthoritySignature {
    AuthoritySignature {
        suite: key.suite(),
        public_key: key,
        signature: vec![0; 64],
    }
}

/// `signer` alone signs `op` on `parent_hashes`.
fn signed(
    vault_id: AuthorityVaultId,
    seq: u64,
    parent_hashes: Vec<AuthorityEntryHash>,
    op: AuthorityOp,
    signer: &SigningKey,
) -> AuthorityLogEntry {
    let overlay_seed = oneiron_authority::authority::authority_overlay_seed_for(&op)
        .expect("authority overlay seed");
    let mut row = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(vault_id),
        seq,
        parent_hashes,
        op,
        overlay_seed,
        signer: signature_slot(key_of(signer)),
        cosigns: Vec::new(),
        ts: 1,
    };
    let transcript = authority_transcript(&row).expect("the transcript signs");
    row.signer.signature = signer.sign(&transcript).to_bytes().to_vec();
    row
}

fn hash(row: &AuthorityLogEntry) -> AuthorityEntryHash {
    authority_entry_hash(row).expect("a row hashes")
}

/// A world key wrap envelope for `to` whose header is made for exactly `key`
/// and `vault_id`, around a blank payload of the world key's length: the
/// header is what a `WorldKeyWraps` row's shape checks, and neither the store
/// door nor the fold opens the envelope. Sealed to a key of its own, since the
/// fixture machine's encryption key is placeholder bytes.
fn world_key_wrap_envelope(
    vault_id: AuthorityVaultId,
    key: WorldKeyId,
    to: &WrapRecipient,
) -> Vec<u8> {
    let sealer =
        HybridSecretKey::from_seed(&[0x7A; 32], b"stranger_adopted_tail_gap/world-key-wrap")
            .expect("setup: the wrap key derives");
    oneiron_crypto::seal(
        &SealParams {
            suite: SuiteId::XCHACHA20POLY1305_V1,
            purpose: Purpose::WorldDek,
            epoch: WORLD_KEY_EPOCH,
            key_id: &key.envelope_key_id(),
            recipient: &to.envelope_recipient(),
            vault_id: &vault_id,
        },
        SealKey::Hybrid {
            recipient: sealer.public_key(),
            kem_suite: SuiteId::KEM_X25519_MLKEM1024_V1,
        },
        &[0; WORLD_KEY_PAYLOAD_LEN],
        &mut getrandom::SysRng,
    )
    .expect("setup: W's wrap seals")
    .to_bytes()
}

/// The stranger root's owner person, distinct from the vault's owner.
fn stranger_owner() -> EntityId {
    EntityId::from_bytes([0xA1; 16]).expect("an id parses")
}

/// A self-host vault as its own server starts one: this install serving and
/// profiled under the host root, and the owner bound and authenticated. It
/// pins no root, so a machine stands under the roster's head alone.
struct ServedVault {
    vault: Vault,
    owner: AuthenticatedOwner,
    issuer: HostSlipIssuer,
    _dir: tempfile::TempDir,
}

/// A self-host vault rooted under the host root before its first serving
/// start: no chain profiles this install yet.
fn unprofiled_self_host() -> (Vault, HostSlipIssuer, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("self-host vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    (vault, issuer, dir)
}

fn vault_id_of(vault: &Vault) -> AuthorityVaultId {
    vault
        .authority_fold()
        .expect("authority fold reads")
        .vault_id
        .expect("the vault is rooted")
}

impl ServedVault {
    fn self_host() -> Self {
        let (vault, issuer, dir) = unprofiled_self_host();
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's machine profile under the host root")
            .roster
            .expect("guard: this install has a roster chain");
        let person = vault.ensure_embedded_owner_actor().expect("the owner");
        oneiron::test_support::bind_host_owner(&vault, &issuer, person)
            .expect("the owner's binding");
        let owner = vault
            .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
            .expect("the owner's proof");
        Self {
            vault,
            owner,
            issuer,
            _dir: dir,
        }
    }

    fn vault_id(&self) -> AuthorityVaultId {
        vault_id_of(&self.vault)
    }

    /// Another machine's request to join this vault.
    fn joining_machine(&self) -> MachineEnrolmentRequest {
        self.request_for(
            EntityId::from_bytes([0x76; 16]).expect("an id parses"),
            &signing(JOINING_SEED),
        )
    }

    /// `machine`'s identity under the machine key `node`, with its own proof.
    fn request_for(&self, machine: EntityId, node: &SigningKey) -> MachineEnrolmentRequest {
        let vault_id = self.vault_id();
        let machine_key = node.verifying_key().to_bytes();
        let device_class = MachineDeviceClass::Computer;
        let encryption_key = MachineEncryptionKey {
            suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
            key: vec![7; MACHINE_ENCRYPTION_KEY_LEN],
        };
        let machine_proof = node
            .sign(&machine_profile_proof_transcript(
                &vault_id,
                machine,
                &machine_key,
                device_class,
                &encryption_key,
            ))
            .to_bytes();
        MachineEnrolmentRequest {
            vault_id,
            machine,
            machine_key,
            device_class,
            encryption_key,
            machine_proof,
            restored_from: None,
        }
    }

    /// The owner enrols `request` as his own, carried by this install.
    fn enrol(&self, request: &MachineEnrolmentRequest) -> oneiron::Result<()> {
        self.vault
            .enroll_machine(
                &self.owner,
                ActSurface::ThisInstall,
                request,
                MachineRole::Owned(MachineOwnership::Yours),
                None,
            )
            .map(drop)
    }
}

/// A stranger's root published on one held valid row and stored. Returns its
/// anchor signing key and the root row's hash.
fn publish_stranger_root(vault: &Vault) -> (SigningKey, AuthorityEntryHash) {
    let vault_id = vault_id_of(vault);
    let seed = RecoveryRootSeed::generate().expect("a fresh stranger root seed");
    let root = seed
        .public(&vault_id)
        .expect("the stranger root's public half");
    let anchor = seed.anchor();
    let parent = vault
        .authority_fold()
        .expect("authority fold for a parent")
        .valid_entries
        .iter()
        .next()
        .copied()
        .expect("guard: the vault holds a valid row for the root's parent");
    let record = OwnerRootRecord {
        owner: stranger_owner(),
        root: root.id,
        recovery_key: MachineEncryptionKey {
            suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
            key: root.recovery_key.to_bytes(),
        },
        anchor_key: root.anchor_key,
    };
    let entry = signed(
        vault_id,
        1,
        vec![parent],
        AuthorityOp::OwnerRoot(record),
        &anchor,
    );
    let root_hash = hash(&entry);
    vault
        .put_authority_log_entry(&entry, AT, 2)
        .expect("the stranger's root row is stored");
    assert!(
        vault
            .authority_fold()
            .expect("authority fold reads")
            .valid_entries
            .contains(&root_hash),
        "guard: the stranger's root is in valid_entries, so its anchor vouches"
    );
    (anchor, root_hash)
}

/// Delivers `entry` to `vault` through the replicated ingest door a sync peer's
/// row takes: the public explicit-tier replay (`sync::replay::replay_entity`
/// with `ImportTier::OwnDevice`), which runs the replicated authority
/// validator and the store door.
fn deliver_via_replicated(vault: &Vault, entry: &AuthorityLogEntry) -> oneiron::Result<()> {
    let body = encode_authority_log_entry_body(entry).expect("the row encodes");
    let id = authority_log_entity_id(entry).expect("the row's content id");
    replay_entity(
        vault,
        ReplicatedEntity {
            id,
            entity_type: ENTITY_TYPE_AUTHORITY_LOG,
            occurred: AT,
            learned_at: 2,
            row_version: 0,
            body: &body,
        },
        ImportTier::OwnDevice,
    )
}

/// The stranger's machine revision C under its anchor `anchor`, whose
/// parent, revision Q on the root row `root_hash`, the stranger keeps:
/// answers Q's hash and C, neither stored.
fn strangers_gapped_revision(
    served: &ServedVault,
    anchor: &SigningKey,
    root_hash: AuthorityEntryHash,
) -> (AuthorityEntryHash, AuthorityLogEntry) {
    let vault_id = served.vault_id();
    let machine = EntityId::from_bytes([0x71; 16]).expect("an id parses");
    let node = signing(STRANGER_MACHINE_SEED);
    let machine_key = node.verifying_key().to_bytes();
    let device_class = MachineDeviceClass::Computer;
    let encryption_key = MachineEncryptionKey {
        suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
        key: vec![7; MACHINE_ENCRYPTION_KEY_LEN],
    };
    let machine_proof = node
        .sign(&machine_profile_proof_transcript(
            &vault_id,
            machine,
            &machine_key,
            device_class,
            &encryption_key,
        ))
        .to_bytes();
    let profile = |revision: u64| MachineProfile {
        machine,
        owner: stranger_owner(),
        machine_key,
        device_class,
        encryption_key: encryption_key.clone(),
        role: MachineRole::Owned(MachineOwnership::Yours),
        revision,
        machine_proof,
        seen_world_edits: BTreeSet::new(),
        carrier: None,
        act: None,
        restored_from: None,
    };
    let withheld = signed(
        vault_id,
        2,
        vec![root_hash],
        AuthorityOp::MachineProfile(profile(1)),
        anchor,
    );
    let withheld_hash = hash(&withheld);
    let delivered = signed(
        vault_id,
        3,
        vec![withheld_hash],
        AuthorityOp::MachineProfile(profile(2)),
        anchor,
    );
    (withheld_hash, delivered)
}

/// The vault adopts its own checkpoint image over the public path: build,
/// host-attest, pin, bundle, adopt. The image covers the whole held log, so
/// the tail past it starts empty; the vault still holds every covered row.
fn adopt_own_checkpoint(served: &ServedVault) -> [u8; 32] {
    let vault = &served.vault;
    let built = vault
        .build_authority_checkpoint_v2()
        .expect("setup: the held log builds a checkpoint image");
    assert_eq!(
        built.unresolved,
        AuthorityCheckpointUnresolved::default(),
        "setup: a clean log's image holds nothing back, so the vault can adopt it"
    );
    let image = vault
        .write_authority_checkpoint_v2(&served.issuer)
        .expect("setup: the checkpoint image is kept");
    vault
        .host_attest_authority_checkpoint(&served.issuer, image)
        .expect("setup: the host root attests the image");
    let pin = vault
        .authority_checkpoint_pin([7; 32])
        .expect("setup: the pin reads")
        .expect("setup: the attested image pins");
    let bundle = vault
        .authority_checkpoint_bundle(&image)
        .expect("setup: the bundle reads")
        .expect("setup: the kept image bundles");
    vault
        .adopt_authority_checkpoint(&pin, &bundle.image, &bundle.attestations)
        .expect("setup: the vault adopts its own image");
    assert!(
        vault
            .adopted_authority_checkpoint()
            .expect("setup: the adoption reads")
            .is_some(),
        "setup: the adoption stands"
    );
    image
}

/// T1 the attack, row C (the stranger's revision 2 of its machine, delivered
/// alone through `replay_entity` past the adopted image while its parent Q is
/// withheld): C stores, the fetch request still names Q, the authority fold
/// reads and the peer route stays settled. RED on main d54d8768 (the fold refuses
/// with the history-required error and settled reads false), GREEN with the
/// fix (C folds as invalid past the image).
#[test]
fn adopted_strangers_withheld_parent_leaves_fold_reading() {
    let served = ServedVault::self_host();
    let (anchor, root_hash) = publish_stranger_root(&served.vault);
    adopt_own_checkpoint(&served);
    assert!(
        served.vault.authority_fold().is_ok(),
        "guard: the adopted vault's fold reads before the stranger's row"
    );
    assert!(
        authority_fold_settled(&served.vault).expect("the settled read"),
        "guard: the adopted vault serves peers before the stranger's row"
    );
    let (withheld_hash, delivered) = strangers_gapped_revision(&served, &anchor, root_hash);
    let delivered_id = authority_log_entity_id(&delivered).expect("C's content-derived id");
    deliver_via_replicated(&served.vault, &delivered).expect("C lands through replicated ingest");
    assert!(
        served
            .vault
            .get_authority_log_entry(&delivered_id)
            .expect("C reads back")
            .is_some(),
        "setup: C is stored, so the attack row reached the log"
    );
    assert!(
        matches!(
            served
                .vault
                .authority_log_entry_status(&withheld_hash)
                .expect("Q's status reads"),
            AuthorityEntryStatus::Unknown
        ),
        "setup: Q is withheld, so no peer holds the parent C names"
    );
    assert!(
        served
            .vault
            .authority_missing_history()
            .expect("the history read")
            .missing
            .contains(&withheld_hash),
        "setup: the fetch request still names Q, so delivery can fetch it"
    );
    assert!(
        served.vault.authority_fold().is_ok(),
        "a stranger's withheld parent refused the adopted tail fold"
    );
    assert!(
        authority_fold_settled(&served.vault).expect("the settled read"),
        "a stranger's withheld parent stalled peer serving on the adopted vault"
    );
}

/// T2 the guard, row C2 (an enrolled device's home candidacy of its own
/// machine, delivered alone through `replay_entity` past the adopted image
/// while its parent P is withheld): C2 stores, the fetch request names P, and
/// the peer route stays unsettled. GREEN on main and with the fix: a
/// believed row reaching a gap still refuses.
#[test]
fn adopted_believed_withheld_parent_keeps_peer_unsettled() {
    let served = ServedVault::self_host();
    let request = served.joining_machine();
    served.enrol(&request).expect("the owner enrols M");
    adopt_own_checkpoint(&served);
    assert!(
        served.vault.authority_fold().is_ok(),
        "guard: the adopted vault's fold reads before C2"
    );
    assert!(
        authority_fold_settled(&served.vault).expect("the settled read"),
        "guard: the adopted vault serves peers before C2"
    );
    let vault_id = served.vault_id();
    let head = served
        .vault
        .authority_fold()
        .expect("authority fold for a parent")
        .valid_entries
        .iter()
        .next()
        .copied()
        .expect("guard: the vault holds a valid row for P's parent");
    let signer = signing(JOINING_SEED);
    let declaration = HomeCandidacy {
        machine: request.machine,
        node_id: 1,
        always_on: false,
        primary: false,
        macro_ready: true,
        cloud: false,
    };
    let withheld = signed(
        vault_id,
        1,
        vec![head],
        AuthorityOp::HomeCandidacy(declaration),
        &signer,
    );
    let withheld_hash = hash(&withheld);
    let delivered = signed(
        vault_id,
        2,
        vec![withheld_hash],
        AuthorityOp::HomeCandidacy(declaration),
        &signer,
    );
    let delivered_id = authority_log_entity_id(&delivered).expect("C2's content-derived id");
    deliver_via_replicated(&served.vault, &delivered).expect("C2 lands through replicated ingest");
    assert!(
        served
            .vault
            .get_authority_log_entry(&delivered_id)
            .expect("C2 reads back")
            .is_some(),
        "setup: C2 is stored, so the believed row reached the log"
    );
    assert!(
        served
            .vault
            .authority_missing_history()
            .expect("the history read")
            .missing
            .contains(&withheld_hash),
        "setup: the fetch request names P, so delivery can fetch it"
    );
    assert!(
        !authority_fold_settled(&served.vault).expect("the settled read"),
        "a believed withheld parent must keep peer serving unsettled"
    );
}

/// T3 the delivery guard on T1's setup: the whole history request still names
/// the stranger's withheld parent past the adopted fold, so delivery fetches
/// it, while the settled gate (which reads the believed request) stays
/// settled. GREEN on main and with the fix.
#[test]
fn adopted_whole_request_still_names_strangers_parent() {
    let served = ServedVault::self_host();
    let (anchor, root_hash) = publish_stranger_root(&served.vault);
    adopt_own_checkpoint(&served);
    let (withheld_hash, delivered) = strangers_gapped_revision(&served, &anchor, root_hash);
    deliver_via_replicated(&served.vault, &delivered).expect("C lands through replicated ingest");
    assert!(
        served
            .vault
            .authority_missing_history()
            .expect("the history read")
            .missing
            .contains(&withheld_hash),
        "delivery still fetches the stranger's parent past the adopted fold"
    );
    assert!(
        authority_fold_settled(&served.vault).expect("the settled read"),
        "the believed request names nothing, so the adopted vault serves peers"
    );
}

/// T4 on T1's setup (#9476 review round 1, P1): the stranger's row C, which
/// the fold past the adopted image leaves out of what it settles, keeps the
/// verdict the stored log's fold gives a row whose parent never folds:
/// `InvalidAncestry(C)` (`fold_schedule`). RED at b5a1e5f4 (the fold names no
/// issue for C), GREEN with the fix.
#[test]
fn adopted_strangers_dropped_row_keeps_its_invalid_ancestry_verdict() {
    let served = ServedVault::self_host();
    let (anchor, root_hash) = publish_stranger_root(&served.vault);
    adopt_own_checkpoint(&served);
    let (_, delivered) = strangers_gapped_revision(&served, &anchor, root_hash);
    deliver_via_replicated(&served.vault, &delivered).expect("C lands through replicated ingest");
    let fold = served
        .vault
        .authority_fold()
        .expect("the fold past the adopted image reads");
    assert!(
        fold.issues
            .contains(&AuthorityFoldIssue::InvalidAncestry(hash(&delivered))),
        "the fold past the adopted image dropped C's invalid-ancestry verdict: {:?}",
        fold.issues
    );
}

/// A batch of two stranger roots, each above a withheld parent, stores and
/// leaves the adopted fold reading and peer serving settled. The pending
/// probes believe the whole batch (#9476 review round 2), and a stranger's
/// rows stay unbelieved there as in the stored log's belief, so their gaps
/// refuse nothing and the batch does not wait for history. Green before and
/// after that change: it guards it.
#[test]
fn adopted_stranger_granting_batch_above_withheld_still_stores() {
    let served = ServedVault::self_host();
    adopt_own_checkpoint(&served);
    assert!(
        served.vault.authority_fold().is_ok(),
        "guard: the adopted vault's fold reads before the stranger batch"
    );
    let vault_id = served.vault_id();
    // Two fresh stranger roots, each self-signed above its own withheld parent.
    let mut batch = Vec::new();
    let mut withheld = Vec::new();
    for tag in [[0x51; 32], [0x52; 32]] {
        let seed = RecoveryRootSeed::generate().expect("setup: a fresh stranger root seed");
        let root = seed
            .public(&vault_id)
            .expect("setup: the stranger root's public half");
        let anchor = seed.anchor();
        withheld.push(tag);
        let record = OwnerRootRecord {
            owner: stranger_owner(),
            root: root.id,
            recovery_key: MachineEncryptionKey {
                suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
                key: root.recovery_key.to_bytes(),
            },
            anchor_key: root.anchor_key,
        };
        let entry = signed(
            vault_id,
            1,
            vec![tag],
            AuthorityOp::OwnerRoot(record),
            &anchor,
        );
        batch.push((entry, AT, 2u64));
    }
    for parent in &withheld {
        assert!(
            matches!(
                served
                    .vault
                    .authority_log_entry_status(parent)
                    .expect("setup: a withheld parent's status reads"),
                AuthorityEntryStatus::Unknown
            ),
            "setup: each withheld parent is unknown, so the batch names missing parents"
        );
    }
    // A batch that waits for history errs history-required here; this one
    // stores, since both rows are unbelieved strangers.
    let stored = served
        .vault
        .put_authority_log_entries(&batch)
        .expect("a stranger granting batch above withheld must store, not pend");
    assert_eq!(
        stored.len(),
        2,
        "setup: both stranger roots stored, so the batch reached the log"
    );
    for (entry, _, _) in &batch {
        let id = authority_log_entity_id(entry).expect("setup: the row's content id");
        assert!(
            served
                .vault
                .get_authority_log_entry(&id)
                .expect("setup: the stored row reads back")
                .is_some(),
            "setup: each stranger root is stored, so the batch reached the log"
        );
    }
    assert!(
        served.vault.authority_fold().is_ok(),
        "a stranger granting batch above withheld must leave the adopted fold reading"
    );
    assert!(
        authority_fold_settled(&served.vault).expect("the settled read"),
        "a stranger granting batch above withheld must leave peer serving settled"
    );
}

/// A stranger's machine revision C names a covered side-branch row W of a
/// world and its withheld parent Q: the adopted fold drops C above Q, and C
/// keeps the `InvalidEntry` the stored log's fold gives a row naming another
/// world's side row, never `InvalidAncestry` (#9476 review round 2). Red
/// before the fix, where every dropped row read `InvalidAncestry`.
#[test]
fn adopted_dropped_row_with_scope_fault_keeps_invalid_entry() {
    let served = ServedVault::self_host();
    let request = served.joining_machine();
    served.enrol(&request).expect("setup: the owner enrols M");
    let (anchor, root_hash) = publish_stranger_root(&served.vault);
    // W: M-signed WorldKeyWraps on a valid head, stored before adoption so the
    // image covers it as a frontier row.
    let vault_id = served.vault_id();
    let head = served
        .vault
        .authority_fold()
        .expect("setup: authority fold for W's parent")
        .valid_entries
        .iter()
        .next()
        .copied()
        .expect("setup: the vault holds a valid row for W's parent");
    let owner_person = served
        .vault
        .ensure_embedded_owner_actor()
        .expect("setup: the vault's owner person for W");
    let world = EntityId::from_bytes([0x77; 16]).expect("setup: W's world id parses");
    let machine = request.machine;
    let recipient = WrapRecipient::Machine(machine);
    let key = WorldKeyId {
        world,
        generation: 1,
        mint: [0x78; 16],
    };
    // A wrap envelope whose header names W's key, vault and recipient: W's
    // shape refuses any other bytes ("body failed validation").
    let envelope = world_key_wrap_envelope(vault_id, key, &recipient);
    let record = WorldKeyWrapsRecord {
        key,
        commitment: [0x79; 32],
        owner: owner_person,
        policy: PolicyRevision([0; 32]),
        machine,
        wraps: vec![(recipient.clone(), envelope)],
        request: None,
        permitted: vec![recipient],
    };
    let w_row = signed(
        vault_id,
        100,
        vec![head],
        AuthorityOp::WorldKeyWraps(record),
        &signing(JOINING_SEED),
    );
    let w_hash = hash(&w_row);
    deliver_via_replicated(&served.vault, &w_row)
        .expect("setup: W lands through replicated ingest");
    let w_id = authority_log_entity_id(&w_row).expect("setup: W's content-derived id");
    assert!(
        served
            .vault
            .get_authority_log_entry(&w_id)
            .expect("setup: W reads back")
            .is_some(),
        "setup: W is stored, so the side-branch parent reached the log"
    );
    adopt_own_checkpoint(&served);
    // C: the stranger's revision 2 naming W plus withheld Q (revision 1 on the
    // stranger root, never stored).
    let (withheld_hash, delivered_template) =
        strangers_gapped_revision(&served, &anchor, root_hash);
    let c_row = signed(
        vault_id,
        101,
        vec![w_hash, withheld_hash],
        delivered_template.op.clone(),
        &anchor,
    );
    let c_hash = hash(&c_row);
    deliver_via_replicated(&served.vault, &c_row).expect(
        "setup: C lands through replicated ingest (the store door does not check parent scope)",
    );
    let c_id = authority_log_entity_id(&c_row).expect("setup: C's content-derived id");
    assert!(
        served
            .vault
            .get_authority_log_entry(&c_id)
            .expect("setup: C reads back")
            .is_some(),
        "setup: C is stored, so the scoped row reached the log"
    );
    assert!(
        matches!(
            served
                .vault
                .authority_log_entry_status(&withheld_hash)
                .expect("setup: Q's status reads"),
            AuthorityEntryStatus::Unknown
        ),
        "setup: Q is withheld, so no peer holds the missing parent C names"
    );
    let fold = served
        .vault
        .authority_fold()
        .expect("setup: the fold past the adopted image reads with dropped C");
    assert!(
        fold.issues
            .contains(&AuthorityFoldIssue::InvalidEntry(c_hash)),
        "a dropped row with a parent-scope fault must keep InvalidEntry: {:?}",
        fold.issues
    );
    assert!(
        !fold
            .issues
            .contains(&AuthorityFoldIssue::InvalidAncestry(c_hash)),
        "a dropped row with a parent-scope fault must not be InvalidAncestry: {:?}",
        fold.issues
    );
}

/// The batch-belief case of #9476 review round 2 (finding 1; FIX
/// [ADOPTED-PENDING-BATCH-BELIEF-RED-TEST]). Its admin enrolment is a row the
/// host root signs above a withheld parent, which only the test door
/// `host_signed_row` builds, so this module compiles only under `--cfg
/// oneiron_test_support`.
#[cfg(oneiron_test_support)]
mod batch_enrolled_signer {
    use oneiron::authority::{
        AuthorityAttestation, AuthorityTier, DeviceAuthority, ROLE_ADMIN, ROLE_AGENT,
    };
    use oneiron::error::RecordError;
    use oneiron::test_doors::authority_adopted_fold::host_signed_row;

    use super::*;

    /// The seed of the admin key K the batch's first row enrols.
    const ADMIN_SEED: u8 = 0x61;
    /// The seed of the agent key K's row enrols.
    const AGENT_SEED: u8 = 0x62;

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

    /// One granting batch on an adopted vault: E, the host root's enrolment
    /// of an admin key K above a withheld parent Q, and C, K's enrolment of an
    /// agent key above a withheld parent X. C does not rest on E, so the
    /// pending probe folds C alone; only a belief that counts the whole batch
    /// takes K as vouched for (E enrols it), and so C's gap X as refusing. The
    /// batch errs history-required naming Q and X and stays pending: no row
    /// stored, the fold reads, and the vault's history request, whose pending
    /// part folds the pending rows as arriving rows outside any probe, names
    /// Q and X. RED with the staged batch left out of the belief (the batch
    /// stores, and the live fold refuses for Q), and RED with the arriving
    /// rows left out of it (the vault's request misses X); GREEN at main
    /// 436c6e52.
    #[test]
    fn adopted_granting_batch_with_batch_enrolled_signer_stays_pending() {
        let served = ServedVault::self_host();
        adopt_own_checkpoint(&served);
        assert!(
            served.vault.authority_fold().is_ok(),
            "setup: the adopted vault's fold reads before the batch"
        );
        let vault_id = served.vault_id();
        let withheld_q: AuthorityEntryHash = [0x5A; 32];
        let withheld_x: AuthorityEntryHash = [0x5B; 32];
        for parent in [withheld_q, withheld_x] {
            assert!(
                matches!(
                    served
                        .vault
                        .authority_log_entry_status(&parent)
                        .expect("setup: a withheld parent's status reads"),
                    AuthorityEntryStatus::Unknown
                ),
                "setup: each withheld parent is unknown, so each batch row names a missing parent"
            );
        }
        let admin = signing(ADMIN_SEED);
        let enrol_admin = host_signed_row(
            &served.issuer,
            vault_id,
            1_000,
            vec![withheld_q],
            AuthorityOp::EnrollDevice {
                device: device(key_of(&admin), ROLE_ADMIN),
            },
        )
        .expect("setup: the host root signs E");
        let enrol_agent = signed(
            vault_id,
            1,
            vec![withheld_x],
            AuthorityOp::EnrollDevice {
                device: device(key_of(&signing(AGENT_SEED)), ROLE_AGENT),
            },
            &admin,
        );
        let batch = vec![
            (enrol_admin.clone(), AT, 2u64),
            (enrol_agent.clone(), AT, 2u64),
        ];
        let put = served.vault.put_authority_log_entries(&batch);
        let Err(oneiron::Error::Record(RecordError::AuthorityHistoryRequired { missing, .. })) =
            &put
        else {
            panic!(
                "a granting batch whose every row needs history must err history-required \
                 and stay pending, not store: {put:?}"
            );
        };
        assert!(
            missing.contains(&withheld_q) && missing.contains(&withheld_x),
            "the refusal must name Q and X, the gaps E and C rest on: {missing:?}"
        );
        for row in [&enrol_admin, &enrol_agent] {
            let id = authority_log_entity_id(row).expect("the row's content id");
            assert!(
                served
                    .vault
                    .get_authority_log_entry(&id)
                    .expect("the row reads back")
                    .is_none(),
                "a pending batch row must not be stored"
            );
        }
        assert!(
            served.vault.authority_fold().is_ok(),
            "a pending granting batch must leave the adopted fold reading"
        );
        let request = served
            .vault
            .authority_missing_history()
            .expect("the history read");
        assert!(
            request.missing.contains(&withheld_q),
            "the vault's history request must name Q, E's gap: {:?}",
            request.missing
        );
        assert!(
            request.missing.contains(&withheld_x),
            "the vault's history request must name X: the pending rows' fold believes C, \
             which a key a pending row enrols signs: {:?}",
            request.missing
        );
    }
}
