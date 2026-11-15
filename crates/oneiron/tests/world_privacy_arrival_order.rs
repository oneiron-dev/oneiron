//! One log folds to the same world settings on every install, whatever order
//! its rows arrive in ([SEQUENCE-FLOOR-DELIVERY-ORDER], root FIX-LIST;
//! Engine RULING SEQ-FLOOR-SHAPE = A, 15 Nov 16:37).
//!
//! A row's sequence floor is the highest sequence among its signer's rows in
//! its scope that do not descend from it, and a world edit below its floor
//! lands as restriction only (Astra #1430). Before, the floor was the highest
//! sequence the install had received from the signer before the row
//! arrived. One machine key that forks its own sequence, signing a later row
//! that does not descend from its earlier world edits, so left two installs
//! holding the same rows with different settings: the install that received
//! the edits first counted the widening, and the install that received the
//! later row first held it to the narrowing it replaced.

use std::collections::BTreeSet;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActSurface, AuthorityAttestation, AuthorityEntryHash,
    AuthorityFold, AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature, AuthorityTier,
    AuthorityVaultId, DeviceAuthority, EffectiveRead, GenesisRecoveryStep,
    MACHINE_ENCRYPTION_KEY_LEN, MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineDeviceClass,
    MachineEncryptionKey, MachineOwnership, MachineProfile, MachineRole, OwnerAct, OwnerActKind,
    ROLE_ADMIN, ROLE_OWNER, ReadLocation, WorldPrivacy, WorldPrivacyEdit, authority_entry_hash,
    authority_transcript, genesis_vault_id, machine_profile_proof_transcript,
};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

const AT: TimeRange = TimeRange { start: 2, end: 2 };

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

fn signed(
    vault_id: Option<AuthorityVaultId>,
    seq: u64,
    parent: Option<&AuthorityLogEntry>,
    op: AuthorityOp,
    signer: &SigningKey,
) -> AuthorityLogEntry {
    let key = key_of(signer);
    let mut entry = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id,
        seq,
        parent_hashes: parent
            .map(|parent| vec![authority_entry_hash(parent).expect("parent hash")])
            .unwrap_or_default(),
        op,
        signer: AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: seq + 1,
    };
    let transcript = authority_transcript(&entry).expect("transcript");
    entry.signer.signature = signer.sign(&transcript).to_bytes().to_vec();
    entry
}

/// The owner's genesis and the vault it founds.
fn genesis(owner: &SigningKey, nonce: u8) -> (AuthorityLogEntry, AuthorityVaultId) {
    let genesis = signed(
        None,
        0,
        None,
        AuthorityOp::Genesis {
            device: device(key_of(owner), ROLE_OWNER | ROLE_ADMIN),
            genesis_nonce: [nonce; 32],
            recovery: GenesisRecoveryStep::Saved([1; 32]),
        },
        owner,
    );
    let vault_id = genesis_vault_id(&genesis).expect("vault id");
    (genesis, vault_id)
}

/// The owner's "yours" mark of `machine`, whose install key is
/// `machine_key`: its first revision, signed by an owner roster key with no
/// carrier, as a roster revision is.
fn yours_mark(
    vault_id: AuthorityVaultId,
    machine: EntityId,
    machine_key: &SigningKey,
) -> AuthorityOp {
    let machine_key_bytes = machine_key.verifying_key().to_bytes();
    let device_class = MachineDeviceClass::Computer;
    let encryption_key = MachineEncryptionKey {
        suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
        key: vec![7; MACHINE_ENCRYPTION_KEY_LEN],
    };
    let machine_proof = machine_key
        .sign(&machine_profile_proof_transcript(
            &vault_id,
            machine,
            &machine_key_bytes,
            device_class,
            &encryption_key,
        ))
        .to_bytes();
    AuthorityOp::MachineProfile(MachineProfile {
        machine,
        owner: EntityId::now(),
        machine_key: machine_key_bytes,
        device_class,
        encryption_key,
        role: MachineRole::Owned(MachineOwnership::Yours),
        revision: 1,
        machine_proof,
        seen_world_edits: BTreeSet::new(),
        carrier: None,
        act: None,
    })
}

/// The owner's edit of `world` to `read`, which `machine` carries under its
/// install key. An owner the log binds nowhere is taken on the carrier's
/// word, and an owner's edit names no settings revision the fold checks.
fn world_edit(
    world: EntityId,
    machine: EntityId,
    owner: EntityId,
    read: ReadLocation,
) -> AuthorityOp {
    AuthorityOp::WorldPrivacy(WorldPrivacyEdit {
        world,
        act: OwnerAct::by_owner(
            owner,
            OwnerActKind::WorldPrivacy,
            world,
            ActSurface::ThisInstall,
            [0; 32],
        ),
        machine,
        settings: WorldPrivacy {
            read,
            ..WorldPrivacy::default()
        },
    })
}

fn hash_of(entry: &AuthorityLogEntry) -> AuthorityEntryHash {
    authority_entry_hash(entry).expect("row hash")
}

/// One install: a fresh vault that receives `rows` one at a time, in the
/// order given, each through the authority write door on its own, as rows
/// that sync delivers in that order arrive. Returns each put's outcome and
/// the install's fold.
struct Install {
    _dir: tempfile::TempDir,
    puts: Vec<String>,
    fold: AuthorityFold,
}

fn install_receiving(rows: &[&AuthorityLogEntry]) -> Install {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    let puts = rows
        .iter()
        .map(|row| match vault.put_authority_log_entry(row, AT, 2) {
            Ok(_) => "stored".to_owned(),
            Err(error) => format!("refused: {:?}", error.kind()),
        })
        .collect();
    let fold = vault.authority_fold().expect("the install folds its log");
    Install {
        _dir: dir,
        puts,
        fold,
    }
}

fn applied(fold: &AuthorityFold) -> BTreeSet<AuthorityEntryHash> {
    fold.valid_entries.iter().copied().collect()
}

/// The finding's case. Machine M, marked "yours" by the owner, carries the
/// owner's edits under its install key K: a narrowing of world 1 to the
/// owner's machines (sequence 1), then a widening of world 1 back to
/// everywhere on it (2), then an edit of world 2 on the mark alone (3),
/// which names neither world-1 edit. Install I receives the rows in that
/// order, install J receives the world-2 edit before both world-1 edits.
/// Both installs hold the same rows, so both must read world 1 the same.
/// The world-2 edit forks K's sequence below it, so both read world 1 as the
/// install that received the fork first does: the widening lands as
/// restriction only, held to the narrowing it replaced.
#[test]
fn a_forked_signers_world_edits_read_the_same_on_every_install() {
    let owner = SigningKey::from_bytes(&[231; 32]);
    let machine_key = SigningKey::from_bytes(&[232; 32]);
    let (genesis, vault_id) = genesis(&owner, 233);
    let machine = EntityId::now();
    let person = EntityId::now();
    let first_world = EntityId::now();
    let second_world = EntityId::now();
    let mark = signed(
        Some(vault_id),
        1,
        Some(&genesis),
        yours_mark(vault_id, machine, &machine_key),
        &owner,
    );
    let narrowing = signed(
        Some(vault_id),
        1,
        Some(&mark),
        world_edit(first_world, machine, person, ReadLocation::MyMachines),
        &machine_key,
    );
    let widening = signed(
        Some(vault_id),
        2,
        Some(&narrowing),
        world_edit(first_world, machine, person, ReadLocation::Everywhere),
        &machine_key,
    );
    let fork = signed(
        Some(vault_id),
        3,
        Some(&mark),
        world_edit(second_world, machine, person, ReadLocation::MyMachines),
        &machine_key,
    );

    let in_order = install_receiving(&[&genesis, &mark, &narrowing, &widening, &fork]);
    let fork_first = install_receiving(&[&genesis, &mark, &fork, &narrowing, &widening]);

    let all = [&genesis, &mark, &narrowing, &widening, &fork]
        .into_iter()
        .map(hash_of)
        .collect::<BTreeSet<_>>();
    for (name, install) in [("I (in order)", &in_order), ("J (fork first)", &fork_first)] {
        assert_eq!(
            applied(&install.fold),
            all,
            "install {name} holds every row as valid; puts {:?}, issues {:?}",
            install.puts,
            install.fold.issues
        );
        assert_eq!(
            install.fold.world_privacy(second_world).read,
            EffectiveRead::MyMachines,
            "install {name} counts the world-2 edit, which no row of its signer forks"
        );
    }
    let read_in_order = in_order.fold.world_privacy(first_world).read;
    let read_fork_first = fork_first.fold.world_privacy(first_world).read;
    assert_eq!(
        read_in_order, read_fork_first,
        "installs I and J hold the same rows, so they must read world 1 the same; \
         I reads {read_in_order:?}, J reads {read_fork_first:?}"
    );
    assert_eq!(
        read_in_order,
        EffectiveRead::MyMachines,
        "the world-2 edit forks K's sequence below the world-1 edits, so the widening \
         is held to the narrowing it replaced on every install"
    );
}
