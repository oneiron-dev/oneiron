//! FIX [AUTHORITY-LOG-SIGNER-FLOOD] (Astra F10, Fable pass 15e): a key a slip
//! issuer's consent vouches for stores past its signer bound, because the
//! count only asks (FIX 8564, 8876). So one admitted machine that keeps
//! signing grows the authority log until the fold's projected peak passes the
//! `authority_log_fold_memory_floor` row. That fold holds no root, every
//! authority gate refuses it, and the owner's removal of the machine cannot
//! fold either: the vault's authority stays down.
//!
//! Now the store door keeps an owner reserve under the memory floor. Once the
//! log's projected fold peak would pass the floor less the reserve, a row that
//! is not the owner's work waits at the door (`AuthorityLogFull`; a replica
//! retries it on every drain, never refused), while the owner's work still
//! lands: a row a slip issuer signs or cosigns, and the owner's will this
//! install carries. The log stays under its floor, the owner removes the
//! machine, and a waiting row lands once the owner raises the floor.
//!
//! Red on main: both tests (every flood row lands, the fold passes its floor,
//! and the removal errors).
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test authority_log_owner_reserve`.

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActSurface, AuthorityEntryHash, AuthorityKey, AuthorityLogEntry,
    AuthorityObservationPolicy, AuthorityOp, AuthoritySignature, AuthorityVaultId,
    MACHINE_ENCRYPTION_KEY_LEN, MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineDeviceClass,
    MachineEncryptionKey, MachineEnrolmentRequest, MachineOwnership, MachineRole, OwnerAct,
    OwnerActKind, WorldPrivacy, WorldPrivacyEdit, authority_entry_hash, authority_transcript,
    machine_profile_proof_transcript,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, ErrorKind, TimeRange, Vault, VaultConfig};

/// The test's memory floor, 4 MiB: the fixture's own log folds well under it
/// (asserted), and about ninety chained rows pass it, since a fold projects
/// 16 KiB a row and 640 bytes an ancestor pair (`authority/log_budget.rs`).
/// Its reserve then holds several of the owner's rows, each with the whole
/// log among its ancestors.
const FLOOR_BYTES: u64 = 4 * 1024 * 1024;

/// The most flood rows a test signs before it gives up.
const FLOOD_CAP: u64 = 400;

const AT: TimeRange = TimeRange { start: 1, end: 1 };

/// The kind of the typed check that names a log at its owner reserve.
const OWNER_RESERVE_CHECK: &str = "authority_log_owner_reserve";

/// A rooted vault as a host starts one: the owner bound under the host root
/// and this install profiled, so it carries the owner's answers.
struct Rooted {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    proof: AuthenticatedOwner,
    vault_id: AuthorityVaultId,
}

fn rooted() -> Rooted {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the install");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof");
    let vault_id = vault
        .authority_vault_id()
        .expect("the fold")
        .expect("a rooted vault");
    Rooted {
        _dir: dir,
        vault,
        owner,
        proof,
        vault_id,
    }
}

/// A machine the owner admitted, whose install key the test holds: no owner
/// key, no slip issuer, and not this install's key.
struct Flooder {
    machine: EntityId,
    signing: SigningKey,
    /// The entry that carried its admission: the flood chain's first parent.
    admission: AuthorityEntryHash,
}

fn admit_flooder(rooted: &Rooted) -> Flooder {
    let signing = SigningKey::from_bytes(&[0xF1; 32]);
    let machine = EntityId::now();
    let machine_key = signing.verifying_key().to_bytes();
    let encryption_key = MachineEncryptionKey {
        suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
        key: vec![7; MACHINE_ENCRYPTION_KEY_LEN],
    };
    let machine_proof = signing
        .sign(&machine_profile_proof_transcript(
            &rooted.vault_id,
            machine,
            &machine_key,
            MachineDeviceClass::Computer,
            &encryption_key,
        ))
        .to_bytes();
    let request = MachineEnrolmentRequest {
        vault_id: rooted.vault_id,
        machine,
        machine_key,
        device_class: MachineDeviceClass::Computer,
        encryption_key,
        machine_proof,
    };
    let folded = rooted
        .vault
        .enroll_machine(
            &rooted.proof,
            ActSurface::ThisInstall,
            &request,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("the owner admits the machine");
    assert!(folded.is_mine(None), "the admitted machine is the owner's");
    let admission = folded
        .chains()
        .map(|(_, head)| head)
        .max_by_key(|head| head.profile.revision)
        .expect("the admission's revision")
        .entry;
    Flooder {
        machine,
        signing,
        admission,
    }
}

/// The flooder's own world edit at `seq` on `parent`: an op its install key
/// vouches for, so the door lands it as it lands any vouched key's row. The
/// world need not exist for the door.
fn flood_row(
    rooted: &Rooted,
    flooder: &Flooder,
    world: EntityId,
    seq: u64,
    parent: AuthorityEntryHash,
) -> AuthorityLogEntry {
    let key = AuthorityKey::Ed25519(flooder.signing.verifying_key().to_bytes());
    let mut entry = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(rooted.vault_id),
        seq,
        parent_hashes: vec![parent],
        op: AuthorityOp::WorldPrivacy(WorldPrivacyEdit {
            world,
            act: OwnerAct::by_owner(
                rooted.owner,
                OwnerActKind::WorldPrivacy,
                world,
                ActSurface::ThisInstall,
                [0; 32],
            ),
            machine: flooder.machine,
            settings: WorldPrivacy::default(),
        }),
        signer: AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: seq + 1,
    };
    let transcript = authority_transcript(&entry).expect("transcript");
    entry.signer.signature = flooder.signing.sign(&transcript).to_bytes().to_vec();
    entry
}

fn set_floor(vault: &Vault, floor_bytes: u64) {
    vault
        .set_authority_observation_policy(AuthorityObservationPolicy {
            log_fold_memory_floor_bytes: Some(floor_bytes),
            ..AuthorityObservationPolicy::default()
        })
        .expect("the floor row");
}

/// How a flood ended.
#[derive(Debug)]
enum FloodEnd {
    /// The door held this row: the log reached its owner reserve.
    Waited(Box<AuthorityLogEntry>),
    /// Every row landed and the fold passed its memory floor.
    PastFloor,
    /// Every row landed, and the fold stayed under its floor.
    Cap,
}

/// The flooder signs one chain until the door holds a row, the fold passes
/// its floor, or [`FLOOD_CAP`] rows landed. Returns the rows that landed.
fn flood(rooted: &Rooted, flooder: &Flooder) -> (u64, FloodEnd) {
    let world = EntityId::now();
    let mut parent = flooder.admission;
    for seq in 1..=FLOOD_CAP {
        let row = flood_row(rooted, flooder, world, seq, parent);
        match rooted.vault.put_authority_log_entry(&row, AT, 1) {
            Ok(_) => parent = authority_entry_hash(&row).expect("hash"),
            Err(error) if error.kind() == ErrorKind::AuthorityLogFull => {
                return (seq - 1, FloodEnd::Waited(Box::new(row)));
            }
            Err(error) => panic!("flood row {seq} was refused, not held: {error}"),
        }
        if rooted
            .vault
            .authority_fold()
            .expect("the fold")
            .authority_log_past_bound()
        {
            return (seq, FloodEnd::PastFloor);
        }
    }
    (FLOOD_CAP, FloodEnd::Cap)
}

fn floored_vault_with_flooder() -> (Rooted, Flooder) {
    let rooted = rooted();
    let flooder = admit_flooder(&rooted);
    set_floor(&rooted.vault, FLOOR_BYTES);
    let fold = rooted.vault.authority_fold().expect("the fold");
    assert!(
        !fold.authority_log_past_bound() && !fold.vault_root_is_conflicted(),
        "the fixture's own log folds under the test's floor"
    );
    (rooted, flooder)
}

#[test]
fn an_admitted_machines_flood_waits_under_the_floor_and_the_owner_removes_it() {
    let (rooted, flooder) = floored_vault_with_flooder();
    let (landed, end) = flood(&rooted, &flooder);
    assert!(landed > 0, "rows under the owner reserve land as before");
    let removal = rooted.vault.set_machine_role(
        &rooted.proof,
        ActSurface::ThisInstall,
        flooder.machine,
        MachineRole::Removed,
        None,
    );
    let fold = rooted.vault.authority_fold().expect("the fold");
    assert!(
        !fold.authority_log_past_bound(),
        "after {landed} flood rows ({end:?}) the fold passes its memory floor, so every \
         authority gate refuses it (the removal: {removal:?})"
    );
    let removed = removal.expect("the owner removes the flooding machine");
    assert!(
        !removed.is_mine(None),
        "the removed machine is no longer the owner's"
    );
    assert!(!fold.vault_root_is_conflicted(), "the vault's root stands");
    assert!(
        fold.machine(flooder.machine)
            .is_some_and(|machine| machine.chains().any(|(_, head)| head.removed)),
        "the fold reads the machine removed"
    );
    let FloodEnd::Waited(held) = end else {
        panic!("the flood ended {end:?}, not held at the door");
    };
    let retry = rooted.vault.put_authority_log_entry(&held, AT, 1);
    assert!(
        retry.is_err(),
        "the removed machine's held row still does not land: {retry:?}"
    );
    assert!(
        !rooted
            .vault
            .authority_fold()
            .expect("the fold")
            .authority_log_past_bound(),
        "the fold stays under its floor"
    );
}

#[test]
fn a_row_held_at_the_owner_reserve_lands_once_the_owner_raises_the_floor() {
    let (rooted, flooder) = floored_vault_with_flooder();
    let (landed, end) = flood(&rooted, &flooder);
    let FloodEnd::Waited(held) = end else {
        panic!(
            "after {landed} flood rows the flood ended {end:?}: no row waited at the owner \
             reserve"
        );
    };
    let checks = rooted.vault.authority_log_checks().expect("the checks");
    let reserve = checks
        .iter()
        .find(|check| check.kind == OWNER_RESERVE_CHECK)
        .unwrap_or_else(|| panic!("no check names the owner reserve: {checks:?}"));
    assert!(
        reserve.threshold < FLOOR_BYTES && reserve.count > reserve.threshold,
        "the check names the projection past the reserve under the floor: {reserve:?}"
    );
    set_floor(&rooted.vault, 4 * FLOOR_BYTES);
    rooted
        .vault
        .put_authority_log_entry(&held, AT, 1)
        .expect("the held row lands under the raised floor");
    let fold = rooted.vault.authority_fold().expect("the fold");
    assert!(!fold.authority_log_past_bound() && !fold.vault_root_is_conflicted());
    assert!(
        rooted
            .vault
            .authority_log_checks()
            .expect("the checks")
            .iter()
            .all(|check| check.kind != OWNER_RESERVE_CHECK),
        "raising the floor clears the owner reserve's check"
    );
}
