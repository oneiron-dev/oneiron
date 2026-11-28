//! Two installs of one vault, for the owner-reserve tests of carried acts
//! (`authority_log_owner_reserve_carry.rs`,
//! `authority_log_owner_reserve_writers.rs`): install A, rooted with the
//! owner bound, a machine the owner admitted on A that floods, and install B,
//! which takes A's history and is flooded until its door holds a row at the
//! owner reserve.

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActSurface, AuthorityEntryHash, AuthorityKey, AuthorityLogEntry,
    AuthorityObservationPolicy, AuthorityOp, AuthoritySignature, AuthorityVaultId, HostSlipIssuer,
    MACHINE_ENCRYPTION_KEY_LEN, MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineDeviceClass,
    MachineEncryptionKey, MachineEnrolmentRequest, MachineOwnership, MachineRole, OwnerAct,
    OwnerActKind, WorldPrivacy, WorldPrivacyEdit, authority_entry_hash, authority_transcript,
    decode_authority_log_entry_body, machine_profile_proof_transcript,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, ErrorKind, TimeRange, Vault, VaultConfig};

/// The test's memory floor on B, 4 MiB: A's history folds well under it
/// (asserted), and about ninety chained rows pass it, as in
/// `authority_log_owner_reserve.rs`.
pub(crate) const FLOOR_BYTES: u64 = 4 * 1024 * 1024;

/// The most flood rows a test signs before it gives up.
pub(crate) const FLOOD_CAP: u64 = 400;

pub(crate) const AT: TimeRange = TimeRange { start: 1, end: 1 };

/// Install A: a rooted vault as a host starts one, the owner bound under the
/// host root and this install profiled, so it carries the owner's answers.
pub(crate) struct Rooted {
    _dir: tempfile::TempDir,
    pub(crate) vault: Vault,
    pub(crate) owner: EntityId,
    pub(crate) proof: AuthenticatedOwner,
    pub(crate) vault_id: AuthorityVaultId,
}

pub(crate) fn rooted() -> Rooted {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("install A");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer: HostSlipIssuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("install A's live machine profile");
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

/// A holds the test host's root as a self-host server holds its own, so
/// `Vault::owner_proof_signer` offers it as the owner key's proof.
pub(crate) fn hold_owner_key(rooted: &Rooted) {
    rooted
        .vault
        .hold_checkpoint_root_signer(Arc::new(oneiron::test_support::test_host_issuer()));
}

/// A machine the owner admitted on A, whose install key the test holds: no
/// owner key, no slip issuer, and neither A's key nor B's.
pub(crate) struct Flooder {
    pub(crate) machine: EntityId,
    pub(crate) signing: SigningKey,
    /// The entry that carried its admission: the flood chain's first parent.
    pub(crate) admission: AuthorityEntryHash,
}

pub(crate) fn admit_flooder(rooted: &Rooted) -> Flooder {
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
        restored_from: None,
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
        .expect("the owner admits the machine")
        .into_standing()
        .expect("the owner's admission stands");
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

/// The flooder's own edit of `world` at `seq` on `parent`, signed by its install
/// key: an op that key vouches for, so a door lands it as it lands any
/// vouched key's row. The world need not exist for the door.
pub(crate) fn flood_row(
    rooted: &Rooted,
    flooder: &Flooder,
    world: EntityId,
    seq: u64,
    parent: AuthorityEntryHash,
) -> AuthorityLogEntry {
    let op = AuthorityOp::WorldPrivacy(WorldPrivacyEdit {
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
    });
    let key = AuthorityKey::Ed25519(flooder.signing.verifying_key().to_bytes());
    let overlay_seed = oneiron_authority::authority::authority_overlay_seed_for(&op)
        .expect("authority overlay seed");
    let mut entry = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(rooted.vault_id),
        seq,
        parent_hashes: vec![parent],
        op,
        overlay_seed,
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

pub(crate) fn stored_history(vault: &Vault) -> Vec<Vec<u8>> {
    vault
        .export_signed_authority_history()
        .expect("the install's history")
}

/// Install B: a second install of A's vault. It has its own directory and
/// keystore, so its own install key, and it takes A's history as sync does.
pub(crate) struct Second {
    _dir: tempfile::TempDir,
    pub(crate) vault: Vault,
    /// The history B took from A.
    pub(crate) taken: Vec<Vec<u8>>,
}

/// B takes A's history, sets its memory floor, and the flooder signs one
/// chain on its admission at B until B's door holds a row at the owner
/// reserve. A row past B's floor, or the cap with no row held, fails the
/// fixture.
pub(crate) fn second_install_at_its_reserve(rooted: &Rooted, flooder: &Flooder) -> Second {
    second_install_at_its_reserve_from(rooted, flooder, (flooder.admission, 1))
}

/// [`second_install_at_its_reserve`] with the flood chain signed on `parent`
/// from sequence `first_seq` on: a test that put the flooder's own rows on A
/// before B took its history floods B past them.
pub(crate) fn second_install_at_its_reserve_from(
    rooted: &Rooted,
    flooder: &Flooder,
    (parent, first_seq): (AuthorityEntryHash, u64),
) -> Second {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("install B");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let taken = stored_history(&rooted.vault);
    vault
        .import_signed_authority_history(&taken, &std::collections::BTreeMap::new())
        .expect("B takes A's history");
    assert_eq!(
        vault.authority_vault_id().expect("B's fold"),
        Some(rooted.vault_id),
        "B holds A's vault"
    );
    vault
        .set_authority_observation_policy(AuthorityObservationPolicy {
            log_fold_memory_floor_bytes: Some(FLOOR_BYTES),
            ..AuthorityObservationPolicy::default()
        })
        .expect("B's floor");
    let fold = vault.authority_fold().expect("B's fold");
    assert!(
        !fold.authority_log_past_bound() && !fold.vault_root_is_conflicted(),
        "A's history folds at B under the test's floor"
    );
    let world = EntityId::now();
    let mut parent = parent;
    for landed in 0..FLOOD_CAP {
        let row = flood_row(rooted, flooder, world, first_seq + landed, parent);
        match vault.put_authority_log_entry(&row, AT, 1) {
            Ok(_) => parent = authority_entry_hash(&row).expect("hash"),
            Err(error) if error.kind() == ErrorKind::AuthorityLogFull => {
                assert!(landed > 0, "rows under B's owner reserve land as before");
                return Second {
                    _dir: dir,
                    vault,
                    taken,
                };
            }
            Err(error) => panic!("flood row {landed} was refused at B, not held: {error}"),
        }
        assert!(
            !vault
                .authority_fold()
                .expect("B's fold")
                .authority_log_past_bound(),
            "after {landed} flood rows B's fold passed its floor with no row held at its reserve"
        );
    }
    panic!("{FLOOD_CAP} flood rows landed at B and none waited at its owner reserve");
}

/// The rows A stored since B took its history, decoded with their hashes.
pub(crate) fn written_since(rooted: &Rooted, second: &Second) -> Vec<(Vec<u8>, AuthorityLogEntry)> {
    stored_history(&rooted.vault)
        .into_iter()
        .filter(|row| !second.taken.contains(row))
        .map(|row| {
            let entry = decode_authority_log_entry_body(&row).expect("A's row");
            (row, entry)
        })
        .collect()
}

/// A's one row since B took its history that carries `wanted`.
pub(crate) fn the_row_a_wrote(
    rooted: &Rooted,
    second: &Second,
    wanted: impl Fn(&AuthorityOp) -> bool,
) -> (Vec<Vec<u8>>, AuthorityLogEntry, AuthorityEntryHash) {
    let written = written_since(rooted, second);
    let rows: Vec<Vec<u8>> = written.iter().map(|(row, _)| row.clone()).collect();
    let mut matching = written.into_iter().filter(|(_, entry)| wanted(&entry.op));
    let (_, entry) = matching.next().expect("A signed the act");
    assert!(matching.next().is_none(), "A signed the act once");
    let hash = authority_entry_hash(&entry).expect("hash");
    (rows, entry, hash)
}

pub(crate) fn removes(op: &AuthorityOp, machine: EntityId) -> bool {
    matches!(op, AuthorityOp::MachineProfile(profile)
        if profile.machine == machine && profile.role == MachineRole::Removed)
}

/// The heads of A's history: every row no other row names as a parent.
pub(crate) fn heads_of_a(rooted: &Rooted) -> Vec<AuthorityEntryHash> {
    let rows: Vec<AuthorityLogEntry> = stored_history(&rooted.vault)
        .iter()
        .map(|body| decode_authority_log_entry_body(body).expect("a stored row"))
        .collect();
    let named: Vec<AuthorityEntryHash> = rows
        .iter()
        .flat_map(|row| row.parent_hashes.iter().copied())
        .collect();
    let mut heads: Vec<AuthorityEntryHash> = rows
        .iter()
        .map(|row| authority_entry_hash(row).expect("hash"))
        .filter(|hash| !named.contains(hash))
        .collect();
    heads.sort_unstable();
    heads
}
