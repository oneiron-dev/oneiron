//! FIX [OWNER-RESERVE-CROSS-INSTALL-CARRY]: past its owner reserve, an
//! install lands only the owner's work (`authority/log_budget.rs`
//! `owner_work`): a row a slip issuer signs or cosigns, a row an anchor this
//! install takes as its own signs, and the owner's will this install
//! carries, which it reads by its own install key. An owner act install A
//! carries reaches install B of the same vault signed by A's install key, so
//! at B it is not B's will. Since row CARRIER-OWNER-PROOF, A signs a machine
//! answer and a policy-setting act with the proof of an owner key it holds
//! beside its own signature, and that cosign is a live owner's: B lands the
//! act past its reserve. An act A carries with no owner key held waits at
//! B, as any row that is not the owner's work.
//!
//! Each test takes A's history to a second install B (its own directory and
//! keystore, so its own install key), sets B's memory floor, and floods B
//! with an admitted machine's rows until B's door holds one at the reserve.
//! A then acts, and B imports what A wrote.
//!
//! Red at the head with the owner key's proof dropped from both writers
//! (`machine_answers.rs` `append_owner_answer_ending_keys_in_txn` and
//! `carried_act.rs` `append_carried_act_in_txn` sign with no proof): B's
//! import of A's removal refuses with `AuthorityLogFull`, and A's setting act
//! either is not counted at A or waits at B. The third test passes there too:
//! it shows the act A carries unproven waits at B.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test authority_log_owner_reserve_carry`.

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
use oneiron::settings::undo_send::UndoSendSetting;
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, ErrorKind, TimeRange, Vault, VaultConfig};

/// The test's memory floor on B, 4 MiB: A's history folds well under it
/// (asserted), and about ninety chained rows pass it, as in
/// `authority_log_owner_reserve.rs`.
const FLOOR_BYTES: u64 = 4 * 1024 * 1024;

/// The most flood rows a test signs before it gives up.
const FLOOD_CAP: u64 = 400;

const AT: TimeRange = TimeRange { start: 1, end: 1 };

/// Install A: a rooted vault as a host starts one, the owner bound under the
/// host root and this install profiled, so it carries the owner's answers.
struct Rooted {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    proof: AuthenticatedOwner,
    vault_id: AuthorityVaultId,
}

fn rooted() -> Rooted {
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
fn hold_owner_key(rooted: &Rooted) {
    rooted
        .vault
        .hold_checkpoint_root_signer(Arc::new(oneiron::test_support::test_host_issuer()));
}

/// A machine the owner admitted on A, whose install key the test holds: no
/// owner key, no slip issuer, and neither A's key nor B's.
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
fn flood_row(
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
    let mut entry = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(rooted.vault_id),
        seq,
        parent_hashes: vec![parent],
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
    entry.signer.signature = flooder.signing.sign(&transcript).to_bytes().to_vec();
    entry
}

fn stored_history(vault: &Vault) -> Vec<Vec<u8>> {
    vault
        .export_signed_authority_history()
        .expect("the install's history")
}

/// Install B: a second install of A's vault. It has its own directory and
/// keystore, so its own install key, and it takes A's history as sync does.
struct Second {
    _dir: tempfile::TempDir,
    vault: Vault,
    /// The history B took from A.
    taken: Vec<Vec<u8>>,
}

/// B takes A's history, sets its memory floor, and the flooder signs one
/// chain on its admission at B until B's door holds a row at the owner
/// reserve. A row past B's floor, or the cap with no row held, fails the
/// fixture.
fn second_install_at_its_reserve(rooted: &Rooted, flooder: &Flooder) -> Second {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("install B");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let taken = stored_history(&rooted.vault);
    vault
        .import_signed_authority_history(&taken)
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
    let mut parent = flooder.admission;
    for landed in 0..FLOOD_CAP {
        let row = flood_row(rooted, flooder, world, landed + 1, parent);
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
fn written_since(rooted: &Rooted, second: &Second) -> Vec<(Vec<u8>, AuthorityLogEntry)> {
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
fn the_row_a_wrote(
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

fn removes(op: &AuthorityOp, machine: EntityId) -> bool {
    matches!(op, AuthorityOp::MachineProfile(profile)
        if profile.machine == machine && profile.role == MachineRole::Removed)
}

/// The owner removes the flooding machine on A, where A holds an owner key.
/// A signs the removal under its install key with the owner key's proof
/// beside it, and B, past its owner reserve, lands it: the flooder reads
/// removed at B too, and B's fold stays under its floor.
#[test]
fn the_owners_removal_another_install_proves_lands_past_this_installs_reserve() {
    let rooted = rooted();
    hold_owner_key(&rooted);
    let flooder = admit_flooder(&rooted);
    let second = second_install_at_its_reserve(&rooted, &flooder);
    rooted
        .vault
        .set_machine_role(
            &rooted.proof,
            ActSurface::ThisInstall,
            flooder.machine,
            MachineRole::Removed,
            None,
        )
        .expect("the owner removes the flooding machine on A")
        .into_standing()
        .expect("the owner's removal stands at A");
    let (rows, entry, hash) = the_row_a_wrote(&rooted, &second, |op| removes(op, flooder.machine));
    second
        .vault
        .import_signed_authority_history(&rows)
        .expect("B lands the removal A carries with the owner key's proof past its reserve");
    let fold = second.vault.authority_fold().expect("B's fold");
    assert!(
        fold.valid_entries.contains(&hash),
        "B's fold counts the removal"
    );
    assert!(
        fold.machine(flooder.machine).is_some_and(|machine| machine
            .chains()
            .any(|(_, head)| head.entry == hash && head.removed)),
        "B reads the flooding machine removed by A's removal"
    );
    assert!(
        !fold.authority_log_past_bound() && !fold.vault_root_is_conflicted(),
        "B's fold stays under its floor and its root stands"
    );
    assert_eq!(
        entry.cosigns.len(),
        1,
        "A signed the removal with one owner key's proof beside its install key"
    );
    assert_ne!(
        entry.cosigns[0].public_key, entry.signer.public_key,
        "the proof is not A's install key"
    );
}

/// The same removal from an A that holds no owner key: A carries it under
/// its install key alone, so at B it is neither an issuer's row nor B's own
/// will, and it waits at B's door (`AuthorityLogFull`, retryable). The
/// flooder stays admitted at B until the owner proves the act or raises
/// B's floor.
#[test]
fn the_owners_removal_another_install_carries_unproven_waits_past_this_installs_reserve() {
    let rooted = rooted();
    let flooder = admit_flooder(&rooted);
    let second = second_install_at_its_reserve(&rooted, &flooder);
    rooted
        .vault
        .set_machine_role(
            &rooted.proof,
            ActSurface::ThisInstall,
            flooder.machine,
            MachineRole::Removed,
            None,
        )
        .expect("the owner removes the flooding machine on A")
        .into_standing()
        .expect("the owner's removal stands at A");
    let (rows, entry, hash) = the_row_a_wrote(&rooted, &second, |op| removes(op, flooder.machine));
    assert!(
        entry.cosigns.is_empty(),
        "A holds no owner key, so it carries the removal unproven"
    );
    let import = second.vault.import_signed_authority_history(&rows);
    assert!(
        import
            .as_ref()
            .is_err_and(|error| error.kind() == ErrorKind::AuthorityLogFull),
        "B's door holds the unproven removal at its reserve: {import:?}"
    );
    let fold = second.vault.authority_fold().expect("B's fold");
    assert!(!fold.valid_entries.contains(&hash), "B does not count it");
    assert!(
        fold.machine(flooder.machine)
            .is_some_and(|machine| !machine.chains().any(|(_, head)| head.removed)),
        "the flooding machine stays admitted at B"
    );
}

/// A policy-setting act A carries for the owner, with the proof of the owner
/// key A holds: the other writer that attaches the proof
/// (`carried_act.rs`). B, past its owner reserve, lands it, and the act is
/// in force there, not waiting for the owner.
#[test]
fn the_owners_setting_another_install_proves_lands_past_this_installs_reserve() {
    let rooted = rooted();
    hold_owner_key(&rooted);
    let here = rooted
        .vault
        .local_machine()
        .expect("install A")
        .expect("install A's machine")
        .id;
    rooted
        .vault
        .set_machine_role(
            &rooted.proof,
            ActSurface::ThisInstall,
            here,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("the owner marks install A yours")
        .into_standing()
        .expect("the owner's answer stands");
    let flooder = admit_flooder(&rooted);
    let second = second_install_at_its_reserve(&rooted, &flooder);
    rooted
        .vault
        .set_undo_send(
            &rooted.proof,
            Some(ActSurface::ThisInstall),
            &UndoSendSetting {
                all_channels_secs: 30,
                channels: Vec::new(),
            },
        )
        .expect("the owner sets the undo-send window on A");
    let (rows, entry, hash) = the_row_a_wrote(&rooted, &second, |op| {
        matches!(op, AuthorityOp::PolicySettingSet(_))
    });
    second
        .vault
        .import_signed_authority_history(&rows)
        .expect("B lands the setting act A carries with the owner key's proof past its reserve");
    let fold = second.vault.authority_fold().expect("B's fold");
    assert!(
        fold.valid_entries.contains(&hash),
        "B's fold counts the setting act"
    );
    assert!(
        !fold.waiting_owner_choices().contains(&hash),
        "the setting act is in force at B, not waiting for the owner"
    );
    assert!(
        !fold.authority_log_past_bound() && !fold.vault_root_is_conflicted(),
        "B's fold stays under its floor and its root stands"
    );
    assert_eq!(
        entry.cosigns.len(),
        1,
        "A signed the setting act with one owner key's proof beside its install key"
    );
}
