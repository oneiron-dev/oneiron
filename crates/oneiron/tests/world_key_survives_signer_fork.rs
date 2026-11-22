//! T5 (Astra anchorsec-seq-floor-s): one row a removed machine's key signs on an old parent must not take its world's key from every install.
//! The removed install mints the world's first key, the standing install wraps the same key, the owner removes the minter, then the minter's key signs a fork on an old parent that floors its mint.
//! Red 23e0a2679c03 refuses the floored mint as NonMonotonicSeq and loses the key; green 00dfd0c99ed3 counts the mint and records SequenceFork.
//! FIX [SEQ-FLOOR-S-ADOPTED-FORK-NEEDS-HISTORY] and [ADOPTED-FOLD-GATE-TEST]: a cold install that adopted an image of every row but the fork folds the fork past it, and its answer is the whole fold's.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test world_key_survives_signer_fork`.

#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{
    ActSurface, AuthorityEntryHash, AuthorityFoldIssue, AuthorityLogEntry, AuthorityOp,
    MachineOwnership, MachineRole, ReadLocation, WorldKeyWrapsRecord, WorldPrivacy,
    authority_entry_hash, decode_authority_log_entry_body,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::registry::ENTITY_TYPE_WORLD;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::authority_adopted_fold::fold_past_prefix_image;
use oneiron::test_doors::world_key_record_signature::sign_world_key_record_as_install;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

const AT: TimeRange = TimeRange { start: 1, end: 1 };

/// The vault's host: rooted, with the owner and the world's row, never marked yours. Its
/// handle holds the host's root as a serving host does, so the owner answers it carries (the
/// two admissions, the removal) are proven (row CARRIER-OWNER-PROOF) and stand instead of
/// being held for an owner device. The beside copies are made on its device, so they share its
/// keystore (each install keeps its own slots there).
struct Host {
    _dir: tempfile::TempDir,
    vault: Vault,
    keystore: Arc<oneiron_keystore::MemoryKeystore>,
    proof: AuthenticatedOwner,
    vault_id: [u8; 32],
}

fn rooted_host() -> Host {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the host install");
    let keystore = Arc::new(oneiron_keystore::MemoryKeystore::default());
    vault.install_device_keystore(keystore.clone());
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("the host install profile");
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("the owner binding");
    vault.hold_checkpoint_root_signer(Arc::new(issuer));
    // A checkpoint is sealed under the vault data key, so the host mints it before its first
    // snapshot for a beside copy.
    vault.ensure_vault_key().expect("mint the vault data key");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof");
    let vault_id = vault
        .authority_vault_id()
        .expect("the fold")
        .expect("a rooted vault");
    Host {
        _dir: dir,
        vault,
        keystore,
        proof,
        vault_id,
    }
}

/// One machine's install: a copy beside its source, enrolled as the owner's.
struct MachineInstall {
    _backups: tempfile::TempDir,
    vault: Vault,
    proof: AuthenticatedOwner,
}

/// A beside copy of `source`, a new install on the same device, with its own owner proof,
/// before enrolment. It takes the device's `keystore`, so it opens the vault data key with the
/// device wrap of the install it was copied from, as a copy made on that device does.
fn restored_beside(
    source: &Vault,
    keystore: &Arc<oneiron_keystore::MemoryKeystore>,
) -> (tempfile::TempDir, Vault, AuthenticatedOwner) {
    let backups = oneiron::test_support::restore_tempdir();
    let image = backups.path().join("image");
    source
        .snapshot_checkpoint(&image, 100)
        .expect("snapshot for a beside copy");
    let key = source
        .checkpoint_key()
        .expect("checkpoint key for a beside copy");
    let origin = source.side_restore_source().expect("beside restore source");
    let (vault, _) = Vault::restore_checkpoint_beside(
        &image,
        &key,
        &backups.path().join("copy"),
        VaultConfig::device(),
        &origin,
        200,
    )
    .expect("restore beside the source");
    vault.install_device_keystore(keystore.clone());
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the owner on the copy");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof on the copy");
    (backups, vault, proof)
}

/// Admits `install`'s machine on `host` as yours; the admitted machine id.
fn admit_install(host: &Host, install: &Vault) -> EntityId {
    let key = install
        .machine_encryption_key(host.vault_id)
        .expect("the install encryption key");
    let request = install
        .machine_enrolment_request(host.vault_id, key)
        .expect("the install enrolment request");
    let machine = request.machine;
    host.vault
        .enroll_machine(
            &host.proof,
            ActSurface::ThisInstall,
            &request,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("the host admits the install");
    machine
}

/// Every authority row `from` holds, landed on `to`.
fn sync_authority(from: &Vault, to: &Vault) {
    let history = from
        .export_signed_authority_history()
        .expect("export authority history");
    to.import_signed_authority_history(&history)
        .expect("import authority history");
}

/// Every stored authority row of `vault`, decoded.
fn stored_rows(vault: &Vault) -> Vec<AuthorityLogEntry> {
    vault
        .export_signed_authority_history()
        .expect("export for stored rows")
        .iter()
        .map(|bytes| decode_authority_log_entry_body(bytes).expect("decode a stored row"))
        .collect()
}

/// The log both tests read, as the standing install holds it, and what they name in it.
struct SignerFork {
    _host: Host,
    _removed_install: MachineInstall,
    standing_install: MachineInstall,
    world: EntityId,
    standing_machine: EntityId,
    first_key_record: WorldKeyWrapsRecord,
    first_key_hash: AuthorityEntryHash,
    second_hash: AuthorityEntryHash,
    fork_hash: AuthorityEntryHash,
}

/// The removed install (A) mints the world's first key (X, E for its settings), the
/// standing install (B) writes its own record of the same key (Z, naming X), the owner
/// removes A (R), then A's key signs a fork on A's admission (Y, one above every row A signed,
/// copying X so its settings revision mismatches its old parents and it lands as a valid
/// no-op). B holds every row.
fn signer_fork_after_removal() -> SignerFork {
    let host = rooted_host();
    let world = EntityId::now();
    host.vault
        .put_entity(&world, ENTITY_TYPE_WORLD, AT, 1, b"world")
        .expect("the world row on the host");

    let (backups_removed, vault_removed, proof_removed) =
        restored_beside(&host.vault, &host.keystore);
    let removed_machine = admit_install(&host, &vault_removed);
    let removed_install = MachineInstall {
        _backups: backups_removed,
        vault: vault_removed,
        proof: proof_removed,
    };
    sync_authority(&host.vault, &removed_install.vault);

    removed_install
        .vault
        .set_world_privacy_as(
            &removed_install.proof,
            ActSurface::ThisInstall,
            world,
            WorldPrivacy {
                read: ReadLocation::MyMachines,
                ..WorldPrivacy::default()
            },
            None,
        )
        .expect("the removed install keeps the world on member machines");

    let rows_minting = stored_rows(&removed_install.vault);
    let first_key_entry = rows_minting
        .iter()
        .find(|entry| {
            matches!(
                &entry.op,
                AuthorityOp::WorldKeyWraps(record) if record.key.world == world
            )
        })
        .expect("the removed install minted the first key record")
        .clone();
    let first_key_record = match &first_key_entry.op {
        AuthorityOp::WorldKeyWraps(record) => record.clone(),
        _ => unreachable!("the first key entry wraps a key"),
    };
    let first_key_hash = authority_entry_hash(&first_key_entry).expect("hash the first key record");
    let admission_removed = rows_minting
        .iter()
        .find(|entry| {
            matches!(
                &entry.op,
                AuthorityOp::MachineProfile(profile)
                    if profile.machine == removed_machine && profile.revision == 1
            )
        })
        .expect("the removed install admission")
        .clone();
    let admission_removed_hash =
        authority_entry_hash(&admission_removed).expect("hash the removed admission");
    sync_authority(&removed_install.vault, &host.vault);

    let (backups_standing, vault_standing, proof_standing) =
        restored_beside(&removed_install.vault, &host.keystore);
    let standing_machine = admit_install(&host, &vault_standing);
    let standing_install = MachineInstall {
        _backups: backups_standing,
        vault: vault_standing,
        proof: proof_standing,
    };
    sync_authority(&host.vault, &removed_install.vault);
    sync_authority(&host.vault, &standing_install.vault);

    removed_install
        .vault
        .ensure_world_key(&removed_install.proof, world)
        .expect("the removed install wraps the key to the standing install");
    sync_authority(&removed_install.vault, &standing_install.vault);
    sync_authority(&removed_install.vault, &host.vault);

    let rows_standing = stored_rows(&standing_install.vault);
    let admission_standing = rows_standing
        .iter()
        .find(|entry| {
            matches!(
                &entry.op,
                AuthorityOp::MachineProfile(profile) if profile.machine == standing_machine
            )
        })
        .expect("the standing install admission")
        .clone();
    let admission_standing_hash =
        authority_entry_hash(&admission_standing).expect("hash the standing admission");

    let mut second_record = first_key_record.clone();
    second_record.machine = standing_machine;
    let second_parents = BTreeSet::from([first_key_hash, admission_standing_hash]);
    let second_entry =
        sign_world_key_record_as_install(&standing_install.vault, second_record, 1, second_parents)
            .expect("the standing install signs its own key record");
    let second_hash = authority_entry_hash(&second_entry).expect("hash the second key record");
    standing_install
        .vault
        .put_authority_log_entry(&second_entry, AT, 1)
        .expect("the standing install stores its own key record");
    sync_authority(&standing_install.vault, &host.vault);
    sync_authority(&standing_install.vault, &removed_install.vault);

    host.vault
        .set_machine_role(
            &host.proof,
            ActSurface::ThisInstall,
            removed_machine,
            MachineRole::Removed,
            None,
        )
        .expect("the host removes the minting install");
    sync_authority(&host.vault, &standing_install.vault);
    sync_authority(&host.vault, &removed_install.vault);

    // Above every row the removed key signed (its rewrap of the key to B, X2, among them), so
    // the fork floors each of its covered key records and no record above vouches for one.
    let removed_top_seq = stored_rows(&standing_install.vault)
        .iter()
        .filter(|entry| entry.signer_key() == first_key_entry.signer_key())
        .map(|entry| entry.seq)
        .max()
        .expect("the removed key signed the first key record");
    let fork_parents = BTreeSet::from([admission_removed_hash]);
    let fork_entry = sign_world_key_record_as_install(
        &removed_install.vault,
        first_key_record.clone(),
        removed_top_seq + 1,
        fork_parents,
    )
    .expect("the removed key signs a fork on its admission");
    standing_install
        .vault
        .put_authority_log_entry(&fork_entry, AT, 1)
        .expect("the standing install stores the fork");
    let fork_hash = authority_entry_hash(&fork_entry).expect("hash the fork");
    SignerFork {
        _host: host,
        _removed_install: removed_install,
        standing_install,
        world,
        standing_machine,
        first_key_record,
        first_key_hash,
        second_hash,
        fork_hash,
    }
}

/// T5: B must still hold the key as current after A's fork, and open it.
#[test]
fn a_world_key_survives_its_signers_fork_after_removal() {
    let SignerFork {
        standing_install,
        world,
        standing_machine,
        first_key_record,
        first_key_hash,
        second_hash,
        ..
    } = signer_fork_after_removal();
    let first_key_id = first_key_record.key;
    let fold = standing_install
        .vault
        .authority_fold()
        .expect("the standing install folds its log");
    let current = fold.current_world_key(world);
    assert!(
        current.is_some_and(|key| key.id == first_key_id),
        "T5 (anchorsec-seq-floor-s): the standing install must still hold the world's first key \
         as current after its removed signer's fork on an old parent; got {current:?}, issues {:?}",
        fold.issues
    );
    assert!(
        fold.valid_entries.contains(&first_key_hash) && fold.valid_entries.contains(&second_hash),
        "T5: the mint and the standing install's own record stay valid after the fork; issues {:?}",
        fold.issues
    );
    assert!(
        fold.issues.iter().any(|issue| matches!(
            issue,
            AuthorityFoldIssue::SequenceFork(forked) if *forked == first_key_hash
        )),
        "T5: the fold records the mint's fork as SequenceFork; issues {:?}",
        fold.issues
    );
    assert!(
        fold.signer_stands(standing_machine),
        "T5: the standing install's machine still stands behind the key"
    );
    let opened = standing_install
        .vault
        .world_key(world)
        .expect("T5: the standing install opens the world's key after the fork");
    assert_eq!(
        *opened.id(),
        first_key_id,
        "T5: the standing install's world key is still the first key after the fork"
    );
}

/// FIX [SEQ-FLOOR-S-ADOPTED-FORK-NEEDS-HISTORY] (Astra r4 F1 on #8449) and
/// [ADOPTED-FOLD-GATE-TEST]: a cold install that adopted an image of every row B holds but
/// the fork (P, E, X, Z, R), and holds none of them, folds the fork (Y) past the image. Y
/// floors X, a covered granting row, which only adds X's SequenceFork; the fold past the
/// image must answer, and answer what B's own fold of the whole log answers, live and as a
/// later image keeps it. Red on main: the fold past the image asks for the covered rows.
#[test]
fn a_cold_adopted_install_folds_its_signers_fork_past_the_image() {
    let fork = signer_fork_after_removal();
    let covered: BTreeSet<AuthorityEntryHash> = stored_rows(&fork.standing_install.vault)
        .iter()
        .map(|entry| authority_entry_hash(entry).expect("hash a stored row"))
        .filter(|hash| *hash != fork.fork_hash)
        .collect();
    let folded = fold_past_prefix_image(&fork.standing_install.vault, &covered)
        .expect("the standing install folds past an image of every row but the fork");
    assert!(
        folded
            .whole
            .current_world_key(fork.world)
            .is_some_and(|key| key.id == fork.first_key_record.key),
        "the whole fold holds the first key as current, as T5 asserts; issues {:?}",
        folded.whole.issues
    );
    let adopted = folded.adopted.unwrap_or_else(|missing| {
        panic!(
            "[SEQ-FLOOR-S-ADOPTED-FORK-NEEDS-HISTORY]: the fold past the image must answer the \
             fork on a covered granting row, not ask for {} covered rows",
            missing.len()
        )
    });
    assert_eq!(
        adopted.current_world_key(fork.world),
        folded.whole.current_world_key(fork.world),
        "the fold past the image holds the whole fold's current key"
    );
    assert_eq!(
        adopted.valid_entries, folded.whole.valid_entries,
        "the fold past the image counts the whole fold's rows"
    );
    assert_eq!(
        adopted.issues, folded.whole.issues,
        "the fold past the image records the whole fold's issues, the mint's SequenceFork in \
         the whole fold's order"
    );
    assert!(
        adopted == folded.whole,
        "the fold past the image is the whole fold"
    );
    let captured = folded.captured.unwrap_or_else(|missing| {
        panic!(
            "[SEQ-FLOOR-S-ADOPTED-FORK-NEEDS-HISTORY]: the capture past the image must answer \
             the fork on a covered granting row, not ask for {} covered rows",
            missing.len()
        )
    });
    assert_eq!(
        captured.safety_issues, folded.whole_captured.safety_issues,
        "a later image keeps the whole image's safety issues"
    );
    assert!(
        captured.fold == folded.whole_captured.fold,
        "a later image keeps the whole image's once fold"
    );
}
