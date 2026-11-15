//! T5 (Astra anchorsec-seq-floor-s): one row a removed machine's key signs on an old parent must not take its world's key from every install.
//! The removed install mints the world's first key, the standing install wraps the same key, the owner removes the minter, then the minter's key signs a fork on an old parent that floors its mint.
//! Red 23e0a2679c03 refuses the floored mint as NonMonotonicSeq and loses the key; green 00dfd0c99ed3 counts the mint and records SequenceFork.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test world_key_survives_signer_fork`.

#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{
    ActSurface, AuthorityFoldIssue, AuthorityLogEntry, AuthorityOp, MachineOwnership, MachineRole,
    ReadLocation, WorldPrivacy, authority_entry_hash, decode_authority_log_entry_body,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::registry::ENTITY_TYPE_WORLD;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::world_key_record_signature::sign_world_key_record_as_install;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

const AT: TimeRange = TimeRange { start: 1, end: 1 };

/// The vault's host: rooted, with the owner and the world's row, never marked yours.
struct Host {
    _dir: tempfile::TempDir,
    vault: Vault,
    proof: AuthenticatedOwner,
    vault_id: [u8; 32],
}

fn rooted_host() -> Host {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the host install");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("the host install profile");
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("the owner binding");
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

/// A beside copy of `source`, with its own keystore and owner proof, before enrolment.
fn restored_beside(source: &Vault) -> (tempfile::TempDir, Vault, AuthenticatedOwner) {
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
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
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

/// T5: the removed install (A) mints the world's first key (X, E for its settings), the
/// standing install (B) writes its own record of the same key (Z, naming X), the owner
/// removes A (R), then A's key signs a fork on A's admission (Y, at X's sequence plus one,
/// copying X so its settings revision mismatches its old parents and it lands as a valid
/// no-op). B must still hold the key as current and open it.
#[test]
fn a_world_key_survives_its_signers_fork_after_removal() {
    let host = rooted_host();
    let world = EntityId::now();
    host.vault
        .put_entity(&world, ENTITY_TYPE_WORLD, AT, 1, b"world")
        .expect("the world row on the host");

    let (backups_removed, vault_removed, proof_removed) = restored_beside(&host.vault);
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
    let first_key_id = first_key_record.key;
    let first_key_seq = first_key_entry.seq;
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
        restored_beside(&removed_install.vault);
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

    let fork_parents = BTreeSet::from([admission_removed_hash]);
    let fork_entry = sign_world_key_record_as_install(
        &removed_install.vault,
        first_key_record.clone(),
        first_key_seq + 1,
        fork_parents,
    )
    .expect("the removed key signs a fork on its admission");
    standing_install
        .vault
        .put_authority_log_entry(&fork_entry, AT, 1)
        .expect("the standing install stores the fork");

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
