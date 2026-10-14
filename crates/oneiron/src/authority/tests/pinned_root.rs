//! World privacy P6b acceptance for this install's pin (contract §4, check
//! 7e): a pin moves trust at once, with no log append, and only while the
//! fold holds its root; and every restore that makes the vault a new machine
//! opens it unpinned, so no image rolls trust back or arrives pinned to a
//! root its install never chose.
use super::machine_identity::{Host, host, own_encryption_key};
use super::*;
use crate::world_keys::PreparedRoot;
use crate::{TimeRange, Vault, VaultConfig};

/// A root drawn and published on `host`'s vault, and the pin naming it.
fn publish_root(host: &Host) -> (PreparedRoot, PinnedRoot) {
    let prepared = host.vault.prepare_owner_root(&host.owner).unwrap();
    let root = prepared.seed().public(&host.vault_id).unwrap();
    let at = prepared.entry().ts;
    host.vault
        .put_authority_log_entry(prepared.entry(), TimeRange { start: at, end: at }, at)
        .unwrap();
    let pin = PinnedRoot {
        id: root.id,
        anchor_key: root.anchor_key,
    };
    (prepared, pin)
}

/// `prepared`'s anchor marks `request`'s machine "yours", in its own chain.
fn anchor_mark(host: &Host, prepared: &PreparedRoot, request: &MachineEnrolmentRequest) {
    let op = AuthorityOp::MachineProfile(MachineProfile {
        machine: request.machine,
        owner: host.owner.actor(),
        machine_key: request.machine_key,
        encryption_key: request.encryption_key.clone(),
        role: MachineRole::Owned(MachineOwnership::Yours),
        revision: 1,
        machine_proof: request.machine_proof,
    });
    let fold = host.vault.authority_fold().unwrap();
    let at = prepared.entry().ts;
    let entry = anchor_signed_entry(&fold, &prepared.seed().anchor(), op, at).unwrap();
    host.vault
        .put_authority_log_entry(&entry, TimeRange { start: at, end: at }, at)
        .unwrap();
}

/// What a pin door commits, without the door: the pin and its generation.
fn pin(vault: &Vault, root: PinnedRoot) {
    vault
        .with_write_txn_grouped(|wtxn| write_pinned_root_in_txn(&vault.store, wtxn, root, None))
        .unwrap();
}

fn pinned(vault: &Vault) -> Option<RecoveryRootId> {
    vault.owner_root_view(None, 0).unwrap().pinned
}

/// A machine only the owner's anchor marks is mine once, and as soon as, this
/// install pins that anchor's root, with nothing appended to the log; a pin
/// naming a root the log does not hold trusts nothing.
#[test]
fn a_pin_alone_moves_trust_at_once() {
    let host = host();
    let own = own_encryption_key(&host.vault, host.vault_id);
    let request = host
        .vault
        .machine_enrolment_request(host.vault_id, own)
        .unwrap();
    let (prepared, root) = publish_root(&host);
    anchor_mark(&host, &prepared, &request);
    let mine = || host.vault.local_machine().unwrap().unwrap().mine;
    assert!(!mine());
    let view = host.vault.owner_root_view(None, 10).unwrap();
    assert_eq!(view.pinned, None);
    assert_eq!(view.foreign, BTreeMap::from([(root.id, 1)]));

    let unknown = PinnedRoot {
        id: RecoveryRootId([9; 32]),
        anchor_key: root.anchor_key,
    };
    pin(&host.vault, unknown);
    assert!(!mine());
    assert_eq!(host.vault.authority_fold().unwrap().pinned_root, None);

    pin(&host.vault, root);
    assert!(mine());
    assert_eq!(host.vault.authority_fold().unwrap().pinned_root, Some(root));
    let view = host.vault.owner_root_view(None, 10).unwrap();
    assert_eq!(view.pinned, Some(root.id));
    assert_eq!((view.foreign.len(), view.foreign_total), (0, 0));
}

/// An install pinned to one root, imaged, then moved to another. A direct
/// restore, a restore beside the vault and a copy keeping its authority are
/// new machines: each opens unpinned, though both roots are in its log. Only
/// the restore that takes the vault's place keeps a pin: the live install's,
/// never the image's (Wonder R1j-F1).
#[test]
fn a_restore_that_makes_a_new_machine_opens_unpinned() {
    let host = host();
    let (_, first) = publish_root(&host);
    let (_, second) = publish_root(&host);
    pin(&host.vault, first);
    let backups = tempfile::tempdir().unwrap();
    let image = backups.path().join("image");
    host.vault.snapshot_checkpoint(&image, 100).unwrap();
    pin(&host.vault, second);

    let (replacement, _) = Vault::restore_checkpoint_replacing(
        &image,
        &backups.path().join("replacement"),
        VaultConfig::default(),
        &host.vault,
        200,
    )
    .unwrap();
    assert_eq!(pinned(&replacement), Some(second.id));
    drop(replacement);

    let (copy, _) = Vault::restore_checkpoint_keeping_authority(
        &image,
        &backups.path().join("copy"),
        VaultConfig::default(),
        &host.vault,
        250,
    )
    .unwrap();
    let (elsewhere, _) = Vault::restore_checkpoint(
        &image,
        &backups.path().join("elsewhere"),
        VaultConfig::default(),
        crate::recovery::checkpoint::RestoreReason::Restore,
        300,
    )
    .unwrap();
    let (beside, _) = Vault::restore_checkpoint_beside(
        &image,
        &backups.path().join("beside"),
        VaultConfig::default(),
        &host.vault.side_restore_source().unwrap(),
        350,
    )
    .unwrap();
    for vault in [&copy, &elsewhere, &beside] {
        assert_eq!(pinned(vault), None);
        assert_eq!(vault.owner_root_view(None, 0).unwrap().inert_foreign, 2);
    }
}

/// The vault a restore replaced, activated beside its replacement, is a new
/// machine and opens unpinned; the replacement keeps the pin.
#[test]
fn an_activated_archive_opens_unpinned() {
    let host = host();
    let (_, root) = publish_root(&host);
    pin(&host.vault, root);
    let Host { _dir, vault, .. } = host;
    let home = vault.store.env.path().to_path_buf();
    let backups = tempfile::tempdir().unwrap();
    let (image, staged) = (backups.path().join("image"), backups.path().join("staged"));
    vault.snapshot_checkpoint(&image, 100).unwrap();
    let (replacement, _) =
        Vault::restore_checkpoint_replacing(&image, &staged, VaultConfig::default(), &vault, 200)
            .unwrap();
    // As `oneiron restore` exchanges the two directories.
    vault
        .swap_in_replacement(&replacement, || {
            let between = home.with_extension("exchange");
            std::fs::rename(&home, &between)?;
            std::fs::rename(&staged, &home)?;
            std::fs::rename(&between, &staged)
        })
        .unwrap();
    drop((vault, replacement));
    let replacement = Vault::open(&home, VaultConfig::default()).unwrap();
    Vault::activate_archived(
        &staged,
        VaultConfig::default(),
        &replacement.side_restore_source().unwrap(),
    )
    .unwrap();
    let side = Vault::open(&staged, VaultConfig::default()).unwrap();
    assert_eq!(pinned(&side), None);
    assert_eq!(pinned(&replacement), Some(root.id));
}
